//! Wasm binary parser frontend using wasmparser.
//! Produces Parsed IR consumed by the resolve stage.
//!
//! Transition note: Phase 1 introduces typed ParsedOperator (Opcode + Immediate)
//! replacing the old string-based OperatorIr. Phase 2 keeps parsing free of
//! stable-ID and fingerprint refresh; those now live in resolve/normalize.

use std::{error::Error, fmt};

use wasmparser::{Encoding, ExternalKind, Operator, Parser, Payload, TypeRef};

use crate::ir::{
    ExportIr, ExternalKindIr, FunctionIr, FunctionKindIr, Immediate, ImportIr, LocalIr, ModuleIr,
    Opcode, ParsedModule, ParsedOperator, TypeIr, TypeRefIr,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    message: String,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "wasm parse error: {}", self.message)
    }
}

impl Error for ParseError {}

impl From<wasmparser::BinaryReaderError> for ParseError {
    fn from(error: wasmparser::BinaryReaderError) -> Self {
        Self::new(error.to_string())
    }
}

pub fn parse_module(bytes: &[u8]) -> Result<ParsedModule, ParseError> {
    let mut module = ModuleIr::new();
    let mut defined_type_indices = Vec::new();
    let mut next_function_index = 0_u32;
    let mut next_defined_function = 0_usize;
    let mut saw_module = false;

    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::Version { encoding, .. } => {
                if encoding != Encoding::Module {
                    return Err(ParseError::new("components are not supported"));
                }
                saw_module = true;
            }
            Payload::TypeSection(section) => {
                for (source_index, ty) in section.into_iter_err_on_gc_types().enumerate() {
                    let ty = ty?;
                    let params = ty
                        .params()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    let results = ty
                        .results()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    let id = type_id(&params, &results);
                    module.types.push(TypeIr {
                        id,
                        source_index: checked_u32(source_index, "type index")?,
                        params,
                        results,
                    });
                }
            }
            Payload::ImportSection(section) => {
                for import in section.into_imports() {
                    let import = import?;
                    let source_index = checked_u32(module.imports.len(), "import index")?;
                    let type_ref = convert_type_ref(import.ty, &module.types)?;
                    let kind = external_kind_for_type_ref(import.ty);
                    let id = import_id(import.module, import.name, kind, &type_ref);

                    if let TypeRefIr::Func {
                        type_index,
                        type_id,
                    } = &type_ref
                    {
                        module.functions.push(FunctionIr {
                            id: format!(
                                "import:{}:{}:func:{}",
                                import.module, import.name, type_id
                            ),
                            source_index: next_function_index,
                            type_index: *type_index,
                            type_id: type_id.clone(),
                            kind: FunctionKindIr::Imported,
                            export_names: Vec::new(),
                            locals: Vec::new(),
                            operators: Vec::new(),
                            direct_calls: Vec::new(),
                            fingerprint: None,
                        });
                        next_function_index =
                            next_function_index.checked_add(1).ok_or_else(|| {
                                ParseError::new("function index overflow while reading imports")
                            })?;
                    }

                    module.imports.push(ImportIr {
                        id,
                        source_index,
                        module: import.module.to_owned(),
                        name: import.name.to_owned(),
                        kind,
                        type_ref,
                    });
                }
            }
            Payload::FunctionSection(section) => {
                for type_index in section {
                    let type_index = type_index?;
                    let type_id = type_id_for_index(&module.types, type_index)?.to_owned();
                    module.functions.push(FunctionIr {
                        id: format!("type:{}:defined:{}", type_id, defined_type_indices.len()),
                        source_index: next_function_index,
                        type_index,
                        type_id,
                        kind: FunctionKindIr::Defined,
                        export_names: Vec::new(),
                        locals: Vec::new(),
                        operators: Vec::new(),
                        direct_calls: Vec::new(),
                        fingerprint: None,
                    });
                    defined_type_indices.push(type_index);
                    next_function_index = next_function_index.checked_add(1).ok_or_else(|| {
                        ParseError::new("function index overflow while reading functions")
                    })?;
                }
            }
            Payload::ExportSection(section) => {
                for export in section {
                    let export = export?;
                    let kind = convert_external_kind(export.kind)?;
                    module.exports.push(ExportIr {
                        id: format!("export:{}:{}", export.name, kind.as_str()),
                        source_index: checked_u32(module.exports.len(), "export index")?,
                        name: export.name.to_owned(),
                        kind,
                        item_index: export.index,
                    });
                }
            }
            Payload::CodeSectionStart { count, .. } => {
                if count as usize != defined_type_indices.len() {
                    return Err(ParseError::new(format!(
                        "function section declares {} bodies but code section has {}",
                        defined_type_indices.len(),
                        count
                    )));
                }
            }
            Payload::CodeSectionEntry(body) => {
                let function = module
                    .functions
                    .iter_mut()
                    .filter(|function| function.kind == FunctionKindIr::Defined)
                    .nth(next_defined_function)
                    .ok_or_else(|| {
                        ParseError::new("code section contains more bodies than functions")
                    })?;

                function.locals = body
                    .get_locals_reader()?
                    .into_iter()
                    .map(|local| {
                        let (count, value_type) = local?;
                        Ok(LocalIr {
                            count,
                            value_type: value_type.to_string(),
                        })
                    })
                    .collect::<Result<Vec<_>, ParseError>>()?;

                let operators = body
                    .get_operators_reader()?
                    .into_iter_with_offsets()
                    .map(|operator| {
                        let (operator, offset) = operator?;
                        Ok(convert_operator(operator, offset))
                    })
                    .collect::<Result<Vec<_>, ParseError>>()?;

                // Phase 1: direct_calls now uses typed immediate instead of string parsing
                function.direct_calls = operators
                    .iter()
                    .filter_map(|op| op.immediate.call_function_index())
                    .collect();
                function.operators = operators;
                next_defined_function += 1;
            }
            Payload::End(_) => {}
            Payload::CustomSection(_)
            | Payload::TableSection(_)
            | Payload::MemorySection(_)
            | Payload::TagSection(_)
            | Payload::GlobalSection(_)
            | Payload::StartSection { .. }
            | Payload::ElementSection(_)
            | Payload::DataCountSection { .. }
            | Payload::DataSection(_) => {}
            _ => {
                return Err(ParseError::new(
                    "nested modules and components are not supported",
                ))
            }
        }
    }

    if !saw_module {
        return Err(ParseError::new("missing wasm module header"));
    }
    if next_defined_function != defined_type_indices.len() {
        return Err(ParseError::new(format!(
            "function section declares {} bodies but parsed {} code bodies",
            defined_type_indices.len(),
            next_defined_function
        )));
    }

    Ok(ParsedModule { module })
}

// ── Phase 1: typed operator conversion ─────────────────────────────────────

/// Convert a wasmparser `Operator` into our typed `(Opcode, Immediate)`.
fn convert_operator<'a>(operator: Operator<'a>, offset: usize) -> ParsedOperator {
    let (opcode, immediate) = operator_to_opcode_immediate(operator);
    ParsedOperator {
        offset: offset as u64,
        opcode,
        immediate,
    }
}

/// Map wasmparser::Operator variants to (Opcode, Immediate).
#[allow(clippy::too_many_lines)]
fn operator_to_opcode_immediate<'a>(op: Operator<'a>) -> (Opcode, Immediate) {
    use Opcode as Oc;
    use Operator::*;

    match op {
        // ── MVP: Control flow ──
        Unreachable => (Oc::Unreachable, Immediate::None),
        Nop => (Oc::Nop, Immediate::None),
        Block { blockty } => (
            Oc::Block,
            Immediate::BlockType(format!("{blockty:?}")),
        ),
        Loop { blockty } => (
            Oc::Loop,
            Immediate::BlockType(format!("{blockty:?}")),
        ),
        If { blockty } => (
            Oc::If,
            Immediate::BlockType(format!("{blockty:?}")),
        ),
        Else => (Oc::Else, Immediate::None),
        End => (Oc::End, Immediate::None),
        Br { relative_depth } => (Oc::Br, Immediate::Branch(relative_depth)),
        BrIf { relative_depth } => (Oc::BrIf, Immediate::Branch(relative_depth)),
        BrOnNull { relative_depth } => (Oc::BrOnNull, Immediate::Branch(relative_depth)),
        BrOnNonNull { relative_depth } => (Oc::BrOnNonNull, Immediate::Branch(relative_depth)),
        BrTable { targets } => (
            Oc::BrTable,
            Immediate::BrTable {
                targets: targets
                    .targets()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap_or_default(),
                default_target: targets.default(),
            },
        ),
        Return => (Oc::Return, Immediate::None),

        // ── MVP: Calls ──
        Call { function_index } => (Oc::Call, Immediate::Call(function_index)),
        CallIndirect {
            type_index,
            table_index,
        } => (
            Oc::CallIndirect,
            Immediate::CallIndirect {
                type_index,
                table_index,
            },
        ),

        // ── MVP: Parametric ──
        Drop => (Oc::Drop, Immediate::None),
        Select => (Oc::Select, Immediate::None),

        // ── MVP: Variable ──
        LocalGet { local_index } => (Oc::LocalGet, Immediate::Local(local_index)),
        LocalSet { local_index } => (Oc::LocalSet, Immediate::Local(local_index)),
        LocalTee { local_index } => (Oc::LocalTee, Immediate::Local(local_index)),
        GlobalGet { global_index } => (Oc::GlobalGet, Immediate::Global(global_index)),
        GlobalSet { global_index } => (Oc::GlobalSet, Immediate::Global(global_index)),

        // ── MVP: Memory loads ──
        I32Load { memarg } => (
            Oc::I32Load,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Load { memarg } => (
            Oc::I64Load,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        F32Load { memarg } => (
            Oc::F32Load,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        F64Load { memarg } => (
            Oc::F64Load,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I32Load8S { memarg } => (
            Oc::I32Load8S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I32Load8U { memarg } => (
            Oc::I32Load8U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I32Load16S { memarg } => (
            Oc::I32Load16S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I32Load16U { memarg } => (
            Oc::I32Load16U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Load8S { memarg } => (
            Oc::I64Load8S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Load8U { memarg } => (
            Oc::I64Load8U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Load16S { memarg } => (
            Oc::I64Load16S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Load16U { memarg } => (
            Oc::I64Load16U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Load32S { memarg } => (
            Oc::I64Load32S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Load32U { memarg } => (
            Oc::I64Load32U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),

        // ── MVP: Memory stores ──
        I32Store { memarg } => (
            Oc::I32Store,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Store { memarg } => (
            Oc::I64Store,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        F32Store { memarg } => (
            Oc::F32Store,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        F64Store { memarg } => (
            Oc::F64Store,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I32Store8 { memarg } => (
            Oc::I32Store8,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I32Store16 { memarg } => (
            Oc::I32Store16,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Store8 { memarg } => (
            Oc::I64Store8,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Store16 { memarg } => (
            Oc::I64Store16,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),
        I64Store32 { memarg } => (
            Oc::I64Store32,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),

        // ── MVP: Memory misc ──
        MemorySize { mem } => (Oc::MemorySize, Immediate::MemoryIndex(mem)),
        MemoryGrow { mem } => (Oc::MemoryGrow, Immediate::MemoryIndex(mem)),

        // ── MVP: Constants ──
        I32Const { value } => (Oc::I32Const, Immediate::I32Const(value)),
        I64Const { value } => (Oc::I64Const, Immediate::I64Const(value)),
        F32Const { value } => (
            Oc::F32Const,
            Immediate::F32Const(value.bits()),
        ),
        F64Const { value } => (
            Oc::F64Const,
            Immediate::F64Const(value.bits()),
        ),

        // ── MVP: i32 test ──
        I32Eqz => (Oc::I32Eqz, Immediate::None),
        I32Eq => (Oc::I32Eq, Immediate::None),
        I32Ne => (Oc::I32Ne, Immediate::None),
        I32LtS => (Oc::I32LtS, Immediate::None),
        I32LtU => (Oc::I32LtU, Immediate::None),
        I32GtS => (Oc::I32GtS, Immediate::None),
        I32GtU => (Oc::I32GtU, Immediate::None),
        I32LeS => (Oc::I32LeS, Immediate::None),
        I32LeU => (Oc::I32LeU, Immediate::None),
        I32GeS => (Oc::I32GeS, Immediate::None),
        I32GeU => (Oc::I32GeU, Immediate::None),

        // ── MVP: i64 test ──
        I64Eqz => (Oc::I64Eqz, Immediate::None),
        I64Eq => (Oc::I64Eq, Immediate::None),
        I64Ne => (Oc::I64Ne, Immediate::None),
        I64LtS => (Oc::I64LtS, Immediate::None),
        I64LtU => (Oc::I64LtU, Immediate::None),
        I64GtS => (Oc::I64GtS, Immediate::None),
        I64GtU => (Oc::I64GtU, Immediate::None),
        I64LeS => (Oc::I64LeS, Immediate::None),
        I64LeU => (Oc::I64LeU, Immediate::None),
        I64GeS => (Oc::I64GeS, Immediate::None),
        I64GeU => (Oc::I64GeU, Immediate::None),

        // ── MVP: f32 test ──
        F32Eq => (Oc::F32Eq, Immediate::None),
        F32Ne => (Oc::F32Ne, Immediate::None),
        F32Lt => (Oc::F32Lt, Immediate::None),
        F32Gt => (Oc::F32Gt, Immediate::None),
        F32Le => (Oc::F32Le, Immediate::None),
        F32Ge => (Oc::F32Ge, Immediate::None),

        // ── MVP: f64 test ──
        F64Eq => (Oc::F64Eq, Immediate::None),
        F64Ne => (Oc::F64Ne, Immediate::None),
        F64Lt => (Oc::F64Lt, Immediate::None),
        F64Gt => (Oc::F64Gt, Immediate::None),
        F64Le => (Oc::F64Le, Immediate::None),
        F64Ge => (Oc::F64Ge, Immediate::None),

        // ── MVP: i32 unary ──
        I32Clz => (Oc::I32Clz, Immediate::None),
        I32Ctz => (Oc::I32Ctz, Immediate::None),
        I32Popcnt => (Oc::I32Popcnt, Immediate::None),

        // ── MVP: i64 unary ──
        I64Clz => (Oc::I64Clz, Immediate::None),
        I64Ctz => (Oc::I64Ctz, Immediate::None),
        I64Popcnt => (Oc::I64Popcnt, Immediate::None),

        // ── MVP: f32 unary ──
        F32Abs => (Oc::F32Abs, Immediate::None),
        F32Neg => (Oc::F32Neg, Immediate::None),
        F32Ceil => (Oc::F32Ceil, Immediate::None),
        F32Floor => (Oc::F32Floor, Immediate::None),
        F32Trunc => (Oc::F32Trunc, Immediate::None),
        F32Nearest => (Oc::F32Nearest, Immediate::None),
        F32Sqrt => (Oc::F32Sqrt, Immediate::None),

        // ── MVP: f64 unary ──
        F64Abs => (Oc::F64Abs, Immediate::None),
        F64Neg => (Oc::F64Neg, Immediate::None),
        F64Ceil => (Oc::F64Ceil, Immediate::None),
        F64Floor => (Oc::F64Floor, Immediate::None),
        F64Trunc => (Oc::F64Trunc, Immediate::None),
        F64Nearest => (Oc::F64Nearest, Immediate::None),
        F64Sqrt => (Oc::F64Sqrt, Immediate::None),

        // ── MVP: i32 binary ──
        I32Add => (Oc::I32Add, Immediate::None),
        I32Sub => (Oc::I32Sub, Immediate::None),
        I32Mul => (Oc::I32Mul, Immediate::None),
        I32DivS => (Oc::I32DivS, Immediate::None),
        I32DivU => (Oc::I32DivU, Immediate::None),
        I32RemS => (Oc::I32RemS, Immediate::None),
        I32RemU => (Oc::I32RemU, Immediate::None),
        I32And => (Oc::I32And, Immediate::None),
        I32Or => (Oc::I32Or, Immediate::None),
        I32Xor => (Oc::I32Xor, Immediate::None),
        I32Shl => (Oc::I32Shl, Immediate::None),
        I32ShrS => (Oc::I32ShrS, Immediate::None),
        I32ShrU => (Oc::I32ShrU, Immediate::None),
        I32Rotl => (Oc::I32Rotl, Immediate::None),
        I32Rotr => (Oc::I32Rotr, Immediate::None),

        // ── MVP: i64 binary ──
        I64Add => (Oc::I64Add, Immediate::None),
        I64Sub => (Oc::I64Sub, Immediate::None),
        I64Mul => (Oc::I64Mul, Immediate::None),
        I64DivS => (Oc::I64DivS, Immediate::None),
        I64DivU => (Oc::I64DivU, Immediate::None),
        I64RemS => (Oc::I64RemS, Immediate::None),
        I64RemU => (Oc::I64RemU, Immediate::None),
        I64And => (Oc::I64And, Immediate::None),
        I64Or => (Oc::I64Or, Immediate::None),
        I64Xor => (Oc::I64Xor, Immediate::None),
        I64Shl => (Oc::I64Shl, Immediate::None),
        I64ShrS => (Oc::I64ShrS, Immediate::None),
        I64ShrU => (Oc::I64ShrU, Immediate::None),
        I64Rotl => (Oc::I64Rotl, Immediate::None),
        I64Rotr => (Oc::I64Rotr, Immediate::None),

        // ── MVP: f32 binary ──
        F32Add => (Oc::F32Add, Immediate::None),
        F32Sub => (Oc::F32Sub, Immediate::None),
        F32Mul => (Oc::F32Mul, Immediate::None),
        F32Div => (Oc::F32Div, Immediate::None),
        F32Min => (Oc::F32Min, Immediate::None),
        F32Max => (Oc::F32Max, Immediate::None),
        F32Copysign => (Oc::F32Copysign, Immediate::None),

        // ── MVP: f64 binary ──
        F64Add => (Oc::F64Add, Immediate::None),
        F64Sub => (Oc::F64Sub, Immediate::None),
        F64Mul => (Oc::F64Mul, Immediate::None),
        F64Div => (Oc::F64Div, Immediate::None),
        F64Min => (Oc::F64Min, Immediate::None),
        F64Max => (Oc::F64Max, Immediate::None),
        F64Copysign => (Oc::F64Copysign, Immediate::None),

        // ── MVP: Conversions ──
        I32WrapI64 => (Oc::I32WrapI64, Immediate::None),
        I32TruncF32S => (Oc::I32TruncF32S, Immediate::None),
        I32TruncF32U => (Oc::I32TruncF32U, Immediate::None),
        I32TruncF64S => (Oc::I32TruncF64S, Immediate::None),
        I32TruncF64U => (Oc::I32TruncF64U, Immediate::None),
        I64ExtendI32S => (Oc::I64ExtendI32S, Immediate::None),
        I64ExtendI32U => (Oc::I64ExtendI32U, Immediate::None),
        I64TruncF32S => (Oc::I64TruncF32S, Immediate::None),
        I64TruncF32U => (Oc::I64TruncF32U, Immediate::None),
        I64TruncF64S => (Oc::I64TruncF64S, Immediate::None),
        I64TruncF64U => (Oc::I64TruncF64U, Immediate::None),
        F32ConvertI32S => (Oc::F32ConvertI32S, Immediate::None),
        F32ConvertI32U => (Oc::F32ConvertI32U, Immediate::None),
        F32ConvertI64S => (Oc::F32ConvertI64S, Immediate::None),
        F32ConvertI64U => (Oc::F32ConvertI64U, Immediate::None),
        F32DemoteF64 => (Oc::F32DemoteF64, Immediate::None),
        F64ConvertI32S => (Oc::F64ConvertI32S, Immediate::None),
        F64ConvertI32U => (Oc::F64ConvertI32U, Immediate::None),
        F64ConvertI64S => (Oc::F64ConvertI64S, Immediate::None),
        F64ConvertI64U => (Oc::F64ConvertI64U, Immediate::None),
        F64PromoteF32 => (Oc::F64PromoteF32, Immediate::None),
        I32ReinterpretF32 => (Oc::I32ReinterpretF32, Immediate::None),
        I64ReinterpretF64 => (Oc::I64ReinterpretF64, Immediate::None),
        F32ReinterpretI32 => (Oc::F32ReinterpretI32, Immediate::None),
        F64ReinterpretI64 => (Oc::F64ReinterpretI64, Immediate::None),

        // ── Sign extension ──
        I32Extend8S => (Oc::I32Extend8S, Immediate::None),
        I32Extend16S => (Oc::I32Extend16S, Immediate::None),
        I64Extend8S => (Oc::I64Extend8S, Immediate::None),
        I64Extend16S => (Oc::I64Extend16S, Immediate::None),
        I64Extend32S => (Oc::I64Extend32S, Immediate::None),

        // ── Saturating float-to-int ──
        I32TruncSatF32S => (Oc::I32TruncSatF32S, Immediate::None),
        I32TruncSatF32U => (Oc::I32TruncSatF32U, Immediate::None),
        I32TruncSatF64S => (Oc::I32TruncSatF64S, Immediate::None),
        I32TruncSatF64U => (Oc::I32TruncSatF64U, Immediate::None),
        I64TruncSatF32S => (Oc::I64TruncSatF32S, Immediate::None),
        I64TruncSatF32U => (Oc::I64TruncSatF32U, Immediate::None),
        I64TruncSatF64S => (Oc::I64TruncSatF64S, Immediate::None),
        I64TruncSatF64U => (Oc::I64TruncSatF64U, Immediate::None),

        // ── Bulk memory ──
        MemoryInit { data_index, mem: _mem } => (
            Oc::MemoryInit,
            Immediate::DataIndex(data_index),
        ),
        DataDrop { data_index } => (
            Oc::DataDrop,
            Immediate::DataIndex(data_index),
        ),
        MemoryCopy {
            dst_mem,
            src_mem,
        } => (
            Oc::MemoryCopy,
            Immediate::MemoryCopy {
                dst_index: dst_mem,
                src_index: src_mem,
            },
        ),
        MemoryFill { mem } => (Oc::MemoryFill, Immediate::MemoryIndex(mem)),
        TableInit {
            elem_index,
            table: _table,
        } => (Oc::TableInit, Immediate::ElemIndex(elem_index)),
        ElemDrop { elem_index } => (Oc::ElemDrop, Immediate::ElemIndex(elem_index)),
        TableCopy {
            dst_table,
            src_table,
        } => (
            Oc::TableCopy,
            Immediate::TableCopy {
                dst_table,
                src_table,
            },
        ),

        // ── Reference types ──
        RefNull { hty } => (Oc::RefNull, Immediate::RefNull(format!("{hty:?}"))),
        RefIsNull => (Oc::RefIsNull, Immediate::None),
        RefFunc { function_index } => (Oc::RefFunc, Immediate::RefFunc(function_index)),
        TypedSelect { .. } => (Oc::Select, Immediate::SelectTypes(vec![])),
        TableFill { table } => (Oc::TableFill, Immediate::TableIndex(table)),
        TableGet { table } => (Oc::TableGet, Immediate::TableIndex(table)),
        TableSet { table } => (Oc::TableSet, Immediate::TableIndex(table)),
        TableGrow { table } => (Oc::TableGrow, Immediate::TableIndex(table)),
        TableSize { table } => (Oc::TableSize, Immediate::TableIndex(table)),

        // ── Tail call ──
        ReturnCall { function_index } => (Oc::ReturnCall, Immediate::Call(function_index)),
        ReturnCallIndirect {
            type_index,
            table_index,
        } => (
            Oc::ReturnCallIndirect,
            Immediate::CallIndirect {
                type_index,
                table_index,
            },
        ),

        // ── GC ──
        RefEq => (Oc::RefEq, Immediate::None),
        StructNew {
            struct_type_index,
        } => (Oc::StructNew, Immediate::StructType(struct_type_index)),
        StructNewDefault {
            struct_type_index,
        } => (
            Oc::StructNewDefault,
            Immediate::StructType(struct_type_index),
        ),
        StructGet {
            struct_type_index,
            field_index,
        } => (
            Oc::StructGet,
            Immediate::StructField {
                type_index: struct_type_index,
                field_index,
            },
        ),
        StructGetS {
            struct_type_index,
            field_index,
        } => (
            Oc::StructGetS,
            Immediate::StructField {
                type_index: struct_type_index,
                field_index,
            },
        ),
        StructGetU {
            struct_type_index,
            field_index,
        } => (
            Oc::StructGetU,
            Immediate::StructField {
                type_index: struct_type_index,
                field_index,
            },
        ),
        StructSet {
            struct_type_index,
            field_index,
        } => (
            Oc::StructSet,
            Immediate::StructField {
                type_index: struct_type_index,
                field_index,
            },
        ),
        ArrayNew {
            array_type_index,
        } => (Oc::ArrayNew, Immediate::ArrayType(array_type_index)),
        ArrayNewDefault {
            array_type_index,
        } => (Oc::ArrayNewDefault, Immediate::ArrayType(array_type_index)),
        ArrayNewFixed {
            array_type_index,
            array_size,
        } => (
            Oc::ArrayNewFixed,
            Immediate::ArrayNewFixed {
                type_index: array_type_index,
                size: array_size,
            },
        ),
        ArrayNewData {
            array_type_index,
            array_data_index,
        } => (
            Oc::ArrayNewData,
            Immediate::ArrayNewData {
                type_index: array_type_index,
                data_index: array_data_index,
            },
        ),
        ArrayNewElem {
            array_type_index,
            array_elem_index,
        } => (
            Oc::ArrayNewElem,
            Immediate::ArrayNewElem {
                type_index: array_type_index,
                elem_index: array_elem_index,
            },
        ),
        ArrayGet {
            array_type_index,
        } => (Oc::ArrayGet, Immediate::ArrayType(array_type_index)),
        ArrayGetS {
            array_type_index,
        } => (Oc::ArrayGetS, Immediate::ArrayType(array_type_index)),
        ArrayGetU {
            array_type_index,
        } => (Oc::ArrayGetU, Immediate::ArrayType(array_type_index)),
        ArraySet {
            array_type_index,
        } => (Oc::ArraySet, Immediate::ArrayType(array_type_index)),
        ArrayLen => (Oc::ArrayLen, Immediate::None),
        ArrayFill {
            array_type_index,
        } => (Oc::ArrayFill, Immediate::ArrayType(array_type_index)),
        ArrayCopy {
            array_type_index_dst,
            array_type_index_src,
        } => (
            Oc::ArrayCopy,
            Immediate::Unrecognized(format!(
                "ArrayCopy {{ array_type_index_dst: {array_type_index_dst}, array_type_index_src: {array_type_index_src} }}"
            )),
        ),
        ArrayInitData {
            array_type_index,
            array_data_index,
        } => (
            Oc::ArrayInitData,
            Immediate::ArrayNewData {
                type_index: array_type_index,
                data_index: array_data_index,
            },
        ),
        ArrayInitElem {
            array_type_index,
            array_elem_index,
        } => (
            Oc::ArrayInitElem,
            Immediate::ArrayNewElem {
                type_index: array_type_index,
                elem_index: array_elem_index,
            },
        ),
        RefTestNonNull { hty } => (
            Oc::RefTestRef,
            Immediate::Unrecognized(format!("RefTestNonNull {{ hty: {hty:?} }}")),
        ),
        RefTestNullable { hty } => (
            Oc::Unrecognized(format!("RefTestNullable {{ hty: {hty:?} }}")),
            Immediate::Unrecognized(format!("RefTestNullable {{ hty: {hty:?} }}")),
        ),
        RefCastNonNull { hty } => (
            Oc::RefCastRef,
            Immediate::Unrecognized(format!("RefCastNonNull {{ hty: {hty:?} }}")),
        ),
        RefCastNullable { hty } => (
            Oc::Unrecognized(format!("RefCastNullable {{ hty: {hty:?} }}")),
            Immediate::Unrecognized(format!("RefCastNullable {{ hty: {hty:?} }}")),
        ),
        BrOnCast {
            relative_depth,
            from_ref_type,
            to_ref_type,
        } => (
            Oc::BrOnCast,
            Immediate::BrOnCast {
                src_type: format!("{from_ref_type:?}"),
                dst_type: format!("{to_ref_type:?}"),
                label: relative_depth,
            },
        ),
        BrOnCastFail {
            relative_depth,
            from_ref_type,
            to_ref_type,
        } => (
            Oc::BrOnCastFail,
            Immediate::BrOnCast {
                src_type: format!("{from_ref_type:?}"),
                dst_type: format!("{to_ref_type:?}"),
                label: relative_depth,
            },
        ),
        AnyConvertExtern => (Oc::AnyConvertExtern, Immediate::None),
        ExternConvertAny => (Oc::ExternConvertAny, Immediate::None),
        RefI31 => (Oc::RefI31, Immediate::None),
        I31GetS => (Oc::I31GetS, Immediate::None),
        I31GetU => (Oc::I31GetU, Immediate::None),

        // ── Exceptions ──
        TryTable { try_table } => (
            Oc::TryTable,
            Immediate::Unrecognized(format!("TryTable {{ try_table: {try_table:?} }}")),
        ),
        Throw { tag_index } => (Oc::Throw, Immediate::TagIndex(tag_index)),
        ThrowRef => (Oc::ThrowRef, Immediate::None),

        // ── Legacy exceptions ──
        Try { blockty } => (
            Oc::Unrecognized(format!("Try {{ blockty: {blockty:?} }}")),
            Immediate::BlockType(format!("{blockty:?}")),
        ),
        Catch { tag_index } => (Oc::Catch, Immediate::TagIndex(tag_index)),
        Rethrow { relative_depth } => (Oc::Rethrow, Immediate::Branch(relative_depth)),
        Delegate { relative_depth } => (Oc::Delegate, Immediate::Branch(relative_depth)),
        CatchAll => (Oc::CatchAll, Immediate::None),

        // ── Reference types: TypedSelectMulti ──
        TypedSelectMulti { tys } => (
            Oc::Select,
            Immediate::SelectTypes(tys.iter().map(|t| format!("{t:?}")).collect()),
        ),

        // ── SIMD lane loads/stores ──
        V128Load8Lane { memarg, lane } => (
            Oc::V128Load8Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),
        V128Load16Lane { memarg, lane } => (
            Oc::V128Load16Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),
        V128Load32Lane { memarg, lane } => (
            Oc::V128Load32Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),
        V128Load64Lane { memarg, lane } => (
            Oc::V128Load64Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),
        V128Store8Lane { memarg, lane } => (
            Oc::V128Store8Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),
        V128Store16Lane { memarg, lane } => (
            Oc::V128Store16Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),
        V128Store32Lane { memarg, lane } => (
            Oc::V128Store32Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),
        V128Store64Lane { memarg, lane } => (
            Oc::V128Store64Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),

        // ── SIMD division / pmin / pmax ──
        F32x4Div => (Oc::F32x4Div, Immediate::None),
        F32x4PMin => (Oc::F32x4PMin, Immediate::None),
        F32x4PMax => (Oc::F32x4PMax, Immediate::None),
        F64x2Div => (Oc::F64x2Div, Immediate::None),
        F64x2PMin => (Oc::F64x2PMin, Immediate::None),
        F64x2PMax => (Oc::F64x2PMax, Immediate::None),

        // ── Relaxed SIMD ──
        I8x16RelaxedSwizzle => (Oc::I8x16RelaxedSwizzle, Immediate::None),
        I32x4RelaxedTruncF32x4S => (Oc::I32x4RelaxedTruncF32x4S, Immediate::None),
        I32x4RelaxedTruncF32x4U => (Oc::I32x4RelaxedTruncF32x4U, Immediate::None),
        I32x4RelaxedTruncF64x2SZero => (Oc::I32x4RelaxedTruncF64x2SZero, Immediate::None),
        I32x4RelaxedTruncF64x2UZero => (Oc::I32x4RelaxedTruncF64x2UZero, Immediate::None),
        F32x4RelaxedMadd => (Oc::F32x4RelaxedMadd, Immediate::None),
        F32x4RelaxedNmadd => (Oc::F32x4RelaxedNmadd, Immediate::None),
        F64x2RelaxedMadd => (Oc::F64x2RelaxedMadd, Immediate::None),
        F64x2RelaxedNmadd => (Oc::F64x2RelaxedNmadd, Immediate::None),
        I8x16RelaxedLaneselect => (Oc::I8x16RelaxedLaneselect, Immediate::None),
        I16x8RelaxedLaneselect => (Oc::I16x8RelaxedLaneselect, Immediate::None),
        I32x4RelaxedLaneselect => (Oc::I32x4RelaxedLaneselect, Immediate::None),
        I64x2RelaxedLaneselect => (Oc::I64x2RelaxedLaneselect, Immediate::None),
        F32x4RelaxedMin => (Oc::F32x4RelaxedMin, Immediate::None),
        F32x4RelaxedMax => (Oc::F32x4RelaxedMax, Immediate::None),
        F64x2RelaxedMin => (Oc::F64x2RelaxedMin, Immediate::None),
        F64x2RelaxedMax => (Oc::F64x2RelaxedMax, Immediate::None),
        I16x8RelaxedQ15mulrS => (Oc::I16x8RelaxedQ15mulrS, Immediate::None),
        I16x8RelaxedDotI8x16I7x16S => (Oc::I16x8RelaxedDotI8x16I7x16S, Immediate::None),
        I32x4RelaxedDotI8x16I7x16AddS => (Oc::I32x4RelaxedDotI8x16I7x16AddS, Immediate::None),

        // ── Catch-all for unrecognized opcodes ──
        unknown => {
            let name = extract_operator_name(&unknown);
            (Opcode::Unrecognized(name.clone()), Immediate::Unrecognized(name))
        }
    }
}

/// Extract the variant name from a wasmparser Operator for use in Unrecognized.
fn extract_operator_name(op: &Operator<'_>) -> String {
    let text = format!("{op:?}");
    if let Some((name, _)) = text.split_once(" {") {
        name.to_owned()
    } else {
        text
    }
}

// ── Helper functions ───────────────────────────────────────────────────────

fn convert_type_ref(type_ref: TypeRef, types: &[TypeIr]) -> Result<TypeRefIr, ParseError> {
    Ok(match type_ref {
        TypeRef::Func(type_index) | TypeRef::FuncExact(type_index) => TypeRefIr::Func {
            type_index,
            type_id: type_id_for_index(types, type_index)?.to_owned(),
        },
        TypeRef::Table(table) => TypeRefIr::Table(format!("{table:?}")),
        TypeRef::Memory(memory) => TypeRefIr::Memory(format!("{memory:?}")),
        TypeRef::Global(global) => TypeRefIr::Global(format!("{global:?}")),
        TypeRef::Tag(tag) => TypeRefIr::Tag(format!("{tag:?}")),
    })
}

fn external_kind_for_type_ref(type_ref: TypeRef) -> ExternalKindIr {
    match type_ref {
        TypeRef::Func(_) | TypeRef::FuncExact(_) => ExternalKindIr::Func,
        TypeRef::Table(_) => ExternalKindIr::Table,
        TypeRef::Memory(_) => ExternalKindIr::Memory,
        TypeRef::Global(_) => ExternalKindIr::Global,
        TypeRef::Tag(_) => ExternalKindIr::Tag,
    }
}

fn convert_external_kind(kind: ExternalKind) -> Result<ExternalKindIr, ParseError> {
    match kind {
        ExternalKind::Func | ExternalKind::FuncExact => Ok(ExternalKindIr::Func),
        ExternalKind::Table => Ok(ExternalKindIr::Table),
        ExternalKind::Memory => Ok(ExternalKindIr::Memory),
        ExternalKind::Global => Ok(ExternalKindIr::Global),
        ExternalKind::Tag => Ok(ExternalKindIr::Tag),
    }
}

fn type_id_for_index(types: &[TypeIr], type_index: u32) -> Result<&str, ParseError> {
    types
        .get(type_index as usize)
        .map(|ty| ty.id.as_str())
        .ok_or_else(|| ParseError::new(format!("type index {type_index} is out of bounds")))
}

fn type_id(params: &[String], results: &[String]) -> String {
    format!("type:{}->{}", params.join(","), results.join(","))
}

fn import_id(module: &str, name: &str, kind: ExternalKindIr, type_ref: &TypeRefIr) -> String {
    format!(
        "import:{}:{}:{}:{}",
        module,
        name,
        kind.as_str(),
        type_ref_id(type_ref)
    )
}

fn type_ref_id(type_ref: &TypeRefIr) -> &str {
    match type_ref {
        TypeRefIr::Func { type_id, .. } => type_id.as_str(),
        TypeRefIr::Table(id)
        | TypeRefIr::Memory(id)
        | TypeRefIr::Global(id)
        | TypeRefIr::Tag(id) => id.as_str(),
    }
}

fn checked_u32(value: usize, label: &str) -> Result<u32, ParseError> {
    u32::try_from(value).map_err(|_| ParseError::new(format!("{label} exceeds u32 range")))
}

#[cfg(test)]
mod tests {
    use super::parse_module;
    use crate::ir::{ExternalKindIr, FunctionKindIr, Opcode};
    use crate::resolve::resolve_module;

    fn make_simple_wasm(with_import: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]);
        if with_import {
            bytes.extend_from_slice(&[0x02, 0x14]);
            bytes.extend_from_slice(b"\x01\x03env\x0cimported_add\x00\x00");
        }
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        bytes.extend_from_slice(&[0x07, 0x07]);
        if with_import {
            bytes.extend_from_slice(b"\x01\x03add\x00\x01");
        } else {
            bytes.extend_from_slice(b"\x01\x03add\x00\x00");
        }
        bytes.extend_from_slice(&[
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
        ]);
        bytes
    }

    #[test]
    fn parses_old_fixture_into_parsed_ir() {
        let bytes = include_bytes!("../tests/fixtures/old.wasm");

        let module = parse_module(bytes).expect("fixture should parse");

        assert_eq!(module.types.len(), 1);
        assert_eq!(module.types[0].id, "type:i32,i32->i32");
        assert!(module.imports.is_empty());
        assert_eq!(module.exports.len(), 1);
        assert_eq!(module.exports[0].name, "add");
        assert_eq!(module.exports[0].kind, ExternalKindIr::Func);
        assert_eq!(module.functions.len(), 1);

        let function = &module.functions[0];
        assert_eq!(function.id, "type:type:i32,i32->i32:defined:0");
        assert_eq!(function.kind, FunctionKindIr::Defined);
        assert_eq!(function.source_index, 0);
        assert_eq!(function.type_id, "type:i32,i32->i32");
        assert!(function.export_names.is_empty());
        assert!(function.locals.is_empty());
        assert_eq!(function.operators.len(), 4);
        assert_eq!(function.operators[0].opcode, Opcode::LocalGet);
        assert_eq!(
            function.operators[1].display_text(),
            "LocalGet { local_index: 1 }"
        );
        assert_eq!(function.operators[2].opcode, Opcode::I32Add);
        assert_eq!(function.operators[3].opcode, Opcode::End);
        assert!(function.direct_calls.is_empty());
    }

    #[test]
    fn parses_fixture_operator_delta_deterministically() {
        let old_module = parse_module(include_bytes!("../tests/fixtures/old.wasm")).unwrap();
        let new_module = parse_module(include_bytes!("../tests/fixtures/new.wasm")).unwrap();

        let old_function = &old_module.functions[0];
        let new_function = &new_module.functions[0];

        assert_eq!(old_module.types, new_module.types);
        assert_eq!(old_module.exports, new_module.exports);
        assert_eq!(
            old_function.operators[1].display_text(),
            "LocalGet { local_index: 1 }"
        );
        assert_eq!(
            new_function.operators[1].display_text(),
            "I32Const { value: 1 }"
        );
        assert_eq!(old_function.operators[0], new_function.operators[0]);
        assert_eq!(old_function.operators[2], new_function.operators[2]);
        assert_eq!(old_function.operators[3], new_function.operators[3]);
    }

    #[test]
    fn invalid_bytes_return_clear_parser_error() {
        let error = parse_module(b"not wasm").expect_err("invalid bytes should fail");

        assert!(error.to_string().starts_with("wasm parse error:"));
    }

    #[test]
    fn stable_id_resists_index_drift() {
        let no_import = make_simple_wasm(false);
        let with_import = make_simple_wasm(true);

        let mod_no_import =
            resolve_module(parse_module(&no_import).expect("no-import module should parse"));
        let mod_with_import =
            resolve_module(parse_module(&with_import).expect("with-import module should parse"));

        assert_eq!(mod_no_import.functions.len(), 1);
        assert_eq!(mod_no_import.functions[0].source_index, 0);
        assert_eq!(
            mod_no_import.functions[0].id,
            "func:export:add:type:i32,i32->i32"
        );

        assert_eq!(mod_with_import.functions.len(), 2);
        assert_eq!(mod_with_import.functions[0].kind, FunctionKindIr::Imported);
        assert_eq!(mod_with_import.functions[0].source_index, 0);
        assert_eq!(mod_with_import.functions[1].kind, FunctionKindIr::Defined);
        assert_eq!(mod_with_import.functions[1].source_index, 1);

        assert_eq!(
            mod_no_import.functions[0].id, mod_with_import.functions[1].id,
            "stable function ID must be same despite index drift"
        );
    }

    #[test]
    fn parse_determinism_repeated_calls() {
        let bytes = make_simple_wasm(true);
        let first = parse_module(&bytes).unwrap();
        let second = parse_module(&bytes).unwrap();
        assert_eq!(
            first, second,
            "parsing same bytes must produce identical ParsedModule"
        );
    }
}
