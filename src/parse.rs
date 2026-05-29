//! Wasm binary parser frontend using wasmparser.
//! Produces Parsed IR consumed by the resolve stage.
//!
//! Transition note: Phase 1 introduces typed ParsedOperator (Opcode + Immediate)
//! replacing the old string-based OperatorIr. Phase 2 keeps parsing free of
//! stable-ID and fingerprint refresh; those now live in resolve/normalize.

use std::{error::Error, fmt};

use wasmparser::{
    ConstExpr, ElementItems, ElementKind, Encoding, ExternalKind, Operator, Parser, Payload,
    TableInit, TypeRef,
};

use crate::ir::{
    ElementIr, ElementKindIr, ExportIr, ExternalKindIr, FunctionIr, FunctionKindIr, Immediate,
    ImportIr, LocalIr, ModuleIr, Opcode, ParsedModule, ParsedOperator, TableIr, TypeIr, TypeRefIr,
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
            Payload::TableSection(section) => {
                let imported_table_count = imported_table_count(&module);
                for (source_index, table) in section.into_iter().enumerate() {
                    let table = table?;
                    let source_index = checked_u32(source_index, "table index")?;
                    let table_index =
                        imported_table_count
                            .checked_add(source_index)
                            .ok_or_else(|| {
                                ParseError::new("table index overflow while reading tables")
                            })?;
                    let (init_function_index, has_unknown_init) = convert_table_init(table.init)?;

                    module.tables.push(TableIr {
                        index: table_index,
                        source_index,
                        init_function_index,
                        has_unknown_init,
                    });
                }
            }
            Payload::StartSection { func, .. } => {
                module.start_function_index = Some(func);
            }
            Payload::ElementSection(section) => {
                for (source_index, element) in section.into_iter().enumerate() {
                    let element = element?;
                    let (kind, table_index) = convert_element_kind(element.kind);
                    let (function_indices, has_unknown_items) =
                        convert_element_items(element.items)?;
                    module.elements.push(ElementIr {
                        source_index: checked_u32(source_index, "element index")?,
                        kind,
                        table_index,
                        function_indices,
                        has_unknown_items,
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
                        convert_operator(operator, offset)
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
            | Payload::MemorySection(_)
            | Payload::TagSection(_)
            | Payload::GlobalSection(_)
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
fn convert_operator<'a>(
    operator: Operator<'a>,
    offset: usize,
) -> Result<ParsedOperator, ParseError> {
    let (opcode, immediate) = operator_to_opcode_immediate(operator)?;
    Ok(ParsedOperator {
        offset: offset as u64,
        opcode,
        immediate,
    })
}

/// Map wasmparser::Operator variants to (Opcode, Immediate).
#[allow(clippy::too_many_lines)]
fn operator_to_opcode_immediate<'a>(op: Operator<'a>) -> Result<(Opcode, Immediate), ParseError> {
    use Opcode as Oc;
    use Operator::*;

    match op {
        // ── MVP: Control flow ──
        Unreachable => Ok((Oc::Unreachable, Immediate::None),),
        Nop => Ok((Oc::Nop, Immediate::None),),
        Block { blockty } => Ok((
            Oc::Block,
            Immediate::BlockType(format!("{blockty:?}")),
        ),),
        Loop { blockty } => Ok((
            Oc::Loop,
            Immediate::BlockType(format!("{blockty:?}")),
        ),),
        If { blockty } => Ok((
            Oc::If,
            Immediate::BlockType(format!("{blockty:?}")),
        ),),
        Else => Ok((Oc::Else, Immediate::None),),
        End => Ok((Oc::End, Immediate::None),),
        Br { relative_depth } => Ok((Oc::Br, Immediate::Branch(relative_depth)),),
        BrIf { relative_depth } => Ok((Oc::BrIf, Immediate::Branch(relative_depth)),),
        BrOnNull { relative_depth } => Ok((Oc::BrOnNull, Immediate::Branch(relative_depth)),),
        BrOnNonNull { relative_depth } => Ok((Oc::BrOnNonNull, Immediate::Branch(relative_depth)),),
        BrTable { targets } => {
            let default_target = targets.default();
            let target_labels = targets
                .targets()
                .collect::<Result<Vec<_>, _>>()?;
            Ok((
                Oc::BrTable,
                Immediate::BrTable {
                    targets: target_labels,
                    default_target,
                },
            ))
        },
        Return => Ok((Oc::Return, Immediate::None),),

        // ── MVP: Calls ──
        Call { function_index } => Ok((Oc::Call, Immediate::Call(function_index)),),
        CallIndirect {
            type_index,
            table_index,
        } => Ok((
            Oc::CallIndirect,
            Immediate::CallIndirect {
                type_index,
                table_index,
            },
        ),),

        // ── MVP: Parametric ──
        Drop => Ok((Oc::Drop, Immediate::None),),
        Select => Ok((Oc::Select, Immediate::None),),

        // ── MVP: Variable ──
        LocalGet { local_index } => Ok((Oc::LocalGet, Immediate::Local(local_index)),),
        LocalSet { local_index } => Ok((Oc::LocalSet, Immediate::Local(local_index)),),
        LocalTee { local_index } => Ok((Oc::LocalTee, Immediate::Local(local_index)),),
        GlobalGet { global_index } => Ok((Oc::GlobalGet, Immediate::Global(global_index)),),
        GlobalSet { global_index } => Ok((Oc::GlobalSet, Immediate::Global(global_index)),),

        // ── MVP: Memory loads ──
        I32Load { memarg } => Ok((
            Oc::I32Load,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Load { memarg } => Ok((
            Oc::I64Load,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        F32Load { memarg } => Ok((
            Oc::F32Load,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        F64Load { memarg } => Ok((
            Oc::F64Load,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I32Load8S { memarg } => Ok((
            Oc::I32Load8S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I32Load8U { memarg } => Ok((
            Oc::I32Load8U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I32Load16S { memarg } => Ok((
            Oc::I32Load16S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I32Load16U { memarg } => Ok((
            Oc::I32Load16U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Load8S { memarg } => Ok((
            Oc::I64Load8S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Load8U { memarg } => Ok((
            Oc::I64Load8U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Load16S { memarg } => Ok((
            Oc::I64Load16S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Load16U { memarg } => Ok((
            Oc::I64Load16U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Load32S { memarg } => Ok((
            Oc::I64Load32S,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Load32U { memarg } => Ok((
            Oc::I64Load32U,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),

        // ── MVP: Memory stores ──
        I32Store { memarg } => Ok((
            Oc::I32Store,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Store { memarg } => Ok((
            Oc::I64Store,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        F32Store { memarg } => Ok((
            Oc::F32Store,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        F64Store { memarg } => Ok((
            Oc::F64Store,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I32Store8 { memarg } => Ok((
            Oc::I32Store8,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I32Store16 { memarg } => Ok((
            Oc::I32Store16,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Store8 { memarg } => Ok((
            Oc::I64Store8,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Store16 { memarg } => Ok((
            Oc::I64Store16,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),
        I64Store32 { memarg } => Ok((
            Oc::I64Store32,
            Immediate::MemArg {
                align: memarg.align as u32,
                offset: memarg.offset,
            },
        ),),

        // ── MVP: Memory misc ──
        MemorySize { mem } => Ok((Oc::MemorySize, Immediate::MemoryIndex(mem)),),
        MemoryGrow { mem } => Ok((Oc::MemoryGrow, Immediate::MemoryIndex(mem)),),

        // ── MVP: Constants ──
        I32Const { value } => Ok((Oc::I32Const, Immediate::I32Const(value)),),
        I64Const { value } => Ok((Oc::I64Const, Immediate::I64Const(value)),),
        F32Const { value } => Ok((
            Oc::F32Const,
            Immediate::F32Const(value.bits()),
        ),),
        F64Const { value } => Ok((
            Oc::F64Const,
            Immediate::F64Const(value.bits()),
        ),),

        // ── MVP: i32 test ──
        I32Eqz => Ok((Oc::I32Eqz, Immediate::None),),
        I32Eq => Ok((Oc::I32Eq, Immediate::None),),
        I32Ne => Ok((Oc::I32Ne, Immediate::None),),
        I32LtS => Ok((Oc::I32LtS, Immediate::None),),
        I32LtU => Ok((Oc::I32LtU, Immediate::None),),
        I32GtS => Ok((Oc::I32GtS, Immediate::None),),
        I32GtU => Ok((Oc::I32GtU, Immediate::None),),
        I32LeS => Ok((Oc::I32LeS, Immediate::None),),
        I32LeU => Ok((Oc::I32LeU, Immediate::None),),
        I32GeS => Ok((Oc::I32GeS, Immediate::None),),
        I32GeU => Ok((Oc::I32GeU, Immediate::None),),

        // ── MVP: i64 test ──
        I64Eqz => Ok((Oc::I64Eqz, Immediate::None),),
        I64Eq => Ok((Oc::I64Eq, Immediate::None),),
        I64Ne => Ok((Oc::I64Ne, Immediate::None),),
        I64LtS => Ok((Oc::I64LtS, Immediate::None),),
        I64LtU => Ok((Oc::I64LtU, Immediate::None),),
        I64GtS => Ok((Oc::I64GtS, Immediate::None),),
        I64GtU => Ok((Oc::I64GtU, Immediate::None),),
        I64LeS => Ok((Oc::I64LeS, Immediate::None),),
        I64LeU => Ok((Oc::I64LeU, Immediate::None),),
        I64GeS => Ok((Oc::I64GeS, Immediate::None),),
        I64GeU => Ok((Oc::I64GeU, Immediate::None),),

        // ── MVP: f32 test ──
        F32Eq => Ok((Oc::F32Eq, Immediate::None),),
        F32Ne => Ok((Oc::F32Ne, Immediate::None),),
        F32Lt => Ok((Oc::F32Lt, Immediate::None),),
        F32Gt => Ok((Oc::F32Gt, Immediate::None),),
        F32Le => Ok((Oc::F32Le, Immediate::None),),
        F32Ge => Ok((Oc::F32Ge, Immediate::None),),

        // ── MVP: f64 test ──
        F64Eq => Ok((Oc::F64Eq, Immediate::None),),
        F64Ne => Ok((Oc::F64Ne, Immediate::None),),
        F64Lt => Ok((Oc::F64Lt, Immediate::None),),
        F64Gt => Ok((Oc::F64Gt, Immediate::None),),
        F64Le => Ok((Oc::F64Le, Immediate::None),),
        F64Ge => Ok((Oc::F64Ge, Immediate::None),),

        // ── MVP: i32 unary ──
        I32Clz => Ok((Oc::I32Clz, Immediate::None),),
        I32Ctz => Ok((Oc::I32Ctz, Immediate::None),),
        I32Popcnt => Ok((Oc::I32Popcnt, Immediate::None),),

        // ── MVP: i64 unary ──
        I64Clz => Ok((Oc::I64Clz, Immediate::None),),
        I64Ctz => Ok((Oc::I64Ctz, Immediate::None),),
        I64Popcnt => Ok((Oc::I64Popcnt, Immediate::None),),

        // ── MVP: f32 unary ──
        F32Abs => Ok((Oc::F32Abs, Immediate::None),),
        F32Neg => Ok((Oc::F32Neg, Immediate::None),),
        F32Ceil => Ok((Oc::F32Ceil, Immediate::None),),
        F32Floor => Ok((Oc::F32Floor, Immediate::None),),
        F32Trunc => Ok((Oc::F32Trunc, Immediate::None),),
        F32Nearest => Ok((Oc::F32Nearest, Immediate::None),),
        F32Sqrt => Ok((Oc::F32Sqrt, Immediate::None),),

        // ── MVP: f64 unary ──
        F64Abs => Ok((Oc::F64Abs, Immediate::None),),
        F64Neg => Ok((Oc::F64Neg, Immediate::None),),
        F64Ceil => Ok((Oc::F64Ceil, Immediate::None),),
        F64Floor => Ok((Oc::F64Floor, Immediate::None),),
        F64Trunc => Ok((Oc::F64Trunc, Immediate::None),),
        F64Nearest => Ok((Oc::F64Nearest, Immediate::None),),
        F64Sqrt => Ok((Oc::F64Sqrt, Immediate::None),),

        // ── MVP: i32 binary ──
        I32Add => Ok((Oc::I32Add, Immediate::None),),
        I32Sub => Ok((Oc::I32Sub, Immediate::None),),
        I32Mul => Ok((Oc::I32Mul, Immediate::None),),
        I32DivS => Ok((Oc::I32DivS, Immediate::None),),
        I32DivU => Ok((Oc::I32DivU, Immediate::None),),
        I32RemS => Ok((Oc::I32RemS, Immediate::None),),
        I32RemU => Ok((Oc::I32RemU, Immediate::None),),
        I32And => Ok((Oc::I32And, Immediate::None),),
        I32Or => Ok((Oc::I32Or, Immediate::None),),
        I32Xor => Ok((Oc::I32Xor, Immediate::None),),
        I32Shl => Ok((Oc::I32Shl, Immediate::None),),
        I32ShrS => Ok((Oc::I32ShrS, Immediate::None),),
        I32ShrU => Ok((Oc::I32ShrU, Immediate::None),),
        I32Rotl => Ok((Oc::I32Rotl, Immediate::None),),
        I32Rotr => Ok((Oc::I32Rotr, Immediate::None),),

        // ── MVP: i64 binary ──
        I64Add => Ok((Oc::I64Add, Immediate::None),),
        I64Sub => Ok((Oc::I64Sub, Immediate::None),),
        I64Mul => Ok((Oc::I64Mul, Immediate::None),),
        I64DivS => Ok((Oc::I64DivS, Immediate::None),),
        I64DivU => Ok((Oc::I64DivU, Immediate::None),),
        I64RemS => Ok((Oc::I64RemS, Immediate::None),),
        I64RemU => Ok((Oc::I64RemU, Immediate::None),),
        I64And => Ok((Oc::I64And, Immediate::None),),
        I64Or => Ok((Oc::I64Or, Immediate::None),),
        I64Xor => Ok((Oc::I64Xor, Immediate::None),),
        I64Shl => Ok((Oc::I64Shl, Immediate::None),),
        I64ShrS => Ok((Oc::I64ShrS, Immediate::None),),
        I64ShrU => Ok((Oc::I64ShrU, Immediate::None),),
        I64Rotl => Ok((Oc::I64Rotl, Immediate::None),),
        I64Rotr => Ok((Oc::I64Rotr, Immediate::None),),

        // ── MVP: f32 binary ──
        F32Add => Ok((Oc::F32Add, Immediate::None),),
        F32Sub => Ok((Oc::F32Sub, Immediate::None),),
        F32Mul => Ok((Oc::F32Mul, Immediate::None),),
        F32Div => Ok((Oc::F32Div, Immediate::None),),
        F32Min => Ok((Oc::F32Min, Immediate::None),),
        F32Max => Ok((Oc::F32Max, Immediate::None),),
        F32Copysign => Ok((Oc::F32Copysign, Immediate::None),),

        // ── MVP: f64 binary ──
        F64Add => Ok((Oc::F64Add, Immediate::None),),
        F64Sub => Ok((Oc::F64Sub, Immediate::None),),
        F64Mul => Ok((Oc::F64Mul, Immediate::None),),
        F64Div => Ok((Oc::F64Div, Immediate::None),),
        F64Min => Ok((Oc::F64Min, Immediate::None),),
        F64Max => Ok((Oc::F64Max, Immediate::None),),
        F64Copysign => Ok((Oc::F64Copysign, Immediate::None),),

        // ── MVP: Conversions ──
        I32WrapI64 => Ok((Oc::I32WrapI64, Immediate::None),),
        I32TruncF32S => Ok((Oc::I32TruncF32S, Immediate::None),),
        I32TruncF32U => Ok((Oc::I32TruncF32U, Immediate::None),),
        I32TruncF64S => Ok((Oc::I32TruncF64S, Immediate::None),),
        I32TruncF64U => Ok((Oc::I32TruncF64U, Immediate::None),),
        I64ExtendI32S => Ok((Oc::I64ExtendI32S, Immediate::None),),
        I64ExtendI32U => Ok((Oc::I64ExtendI32U, Immediate::None),),
        I64TruncF32S => Ok((Oc::I64TruncF32S, Immediate::None),),
        I64TruncF32U => Ok((Oc::I64TruncF32U, Immediate::None),),
        I64TruncF64S => Ok((Oc::I64TruncF64S, Immediate::None),),
        I64TruncF64U => Ok((Oc::I64TruncF64U, Immediate::None),),
        F32ConvertI32S => Ok((Oc::F32ConvertI32S, Immediate::None),),
        F32ConvertI32U => Ok((Oc::F32ConvertI32U, Immediate::None),),
        F32ConvertI64S => Ok((Oc::F32ConvertI64S, Immediate::None),),
        F32ConvertI64U => Ok((Oc::F32ConvertI64U, Immediate::None),),
        F32DemoteF64 => Ok((Oc::F32DemoteF64, Immediate::None),),
        F64ConvertI32S => Ok((Oc::F64ConvertI32S, Immediate::None),),
        F64ConvertI32U => Ok((Oc::F64ConvertI32U, Immediate::None),),
        F64ConvertI64S => Ok((Oc::F64ConvertI64S, Immediate::None),),
        F64ConvertI64U => Ok((Oc::F64ConvertI64U, Immediate::None),),
        F64PromoteF32 => Ok((Oc::F64PromoteF32, Immediate::None),),
        I32ReinterpretF32 => Ok((Oc::I32ReinterpretF32, Immediate::None),),
        I64ReinterpretF64 => Ok((Oc::I64ReinterpretF64, Immediate::None),),
        F32ReinterpretI32 => Ok((Oc::F32ReinterpretI32, Immediate::None),),
        F64ReinterpretI64 => Ok((Oc::F64ReinterpretI64, Immediate::None),),

        // ── Sign extension ──
        I32Extend8S => Ok((Oc::I32Extend8S, Immediate::None),),
        I32Extend16S => Ok((Oc::I32Extend16S, Immediate::None),),
        I64Extend8S => Ok((Oc::I64Extend8S, Immediate::None),),
        I64Extend16S => Ok((Oc::I64Extend16S, Immediate::None),),
        I64Extend32S => Ok((Oc::I64Extend32S, Immediate::None),),

        // ── Saturating float-to-int ──
        I32TruncSatF32S => Ok((Oc::I32TruncSatF32S, Immediate::None),),
        I32TruncSatF32U => Ok((Oc::I32TruncSatF32U, Immediate::None),),
        I32TruncSatF64S => Ok((Oc::I32TruncSatF64S, Immediate::None),),
        I32TruncSatF64U => Ok((Oc::I32TruncSatF64U, Immediate::None),),
        I64TruncSatF32S => Ok((Oc::I64TruncSatF32S, Immediate::None),),
        I64TruncSatF32U => Ok((Oc::I64TruncSatF32U, Immediate::None),),
        I64TruncSatF64S => Ok((Oc::I64TruncSatF64S, Immediate::None),),
        I64TruncSatF64U => Ok((Oc::I64TruncSatF64U, Immediate::None),),

        // ── Bulk memory ──
        MemoryInit { data_index, mem: _mem } => Ok((
            Oc::MemoryInit,
            Immediate::DataIndex(data_index),
        ),),
        DataDrop { data_index } => Ok((
            Oc::DataDrop,
            Immediate::DataIndex(data_index),
        ),),
        MemoryCopy {
            dst_mem,
            src_mem,
        } => Ok((
            Oc::MemoryCopy,
            Immediate::MemoryCopy {
                dst_index: dst_mem,
                src_index: src_mem,
            },
        ),),
        MemoryFill { mem } => Ok((Oc::MemoryFill, Immediate::MemoryIndex(mem)),),
        TableInit {
            elem_index,
            table: _table,
        } => Ok((Oc::TableInit, Immediate::ElemIndex(elem_index)),),
        ElemDrop { elem_index } => Ok((Oc::ElemDrop, Immediate::ElemIndex(elem_index)),),
        TableCopy {
            dst_table,
            src_table,
        } => Ok((
            Oc::TableCopy,
            Immediate::TableCopy {
                dst_table,
                src_table,
            },
        ),),

        // ── Reference types ──
        RefNull { hty } => Ok((Oc::RefNull, Immediate::RefNull(format!("{hty:?}"))),),
        RefIsNull => Ok((Oc::RefIsNull, Immediate::None),),
        RefFunc { function_index } => Ok((Oc::RefFunc, Immediate::RefFunc(function_index)),),
        TypedSelect { .. } => Ok((Oc::Select, Immediate::SelectTypes(vec![])),),
        TableFill { table } => Ok((Oc::TableFill, Immediate::TableIndex(table)),),
        TableGet { table } => Ok((Oc::TableGet, Immediate::TableIndex(table)),),
        TableSet { table } => Ok((Oc::TableSet, Immediate::TableIndex(table)),),
        TableGrow { table } => Ok((Oc::TableGrow, Immediate::TableIndex(table)),),
        TableSize { table } => Ok((Oc::TableSize, Immediate::TableIndex(table)),),

        // ── Tail call ──
        ReturnCall { function_index } => Ok((Oc::ReturnCall, Immediate::Call(function_index)),),
        ReturnCallIndirect {
            type_index,
            table_index,
        } => Ok((
            Oc::ReturnCallIndirect,
            Immediate::CallIndirect {
                type_index,
                table_index,
            },
        ),),

        // ── GC ──
        RefEq => Ok((Oc::RefEq, Immediate::None),),
        StructNew {
            struct_type_index,
        } => Ok((Oc::StructNew, Immediate::StructType(struct_type_index)),),
        StructNewDefault {
            struct_type_index,
        } => Ok((
            Oc::StructNewDefault,
            Immediate::StructType(struct_type_index),
        ),),
        StructGet {
            struct_type_index,
            field_index,
        } => Ok((
            Oc::StructGet,
            Immediate::StructField {
                type_index: struct_type_index,
                field_index,
            },
        ),),
        StructGetS {
            struct_type_index,
            field_index,
        } => Ok((
            Oc::StructGetS,
            Immediate::StructField {
                type_index: struct_type_index,
                field_index,
            },
        ),),
        StructGetU {
            struct_type_index,
            field_index,
        } => Ok((
            Oc::StructGetU,
            Immediate::StructField {
                type_index: struct_type_index,
                field_index,
            },
        ),),
        StructSet {
            struct_type_index,
            field_index,
        } => Ok((
            Oc::StructSet,
            Immediate::StructField {
                type_index: struct_type_index,
                field_index,
            },
        ),),
        ArrayNew {
            array_type_index,
        } => Ok((Oc::ArrayNew, Immediate::ArrayType(array_type_index)),),
        ArrayNewDefault {
            array_type_index,
        } => Ok((Oc::ArrayNewDefault, Immediate::ArrayType(array_type_index)),),
        ArrayNewFixed {
            array_type_index,
            array_size,
        } => Ok((
            Oc::ArrayNewFixed,
            Immediate::ArrayNewFixed {
                type_index: array_type_index,
                size: array_size,
            },
        ),),
        ArrayNewData {
            array_type_index,
            array_data_index,
        } => Ok((
            Oc::ArrayNewData,
            Immediate::ArrayNewData {
                type_index: array_type_index,
                data_index: array_data_index,
            },
        ),),
        ArrayNewElem {
            array_type_index,
            array_elem_index,
        } => Ok((
            Oc::ArrayNewElem,
            Immediate::ArrayNewElem {
                type_index: array_type_index,
                elem_index: array_elem_index,
            },
        ),),
        ArrayGet {
            array_type_index,
        } => Ok((Oc::ArrayGet, Immediate::ArrayType(array_type_index)),),
        ArrayGetS {
            array_type_index,
        } => Ok((Oc::ArrayGetS, Immediate::ArrayType(array_type_index)),),
        ArrayGetU {
            array_type_index,
        } => Ok((Oc::ArrayGetU, Immediate::ArrayType(array_type_index)),),
        ArraySet {
            array_type_index,
        } => Ok((Oc::ArraySet, Immediate::ArrayType(array_type_index)),),
        ArrayLen => Ok((Oc::ArrayLen, Immediate::None),),
        ArrayFill {
            array_type_index,
        } => Ok((Oc::ArrayFill, Immediate::ArrayType(array_type_index)),),
        ArrayCopy {
            array_type_index_dst,
            array_type_index_src,
        } => Ok((
            Oc::ArrayCopy,
            Immediate::Unrecognized(format!(
                "ArrayCopy {{ array_type_index_dst: {array_type_index_dst}, array_type_index_src: {array_type_index_src} }}"
            )),
        ),),
        ArrayInitData {
            array_type_index,
            array_data_index,
        } => Ok((
            Oc::ArrayInitData,
            Immediate::ArrayNewData {
                type_index: array_type_index,
                data_index: array_data_index,
            },
        ),),
        ArrayInitElem {
            array_type_index,
            array_elem_index,
        } => Ok((
            Oc::ArrayInitElem,
            Immediate::ArrayNewElem {
                type_index: array_type_index,
                elem_index: array_elem_index,
            },
        ),),
        RefTestNonNull { hty } => Ok((
            Oc::RefTestRef,
            Immediate::Unrecognized(format!("RefTestNonNull {{ hty: {hty:?} }}")),
        ),),
        RefTestNullable { hty } => Ok((
            Oc::Unrecognized(format!("RefTestNullable {{ hty: {hty:?} }}")),
            Immediate::Unrecognized(format!("RefTestNullable {{ hty: {hty:?} }}")),
        ),),
        RefCastNonNull { hty } => Ok((
            Oc::RefCastRef,
            Immediate::Unrecognized(format!("RefCastNonNull {{ hty: {hty:?} }}")),
        ),),
        RefCastNullable { hty } => Ok((
            Oc::Unrecognized(format!("RefCastNullable {{ hty: {hty:?} }}")),
            Immediate::Unrecognized(format!("RefCastNullable {{ hty: {hty:?} }}")),
        ),),
        BrOnCast {
            relative_depth,
            from_ref_type,
            to_ref_type,
        } => Ok((
            Oc::BrOnCast,
            Immediate::BrOnCast {
                src_type: format!("{from_ref_type:?}"),
                dst_type: format!("{to_ref_type:?}"),
                label: relative_depth,
            },
        ),),
        BrOnCastFail {
            relative_depth,
            from_ref_type,
            to_ref_type,
        } => Ok((
            Oc::BrOnCastFail,
            Immediate::BrOnCast {
                src_type: format!("{from_ref_type:?}"),
                dst_type: format!("{to_ref_type:?}"),
                label: relative_depth,
            },
        ),),
        AnyConvertExtern => Ok((Oc::AnyConvertExtern, Immediate::None),),
        ExternConvertAny => Ok((Oc::ExternConvertAny, Immediate::None),),
        RefI31 => Ok((Oc::RefI31, Immediate::None),),
        I31GetS => Ok((Oc::I31GetS, Immediate::None),),
        I31GetU => Ok((Oc::I31GetU, Immediate::None),),

        // ── Exceptions ──
        TryTable { try_table } => Ok((
            Oc::TryTable,
            Immediate::Unrecognized(format!("TryTable {{ try_table: {try_table:?} }}")),
        ),),
        Throw { tag_index } => Ok((Oc::Throw, Immediate::TagIndex(tag_index)),),
        ThrowRef => Ok((Oc::ThrowRef, Immediate::None),),

        // ── Legacy exceptions ──
        Try { blockty } => Ok((
            Oc::Unrecognized(format!("Try {{ blockty: {blockty:?} }}")),
            Immediate::BlockType(format!("{blockty:?}")),
        ),),
        Catch { tag_index } => Ok((Oc::Catch, Immediate::TagIndex(tag_index)),),
        Rethrow { relative_depth } => Ok((Oc::Rethrow, Immediate::Branch(relative_depth)),),
        Delegate { relative_depth } => Ok((Oc::Delegate, Immediate::Branch(relative_depth)),),
        CatchAll => Ok((Oc::CatchAll, Immediate::None),),

        // ── Reference types: TypedSelectMulti ──
        TypedSelectMulti { tys } => Ok((
            Oc::Select,
            Immediate::SelectTypes(tys.iter().map(|t| format!("{t:?}")).collect()),
        ),),

        // ── SIMD lane loads/stores ──
        V128Load8Lane { memarg, lane } => Ok((
            Oc::V128Load8Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),),
        V128Load16Lane { memarg, lane } => Ok((
            Oc::V128Load16Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),),
        V128Load32Lane { memarg, lane } => Ok((
            Oc::V128Load32Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),),
        V128Load64Lane { memarg, lane } => Ok((
            Oc::V128Load64Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),),
        V128Store8Lane { memarg, lane } => Ok((
            Oc::V128Store8Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),),
        V128Store16Lane { memarg, lane } => Ok((
            Oc::V128Store16Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),),
        V128Store32Lane { memarg, lane } => Ok((
            Oc::V128Store32Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),),
        V128Store64Lane { memarg, lane } => Ok((
            Oc::V128Store64Lane,
            Immediate::SimdMemLane {
                align: memarg.align as u32,
                offset: memarg.offset,
                lane,
            },
        ),),

        // ── SIMD division / pmin / pmax ──
        F32x4Div => Ok((Oc::F32x4Div, Immediate::None),),
        F32x4PMin => Ok((Oc::F32x4PMin, Immediate::None),),
        F32x4PMax => Ok((Oc::F32x4PMax, Immediate::None),),
        F64x2Div => Ok((Oc::F64x2Div, Immediate::None),),
        F64x2PMin => Ok((Oc::F64x2PMin, Immediate::None),),
        F64x2PMax => Ok((Oc::F64x2PMax, Immediate::None),),

        // ── Relaxed SIMD ──
        I8x16RelaxedSwizzle => Ok((Oc::I8x16RelaxedSwizzle, Immediate::None),),
        I32x4RelaxedTruncF32x4S => Ok((Oc::I32x4RelaxedTruncF32x4S, Immediate::None),),
        I32x4RelaxedTruncF32x4U => Ok((Oc::I32x4RelaxedTruncF32x4U, Immediate::None),),
        I32x4RelaxedTruncF64x2SZero => Ok((Oc::I32x4RelaxedTruncF64x2SZero, Immediate::None),),
        I32x4RelaxedTruncF64x2UZero => Ok((Oc::I32x4RelaxedTruncF64x2UZero, Immediate::None),),
        F32x4RelaxedMadd => Ok((Oc::F32x4RelaxedMadd, Immediate::None),),
        F32x4RelaxedNmadd => Ok((Oc::F32x4RelaxedNmadd, Immediate::None),),
        F64x2RelaxedMadd => Ok((Oc::F64x2RelaxedMadd, Immediate::None),),
        F64x2RelaxedNmadd => Ok((Oc::F64x2RelaxedNmadd, Immediate::None),),
        I8x16RelaxedLaneselect => Ok((Oc::I8x16RelaxedLaneselect, Immediate::None),),
        I16x8RelaxedLaneselect => Ok((Oc::I16x8RelaxedLaneselect, Immediate::None),),
        I32x4RelaxedLaneselect => Ok((Oc::I32x4RelaxedLaneselect, Immediate::None),),
        I64x2RelaxedLaneselect => Ok((Oc::I64x2RelaxedLaneselect, Immediate::None),),
        F32x4RelaxedMin => Ok((Oc::F32x4RelaxedMin, Immediate::None),),
        F32x4RelaxedMax => Ok((Oc::F32x4RelaxedMax, Immediate::None),),
        F64x2RelaxedMin => Ok((Oc::F64x2RelaxedMin, Immediate::None),),
        F64x2RelaxedMax => Ok((Oc::F64x2RelaxedMax, Immediate::None),),
        I16x8RelaxedQ15mulrS => Ok((Oc::I16x8RelaxedQ15mulrS, Immediate::None),),
        I16x8RelaxedDotI8x16I7x16S => Ok((Oc::I16x8RelaxedDotI8x16I7x16S, Immediate::None),),
        I32x4RelaxedDotI8x16I7x16AddS => Ok((Oc::I32x4RelaxedDotI8x16I7x16AddS, Immediate::None),),

        // ── Catch-all for unrecognized opcodes ──
        unknown => {
            let name = extract_operator_name(&unknown);
            Ok((Opcode::Unrecognized(name.clone()), Immediate::Unrecognized(name)))
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

fn convert_table_init(init: TableInit<'_>) -> Result<(Option<u32>, bool), ParseError> {
    match init {
        TableInit::RefNull => Ok((None, false)),
        TableInit::Expr(expr) => match const_expr_function_index(expr)? {
            ConstExprFunctionRef::Function(index) => Ok((Some(index), false)),
            ConstExprFunctionRef::Null => Ok((None, false)),
            ConstExprFunctionRef::Unknown => Ok((None, true)),
        },
    }
}

fn convert_element_kind(kind: ElementKind<'_>) -> (ElementKindIr, Option<u32>) {
    match kind {
        ElementKind::Active { table_index, .. } => {
            (ElementKindIr::Active, Some(table_index.unwrap_or(0)))
        }
        ElementKind::Passive => (ElementKindIr::Passive, None),
        ElementKind::Declared => (ElementKindIr::Declared, None),
    }
}

fn convert_element_items(items: ElementItems<'_>) -> Result<(Vec<u32>, bool), ParseError> {
    let mut function_indices = Vec::new();
    let mut has_unknown_items = false;

    match items {
        ElementItems::Functions(functions) => {
            for function in functions {
                function_indices.push(function?);
            }
        }
        ElementItems::Expressions(_, expressions) => {
            for expression in expressions {
                match const_expr_function_index(expression?)? {
                    ConstExprFunctionRef::Function(index) => function_indices.push(index),
                    ConstExprFunctionRef::Null => {}
                    ConstExprFunctionRef::Unknown => has_unknown_items = true,
                }
            }
        }
    }

    Ok((function_indices, has_unknown_items))
}

enum ConstExprFunctionRef {
    Function(u32),
    Null,
    Unknown,
}

fn const_expr_function_index(expr: ConstExpr<'_>) -> Result<ConstExprFunctionRef, ParseError> {
    let mut saw_null = false;

    for operator in expr.get_operators_reader() {
        match operator? {
            Operator::RefFunc { function_index } => {
                return Ok(ConstExprFunctionRef::Function(function_index));
            }
            Operator::RefNull { .. } => saw_null = true,
            Operator::End => {}
            _ => return Ok(ConstExprFunctionRef::Unknown),
        }
    }

    if saw_null {
        Ok(ConstExprFunctionRef::Null)
    } else {
        Ok(ConstExprFunctionRef::Unknown)
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

fn imported_table_count(module: &ModuleIr) -> u32 {
    module
        .imports
        .iter()
        .filter(|import| import.kind == ExternalKindIr::Table)
        .count() as u32
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
        assert_eq!(module.start_function_index, None);

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
    fn parses_start_section_into_parsed_ir() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]);
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        bytes.extend_from_slice(&[0x08, 0x01, 0x00]);
        bytes.extend_from_slice(&[
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
        ]);

        let module = parse_module(&bytes).expect("start module should parse");

        assert_eq!(module.start_function_index, Some(0));
        assert_eq!(module.functions.len(), 1);
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

    #[test]
    fn parse_br_table_preserves_targets() {
        // Minimal wasm module with a single br_table instruction:
        //   br_table 2(targets=0,1) default=2
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // Type section: (func () -> ())
        bytes.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        // Function section: 1 function uses type 0
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        // Code section: 1 body, br_table count=2, targets=[0,1], default=2, end
        bytes.extend_from_slice(&[
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x0e, 0x02, 0x00, 0x01, 0x02, 0x0b,
        ]);

        let module = parse_module(&bytes).expect("valid br_table module should parse");
        assert_eq!(module.functions.len(), 1);
        let func = &module.functions[0];
        assert_eq!(func.operators.len(), 2); // br_table + end
        assert_eq!(func.operators[0].opcode, Opcode::BrTable);
        match &func.operators[0].immediate {
            crate::ir::Immediate::BrTable {
                targets,
                default_target,
            } => {
                assert_eq!(targets, &vec![0_u32, 1_u32]);
                assert_eq!(*default_target, 2_u32);
            }
            other => panic!("expected BrTable immediate, got {other:?}"),
        }
    }

    #[test]
    fn parse_malformed_br_table_fails() {
        // Truncated br_table: count says 2 targets but body ends after 1 target byte.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // Type section: (func () -> ())
        bytes.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        // Function section: 1 function uses type 0
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        // Code section: truncated br_table (count=2, only 1 target byte provided)
        bytes.extend_from_slice(&[0x0a, 0x06, 0x01, 0x04, 0x00, 0x0e, 0x02, 0x00]);

        let error = parse_module(&bytes).expect_err("malformed br_table should fail");
        assert!(
            error.to_string().starts_with("wasm parse error:"),
            "error should be a ParseError: {error}"
        );
    }
}
