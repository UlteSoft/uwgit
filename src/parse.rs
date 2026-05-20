//! Wasm binary parser frontend using wasmparser.
//! Produces a stable ModuleIR consumed by the inspect and diff pipelines.

use std::{error::Error, fmt};

use wasmparser::{Encoding, ExternalKind, Operator, Parser, Payload, TypeRef};

use crate::fingerprint::{module_fingerprints, stable_function_id};
use crate::ir::{
    ExportIr, ExternalKindIr, FunctionIr, FunctionKindIr, ImportIr, LocalIr, ModuleIr, OperatorIr,
    TypeIr, TypeRefIr,
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

pub fn parse_module(bytes: &[u8]) -> Result<ModuleIr, ParseError> {
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
                function.direct_calls = operators
                    .iter()
                    .filter_map(|operator| direct_call_target(&operator.text))
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

    attach_function_exports(&mut module);
    refresh_function_stable_ids(&mut module);
    refresh_function_fingerprints(&mut module);
    Ok(module)
}

fn convert_operator(operator: Operator<'_>, offset: usize) -> OperatorIr {
    let text = format!("{operator:?}");
    OperatorIr {
        offset: offset as u64,
        kind: operator_kind(&text),
        text,
    }
}

fn operator_kind(text: &str) -> String {
    text.split_once(" {")
        .map_or(text, |(kind, _)| kind)
        .to_owned()
}

fn direct_call_target(text: &str) -> Option<u32> {
    let rest = text.strip_prefix("Call { function_index: ")?;
    let index = rest.strip_suffix(" }")?;
    index.parse().ok()
}

fn attach_function_exports(module: &mut ModuleIr) {
    for export in &module.exports {
        if export.kind != ExternalKindIr::Func {
            continue;
        }
        if let Some(function) = module.functions.get_mut(export.item_index as usize) {
            function.export_names.push(export.name.clone());
        }
    }
    for function in &mut module.functions {
        function.export_names.sort();
    }
}

fn refresh_function_stable_ids(module: &mut ModuleIr) {
    let ids = module
        .functions
        .iter()
        .map(|function| stable_function_id(module, function))
        .collect::<Vec<_>>();

    for (function, id) in module.functions.iter_mut().zip(ids) {
        function.id = id;
    }
}

fn refresh_function_fingerprints(module: &mut ModuleIr) {
    let fingerprints = module_fingerprints(module);

    for (function, fingerprint) in module.functions.iter_mut().zip(fingerprints) {
        function.fingerprint = Some(fingerprint);
    }
}

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
    use crate::ir::{ExternalKindIr, FunctionKindIr};

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
    fn parses_old_fixture_into_module_ir() {
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
        assert_eq!(function.id, "func:export:add:type:i32,i32->i32");
        assert_eq!(function.kind, FunctionKindIr::Defined);
        assert_eq!(function.source_index, 0);
        assert_eq!(function.type_id, "type:i32,i32->i32");
        assert_eq!(function.export_names, ["add"]);
        assert!(function.locals.is_empty());
        assert_eq!(function.operators.len(), 4);
        assert_eq!(function.operators[0].kind, "LocalGet");
        assert_eq!(function.operators[1].text, "LocalGet { local_index: 1 }");
        assert_eq!(function.operators[2].kind, "I32Add");
        assert_eq!(function.operators[3].kind, "End");
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
            old_function.operators[1].text,
            "LocalGet { local_index: 1 }"
        );
        assert_eq!(new_function.operators[1].text, "I32Const { value: 1 }");
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

        let mod_no_import = parse_module(&no_import).expect("no-import module should parse");
        let mod_with_import = parse_module(&with_import).expect("with-import module should parse");

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
            "parsing same bytes must produce identical ModuleIr"
        );
    }
}
