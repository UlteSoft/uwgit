//! Internal representation of a Wasm module with stable identifiers.
//! Types, imports, exports, functions, and code bodies are stored with
//! deterministic IDs that do not depend on raw Wasm binary indices.

use serde::Serialize;

use crate::fingerprint::FuncFingerprint;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ModuleIr {
    pub types: Vec<TypeIr>,
    pub imports: Vec<ImportIr>,
    pub exports: Vec<ExportIr>,
    pub functions: Vec<FunctionIr>,
}

impl ModuleIr {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeIr {
    pub id: String,
    pub source_index: u32,
    pub params: Vec<String>,
    pub results: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportIr {
    pub id: String,
    pub source_index: u32,
    pub module: String,
    pub name: String,
    pub kind: ExternalKindIr,
    pub type_ref: TypeRefIr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportIr {
    pub id: String,
    pub source_index: u32,
    pub name: String,
    pub kind: ExternalKindIr,
    pub item_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionIr {
    pub id: String,
    pub source_index: u32,
    pub type_index: u32,
    pub type_id: String,
    pub kind: FunctionKindIr,
    pub export_names: Vec<String>,
    pub locals: Vec<LocalIr>,
    pub operators: Vec<OperatorIr>,
    pub direct_calls: Vec<u32>,
    pub fingerprint: Option<FuncFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FunctionKindIr {
    Imported,
    Defined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalIr {
    pub count: u32,
    pub value_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorIr {
    pub offset: u64,
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExternalKindIr {
    Func,
    Table,
    Memory,
    Global,
    Tag,
}

impl ExternalKindIr {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalKindIr::Func => "func",
            ExternalKindIr::Table => "table",
            ExternalKindIr::Memory => "memory",
            ExternalKindIr::Global => "global",
            ExternalKindIr::Tag => "tag",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TypeRefIr {
    Func { type_index: u32, type_id: String },
    Table(String),
    Memory(String),
    Global(String),
    Tag(String),
}
