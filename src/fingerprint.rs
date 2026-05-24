//! Deterministic function fingerprints for exact-body and canonical-body matching.
//! Used as input to the matcher module for stable diff comparison.
//!
//! Phase 1: fingerprint calculation now uses typed ParsedOperator (Opcode + Immediate)
//! instead of parsing wasmparser Debug strings.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::json;

use crate::ir::{FunctionIr, FunctionKindIr, Immediate, ModuleIr, ParsedOperator, ResolvedModule};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct FingerprintHash(#[serde(serialize_with = "serialize_fingerprint_hash")] u64);

fn serialize_fingerprint_hash<S: serde::Serializer>(
    value: &u64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{:016x}", value))
}

impl FingerprintHash {
    pub fn hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FuncFingerprint {
    pub stable_id: String,
    pub type_sig_hash: FingerprintHash,
    pub exact_body_hash: FingerprintHash,
    pub canonical_body_hash: FingerprintHash,
    pub opcode_histogram: Vec<OpcodeCount>,
    pub direct_call_targets: Vec<StableFuncRef>,
    pub instruction_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpcodeCount {
    pub opcode: String,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct StableFuncRef {
    pub stable_id: String,
}

pub fn module_fingerprints(module: &ResolvedModule) -> Vec<FuncFingerprint> {
    module
        .functions
        .iter()
        .map(|function| function_fingerprint(&module.module, function))
        .collect()
}

pub fn function_fingerprint(module: &ModuleIr, function: &FunctionIr) -> FuncFingerprint {
    let exact_body_hash = exact_body_hash(function);
    let canonical_body_hash = canonical_body_hash(module, function);

    FuncFingerprint {
        stable_id: stable_function_id_for_hash(function, canonical_body_hash),
        type_sig_hash: hash_parts([function.type_id.as_str()]),
        exact_body_hash,
        canonical_body_hash,
        opcode_histogram: opcode_histogram(function),
        direct_call_targets: direct_call_targets(module, function),
        instruction_count: function.operators.len() as u32,
    }
}

pub fn stable_function_id(module: &ModuleIr, function: &FunctionIr) -> String {
    stable_function_id_for_hash(function, canonical_body_hash(module, function))
}

fn stable_function_id_for_hash(
    function: &FunctionIr,
    canonical_body_hash: FingerprintHash,
) -> String {
    match function.kind {
        FunctionKindIr::Imported => function.id.clone(),
        FunctionKindIr::Defined => match function.export_names.as_slice() {
            [export_name] => format!("func:export:{export_name}:{}", function.type_id),
            [] => format!(
                "func:type:{}:body:{}",
                function.type_id,
                canonical_body_hash.hex()
            ),
            export_names => format!("func:exports:{}:{}", json!(export_names), function.type_id),
        },
    }
}

fn exact_body_hash(function: &FunctionIr) -> FingerprintHash {
    let mut parts = vec!["exact-body".to_owned(), function.type_id.clone()];
    parts.extend(
        function
            .locals
            .iter()
            .map(|local| format!("local:{}:{}", local.count, local.value_type)),
    );
    parts.extend(
        function
            .operators
            .iter()
            .map(|operator| format!("op:{}", operator.display_text())),
    );
    hash_owned_parts(parts)
}

fn canonical_body_hash(module: &ModuleIr, function: &FunctionIr) -> FingerprintHash {
    let mut parts = vec!["canonical-body".to_owned(), function.type_id.clone()];
    parts.extend(
        function
            .locals
            .iter()
            .map(|local| format!("local:{}:{}", local.count, local.value_type)),
    );
    parts.extend(function.operators.iter().map(|operator| {
        format!(
            "op:{}:{}",
            operator.opcode.as_str(),
            canonical_operator_text(module, operator)
        )
    }));
    hash_owned_parts(parts)
}

/// Produce canonical text for an operator's immediate, replacing
/// raw call target indices with stable function IDs.
fn canonical_operator_text(module: &ModuleIr, operator: &ParsedOperator) -> String {
    match &operator.immediate {
        Immediate::Call(index) => module.functions.get(*index as usize).map_or_else(
            || format!("function_index:{index}"),
            |target| format!("Call {{ function: {} }}", target.id),
        ),
        immediate => immediate.as_hash_text(),
    }
}

fn opcode_histogram(function: &FunctionIr) -> Vec<OpcodeCount> {
    let mut counts = BTreeMap::<String, u32>::new();
    for operator in &function.operators {
        *counts
            .entry(operator.opcode.as_str().to_owned())
            .or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(opcode, count)| OpcodeCount { opcode, count })
        .collect()
}

fn direct_call_targets(module: &ModuleIr, function: &FunctionIr) -> Vec<StableFuncRef> {
    let mut targets = function
        .direct_calls
        .iter()
        .filter_map(|index| module.functions.get(*index as usize))
        .map(|target| StableFuncRef {
            stable_id: target.id.clone(),
        })
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    targets
}

fn hash_owned_parts(parts: Vec<String>) -> FingerprintHash {
    let part_refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
    hash_parts(part_refs)
}

fn hash_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> FingerprintHash {
    let mut hash = 0xcbf29ce484222325_u64;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    FingerprintHash(hash)
}

#[cfg(test)]
mod tests {
    use super::{function_fingerprint, module_fingerprints};
    use crate::parse::parse_module;
    use crate::resolve::resolve_module;

    fn resolved(bytes: &[u8]) -> crate::ir::ResolvedModule {
        resolve_module(parse_module(bytes).unwrap())
    }

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

    fn make_multi_export_wasm() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]);
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        bytes.extend_from_slice(&[
            0x07, 0x09, 0x02, 0x01, 0x61, 0x00, 0x00, 0x01, 0x62, 0x00, 0x00,
        ]);
        bytes.extend_from_slice(&[
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
        ]);
        bytes
    }

    #[test]
    fn fingerprints_are_deterministic_for_canonical_fixtures() {
        let first = resolved(include_bytes!("../tests/fixtures/old.wasm"));
        let second = resolved(include_bytes!("../tests/fixtures/old.wasm"));

        assert_eq!(module_fingerprints(&first), module_fingerprints(&second));
    }

    #[test]
    fn exact_and_canonical_body_hashes_detect_fixture_delta() {
        let old_module = resolved(include_bytes!("../tests/fixtures/old.wasm"));
        let new_module = resolved(include_bytes!("../tests/fixtures/new.wasm"));

        let old_fingerprint = function_fingerprint(&old_module.module, &old_module.functions[0]);
        let new_fingerprint = function_fingerprint(&new_module.module, &new_module.functions[0]);

        assert_eq!(old_fingerprint.stable_id, new_fingerprint.stable_id);
        assert_eq!(old_fingerprint.type_sig_hash, new_fingerprint.type_sig_hash);
        assert_ne!(
            old_fingerprint.exact_body_hash,
            new_fingerprint.exact_body_hash
        );
        assert_ne!(
            old_fingerprint.canonical_body_hash,
            new_fingerprint.canonical_body_hash
        );
    }

    #[test]
    fn exported_function_stable_id_ignores_source_index_and_body_change() {
        let old_module = resolved(include_bytes!("../tests/fixtures/old.wasm"));
        let new_module = resolved(include_bytes!("../tests/fixtures/new.wasm"));

        assert_eq!(old_module.functions[0].source_index, 0);
        assert_eq!(new_module.functions[0].source_index, 0);
        assert_eq!(
            old_module.functions[0].id,
            "func:export:add:type:i32,i32->i32"
        );
        assert_eq!(old_module.functions[0].id, new_module.functions[0].id);
    }

    #[test]
    fn exported_function_stable_id_uses_all_export_names() {
        let module = resolved(&make_multi_export_wasm());

        assert_eq!(module.functions[0].export_names, ["a", "b"]);
        assert_eq!(
            module.functions[0].id,
            r#"func:exports:["a","b"]:type:i32,i32->i32"#
        );
    }

    #[test]
    fn fingerprints_match_under_index_drift() {
        let no_import = make_simple_wasm(false);
        let with_import = make_simple_wasm(true);

        let mod_no_import = resolved(&no_import);
        let mod_with_import = resolved(&with_import);

        let fp_no_import = function_fingerprint(&mod_no_import.module, &mod_no_import.functions[0]);
        let fp_with_import =
            function_fingerprint(&mod_with_import.module, &mod_with_import.functions[1]);

        assert_eq!(fp_no_import.stable_id, fp_with_import.stable_id);
        assert_eq!(fp_no_import.stable_id, "func:export:add:type:i32,i32->i32");
        assert_eq!(fp_no_import.exact_body_hash, fp_with_import.exact_body_hash);
        assert_eq!(
            fp_no_import.canonical_body_hash,
            fp_with_import.canonical_body_hash
        );
        assert_eq!(fp_no_import.type_sig_hash, fp_with_import.type_sig_hash);
        assert_eq!(
            fp_no_import.opcode_histogram,
            fp_with_import.opcode_histogram
        );
        assert_eq!(
            fp_no_import.instruction_count,
            fp_with_import.instruction_count
        );
    }

    #[test]
    fn fingerprint_determinism_regression() {
        let bytes = make_simple_wasm(true);
        let first = resolved(&bytes);
        let second = resolved(&bytes);

        let fp_first = module_fingerprints(&first);
        let fp_second = module_fingerprints(&second);

        assert_eq!(
            fp_first, fp_second,
            "fingerprints must be deterministic under repeated parses"
        );
    }
}
