//! Validated core Wasm fixtures spanning the features used by Wasm 1.0–3.0.
//! Fixtures are validated before invoking the CLI, so decoder acceptance alone
//! cannot turn a malformed test input into apparent feature coverage.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use wasmparser::{Validator, WasmFeatures};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new(label: &str) -> Self {
        let directory = Path::new("/tmp").join(format!(
            "uwgit-core-{label}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create isolated fixture directory in /tmp");
        Self(directory)
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_json(arguments: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(arguments)
        .output()
        .expect("execute wasm-git");
    assert!(
        output.status.success(),
        "wasm-git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI emits JSON")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn offset(value: &Value, key: &str) -> usize {
    usize::try_from(value[key].as_u64().expect("physical byte offset")).unwrap()
}

fn verify(label: &str, old_wat: &str, new_wat: &str) -> (Value, Value) {
    let old = wat::parse_str(old_wat).unwrap_or_else(|error| panic!("{label} old WAT: {error}"));
    let new = wat::parse_str(new_wat).unwrap_or_else(|error| panic!("{label} new WAT: {error}"));
    assert_ne!(old, new, "{label} must change encoded bytes");
    for (side, bytes) in [("old", &old), ("new", &new)] {
        Validator::new_with_features(WasmFeatures::all())
            .validate_all(bytes)
            .unwrap_or_else(|error| panic!("{label} {side} must be a valid core module: {error}"));
    }
    let directory = FixtureDirectory::new(label);
    let old_path = directory.0.join("old.wasm");
    let new_path = directory.0.join("new.wasm");
    std::fs::write(&old_path, &old).unwrap();
    std::fs::write(&new_path, &new).unwrap();
    let old_path = old_path.to_str().unwrap();
    let new_path = new_path.to_str().unwrap();
    let inspection = run_json(&["inspect", new_path, "--json"]);
    assert_eq!(
        inspection["audit"]["validation"], "valid_with_all_known_features",
        "{label}"
    );
    assert_eq!(
        inspection["function_analysis"]["available"], true,
        "{label}"
    );
    let difference = run_json(&["diff", old_path, new_path, "--format", "json"]);
    let audit = &difference["audit"];
    assert_eq!(difference["binary_changed"], true, "{label}");
    assert_eq!(
        audit["exact_minimal"], true,
        "{label}: small fixtures use exact byte alignment"
    );
    assert_eq!(
        audit["old"]["validation"], "valid_with_all_known_features",
        "{label}"
    );
    assert_eq!(
        audit["new"]["validation"], "valid_with_all_known_features",
        "{label}"
    );
    let edits = audit["edits"].as_array().expect("physical edit groups");
    assert!(!edits.is_empty(), "{label}: the edit must be reported");
    let mut replayed = Vec::new();
    let mut cursor = 0;
    for edit in edits {
        let old_start = offset(&edit["old_span"], "start");
        let old_end = offset(&edit["old_span"], "end");
        let new_start = offset(&edit["new_span"], "start");
        let new_end = offset(&edit["new_span"], "end");
        assert!(cursor <= old_start && old_start <= old_end && old_end <= old.len());
        assert!(new_start <= new_end && new_end <= new.len());
        assert_eq!(edit["old_hex"], hex(&old[old_start..old_end]));
        assert_eq!(edit["new_hex"], hex(&new[new_start..new_end]));
        replayed.extend_from_slice(&old[cursor..old_start]);
        replayed.extend_from_slice(&new[new_start..new_end]);
        cursor = old_end;
    }
    replayed.extend_from_slice(&old[cursor..]);
    assert_eq!(
        replayed, new,
        "{label}: the reported edits reconstruct every changed byte"
    );
    (inspection, difference)
}

fn verify_replacement(label: &str, source: &str, from: &str, to: &str) -> (Value, Value) {
    assert!(source.contains(from));
    verify(label, source, &source.replacen(from, to, 1))
}

#[test]
fn mvp_local_and_control_flow_edits_are_audited() {
    let source = r#"(module
        (func (export "run") (param i32) (result i32) (local i32)
            local.get 0
            if (result i32) i32.const 17 else i32.const 18 end))"#;
    let (_, difference) = verify_replacement("mvp", source, "i32.const 17", "i32.const 19");
    assert!(difference["audit"].to_string().contains("I32Const"));
}

#[test]
fn arbitrary_import_namespaces_and_every_external_kind_are_audited() {
    let source = r#"(module
        (type $call (func (param i32) (result i32)))
        (import "arbitrary.host/interface" "call" (func $imported (type $call)))
        (import "arbitrary.host/interface" "memory" (memory 1))
        (import "arbitrary.host/interface" "table" (table 1 funcref))
        (import "arbitrary.host/interface" "global" (global (mut i32)))
        (import "arbitrary.host/interface" "tag" (tag (param i32)))
        (func (export "run") (param i32) (result i32) local.get 0 call $imported))"#;
    let (inspection, difference) = verify_replacement(
        "imports",
        source,
        "arbitrary.host/interface",
        "another.namespace/interface",
    );
    assert_eq!(inspection["module"]["imports"].as_array().unwrap().len(), 5);
    assert!(difference["audit"]["semantic_changes"]
        .to_string()
        .contains("import[0]"));
}

#[test]
fn gc_recursive_struct_array_and_field_changes_are_audited() {
    let source = r#"(module
        (rec
            (type $node (struct
                (field $value (mut i32))
                (field (ref null $node))))
            (type $children (array (mut (ref null $node)))))
        (func (export "make") (result (ref $node)) struct.new_default $node)
        (func (export "get") (param (ref $node)) (result i32)
            local.get 0 struct.get $node $value))"#;
    let (inspection, difference) = verify_replacement(
        "gc",
        source,
        "(field $value (mut i32))",
        "(field $value i32)",
    );
    assert!(inspection["module"]["recursion_groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|group| group["explicit"] == true));
    assert!(difference["audit"]["semantic_changes"]
        .to_string()
        .contains("type[0]"));
}

#[test]
fn typed_function_references_and_call_ref_edits_are_audited() {
    let source = r#"(module
        (type $signature (func (result i32)))
        (func $target (type $signature) (result i32) i32.const 21)
        (elem declare func $target)
        (func (export "run") (result i32) ref.func $target call_ref $signature))"#;
    let (inspection, _) = verify_replacement("call-ref", source, "i32.const 21", "i32.const 22");
    assert!(inspection["audit"].to_string().contains("CallRef"));
}

#[test]
fn wasm2_reference_types_and_typed_select_are_audited() {
    let source = r#"(module
        (func (export "choose") (param externref) (result externref)
            local.get 0 ref.null extern i32.const 0 select (result externref)))"#;
    let (inspection, _) = verify_replacement("externref", source, "i32.const 0", "i32.const 1");
    assert!(inspection["audit"].to_string().contains("TypedSelect"));
}

#[test]
fn wasm3_try_table_throw_and_tag_are_audited() {
    let source = r#"(module
        (tag $signal (param i32))
        (func (export "run") (result i32)
            (block $caught (result i32)
                (try_table (catch $signal $caught)
                    i32.const 31 throw $signal)
                i32.const 0)))"#;
    let (inspection, difference) =
        verify_replacement("exceptions", source, "i32.const 31", "i32.const 32");
    assert!(inspection["audit"].to_string().contains("TryTable"));
    assert!(difference["audit"].to_string().contains("exceptions"));
}

#[test]
fn simd_lane_immediate_only_edits_are_audited() {
    let source = r#"(module
        (func (export "lane") (result i32)
            v128.const i32x4 1 2 3 4 i8x16.extract_lane_s 0))"#;
    let (_, difference) =
        verify_replacement("simd", source, "extract_lane_s 0", "extract_lane_s 1");
    assert!(difference["audit"]["semantic_changes"]
        .to_string()
        .contains("lane"));
    assert_eq!(difference["summary"]["functions_changed"], 1);
}

#[test]
fn nan_payload_only_edits_are_audited() {
    let source = r#"(module (func (export "value") (result f32) f32.const nan:0x400001))"#;
    let (_, difference) = verify_replacement("nan", source, "nan:0x400001", "nan:0x400002");
    assert_eq!(difference["summary"]["functions_changed"], 1);
}

#[test]
fn memory64_multi_memory_and_large_offset_edits_are_audited() {
    let source = r#"(module
        (memory $small 1)
        (memory $wide i64 1)
        (func (export "load") (param i64) (result i32)
            local.get 0 i32.load $wide offset=4294967296 align=4))"#;
    let (inspection, _) =
        verify_replacement("memory64", source, "offset=4294967296", "offset=4294967297");
    assert!(inspection["audit"].to_string().contains("4294967297"));
}

#[test]
fn shared_memory_atomic_immediates_are_audited() {
    let source = r#"(module
        (memory 1 1 shared)
        (func (export "load") (param i32) (result i32)
            local.get 0 i32.atomic.load offset=4))"#;
    let (_, difference) = verify_replacement("atomic", source, "offset=4", "offset=8");
    assert!(difference["audit"]["semantic_changes"]
        .to_string()
        .contains("I32AtomicLoad"));
}

#[test]
fn bulk_memory_destination_index_only_edits_are_audited() {
    let source = r#"(module
        (memory $first 1)
        (memory $second 1)
        (data $bytes "abc")
        (func (export "initialize")
            i32.const 0 i32.const 0 i32.const 3 memory.init $first $bytes))"#;
    let (_, difference) = verify_replacement(
        "memory-init-index",
        source,
        "memory.init $first",
        "memory.init $second",
    );
    assert_eq!(difference["summary"]["functions_changed"], 1);
}

#[test]
fn bulk_table_destination_index_only_edits_are_audited() {
    let source = r#"(module
        (table $first 1 funcref)
        (table $second 1 funcref)
        (func $target)
        (elem $targets func $target)
        (func (export "initialize")
            i32.const 0 i32.const 0 i32.const 1 table.init $first $targets))"#;
    let (_, difference) = verify_replacement(
        "table-init-index",
        source,
        "table.init $first",
        "table.init $second",
    );
    assert_eq!(difference["summary"]["functions_changed"], 1);
}

#[test]
fn all_core_section_kinds_and_bulk_data_initialization_are_audited() {
    let source = r#"(module
        (type $empty (func))
        (import "host" "f" (func $imported (type $empty)))
        (memory $memory 1)
        (table $table 1 funcref)
        (global (export "counter") (mut i32) (i32.const 41))
        (tag $signal (param i32))
        (func $helper (type $empty) nop)
        (func $start (type $empty)
            i32.const 0 i32.const 0 i32.const 3 memory.init $memory $passive)
        (export "run" (func $helper))
        (export "memory" (memory $memory))
        (export "table" (table $table))
        (export "signal" (tag $signal))
        (start $start)
        (elem (table $table) (i32.const 0) func $helper)
        (data (memory $memory) (i32.const 8) "abc")
        (data $passive "def"))"#;
    let (inspection, _) =
        verify_replacement("all-sections", source, "i32.const 41", "i32.const 42");
    let sections = inspection["audit"]["sections"].as_array().unwrap();
    for id in 1..=13 {
        assert!(
            sections.iter().any(|section| section["id"] == id),
            "section id {id} must be present"
        );
    }
}

#[test]
fn pure_function_name_changes_are_audited() {
    let source = r#"(module (func $before (export "run") nop))"#;
    let (_, difference) = verify_replacement("names", source, "$before", "$after");
    assert!(difference["audit"]["semantic_changes"]
        .to_string()
        .contains("name"));
    assert_eq!(difference["summary"]["functions_changed"], 0);
}

#[test]
fn import_names_with_delimiters_have_distinct_identities() {
    let old = r#"(module (import "a:b" "c" (func)))"#;
    let new = r#"(module (import "a" "b:c" (func)))"#;
    let (_, difference) = verify("import-identity", old, new);
    assert_eq!(difference["summary"]["imports_added"], 1);
    assert_eq!(difference["summary"]["imports_removed"], 1);
    assert_eq!(difference["summary"]["functions_added"], 1);
    assert_eq!(difference["summary"]["functions_removed"], 1);
    assert!(difference["function_matches"]
        .as_array()
        .unwrap()
        .is_empty());
}
