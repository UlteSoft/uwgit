//! Fixed, independently checked export dependency graphs. No guest execution.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::{audit, patch::BytePatch, standard::Standard};
use wasmparser::{Operator, Parser, Payload, TypeRef, Validator, WasmFeatures};

const SCOPE: &str = "unique_static_function_dependencies_without_export_roles";
const CHAIN: &str = r#"(module (func (result i32) i32.const 7)
    (func (result i32) call 0) (func (result i32) call 1) (export "run" (func 2)))"#;
const REORDERED_CHAIN: &str = r#"(module (import "env" "unused" (func))
    (func (result i32) call 3) (func (result i32) i32.const 7)
    (func (result i32) call 2) (export "run" (func 1)))"#;
const DUPLICATE_LEAF: &str = r#"(module (func (result i32) i32.const 1)
    (func (result i32) i32.const 1) (func (result i32) call 0) (export "run" (func 2)))"#;
const SHIFTED_DUPLICATE_LEAF: &str = r#"(module (import "env" "unused" (func))
    (func (result i32) i32.const 1) (func (result i32) i32.const 1)
    (func (result i32) call 1) (export "run" (func 3)))"#;
const REF_FUNC: &str = r#"(module (func) (elem declare func 0)
    (func (result funcref) ref.func 0) (export "run" (func 1)))"#;
const SHIFTED_REF_FUNC: &str = r#"(module (import "env" "unused" (func))
    (func) (elem declare func 1) (func (result funcref) ref.func 1) (export "run" (func 2)))"#;
const PROFILES: [(&str, Standard); 4] = [
    ("core1", Standard::Core1),
    ("core2", Standard::Core2),
    ("core3", Standard::Core3),
    ("all-known", Standard::AllKnown),
];
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-export-dependencies-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.path(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn success(arguments: &[&str]) -> String {
    let result = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(arguments)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn run_json(arguments: &[&str]) -> Value {
    serde_json::from_str(&success(arguments)).unwrap()
}
struct Pair {
    temp: Temp,
    old: Vec<u8>,
    new: Vec<u8>,
    old_path: String,
    new_path: String,
}
impl Pair {
    fn new(old: &str, new: &str) -> Self {
        let old = wat::parse_str(old).unwrap();
        let new = wat::parse_str(new).unwrap();
        for bytes in [&old, &new] {
            Validator::new_with_features(WasmFeatures::all())
                .validate_all(bytes)
                .unwrap();
        }
        let temp = Temp::new();
        let old_path = temp.write("old.wasm", &old);
        let new_path = temp.write("new.wasm", &new);
        Self {
            temp,
            old,
            new,
            old_path,
            new_path,
        }
    }
    fn diff(&self) -> Value {
        let report = run_json(&["diff", &self.old_path, &self.new_path, "--format", "json"]);
        assert_eq!(report["function_analysis"]["available"], true);
        verify_graph(self, &report);
        report
    }
}
fn number(value: &Value) -> u64 {
    value.as_u64().unwrap()
}
fn functions(module: &Value) -> &[Value] {
    module["functions"].as_array().unwrap()
}
fn function(module: &Value, index: u64) -> &Value {
    functions(module)
        .iter()
        .find(|function| function["source_index"] == index)
        .unwrap()
}
fn nodes(report: &Value) -> &[Value] {
    report["export_dependency_graph"]["nodes"]
        .as_array()
        .unwrap()
}
fn node(report: &Value, old: u64) -> Option<&Value> {
    nodes(report)
        .iter()
        .find(|node| node["old_source_index"] == old)
}
fn note<'a>(report: &'a Value, name: &str) -> &'a Value {
    let found: Vec<_> = report["export_binding_notes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|note| note["old"]["name"] == name)
        .collect();
    assert_eq!(found.len(), 1, "one paired export for {name}");
    found[0]
}
fn binding<'a>(
    report: &'a Value,
    name: &str,
    relation: &str,
    changed: Option<bool>,
    old: u64,
    new: u64,
) -> &'a Value {
    let entry = note(report, name);
    assert_eq!(entry["pairing"], "export_name_kind");
    assert_eq!(
        entry["match_scope"],
        "exports_removed_from_candidate_matching"
    );
    assert_eq!(entry["identity_unproven"], true);
    assert_eq!(entry["relation"], relation);
    assert_eq!(entry["target_changed"], json!(changed));
    assert_eq!(entry["old"]["item_index"], old);
    assert_eq!(entry["new"]["item_index"], new);
    entry
}
fn root(report: &Value, entry: &Value, old: u64, new: u64, depth: u64) {
    assert_eq!(
        entry["dependency_proof"],
        json!({
            "old_source_index": old, "new_source_index": new, "depth": depth
        })
    );
    let proof = node(report, old).unwrap();
    assert_eq!(proof["new_source_index"], new);
    assert_eq!(proof["depth"], depth);
    assert_eq!(entry["target_match"]["old_source_index"], old);
    assert_eq!(entry["target_match"]["new_source_index"], new);
    assert_eq!(entry["target_match"]["ambiguous"], false);
    assert_eq!(entry["target_match"]["reference_context_complete"], true);
    if depth > 0 {
        assert_eq!(
            entry["target_match"]["reason"],
            "same_matched_reference_body"
        );
        let confidence = entry["target_match"]["confidence"].as_f64().unwrap();
        assert!((confidence - 0.9).abs() < 0.000_001);
    }
}
fn unproved(report: &Value, name: &str, old: u64, new: u64) {
    let entry = note(report, name);
    assert!(matches!(
        entry["relation"].as_str(),
        Some("unresolved_target" | "ambiguous_target")
    ));
    assert!(entry["target_changed"].is_null());
    assert!(entry["dependency_proof"].is_null());
    assert_eq!(entry["identity_unproven"], true);
    assert_eq!(entry["old"]["item_index"], old);
    assert_eq!(entry["new"]["item_index"], new);
    assert!(
        node(report, old).is_none(),
        "no graph root may silently support an unproved export"
    );
}
fn raw_counts(report: &Value, count: u64) {
    assert_eq!(report["summary"]["exports_added"], count);
    assert_eq!(report["summary"]["exports_removed"], count);
}
fn reference(operator: &Value) -> Option<u64> {
    operator["immediate"]
        .get("Call")
        .or_else(|| operator["immediate"].get("RefFunc"))
        .map(number)
}
fn import_binding(module: &Value, index: u64) -> Value {
    let import = module["imports"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|import| import["kind"] == "Func")
        .nth(index as usize)
        .unwrap();
    json!({"module": import["module"], "name": import["name"],
        "type_id": import["type_ref"]["Func"]["type_id"], "exact": import["type_ref"]["Func"]["exact"]})
}
fn physical_references(bytes: &[u8]) -> BTreeMap<(u64, usize), (u64, &'static str, u64)> {
    let mut imported = 0;
    let mut defined = 0;
    let mut result = BTreeMap::new();
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.unwrap() {
            Payload::ImportSection(section) => {
                for item in section.into_imports() {
                    if matches!(item.unwrap().ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
                        imported += 1;
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut reader = body.get_operators_reader().unwrap();
                let mut ordinal = 0;
                while !reader.eof() {
                    let offset = reader.original_position() as u64;
                    let item = match reader.read().unwrap() {
                        Operator::Call { function_index } => Some(("Call", function_index)),
                        Operator::ReturnCall { function_index } => {
                            Some(("ReturnCall", function_index))
                        }
                        Operator::RefFunc { function_index } => Some(("RefFunc", function_index)),
                        _ => None,
                    };
                    if let Some((opcode, target)) = item {
                        result.insert(
                            (imported + defined, ordinal),
                            (offset, opcode, u64::from(target)),
                        );
                    }
                    ordinal += 1;
                }
                defined += 1;
            }
            _ => {}
        }
    }
    result
}
fn body_key(function: &Value, mapped: &BTreeMap<u64, u64>) -> Option<String> {
    let mut operators = Vec::new();
    for operator in function["operators"].as_array().unwrap() {
        let immediate = match reference(operator) {
            Some(target) => json!({"mapped_function": mapped.get(&target)?}),
            None => operator["immediate"].clone(),
        };
        operators.push(json!([operator["opcode"], immediate]));
    }
    Some(
        serde_json::to_string(&json!([function["type_id"], function["locals"], operators]))
            .unwrap(),
    )
}
fn verify_graph(pair: &Pair, report: &Value) {
    let graph = &report["export_dependency_graph"];
    assert_eq!(graph["scope"], SCOPE);
    assert_eq!(graph["identity_unproven"], true);
    let old = run_json(&["inspect", &pair.old_path, "--json"]);
    let new = run_json(&["inspect", &pair.new_path, "--json"]);
    let old = &old["module"];
    let new = &new["module"];
    let mut forward = BTreeMap::new();
    let mut new_indices = BTreeSet::new();
    for entry in nodes(report) {
        let a = number(&entry["old_source_index"]);
        let b = number(&entry["new_source_index"]);
        assert!(forward.insert(a, b).is_none());
        assert!(new_indices.insert(b));
    }
    let new_map = new_indices
        .iter()
        .map(|index| (*index, *index))
        .collect::<BTreeMap<_, _>>();
    let old_physical = physical_references(&pair.old);
    let new_physical = physical_references(&pair.new);
    for entry in nodes(report) {
        let a = number(&entry["old_source_index"]);
        let b = number(&entry["new_source_index"]);
        let left = function(old, a);
        let right = function(new, b);
        assert_eq!(left["kind"], right["kind"]);
        assert_eq!(entry["type_id"], left["type_id"]);
        assert_eq!(left["type_id"], right["type_id"]);
        assert_eq!(left["locals"], right["locals"]);
        let depth = number(&entry["depth"]);
        if entry["kind"] == "unique_import_binding" {
            assert_eq!(left["kind"], "Imported");
            assert_eq!(depth, 0);
            assert_eq!(entry["references"], json!([]));
            let binding = import_binding(old, a);
            assert_eq!(entry["import"], binding);
            assert_eq!(import_binding(new, b), binding);
            for module in [old, new] {
                assert_eq!(
                    functions(module)
                        .iter()
                        .filter(|function| function["kind"] == "Imported"
                            && import_binding(module, number(&function["source_index"])) == binding)
                        .count(),
                    1
                );
            }
            continue;
        }
        assert_eq!(left["kind"], "Defined");
        assert!(entry["import"].is_null());
        let left_ops = left["operators"].as_array().unwrap();
        let right_ops = right["operators"].as_array().unwrap();
        assert_eq!(left_ops.len(), right_ops.len());
        let mut refs = Vec::new();
        let mut deepest = None;
        for (index, (left_op, right_op)) in left_ops.iter().zip(right_ops).enumerate() {
            assert_eq!(left_op["opcode"], right_op["opcode"]);
            if let Some(old_target) = reference(left_op) {
                let new_target = reference(right_op).expect("same typed reference form");
                assert_eq!(forward.get(&old_target), Some(&new_target));
                let child = node(report, old_target).unwrap();
                let child_depth = number(&child["depth"]);
                assert!(child_depth < depth, "a proof cannot bootstrap a cycle");
                deepest = Some(deepest.map_or(child_depth, |old: u64| old.max(child_depth)));
                let left_raw = old_physical.get(&(a, index)).unwrap();
                let right_raw = new_physical.get(&(b, index)).unwrap();
                assert_eq!(left_raw.0, number(&left_op["offset"]));
                assert_eq!(right_raw.0, number(&right_op["offset"]));
                assert_eq!(left_raw.1, left_op["opcode"].as_str().unwrap());
                assert_eq!(right_raw.1, right_op["opcode"].as_str().unwrap());
                assert_eq!(left_raw.2, old_target);
                assert_eq!(right_raw.2, new_target);
                refs.push(
                    json!({"old_operator_index": index, "new_operator_index": index,
                    "old_offset": left_raw.0, "new_offset": right_raw.0,
                    "opcode": left_raw.1, "old_target": old_target, "new_target": new_target}),
                );
            } else {
                assert_eq!(left_op["immediate"], right_op["immediate"]);
            }
        }
        assert_eq!(entry["references"], Value::Array(refs));
        match deepest {
            Some(child_depth) => {
                assert_eq!(entry["kind"], "unique_mapped_reference_body");
                assert_eq!(depth, child_depth + 1);
            }
            None => {
                assert_eq!(entry["kind"], "unique_reference_free_body");
                assert_eq!(depth, 0);
            }
        }
        let key = body_key(left, &forward).unwrap();
        assert_eq!(body_key(right, &new_map).as_ref(), Some(&key));
        for (module, mapped) in [(old, &forward), (new, &new_map)] {
            assert_eq!(functions(module).iter().filter(|function| function["kind"] == "Defined"
                && body_key(function, mapped).as_ref() == Some(&key)).count(), 1,
                "uniqueness includes every eligible function, including surplus duplicate occurrences");
        }
    }
    for entry in report["export_binding_notes"].as_array().unwrap() {
        if entry["dependency_proof"].is_null() {
            continue;
        }
        let root = &entry["dependency_proof"];
        let a = number(&root["old_source_index"]);
        let proof = node(report, a).unwrap();
        assert_eq!(entry["old"]["item_index"], a);
        assert_eq!(root["new_source_index"], proof["new_source_index"]);
        assert_eq!(root["depth"], proof["depth"]);
    }
}

#[test]
fn unique_defined_and_imported_seeds_prove_multiple_layers_after_reordering() {
    let pair = Pair::new(CHAIN, REORDERED_CHAIN);
    let report = pair.diff();
    raw_counts(&report, 1);
    let entry = binding(
        &report,
        "run",
        "candidate_same_target_index_relocated",
        Some(false),
        2,
        1,
    );
    root(&report, entry, 2, 1, 2);
    for (old, new, depth) in [(0, 2, 0), (1, 3, 1), (2, 1, 2)] {
        let proof = node(&report, old).unwrap();
        assert_eq!(proof["new_source_index"], new);
        assert_eq!(proof["depth"], depth);
    }
    let full = success(&["diff", &pair.old_path, &pair.new_path, "--format", "text"]);
    for label in [
        "Export dependency proof witnesses",
        "dependency proof root",
        "old operator[",
        "new operator[",
    ] {
        assert!(full.contains(label), "missing physical proof text {label}");
    }
    let short = success(&["diff", &pair.old_path, &pair.new_path, "--short"]);
    assert!(short.contains("export dependency proof:"));
    assert!(short.contains("identity unproven"));
    let old = r#"(module (import "m" "get" (func (result i32)))
        (func (result i32) call 0) (func (result i32) call 1) (export "run" (func 2)))"#;
    let new = r#"(module (import "env" "unused" (func)) (import "m" "get" (func (result i32)))
        (func (result i32) call 1) (func (result i32) call 2) (export "run" (func 3)))"#;
    let report = Pair::new(old, new).diff();
    root(
        &report,
        binding(
            &report,
            "run",
            "candidate_same_target_index_relocated",
            Some(false),
            2,
            3,
        ),
        2,
        3,
        2,
    );
    assert_eq!(node(&report, 0).unwrap()["kind"], "unique_import_binding");
}

#[test]
fn duplicate_leaf_and_import_bindings_cannot_seed_a_unique_wrapper() {
    let redirected = r#"(module (import "env" "unused" (func))
        (func (result i32) i32.const 1) (func (result i32) i32.const 1)
        (func (result i32) call 2) (export "run" (func 3)))"#;
    for new in [SHIFTED_DUPLICATE_LEAF, redirected] {
        let report = Pair::new(DUPLICATE_LEAF, new).diff();
        unproved(&report, "run", 2, 3);
        assert!(nodes(&report).is_empty());
        raw_counts(&report, 1);
    }
    let old = r#"(module (import "m" "f" (func (result i32))) (import "m" "f" (func (result i32)))
        (func (result i32) call 0) (export "run" (func 2)))"#;
    let new = r#"(module (import "env" "unused" (func))
        (import "m" "f" (func (result i32))) (import "m" "f" (func (result i32)))
        (func (result i32) call 1) (export "run" (func 3)))"#;
    let report = Pair::new(old, new).diff();
    unproved(&report, "run", 2, 3);
    assert!(nodes(&report).is_empty());
    raw_counts(&report, 1);
}

#[test]
fn duplicate_wrappers_and_surplus_occurrences_block_their_dependants() {
    let old = r#"(module (func (result i32) i32.const 1)
        (func (result i32) call 0) (func (result i32) call 0) (func (result i32) call 1)
        (export "run" (func 1)) (export "top" (func 3)))"#;
    let duplicate = r#"(module (import "env" "unused" (func)) (func (result i32) i32.const 1)
        (func (result i32) call 1) (func (result i32) call 1) (func (result i32) call 3)
        (export "run" (func 3)) (export "top" (func 4)))"#;
    let removed = r#"(module (import "env" "unused" (func)) (import "env" "other" (func))
        (func (result i32) i32.const 1) (func (result i32) call 2) (func (result i32) call 3)
        (export "run" (func 3)) (export "top" (func 4)))"#;
    for new in [duplicate, removed] {
        let report = Pair::new(old, new).diff();
        unproved(&report, "run", 1, 3);
        unproved(&report, "top", 3, 4);
        assert!(node(&report, 2).is_none());
        assert_eq!(nodes(&report).len(), 1);
        raw_counts(&report, 2);
    }
}

#[test]
fn self_and_mutual_cycles_cannot_bootstrap_even_with_an_unrelated_proved_seed() {
    for (old, new, a, b) in [
        (
            r#"(module (func (result i32) call 0) (export "run" (func 0)))"#,
            r#"(module (import "env" "unused" (func)) (func (result i32) call 1) (export "run" (func 1)))"#,
            0,
            1,
        ),
        (
            r#"(module (func (result i32) call 1) (func (result i32) call 0) (export "run" (func 0)))"#,
            r#"(module (import "env" "unused" (func)) (func (result i32) call 2)
             (func (result i32) call 1) (export "run" (func 1)))"#,
            0,
            1,
        ),
        (
            r#"(module (func (result i32) i32.const 9) (func (result i32) call 0 drop call 2)
             (func (result i32) call 1) (export "run" (func 1)))"#,
            r#"(module (import "env" "unused" (func)) (func (result i32) i32.const 9)
             (func (result i32) call 1 drop call 3) (func (result i32) call 2) (export "run" (func 2)))"#,
            1,
            2,
        ),
    ] {
        let report = Pair::new(old, new).diff();
        unproved(&report, "run", a, b);
        raw_counts(&report, 1);
        assert!(nodes(&report).iter().all(|node| node["depth"] == 0));
    }
}

#[test]
fn ordered_repeated_reference_sites_must_all_follow_the_same_proved_mapping() {
    let old = r#"(module (func (result i32) i32.const 1) (func (result i32) i32.const 2)
        (func (result i32) call 0 drop call 1) (export "run" (func 2)))"#;
    let shifted = r#"(module (import "env" "unused" (func))
        (func (result i32) i32.const 1) (func (result i32) i32.const 2)
        (func (result i32) call 1 drop call 2) (export "run" (func 3)))"#;
    let report = Pair::new(old, shifted).diff();
    root(
        &report,
        binding(
            &report,
            "run",
            "candidate_same_target_index_relocated",
            Some(false),
            2,
            3,
        ),
        2,
        3,
        1,
    );
    assert_eq!(
        node(&report, 2).unwrap()["references"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let retarget = r#"(module (import "env" "unused" (func))
        (func (result i32) i32.const 1) (func (result i32) i32.const 2)
        (func (result i32) call 1 drop call 2) (func (result i32) call 2 drop call 1)
        (export "run" (func 4)))"#;
    let report = Pair::new(old, retarget).diff();
    root(
        &report,
        binding(&report, "run", "different_target", Some(true), 2, 4),
        2,
        3,
        1,
    );
    let repeat = r#"(module (func (result i32) i32.const 1) (func (result i32) i32.const 2)
        (func (result i32) call 0 drop call 0) (export "run" (func 2)))"#;
    let report = Pair::new(repeat, shifted).diff();
    unproved(&report, "run", 2, 3);
}

#[test]
fn ref_func_and_return_call_use_typed_reference_positions_and_keep_their_opcodes() {
    let report = Pair::new(REF_FUNC, SHIFTED_REF_FUNC).diff();
    root(
        &report,
        binding(
            &report,
            "run",
            "candidate_same_target_index_relocated",
            Some(false),
            1,
            2,
        ),
        1,
        2,
        1,
    );
    assert_eq!(
        node(&report, 1).unwrap()["references"][0]["opcode"],
        "RefFunc"
    );
    let old = r#"(module (func (result i32) i32.const 7)
        (func (result i32) return_call 0) (export "run" (func 1)))"#;
    let new = r#"(module (import "env" "unused" (func)) (func (result i32) i32.const 7)
        (func (result i32) return_call 1) (export "run" (func 2)))"#;
    let report = Pair::new(old, new).diff();
    root(
        &report,
        binding(
            &report,
            "run",
            "candidate_same_target_index_relocated",
            Some(false),
            1,
            2,
        ),
        1,
        2,
        1,
    );
    assert_eq!(
        node(&report, 1).unwrap()["references"][0]["opcode"],
        "ReturnCall"
    );
    let call = r#"(module (func (result i32) i32.const 7)
        (func (result i32) call 0) (export "run" (func 1)))"#;
    let report = Pair::new(call, new).diff();
    unproved(&report, "run", 1, 2);
}

#[test]
fn non_reference_operands_locals_and_types_are_not_erased_by_dependency_translation() {
    for (old_body, new_body) in [
        (
            "(param i32 i32) (result i32) local.get 0 drop call 0",
            "(param i32 i32) (result i32) local.get 1 drop call 1",
        ),
        (
            "(result i32) call 0 i32.const 7 i32.add",
            "(result i32) call 1 i32.const 8 i32.add",
        ),
        (
            "(result i32) (local i32) call 0",
            "(result i32) (local i64) call 1",
        ),
        (
            "(param i32) (result i32) call 0",
            "(param i64) (result i32) call 1",
        ),
    ] {
        let old = format!(
            "(module (func (result i32) i32.const 7) (func {old_body}) (export \"run\" (func 1)))"
        );
        let new = format!("(module (import \"env\" \"unused\" (func)) (func (result i32) i32.const 7) (func {new_body}) (export \"run\" (func 2)))");
        let pair = Pair::new(&old, &new);
        let report = pair.diff();
        unproved(&report, "run", 1, 2);
        raw_counts(&report, 1);
        assert_eq!(nodes(&report).len(), 1);
        assert_eq!(node(&report, 0).unwrap()["depth"], 0);
        replay(&pair.old, &pair.new, &report["audit"]["edits"]);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn range(span: &Value, bytes: &[u8]) -> (usize, usize) {
    let a = usize::try_from(number(&span["start"])).unwrap();
    let b = usize::try_from(number(&span["end"])).unwrap();
    assert!(a <= b && b <= bytes.len());
    (a, b)
}
fn regions(audit: &Value) -> Vec<&Value> {
    fn walk<'a>(entries: &'a Value, result: &mut Vec<&'a Value>) {
        for entry in entries.as_array().unwrap() {
            result.push(entry);
            if let Some(children) = entry.get("regions") {
                walk(children, result);
            }
            if let Some(children) = entry.get("children") {
                walk(children, result);
            }
        }
    }
    let mut result = Vec::new();
    walk(&audit["sections"], &mut result);
    result
}
fn raw_audit(audit: &Value, bytes: &[u8]) {
    for entry in regions(audit) {
        range(&entry["span"], bytes);
    }
    for entry in audit["standard"]["evidence"].as_array().unwrap() {
        let (a, b) = range(&entry["span"], bytes);
        assert_eq!(entry["raw_hex"], hex(&bytes[a..b]));
    }
}
fn replay(old: &[u8], new: &[u8], edits: &Value) {
    let (mut a, mut b) = (0, 0);
    let mut output = Vec::new();
    for edit in edits.as_array().unwrap() {
        let (x, y) = range(&edit["old_span"], old);
        let (u, v) = range(&edit["new_span"], new);
        assert!(a <= x && b <= u);
        assert_eq!(&old[a..x], &new[b..u]);
        assert_eq!(edit["old_hex"], hex(&old[x..y]));
        assert_eq!(edit["new_hex"], hex(&new[u..v]));
        output.extend_from_slice(&old[a..x]);
        output.extend_from_slice(&new[u..v]);
        a = y;
        b = v;
    }
    assert_eq!(&old[a..], &new[b..]);
    output.extend_from_slice(&old[a..]);
    assert_eq!(output, new);
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            assert!(!entry.file_type().unwrap().is_symlink());
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                result.insert(relative, None);
                walk(root, &path, result);
            } else {
                result.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

#[test]
fn dependency_proofs_leave_raw_edits_patches_profiles_and_physical_history_unchanged() {
    for (old, new) in [
        (CHAIN, REORDERED_CHAIN),
        (REF_FUNC, SHIFTED_REF_FUNC),
        (DUPLICATE_LEAF, SHIFTED_DUPLICATE_LEAF),
    ] {
        let pair = Pair::new(old, new);
        let mut prior_edits = None;
        let mut prior_graph = None;
        let mut selected = Value::Null;
        for (profile, standard) in PROFILES {
            let report = run_json(&[
                "diff",
                &pair.old_path,
                &pair.new_path,
                "--format",
                "json",
                "--standard",
                profile,
            ]);
            assert_eq!(report["function_analysis"]["available"], true);
            assert_eq!(report["binary_changed"], true);
            verify_graph(&pair, &report);
            raw_counts(&report, 1);
            for (role, bytes) in [("old", &pair.old), ("new", &pair.new)] {
                raw_audit(&report["audit"][role], bytes);
                assert_eq!(
                    report["audit"][role]["standard"]["selected_standard"],
                    profile
                );
            }
            let direct = audit::compare_with_standard(&pair.old, &pair.new, standard).unwrap();
            assert_eq!(
                report["audit"]["edits"],
                serde_json::to_value(direct.edits).unwrap()
            );
            replay(&pair.old, &pair.new, &report["audit"]["edits"]);
            if let Some(prior) = &prior_edits {
                assert_eq!(prior, &report["audit"]["edits"]);
            }
            if let Some(prior) = &prior_graph {
                assert_eq!(prior, &report["export_dependency_graph"]);
            }
            prior_edits = Some(report["audit"]["edits"].clone());
            prior_graph = Some(report["export_dependency_graph"].clone());
            selected = regions(&report["audit"]["new"])
                .into_iter()
                .find(|entry| entry["path"] == "export[0]/entry[0]")
                .unwrap()["span"]
                .clone();
        }
        for (label, old, new, old_path, new_path) in [
            (
                "forward",
                &pair.old,
                &pair.new,
                &pair.old_path,
                &pair.new_path,
            ),
            (
                "reverse",
                &pair.new,
                &pair.old,
                &pair.new_path,
                &pair.old_path,
            ),
        ] {
            let patch = pair.temp.path(&format!("{label}.uwgp"));
            let applied = pair.temp.path(&format!("{label}.wasm"));
            run_json(&["patch", old_path, new_path, "--output", &patch]);
            let raw = std::fs::read(&patch).unwrap();
            let encoded: Value = serde_json::from_slice(&raw).unwrap();
            replay(old, new, &encoded["edits"]);
            assert_eq!(
                BytePatch::from_bytes(&raw).unwrap().apply(old).unwrap(),
                *new
            );
            run_json(&["apply", old_path, &patch, "--output", &applied]);
            assert_eq!(std::fs::read(applied).unwrap(), *new);
        }
        let repo = pair.temp.path("repo");
        success(&["init", &repo]);
        let old_id = success(&["commit", &repo, &pair.old_path, "-m", "old"])
            .split_whitespace()
            .last()
            .unwrap()
            .to_owned();
        let new_id = success(&["commit", &repo, &pair.new_path, "-m", "new"])
            .split_whitespace()
            .last()
            .unwrap()
            .to_owned();
        let before = snapshot(Path::new(&repo));
        let named = run_json(&["trace", &repo, "HEAD", "--path", "export[0]/entry[0]"]);
        let (a, b) = range(&selected, &pair.new);
        let numeric = run_json(&["trace", &repo, "HEAD", "--range", &format!("{a}:{b}")]);
        assert_eq!(named["selection"]["span"], selected);
        assert_eq!(named["trace"], numeric["trace"]);
        assert_eq!(named["repository_verified"], true);
        assert_eq!(named["trace"]["complete"], true);
        assert_eq!(named["trace"]["identity_unproven"], true);
        let edges = named["trace"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["parent"], old_id);
        assert_eq!(edges[0]["child"], new_id);
        assert!(!edges[0]["events"].as_array().unwrap().is_empty());
        for event in edges[0]["events"].as_array().unwrap() {
            let edit = &event["edit"];
            let (a, b) = range(&edit["old_span"], &pair.old);
            let (c, d) = range(&edit["new_span"], &pair.new);
            assert_eq!(edit["old_hex"], hex(&pair.old[a..b]));
            assert_eq!(edit["new_hex"], hex(&pair.new[c..d]));
        }
        for gap in edges[0]["gap_mappings"].as_array().unwrap() {
            let (a, b) = range(&gap["parent"]["span"], &pair.old);
            let (c, d) = range(&gap["child"]["span"], &pair.new);
            assert_eq!(&pair.old[a..b], &pair.new[c..d]);
        }
        let fsck = run_json(&["fsck", &repo]);
        assert_eq!(fsck["commits"], 2);
        assert_eq!(fsck["wasm_blobs"], 2);
        assert_eq!(snapshot(Path::new(&repo)), before);
        assert_eq!(std::fs::read(&pair.old_path).unwrap(), pair.old);
        assert_eq!(std::fs::read(&pair.new_path).unwrap(), pair.new);
    }
    let temp = Temp::new();
    let mut malformed = [
        0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 7, 5, 1, 1, 0xff, 0, 0, 10,
        4, 1, 2, 0, 0x0b,
    ];
    let old = temp.write("unknown.wasm", &malformed);
    malformed[22] = b'x';
    let new = temp.write("known.wasm", &malformed);
    let report = run_json(&["diff", &old, &new, "--format", "json"]);
    assert_eq!(report["function_analysis"]["available"], false);
    assert!(report["export_binding_notes"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(report["export_dependency_graph"].is_null());
    assert_eq!(report["binary_changed"], true);
}
