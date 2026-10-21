//! Fixed call/reference dependency evidence. All fixtures live in /tmp.
//! The independent oracle reads original Wasm bytes; no guest is executed.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::{audit, patch::BytePatch, standard::Standard};
use wasmparser::{CompositeInnerType, Operator, Parser, Payload, TypeRef, Validator, WasmFeatures};

const SCOPE: &str = "exports_removed_from_candidate_matching";
const GRAPH_SCOPE: &str = "unique_static_function_dependencies_without_export_roles";
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
            "uwgit-call-dependencies-{}-{}",
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
    let output = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(arguments)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
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
        verify_report(self, &report);
        report
    }
}
fn number(value: &Value) -> u64 {
    value.as_u64().unwrap()
}

#[derive(Debug)]
struct RawOperator {
    offset: u64,
    text: String,
    reference: Option<(&'static str, u64)>,
}
#[derive(Debug)]
struct RawFunction {
    type_id: String,
    import: Option<Value>,
    locals: Vec<(u32, String)>,
    operators: Vec<RawOperator>,
}

// These fixtures deliberately use ordinary final function types. The raw
// reader expands their signatures independently of product identities, export
// names, fingerprints, normalization, and the global function matcher.
fn raw_functions(bytes: &[u8]) -> Vec<RawFunction> {
    let mut types = Vec::new();
    let mut declarations = Vec::new();
    let mut functions = Vec::new();
    let mut defined = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.unwrap() {
            Payload::TypeSection(reader) => {
                for group in reader {
                    for (_, ty) in group.unwrap().into_types_and_offsets() {
                        assert!(ty.is_final && ty.supertype_idx.is_none());
                        assert!(!ty.composite_type.shared);
                        let CompositeInnerType::Func(function) = ty.composite_type.inner else {
                            panic!("fixed oracle requires ordinary function signatures")
                        };
                        let params = function
                            .params()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>();
                        let results = function
                            .results()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>();
                        types.push(format!("type:{}->{}", params.join(","), results.join(",")));
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.unwrap();
                    let (index, exact) = match import.ty {
                        TypeRef::Func(index) => (index, false),
                        TypeRef::FuncExact(index) => (index, true),
                        _ => continue,
                    };
                    let type_id = types[index as usize].clone();
                    functions.push(RawFunction {
                        type_id: type_id.clone(),
                        import: Some(json!({"module":import.module, "name":import.name,
                            "type_id":type_id, "exact":exact})),
                        locals: Vec::new(),
                        operators: Vec::new(),
                    });
                }
            }
            Payload::FunctionSection(reader) => {
                for index in reader {
                    declarations.push(index.unwrap());
                }
            }
            Payload::CodeSectionEntry(body) => {
                let locals = body
                    .get_locals_reader()
                    .unwrap()
                    .into_iter()
                    .map(|local| {
                        let (count, ty) = local.unwrap();
                        (count, ty.to_string())
                    })
                    .collect();
                let mut reader = body.get_operators_reader().unwrap();
                let mut operators = Vec::new();
                while !reader.eof() {
                    let offset = reader.original_position() as u64;
                    let operator = reader.read().unwrap();
                    let reference = match operator {
                        Operator::Call { function_index } => Some(("Call", function_index)),
                        Operator::ReturnCall { function_index } => {
                            Some(("ReturnCall", function_index))
                        }
                        Operator::RefFunc { function_index } => Some(("RefFunc", function_index)),
                        _ => None,
                    };
                    operators.push(RawOperator {
                        offset,
                        text: format!("{operator:?}"),
                        reference: reference.map(|(opcode, index)| (opcode, u64::from(index))),
                    });
                }
                functions.push(RawFunction {
                    type_id: types[declarations[defined] as usize].clone(),
                    import: None,
                    locals,
                    operators,
                });
                defined += 1;
            }
            _ => {}
        }
    }
    functions
}

fn raw_key(function: &RawFunction, targets: &BTreeMap<u64, u64>) -> Option<String> {
    if let Some(import) = &function.import {
        return Some(serde_json::to_string(&json!(["import", import])).unwrap());
    }
    let mut operators = Vec::new();
    for operator in &function.operators {
        operators.push(match operator.reference {
            Some((opcode, index)) => json!([opcode, targets.get(&index)?]),
            None => json!(["literal_typed_operator", operator.text]),
        });
    }
    Some(
        serde_json::to_string(&json!([
            "defined",
            function.type_id,
            function.locals,
            operators
        ]))
        .unwrap(),
    )
}

// Full-domain fixed-point rescans intentionally differ from the product's
// dependency worklist. All occurrences remain in each key group, including
// nodes already paired in previous rounds and functions bearing export roles.
fn raw_correspondence(old: &[RawFunction], new: &[RawFunction]) -> BTreeMap<u64, (u64, u64)> {
    let mut result = BTreeMap::<u64, (u64, u64)>::new();
    loop {
        let forward = result.iter().map(|(&a, &(b, _))| (a, b)).collect();
        let new_targets = result.values().map(|&(b, _)| (b, b)).collect();
        let mut groups = BTreeMap::<String, (Vec<u64>, Vec<u64>)>::new();
        for (side, functions, targets) in [(0, old, &forward), (1, new, &new_targets)] {
            for (index, function) in functions.iter().enumerate() {
                if let Some(key) = raw_key(function, targets) {
                    let group = groups.entry(key).or_default();
                    if side == 0 {
                        group.0.push(index as u64);
                    } else {
                        group.1.push(index as u64);
                    }
                }
            }
        }
        let mut ready = Vec::new();
        for (a, b) in groups.into_values() {
            let ([a], [b]) = (&a[..], &b[..]) else {
                continue;
            };
            if result.contains_key(a) || result.values().any(|(index, _)| index == b) {
                continue;
            }
            let depth = old[*a as usize]
                .operators
                .iter()
                .filter_map(|operator| operator.reference)
                .map(|(_, index)| result[&index].1 + 1)
                .max()
                .unwrap_or(0);
            ready.push((*a, (*b, depth)));
        }
        if ready.is_empty() {
            break;
        }
        result.extend(ready);
    }
    result
}
fn nodes(report: &Value) -> &[Value] {
    report["export_dependency_graph"]["nodes"]
        .as_array()
        .unwrap()
}
fn node(report: &Value, old_index: u64) -> Option<&Value> {
    nodes(report)
        .iter()
        .find(|node| node["old_source_index"] == old_index)
}
fn bindings(report: &Value) -> Vec<&Value> {
    let changed = report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["kind"] == "function_changed")
        .map(|change| &change["function"]);
    let notes = report["call_binding_notes"].as_array().unwrap().iter();
    changed
        .chain(notes)
        .flat_map(|function| function["call_bindings"].as_array().unwrap())
        .collect()
}
fn caller<'a>(report: &'a Value, name: &str) -> Option<&'a Value> {
    let prefix = format!("func:export:{name}:");
    report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["kind"] == "function_changed")
        .map(|change| &change["function"])
        .find(|function| function["old_id"].as_str().unwrap().starts_with(&prefix))
}
fn binding(report: &Value, old_target: u64, new_target: u64) -> &Value {
    let found = bindings(report)
        .into_iter()
        .filter(|binding| {
            binding["old"]["function_index"] == old_target
                && binding["new"]["function_index"] == new_target
        })
        .collect::<Vec<_>>();
    assert_eq!(
        found.len(),
        1,
        "one aligned reference for {old_target}->{new_target}"
    );
    found[0]
}
fn unproved(entry: &Value) {
    assert!(matches!(
        entry["relation"].as_str(),
        Some("ambiguous_target" | "unresolved_target")
    ));
    assert!(entry["target_changed"].is_null());
    assert!(entry["dependency_proof"].is_null());
    if !entry["target_match"].is_null() {
        assert_eq!(entry["target_match"]["ambiguous"], true);
    }
}
fn root(entry: &Value, old_index: u64, new_index: u64, depth: u64) {
    assert_eq!(
        entry["dependency_proof"],
        json!({"old_source_index":old_index, "new_source_index":new_index, "depth":depth})
    );
    assert_eq!(entry["target_match"]["old_source_index"], old_index);
    assert_eq!(entry["target_match"]["new_source_index"], new_index);
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
fn verify_site(site: &Value, functions: &[RawFunction]) {
    if site.is_null() {
        return;
    }
    let offset = number(&site["offset"]);
    let found = functions
        .iter()
        .flat_map(|function| function.operators.iter().enumerate())
        .filter(|(_, operator)| operator.offset == offset)
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1, "physical reference offset must be unique");
    let (ordinal, operator) = found[0];
    let (opcode, target) = operator
        .reference
        .expect("a real static function reference");
    assert_eq!(site["operator_index"], ordinal);
    assert_eq!(site["opcode"], opcode);
    assert_eq!(site["function_index"], target);
    assert_eq!(site["target"]["source_index"], target);
    assert_eq!(
        site["target"]["type_id"],
        functions[target as usize].type_id
    );
    assert_eq!(
        site["target"]["import"],
        json!(functions[target as usize].import)
    );
}
fn verify_report(pair: &Pair, report: &Value) {
    assert_eq!(report["function_analysis"]["available"], true);
    let graph = &report["export_dependency_graph"];
    assert_eq!(graph["scope"], GRAPH_SCOPE);
    assert_eq!(graph["identity_unproven"], true);
    let old = raw_functions(&pair.old);
    let new = raw_functions(&pair.new);
    let expected = raw_correspondence(&old, &new);
    assert_eq!(nodes(report).len(), expected.len());
    let mut old_indices = BTreeSet::new();
    let mut new_indices = BTreeSet::new();
    for entry in nodes(report) {
        let a = number(&entry["old_source_index"]);
        let b = number(&entry["new_source_index"]);
        let depth = number(&entry["depth"]);
        assert!(old_indices.insert(a));
        assert!(new_indices.insert(b));
        assert_eq!(expected.get(&a), Some(&(b, depth)));
        let left = &old[a as usize];
        let right = &new[b as usize];
        assert_eq!(entry["type_id"], left.type_id);
        assert_eq!(left.type_id, right.type_id);
        assert_eq!(left.locals, right.locals);
        if let Some(import) = &left.import {
            assert_eq!(entry["kind"], "unique_import_binding");
            assert_eq!(entry["import"], *import);
            assert_eq!(right.import.as_ref(), Some(import));
            assert_eq!(depth, 0);
            assert_eq!(entry["references"], json!([]));
            for functions in [&old, &new] {
                assert_eq!(
                    functions
                        .iter()
                        .filter(|function| function.import.as_ref() == Some(import))
                        .count(),
                    1
                );
            }
            continue;
        }
        assert!(right.import.is_none());
        assert!(entry["import"].is_null());
        assert_eq!(left.operators.len(), right.operators.len());
        let mut refs = Vec::new();
        let mut deepest = None;
        for (index, (left_op, right_op)) in left.operators.iter().zip(&right.operators).enumerate()
        {
            match (left_op.reference, right_op.reference) {
                (Some((old_opcode, old_target)), Some((new_opcode, new_target))) => {
                    assert_eq!(old_opcode, new_opcode);
                    let &(mapped, child_depth) = expected.get(&old_target).unwrap();
                    assert_eq!(mapped, new_target);
                    assert!(child_depth < depth);
                    deepest = Some(
                        deepest.map_or(child_depth, |previous: u64| previous.max(child_depth)),
                    );
                    refs.push(
                        json!({"old_operator_index":index, "new_operator_index":index,
                        "old_offset":left_op.offset, "new_offset":right_op.offset,
                        "opcode":old_opcode, "old_target":old_target, "new_target":new_target}),
                    );
                }
                (None, None) => assert_eq!(left_op.text, right_op.text),
                _ => panic!("reference forms must remain identical"),
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
    }
    for entry in bindings(report) {
        assert_eq!(entry["pairing"], "opcode_alignment");
        assert_eq!(entry["match_scope"], SCOPE);
        assert_eq!(entry["identity_unproven"], true);
        verify_site(&entry["old"], &old);
        verify_site(&entry["new"], &new);
        if !entry["dependency_proof"].is_null() {
            let proof = &entry["dependency_proof"];
            let a = number(&proof["old_source_index"]);
            let b = number(&proof["new_source_index"]);
            let depth = number(&proof["depth"]);
            assert_eq!(entry["old"]["function_index"], a);
            assert_eq!(expected.get(&a), Some(&(b, depth)));
            root(entry, a, b, depth);
            if entry["target_changed"] == false {
                assert_eq!(entry["new"]["function_index"], b);
            }
            if entry["target_changed"] == true {
                assert_ne!(entry["new"]["function_index"], b);
            }
        } else if !entry["target_match"].is_null() {
            assert_eq!(entry["target_match"]["ambiguous"], true);
        }
    }
}

fn roles(reference: &str, swapped: bool, target: u32) -> String {
    let (a, b) = if swapped { ("B", "A") } else { ("A", "B") };
    let (declaration, result) = if reference == "ref.func" {
        ("(elem declare func 0 1)", "funcref")
    } else {
        ("", "i32")
    };
    format!(
        r#"(module (func (export "{a}") (result i32) i32.const 7)
        (func (export "{b}") (result i32) i32.const 9) {declaration}
        (func (export "run") (result {result}) {reference} {target}))"#
    )
}

#[test]
fn export_role_swaps_cannot_hide_real_call_ref_func_or_return_call_retargeting() {
    for opcode in ["call", "ref.func", "return_call"] {
        let pair = Pair::new(&roles(opcode, false, 0), &roles(opcode, true, 1));
        let report = pair.diff();
        let changed =
            caller(&report, "run").expect("real reference retargeting must remain visible");
        assert_eq!(changed["call_bindings"].as_array().unwrap().len(), 1);
        let entry = binding(&report, 0, 1);
        assert_eq!(entry["relation"], "different_target");
        assert_eq!(entry["target_changed"], true);
        root(entry, 0, 0, 0);
        assert_eq!(node(&report, 0).unwrap()["new_source_index"], 0);
        let global = report["function_matches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["old_source_index"] == 0)
            .unwrap();
        assert_eq!(global["new_source_index"], 1);
        assert_eq!(global["reason"], "same_stable_id");
        assert_ne!(
            entry["target_match"]["new_source_index"],
            global["new_source_index"]
        );
    }
}

#[test]
fn changing_only_export_roles_cannot_invent_a_caller_binding_modification() {
    for opcode in ["call", "ref.func", "return_call"] {
        let pair = Pair::new(&roles(opcode, false, 0), &roles(opcode, true, 0));
        let report = pair.diff();
        assert!(caller(&report, "run").is_none());
        assert!(bindings(&report).is_empty());
        assert_eq!(node(&report, 0).unwrap()["new_source_index"], 0);
        let exports = report["export_binding_notes"].as_array().unwrap();
        assert_eq!(exports.len(), 2);
        assert!(exports.iter().all(
            |entry| entry["relation"] == "different_target" && entry["target_changed"] == true
        ));
    }
}

#[test]
fn unmatched_surplus_imports_remain_ambiguous_after_duplicate_occurrences_shrink() {
    for reference in ["call", "return_call", "ref.func"] {
        let (result, elem) = if reference == "ref.func" {
            ("funcref", "(elem declare func 0 1)")
        } else {
            ("i32", "")
        };
        let old = format!(
            r#"(module (import "m" "f" (func (result i32)))
            (import "m" "f" (func (result i32))) {elem}
            (func (export "run") (result {result}) {reference} 1))"#
        );
        let new = format!(
            r#"(module (import "m" "f" (func (result i32)))
            {} (func (export "run") (result {result}) {reference} 0))"#,
            if reference == "ref.func" {
                "(elem declare func 0)"
            } else {
                ""
            }
        );
        let report = Pair::new(&old, &new).diff();
        let entry = binding(&report, 1, 0);
        assert_eq!(entry["relation"], "ambiguous_target");
        unproved(entry);
        assert!(entry["old"]["target"]["import"] == entry["new"]["target"]["import"]);
        assert!(node(&report, 1).is_none());
        assert!(report["function_matches"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["old_source_index"] != 1));
    }
    // Equal raw indices cannot hide the same unmatched-surplus ambiguity.
    let old = r#"(module (import "m" "f" (func)) (import "m" "f" (func))
        (import "m" "f" (func)) (func (export "run") call 2))"#;
    let new = r#"(module (import "u" "other" (func)) (import "m" "f" (func))
        (import "m" "f" (func)) (func (export "run") call 2))"#;
    let report = Pair::new(old, new).diff();
    let entry = binding(&report, 2, 2);
    assert_eq!(entry["relation"], "ambiguous_target");
    unproved(entry);
    assert!(caller(&report, "run").is_none());
}

#[test]
fn consuming_an_export_anchor_cannot_make_a_duplicate_defined_target_unique() {
    let old = r#"(module (func (export "a") (result i32) i32.const 7)
        (func (result i32) i32.const 7) (func (export "run") (result i32) call 1))"#;
    let new = r#"(module (import "u" "unused" (func))
        (func (export "a") (result i32) i32.const 7)
        (func (result i32) i32.const 7) (func (export "run") (result i32) call 2))"#;
    let report = Pair::new(old, new).diff();
    let entry = binding(&report, 1, 2);
    assert_eq!(entry["relation"], "ambiguous_target");
    unproved(entry);
    assert!(node(&report, 1).is_none());
    assert!(nodes(&report).is_empty());
}

#[test]
fn unexported_start_callers_share_multilayer_static_proofs_after_reordering() {
    let old = r#"(module (func (result i32) i32.const 7)
        (func (result i32) call 0) (func call 1 drop) (start 2))"#;
    let new = r#"(module (import "u" "unused" (func))
        (func call 3 drop) (func (result i32) i32.const 7)
        (func (result i32) call 2) (start 1))"#;
    let pair = Pair::new(old, new);
    let report = pair.diff();
    assert!(report["export_binding_notes"]
        .as_array()
        .unwrap()
        .is_empty());
    let entry = binding(&report, 1, 3);
    assert_eq!(entry["relation"], "same_target_index_relocated");
    assert_eq!(entry["target_changed"], false);
    root(entry, 1, 3, 1);
    assert_eq!(node(&report, 2).unwrap()["depth"], 2);
    assert_eq!(node(&report, 2).unwrap()["new_source_index"], 1);
    for arguments in [vec!["--format", "text"], vec!["--short"]] {
        let mut args = vec!["diff", pair.old_path.as_str(), pair.new_path.as_str()];
        args.extend(arguments);
        let text = success(&args).to_lowercase();
        assert!(text.contains("dependency proof"));
        assert!(text.contains("identity unproven") || text.contains("identity_unproven=true"));
    }
    let full = success(&["diff", &pair.old_path, &pair.new_path, "--format", "text"]);
    assert!(full.contains("old operator["));
    assert!(full.contains("new operator["));
}

#[test]
fn reference_bearing_targets_with_duplicate_dependencies_remain_unproved() {
    let old = r#"(module (func (result i32) i32.const 7)
        (func (result i32) i32.const 7) (func (export "wrap") (result i32) call 0)
        (func (export "run") (result i32) call 2))"#;
    let new = r#"(module (import "u" "unused" (func))
        (func (result i32) i32.const 7) (func (result i32) i32.const 7)
        (func (export "wrap") (result i32) call 1)
        (func (export "run") (result i32) call 3))"#;
    let report = Pair::new(old, new).diff();
    unproved(binding(&report, 2, 3));
    assert!(nodes(&report).is_empty());
    assert!(bindings(&report)
        .iter()
        .all(|entry| entry["target_changed"].is_null()));
}

#[test]
fn recursive_export_roles_cannot_bootstrap_call_binding_proofs() {
    for (old_body, new_body) in [("call 0", "call 1"), ("call 1", "call 2")] {
        let (extra_old, extra_new) = if old_body == "call 1" {
            ("(func (result i32) call 0)", "(func (result i32) call 1)")
        } else {
            ("", "")
        };
        let old = format!(
            r#"(module (func (export "cycle") (result i32) {old_body})
            {extra_old} (func (export "run") (result i32) call 0))"#
        );
        let new = format!(
            r#"(module (import "u" "unused" (func))
            (func (export "cycle") (result i32) {new_body})
            {extra_new} (func (export "run") (result i32) call 1))"#
        );
        let report = Pair::new(&old, &new).diff();
        assert!(nodes(&report).is_empty());
        let run = caller(&report, "run").unwrap();
        let entry = &run["call_bindings"][0];
        assert_eq!(entry["old"]["function_index"], 0);
        assert_eq!(entry["new"]["function_index"], 1);
        unproved(entry);
        assert!(bindings(&report)
            .iter()
            .all(|entry| entry["target_changed"].is_null()));
    }
}

#[test]
fn same_index_implementation_changes_and_opcode_alignment_preserve_caller_evidence() {
    for reference in ["call", "ref.func", "return_call"] {
        let old = roles(reference, false, 0);
        let new = old.replace("i32.const 7", "i32.const 8");
        let report = Pair::new(&old, &new).diff();
        assert!(caller(&report, "run").is_none());
        assert!(bindings(&report).is_empty());
        assert!(node(&report, 0).is_none());
        assert_eq!(report["summary"]["functions_changed"], 1);
    }
    let old = r#"(module (func (export "A") (result i32) i32.const 7)
        (func (export "B") (result i32) i32.const 9)
        (func (export "run") (result i32) call 0 drop call 1))"#;
    let inserted = r#"(module (func (export "B") (result i32) i32.const 7)
        (func (export "A") (result i32) i32.const 9)
        (func (export "run") (result i32) nop call 1 drop call 1))"#;
    let report = Pair::new(old, inserted).diff();
    let entry = binding(&report, 0, 1);
    assert_eq!(entry["old"]["operator_index"], 0);
    assert_eq!(entry["new"]["operator_index"], 1);
    assert_eq!(entry["target_changed"], true);
    root(entry, 0, 0, 0);
    let removed = old.replace("call 0 drop call 1", "i32.const 3");
    for (old, new, relation) in [
        (old, removed.as_str(), "site_removed"),
        (removed.as_str(), old, "site_added"),
    ] {
        let report = Pair::new(old, new).diff();
        let entries = bindings(&report);
        assert_eq!(entries.len(), 2);
        for entry in entries {
            assert_eq!(entry["relation"], relation);
            assert!(entry["target_changed"].is_null());
            assert_eq!(entry["old"].is_null(), relation == "site_added");
            assert_eq!(entry["new"].is_null(), relation == "site_removed");
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn span(span: &Value, bytes: &[u8]) -> (usize, usize) {
    let a = usize::try_from(number(&span["start"])).unwrap();
    let b = usize::try_from(number(&span["end"])).unwrap();
    assert!(a <= b && b <= bytes.len());
    (a, b)
}
fn regions(audit: &Value) -> Vec<&Value> {
    fn walk<'a>(entries: &'a Value, output: &mut Vec<&'a Value>) {
        for entry in entries.as_array().unwrap() {
            output.push(entry);
            for name in ["regions", "children"] {
                if let Some(children) = entry.get(name) {
                    walk(children, output);
                }
            }
        }
    }
    let mut result = Vec::new();
    walk(&audit["sections"], &mut result);
    result
}
fn replay(old: &[u8], new: &[u8], edits: &Value) {
    let (mut a, mut b) = (0, 0);
    let mut output = Vec::new();
    for edit in edits.as_array().unwrap() {
        let (x, y) = span(&edit["old_span"], old);
        let (u, v) = span(&edit["new_span"], new);
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
fn dependency_bindings_preserve_four_profile_raw_replay_patches_and_physical_history() {
    for reference in ["call", "ref.func", "return_call"] {
        let pair = Pair::new(&roles(reference, false, 0), &roles(reference, true, 1));
        let mut prior = None;
        let mut selected = Value::Null;
        let path = "code[0]/function[2]/operator[0]";
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
            verify_report(&pair, &report);
            assert_eq!(report["binary_changed"], true);
            assert_eq!(binding(&report, 0, 1)["target_changed"], true);
            for (role, bytes) in [("old", &pair.old), ("new", &pair.new)] {
                let audit = &report["audit"][role];
                assert_eq!(audit["standard"]["selected_standard"], profile);
                let valid = !(reference == "ref.func" && profile == "core1"
                    || reference == "return_call" && matches!(profile, "core1" | "core2"));
                assert_eq!(
                    audit["standard"]["validation"],
                    if valid { "valid" } else { "invalid" }
                );
                for region in regions(audit) {
                    span(&region["span"], bytes);
                }
                for evidence in audit["standard"]["evidence"].as_array().unwrap() {
                    let (a, b) = span(&evidence["span"], bytes);
                    assert_eq!(evidence["raw_hex"], hex(&bytes[a..b]));
                }
            }
            let direct = audit::compare_with_standard(&pair.old, &pair.new, standard).unwrap();
            assert_eq!(
                report["audit"]["edits"],
                serde_json::to_value(direct.edits).unwrap()
            );
            replay(&pair.old, &pair.new, &report["audit"]["edits"]);
            let invariant = json!([
                report["audit"]["edits"],
                report["export_dependency_graph"],
                bindings(&report)
            ]);
            if let Some(previous) = &prior {
                assert_eq!(previous, &invariant);
            }
            prior = Some(invariant);
            selected = regions(&report["audit"]["new"])
                .into_iter()
                .find(|region| region["path"] == path)
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
        let named = run_json(&["trace", &repo, "HEAD", "--path", path]);
        let (a, b) = span(&selected, &pair.new);
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
            let (a, b) = span(&edit["old_span"], &pair.old);
            let (c, d) = span(&edit["new_span"], &pair.new);
            assert_eq!(edit["old_hex"], hex(&pair.old[a..b]));
            assert_eq!(edit["new_hex"], hex(&pair.new[c..d]));
        }
        for gap in edges[0]["gap_mappings"].as_array().unwrap() {
            let (a, b) = span(&gap["parent"]["span"], &pair.old);
            let (c, d) = span(&gap["child"]["span"], &pair.new);
            assert_eq!(&pair.old[a..b], &pair.new[c..d]);
        }
        let fsck = run_json(&["fsck", &repo]);
        assert_eq!(fsck["commits"], 2);
        assert_eq!(fsck["wasm_blobs"], 2);
        assert_eq!(snapshot(Path::new(&repo)), before);
        assert_eq!(std::fs::read(&pair.old_path).unwrap(), pair.old);
        assert_eq!(std::fs::read(&pair.new_path).unwrap(), pair.new);
    }
}
