//! Fixed export binding candidates, separate from raw export keys and history.
//! Fixtures and repositories stay in /tmp; no Wasm guest is executed.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::{audit, patch::BytePatch, standard::Standard};
use wasmparser::{ExternalKind, Parser, Payload, Validator, WasmFeatures};

const PROFILES: [(&str, Standard); 4] = [
    ("core1", Standard::Core1),
    ("core2", Standard::Core2),
    ("core3", Standard::Core3),
    ("all-known", Standard::AllKnown),
];
const SINGLE: &str = r#"(module (func (export "run")))"#;
const SHIFTED: &str = r#"(module (import "env" "unused" (func)) (func (export "run")))"#;
const TARGETS: &str = r#"(module
    (func (result i32) i32.const 1) (func (result i32) i32.const 2)
    (export "run" (func 0)))"#;
const RETARGETED: &str = r#"(module
    (func (result i32) i32.const 1) (func (result i32) i32.const 2)
    (export "run" (func 1)))"#;
const TWO_EXPORTS: &str = r#"(module
    (func (result i32) i32.const 1) (func (result i32) i32.const 2)
    (export "run" (func 0)) (export "aux" (func 1)))"#;
const SWAPPED: &str = r#"(module
    (func (result i32) i32.const 1) (func (result i32) i32.const 2)
    (export "run" (func 1)) (export "aux" (func 0)))"#;
const DUPLICATES: &str = r#"(module (func) (func) (export "run" (func 0)))"#;
const DUPLICATE_RETARGET: &str = r#"(module (func) (func) (export "run" (func 1)))"#;
const IMPORTS: &str = r#"(module
    (import "m" "a" (func (result i32))) (import "m" "b" (func (result i32)))
    (export "run" (func 0)))"#;
const IMPORTS_REORDERED: &str = r#"(module
    (import "m" "b" (func (result i32))) (import "m" "a" (func (result i32)))
    (export "run" (func 1)))"#;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-export-bindings-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
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
    serde_json::from_str(&success(arguments)).expect("CLI JSON")
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
        verify_sites(self, &report);
        report
    }
}
fn notes(report: &Value) -> &[Value] {
    report["export_binding_notes"]
        .as_array()
        .expect("export binding notes")
}
fn note<'a>(report: &'a Value, name: &str) -> &'a Value {
    let matches: Vec<_> = notes(report)
        .iter()
        .filter(|entry| entry["old"]["name"] == name)
        .collect();
    assert_eq!(matches.len(), 1, "one paired export note for {name}");
    matches[0]
}
fn check_note<'a>(
    report: &'a Value,
    name: &str,
    relation: &str,
    changed: Option<bool>,
    old: u32,
    new: u32,
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
fn strong_candidate(entry: &Value, old: u32, new: u32) {
    let candidate = &entry["target_match"];
    assert_eq!(candidate["old_source_index"], old);
    assert_eq!(candidate["new_source_index"], new);
    assert_eq!(candidate["ambiguous"], false);
    assert_eq!(candidate["reference_context_complete"], true);
    assert!(matches!(
        candidate["reason"].as_str(),
        Some("same_exact_body_hash" | "same_canonical_body_hash")
    ));
    let confidence = candidate["confidence"].as_f64().unwrap();
    assert!(confidence > 0.0 && confidence <= 1.0);
}
fn raw_export_counts(report: &Value, count: usize) {
    assert_eq!(report["summary"]["exports_added"], count);
    assert_eq!(report["summary"]["exports_removed"], count);
    for (kind, expected) in [("export_added", count), ("export_removed", count)] {
        let changes: Vec<_> = report["changes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["kind"] == kind)
            .collect();
        assert_eq!(changes.len(), expected);
        assert!(changes
            .iter()
            .all(|entry| entry["id"].as_str().unwrap().contains(":target:")));
    }
}
fn verify_sites(pair: &Pair, report: &Value) {
    if notes(report).is_empty() {
        return;
    }
    for (role, bytes, path) in [
        ("old", &pair.old, &pair.old_path),
        ("new", &pair.new, &pair.new_path),
    ] {
        let inspection = run_json(&["inspect", path, "--json"]);
        let module = &inspection["module"];
        let mut exports = Vec::new();
        for payload in Parser::new(0).parse_all(bytes) {
            if let Payload::ExportSection(section) = payload.unwrap() {
                for item in section {
                    exports.push(item.unwrap());
                }
            }
        }
        for entry in notes(report) {
            assert_eq!(entry["pairing"], "export_name_kind");
            assert_eq!(
                entry["match_scope"],
                "exports_removed_from_candidate_matching"
            );
            assert_eq!(entry["identity_unproven"], true);
            let site = &entry[role];
            let export_index = site["export_index"].as_u64().unwrap() as usize;
            let decoded = &exports[export_index];
            assert_eq!(decoded.kind, ExternalKind::Func);
            assert_eq!(site["name"], decoded.name);
            assert_eq!(site["kind"], "func");
            assert_eq!(site["item_index"], decoded.index);
            assert_eq!(site["exact"], false);
            let function = module["functions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|function| function["source_index"] == decoded.index)
                .unwrap();
            let target = &site["target"];
            for field in [
                "id",
                "source_index",
                "type_index",
                "type_id",
                "export_names",
            ] {
                assert_eq!(
                    target[field], function[field],
                    "original target {role}.{field}"
                );
            }
            if function["kind"] == "Imported" {
                assert_eq!(target["kind"], "imported");
                let import = module["imports"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|item| item["kind"] == "Func")
                    .nth(decoded.index as usize)
                    .unwrap();
                assert_eq!(
                    target["import"],
                    json!({
                        "module": import["module"], "name": import["name"],
                        "type_id": import["type_ref"]["Func"]["type_id"],
                        "exact": import["type_ref"]["Func"]["exact"]
                    })
                );
            } else {
                assert_eq!(target["kind"], "defined");
                assert!(target["import"].is_null());
            }
        }
    }
}

#[test]
fn unused_import_relocates_a_candidate_without_erasing_raw_export_changes_or_text() {
    let pair = Pair::new(SINGLE, SHIFTED);
    let report = pair.diff();
    raw_export_counts(&report, 1);
    assert_eq!(report["summary"]["functions_changed"], 0);
    assert_eq!(notes(&report).len(), 1);
    let entry = check_note(
        &report,
        "run",
        "candidate_same_target_index_relocated",
        Some(false),
        0,
        1,
    );
    strong_candidate(entry, 0, 1);
    for extra in [vec!["--format", "text"], vec!["--short"]] {
        let mut arguments = vec!["diff", pair.old_path.as_str(), pair.new_path.as_str()];
        arguments.extend(extra);
        let text = success(&arguments);
        let lower = text.to_lowercase();
        assert!(lower.contains("export binding"));
        assert!(lower.contains("raw target keys"));
        assert!(lower.contains("identity unproven") || lower.contains("identity_unproven=true"));
    }
}

#[test]
fn retargets_and_export_swaps_cannot_use_their_own_export_name_as_identity_proof() {
    for (old, new, expected) in [(TARGETS, RETARGETED, 1), (TWO_EXPORTS, SWAPPED, 2)] {
        let pair = Pair::new(old, new);
        let report = pair.diff();
        raw_export_counts(&report, expected);
        assert_eq!(notes(&report).len(), expected);
        let run = check_note(&report, "run", "different_target", Some(true), 0, 1);
        strong_candidate(run, 0, 0);
        let circular = report["function_matches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|matched| matched["old_source_index"] == 0)
            .unwrap();
        assert_eq!(circular["new_source_index"], 1);
        assert_eq!(circular["reason"], "same_stable_id");
        assert_ne!(
            run["target_match"]["new_source_index"],
            circular["new_source_index"]
        );
        if expected == 2 {
            let aux = check_note(&report, "aux", "different_target", Some(true), 1, 0);
            strong_candidate(aux, 1, 1);
        }
    }
}

#[test]
fn duplicate_defined_bodies_keep_ambiguity_even_with_a_unique_export_role() {
    let shifted = r#"(module (import "env" "unused" (func))
        (func) (func) (export "run" (func 2)))"#;
    for (new, index) in [(DUPLICATE_RETARGET, 1), (shifted, 2)] {
        let pair = Pair::new(DUPLICATES, new);
        let report = pair.diff();
        raw_export_counts(&report, 1);
        let entry = check_note(&report, "run", "ambiguous_target", None, 0, index);
        assert_eq!(entry["target_match"]["ambiguous"], true);
        assert_ne!(entry["target_match"]["reason"], "same_stable_id");
    }
}

#[test]
fn imported_targets_compare_complete_binding_tuples_instead_of_raw_indices() {
    let pair = Pair::new(IMPORTS, IMPORTS_REORDERED);
    let report = pair.diff();
    raw_export_counts(&report, 1);
    let entry = check_note(
        &report,
        "run",
        "candidate_same_target_index_relocated",
        Some(false),
        0,
        1,
    );
    assert_eq!(
        entry["old"]["target"]["import"],
        entry["new"]["target"]["import"]
    );
    assert_eq!(
        entry["old"]["target"]["import"],
        json!({
            "module": "m", "name": "a", "type_id": "type:->i32", "exact": false
        })
    );
    let old = r#"(module (import "m" "a" (func (result i32))) (export "run" (func 0)))"#;
    for new in [
        r#"(module (import "m" "c" (func (result i32))) (export "run" (func 0)))"#,
        r#"(module (import "n" "a" (func (result i32))) (export "run" (func 0)))"#,
        r#"(module (import "m" "a" (func (param i32) (result i32))) (export "run" (func 0)))"#,
    ] {
        let pair = Pair::new(old, new);
        let report = pair.diff();
        raw_export_counts(&report, 0);
        let entry = check_note(&report, "run", "different_target", Some(true), 0, 0);
        assert_ne!(
            entry["old"]["target"]["import"],
            entry["new"]["target"]["import"]
        );
    }
}

#[test]
fn duplicate_import_occurrences_stay_ambiguous_and_identical_inputs_add_no_notes() {
    let old = r#"(module (import "m" "f" (func)) (import "m" "f" (func))
        (export "run" (func 0)))"#;
    let new = r#"(module (import "env" "unused" (func))
        (import "m" "f" (func)) (import "m" "f" (func)) (export "run" (func 1)))"#;
    let pair = Pair::new(old, new);
    let report = pair.diff();
    let entry = check_note(&report, "run", "ambiguous_target", None, 0, 1);
    assert_eq!(
        entry["old"]["target"]["import"],
        entry["new"]["target"]["import"]
    );
    assert_eq!(entry["target_match"]["ambiguous"], true);
    raw_export_counts(&report, 1);
    for source in [old, DUPLICATES, SINGLE] {
        let pair = Pair::new(source, source);
        let report = pair.diff();
        assert_eq!(report["binary_changed"], false);
        assert!(notes(&report).is_empty());
        assert!(report["changes"].as_array().unwrap().is_empty());
    }
}

#[test]
fn names_aliases_implementation_changes_and_unknown_grammar_do_not_invent_bindings() {
    let rename = Pair::new(
        r#"(module (func (export "f")))"#,
        r#"(module (func (export "g")))"#,
    );
    let report = rename.diff();
    raw_export_counts(&report, 1);
    assert!(
        notes(&report).is_empty(),
        "different names are not a paired export binding"
    );
    let aliased = r#"(module (func (result i32) i32.const 1) (func (result i32) i32.const 2)
        (export "run" (func 0)) (export "aux" (func 0)))"#;
    let pair = Pair::new(aliased, TWO_EXPORTS);
    let report = pair.diff();
    assert_eq!(notes(&report).len(), 1);
    strong_candidate(
        check_note(&report, "aux", "different_target", Some(true), 0, 1),
        0,
        0,
    );
    raw_export_counts(&report, 1);
    let changed_body = Pair::new(
        r#"(module (func (export "run") (result i32) i32.const 1))"#,
        r#"(module (func (export "run") (result i32) i32.const 2))"#,
    );
    let report = changed_body.diff();
    assert!(notes(&report).is_empty());
    assert_eq!(report["summary"]["functions_changed"], 1);
    raw_export_counts(&report, 0);
    let reordered = r#"(module (func (result i32) i32.const 1) (func (result i32) i32.const 2)
        (export "aux" (func 1)) (export "run" (func 0)))"#;
    let report = Pair::new(TWO_EXPORTS, reordered).diff();
    assert!(notes(&report).is_empty());
    raw_export_counts(&report, 0);
    let weak = Pair::new(
        r#"(module (func (export "run") (result i32) i32.const 1))"#,
        r#"(module (import "env" "unused" (func)) (func (export "run") (result i32) i32.const 2))"#,
    );
    let report = weak.diff();
    let entry = check_note(&report, "run", "unresolved_target", None, 0, 1);
    if !entry["target_match"].is_null() {
        assert_eq!(entry["target_match"]["reason"], "similarity_fallback");
    }
    let temp = Temp::new();
    let malformed = [
        0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 7, 5, 1, 1, 0xff, 0, 0, 10,
        4, 1, 2, 0, 0x0b,
    ];
    let old = temp.write("unknown.wasm", &malformed);
    let mut fixed = malformed;
    fixed[22] = b'x';
    let new = temp.write("known.wasm", &fixed);
    let report = run_json(&["diff", &old, &new, "--format", "json"]);
    assert_eq!(report["function_analysis"]["available"], false);
    assert!(notes(&report).is_empty());
    assert_eq!(report["binary_changed"], true);
    assert!(!report["audit"]["edits"].as_array().unwrap().is_empty());
}

#[test]
fn static_reference_wrappers_require_unique_dependency_proofs() {
    let cases = [
        (
            r#"(module (func (result i32) i32.const 1) (func (result i32) i32.const 1)
                (func (export "run") (result i32) call 0))"#,
            r#"(module (import "env" "unused" (func))
                (func (result i32) i32.const 1) (func (result i32) i32.const 1)
                (func (export "run") (result i32) call 1))"#,
            2,
            3,
        ),
        (
            r#"(module (import "m" "f" (func (result i32)))
                (import "m" "f" (func (result i32))) (func (export "run") (result i32) call 0))"#,
            r#"(module (import "env" "unused" (func))
                (import "m" "f" (func (result i32))) (import "m" "f" (func (result i32)))
                (func (export "run") (result i32) call 1))"#,
            2,
            3,
        ),
        (
            r#"(module (func (result i32) i32.const 1)
                (func (export "run") (result i32) call 0))"#,
            r#"(module (import "env" "unused" (func)) (func (result i32) i32.const 1)
                (func (export "run") (result i32) call 1))"#,
            1,
            2,
        ),
        (
            r#"(module (func) (elem declare func 0)
                (func (export "run") (result funcref) ref.func 0))"#,
            r#"(module (import "env" "unused" (func)) (func) (elem declare func 1)
                (func (export "run") (result funcref) ref.func 1))"#,
            1,
            2,
        ),
    ];
    for (index, (old, new, old_index, new_index)) in cases.into_iter().enumerate() {
        let pair = Pair::new(old, new);
        let report = pair.diff();
        let proved = index >= 2;
        let entry = check_note(
            &report,
            "run",
            if proved {
                "candidate_same_target_index_relocated"
            } else {
                "unresolved_target"
            },
            if proved { Some(false) } else { None },
            old_index,
            new_index,
        );
        if proved {
            assert_eq!(
                entry["dependency_proof"],
                json!({
                    "old_source_index": old_index, "new_source_index": new_index, "depth": 1
                })
            );
            assert_eq!(
                entry["target_match"]["reason"],
                "same_matched_reference_body"
            );
            assert_eq!(entry["target_match"]["ambiguous"], false);
            assert_eq!(entry["target_match"]["reference_context_complete"], true);
        } else {
            assert!(entry["target_match"].is_null());
            assert!(
                entry["dependency_proof"].is_null(),
                "ambiguous callees cannot prove a wrapper"
            );
        }
        raw_export_counts(&report, 1);
        raw_audit(&report["audit"]["old"], &pair.old);
        raw_audit(&report["audit"]["new"], &pair.new);
        assert!(!report["audit"]["edits"].as_array().unwrap().is_empty());
        replay(&pair.old, &pair.new, &report["audit"]["edits"]);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn range(span: &Value, bytes: &[u8]) -> (usize, usize) {
    let a = usize::try_from(span["start"].as_u64().unwrap()).unwrap();
    let b = usize::try_from(span["end"].as_u64().unwrap()).unwrap();
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
fn raw_audit(module: &Value, bytes: &[u8]) {
    for entry in regions(module) {
        range(&entry["span"], bytes);
    }
    for evidence in module["standard"]["evidence"].as_array().unwrap() {
        let (a, b) = range(&evidence["span"], bytes);
        assert_eq!(evidence["raw_hex"], hex(&bytes[a..b]));
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
fn candidate_notes_preserve_four_profile_raw_edits_patches_and_repository_trace() {
    for (label, old, new) in [
        ("shift", SINGLE, SHIFTED),
        ("retarget", TARGETS, RETARGETED),
        ("swap", TWO_EXPORTS, SWAPPED),
        ("duplicate", DUPLICATES, DUPLICATE_RETARGET),
        ("import-reorder", IMPORTS, IMPORTS_REORDERED),
        (
            "rename",
            r#"(module (func (export "f")))"#,
            r#"(module (func (export "g")))"#,
        ),
    ] {
        let pair = Pair::new(old, new);
        let mut prior_edits = None;
        let mut prior_notes = None;
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
            for (role, bytes) in [("old", &pair.old), ("new", &pair.new)] {
                raw_audit(&report["audit"][role], bytes);
                assert_eq!(
                    report["audit"][role]["standard"]["selected_standard"],
                    profile
                );
            }
            let independent = audit::compare_with_standard(&pair.old, &pair.new, standard).unwrap();
            assert_eq!(
                report["audit"]["edits"],
                serde_json::to_value(&independent.edits).unwrap()
            );
            replay(&pair.old, &pair.new, &report["audit"]["edits"]);
            if let Some(edits) = &prior_edits {
                assert_eq!(edits, &report["audit"]["edits"]);
            }
            if let Some(notes) = &prior_notes {
                assert_eq!(notes, &report["export_binding_notes"]);
            }
            prior_edits = Some(report["audit"]["edits"].clone());
            prior_notes = Some(report["export_binding_notes"].clone());
            selected = regions(&report["audit"]["new"])
                .into_iter()
                .find(|entry| entry["path"] == "export[0]/entry[0]")
                .unwrap()["span"]
                .clone();
        }
        for (direction, old, new, old_path, new_path) in [
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
            let patch = pair.temp.path(&format!("{direction}.uwgp"));
            let output = pair.temp.path(&format!("{direction}.wasm"));
            run_json(&["patch", old_path, new_path, "--output", &patch]);
            let encoded = std::fs::read(&patch).unwrap();
            let stored: Value = serde_json::from_slice(&encoded).unwrap();
            replay(old, new, &stored["edits"]);
            assert_eq!(
                BytePatch::from_bytes(&encoded).unwrap().apply(old).unwrap(),
                *new
            );
            run_json(&["apply", old_path, &patch, "--output", &output]);
            assert_eq!(std::fs::read(output).unwrap(), *new);
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
        let (start, end) = range(&selected, &pair.new);
        let numeric = run_json(&["trace", &repo, "HEAD", "--range", &format!("{start}:{end}")]);
        assert_eq!(named["selection"]["span"], selected);
        assert_eq!(named["trace"], numeric["trace"]);
        assert_eq!(named["repository_verified"], true);
        assert_eq!(named["trace"]["complete"], true);
        assert_eq!(named["trace"]["identity_unproven"], true);
        let edges = named["trace"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1, "{label}");
        let edge = &edges[0];
        assert_eq!(edge["parent"], old_id);
        assert_eq!(edge["child"], new_id);
        assert!(!edge["events"].as_array().unwrap().is_empty());
        for event in edge["events"].as_array().unwrap() {
            let edit = &event["edit"];
            let (a, b) = range(&edit["old_span"], &pair.old);
            let (c, d) = range(&edit["new_span"], &pair.new);
            assert_eq!(edit["old_hex"], hex(&pair.old[a..b]));
            assert_eq!(edit["new_hex"], hex(&pair.new[c..d]));
        }
        for gap in edge["gap_mappings"].as_array().unwrap() {
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
}
