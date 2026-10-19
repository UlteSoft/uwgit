//! End-to-end repository merges. Every fixture, checkout, clone and bundle is
//! confined to /tmp. The tests encode/validate Wasm but never execute it.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use wasmparser::{Operator, Parser, Payload, Validator, WasmFeatures};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-merge-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn invoke(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(arguments)
        .output()
        .expect("execute wasm-git")
}

fn success(arguments: &[&str]) -> String {
    let output = invoke(arguments);
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn json_success(arguments: &[&str]) -> Value {
    serde_json::from_str(&success(arguments)).expect("JSON result")
}

fn wat(source: &str) -> Vec<u8> {
    let bytes = wat::parse_str(source).expect("encode WAT merge fixture");
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(&bytes)
        .expect("merge fixture must be valid before deliberate unknown-opcode mutation");
    bytes
}

fn functions(a: i32, b: i32, nops_in_a: usize) -> Vec<u8> {
    wat(&format!(
        r#"(module
        (func (export "a") (result i32) {} i32.const {a})
        (func (export "b") (result i32) i32.const {b}))"#,
        "nop ".repeat(nops_in_a)
    ))
}

fn commit(repo: &str, input: &str, bytes: &[u8], message: &str) -> String {
    std::fs::write(input, bytes).unwrap();
    success(&["commit", repo, input, "-m", message])
        .split_whitespace()
        .last()
        .unwrap()
        .to_owned()
}

struct History {
    tmp: Temp,
    repo: String,
    base: String,
    left: String,
    right: String,
    base_bytes: Vec<u8>,
    left_bytes: Vec<u8>,
    right_bytes: Vec<u8>,
}
impl History {
    fn fork(label: &str, base_bytes: Vec<u8>, left_bytes: Vec<u8>, right_bytes: Vec<u8>) -> Self {
        let tmp = Temp::new(label);
        let repo = tmp.path("repo");
        let input = tmp.path("input.wasm");
        success(&["init", &repo]);
        let base = commit(&repo, &input, &base_bytes, "base");
        success(&["branch", &repo, "right", &base]);
        let left = commit(&repo, &input, &left_bytes, "left");
        success(&["switch", &repo, "right"]);
        let right = commit(&repo, &input, &right_bytes, "right");
        success(&["switch", &repo, "main"]);
        Self {
            tmp,
            repo,
            base,
            left,
            right,
            base_bytes,
            left_bytes,
            right_bytes,
        }
    }
    fn merge(&self) -> Value {
        json_success(&["merge", &self.repo, &self.right, "-m", "combine"])
    }
    fn checkout(&self, revision: &str, name: &str) -> Vec<u8> {
        let output = self.tmp.path(name);
        success(&["checkout", &self.repo, revision, &output]);
        std::fs::read(output).unwrap()
    }
}

fn snapshot(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), result);
            } else {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(directory, directory, &mut result);
    result
}

fn store_snapshot(repo: &str) -> BTreeMap<PathBuf, Vec<u8>> {
    snapshot(&Path::new(repo).join(".uwgit"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_conflict(history: &History) -> Value {
    let before = store_snapshot(&history.repo);
    let output = invoke(&[
        "merge",
        &history.repo,
        &history.right,
        "-m",
        "conflicting changes",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).expect("conflict is a JSON result");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["status"], "conflict");
    assert_eq!(result["old_head"], history.left);
    assert_eq!(result["target"], history.right);
    assert!(result["commit"].is_null());
    assert_eq!(result["report"]["status"], "conflict");
    let conflicts = result["report"]["conflicts"].as_array().unwrap();
    assert!(!conflicts.is_empty());
    for conflict in conflicts {
        assert!(!conflict["path"].as_str().unwrap().is_empty());
        assert!(!conflict["reason"].as_str().unwrap().is_empty());
        for (side, bytes) in [
            ("base", &history.base_bytes),
            ("ours", &history.left_bytes),
            ("theirs", &history.right_bytes),
        ] {
            let record = &conflict[side];
            let start = record["span"]["start"].as_u64().unwrap() as usize;
            let end = record["span"]["end"].as_u64().unwrap() as usize;
            assert!(
                start <= end && end <= bytes.len(),
                "physical {side} conflict span"
            );
            assert_eq!(record["hex"], hex(&bytes[start..end]));
        }
    }
    assert_eq!(
        store_snapshot(&history.repo),
        before,
        "conflicts must publish no objects or refs and leave no lock/temp files"
    );
    result
}

fn assert_exported_constant(inspection: &Value, export: &str, expected: i32) {
    let function = inspection["module"]["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|function| {
            function["export_names"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name == export)
        })
        .unwrap();
    assert!(function["operators"]
        .as_array()
        .unwrap()
        .iter()
        .any(|operator| operator["opcode"] == "I32Const"
            && operator["immediate"]["I32Const"] == expected));
}

fn verify_history_and_transfers(history: &History, merged: &str, expected: &[u8]) {
    let shown = json_success(&["show", &history.repo, merged]);
    assert_eq!(shown["parents"], json!([history.left, history.right]));
    let log = json_success(&["log", &history.repo, merged]);
    assert_eq!(log.as_array().unwrap().len(), 4);
    assert_eq!(json_success(&["fsck", &history.repo])["commits"], 4);
    assert_eq!(history.checkout(merged, "merged-exact.wasm"), expected);
    let inspection = json_success(&["inspect", merged, "--repo", &history.repo]);
    assert_eq!(
        inspection["audit"]["validation"],
        "valid_with_all_known_features"
    );

    let clone = history.tmp.path("clone");
    success(&["clone", &history.repo, &clone]);
    assert_eq!(json_success(&["show", &clone, "HEAD"])["id"], merged);
    assert_eq!(
        json_success(&["show", &clone, "HEAD"])["parents"],
        shown["parents"]
    );
    let clone_output = history.tmp.path("clone-exact.wasm");
    success(&["checkout", &clone, "HEAD", &clone_output]);
    assert_eq!(std::fs::read(clone_output).unwrap(), expected);
    assert_eq!(json_success(&["fsck", &clone])["commits"], 4);

    let bundle = history.tmp.path("merged.bundle");
    let recipient = history.tmp.path("recipient");
    success(&["bundle", &history.repo, &bundle]);
    success(&["init", &recipient]);
    success(&["unbundle", &recipient, &bundle, "incoming"]);
    assert_eq!(
        json_success(&["show", &recipient, "incoming"])["id"],
        merged
    );
    assert_eq!(
        json_success(&["show", &recipient, "incoming"])["parents"],
        shown["parents"]
    );
    let imported_output = history.tmp.path("imported-exact.wasm");
    success(&["checkout", &recipient, "incoming", &imported_output]);
    assert_eq!(std::fs::read(imported_output).unwrap(), expected);
    assert_eq!(json_success(&["fsck", &recipient])["commits"], 4);
}

#[test]
fn different_function_changes_merge_across_leb_length_boundaries_and_survive_transfer() {
    let history = History::fork(
        "separate-functions",
        functions(1, 2, 0),
        functions(100_000, 2, 130),
        functions(1, 200_000, 0),
    );
    assert_eq!(
        json_success(&["merge-base", &history.repo, &history.left, &history.right]),
        json!([history.base])
    );
    let merged = history.merge();
    assert_eq!(merged["status"], "merged");
    assert_eq!(merged["base"], history.base);
    assert_eq!(merged["report"]["status"], "clean");
    assert!(!merged["report"]["framing_fixups"]
        .as_array()
        .unwrap()
        .is_empty());
    let id = merged["commit"].as_str().unwrap();
    let expected = functions(100_000, 200_000, 130);
    verify_history_and_transfers(&history, id, &expected);
    let inspection = json_success(&["inspect", id, "--repo", &history.repo]);
    assert_exported_constant(&inspection, "a", 100_000);
    assert_exported_constant(&inspection, "b", 200_000);
}

#[test]
fn disjoint_instructions_in_one_function_merge_with_the_same_control_structure() {
    let source = r#"(module (func (export "sum") (result i32) i32.const 11 i32.const 22 i32.add))"#;
    let left = source.replace("const 11", "const 100000");
    let right = source.replace("const 22", "const 200000");
    let expected = left.replace("const 22", "const 200000");
    let history = History::fork("same-function", wat(source), wat(&left), wat(&right));
    let result = history.merge();
    assert_eq!(result["status"], "merged");
    assert_eq!(
        history.checkout("HEAD", "same-function.wasm"),
        wat(&expected)
    );
}

#[test]
fn reordered_instruction_runs_conflict_with_an_edit_to_the_old_run_position() {
    let base = wat(r#"(module (func (export "run")
        i32.const 1 drop i32.const 2 drop
        i32.const 3 drop i32.const 2 drop))"#);
    let moved = wat(r#"(module (func (export "run")
        i32.const 3 drop i32.const 2 drop
        i32.const 1 drop i32.const 2 drop))"#);
    let edited = wat(r#"(module (func (export "run")
        i32.const 1 drop i32.const 4 drop
        i32.const 3 drop i32.const 2 drop))"#);
    let history = History::fork("reordered-atoms", base, moved, edited);
    assert_conflict(&history);
}

#[test]
fn overlapping_instruction_conflict_can_be_resolved_explicitly_with_two_parents() {
    let history = History::fork(
        "manual",
        functions(1, 10, 0),
        functions(2, 10, 0),
        functions(3, 10, 0),
    );
    let conflict = assert_conflict(&history);
    let resolved = functions(4, 10, 0);
    let file = history.tmp.path("resolution.wasm");
    std::fs::write(&file, &resolved).unwrap();
    let result = json_success(&[
        "merge",
        &history.repo,
        conflict["target"].as_str().unwrap(),
        "-m",
        "manual decision",
        "--resolved",
        &file,
        "--expect-head",
        conflict["old_head"].as_str().unwrap(),
    ]);
    assert_eq!(result["status"], "merged_resolved");
    assert_eq!(result["manual_resolution"]["supplied_bytes"], true);
    assert_eq!(
        result["manual_resolution"]["audit_validation"],
        "valid_with_all_known_features"
    );
    verify_history_and_transfers(&history, result["commit"].as_str().unwrap(), &resolved);
}

#[test]
fn changed_import_index_context_conflicts_with_concurrent_body_edits() {
    let left = wat(r#"(module
        (import "arbitrary.host" "new-function" (func (result i32)))
        (func (export "a") (result i32) i32.const 1)
        (func (export "b") (result i32) i32.const 2))"#);
    let history = History::fork(
        "import-context",
        functions(1, 2, 0),
        left,
        functions(1, 3, 0),
    );
    assert_conflict(&history);
}

fn unknown_first_opcode(bytes: &[u8]) -> Vec<u8> {
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.unwrap() {
            for operator in body
                .get_operators_reader()
                .unwrap()
                .into_iter_with_offsets()
            {
                let (operator, offset) = operator.unwrap();
                if matches!(operator, Operator::I32Const { .. }) {
                    let mut changed = bytes.to_vec();
                    changed[offset] = 0xff;
                    return changed;
                }
            }
        }
    }
    panic!("expected a constant opcode to deliberately replace with an unknown byte");
}

#[test]
fn concurrent_unknown_opcode_changes_conflict_without_store_mutation() {
    let base = functions(1, 2, 0);
    let unknown = unknown_first_opcode(&base);
    let history = History::fork("unknown-conflict", base, unknown, functions(1, 3, 0));
    assert_conflict(&history);
}

#[test]
fn one_sided_unknown_bytes_are_preserved_exactly_when_the_other_module_is_unchanged() {
    let base = functions(1, 2, 0);
    let unknown = unknown_first_opcode(&base);
    let history = History::fork("unknown-preserved", base.clone(), unknown.clone(), base);
    let result = history.merge();
    assert_ne!(result["status"], "conflict");
    assert_eq!(history.checkout("HEAD", "unknown-exact.wasm"), unknown);
    let inspection = json_success(&["inspect", "HEAD", "--repo", &history.repo]);
    assert!(inspection["audit"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "unknown_operator"));
}

#[test]
fn identical_sibling_edits_have_an_explicit_clean_result() {
    let expected = functions(9, 2, 0);
    let history = History::fork(
        "identical",
        functions(1, 2, 0),
        expected.clone(),
        expected.clone(),
    );
    let result = history.merge();
    assert!(matches!(
        result["status"].as_str(),
        Some("merged" | "already_up_to_date")
    ));
    assert_eq!(history.checkout("HEAD", "identical.wasm"), expected);
    if result["status"] == "merged" {
        assert_eq!(
            json_success(&["show", &history.repo, "HEAD"])["parents"],
            json!([history.left, history.right])
        );
    }
}

#[test]
fn fast_forward_creates_no_objects_and_repeated_merge_is_a_noop() {
    let tmp = Temp::new("fast-forward");
    let repo = tmp.path("repo");
    let input = tmp.path("input.wasm");
    success(&["init", &repo]);
    let base = commit(&repo, &input, &functions(1, 2, 0), "base");
    success(&["branch", &repo, "right", &base]);
    success(&["switch", &repo, "right"]);
    let target = commit(&repo, &input, &functions(3, 2, 0), "right");
    success(&["switch", &repo, "main"]);
    let objects = snapshot(&Path::new(&repo).join(".uwgit/objects"));
    let result = json_success(&["merge", &repo, &target, "-m", "fast forward"]);
    assert_eq!(result["status"], "fast_forward");
    assert_eq!(json_success(&["show", &repo, "HEAD"])["id"], target);
    assert_eq!(snapshot(&Path::new(&repo).join(".uwgit/objects")), objects);
    let before = store_snapshot(&repo);
    assert_eq!(
        json_success(&["merge", &repo, &target, "-m", "again"])["status"],
        "already_up_to_date"
    );
    assert_eq!(store_snapshot(&repo), before);
}

#[test]
fn manual_resolution_refuses_stale_head_and_mutable_target_without_writes() {
    let history = History::fork(
        "stale-resolution",
        functions(1, 10, 0),
        functions(2, 10, 0),
        functions(3, 10, 0),
    );
    assert_conflict(&history);
    let input = history.tmp.path("advanced.wasm");
    let advanced = commit(
        &history.repo,
        &input,
        &functions(5, 10, 0),
        "advance after conflict",
    );
    let resolution = history.tmp.path("resolution.wasm");
    std::fs::write(&resolution, functions(4, 10, 0)).unwrap();
    let before = store_snapshot(&history.repo);
    let stale = invoke(&[
        "merge",
        &history.repo,
        &history.right,
        "-m",
        "stale decision",
        "--resolved",
        &resolution,
        "--expect-head",
        &history.left,
    ]);
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("HEAD changed since resolution"));
    assert_eq!(store_snapshot(&history.repo), before);
    assert_eq!(
        json_success(&["show", &history.repo, "HEAD"])["id"],
        advanced
    );
    let mutable_target = invoke(&[
        "merge",
        &history.repo,
        "right",
        "-m",
        "mutable target",
        "--resolved",
        &resolution,
        "--expect-head",
        &advanced,
    ]);
    assert!(!mutable_target.status.success());
    assert!(String::from_utf8_lossy(&mutable_target.stderr).contains("invalid object ID"));
    assert_eq!(store_snapshot(&history.repo), before);
}

#[test]
fn merge_help_performs_no_repository_actions() {
    let tmp = Temp::new("help");
    let nonexistent = tmp.path("must-not-exist");
    for command in ["merge", "merge-base"] {
        let output = invoke(&[command, &nonexistent, "--help"]);
        assert!(output.status.success());
        assert!(!Path::new(&nonexistent).exists());
    }
    let repo = tmp.path("repo");
    let input = tmp.path("input.wasm");
    success(&["init", &repo]);
    commit(&repo, &input, &functions(1, 2, 0), "base");
    let before = store_snapshot(&repo);
    assert!(invoke(&["merge", &repo, "HEAD", "-m", "unused", "--help"])
        .status
        .success());
    assert_eq!(store_snapshot(&repo), before);
}
