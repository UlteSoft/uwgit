use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-history-queries-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        ok(&["init", p(&root)]);
        Self(root)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn execute(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = execute(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim_end().into()
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}
fn commit(root: &Path, file: &str, value: u8, message: &str) -> String {
    fs::write(root.join(file), wasm(value)).unwrap();
    ok(&["add", p(root), file]);
    ok(&["commit", p(root), "-m", message]);
    ok(&["rev-parse", p(root), "HEAD"])
}

#[test]
fn shortlog_counts_actual_changed_module_paths_and_explicit_subject_groups() {
    let temp = Temp::new();
    let root = &temp.0;
    commit(root, "a.wasm", 1, "initial");
    commit(root, "a.wasm", 2, "update");
    commit(root, "b.wasm", 3, "update");
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    let report = json(&["shortlog", p(root), "-s", "-n"]);
    assert_eq!(report["commits"], 3);
    assert_eq!(report["groups"][0]["key"], "a.wasm");
    assert_eq!(report["groups"][0]["count"], 2);
    assert!(report["groups"][0].get("commits").is_none());
    let report = json(&["shortlog", p(root), "--group=subject", "-n"]);
    assert_eq!(report["groups"][0]["key"], "update");
    assert_eq!(report["groups"][0]["count"], 2);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
}

#[test]
fn range_diff_matches_exact_wasm_transitions_after_an_unrelated_module_change() {
    let temp = Temp::new();
    let root = &temp.0;
    let base = commit(root, "a.wasm", 1, "root");
    let old_tip = commit(root, "a.wasm", 2, "old message");
    ok(&["branch", p(root), "old"]);
    ok(&["reset", p(root), "--hard", &base]);
    let new_base = commit(root, "b.wasm", 7, "unrelated base");
    let new_tip = commit(root, "a.wasm", 2, "new message");
    let report = json(&[
        "range-diff",
        p(root),
        &format!("{base}..{old_tip}"),
        &format!("{new_base}..{new_tip}"),
    ]);
    assert_eq!(report["rows"].as_array().unwrap().len(), 1);
    assert_eq!(report["rows"][0]["status"], "equal_transition");
    assert_eq!(report["rows"][0]["message_changed"], true);
    assert_eq!(report["old"]["commits"][0]["changes"][0]["path"], "a.wasm");
    assert!(
        report["old"]["commits"][0]["changes"][0]["audit"]["changed"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["semantic_equivalence_proven"].as_bool().unwrap());
    let unchanged = json(&[
        "range-diff",
        p(root),
        &format!("{base}..{base}"),
        &format!("{base}..{base}"),
    ]);
    assert!(unchanged["rows"].as_array().unwrap().is_empty());
}

#[test]
fn changed_transitions_stay_unpaired_and_equal_empty_commits_remain_ambiguous() {
    let temp = Temp::new();
    let root = &temp.0;
    let base = commit(root, "a.wasm", 1, "root");
    let old = commit(root, "a.wasm", 2, "old");
    ok(&["reset", p(root), "--hard", &base]);
    let new = commit(root, "a.wasm", 3, "new");
    let report = json(&[
        "range-diff",
        p(root),
        &format!("{base}..{old}"),
        &format!("{base}..{new}"),
        "--no-audit",
    ]);
    assert_eq!(report["rows"][0]["status"], "removed");
    assert_eq!(report["rows"][1]["status"], "added");
    ok(&["reset", p(root), "--hard", &base]);
    for message in ["empty one", "empty two"] {
        ok(&["commit", p(root), "--allow-empty", "-m", message]);
    }
    let old = ok(&["rev-parse", p(root), "HEAD"]);
    ok(&["reset", p(root), "--hard", &base]);
    for message in ["new empty one", "new empty two"] {
        ok(&["commit", p(root), "--allow-empty", "-m", message]);
    }
    let new = ok(&["rev-parse", p(root), "HEAD"]);
    let report = json(&[
        "range-diff",
        p(root),
        &format!("{base}..{old}"),
        &format!("{base}..{new}"),
    ]);
    assert_eq!(report["rows"].as_array().unwrap().len(), 4);
    assert!(report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["status"] == "ambiguous"));
}

#[test]
fn range_and_resource_failures_are_explicit_and_queries_write_nothing() {
    let temp = Temp::new();
    let root = &temp.0;
    let base = commit(root, "a.wasm", 1, "root");
    let tip = commit(root, "a.wasm", 2, "tip");
    let before = fs::read(root.join(".uwgit/reflog")).unwrap();
    for extra in [vec!["--max-commits", "0"], vec!["--max-bytes", "0"]] {
        let mut args = vec!["range-diff", p(root)];
        let range = format!("{base}..{tip}");
        args.extend([range.as_str(), range.as_str()]);
        args.extend(extra);
        assert!(!execute(&args).status.success());
    }
    assert!(!execute(&["range-diff", p(root), "HEAD", "HEAD"])
        .status
        .success());
    assert_eq!(fs::read(root.join(".uwgit/reflog")).unwrap(), before);
}
