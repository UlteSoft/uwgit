#![cfg(unix)]
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-mergetool-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
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
fn module(value: i32) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (func (export \"value\") (result i32) i32.const {value}))"
    ))
    .unwrap()
}
fn commit(root: &Path, value: i32) -> String {
    fs::write(root.join("a.wasm"), module(value)).unwrap();
    ok(&["add", p(root), "a.wasm"]);
    ok(&["commit", p(root), "-m", "change"]);
    ok(&["rev-parse", p(root), "HEAD"])
}
fn pending(root: &Path) -> (String, String) {
    ok(&["init", p(root)]);
    commit(root, 1);
    ok(&["branch", p(root), "topic"]);
    let ours = commit(root, 2);
    ok(&["switch", p(root), "topic"]);
    let theirs = commit(root, 3);
    ok(&["switch", p(root), "main"]);
    let output = execute(&[
        "merge",
        p(root),
        "topic",
        "--record-conflict",
        "-m",
        "merge",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (ours, theirs)
}
fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn export_is_a_frozen_three_way_snapshot_and_explicit_tool_staging_never_moves_head_or_worktree() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (ours, theirs) = pending(&root);
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    let original_pending = fs::read(root.join(".uwgit/pending.json")).unwrap();
    let output = temp.path("review");
    let report = json(&["mergetool", p(&root), "--output", p(&output)]);
    assert_eq!(report["ours"], ours);
    assert_eq!(report["theirs"], theirs);
    assert_eq!(report["files"].as_array().unwrap().len(), 1);
    for (side, value) in [("base", 1), ("local", 2), ("remote", 3)] {
        assert_eq!(
            fs::read(report["files"][0][side]["file"].as_str().unwrap()).unwrap(),
            module(value)
        );
    }
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
    assert_eq!(
        fs::read(root.join(".uwgit/pending.json")).unwrap(),
        original_pending
    );
    let tool = temp.path("select-remote.sh");
    script(
        &tool,
        "printf 'tool diagnostics\\n'\ncp \"$REMOTE\" \"$MERGED\"",
    );
    let output = temp.path("resolved");
    let report = json(&[
        "mergetool",
        p(&root),
        "--output",
        p(&output),
        "--tool",
        p(&tool),
        "--stage",
    ]);
    assert_eq!(report["index_updated"], true);
    assert_eq!(report["pending_continued"], false);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), module(2));
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), ours);
    assert_eq!(
        fs::read(root.join(".uwgit/pending.json")).unwrap(),
        original_pending
    );
    json(&["merge", p(&root), "--continue", "--resolved-index"]);
    let exported = temp.path("result.wasm");
    ok(&[
        "show",
        p(&root),
        "HEAD",
        "--file",
        "a.wasm",
        "--output",
        p(&exported),
    ]);
    assert_eq!(fs::read(exported).unwrap(), module(3));
    let commit = json(&["cat-file", p(&root), "HEAD"]);
    assert_eq!(commit["parents"], serde_json::json!([ours, theirs]));
}

#[test]
fn failed_tools_invalid_outputs_symlinks_and_changed_inputs_cannot_stage_results() {
    let temp = Temp::new();
    let root = temp.path("repo");
    pending(&root);
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    let pending = fs::read(root.join(".uwgit/pending.json")).unwrap();
    for (position, body) in [
        "exit 7",
        "printf invalid > \"$MERGED\"",
        "ln -s \"$REMOTE\" \"$MERGED\"",
        "cp \"$REMOTE\" \"$MERGED\"\nprintf changed > \"$BASE\"",
    ]
    .into_iter()
    .enumerate()
    {
        let tool = temp.path(&format!("tool-{position}.sh"));
        script(&tool, body);
        let output = temp.path(&format!("output-{position}"));
        assert!(!execute(&[
            "mergetool",
            p(&root),
            "--output",
            p(&output),
            "--tool",
            p(&tool),
            "--stage"
        ])
        .status
        .success());
        assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
        assert_eq!(fs::read(root.join(".uwgit/pending.json")).unwrap(), pending);
        assert_eq!(fs::read(root.join("a.wasm")).unwrap(), module(2));
    }
}

#[test]
fn concurrent_index_changes_are_detected_and_metadata_exports_are_rejected_before_creation() {
    let temp = Temp::new();
    let root = temp.path("repo");
    pending(&root);
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    let forbidden = root.join(".uwgit/review");
    assert!(
        !execute(&["mergetool", p(&root), "--output", p(&forbidden)])
            .status
            .success()
    );
    assert!(!forbidden.exists());
    let tool = temp.path("change-index.sh");
    script(
        &tool,
        "cp \"$REMOTE\" \"$MERGED\"\nprintf editor-change > \"$UWGIT_TEST_INDEX\"",
    );
    let output = temp.path("changed-index");
    let result = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args([
            "mergetool",
            p(&root),
            "--output",
            p(&output),
            "--tool",
            p(&tool),
            "--stage",
        ])
        .env("UWGIT_TEST_INDEX", root.join(".uwgit/index"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(
        fs::read(root.join(".uwgit/index")).unwrap(),
        b"editor-change"
    );
    fs::write(root.join(".uwgit/index"), index).unwrap();
    ok(&["fsck", p(&root)]);
}
