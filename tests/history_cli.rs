//! Fixed history operations: independent edits, conflicts, and exact recovery.
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = PathBuf::from(format!(
            "/tmp/uwgit-history-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().into()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn success(args: &[&str]) -> String {
    let output = invoke(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn run(args: &[&str]) -> Value {
    serde_json::from_str(&success(args)).unwrap()
}
fn revision(root: &str, name: &str) -> String {
    success(&["rev-parse", root, name]).trim().into()
}
fn module(a: i32, b: i32) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (func (result i32) i32.const {a}) (func (result i32) i32.const {b}))"
    ))
    .unwrap()
}
fn commit(root: &str, file: &str, a: i32, b: i32, message: &str) -> String {
    std::fs::write(file, module(a, b)).unwrap();
    success(&["commit", root, file, "-m", message]);
    revision(root, "HEAD")
}
fn bytes(root: &str, revision: &str, output: &str) -> Vec<u8> {
    success(&["show", root, revision, "--output", output]);
    std::fs::read(output).unwrap()
}

fn metadata(root: &str) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(
        root: &std::path::Path,
        path: &std::path::Path,
        result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>,
    ) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                result.insert(relative, None);
                visit(root, &path, result);
            } else {
                result.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let root = std::path::Path::new(root);
    let mut result = BTreeMap::new();
    visit(root, &root.join(".uwgit"), &mut result);
    result
}

fn staged(root: &str, a: i32, b: i32, message: &str) -> String {
    std::fs::write(std::path::Path::new(root).join("module.wasm"), module(a, b)).unwrap();
    success(&["add", root, "module.wasm"]);
    success(&["commit", root, "-m", message]);
    revision(root, "HEAD")
}

#[test]
fn literal_help_values_commit_config_and_stash_instead_of_returning_usage() {
    for (message_flag, literal) in [("-m", "--help"), ("--message", "-h")] {
        let temp = Temp::new();
        let root = temp.path("repo");
        success(&["init", &root]);
        let file = std::path::Path::new(&root).join("module.wasm");
        std::fs::write(&file, module(0, 1)).unwrap();
        success(&["add", &root, "module.wasm"]);
        success(&["commit", &root, message_flag, literal]);
        let head = revision(&root, "HEAD");
        assert_eq!(run(&["show", &root, "HEAD"])["message"], literal);
        success(&["config", &root, "user.name", literal]);
        assert_eq!(success(&["config", &root, "user.name"]).trim(), literal);
        std::fs::write(&file, module(0, 2)).unwrap();
        success(&["stash", &root, "push", "-m", literal]);
        assert_eq!(run(&["stash", &root, "list"])[0]["message"], literal);
        assert_eq!(std::fs::read(&file).unwrap(), module(0, 1));
        assert_eq!(revision(&root, "HEAD"), head);
        success(&["stash", &root, "pop", "0"]);
        assert_eq!(std::fs::read(file).unwrap(), module(0, 2));
        run(&["fsck", &root]);
    }
}

#[test]
fn legacy_commit_and_history_operations_preserve_literal_help_messages() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let file = temp.path("input.wasm");
    success(&["init", &root]);
    commit(&root, &file, 0, 0, "--help");
    assert_eq!(run(&["show", &root, "HEAD"])["message"], "--help");
    success(&["branch", &root, "topic"]);
    let ours = commit(&root, &file, 1, 0, "ours");
    success(&["switch", &root, "topic"]);
    let change = commit(&root, &file, 0, 2, "theirs");
    success(&["switch", &root, "main"]);
    let picked = run(&["cherry-pick", &root, &change, "-m", "-h"]);
    let picked_id = picked["commit"].as_str().unwrap();
    assert_eq!(run(&["show", &root, picked_id])["message"], "-h");
    assert_eq!(
        run(&["show", &root, picked_id])["parents"],
        serde_json::json!([ours])
    );
    let reverted = run(&["revert", &root, picked_id, "-m", "--help"]);
    assert_eq!(run(&["show", &root, "HEAD"])["message"], "--help");
    assert_eq!(
        bytes(&root, "HEAD", &temp.path("reverted.wasm")),
        module(1, 0)
    );
    let merged = run(&["merge", &root, &change, "--message", "--help"]);
    assert_eq!(merged["status"], "merged");
    let info = run(&["show", &root, "HEAD"]);
    assert_eq!(info["message"], "--help");
    assert_eq!(
        info["parents"],
        serde_json::json!([reverted["commit"], change])
    );
    assert_eq!(
        bytes(&root, "HEAD", &temp.path("merged.wasm")),
        module(1, 2)
    );
    run(&["fsck", &root]);
}

#[test]
fn real_help_options_still_return_before_repository_or_network_access() {
    let temp = Temp::new();
    let absent = temp.path("must-not-exist");
    for command in [
        "commit",
        "merge",
        "pull",
        "cherry-pick",
        "revert",
        "stash",
        "config",
    ] {
        assert!(!success(&[command, &absent, "--help"]).is_empty());
        if command != "config" {
            assert!(!success(&[command, &absent, "-m", "-h", "--help"]).is_empty());
        }
        assert!(!std::path::Path::new(&absent).exists());
    }
}

#[test]
fn export_help_named_operands_are_files_and_leave_repository_metadata_unchanged() {
    let temp = Temp::new();
    let root = temp.path("repo");
    success(&["init", &root]);
    staged(&root, 0, 1, "base");
    let info = run(&["show", &root, "HEAD"]);
    let tree = info["tree"].as_str().unwrap();
    let entries = run(&["cat-file", &root, "-p", tree]);
    let blob = entries["entries"]["module.wasm"].as_str().unwrap();
    std::fs::write(
        std::path::Path::new(&root).join("module.wasm"),
        module(0, 2),
    )
    .unwrap();
    success(&["stash", &root, "push", "-m", "saved bytes"]);
    let before = metadata(&root);
    for literal in ["--help", "-h"] {
        for route in ["restore", "cat-file", "stash"] {
            let output_dir = temp.0.join(format!("{route}-{literal}"));
            std::fs::create_dir(&output_dir).unwrap();
            let args = match route {
                "restore" => vec![
                    "restore",
                    &root,
                    "--file",
                    "module.wasm",
                    "--output",
                    literal,
                ],
                "cat-file" => vec!["cat-file", &root, blob, "--output", literal],
                _ => vec!["stash", &root, "apply", "0", "--output", literal],
            };
            let result = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
                .current_dir(&output_dir)
                .args(&args)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                std::fs::read(output_dir.join(literal)).unwrap(),
                module(0, if route == "stash" { 2 } else { 1 })
            );
            assert_eq!(metadata(&root), before);
            assert_eq!(std::fs::read_dir(&output_dir).unwrap().count(), 1);
        }
    }
    run(&["fsck", &root]);
}

#[test]
fn standalone_export_help_after_a_literal_operand_still_avoids_io() {
    let temp = Temp::new();
    let absent = temp.path("absent");
    for args in [
        vec![
            "restore",
            absent.as_str(),
            "--file",
            "module.wasm",
            "--output",
            "-h",
            "--help",
        ],
        vec![
            "cat-file",
            absent.as_str(),
            "HEAD",
            "--output",
            "--help",
            "-h",
        ],
        vec![
            "stash",
            absent.as_str(),
            "apply",
            "0",
            "--output",
            "-h",
            "--help",
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
            .current_dir(&temp.0)
            .args(&args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!result.stdout.is_empty());
        assert_eq!(std::fs::read_dir(&temp.0).unwrap().count(), 0);
    }
}

#[test]
fn cherry_pick_and_revert_preserve_other_function_and_exact_parent() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let file = temp.path("input.wasm");
    success(&["init", &root]);
    let base = commit(&root, &file, 0, 0, "base");
    success(&["branch", &root, "topic"]);
    let ours = commit(&root, &file, 1, 0, "ours");
    success(&["switch", &root, "topic"]);
    let change = commit(&root, &file, 0, 2, "theirs");
    success(&["switch", &root, "main"]);
    let picked = run(&["cherry-pick", &root, &change]);
    let picked_id = picked["commit"].as_str().unwrap();
    assert_eq!(
        run(&["show", &root, picked_id])["parents"],
        serde_json::json!([ours])
    );
    assert_eq!(
        bytes(&root, picked_id, &temp.path("pick.wasm")),
        module(1, 2)
    );
    let reverted = run(&["revert", &root, &change]);
    assert_eq!(
        bytes(
            &root,
            reverted["commit"].as_str().unwrap(),
            &temp.path("revert.wasm")
        ),
        module(1, 0)
    );
    assert_eq!(revision(&root, "topic~1"), base);
    run(&["fsck", &root]);
}

#[test]
fn rebase_replays_linear_commits_and_conflict_does_not_publish_any_step() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let file = temp.path("input.wasm");
    success(&["init", &root]);
    commit(&root, &file, 0, 0, "base");
    success(&["branch", &root, "topic"]);
    let upstream = commit(&root, &file, 1, 0, "upstream");
    success(&["switch", &root, "topic"]);
    commit(&root, &file, 0, 2, "first");
    commit(&root, &file, 0, 3, "second");
    let replay = run(&["rebase", &root, "main"]);
    assert_eq!(replay["commits"].as_array().unwrap().len(), 2);
    assert_eq!(
        bytes(&root, "HEAD", &temp.path("rebase.wasm")),
        module(1, 3)
    );
    assert_eq!(revision(&root, "HEAD~2"), upstream);
    success(&["branch", &root, "conflict", "main"]);
    success(&["switch", &root, "conflict"]);
    let before = commit(&root, &file, 4, 0, "conflicting");
    let output = invoke(&["cherry-pick", &root, "topic"]);
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "conflict");
    assert_eq!(revision(&root, "HEAD"), before);
    run(&["fsck", &root]);
}

#[test]
fn replay_updates_clean_tracked_module_and_rejects_dirty_bytes_before_objects_change() {
    let temp = Temp::new();
    let root = temp.path("repo");
    success(&["init", &root]);
    staged(&root, 0, 0, "base");
    success(&["branch", &root, "topic"]);
    let ours = staged(&root, 1, 0, "ours");
    success(&["switch", &root, "topic"]);
    let change = staged(&root, 0, 2, "theirs");
    success(&["switch", &root, "main"]);
    let tracked = std::path::Path::new(&root).join("module.wasm");
    assert_eq!(std::fs::read(&tracked).unwrap(), module(1, 0));
    let dirty = module(9, 0);
    std::fs::write(&tracked, &dirty).unwrap();
    let before = metadata(&root);
    let output = invoke(&["cherry-pick", &root, &change]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(metadata(&root), before);
    assert_eq!(std::fs::read(&tracked).unwrap(), dirty);
    success(&["restore", &root]);
    let picked = run(&["cherry-pick", &root, &change]);
    assert_eq!(picked["status"], "committed");
    assert_eq!(
        run(&["show", &root, "HEAD"])["parents"],
        serde_json::json!([ours])
    );
    assert_eq!(std::fs::read(&tracked).unwrap(), module(1, 2));
    let status = run(&["status", &root]);
    assert_eq!(status["staged"], false);
    assert_eq!(status["worktree"], "clean");
    run(&["revert", &root, &change]);
    assert_eq!(std::fs::read(&tracked).unwrap(), module(1, 0));
    let before = metadata(&root);
    let output = invoke(&["revert", &root, "HEAD", "--mainline", "2"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(metadata(&root), before);
    assert_eq!(std::fs::read(&tracked).unwrap(), module(1, 0));
}

#[test]
fn later_rebase_conflict_retains_every_object_ref_index_and_tracked_byte() {
    let temp = Temp::new();
    let root = temp.path("repo");
    success(&["init", &root]);
    staged(&root, 0, 0, "base");
    success(&["branch", &root, "topic"]);
    staged(&root, 1, 0, "upstream");
    success(&["switch", &root, "topic"]);
    staged(&root, 0, 2, "independent first replay");
    let stopped_at = staged(&root, 4, 2, "conflicting second replay");
    let before = metadata(&root);
    let tracked = std::path::Path::new(&root).join("module.wasm");
    let before_bytes = std::fs::read(&tracked).unwrap();
    let output = invoke(&["rebase", &root, "main"]);
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "conflict");
    assert_eq!(report["stopped_at"], stopped_at);
    assert_eq!(metadata(&root), before);
    assert_eq!(std::fs::read(&tracked).unwrap(), before_bytes);
    assert_eq!(revision(&root, "HEAD"), stopped_at);
    let status = run(&["status", &root]);
    assert_eq!(status["staged"], false);
    assert_eq!(status["worktree"], "clean");
    run(&["fsck", &root]);
}
