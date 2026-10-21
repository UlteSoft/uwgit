//! Fixed staged tree worktree cases; never execute Wasm or generate inputs.
//! The parent test driver runs this only in the existing SSH Linux cgroup.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const A: &[u8] = b"\0asm\x01\0\0\0";
// A future/unknown section is intentionally not validated by the index.
const B: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
const C: &[u8] = b"\0asm\x01\0\0\0\0\x02\x01x";

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-porcelain-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn root(&self) -> &str {
        self.0.to_str().unwrap()
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().into()
    }
    fn write(&self, bytes: &[u8]) {
        fs::write(self.0.join("module.wasm"), bytes).unwrap();
    }
    fn init(&self) {
        success(&["init", self.root()]);
    }
    fn stage(&self, bytes: &[u8]) {
        self.write(bytes);
        success(&["add", self.root(), "module.wasm"]);
    }
    fn commit(&self, message: &str) -> String {
        success(&["commit", self.root(), "-m", message]);
        success(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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

fn failure(args: &[&str]) {
    let output = invoke(args);
    assert!(!output.status.success(), "unexpected success: {args:?}");
}

fn status(temp: &Temp) -> Value {
    serde_json::from_str(&success(&["status", temp.root()])).unwrap()
}

fn metadata(temp: &Temp) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().into(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(&temp.0, &temp.0.join(".uwgit"), &mut result);
    result
}

#[test]
fn stages_unknown_wasm_bytes_losslessly_and_reports_worktree_changes() {
    let temp = Temp::new("unknown");
    temp.init();
    assert_eq!(status(&temp)["worktree"], "untracked");
    temp.stage(B);
    assert_eq!(status(&temp)["staged"], true);
    assert_eq!(status(&temp)["worktree"], "clean");
    let id = temp.commit("unknown future section");
    assert_eq!(id.len(), 64);
    assert_eq!(status(&temp)["staged"], false);
    temp.write(C);
    assert_eq!(status(&temp)["worktree"], "modified");
    let output = temp.path("committed.wasm");
    success(&["restore", temp.root(), "HEAD", "--output", &output]);
    assert_eq!(fs::read(&output).unwrap(), B);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), C);
    fs::remove_file(temp.path("module.wasm")).unwrap();
    assert_eq!(status(&temp)["worktree"], "deleted");
    assert_eq!(success(&["ls-files", temp.root()]).trim(), "module.wasm");
}

#[test]
fn status_reports_staged_physical_removal_as_clean_worktree_and_empty_commit() {
    let temp = Temp::new("status-removed");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    success(&["rm", temp.root(), "module.wasm"]);
    assert!(!Path::new(&temp.path("module.wasm")).exists());
    let removed = status(&temp);
    assert_eq!(
        removed["files"],
        serde_json::json!([{
            "path": "module.wasm", "staged": "deleted", "worktree": "clean"
        }])
    );
    assert_eq!(removed["staged"], true);
    assert_eq!(removed["worktree"], "clean");
    assert_eq!(removed["untracked"], serde_json::json!([]));
    temp.commit("remove last module");
    let empty = status(&temp);
    assert_eq!(empty["index_present"], true);
    assert_eq!(empty["files"], serde_json::json!([]));
    assert_eq!(empty["staged"], false);
    assert_eq!(empty["worktree"], "clean");
    assert_eq!(empty["untracked"], serde_json::json!([]));
}

#[test]
fn status_reports_cached_removal_as_untracked_while_file_remains() {
    let temp = Temp::new("status-cached");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    success(&["rm", temp.root(), "--cached", "module.wasm"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), A);
    let cached = status(&temp);
    assert_eq!(
        cached["files"],
        serde_json::json!([{
            "path": "module.wasm", "staged": "deleted", "worktree": "untracked"
        }])
    );
    assert_eq!(cached["staged"], true);
    assert_eq!(cached["untracked"], serde_json::json!(["module.wasm"]));
    temp.commit("untrack last module");
    let empty = status(&temp);
    assert_eq!(empty["files"], serde_json::json!([]));
    assert_eq!(empty["staged"], false);
    assert_eq!(empty["untracked"], serde_json::json!(["module.wasm"]));
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), A);
}

#[test]
fn status_distinguishes_missing_tracked_file_from_staged_deletion() {
    let temp = Temp::new("status-missing");
    temp.init();
    success(&["commit", temp.root(), "--allow-empty", "-m", "empty base"]);
    let empty = status(&temp);
    assert_eq!(empty["files"], serde_json::json!([]));
    assert_eq!(empty["staged"], false);
    assert_eq!(empty["worktree"], "clean");
    temp.stage(A);
    temp.commit("track module");
    fs::remove_file(temp.path("module.wasm")).unwrap();
    let missing = status(&temp);
    assert_eq!(
        missing["files"],
        serde_json::json!([{
            "path": "module.wasm", "staged": "clean", "worktree": "deleted"
        }])
    );
    assert_eq!(missing["staged"], false);
    assert_eq!(missing["worktree"], "deleted");
    assert_eq!(missing["untracked"], serde_json::json!([]));
    success(&["rm", temp.root(), "--cached", "module.wasm"]);
    let removed = status(&temp);
    assert_eq!(removed["files"][0]["staged"], "deleted");
    assert_eq!(removed["files"][0]["worktree"], "clean");
    assert_eq!(removed["worktree"], "clean");
}

#[test]
fn restore_export_is_exclusive_and_hard_reset_replaces_only_tracked_file() {
    let temp = Temp::new("new-output");
    temp.init();
    temp.stage(A);
    let first = temp.commit("first");
    temp.stage(B);
    let second = temp.commit("second");
    let before = metadata(&temp);
    let current = temp.path("module.wasm");
    failure(&["restore", temp.root(), &first, "--output", &current]);
    failure(&["reset", temp.root(), "--hard", &first, "--output", &current]);
    assert_eq!(metadata(&temp), before);
    assert_eq!(fs::read(&current).unwrap(), B);
    let unrelated = temp.path("unrelated.wasm");
    fs::write(&unrelated, C).unwrap();
    success(&["reset", temp.root(), "--hard", &first]);
    assert_eq!(fs::read(&current).unwrap(), A);
    assert_eq!(fs::read(unrelated).unwrap(), C);
    assert_eq!(success(&["rev-parse", temp.root(), "HEAD"]).trim(), first);
    assert_eq!(status(&temp)["staged"], false);
    assert_eq!(status(&temp)["worktree"], "clean");
    temp.write(C);
    success(&["restore", temp.root()]);
    assert_eq!(fs::read(&current).unwrap(), A);
    success(&["restore", temp.root(), "--source", &second]);
    assert_eq!(fs::read(&current).unwrap(), B);
    assert_eq!(status(&temp)["staged"], false);
    assert_eq!(status(&temp)["worktree"], "modified");
}

#[test]
fn soft_and_mixed_reset_distinguish_head_and_index() {
    let temp = Temp::new("reset");
    temp.init();
    temp.stage(A);
    let first = temp.commit("first");
    temp.stage(B);
    temp.commit("second");
    success(&["reset", temp.root(), "--soft", &first]);
    assert_eq!(status(&temp)["staged"], true);
    assert_eq!(status(&temp)["worktree"], "clean");
    success(&["reset", temp.root()]);
    assert_eq!(status(&temp)["staged"], false);
    assert_eq!(status(&temp)["worktree"], "modified");
    let output = temp.path("index-after-reset.wasm");
    success(&["commit", temp.root(), "--allow-empty", "-m", "reset index"]);
    success(&["restore", temp.root(), "HEAD", "--output", &output]);
    assert_eq!(fs::read(output).unwrap(), A);
}

#[test]
fn stash_preserves_index_and_dirty_worktree_independently() {
    let temp = Temp::new("stash");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    temp.stage(B);
    temp.write(C);
    success(&["stash", temp.root(), "push", "-m", "both byte streams"]);
    assert_eq!(status(&temp)["staged"], false);
    assert_eq!(status(&temp)["worktree"], "clean");
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), A);
    let list: Value = serde_json::from_str(&success(&["stash", temp.root(), "list"])).unwrap();
    assert_eq!(list[0]["id"], 0);
    assert_eq!(list[0]["index_bytes"], B.len());
    assert_eq!(list[0]["worktree_bytes"], C.len());
    let output = temp.path("stashed-worktree.wasm");
    success(&["stash", temp.root(), "apply", "0", "--output", &output]);
    assert_eq!(fs::read(output).unwrap(), C);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), A);
    temp.write(B);
    let before = metadata(&temp);
    failure(&["stash", temp.root(), "pop", "0"]);
    assert_eq!(metadata(&temp), before);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), B);
    success(&["restore", temp.root()]);
    success(&["stash", temp.root(), "apply", "0"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), C);
    temp.commit("restored staged bytes");
    let staged = temp.path("stashed-index.wasm");
    success(&["restore", temp.root(), "HEAD", "--output", &staged]);
    assert_eq!(fs::read(staged).unwrap(), B);
    success(&["reset", temp.root(), "--hard", "HEAD~1"]);
    success(&["stash", temp.root(), "pop", "0"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), C);
    assert_eq!(success(&["stash", temp.root(), "list"]).trim(), "[]");
    failure(&["stash", temp.root(), "drop", "0"]);
}

#[test]
fn invalid_paths_and_corrupt_index_leave_repository_bytes_unchanged() {
    let temp = Temp::new("invalid");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    let before = metadata(&temp);
    for path in [
        "../outside.wasm",
        "/tmp/outside.wasm",
        ".uwgit/format",
        "./module.wasm",
        "x/../module.wasm",
        "x\\module.wasm",
        "x//module.wasm",
    ] {
        failure(&["add", temp.root(), path]);
        assert_eq!(metadata(&temp), before);
    }
    let inside = temp.path(".uwgit/tmp/new-output");
    failure(&["restore", temp.root(), "HEAD", "--output", &inside]);
    assert_eq!(metadata(&temp), before);
    let index_path = temp.path(".uwgit/index");
    // The encoded length exceeds both payload and 32-bit address space.
    let mut corrupt = b"UWGITIDX\x01".to_vec();
    corrupt.extend_from_slice(&u64::MAX.to_le_bytes());
    corrupt.extend_from_slice(&8u64.to_le_bytes());
    corrupt.extend_from_slice(A);
    fs::write(&index_path, corrupt).unwrap();
    let corrupt_before = metadata(&temp);
    for args in [
        vec!["status", temp.root()],
        vec!["add", temp.root(), "module.wasm"],
        vec!["commit", temp.root(), "-m", "must fail"],
    ] {
        failure(&args);
        assert_eq!(metadata(&temp), corrupt_before);
    }
}

#[test]
fn config_is_literal_validated_data_and_rejects_noncanonical_metadata() {
    let temp = Temp::new("config");
    temp.init();
    success(&[
        "config",
        temp.root(),
        "user.name",
        "A literal $(false) `false` name",
    ]);
    assert_eq!(
        success(&["config", temp.root(), "user.name"]).trim(),
        "A literal $(false) `false` name"
    );
    let before = metadata(&temp);
    for (name, value) in [
        ("../name", "x"),
        ("user..name", "x"),
        ("user.name", "bad\nvalue"),
    ] {
        failure(&["config", temp.root(), name, value]);
        assert_eq!(metadata(&temp), before);
    }
    success(&["config", temp.root(), "--unset", "user.name"]);
    failure(&["config", temp.root(), "user.name"]);
    fs::write(
        temp.path(".uwgit/config"),
        b"{\"format\":1,\"values\":{\"user.name\":\"a\",\"user.name\":\"b\"}}\n",
    )
    .unwrap();
    let corrupt = metadata(&temp);
    failure(&["config", temp.root(), "user.name", "replace"]);
    assert_eq!(metadata(&temp), corrupt);
}

#[test]
fn cached_remove_preserves_worktree_and_old_file_commit_stays_compatible() {
    let temp = Temp::new("cached");
    temp.init();
    temp.stage(B);
    let id = temp.commit("staged");
    let info: Value = serde_json::from_str(&success(&["cat-file", temp.root(), &id])).unwrap();
    assert_eq!(info["id"], id);
    success(&["rm", temp.root(), "--cached"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), B);
    assert_eq!(success(&["ls-files", temp.root()]).trim(), "");
    temp.commit("delete final tracked path");
    let before = metadata(&temp);
    failure(&[
        "commit",
        temp.root(),
        &temp.path("module.wasm"),
        "-m",
        "old explicit input",
    ]);
    assert_eq!(metadata(&temp), before);
    let legacy = Temp::new("legacy-file-commit");
    legacy.init();
    success(&[
        "commit",
        legacy.root(),
        &temp.path("module.wasm"),
        "-m",
        "old explicit input",
    ]);
    let output = legacy.path("old-output.wasm");
    success(&["checkout", legacy.root(), "HEAD", &output]);
    assert_eq!(fs::read(output).unwrap(), B);
}

#[test]
fn default_remove_checks_dirty_bytes_and_only_deletes_the_tracked_module() {
    let temp = Temp::new("rm");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    let unrelated = temp.path("untracked.wasm");
    fs::write(&unrelated, C).unwrap();
    temp.write(B);
    let before = metadata(&temp);
    failure(&["rm", temp.root()]);
    assert_eq!(metadata(&temp), before);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), B);
    success(&["restore", temp.root()]);
    success(&["rm", temp.root()]);
    assert!(!Path::new(&temp.path("module.wasm")).exists());
    assert_eq!(fs::read(&unrelated).unwrap(), C);
    assert_eq!(success(&["ls-files", temp.root()]).trim(), "");
    temp.stage(B);
    success(&["rm", temp.root(), "--force"]);
    assert!(!Path::new(&temp.path("module.wasm")).exists());
    assert_eq!(fs::read(unrelated).unwrap(), C);
}

#[test]
fn stash_roundtrips_deleted_and_non_wasm_dirty_worktree_bytes() {
    let temp = Temp::new("stash-dirty");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    let dirty = b"unfinished editor bytes\0\xff";
    temp.write(dirty);
    success(&["stash", temp.root()]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), A);
    success(&["stash", temp.root(), "pop", "0"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), dirty);
    success(&["restore", temp.root()]);
    fs::remove_file(temp.path("module.wasm")).unwrap();
    success(&["stash", temp.root(), "push"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), A);
    success(&["stash", temp.root(), "pop", "1"]);
    assert!(!Path::new(&temp.path("module.wasm")).exists());
    assert_eq!(status(&temp)["worktree"], "deleted");
}

#[test]
fn tag_reflog_revision_and_raw_object_commands_preserve_future_module_payload() {
    let temp = Temp::new("refs");
    temp.init();
    temp.stage(A);
    let first = temp.commit("first");
    temp.stage(B);
    let second = temp.commit("second");
    success(&["tag", temp.root(), "v1", &first]);
    assert_eq!(success(&["rev-parse", temp.root(), "v1"]).trim(), first);
    assert_eq!(success(&["rev-parse", temp.root(), "HEAD~1"]).trim(), first);
    assert_eq!(
        success(&["rev-parse", temp.root(), &second[..12]]).trim(),
        second
    );
    let tags: Value = serde_json::from_str(&success(&["tag", temp.root()])).unwrap();
    assert_eq!(tags["v1"], first);
    let log: Value = serde_json::from_str(&success(&["reflog", temp.root()])).unwrap();
    assert!(log.as_array().unwrap().len() >= 3);
    let info: Value = serde_json::from_str(&success(&["cat-file", temp.root(), "HEAD"])).unwrap();
    let tree = info["tree"].as_str().unwrap();
    let tree: Value =
        serde_json::from_str(&success(&["cat-file", temp.root(), "-p", tree])).unwrap();
    let blob = tree["entries"]["module.wasm"].as_str().unwrap();
    assert_eq!(
        success(&["cat-file", temp.root(), "-t", blob]).trim(),
        "wasm"
    );
    assert_eq!(
        success(&["cat-file", temp.root(), "-s", blob]).trim(),
        B.len().to_string()
    );
    let raw = temp.path("raw-object.wasm");
    success(&["cat-file", temp.root(), blob, "--output", &raw]);
    assert_eq!(fs::read(&raw).unwrap(), B);
    failure(&["cat-file", temp.root(), blob, "--output", &raw]);
    success(&["tag", temp.root(), "-d", "v1"]);
    failure(&["rev-parse", temp.root(), "v1"]);
}

#[test]
fn amend_replaces_parent_link_and_message_and_empty_commits_are_explicit() {
    let temp = Temp::new("amend");
    temp.init();
    temp.stage(A);
    let first = temp.commit("first");
    let before = metadata(&temp);
    failure(&["commit", temp.root(), "-m", "unchanged"]);
    assert_eq!(metadata(&temp), before);
    success(&[
        "commit",
        temp.root(),
        "--allow-empty",
        "-m",
        "explicit empty",
    ]);
    let empty = success(&["rev-parse", temp.root(), "HEAD"])
        .trim()
        .to_string();
    assert_ne!(empty, first);
    temp.stage(B);
    success(&["commit", temp.root(), "--amend", "-m", "amended bytes"]);
    let info: Value = serde_json::from_str(&success(&["cat-file", temp.root(), "HEAD"])).unwrap();
    assert_eq!(info["parents"], serde_json::json!([first]));
    assert_eq!(info["message"], "amended bytes");
    let amended_id = info["id"].as_str().unwrap();
    assert_ne!(amended_id, empty);
    success(&["rm", temp.root(), "--cached"]);
    success(&["restore", temp.root(), "--source", "HEAD", "--staged"]);
    success(&["commit", temp.root(), "--amend", "-m", "message only"]);
    let info: Value = serde_json::from_str(&success(&["cat-file", temp.root(), "HEAD"])).unwrap();
    assert_eq!(info["parents"], serde_json::json!([first]));
    assert_eq!(info["message"], "message only");
    let raw = temp.path("amended.wasm");
    success(&["restore", temp.root(), "HEAD", "--output", &raw]);
    assert_eq!(fs::read(raw).unwrap(), B);
}

#[test]
fn branch_switch_syncs_tracked_bytes_and_rejects_dirty_changes() {
    let temp = Temp::new("switch");
    temp.init();
    success(&["switch", temp.root(), "-c", "trunk"]);
    temp.stage(A);
    let first = temp.commit("base");
    success(&["switch", temp.root(), "-c", "feature"]);
    temp.stage(B);
    temp.commit("feature change");
    success(&["switch", temp.root(), "trunk"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), A);
    assert_eq!(status(&temp)["staged"], false);
    temp.write(C);
    let before = metadata(&temp);
    failure(&["switch", temp.root(), "feature"]);
    assert_eq!(metadata(&temp), before);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), C);
    success(&["restore", temp.root()]);
    failure(&["branch", temp.root(), "-d", "feature"]);
    success(&["branch", temp.root(), "-m", "main"]);
    assert_eq!(success(&["rev-parse", temp.root(), "main"]).trim(), first);
    success(&["branch", temp.root(), "-m", "feature", "topic"]);
    success(&["switch", temp.root(), "topic"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), B);
    success(&["branch", temp.root(), "-d", "main"]);
    failure(&["branch", temp.root(), "-D", "topic"]);
    success(&["branch", temp.root(), "other", &first]);
    success(&["branch", temp.root(), "-D", "other"]);
}

#[test]
fn move_tracks_the_new_path_without_overwriting_untracked_or_dirty_bytes() {
    let temp = Temp::new("mv");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    temp.write(B);
    let untracked = temp.path("other.wasm");
    fs::write(&untracked, C).unwrap();
    let before = metadata(&temp);
    failure(&["mv", temp.root(), "module.wasm", "other.wasm"]);
    failure(&["mv", temp.root(), "module.wasm", "../escaped.wasm"]);
    assert_eq!(metadata(&temp), before);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), B);
    success(&["mv", temp.root(), "module.wasm", "moved.wasm"]);
    assert!(!Path::new(&temp.path("module.wasm")).exists());
    assert_eq!(fs::read(temp.path("moved.wasm")).unwrap(), B);
    assert_eq!(fs::read(untracked).unwrap(), C);
    assert_eq!(success(&["ls-files", temp.root()]).trim(), "moved.wasm");
    assert_eq!(status(&temp)["worktree"], "modified");
    success(&["restore", temp.root()]);
    assert_eq!(fs::read(temp.path("moved.wasm")).unwrap(), A);
}

#[test]
fn cached_remove_does_not_drop_unique_index_bytes_without_force() {
    let temp = Temp::new("unique-index");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    temp.stage(B);
    temp.write(C);
    let before = metadata(&temp);
    failure(&["rm", temp.root(), "--cached"]);
    assert_eq!(metadata(&temp), before);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), C);
    success(&["rm", temp.root(), "--cached", "--force"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), C);
    assert_eq!(success(&["ls-files", temp.root()]).trim(), "");
}

#[test]
fn stash_merges_independent_head_changes_and_retains_conflicting_snapshot() {
    fn functions(a: i32, b: i32) -> Vec<u8> {
        wat::parse_str(format!(
            "(module (func (result i32) i32.const {a}) (func (result i32) i32.const {b}))"
        ))
        .unwrap()
    }
    let temp = Temp::new("stash-merge");
    temp.init();
    temp.stage(&functions(0, 0));
    temp.commit("base");
    temp.stage(&functions(0, 2));
    temp.write(&functions(0, 3));
    success(&["stash", temp.root(), "push"]);
    temp.stage(&functions(1, 0));
    temp.commit("independent upstream");
    success(&["stash", temp.root(), "apply", "0"]);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), functions(1, 3));
    let restored = temp.commit("merged staged bytes");
    let output = temp.path("merged-index.wasm");
    success(&["restore", temp.root(), &restored, "--output", &output]);
    assert_eq!(fs::read(output).unwrap(), functions(1, 2));
    success(&["reset", temp.root(), "--hard", "HEAD~1"]);
    temp.stage(&functions(1, 4));
    temp.commit("conflicting upstream");
    let before = metadata(&temp);
    let worktree = fs::read(temp.path("module.wasm")).unwrap();
    failure(&["stash", temp.root(), "pop", "0"]);
    assert_eq!(metadata(&temp), before);
    assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), worktree);
    let list: Value = serde_json::from_str(&success(&["stash", temp.root(), "list"])).unwrap();
    assert_eq!(list[0]["id"], 0);
}

#[cfg(unix)]
#[test]
fn symlink_tracking_and_metadata_redirection_are_refused() {
    use std::os::unix::fs::symlink;
    let temp = Temp::new("symlink");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    let outside = Temp::new("outside");
    outside.write(B);
    symlink(outside.path("module.wasm"), temp.path("linked.wasm")).unwrap();
    let before = metadata(&temp);
    failure(&["add", temp.root(), "linked.wasm"]);
    assert_eq!(metadata(&temp), before);
    symlink(&outside.0, temp.path("linked-dir")).unwrap();
    failure(&["add", temp.root(), "linked-dir/module.wasm"]);
    assert_eq!(metadata(&temp), before);
    fs::remove_file(temp.path(".uwgit/index")).unwrap();
    symlink(outside.path("module.wasm"), temp.path(".uwgit/index")).unwrap();
    failure(&["add", temp.root(), "module.wasm"]);
    assert_eq!(fs::read(outside.path("module.wasm")).unwrap(), B);
    assert!(fs::symlink_metadata(temp.path(".uwgit/index"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(unix)]
#[test]
fn metadata_staging_directory_symlink_is_rejected_before_any_write() {
    use std::os::unix::fs::symlink;
    let temp = Temp::new("metadata-tmp");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    let outside = Temp::new("metadata-outside");
    outside.write(C);
    let original_index = fs::read(temp.path(".uwgit/index")).unwrap();
    let original_head = fs::read(temp.path(".uwgit/HEAD")).unwrap();
    fs::remove_dir(temp.path(".uwgit/tmp")).unwrap();
    symlink(&outside.0, temp.path(".uwgit/tmp")).unwrap();
    temp.write(B);
    failure(&["add", temp.root(), "module.wasm"]);
    failure(&["config", temp.root(), "user.name", "must not write"]);
    assert_eq!(fs::read(temp.path(".uwgit/index")).unwrap(), original_index);
    assert_eq!(fs::read(temp.path(".uwgit/HEAD")).unwrap(), original_head);
    assert_eq!(fs::read(outside.path("module.wasm")).unwrap(), C);
    assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 1);
    assert!(!Path::new(&temp.path(".uwgit/index.lock")).exists());
}

#[test]
fn worktree_and_cached_diff_use_distinct_lossless_snapshots_without_writing() {
    let temp = Temp::new("diff-snapshots");
    temp.init();
    temp.stage(A);
    temp.commit("base");
    temp.stage(B);
    temp.write(C);
    let before = metadata(&temp);
    for (cached, old, new) in [(false, B, C), (true, A, B)] {
        let mut arguments = vec![
            "diff",
            temp.root(),
            "--format",
            "json",
            "--standard",
            "core1",
        ];
        if cached {
            arguments.push("--cached");
        }
        let report: Value = serde_json::from_str(&success(&arguments)).unwrap();
        assert_eq!(report["kind"], "tree_diff");
        assert_eq!(report["binary_changed"], true);
        let report = &report["files"][0]["diff"];
        assert_eq!(
            report["inputs"]["new"]["kind"],
            if cached { "index" } else { "worktree" }
        );
        if cached {
            assert_eq!(
                report["inputs"]["old"]["commit"],
                success(&["rev-parse", temp.root(), "HEAD"]).trim()
            );
        }
        let expected =
            wasm_git::audit::compare_with_standard(old, new, wasm_git::standard::Standard::Core1)
                .unwrap();
        assert_eq!(report["audit"], serde_json::to_value(expected).unwrap());
        assert_eq!(metadata(&temp), before);
        assert_eq!(fs::read(temp.path("module.wasm")).unwrap(), C);
    }
    fs::remove_file(temp.path("module.wasm")).unwrap();
    let report: Value =
        serde_json::from_str(&success(&["diff", temp.root(), "--format", "json"])).unwrap();
    assert_eq!(report["files"][0]["status"], "deleted");
    assert_eq!(report["files"][0]["content"]["side"], "old");
    assert_eq!(status(&temp)["worktree"], "deleted");
    assert_eq!(metadata(&temp), before);
}
