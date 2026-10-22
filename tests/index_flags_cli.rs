use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "uwgit-flags-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        ok(&["init", p.to_str().unwrap()]);
        Self(p)
    }
    fn root(&self) -> &str {
        self.0.to_str().unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(args: &[&str], input: Option<&[u8]>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    if let Some(bytes) = input {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
fn ok(args: &[&str]) -> String {
    let o = run(args, None);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap().trim_end().to_owned()
}
fn fail(args: &[&str]) {
    let o = run(args, None);
    assert!(
        !o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stdout)
    );
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn wasm(n: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', n]].concat()
}
fn seed(t: &Temp) {
    fs::write(t.0.join("a.wasm"), wasm(1)).unwrap();
    ok(&["add", t.root(), "a.wasm"]);
    ok(&["commit", t.root(), "-m", "base"]);
}
fn index(t: &Temp) -> Vec<u8> {
    fs::read(t.0.join(".uwgit/index")).unwrap()
}

#[test]
fn assume_unchanged_is_a_persistent_query_promise_and_never_discards_hidden_work() {
    let t = Temp::new();
    seed(&t);
    let r = t.root();
    let head = ok(&["rev-parse", r, "HEAD"]);
    ok(&["update-index", r, "--assume-unchanged", "a.wasm"]);
    assert!(index(&t).starts_with(b"UWGITIDX\x04"));
    assert_eq!(ok(&["ls-files", r, "-v"]), "h a.wasm");
    fs::write(t.0.join("a.wasm"), wasm(2)).unwrap();
    assert_eq!(json(&["status", r])["worktree"], "clean");
    assert_eq!(ok(&["ls-files", r, "-m"]), "");
    let before = index(&t);
    ok(&["add", r, "a.wasm"]);
    assert_eq!(index(&t), before);
    fail(&["update-index", r, "--really-refresh"]);
    assert_eq!(index(&t), before);
    ok(&["branch", r, "topic"]);
    fail(&["switch", r, "topic"]);
    assert_eq!(ok(&["rev-parse", r, "HEAD"]), head);
    assert_eq!(fs::read(t.0.join("a.wasm")).unwrap(), wasm(2));
    ok(&["update-index", r, "--no-assume-unchanged", "a.wasm"]);
    assert_eq!(json(&["status", r])["worktree"], "modified");
    ok(&["add", r, "a.wasm"]);
    ok(&["commit", r, "-m", "explicitly staged"]);
}

#[test]
fn skipped_absence_survives_checkout_add_switch_and_hard_reset_until_explicit_materialization() {
    let t = Temp::new();
    seed(&t);
    let r = t.root();
    let first = ok(&["rev-parse", r, "HEAD"]);
    fs::write(t.0.join("a.wasm"), wasm(2)).unwrap();
    ok(&["add", r, "a.wasm"]);
    ok(&["commit", r, "-m", "second"]);
    let second = ok(&["rev-parse", r, "HEAD"]);
    ok(&["branch", r, "old", &first]);
    ok(&["update-index", r, "--skip-worktree", "a.wasm"]);
    fs::remove_file(t.0.join("a.wasm")).unwrap();
    assert_eq!(json(&["status", r])["worktree"], "clean");
    assert_eq!(ok(&["ls-files", r, "-t"]), "S a.wasm");
    let before = index(&t);
    ok(&["add", r, "-A"]);
    assert_eq!(index(&t), before);
    ok(&["checkout-index", r, "--all"]);
    assert!(!t.0.join("a.wasm").exists());
    ok(&["restore", r, "--", "a.wasm"]);
    assert!(!t.0.join("a.wasm").exists());
    ok(&["switch", r, "old"]);
    assert!(!t.0.join("a.wasm").exists());
    assert_eq!(ok(&["ls-files", r, "-t"]), "S a.wasm");
    ok(&["reset", r, "--hard", &second]);
    assert!(!t.0.join("a.wasm").exists());
    ok(&["checkout-index", r, "--all", "--ignore-skip-worktree-bits"]);
    assert_eq!(fs::read(t.0.join("a.wasm")).unwrap(), wasm(2));
    fs::write(t.0.join("a.wasm"), wasm(3)).unwrap();
    fail(&["add", r, "a.wasm"]);
    ok(&["add", r, "--sparse", "a.wasm"]);
    assert!(json(&["status", r])["staged"].as_bool().unwrap());
}

#[test]
fn intent_to_add_has_no_fabricated_image_and_commit_all_stages_actual_bytes() {
    let t = Temp::new();
    seed(&t);
    let r = t.root();
    let tree = ok(&["write-tree", r]);
    let objects = fs::read_dir(t.0.join(".uwgit/objects")).unwrap().count();
    fs::write(t.0.join("new.wasm"), wasm(2)).unwrap();
    ok(&["add", r, "-N", "new.wasm"]);
    assert_eq!(
        fs::read_dir(t.0.join(".uwgit/objects")).unwrap().count(),
        objects
    );
    assert_eq!(ok(&["write-tree", r]), tree);
    assert_eq!(ok(&["diff-files", r, "--name-status"]), "A\tnew.wasm");
    assert!(ok(&["ls-files", r, "-s"]).contains("100644 - 0\tnew.wasm"));
    let row = json(&["ls-files", r, "--json", "--", "new.wasm"]);
    assert_eq!(row["entries"][0]["intent_to_add"], true);
    assert!(row["entries"][0]["object_id"].is_null());
    let status = json(&["status", r]);
    assert_eq!(status["files"][1]["worktree"], "added");
    assert_eq!(status["staged"], false);
    assert!(status["untracked"].as_array().unwrap().is_empty());
    fail(&["commit", r, "-m", "not staged yet"]);
    fail(&["stash", r, "push"]);
    fail(&["restore", r, "--", "new.wasm"]);
    fs::write(t.0.join("untracked.wasm"), wasm(9)).unwrap();
    fs::write(t.0.join("new.wasm"), wasm(3)).unwrap();
    ok(&["commit", r, "-a", "-m", "stage actual tracked bytes"]);
    let rows = json(&["ls-tree", r, "HEAD", "--json"]);
    let rows = rows["entries"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|row| row["path"] == "new.wasm"));
    assert!(!ok(&["ls-files", r, "-s"]).contains("100644 -"));
    ok(&["fsck", r]);
}

#[test]
fn intent_move_and_cached_removal_preserve_editor_bytes_and_other_entries() {
    let t = Temp::new();
    seed(&t);
    let r = t.root();
    fs::write(t.0.join("new.wasm"), wasm(2)).unwrap();
    ok(&["add", r, "--intent-to-add", "new.wasm"]);
    fs::write(t.0.join("new.wasm"), b"unsaved non-Wasm editor bytes").unwrap();
    ok(&["mv", r, "new.wasm", "moved.wasm"]);
    assert_eq!(
        fs::read(t.0.join("moved.wasm")).unwrap(),
        b"unsaved non-Wasm editor bytes"
    );
    assert!(ok(&["ls-files", r, "-s"]).contains("100644 - 0\tmoved.wasm"));
    fail(&["rm", r, "moved.wasm"]);
    ok(&["rm", r, "--cached", "moved.wasm"]);
    assert!(t.0.join("moved.wasm").exists());
    assert_eq!(ok(&["ls-files", r]), "a.wasm");
}

#[test]
fn refresh_checks_images_without_staging_and_monitor_validity_expires_on_byte_changes() {
    let t = Temp::new();
    seed(&t);
    let r = t.root();
    ok(&["update-index", r, "--fsmonitor-valid", "a.wasm"]);
    assert_eq!(ok(&["ls-files", r, "-f"]), "h a.wasm");
    ok(&["update-index", r, "--refresh"]);
    let before = index(&t);
    fs::write(t.0.join("a.wasm"), wasm(2)).unwrap();
    assert_eq!(ok(&["ls-files", r, "-f"]), "H a.wasm");
    assert_eq!(json(&["status", r])["worktree"], "modified");
    fail(&["update-index", r, "--refresh"]);
    fail(&["update-index", r, "--fsmonitor-valid", "a.wasm"]);
    assert_eq!(index(&t), before);
    fs::write(t.0.join("a.wasm"), wasm(1)).unwrap();
    ok(&["update-index", r, "--no-fsmonitor-valid", "a.wasm"]);
    assert_eq!(ok(&["ls-files", r, "-f"]), "H a.wasm");
    fs::remove_file(t.0.join("a.wasm")).unwrap();
    fail(&["update-index", r, "--refresh"]);
    ok(&["update-index", r, "--refresh", "--ignore-missing"]);
    assert_eq!(ok(&["ls-files", r]), "a.wasm");
}

#[test]
fn skipped_missing_paths_can_be_removed_by_switch_and_read_tree_without_materializing_them() {
    for read_tree in [false, true] {
        let t = Temp::new();
        seed(&t);
        let r = t.root();
        ok(&["branch", r, "empty"]);
        ok(&["switch", r, "empty"]);
        ok(&["rm", r, "a.wasm"]);
        ok(&["commit", r, "-m", "remove final module"]);
        let empty = ok(&["write-tree", r]);
        ok(&["switch", r, "main"]);
        ok(&["update-index", r, "--skip-worktree", "a.wasm"]);
        fs::remove_file(t.0.join("a.wasm")).unwrap();
        if read_tree {
            ok(&["read-tree", r, "-u", &empty]);
        } else {
            ok(&["switch", r, "empty"]);
        }
        assert!(!t.0.join("a.wasm").exists());
        assert_eq!(ok(&["ls-files", r]), "");
    }
}

#[test]
fn squash_merge_preserves_skip_flags_and_absence_while_staging_the_selected_wasm_image() {
    let t = Temp::new();
    seed(&t);
    let r = t.root();
    let head = ok(&["rev-parse", r, "HEAD"]);
    ok(&["branch", r, "topic"]);
    ok(&["switch", r, "topic"]);
    fs::write(t.0.join("a.wasm"), wasm(2)).unwrap();
    ok(&["add", r, "a.wasm"]);
    ok(&["commit", r, "-m", "topic"]);
    ok(&["switch", r, "main"]);
    ok(&["update-index", r, "--skip-worktree", "a.wasm"]);
    fs::remove_file(t.0.join("a.wasm")).unwrap();
    ok(&["merge", r, "topic", "--squash"]);
    assert!(!t.0.join("a.wasm").exists());
    assert_eq!(ok(&["ls-files", r, "-t"]), "S a.wasm");
    assert_eq!(ok(&["rev-parse", r, "HEAD"]), head);
    assert_eq!(json(&["status", r])["staged"], true);
    ok(&["checkout-index", r, "--all", "--ignore-skip-worktree-bits"]);
    assert_eq!(fs::read(t.0.join("a.wasm")).unwrap(), wasm(2));
}

#[test]
fn flag_batches_validate_all_paths_and_keep_bytes_on_bad_options_or_unmerged_entries() {
    let t = Temp::new();
    seed(&t);
    let r = t.root();
    let before = index(&t);
    fail(&[
        "update-index",
        r,
        "--skip-worktree",
        "a.wasm",
        "missing.wasm",
    ]);
    assert_eq!(index(&t), before);
    fail(&[
        "update-index",
        r,
        "--skip-worktree",
        "--no-skip-worktree",
        "a.wasm",
    ]);
    fail(&["update-index", r, "--assume-unchanged", "--add", "a.wasm"]);
    assert_eq!(index(&t), before);
    let out = run(
        &["update-index", r, "--assume-unchanged", "--stdin", "-z"],
        Some(b"a.wasm\0"),
    );
    assert!(out.status.success());
    assert_eq!(ok(&["ls-files", r, "-v"]), "h a.wasm");
    let row = ok(&["ls-files", r, "-s"]);
    let id = row.split_whitespace().nth(1).unwrap();
    let input = format!("100644 {id} 2\ta.wasm\n");
    let out = run(&["update-index", r, "--index-info"], Some(input.as_bytes()));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let before = index(&t);
    fail(&["update-index", r, "--skip-worktree", "a.wasm"]);
    ok(&["update-index", r, "--refresh", "--unmerged"]);
    assert_eq!(index(&t), before);
}

fn git(root: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "NativeReference")
        .env("GIT_COMMITTER_NAME", "NativeReference")
        .env("GIT_AUTHOR_EMAIL", "native@example.invalid")
        .env("GIT_COMMITTER_EMAIL", "native@example.invalid")
        .output()
        .unwrap()
}
fn git_ok(root: &Path, args: &[&str]) -> String {
    let o = git(root, args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap().trim_end().to_owned()
}
#[test]
fn real_git_promises_and_intent_tree_membership_match_native_wasm_flags() {
    let t = Temp::new();
    seed(&t);
    let r = t.root();
    let reference = t.0.join("reference");
    fs::create_dir(&reference).unwrap();
    git_ok(&reference, &["init", "-b", "main"]);
    fs::write(reference.join("a.wasm"), wasm(1)).unwrap();
    git_ok(&reference, &["add", "a.wasm"]);
    git_ok(&reference, &["commit", "-m", "base"]);
    for flag in [
        "--assume-unchanged",
        "--no-assume-unchanged",
        "--skip-worktree",
        "--no-skip-worktree",
    ] {
        ok(&["update-index", r, flag, "a.wasm"]);
        git_ok(&reference, &["update-index", flag, "a.wasm"]);
        assert_eq!(
            ok(&["ls-files", r, "-v"]),
            git_ok(&reference, &["ls-files", "-v"])
        );
    }
    for root in [&t.0, &reference] {
        fs::write(root.join("new.wasm"), wasm(2)).unwrap();
    }
    ok(&["add", r, "-N", "new.wasm"]);
    git_ok(&reference, &["add", "-N", "new.wasm"]);
    assert_eq!(ok(&["ls-files", r]), git_ok(&reference, &["ls-files"]));
    let tree = git_ok(&reference, &["write-tree"]);
    assert_eq!(
        ok(&["ls-tree", r, &ok(&["write-tree", r]), "--name-only"]),
        git_ok(&reference, &["ls-tree", "--name-only", &tree])
    );
}
