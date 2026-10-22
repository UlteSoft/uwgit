//! Native HEAD identities, branch-independent commits, and shared-store leases.
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
            "uwgit-head-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn repo(&self, name: &str) -> PathBuf {
        let root = self.0.join(name);
        ok(&["init", p(&root)]);
        root
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
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let o = run(args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap().trim().into()
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}
fn commit(root: &Path, value: u8) -> String {
    fs::write(root.join("a.wasm"), wasm(value)).unwrap();
    ok(&["add", p(root), "a.wasm"]);
    ok(&["commit", p(root), "-m", &format!("value {value}")]);
    ok(&["rev-parse", p(root), "HEAD"])
}

#[test]
fn detached_commits_amend_and_reset_move_only_the_actual_head_pointer() {
    let t = Temp::new();
    let root = t.repo("root");
    let r = p(&root);
    let base = commit(&root, 1);
    let branch = fs::read(root.join(".uwgit/refs/main")).unwrap();
    ok(&["switch", r, "--detach", "HEAD"]);
    assert_eq!(
        fs::read(root.join(".uwgit/HEAD")).unwrap(),
        format!("{base}\n").as_bytes()
    );
    let quiet = run(&["symbolic-ref", r, "-q", "HEAD"]);
    assert_eq!(quiet.status.code(), Some(1));
    assert!(quiet.stdout.is_empty() && quiet.stderr.is_empty());
    let second = commit(&root, 2);
    assert_ne!(second, base);
    assert_eq!(fs::read(root.join(".uwgit/refs/main")).unwrap(), branch);
    assert_eq!(fs::read_dir(root.join(".uwgit/refs")).unwrap().count(), 1);
    let status = json(&["status", r]);
    assert_eq!(status["detached"], true);
    assert_eq!(status["head"], second);
    assert_eq!(
        json(&["show", r, "HEAD"])["parents"],
        serde_json::json!([base])
    );
    assert_eq!(json(&["log", r]).as_array().unwrap().len(), 2);
    ok(&["commit", r, "--amend", "-m", "amended detached"]);
    let amended = ok(&["rev-parse", r, "HEAD"]);
    assert_ne!(amended, second);
    assert_eq!(
        json(&["show", r, "HEAD"])["parents"],
        serde_json::json!([base])
    );
    ok(&["reset", r, "--hard", &base]);
    assert_eq!(ok(&["rev-parse", r, "HEAD"]), base);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(1));
    assert!(ok(&["branch", r]).contains("HEAD detached"));
    assert_eq!(ok(&["rev-parse", r, "HEAD@{1}"]), amended);
    ok(&["switch", r, "main"]);
    assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), b"main\n");
    ok(&["fsck", r]);
}

#[test]
fn orphan_starts_an_empty_root_and_keeps_untracked_files_and_existing_history() {
    let t = Temp::new();
    let root = t.repo("root");
    let r = p(&root);
    let base = commit(&root, 1);
    fs::write(root.join("keep.txt"), b"untracked original").unwrap();
    fs::write(root.join("a.wasm"), wasm(2)).unwrap();
    let before = fs::read(root.join(".uwgit/HEAD")).unwrap();
    assert!(!run(&["switch", r, "--orphan", "fresh"]).status.success());
    assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), before);
    ok(&["restore", r, "--", "a.wasm"]);
    ok(&["checkout", r, "--orphan", "fresh"]);
    assert!(!root.join("a.wasm").exists());
    assert_eq!(
        fs::read(root.join("keep.txt")).unwrap(),
        b"untracked original"
    );
    assert!(!run(&["rev-parse", r, "HEAD"]).status.success());
    assert_eq!(ok(&["ls-files", r]), "");
    let fresh = commit(&root, 3);
    assert_eq!(json(&["show", r, "HEAD"])["parents"], serde_json::json!([]));
    assert_ne!(fresh, base);
    assert_eq!(ok(&["rev-parse", r, "main"]), base);
    ok(&["checkout", r, &base]);
    assert_eq!(json(&["status", r])["detached"], true);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(1));
    assert!(!run(&["switch", r, "--orphan", "main"]).status.success());
    ok(&["fsck", r]);
}

#[test]
fn detached_linked_worktrees_share_objects_without_reserving_a_branch_or_mixing_local_logs() {
    let t = Temp::new();
    let root = t.repo("root");
    let r = p(&root);
    let base = commit(&root, 1);
    let linked = t.0.join("linked");
    let peer = t.0.join("peer");
    ok(&["worktree", r, "add", "--detach", p(&linked), &base]);
    ok(&["worktree", r, "add", "-d", p(&peer), &base]);
    let one = commit(&linked, 2);
    let two = commit(&peer, 3);
    assert_eq!(ok(&["rev-parse", p(&linked), "HEAD"]), one);
    assert_eq!(ok(&["rev-parse", p(&peer), "HEAD"]), two);
    assert_eq!(ok(&["rev-parse", r, "HEAD"]), base);
    assert_eq!(ok(&["rev-parse", p(&linked), "HEAD@{1}"]), base);
    ok(&["switch", p(&linked), "-c", "alpha"]);
    let alpha = commit(&linked, 4);
    assert_eq!(ok(&["rev-parse", p(&linked), "HEAD@{1}"]), one);
    ok(&["switch", p(&linked), "-"]);
    assert_eq!(ok(&["rev-parse", p(&linked), "HEAD"]), one);
    assert_eq!(ok(&["rev-parse", p(&peer), "HEAD"]), two);
    assert_eq!(ok(&["rev-parse", r, "alpha"]), alpha);
    let listing = ok(&["worktree", r, "list", "--porcelain"]);
    assert!(listing.contains("detached"));
    assert!(!listing.contains(&format!("refs/heads/{one}")));
    ok(&["fsck", r]);
    ok(&["worktree", r, "remove", p(&linked)]);
    ok(&["worktree", r, "remove", p(&peer)]);
}

#[test]
fn detached_head_without_any_branch_survives_bundle_clone_gc_and_index_materialization() {
    let t = Temp::new();
    let root = t.repo("root");
    let r = p(&root);
    commit(&root, 1);
    ok(&["switch", r, "--detach"]);
    let tip = commit(&root, 2);
    ok(&["branch", r, "-D", "main"]);
    assert_eq!(fs::read_dir(root.join(".uwgit/refs")).unwrap().count(), 0);
    assert_eq!(ok(&["show-ref", r, "--head"]), format!("{tip} HEAD"));
    assert_eq!(ok(&["rev-list", r, "--all", "--count"]), "2");
    assert_eq!(json(&["fsck", r])["unreachable_objects"], 0);
    ok(&["gc", r, "--prune=now"]);
    assert_eq!(ok(&["rev-parse", r, "HEAD"]), tip);
    let bundle = t.0.join("detached.bundle");
    ok(&["bundle", r, p(&bundle)]);
    let clone = t.0.join("clone");
    ok(&["clone", r, p(&clone)]);
    assert_eq!(
        fs::read(clone.join(".uwgit/HEAD")).unwrap(),
        format!("{tip}\n").as_bytes()
    );
    ok(&[
        "restore",
        p(&clone),
        "--source",
        "HEAD",
        "--staged",
        "--worktree",
    ]);
    assert_eq!(fs::read(clone.join("a.wasm")).unwrap(), wasm(2));
    let imported = t.repo("imported");
    ok(&["unbundle", p(&imported), p(&bundle), "incoming"]);
    assert_eq!(ok(&["rev-parse", p(&imported), "incoming"]), tip);
    ok(&["fsck", p(&clone)]);
    ok(&["fsck", p(&imported)]);
}

#[test]
fn branch_copy_force_rename_and_force_update_preserve_checked_out_worktree_leases() {
    let t = Temp::new();
    let root = t.repo("root");
    let r = p(&root);
    let base = commit(&root, 1);
    let tip = commit(&root, 2);
    ok(&["branch", r, "-c", "main", "copy"]);
    assert_eq!(ok(&["rev-parse", r, "copy"]), tip);
    ok(&["branch", r, "-f", "copy", &base]);
    assert_eq!(ok(&["rev-parse", r, "copy"]), base);
    ok(&["branch", r, "-C", "main", "copy"]);
    assert_eq!(ok(&["rev-parse", r, "copy"]), tip);
    ok(&["branch", r, "other", &base]);
    ok(&["branch", r, "-M", "other", "copy"]);
    assert_eq!(ok(&["rev-parse", r, "copy"]), base);
    assert!(!run(&["rev-parse", r, "other"]).status.success());
    let linked = t.0.join("linked");
    ok(&["worktree", r, "add", p(&linked), "copy"]);
    for args in [
        vec!["branch", r, "-f", "main", &base],
        vec!["branch", r, "-f", "copy", &tip],
        vec!["branch", r, "-M", "main", "copy"],
        vec!["branch", r, "-C", "main", "copy"],
    ] {
        assert!(!run(&args).status.success(), "{args:?}");
    }
    assert_eq!(ok(&["rev-parse", r, "main"]), tip);
    assert_eq!(ok(&["rev-parse", p(&linked), "HEAD"]), base);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    ok(&["worktree", r, "remove", p(&linked)]);
    ok(&["fsck", r]);
}

#[test]
fn detached_conflict_continuation_keeps_branch_tips_and_records_two_real_parents() {
    let t = Temp::new();
    let root = t.repo("root");
    let r = p(&root);
    commit(&root, 1);
    ok(&["branch", r, "topic"]);
    let ours = commit(&root, 2);
    ok(&["switch", r, "topic"]);
    let theirs = commit(&root, 3);
    ok(&["switch", r, "--detach", &ours]);
    let conflict = run(&[
        "merge",
        r,
        "topic",
        "-m",
        "reviewed merge",
        "--record-conflict",
    ]);
    assert_eq!(
        conflict.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&conflict.stderr)
    );
    fs::write(root.join("a.wasm"), wasm(4)).unwrap();
    ok(&["add", r, "a.wasm"]);
    ok(&["merge", r, "--continue", "--resolved-index"]);
    let tip = ok(&["rev-parse", r, "HEAD"]);
    assert_ne!(tip, ours);
    assert_eq!(
        json(&["show", r, "HEAD"])["parents"],
        serde_json::json!([ours, theirs])
    );
    assert_eq!(ok(&["rev-parse", r, "main"]), ours);
    assert_eq!(ok(&["rev-parse", r, "topic"]), theirs);
    assert!(!root.join(".uwgit/pending.json").exists());
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(4));
    ok(&["fsck", r]);
}
