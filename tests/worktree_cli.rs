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
            "uwgit-worktrees-{}-{}",
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
fn fail(args: &[&str]) {
    let output = execute(args);
    assert!(!output.status.success(), "{args:?}");
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}
fn seed(root: &Path) -> String {
    ok(&["init", p(root)]);
    fs::write(root.join("module.wasm"), wasm(1)).unwrap();
    ok(&["add", p(root), "module.wasm"]);
    ok(&["commit", p(root), "-m", "root"]);
    ok(&["rev-parse", p(root), "HEAD"])
}
fn add(primary: &Path, linked: &Path) {
    json(&["worktree", p(primary), "add", p(linked), "-b", "topic"]);
}

#[test]
fn linked_worktrees_share_original_objects_refs_and_tags_but_not_head_index_or_work_bytes() {
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    let first = seed(&primary);
    add(&primary, &linked);
    assert_eq!(fs::read(linked.join("module.wasm")).unwrap(), wasm(1));
    assert!(!linked.join(".uwgit/objects").exists());
    assert!(!linked.join(".uwgit/refs").exists());
    fs::write(linked.join("module.wasm"), wasm(9)).unwrap();
    ok(&["add", p(&linked), "module.wasm"]);
    ok(&["commit", p(&linked), "-m", "linked change"]);
    let tip = ok(&["rev-parse", p(&linked), "HEAD"]);
    assert_ne!(first, tip);
    assert_eq!(ok(&["rev-parse", p(&primary), "HEAD"]), first);
    assert_eq!(ok(&["rev-parse", p(&primary), "topic"]), tip);
    assert_eq!(fs::read(primary.join("module.wasm")).unwrap(), wasm(1));
    assert_ne!(
        fs::read(primary.join(".uwgit/index")).unwrap(),
        fs::read(linked.join(".uwgit/index")).unwrap()
    );
    ok(&["tag", p(&linked), "linked-tag"]);
    assert_eq!(ok(&["rev-parse", p(&primary), "linked-tag"]), tip);
    ok(&["fsck", p(&primary)]);
    ok(&["fsck", p(&linked)]);
    let list = json(&["worktree", p(&linked), "list"]);
    assert_eq!(list["worktrees"].as_array().unwrap().len(), 2);
    let report = execute(&["worktree", p(&primary), "list", "--porcelain", "-z"]);
    assert!(report.status.success());
    assert!(report.stdout.contains(&0));
    assert!(!report.stdout.ends_with(b"\n"));
}

#[test]
fn checked_out_branches_cannot_be_switched_deleted_renamed_or_overwritten_from_another_tree() {
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    let first = seed(&primary);
    add(&primary, &linked);
    let before = fs::read(primary.join(".uwgit/index")).unwrap();
    let head = fs::read(primary.join(".uwgit/HEAD")).unwrap();
    for args in [
        vec!["switch", p(&primary), "topic"],
        vec!["branch", p(&primary), "-D", "topic"],
        vec!["branch", p(&primary), "-m", "topic", "renamed"],
        vec!["update-ref", p(&primary), "-d", "refs/heads/topic", &first],
        vec!["switch", p(&linked), "main"],
    ] {
        fail(&args);
    }
    assert_eq!(fs::read(primary.join(".uwgit/index")).unwrap(), before);
    assert_eq!(fs::read(primary.join(".uwgit/HEAD")).unwrap(), head);
    assert_eq!(fs::read(primary.join("module.wasm")).unwrap(), wasm(1));
    let duplicate = temp.path("duplicate");
    fail(&["worktree", p(&primary), "add", p(&duplicate), "topic"]);
    assert!(!duplicate.exists());
    ok(&["switch", p(&linked), "-c", "alternate"]);
    ok(&["branch", p(&linked), "-m", "renamed"]);
    ok(&["branch", p(&primary), "-D", "topic"]);
    fail(&["switch", p(&primary), "renamed"]);
    assert_eq!(
        json(&["worktree", p(&primary), "list"])["worktrees"][1]["branch"],
        "renamed"
    );
}

#[test]
fn worktree_locks_moves_and_force_removal_preserve_shared_history() {
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    let moved = temp.path("moved");
    seed(&primary);
    add(&primary, &linked);
    json(&[
        "worktree",
        p(&primary),
        "lock",
        p(&linked),
        "--reason",
        "keep",
    ]);
    fail(&["worktree", p(&primary), "remove", p(&linked), "-f"]);
    fail(&["worktree", p(&primary), "move", p(&linked), p(&moved)]);
    json(&["worktree", p(&primary), "unlock", p(&linked)]);
    fs::write(linked.join("module.wasm"), b"dirty bytes").unwrap();
    json(&["worktree", p(&primary), "move", p(&linked), p(&moved)]);
    assert!(!linked.exists());
    assert_eq!(fs::read(moved.join("module.wasm")).unwrap(), b"dirty bytes");
    assert!(!moved.join(".uwgit/index.lock").exists());
    json(&["status", p(&moved)]);
    fail(&["worktree", p(&primary), "remove", p(&moved)]);
    json(&["worktree", p(&primary), "remove", p(&moved), "-f"]);
    assert!(!moved.exists());
    ok(&["rev-parse", p(&primary), "topic"]);
    ok(&["fsck", p(&primary)]);
}

#[test]
fn external_moves_require_repair_and_pruning_only_removes_missing_unlocked_registrations() {
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    let moved = temp.path("external");
    seed(&primary);
    add(&primary, &linked);
    fs::rename(&linked, &moved).unwrap();
    fail(&["status", p(&moved)]);
    assert_eq!(
        json(&["worktree", p(&primary), "prune", "-n"])["paths"],
        serde_json::json!([linked])
    );
    json(&["worktree", p(&primary), "repair", p(&moved)]);
    json(&["status", p(&moved)]);
    fs::remove_dir_all(&moved).unwrap();
    let list = json(&["worktree", p(&primary), "list"]);
    assert_eq!(list["worktrees"][1]["missing"], true);
    json(&["worktree", p(&primary), "prune"]);
    assert_eq!(
        json(&["worktree", p(&primary), "list"])["worktrees"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    ok(&["rev-parse", p(&primary), "topic"]);
}

#[test]
fn removal_refuses_untracked_content_and_foreign_repositories() {
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    let foreign = temp.path("foreign");
    seed(&primary);
    seed(&foreign);
    add(&primary, &linked);
    fs::write(linked.join("untracked.txt"), b"preserve").unwrap();
    fail(&["worktree", p(&primary), "remove", p(&linked)]);
    assert_eq!(fs::read(linked.join("untracked.txt")).unwrap(), b"preserve");
    fail(&["worktree", p(&foreign), "remove", p(&linked), "-f"]);
    assert!(linked.exists());
    fail(&["worktree", p(&primary), "remove", p(&primary), "-f"]);
    assert!(primary.exists());
    json(&["worktree", p(&primary), "remove", p(&linked), "-f"]);
}

#[cfg(unix)]
#[test]
fn redirected_metadata_and_external_symlinks_cannot_redirect_worktree_removal() {
    use std::os::unix::fs::symlink;
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    let outside = temp.path("outside");
    seed(&primary);
    add(&primary, &linked);
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), b"keep").unwrap();
    symlink(&outside, linked.join("redirect")).unwrap();
    fail(&["worktree", p(&primary), "remove", p(&linked), "-f"]);
    assert_eq!(fs::read(outside.join("keep")).unwrap(), b"keep");
    fs::remove_file(linked.join("redirect")).unwrap();
    let common = fs::read(linked.join(".uwgit/commondir")).unwrap();
    fs::remove_file(linked.join(".uwgit/commondir")).unwrap();
    symlink(outside.join("keep"), linked.join(".uwgit/commondir")).unwrap();
    fail(&["status", p(&linked)]);
    fs::remove_file(linked.join(".uwgit/commondir")).unwrap();
    fs::write(linked.join(".uwgit/commondir"), common).unwrap();
    json(&["status", p(&linked)]);
    assert_eq!(fs::read(outside.join("keep")).unwrap(), b"keep");
}

#[test]
fn missing_locked_worktrees_stay_reserved_until_explicit_unlock_and_prune() {
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    seed(&primary);
    add(&primary, &linked);
    json(&["worktree", p(&primary), "lock", p(&linked)]);
    fs::remove_dir_all(&linked).unwrap();
    let report = json(&["worktree", p(&primary), "prune", "-n"]);
    assert!(report["paths"].as_array().unwrap().is_empty());
    fail(&["switch", p(&primary), "topic"]);
    json(&["worktree", p(&primary), "unlock", p(&linked)]);
    json(&["worktree", p(&primary), "prune"]);
    ok(&["switch", p(&primary), "topic"]);
}

#[test]
fn force_removal_preserves_foreign_git_metadata_and_lock_reasons_cannot_break_porcelain_framing() {
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    seed(&primary);
    add(&primary, &linked);
    fs::create_dir(linked.join(".git")).unwrap();
    fs::write(linked.join(".git/keep"), b"foreign repository metadata").unwrap();
    fail(&["worktree", p(&primary), "remove", p(&linked), "-f"]);
    assert_eq!(
        fs::read(linked.join(".git/keep")).unwrap(),
        b"foreign repository metadata"
    );
    fail(&[
        "worktree",
        p(&primary),
        "lock",
        p(&linked),
        "--reason",
        "line one\nworktree injected",
    ]);
    assert_eq!(
        json(&["worktree", p(&primary), "list"])["worktrees"][1]["locked"],
        Value::Null
    );
}
#[test]
fn gc_stops_conservative_whole_store_retention_after_the_last_worktree_is_removed() {
    let temp = Temp::new();
    let primary = temp.path("primary");
    let linked = temp.path("linked");
    seed(&primary);
    add(&primary, &linked);
    let tree = ok(&["write-tree", p(&primary)]);
    let dangling = ok(&["commit-tree", p(&primary), &tree, "-m", "unreferenced"]);
    assert!(json(&["gc", p(&primary), "--prune=now"])["removed"]
        .as_array()
        .unwrap()
        .is_empty());
    json(&["worktree", p(&primary), "remove", p(&linked)]);
    let report = json(&["gc", p(&primary), "--prune=now"]);
    assert!(report["removed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id == &dangling));
    ok(&["fsck", p(&primary)]);
}
