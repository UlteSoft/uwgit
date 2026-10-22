use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-merge-policies-{}-{}",
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
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim_end().into()
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn wasm(value: i32) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (func (export \"f\") (result i32) i32.const {value}))"
    ))
    .unwrap()
}
fn commit(root: &Path, name: &str, value: i32) -> String {
    fs::write(root.join(name), wasm(value)).unwrap();
    ok(&["add", p(root), name]);
    ok(&["commit", p(root), "-m", "change"]);
    ok(&["rev-parse", p(root), "HEAD"])
}
fn setup(root: &Path) -> (String, String) {
    ok(&["init", p(root)]);
    let base = commit(root, "a.wasm", 1);
    ok(&["switch", p(root), "-c", "topic"]);
    let tip = commit(root, "a.wasm", 2);
    ok(&["switch", p(root), "main"]);
    (base, tip)
}
#[test]
fn no_ff_creates_a_real_two_parent_commit_and_keeps_literal_message_flags() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (base, tip) = setup(&root);
    let report = json(&["merge", p(&root), "topic", "--no-ff", "-m", "--help"]);
    assert_eq!(report["status"], "merged");
    let merged = ok(&["rev-parse", p(&root), "HEAD"]);
    assert_ne!(merged, tip);
    let info = json(&["cat-file", p(&root), "HEAD"]);
    assert_eq!(info["parents"], serde_json::json!([base, tip]));
    assert_eq!(info["message"], "--help");
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    let before = fs::read_dir(root.join(".uwgit/objects")).unwrap().count();
    assert_eq!(
        json(&["merge", p(&root), "topic", "--no-ff", "-m", "again"])["status"],
        "already_up_to_date"
    );
    assert_eq!(
        fs::read_dir(root.join(".uwgit/objects")).unwrap().count(),
        before
    );
    ok(&["fsck", p(&root)]);
}
#[test]
fn squash_stages_the_target_without_moving_head_and_the_following_commit_has_one_parent() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (base, tip) = setup(&root);
    let report = json(&["merge", p(&root), "topic", "--squash"]);
    assert_eq!(report["status"], "squashed");
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), base);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    assert!(!root.join(".uwgit/pending.json").exists());
    ok(&["commit", p(&root), "-m", "reviewed squash"]);
    let info = json(&["cat-file", p(&root), "HEAD"]);
    assert_eq!(info["parents"], serde_json::json!([base]));
    assert_ne!(info["id"], tip);
    ok(&["fsck", p(&root)]);
}
#[test]
fn divergent_squash_preserves_both_independent_module_changes() {
    let temp = Temp::new();
    let root = temp.path("repo");
    ok(&["init", p(&root)]);
    commit(&root, "a.wasm", 1);
    commit(&root, "b.wasm", 1);
    ok(&["branch", p(&root), "topic"]);
    let ours = commit(&root, "a.wasm", 2);
    ok(&["switch", p(&root), "topic"]);
    commit(&root, "b.wasm", 3);
    ok(&["switch", p(&root), "main"]);
    json(&["merge", p(&root), "topic", "--squash"]);
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), ours);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    assert_eq!(fs::read(root.join("b.wasm")).unwrap(), wasm(3));
}
#[test]
fn conflicts_dirty_state_untracked_obstructions_and_invalid_policy_combinations_publish_nothing() {
    let temp = Temp::new();
    let root = temp.path("repo");
    setup(&root);
    commit(&root, "a.wasm", 3);
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    let head = ok(&["rev-parse", p(&root), "HEAD"]);
    let count = fs::read_dir(root.join(".uwgit/objects")).unwrap().count();
    let out = run(&["merge", p(&root), "topic", "--squash"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(3));
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), head);
    assert_eq!(
        fs::read_dir(root.join(".uwgit/objects")).unwrap().count(),
        count
    );
    for flags in [
        vec!["--no-ff", "--ff-only"],
        vec!["--squash", "--no-ff"],
        vec!["--squash", "--record-conflict"],
    ] {
        let mut args = vec!["merge", p(&root), "topic"];
        args.extend(flags);
        args.extend(["-m", "message"]);
        assert!(!run(&args).status.success());
        assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
    }
    fs::write(root.join("a.wasm"), b"dirty").unwrap();
    assert!(!run(&["merge", p(&root), "topic", "--squash"])
        .status
        .success());
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), b"dirty");
}
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn real_http_pull_no_ff_creates_two_parents_after_verified_fetch() {
    let temp = Temp::new();
    let served = temp.path("served");
    fs::create_dir(&served).unwrap();
    let root = served.join("repo");
    ok(&["init", p(&root)]);
    let base = commit(&root, "a.wasm", 1);
    let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(["server", "--root", p(&served), "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let _server = Server(child);
    let startup: Value = serde_json::from_str(&line).unwrap();
    let url = format!("http://{}/repo", startup["listen"].as_str().unwrap());
    let peer = temp.path("peer");
    ok(&["clone", &url, p(&peer)]);
    ok(&[
        "restore",
        p(&peer),
        "--source",
        "HEAD",
        "--staged",
        "--worktree",
    ]);
    let tip = commit(&root, "a.wasm", 2);
    json(&["pull", p(&peer), "--no-ff", "-m", "reviewed"]);
    let info = json(&["cat-file", p(&peer), "HEAD"]);
    assert_eq!(info["parents"], serde_json::json!([base, tip]));
    assert_eq!(fs::read(peer.join("a.wasm")).unwrap(), wasm(2));
}

#[test]
fn squash_without_an_index_cannot_overwrite_existing_untracked_work_bytes() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (base, _) = setup(&root);
    fs::remove_file(root.join(".uwgit/index")).unwrap();
    fs::write(root.join("a.wasm"), b"untracked local bytes").unwrap();
    assert!(!run(&["merge", p(&root), "topic", "--squash"])
        .status
        .success());
    assert_eq!(
        fs::read(root.join("a.wasm")).unwrap(),
        b"untracked local bytes"
    );
    assert!(!root.join(".uwgit/index").exists());
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), base);
}
