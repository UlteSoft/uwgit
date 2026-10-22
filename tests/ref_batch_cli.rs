use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-ref-batch-{}-{}",
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
fn execute(args: &[&str], input: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = execute(args, None);
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
fn seed(root: &Path) -> String {
    ok(&["init", p(root)]);
    fs::write(root.join("a.wasm"), wasm(0xff)).unwrap();
    ok(&["add", p(root), "a.wasm"]);
    ok(&["commit", p(root), "-m", "root"]);
    ok(&["rev-parse", p(root), "HEAD"])
}
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn server(root: &Path) -> (Server, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(["server", "--root", p(root), "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let guard = Server(child);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        tx.send(line).unwrap();
    });
    let value: Value =
        serde_json::from_str(&rx.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
    let url = format!("http://{}/project", value["listen"].as_str().unwrap());
    (guard, url)
}

#[test]
fn nested_branches_tags_rename_and_prefix_cleanup_preserve_the_same_native_history() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let id = seed(&root);
    ok(&["branch", p(&root), "feature/x"]);
    ok(&["tag", p(&root), "release/2026"]);
    assert!(root.join(".uwgit/refs/feature/x").is_file());
    assert_eq!(ok(&["rev-parse", p(&root), "release/2026"]), id);
    ok(&["branch", p(&root), "-m", "feature/x", "feature/y"]);
    ok(&["branch", p(&root), "-D", "feature/y"]);
    assert!(!root.join(".uwgit/refs/feature").exists());
    ok(&["branch", p(&root), "feature"]);
    for name in [
        "a/../b",
        "a//b",
        "a/.lock/b",
        "a/./b",
        "a/b.lock",
        "a/../../outside",
    ] {
        assert!(
            !execute(&["branch", p(&root), name], None).status.success(),
            "{name}"
        );
    }
    ok(&["fsck", p(&root)]);
}
#[test]
fn nested_reference_names_survive_real_http_clone_and_upstream_queries() {
    let temp = Temp::new();
    let served = temp.path("served");
    fs::create_dir(&served).unwrap();
    let root = served.join("project");
    let id = seed(&root);
    ok(&["branch", p(&root), "feature/x"]);
    ok(&["tag", p(&root), "release/2026"]);
    let (_server, url) = server(&served);
    let peer = temp.path("peer");
    ok(&["clone", &url, p(&peer), "--allow-insecure-http"]);
    assert_eq!(ok(&["rev-parse", p(&peer), "feature/x"]), id);
    assert_eq!(ok(&["rev-parse", p(&peer), "release/2026"]), id);
    ok(&["branch", p(&peer), "feature/tracking", "origin/feature/x"]);
    ok(&[
        "branch",
        p(&peer),
        "-u",
        "origin/feature/x",
        "feature/tracking",
    ]);
    assert_eq!(ok(&["rev-parse", p(&peer), "feature/tracking@{u}"]), id);
    ok(&["fsck", p(&peer)]);
}
#[test]
fn symbolic_head_updates_only_the_pointer_and_name_checks_reject_metadata_traversal() {
    let temp = Temp::new();
    let root = temp.path("repo");
    seed(&root);
    ok(&["branch", p(&root), "feature/x"]);
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    let bytes = fs::read(root.join("a.wasm")).unwrap();
    ok(&["symbolic-ref", p(&root), "HEAD", "refs/heads/feature/x"]);
    assert_eq!(
        ok(&["symbolic-ref", p(&root), "--short", "HEAD"]),
        "feature/x"
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), bytes);
    assert_eq!(
        ok(&["check-ref-format", "--branch", "feature/x"]),
        "feature/x"
    );
    assert_eq!(
        ok(&["check-ref-format", "--normalize", "/refs//heads/feature/x"]),
        "refs/heads/feature/x"
    );
    for name in [
        "refs/heads/../outside",
        "refs/heads/x.lock/y",
        "refs/heads/x//y",
    ] {
        assert!(!execute(&["check-ref-format", name], None).status.success());
    }
}
#[test]
fn batch_outputs_raw_wasm_bytes_with_correct_headers_and_typed_object_paths() {
    let temp = Temp::new();
    let root = temp.path("repo");
    seed(&root);
    let tree = json(&["ls-tree", p(&root), "HEAD"]);
    let blob = tree["entries"][0]["object_id"].as_str().unwrap();
    let input = format!("HEAD:a.wasm\n{}\n", "f".repeat(64));
    let output = execute(&["cat-file", p(&root), "--batch"], Some(input.as_bytes()));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = wasm(0xff);
    let header = format!("{blob} wasm {}\n", bytes.len());
    let expected = [
        header.as_bytes(),
        bytes.as_slice(),
        b"\n",
        format!("{} missing\n", "f".repeat(64)).as_bytes(),
    ]
    .concat();
    assert_eq!(output.stdout, expected);
    assert_eq!(ok(&["cat-file", p(&root), "-t", "HEAD^{tree}"]), "tree");
    assert_eq!(ok(&["cat-file", p(&root), "-t", "HEAD:a.wasm"]), "wasm");
}
#[test]
fn nul_framing_command_mode_buffers_and_input_failures_do_not_mutate_objects() {
    let temp = Temp::new();
    let root = temp.path("repo");
    seed(&root);
    let count = fs::read_dir(root.join(".uwgit/objects")).unwrap().count();
    let output = execute(
        &["cat-file", p(&root), "--batch-command", "--buffer", "-Z"],
        Some(b"info HEAD\0contents HEAD:a.wasm\0flush\0"),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.contains(&0xff));
    assert!(output.stdout.ends_with(&[0]));
    assert!(
        !execute(&["cat-file", p(&root), "--batch"], Some(&[0xff, b'\n']))
            .status
            .success()
    );
    assert!(!execute(
        &["cat-file", p(&root), "--batch"],
        Some("a".repeat(8193).as_bytes())
    )
    .status
    .success());
    assert_eq!(
        fs::read_dir(root.join(".uwgit/objects")).unwrap().count(),
        count
    );
}

#[test]
fn describe_roundtrips_a_hierarchical_tag_without_treating_it_as_tracking() {
    let temp = Temp::new();
    let root = temp.path("repo");
    seed(&root);
    ok(&["tag", p(&root), "release/2026"]);
    fs::write(root.join("a.wasm"), wasm(7)).unwrap();
    ok(&["add", p(&root), "a.wasm"]);
    ok(&["commit", p(&root), "-m", "later"]);
    let description = ok(&["describe", p(&root)]);
    assert!(description.starts_with("release/2026-1-g"));
    assert_eq!(
        ok(&["rev-parse", p(&root), &description]),
        ok(&["rev-parse", p(&root), "HEAD"])
    );
}

#[test]
fn batch_command_rejects_missing_object_operands() {
    let temp = Temp::new();
    let root = temp.path("repo");
    seed(&root);
    let output = execute(&["cat-file", p(&root), "--batch-command"], Some(b"info \n"));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
