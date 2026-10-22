use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "uwgit-ref-transactions-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
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
fn execute(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = execute(args, &[]);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim_end().into()
}
fn batch(root: &Path, input: &str) -> Output {
    execute(
        &["update-ref", p(root), "--stdin", "-m", "atomic fixture"],
        input.as_bytes(),
    )
}
fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}
fn seed(root: &Path) -> (String, String) {
    ok(&["init", p(root)]);
    let mut ids = Vec::new();
    for value in [1, 2] {
        fs::write(root.join("a.wasm"), wasm(value)).unwrap();
        ok(&["add", p(root), "a.wasm"]);
        ok(&["commit", p(root), "-m", &format!("value {value}")]);
        ids.push(ok(&["rev-parse", p(root), "HEAD"]));
    }
    (ids.remove(0), ids.remove(0))
}
fn image(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(root: &Path, path: &Path, entries: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, entries);
            } else {
                entries.push((
                    path.strip_prefix(root).unwrap().into(),
                    fs::read(&path).unwrap(),
                ));
            }
        }
    }
    let mut entries = Vec::new();
    walk(root, root, &mut entries);
    entries.sort();
    entries
}

#[test]
fn one_snapshot_creates_updates_deletes_verifies_and_preserves_wasm_index_and_head() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    ok(&["tag", p(&root), "old", &first]);
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    let bytes = fs::read(root.join("a.wasm")).unwrap();
    let before: Vec<Value> = fs::read_to_string(root.join(".uwgit/reflog"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(success(batch(&root, &format!("update refs/heads/topic HEAD {first}\ncreate refs/tags/release topic\ndelete refs/tags/old {first}\nverify refs/heads/main {second}\nverify refs/heads/absent\n"))).is_empty());
    assert_eq!(ok(&["rev-parse", p(&root), "topic"]), second);
    // Every operand resolves against the original snapshot, including topic.
    assert_eq!(ok(&["rev-parse", p(&root), "release"]), first);
    assert!(!root.join(".uwgit/tags/old").exists());
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), bytes);
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), second);
    let after: Vec<Value> = fs::read_to_string(root.join(".uwgit/reflog"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(&after[..before.len()], before);
    assert_eq!(after.len(), before.len() + 3);
    assert!(after[before.len()..]
        .iter()
        .all(|entry| entry["operation"] == "atomic fixture"));
    assert!(!root.join(".uwgit/ref-transaction.json").exists());
    ok(&["fsck", p(&root)]);
}

#[test]
fn failed_batch_leases_types_duplicates_names_and_checked_out_refs_publish_nothing() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    let tree: Value = serde_json::from_str(&ok(&["ls-tree", p(&root), "HEAD"])).unwrap();
    let blob = tree["entries"][0]["object_id"].as_str().unwrap();
    let zero = "0".repeat(64);
    for tail in [
        format!("update refs/heads/topic {second} {second}\n"),
        format!("create refs/heads/topic {second}\n"),
        format!("create refs/tags/blob {blob}\n"),
        format!("create refs/heads/bad/../escape {second}\n"),
        format!("update refs/heads/main {first}\n"),
        format!("delete refs/heads/topic {zero}\n"),
        "verify refs/heads/topic\n".to_owned(),
        format!("create refs/heads/topic/child {second}\n"),
        format!("verify refs/tags/new {zero}\n"),
    ] {
        let before = image(&root);
        let output = batch(&root, &format!("create refs/tags/new {second}\n{tail}"));
        assert!(
            !output.status.success(),
            "{tail}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(image(&root), before, "{tail}");
    }
}

#[test]
fn explicit_eof_abort_and_prepared_abort_leave_every_byte_unchanged() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (_, second) = seed(&root);
    for ending in ["", "prepare\n", "prepare\nabort\n", "abort\n"] {
        let before = image(&root);
        let output = success(batch(
            &root,
            &format!("start\ncreate refs/tags/new {second}\n{ending}"),
        ));
        assert!(output.starts_with(b"start: ok\n"));
        assert_eq!(image(&root), before);
    }
    assert_eq!(
        success(batch(
            &root,
            &format!("start\ncreate refs/tags/new {second}\nprepare\ncommit\n")
        )),
        b"start: ok\nprepare: ok\ncommit: ok\n"
    );
    assert_eq!(ok(&["rev-parse", p(&root), "new"]), second);
}

#[test]
fn nul_fields_c_quoting_and_zero_updates_use_native_ids() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    let zero = "0".repeat(64);
    success(batch(
        &root,
        &format!("create \"refs/tags/release\\057one\" \"{first}\"\n"),
    ));
    let input = format!("start\0option no-deref\0update refs/tags/release/one\0{second}\0{first}\0create refs/tags/second\0{second}\0verify refs/tags/missing\0\0prepare\0commit\0");
    assert_eq!(
        success(execute(
            &[
                "update-ref",
                p(&root),
                "--stdin",
                "-z",
                "--no-deref",
                "--create-reflog"
            ],
            input.as_bytes()
        )),
        b"start: ok\nprepare: ok\ncommit: ok\n"
    );
    assert_eq!(ok(&["rev-parse", p(&root), "release/one"]), second);
    success(batch(&root, &format!("update refs/tags/release/one {zero} {second}\nupdate refs/tags/second {zero} {second}\n")));
    assert!(!root.join(".uwgit/tags/release").exists());
}

#[test]
fn malformed_streams_and_invalid_control_after_prepare_abort_the_current_transaction() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (_, second) = seed(&root);
    for tail in [
        "create refs/tags/new",
        "\n",
        "commit extra\n",
        "prepare\ncreate refs/tags/other HEAD\n",
        "option no-deref\ncommit\n",
        "option unknown\n",
        "symref-update HEAD refs/heads/topic\n",
        "create \"unclosed\n",
    ] {
        let before = image(&root);
        let output = batch(
            &root,
            &format!("start\ncreate refs/tags/new {second}\n{tail}"),
        );
        assert!(!output.status.success(), "{tail}");
        assert_eq!(image(&root), before, "{tail}");
    }
    let before = image(&root);
    assert!(!execute(
        &["update-ref", p(&root), "--stdin", "-z"],
        b"create refs/tags/new\0"
    )
    .status
    .success());
    assert!(
        !execute(&["update-ref", p(&root), "--stdin"], &[0xff, b'\n'])
            .status
            .success()
    );
    assert!(!batch(&root, &"x".repeat(8193)).status.success());
    assert_eq!(image(&root), before);
}

#[test]
fn prepare_acknowledgement_holds_writer_lock_until_commit_and_never_publishes_early() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (_, second) = seed(&root);
    let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(["update-ref", p(&root), "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    write!(input, "start\ncreate refs/tags/held {second}\nprepare\n").unwrap();
    input.flush().unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        "start: ok"
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        "prepare: ok"
    );
    assert!(!root.join(".uwgit/tags/held").exists());
    assert!(root.join(".uwgit/write.lock").is_file());
    assert!(!execute(&["show-ref", p(&root)], &[]).status.success());
    assert!(
        !execute(&["update-ref", p(&root), "refs/tags/racer", &second], &[])
            .status
            .success()
    );
    input.write_all(b"commit\n").unwrap();
    input.flush().unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        "commit: ok"
    );
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join(".uwgit/write.lock").exists());
    assert_eq!(ok(&["rev-parse", p(&root), "held"]), second);
}

#[test]
fn prefix_replacements_and_multiple_explicit_transactions_keep_independent_leases() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    success(batch(&root, &format!("start\ncreate refs/heads/topic/sub {second}\ndelete refs/heads/topic {first}\ncommit\nstart\ncreate refs/heads/topic {first}\ndelete refs/heads/topic/sub {second}\nprepare\ncommit\n")));
    assert_eq!(ok(&["rev-parse", p(&root), "topic"]), first);
    assert!(root.join(".uwgit/refs/topic").is_file());
    let output = batch(&root, &format!("start\ncreate refs/tags/committed {first}\ncommit\nstart\nupdate refs/heads/topic {second} {second}\ncommit\n"));
    assert!(!output.status.success());
    assert_eq!(ok(&["rev-parse", p(&root), "committed"]), first);
    assert_eq!(ok(&["rev-parse", p(&root), "topic"]), first);
}

#[test]
fn linked_worktree_branch_protection_rejects_the_entire_batch() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let peer = temp.path("peer");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    ok(&["worktree", p(&root), "add", p(&peer), "topic"]);
    let before = image(&root);
    let peer_before = image(&peer);
    assert!(!batch(
        &root,
        &format!("create refs/tags/unrelated {second}\nupdate refs/heads/topic {second} {first}\n")
    )
    .status
    .success());
    assert_eq!(image(&root), before);
    assert_eq!(image(&peer), peer_before);
}
