use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-plumbing-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        ok(&["init", path(&root)], None);
        Self(root)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}
fn execute(args: &[&str], input: Option<&[u8]>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
fn ok(args: &[&str], input: Option<&[u8]>) -> String {
    let output = execute(args, input);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}
fn fail(args: &[&str], input: Option<&[u8]>) {
    let output = execute(args, input);
    assert!(!output.status.success(), "unexpected success: {args:?}");
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}
fn files(root: &Path) -> usize {
    fs::read_dir(root.join(".uwgit/objects")).unwrap().count()
}
fn blob(root: &Path, value: u8) -> String {
    ok(
        &["hash-object", path(root), "-w", "--stdin"],
        Some(&wasm(value)),
    )
}
fn tree(root: &Path, blob: &str) -> String {
    ok(
        &["mktree", path(root)],
        Some(format!("100644 wasm {blob}\ta.wasm\n").as_bytes()),
    )
}
fn commit(root: &Path, tree: &str, parent: Option<&str>, message: &str) -> String {
    let mut args = vec!["commit-tree", path(root), tree, "-m", message];
    if let Some(parent) = parent {
        args.extend(["-p", parent]);
    }
    ok(&args, None)
}

#[test]
fn object_hashes_payloads_and_graphs_roundtrip_without_touching_head() {
    let temp = Temp::new();
    let root = &temp.0;
    let bytes = wasm(7);
    let dry = ok(&["hash-object", path(root), "--stdin"], Some(&bytes));
    let mut envelope = b"UWGO\0\0\0\x01".to_vec();
    envelope.push(1);
    envelope.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    envelope.extend_from_slice(&bytes);
    assert_eq!(dry, format!("{:x}", Sha256::digest(&envelope)));
    assert_eq!(files(root), 0);
    let blob = blob(root, 7);
    assert_eq!(blob, dry);
    assert_eq!(
        fs::read(root.join(".uwgit/objects").join(&blob)).unwrap(),
        envelope
    );
    let tree = tree(root, &blob);
    let id = commit(root, &tree, None, "first");
    assert_eq!(ok(&["cat-file", path(root), "-t", &tree], None), "tree");
    assert_eq!(ok(&["cat-file", path(root), "-t", &id], None), "commit");
    let exported = root.join("copy.wasm");
    ok(
        &["cat-file", path(root), &blob, "--output", path(&exported)],
        None,
    );
    assert_eq!(fs::read(exported).unwrap(), bytes);
    assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), b"main\n");
    assert!(!root.join(".uwgit/index").exists());
    assert_eq!(fs::read_dir(root.join(".uwgit/refs")).unwrap().count(), 0);
    ok(&["fsck", path(root)], None);
}

#[test]
fn tree_and_commit_rejections_publish_nothing() {
    let temp = Temp::new();
    let root = &temp.0;
    let blob = blob(root, 1);
    let before = files(root);
    for record in [
        format!("100644 wasm {blob}\t../outside\n"),
        format!("100644 tree {blob}\ta\n"),
        format!("100644 wasm {blob}\ta\n100644 wasm {blob}\ta\n"),
        format!("100644 wasm {}\ta\n", "f".repeat(64)),
        format!("100644 wasm {blob}\ta\n100644 wasm {blob}\ta/b\n"),
    ] {
        fail(&["mktree", path(root)], Some(record.as_bytes()));
        assert_eq!(files(root), before);
    }
    fail(
        &["hash-object", path(root), "-w", "--stdin"],
        Some(b"not a Wasm file"),
    );
    fail(&["commit-tree", path(root), &blob, "-m", "bad"], None);
    let tree = tree(root, &blob);
    let first = commit(root, &tree, None, "first");
    let before = files(root);
    fail(
        &[
            "commit-tree",
            path(root),
            &tree,
            "-m",
            "duplicate",
            "-p",
            &first,
            "-p",
            &first,
        ],
        None,
    );
    assert_eq!(files(root), before);
}

#[test]
fn ref_leases_creation_update_deletion_and_checked_out_protection() {
    let temp = Temp::new();
    let root = &temp.0;
    let blob = blob(root, 1);
    let tree = tree(root, &blob);
    let first = commit(root, &tree, None, "first");
    let second = commit(root, &tree, Some(&first), "second");
    let zero = "0".repeat(64);
    ok(
        &["update-ref", path(root), "refs/heads/topic", &first, &zero],
        None,
    );
    let before = fs::read(root.join(".uwgit/reflog")).unwrap();
    fail(
        &["update-ref", path(root), "refs/heads/topic", &second, &zero],
        None,
    );
    assert_eq!(fs::read(root.join(".uwgit/reflog")).unwrap(), before);
    ok(
        &[
            "update-ref",
            path(root),
            "refs/heads/topic",
            &second,
            &first,
        ],
        None,
    );
    fail(
        &["update-ref", path(root), "refs/heads/main", &first, &zero],
        None,
    );
    fail(
        &["update-ref", path(root), "-d", "refs/heads/topic", &first],
        None,
    );
    ok(
        &["update-ref", path(root), "-d", "refs/heads/topic", &second],
        None,
    );
    assert_eq!(fs::read_dir(root.join(".uwgit/refs")).unwrap().count(), 0);
    ok(&["fsck", path(root)], None);
}

#[test]
fn read_and_write_tree_leave_work_bytes_and_branch_unchanged() {
    let temp = Temp::new();
    let root = &temp.0;
    fs::write(root.join("a.wasm"), wasm(1)).unwrap();
    ok(&["add", path(root), "a.wasm"], None);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    let tree = ok(&["write-tree", path(root)], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    fs::write(root.join("a.wasm"), b"dirty work bytes").unwrap();
    ok(&["read-tree", path(root), "--empty"], None);
    assert_eq!(ok(&["ls-files", path(root)], None), "");
    ok(&["read-tree", path(root), &tree], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), b"dirty work bytes");
    assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), b"main\n");
}

#[test]
fn revision_walk_ranges_first_parent_reverse_and_limits_follow_the_actual_dag() {
    let temp = Temp::new();
    let root = &temp.0;
    let blob = blob(root, 1);
    let tree = tree(root, &blob);
    let first = commit(root, &tree, None, "first");
    let left = commit(root, &tree, Some(&first), "left");
    let right = commit(root, &tree, Some(&first), "right");
    let merge = ok(
        &[
            "commit-tree",
            path(root),
            &tree,
            "-p",
            &left,
            "-p",
            &right,
            "-m",
            "merge",
        ],
        None,
    );
    let rows = ok(&["rev-list", path(root), &merge], None);
    assert_eq!(rows.lines().next(), Some(merge.as_str()));
    assert_eq!(rows.lines().last(), Some(first.as_str()));
    assert_eq!(rows.lines().count(), 4);
    assert_eq!(
        ok(&["rev-list", path(root), "--first-parent", &merge], None),
        format!("{merge}\n{left}\n{first}")
    );
    assert_eq!(
        ok(
            &[
                "rev-list",
                path(root),
                "--reverse",
                "-n",
                "2",
                "--first-parent",
                &merge
            ],
            None
        ),
        format!("{left}\n{merge}")
    );
    assert_eq!(
        ok(
            &[
                "rev-list",
                path(root),
                "--count",
                &format!("{first}..{merge}")
            ],
            None
        ),
        "3"
    );
    assert_eq!(ok(&["rev-list", path(root), "--count", "--all"], None), "0");
}

#[test]
fn malformed_options_help_literal_messages_and_locks_have_no_side_effects() {
    for command in [
        "hash-object",
        "mktree",
        "write-tree",
        "read-tree",
        "commit-tree",
        "update-ref",
        "rev-list",
    ] {
        ok(&[command, "--help"], None);
    }
    let temp = Temp::new();
    let root = &temp.0;
    let blob = blob(root, 1);
    let tree = tree(root, &blob);
    let id = commit(root, &tree, None, "--help");
    let value: Value =
        serde_json::from_str(&ok(&["cat-file", path(root), "-p", &id], None)).unwrap();
    assert_eq!(value["message"], "--help");
    let before = files(root);
    fs::write(root.join(".uwgit/write.lock"), b"held").unwrap();
    fail(
        &["hash-object", path(root), "-w", "--stdin"],
        Some(&wasm(9)),
    );
    assert_eq!(files(root), before);
    fs::remove_file(root.join(".uwgit/write.lock")).unwrap();
    fail(&["rev-list", path(root), "--invented"], None);
    fail(&["read-tree", path(root), "--empty", &tree], None);
    assert_eq!(files(root), before);
}
