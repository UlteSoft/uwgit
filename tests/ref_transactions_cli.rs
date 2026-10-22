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
fn partial(root: &Path, input: &str, nul: bool) -> Output {
    let mut args = vec![
        "update-ref",
        p(root),
        "--stdin",
        "--batch-updates",
        "-m",
        "partial fixture",
    ];
    if nul {
        args.push("-z");
    }
    execute(&args, input.as_bytes())
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

#[test]
fn partial_batches_publish_only_accepted_refs_and_preserve_original_wasm_work_and_index() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    ok(&["tag", p(&root), "obsolete", &first]);
    let original = image(&root);
    let records = format!("update refs/heads/topic {second} {first}\ncreate refs/tags/release topic\ndelete refs/tags/obsolete {first}\nupdate refs/heads/missing {first} {second}\nverify refs/heads/main {second}\n");
    assert!(!batch(&root, &records).status.success());
    assert_eq!(image(&root), original);
    assert_eq!(
        success(partial(&root, &records, false)),
        format!("rejected refs/heads/missing {first} {second} reference does not exist\n")
            .into_bytes()
    );
    assert_eq!(ok(&["rev-parse", p(&root), "topic"]), second);
    assert_eq!(ok(&["rev-parse", p(&root), "release"]), first);
    assert!(!root.join(".uwgit/tags/obsolete").exists());
    for path in [".uwgit/index", "a.wasm", ".uwgit/HEAD"] {
        assert_eq!(
            fs::read(root.join(path)).unwrap(),
            original
                .iter()
                .find(|(name, _)| name == Path::new(path))
                .unwrap()
                .1
        );
    }
    let log = fs::read_to_string(root.join(".uwgit/reflog")).unwrap();
    let changes = log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| entry["operation"] == "partial fixture")
        .collect::<Vec<_>>();
    assert_eq!(changes.len(), 3);
    assert!(changes
        .iter()
        .all(|entry| entry["reference"] != "refs/heads/missing"));
    assert!(!root.join(".uwgit/ref-transaction.json").exists());
    ok(&["fsck", p(&root)]);
}

#[test]
fn semantic_rejections_use_resolved_native_ids_and_stable_reasons() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    let tree: Value = serde_json::from_str(&ok(&["ls-tree", p(&root), "HEAD"])).unwrap();
    let blob = tree["entries"][0]["object_id"].as_str().unwrap();
    let zero = "0".repeat(64);
    let absent = "f".repeat(64);
    let records = format!("create refs/tags/accepted HEAD\nupdate refs/heads/topic {second} {second}\ncreate refs/heads/main HEAD\ncreate refs/heads/bad-type {blob}\ncreate refs/heads/absent-object {absent}\nverify refs/heads/topic-check\nverify refs/heads/main HEAD\n");
    let expected = format!("rejected refs/heads/absent-object {absent} {zero} invalid new value provided\nrejected refs/heads/bad-type {blob} {zero} invalid new value provided\nrejected refs/heads/main {second} {zero} reference already exists\nrejected refs/heads/topic {second} {second} incorrect old value provided\n");
    // Duplicate refs remain a framing error, including a create/verify pair.
    let before = image(&root);
    assert!(!partial(&root, &records, false).status.success());
    assert_eq!(image(&root), before);
    let records = records.replace(
        "verify refs/heads/main HEAD\n",
        "verify refs/tags/missing\n",
    );
    assert_eq!(
        success(partial(&root, &records, false)),
        expected.into_bytes()
    );
    assert_eq!(ok(&["rev-parse", p(&root), "accepted"]), second);
    assert_eq!(ok(&["rev-parse", p(&root), "topic"]), first);
}

#[test]
fn all_rejected_or_noop_batches_change_no_files_and_report_successful_processing() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    let zero = "0".repeat(64);
    let before = image(&root);
    assert_eq!(success(partial(&root, &format!("verify refs/heads/main\nupdate refs/heads/missing {first} {second}\n"), false)), format!("rejected refs/heads/main {zero} {zero} reference already exists\nrejected refs/heads/missing {first} {second} reference does not exist\n").into_bytes());
    assert_eq!(image(&root), before);
    assert!(success(partial(
        &root,
        &format!("verify refs/heads/main {second}\nverify refs/tags/absent\n"),
        false
    ))
    .is_empty());
    assert_eq!(image(&root), before);
}

#[test]
fn batch_mode_keeps_syntax_revision_and_framing_failures_fatal_before_publication() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (_, second) = seed(&root);
    let zero = "0".repeat(64);
    for tail in [
        format!("create refs/heads/bad/../name {second}\n"),
        "create refs/tags/revision no-such-revision\n".into(),
        format!("create refs/tags/zero {zero}\n"),
        format!("delete refs/tags/zero {zero}\n"),
        "symref-update HEAD refs/heads/new\n".into(),
        format!("create refs/tags/accepted {second}\n"),
        "option unknown\n".into(),
        "prepare\nunknown-command\n".into(),
    ] {
        let before = image(&root);
        assert!(
            !partial(
                &root,
                &format!("create refs/tags/accepted {second}\n{tail}"),
                false
            )
            .status
            .success(),
            "{tail}"
        );
        assert_eq!(image(&root), before, "{tail}");
    }
    let before = image(&root);
    assert!(!execute(
        &["update-ref", p(&root), "--stdin", "--batch-updates"],
        &[0xff, b'\n']
    )
    .status
    .success());
    assert!(!partial(&root, "create refs/tags/incomplete\0", true)
        .status
        .success());
    assert!(!execute(
        &[
            "update-ref",
            p(&root),
            "--batch-updates",
            "refs/tags/x",
            &second
        ],
        &[]
    )
    .status
    .success());
    assert!(
        !execute(&["update-ref", p(&root), "-z", "refs/tags/x", &second], &[])
            .status
            .success()
    );
    assert_eq!(image(&root), before);
}

#[test]
fn partial_prefix_conflicts_reject_all_new_competitors_and_respect_rejected_deletions() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    let zero = "0".repeat(64);
    ok(&["branch", p(&root), "existing/child", &first]);
    for reverse in [false, true] {
        let new_refs = if reverse {
            format!("create refs/heads/new/child {first}\ncreate refs/heads/new {second}\n")
        } else {
            format!("create refs/heads/new {second}\ncreate refs/heads/new/child {first}\n")
        };
        let records = format!("{new_refs}update refs/heads/existing/child {second} {first}\ncreate refs/heads/existing {first}\n");
        let expected = format!("rejected refs/heads/existing {first} {zero} refname conflict\nrejected refs/heads/new {second} {zero} refname conflict\nrejected refs/heads/new/child {first} {zero} refname conflict\n");
        if reverse {
            ok(&[
                "update-ref",
                p(&root),
                "refs/heads/existing/child",
                &first,
                &second,
            ]);
        }
        assert_eq!(
            success(partial(&root, &records, false)),
            expected.into_bytes()
        );
        assert_eq!(ok(&["rev-parse", p(&root), "existing/child"]), second);
    }
    let expected = format!("rejected refs/heads/existing {first} {zero} refname conflict\nrejected refs/heads/existing/child {zero} {first} incorrect old value provided\n");
    assert_eq!(success(partial(&root, &format!("create refs/tags/accepted {second}\ncreate refs/heads/existing {first}\ndelete refs/heads/existing/child {first}\n"), false)), expected.into_bytes());
    assert!(success(partial(
        &root,
        &format!("create refs/heads/existing {first}\ndelete refs/heads/existing/child {second}\n"),
        false
    ))
    .is_empty());
    assert_eq!(ok(&["rev-parse", p(&root), "existing"]), first);
}

#[test]
fn prepare_without_start_aborts_on_eof_in_both_modes_and_suppresses_rejections() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    for allow_failures in [false, true] {
        for ending in ["prepare\n", "prepare\nabort\n"] {
            let before = image(&root);
            let rejected = if allow_failures {
                format!("update refs/heads/missing {first} {second}\n")
            } else {
                String::new()
            };
            let records = format!("create refs/tags/accepted {second}\n{rejected}{ending}");
            let output = success(if allow_failures {
                partial(&root, &records, false)
            } else {
                batch(&root, &records)
            });
            assert_eq!(
                output,
                if ending.ends_with("abort\n") {
                    b"prepare: ok\nabort: ok\n".as_slice()
                } else {
                    b"prepare: ok\n".as_slice()
                }
            );
            assert_eq!(image(&root), before);
        }
    }
}

#[test]
fn corruption_and_system_failures_are_never_downgraded_to_partial_rejections() {
    for damage in ["registry", "object", "journal", "lock", "reflog"] {
        let temp = Temp::new();
        let root = temp.path("repo");
        let (_, second) = seed(&root);
        match damage {
            "registry" => {
                fs::write(root.join(".uwgit/worktrees.json"), b"corrupt registry").unwrap()
            }
            "object" => {
                fs::write(root.join(".uwgit/objects").join(&second), b"corrupt object").unwrap()
            }
            "journal" => fs::create_dir(root.join(".uwgit/ref-transaction.json")).unwrap(),
            "lock" => fs::write(root.join(".uwgit/write.lock"), b"external writer\n").unwrap(),
            _ => {
                fs::remove_file(root.join(".uwgit/reflog")).unwrap();
                fs::create_dir(root.join(".uwgit/reflog")).unwrap();
            }
        }
        let before = image(&root);
        let output = partial(
            &root,
            &format!(
                "create refs/tags/accepted {second}\ncreate refs/heads/invalid {}\n",
                "f".repeat(64)
            ),
            false,
        );
        assert!(!output.status.success(), "{damage}");
        assert!(output.stdout.is_empty());
        assert_eq!(image(&root), before, "{damage}");
    }
}

#[test]
fn partial_worktree_protection_rejects_occupied_refs_but_keeps_unrelated_successes() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let peer = temp.path("peer");
    let (first, second) = seed(&root);
    let zero = "0".repeat(64);
    ok(&["branch", p(&root), "topic", &first]);
    ok(&["worktree", p(&root), "add", p(&peer), "topic"]);
    let peer_index = fs::read(peer.join(".uwgit/index")).unwrap();
    let peer_bytes = fs::read(peer.join("a.wasm")).unwrap();
    assert_eq!(success(partial(&root, &format!("create refs/tags/accepted {second}\nupdate refs/heads/topic {second} {first}\nupdate refs/heads/main {first} {second}\n"), false)), format!("rejected refs/heads/main {first} {second} reference is checked out in a worktree\nrejected refs/heads/topic {second} {first} reference is checked out in a worktree\n").into_bytes());
    assert_eq!(ok(&["rev-parse", p(&peer), "HEAD"]), first);
    assert_eq!(fs::read(peer.join(".uwgit/index")).unwrap(), peer_index);
    assert_eq!(fs::read(peer.join("a.wasm")).unwrap(), peer_bytes);
    assert_eq!(ok(&["rev-parse", p(&root), "accepted"]), second);
    assert_eq!(
        success(partial(
            &peer,
            &format!("delete refs/heads/main {second}\ncreate refs/tags/peer-accepted {first}\n"),
            false
        )),
        format!(
            "rejected refs/heads/main {zero} {second} reference is checked out in a worktree\n"
        )
        .into_bytes()
    );
}

#[test]
fn short_batch_flag_nul_rejections_and_last_option_wins_have_real_effects() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    let records = format!(
        "create refs/tags/accepted\0{second}\0update refs/heads/missing\0{first}\0{second}\0"
    );
    assert_eq!(
        success(execute(
            &["update-ref", p(&root), "--stdin", "-0", "-z"],
            records.as_bytes()
        )),
        format!("rejected refs/heads/missing {first} {second} reference does not exist\n")
            .into_bytes()
    );
    let records =
        format!("create refs/tags/second {second}\nupdate refs/heads/missing {first} {second}\n");
    let before = image(&root);
    assert!(!execute(
        &[
            "update-ref",
            p(&root),
            "--stdin",
            "--batch-updates",
            "--no-batch-updates"
        ],
        records.as_bytes()
    )
    .status
    .success());
    assert_eq!(image(&root), before);
    success(execute(
        &[
            "update-ref",
            p(&root),
            "--stdin",
            "--no-batch-updates",
            "--batch-updates",
        ],
        records.as_bytes(),
    ));
    assert_eq!(ok(&["rev-parse", p(&root), "second"]), second);
}

#[test]
fn partial_prepare_holds_the_shared_lock_and_reports_rejections_only_after_commit() {
    struct Process(Option<std::process::Child>);
    impl Drop for Process {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    for ending in ["commit", "abort", "eof"] {
        let temp = Temp::new();
        let root = temp.path("repo");
        let (first, second) = seed(&root);
        let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
            .args(["update-ref", p(&root), "--stdin", "--batch-updates"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut process = Process(Some(child));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        write!(input, "start\ncreate refs/tags/accepted {second}\nupdate refs/heads/missing {first} {second}\nprepare\n").unwrap();
        input.flush().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            "start: ok"
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            "prepare: ok"
        );
        assert!(rx.try_recv().is_err());
        assert!(root.join(".uwgit/write.lock").is_file());
        assert!(!root.join(".uwgit/tags/accepted").exists());
        assert!(!execute(&["show-ref", p(&root)], &[]).status.success());
        if ending != "eof" {
            writeln!(input, "{ending}").unwrap();
            input.flush().unwrap();
        }
        if ending == "commit" {
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(10)).unwrap(),
                format!("rejected refs/heads/missing {first} {second} reference does not exist")
            );
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(10)).unwrap(),
                "commit: ok"
            );
        } else if ending == "abort" {
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(10)).unwrap(),
                "abort: ok"
            );
        }
        drop(input);
        let output = process.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!root.join(".uwgit/write.lock").exists());
        assert!(!root.join(".uwgit/ref-transaction.json").exists());
        assert_eq!(
            root.join(".uwgit/tags/accepted").exists(),
            ending == "commit"
        );
        assert!(rx.recv_timeout(Duration::from_secs(10)).is_err());
    }
}

#[test]
fn start_can_adopt_queued_updates_and_requires_an_explicit_commit() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (_, second) = seed(&root);
    for allow_failures in [false, true] {
        let before = image(&root);
        let records = format!("create refs/tags/adopted {second}\nstart\n");
        let output = success(if allow_failures {
            partial(&root, &records, false)
        } else {
            batch(&root, &records)
        });
        assert_eq!(output, b"start: ok\n");
        assert_eq!(image(&root), before);
    }
    assert_eq!(
        success(partial(
            &root,
            &format!("create refs/tags/adopted {second}\nstart\nprepare\ncommit\n"),
            false
        )),
        b"start: ok\nprepare: ok\ncommit: ok\n"
    );
    assert_eq!(ok(&["rev-parse", p(&root), "adopted"]), second);
}
