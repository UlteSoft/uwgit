use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::Duration;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "uwgit-head-transactions-{}-{}",
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
struct Process(Option<Child>);
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
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
fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn ok(args: &[&str]) -> String {
    String::from_utf8(success(execute(args, &[])))
        .unwrap()
        .trim_end()
        .into()
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn batch(root: &Path, input: &str, partial: bool, nul: bool) -> Output {
    let mut args = vec![
        "update-ref",
        p(root),
        "--stdin",
        "--no-deref",
        "-m",
        "head fixture",
    ];
    if partial {
        args.push("--batch-updates");
    }
    if nul {
        args.push("-z");
    }
    execute(&args, input.as_bytes())
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
fn log(root: &Path, name: &str) -> Vec<Value> {
    let bytes = fs::read(root.join(".uwgit").join(name)).unwrap();
    if name == "reflog" {
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}
fn image(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(root: &Path, path: &Path, result: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, result);
            } else {
                result.push((
                    path.strip_prefix(root).unwrap().into(),
                    fs::read(&path).unwrap(),
                ));
            }
        }
    }
    let mut result = Vec::new();
    walk(root, root, &mut result);
    result.sort();
    result
}

#[test]
fn branch_creation_and_symbolic_head_publish_together_with_correct_logs_and_original_bytes() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    fs::write(root.join("a.wasm"), b"dirty original bytes").unwrap();
    let global = log(&root, "reflog");
    let local = log(&root, "head-reflog.json");
    assert_eq!(success(batch(&root,&format!("start\ncreate refs/heads/reviewed {first}\nsymref-update HEAD refs/heads/reviewed ref refs/heads/main\nprepare\ncommit\n"),false,false)),b"start: ok\nprepare: ok\ncommit: ok\n");
    assert_eq!(
        ok(&["symbolic-ref", p(&root), "HEAD"]),
        "refs/heads/reviewed"
    );
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), first);
    assert_eq!(ok(&["rev-parse", p(&root), "main"]), second);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
    assert_eq!(
        fs::read(root.join("a.wasm")).unwrap(),
        b"dirty original bytes"
    );
    let next = log(&root, "reflog");
    assert_eq!(&next[..global.len()], global);
    assert_eq!(next.len(), global.len() + 2);
    assert_eq!(next.last().unwrap()["reference"], "HEAD");
    let next_local = log(&root, "head-reflog.json");
    assert_eq!(next_local.len(), local.len() + 1);
    assert_eq!(next_local.last().unwrap()["old"], second);
    assert_eq!(next_local.last().unwrap()["new"], first);
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD@{1}"]), second);
    assert!(!root.join(".uwgit/ref-transaction.json").exists());
    ok(&["fsck", p(&root)]);
}

#[test]
fn head_uses_final_destination_tip_while_oid_operands_use_the_original_snapshot() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    let local = log(&root, "head-reflog.json").len();
    success(batch(&root,&format!("create refs/tags/prior HEAD\nupdate refs/heads/topic {second} {first}\nsymref-update HEAD refs/heads/topic ref refs/heads/main\n"),false,false));
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), second);
    assert_eq!(ok(&["rev-parse", p(&root), "prior"]), second);
    let after = log(&root, "head-reflog.json");
    assert_eq!(after.len(), local + 1);
    assert_eq!(after.last().unwrap()["old"], second);
    assert_eq!(after.last().unwrap()["new"], second);
    ok(&["symbolic-ref", p(&root), "HEAD", "refs/heads/main"]);
    assert_eq!(log(&root, "head-reflog.json").len(), local + 2);
    let before = image(&root);
    ok(&["symbolic-ref", p(&root), "HEAD", "refs/heads/main"]);
    assert_eq!(image(&root), before);
}

#[test]
fn ref_and_oid_leases_reject_the_whole_batch_or_only_the_head_as_requested() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    for (suffix, old, reason) in [
        (
            "ref",
            "ref refs/heads/wrong".to_owned(),
            "refs/heads/wrong".to_owned(),
        ),
        ("oid", format!("oid {first}"), first.clone()),
    ] {
        let records = format!(
            "create refs/tags/{suffix} {first}\nsymref-update HEAD refs/heads/topic {old}\n"
        );
        let before = image(&root);
        assert!(!batch(&root, &records, false, false).status.success());
        assert_eq!(image(&root), before);
        let local = log(&root, "head-reflog.json");
        assert_eq!(
            success(batch(&root, &records, true, false)),
            format!("rejected HEAD refs/heads/topic {reason} incorrect old value provided\n")
                .into_bytes()
        );
        assert_eq!(log(&root, "head-reflog.json"), local);
        assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), second);
        assert_eq!(ok(&["rev-parse", p(&root), suffix]), first);
    }
    success(batch(
        &root,
        &format!("symref-update HEAD refs/heads/topic oid {second}\n"),
        false,
        false,
    ));
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), first);
}

#[test]
fn detached_head_oid_leases_reattach_and_reports_distinguish_symbolic_and_commit_identity() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    let report = json(&[
        "update-ref",
        p(&root),
        "--no-deref",
        "HEAD",
        &first,
        &second,
    ]);
    assert_eq!(report["old_kind"], "symbolic");
    assert_eq!(report["old"], "refs/heads/main");
    assert_eq!(report["new_kind"], "commit");
    assert_eq!(report["new"], first);
    assert_eq!(report["new_commit"], first);
    assert_eq!(ok(&["rev-parse", p(&root), "main"]), second);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    let image_before = image(&root);
    assert!(
        !batch(&root, "symref-verify HEAD refs/heads/main\n", false, false)
            .status
            .success()
    );
    assert_eq!(image(&root), image_before);
    assert!(String::from_utf8(success(batch(
        &root,
        "symref-update HEAD refs/heads/topic ref refs/heads/main\n",
        true,
        false
    )))
    .unwrap()
    .contains("expected symref but found regular ref"));
    success(batch(
        &root,
        &format!("symref-update HEAD refs/heads/topic oid {first}\n"),
        false,
        false,
    ));
    assert_eq!(ok(&["symbolic-ref", p(&root), "HEAD"]), "refs/heads/topic");
}

#[test]
fn verify_noop_and_unborn_head_use_real_absence_without_synthetic_commits() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (_, second) = seed(&root);
    let before = image(&root);
    success(batch(
        &root,
        "symref-verify HEAD refs/heads/main\n",
        false,
        false,
    ));
    assert_eq!(image(&root), before);
    success(batch(
        &root,
        &format!("verify HEAD {second}\n"),
        false,
        false,
    ));
    assert_eq!(image(&root), before);
    success(batch(
        &root,
        "symref-update HEAD refs/heads/main ref refs/heads/main\n",
        false,
        false,
    ));
    assert_eq!(image(&root), before);
    assert!(!batch(&root, "symref-verify HEAD\n", false, false)
        .status
        .success());
    assert_eq!(image(&root), before);
    let objects = fs::read_dir(root.join(".uwgit/objects")).unwrap().count();
    ok(&["symbolic-ref", p(&root), "HEAD", "refs/heads/unborn"]);
    success(batch(
        &root,
        &format!("verify HEAD {}\n", "0".repeat(64)),
        false,
        false,
    ));
    success(batch(
        &root,
        "symref-update HEAD refs/heads/another ref refs/heads/unborn\n",
        false,
        false,
    ));
    let last = log(&root, "head-reflog.json").pop().unwrap();
    assert!(last["old"].is_null() && last["new"].is_null());
    assert_eq!(
        fs::read_dir(root.join(".uwgit/objects")).unwrap().count(),
        objects
    );
    assert!(!execute(&["rev-parse", p(&root), "HEAD"], &[])
        .status
        .success());
    success(batch(
        &root,
        &format!(
            "symref-update HEAD refs/heads/main oid {}\n",
            "0".repeat(64)
        ),
        false,
        false,
    ));
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), second);
}

#[test]
fn nul_old_target_modes_and_one_command_no_deref_options_are_validated() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "topic", &first]);
    success(batch(
        &root,
        "symref-update HEAD\0refs/heads/topic\0ref\0refs/heads/main\0",
        false,
        true,
    ));
    success(batch(
        &root,
        "symref-verify HEAD\0refs/heads/topic\0",
        false,
        true,
    ));
    success(batch(
        &root,
        "symref-update HEAD\0refs/heads/main\0\0\0",
        false,
        true,
    ));
    let records = "option no-deref\nverify refs/tags/absent\nsymref-verify HEAD refs/heads/main\n";
    let before = image(&root);
    assert!(
        !execute(&["update-ref", p(&root), "--stdin"], records.as_bytes())
            .status
            .success()
    );
    assert_eq!(image(&root), before);
    success(execute(
        &["update-ref", p(&root), "--stdin"],
        b"option no-deref\nsymref-verify HEAD refs/heads/main\n",
    ));
    assert!(!execute(
        &["update-ref", p(&root), "--stdin", "--no-deref", "--deref"],
        b"symref-verify HEAD refs/heads/main\n"
    )
    .status
    .success());
    success(execute(
        &["update-ref", p(&root), "--stdin", "--deref", "--no-deref"],
        b"symref-verify HEAD refs/heads/main\n",
    ));
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), second);
}

#[test]
fn malformed_symbolic_modes_targets_and_framing_never_publish_any_queued_updates() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (_, second) = seed(&root);
    for tail in [
        "symref-update HEAD\n",
        "symref-update HEAD refs/heads/topic ref\n",
        "symref-update HEAD refs/heads/topic unknown refs/heads/main\n",
        "symref-update HEAD refs/tags/not-a-head\n",
        "symref-update HEAD HEAD\n",
        "symref-update HEAD refs/heads/a/../escape\n",
        "symref-verify HEAD refs/heads/main extra\n",
        "symref-update refs/heads/alias refs/heads/main\n",
        "symref-create HEAD refs/heads/topic\n",
        "symref-delete HEAD\n",
    ] {
        let before = image(&root);
        let output = batch(
            &root,
            &format!("create refs/tags/queued {second}\n{tail}"),
            true,
            false,
        );
        assert!(!output.status.success(), "{tail}");
        assert_eq!(image(&root), before, "{tail}");
    }
    let before = image(&root);
    assert!(!batch(
        &root,
        "symref-update HEAD\0refs/heads/topic\0ref\0",
        true,
        true
    )
    .status
    .success());
    assert_eq!(image(&root), before);
    assert!(!execute(
        &["update-ref", p(&root), "--stdin"],
        b"start\nsymref-update HEAD refs/heads/topic\n"
    )
    .status
    .success());
    assert_eq!(image(&root), before);
}

#[test]
fn head_alias_duplicates_and_required_head_deletion_keep_the_native_repository_valid() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let (first, second) = seed(&root);
    let before = image(&root);
    let records = format!("verify HEAD {second}\nverify refs/heads/main {second}\n");
    assert!(
        !execute(&["update-ref", p(&root), "--stdin"], records.as_bytes())
            .status
            .success()
    );
    assert_eq!(image(&root), before);
    success(batch(&root, &records, false, false));
    assert_eq!(image(&root), before);
    assert!(!execute(
        &["update-ref", p(&root), "--no-deref", "-d", "HEAD", &second],
        &[]
    )
    .status
    .success());
    assert_eq!(image(&root), before);
    let output = success(batch(
        &root,
        &format!("create refs/tags/accepted {first}\ndelete HEAD {second}\n"),
        true,
        false,
    ));
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("native HEAD cannot be deleted"));
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), second);
    assert_eq!(ok(&["rev-parse", p(&root), "accepted"]), first);
    assert!(
        !execute(&["update-ref", p(&root), "HEAD", &first, &second], &[])
            .status
            .success()
    );
}

#[test]
fn linked_worktree_head_registry_and_local_logs_change_together_without_touching_peers() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let peer = temp.path("peer");
    let (first, second) = seed(&root);
    ok(&["branch", p(&root), "peer", &first]);
    ok(&["branch", p(&root), "topic", &second]);
    ok(&["worktree", p(&root), "add", p(&peer), "peer"]);
    let primary_log = fs::read(root.join(".uwgit/head-reflog.json")).unwrap();
    let index = fs::read(peer.join(".uwgit/index")).unwrap();
    let bytes = fs::read(peer.join("a.wasm")).unwrap();
    success(batch(
        &peer,
        "symref-update HEAD refs/heads/topic ref refs/heads/peer\n",
        false,
        false,
    ));
    assert_eq!(ok(&["symbolic-ref", p(&peer), "HEAD"]), "refs/heads/topic");
    assert_eq!(ok(&["rev-parse", p(&peer), "HEAD"]), second);
    assert_eq!(
        fs::read(root.join(".uwgit/head-reflog.json")).unwrap(),
        primary_log
    );
    assert_eq!(fs::read(peer.join(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(peer.join("a.wasm")).unwrap(), bytes);
    let worktrees = json(&["worktree", p(&root), "list"]);
    let peer_row = worktrees["worktrees"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == p(&peer))
        .unwrap();
    assert_eq!(peer_row["branch"], "topic");
    let primary_before = image(&root);
    assert!(!batch(
        &root,
        "symref-update HEAD refs/heads/topic ref refs/heads/main\n",
        false,
        false
    )
    .status
    .success());
    assert_eq!(image(&root), primary_before);
    let output=success(batch(&peer,&format!("create refs/tags/peer-result {first}\nsymref-update HEAD refs/heads/main ref refs/heads/topic\n"),true,false));
    assert!(String::from_utf8(output)
        .unwrap()
        .contains("reference is checked out in a worktree"));
    assert_eq!(ok(&["symbolic-ref", p(&peer), "HEAD"]), "refs/heads/topic");
    assert_eq!(ok(&["symbolic-ref", p(&root), "HEAD"]), "refs/heads/main");
}

#[test]
fn prepared_head_batch_holds_the_writer_lock_and_abort_or_eof_preserves_every_byte() {
    for ending in ["commit", "abort", "eof"] {
        let temp = Temp::new();
        let root = temp.path("repo");
        let (first, _) = seed(&root);
        let before = image(&root);
        let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
            .args(["update-ref", p(&root), "--stdin", "--no-deref"])
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
        write!(input,"start\ncreate refs/heads/reviewed {first}\nsymref-update HEAD refs/heads/reviewed ref refs/heads/main\nprepare\n").unwrap();
        input.flush().unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            "start: ok"
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            "prepare: ok"
        );
        assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), b"main\n");
        assert!(!root.join(".uwgit/refs/reviewed").exists());
        assert!(!root.join(".uwgit/ref-transaction.json").exists());
        assert!(!execute(&["show-ref", p(&root)], &[]).status.success());
        if ending != "eof" {
            writeln!(input, "{ending}").unwrap();
            input.flush().unwrap();
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(10)).unwrap(),
                format!("{ending}: ok")
            );
        }
        drop(input);
        let output = process.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if ending == "commit" {
            assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), first);
        } else {
            assert_eq!(image(&root), before);
        }
    }
}
