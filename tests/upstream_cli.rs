//! Fixed explicit local upstream metadata workflows. No fuzz or guest execution.
//! The SSH shim runs the real framed stdio service with fixtures only in /tmp.
#![cfg(unix)]

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const UNKNOWN: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    service: PathBuf,
    local: PathBuf,
    shim: PathBuf,
    url: String,
}
fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}
fn command(args: &[&str]) -> Command {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    child
        .args(args)
        .env_remove("UWGIT_REMOTE_TOKEN")
        .env_remove("UWGIT_SSH_PROGRAM")
        .env_remove("UWGIT_REMOTE_PROGRAM");
    child
}
fn successful(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn run(args: &[&str]) -> String {
    successful(command(args).output().unwrap())
}
impl Fixture {
    fn new() -> Self {
        let root = Path::new("/tmp").join(format!(
            "uwgit-upstream-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("producer");
        let service = root.join("upstream.git");
        let local = root.join("local");
        run(&["init", path(&source)]);
        fs::write(source.join("a.wasm"), HEADER).unwrap();
        run(&["add", path(&source), "a.wasm"]);
        run(&["commit", path(&source), "-m", "base"]);
        run(&["branch", path(&source), "feature"]);
        // Local clone deliberately creates neither remote nor upstream config.
        run(&["clone", path(&source), path(&local)]);
        run(&["clone", path(&source), path(&service)]);
        let shim = root.join("ssh-shim");
        fs::write(&shim, b"#!/bin/sh\nset -eu\nexec \"$UWGIT_UPSTREAM_TEST_BINARY\" server --stdio --root \"$UWGIT_UPSTREAM_TEST_ROOT\"\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
        let url = format!("ssh://test@localhost{}/upstream.git", root.display());
        let fixture = Self {
            root,
            source,
            service,
            local,
            shim,
            url,
        };
        fixture.ok(&["remote", fixture.repo(), "add", "origin", &fixture.url]);
        fixture
    }
    fn repo(&self) -> &str {
        path(&self.local)
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut child = command(args);
        child
            .env("UWGIT_SSH_PROGRAM", &self.shim)
            .env("UWGIT_UPSTREAM_TEST_BINARY", env!("CARGO_BIN_EXE_wasm-git"))
            .env("UWGIT_UPSTREAM_TEST_ROOT", &self.root);
        child
    }
    fn ok(&self, args: &[&str]) -> String {
        successful(self.command(args).output().unwrap())
    }
    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.ok(args)).unwrap()
    }
    fn fetch(&self) {
        self.ok(&["fetch", self.repo(), "origin"]);
    }
    fn head(&self, revision: &str) -> String {
        self.ok(&["rev-parse", self.repo(), revision]).trim().into()
    }
    fn publish(&self, branch: &str) {
        let bundle = self.root.join(format!(
            "publication-{}.bundle",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        run(&["bundle", path(&self.source), path(&bundle)]);
        run(&["unbundle", path(&self.service), path(&bundle), branch]);
    }
    fn reject(&self, args: &[&str]) {
        let before = snapshot(&self.local);
        let output = self.command(args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            snapshot(&self.local),
            before,
            "rejection changed local state: {args:?}"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, directory: &Path, output: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let file = entry.path();
            let relative = file.strip_prefix(root).unwrap().to_owned();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                output.insert(relative, Entry::Symlink(fs::read_link(file).unwrap()));
            } else if kind.is_dir() {
                output.insert(relative, Entry::Directory);
                visit(root, &file, output);
            } else {
                assert!(kind.is_file());
                output.insert(relative, Entry::File(fs::read(file).unwrap()));
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}
fn branch<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["branches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap()
}

#[test]
fn explicit_upstream_forms_resolve_fetched_tips_and_preserve_dirty_index_and_worktree() {
    let fixture = Fixture::new();
    fixture.fetch();
    fixture.reject(&["rev-parse", fixture.repo(), "@{upstream}"]);
    fixture.ok(&[
        "restore",
        fixture.repo(),
        "--source",
        "HEAD",
        "--staged",
        "--worktree",
    ]);
    fs::write(fixture.local.join("a.wasm"), UNKNOWN).unwrap();
    fixture.ok(&["add", fixture.repo(), "a.wasm"]);
    fs::write(fixture.local.join("a.wasm"), b"unfinished editor bytes").unwrap();
    fs::write(fixture.local.join("private.txt"), b"untracked data").unwrap();
    let plain = fixture.ok(&["branch", fixture.repo()]);
    let head = fixture.head("HEAD");
    let index = fs::read(fixture.local.join(".uwgit/index")).unwrap();
    let working = fs::read(fixture.local.join("a.wasm")).unwrap();
    fixture.ok(&["branch", fixture.repo(), "-u", "origin/feature"]);
    assert_eq!(fixture.head("@{upstream}"), fixture.head("origin/feature"));
    assert_eq!(fixture.head("@{u}"), fixture.head("origin/feature"));
    assert_eq!(fixture.head("HEAD@{u}"), fixture.head("origin/feature"));
    assert_eq!(
        fixture.head("main@{upstream}"),
        fixture.head("origin/feature")
    );
    let report = fixture.json(&["branch", fixture.repo(), "-vv"]);
    let main = branch(&report, "main");
    assert_eq!(main["current"], true);
    assert_eq!(main["commit"], head);
    assert_eq!(main["upstream"]["remote"], "origin");
    assert_eq!(main["upstream"]["branch"], "feature");
    assert_eq!(main["upstream"]["tracking"], "origin/feature");
    assert_eq!(main["upstream"]["status"], "available");
    assert_eq!(main["upstream"]["tip"], fixture.head("origin/feature"));
    assert!(branch(&report, "feature")["upstream"].is_null());
    fixture.ok(&[
        "branch",
        fixture.repo(),
        "--set-upstream-to",
        "origin/main",
        "feature",
    ]);
    assert_eq!(fixture.head("feature@{u}"), fixture.head("origin/main"));
    fixture.ok(&["branch", fixture.repo(), "--set-upstream-to=origin/main"]);
    assert_eq!(fixture.head("@{u}"), fixture.head("origin/main"));
    assert_eq!(fixture.ok(&["branch", fixture.repo()]), plain);
    assert_eq!(fixture.head("HEAD"), head);
    assert_eq!(fs::read(fixture.local.join(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(fixture.local.join("a.wasm")).unwrap(), working);
    assert_eq!(
        fs::read(fixture.local.join("private.txt")).unwrap(),
        b"untracked data"
    );
    fixture.ok(&["branch", fixture.repo(), "--unset-upstream"]);
    fixture.reject(&["rev-parse", fixture.repo(), "@{u}"]);
    assert_eq!(fixture.head("feature@{u}"), fixture.head("origin/main"));
    fixture.ok(&["branch", fixture.repo(), "--unset-upstream", "feature"]);
    fixture.reject(&["branch", fixture.repo(), "--unset-upstream", "feature"]);
    fixture.ok(&["fsck", fixture.repo()]);
}

#[test]
fn bindings_follow_local_branch_rename_delete_and_remote_rename_remove() {
    let fixture = Fixture::new();
    fixture.fetch();
    fixture.ok(&["branch", fixture.repo(), "-u", "origin/feature", "feature"]);
    fixture.ok(&["branch", fixture.repo(), "-m", "feature", "topic"]);
    assert_eq!(fixture.head("topic@{u}"), fixture.head("origin/feature"));
    fixture.reject(&["rev-parse", fixture.repo(), "feature@{u}"]);
    fixture.ok(&["remote", fixture.repo(), "rename", "origin", "peer"]);
    let report = fixture.json(&["branch", fixture.repo(), "-vv"]);
    assert_eq!(
        branch(&report, "topic")["upstream"]["tracking"],
        "peer/feature"
    );
    assert_eq!(
        fixture.head("topic@{upstream}"),
        fixture.head("peer/feature")
    );
    fixture.ok(&["branch", fixture.repo(), "-d", "topic"]);
    fixture.ok(&["branch", fixture.repo(), "topic"]);
    assert!(
        branch(&fixture.json(&["branch", fixture.repo(), "-vv"]), "topic")["upstream"].is_null()
    );
    fixture.ok(&[
        "branch",
        fixture.repo(),
        "--set-upstream-to=peer/main",
        "topic",
    ]);
    fixture.ok(&["remote", fixture.repo(), "remove", "peer"]);
    assert!(
        branch(&fixture.json(&["branch", fixture.repo(), "-vv"]), "topic")["upstream"].is_null()
    );
    fixture.reject(&["rev-parse", fixture.repo(), "topic@{u}"]);
    fixture.ok(&["fsck", fixture.repo()]);
}

#[test]
fn a_deleted_remote_target_is_reported_gone_without_guessing_local_head() {
    let fixture = Fixture::new();
    fixture.fetch();
    fixture.ok(&["branch", fixture.repo(), "-u", "origin/feature"]);
    fixture.ok(&["branch", path(&fixture.service), "-d", "feature"]);
    fixture.fetch();
    let before = snapshot(&fixture.local);
    let report = fixture.json(&["branch", fixture.repo(), "-vv"]);
    let upstream = &branch(&report, "main")["upstream"];
    assert_eq!(upstream["remote"], "origin");
    assert_eq!(upstream["branch"], "feature");
    assert_eq!(upstream["status"], "gone");
    assert!(upstream["tip"].is_null());
    assert_eq!(snapshot(&fixture.local), before);
    fixture.reject(&["rev-parse", fixture.repo(), "@{u}"]);
    fixture.ok(&["branch", fixture.repo(), "--unset-upstream"]);
}

#[test]
fn malformed_unfetched_and_unknown_bindings_fail_before_any_persistent_change() {
    let fixture = Fixture::new();
    fixture.reject(&["branch", fixture.repo(), "-u", "origin/main"]);
    fixture.fetch();
    for spec in [
        "origin",
        "origin/",
        "/main",
        "origin/main/extra",
        "unknown/main",
        "origin/absent",
        "origin/HEAD",
        "origin/bad.lock",
        "--help",
        "-h",
        "--allow-insecure-http",
    ] {
        fixture.reject(&["branch", fixture.repo(), "-u", spec]);
    }
    for suffix in [
        vec!["-u"],
        vec!["--set-upstream-to"],
        vec!["--set-upstream-to="],
        vec!["-u", "origin/main", "missing"],
        vec!["-u", "origin/main", "HEAD"],
        vec!["-u", "origin/main", "main", "extra"],
        vec!["--unset-upstream", "main", "extra"],
        vec!["-vv", "main"],
    ] {
        let mut args = vec!["branch", fixture.repo()];
        args.extend(suffix);
        fixture.reject(&args);
    }
    for revision in ["missing@{upstream}", "@{u}~1", "@{1}", "main@{1}"] {
        fixture.reject(&["rev-parse", fixture.repo(), revision]);
    }
    fixture.ok(&["fsck", fixture.repo()]);
}

#[test]
fn unborn_and_new_branches_never_guess_an_upstream_and_help_is_readonly() {
    let fixture = Fixture::new();
    fixture.fetch();
    fixture.ok(&["branch", fixture.repo(), "topic", "origin/main"]);
    fixture.ok(&["switch", fixture.repo(), "-c", "other", "origin/main"]);
    let report = fixture.json(&["branch", fixture.repo(), "-vv"]);
    assert!(branch(&report, "topic")["upstream"].is_null());
    assert!(branch(&report, "other")["upstream"].is_null());
    let unborn = fixture.root.join("unborn");
    run(&["init", path(&unborn)]);
    let before = snapshot(&unborn);
    let report = fixture.json(&["branch", path(&unborn), "-vv"]);
    let main = branch(&report, "main");
    assert!(main["commit"].is_null());
    assert!(main["upstream"].is_null());
    assert_eq!(snapshot(&unborn), before);
    let output = fixture
        .command(&["branch", path(&unborn), "-u", "origin/main"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(snapshot(&unborn), before);
    let absent = fixture.root.join("must-not-exist");
    for args in [
        vec!["branch", path(&absent), "-u", "origin/main", "--help"],
        vec!["branch", path(&absent), "--unset-upstream", "-h"],
    ] {
        assert!(fixture.ok(&args).contains("upstream"));
        assert!(!absent.exists());
    }
    let no_remotes = fixture.root.join("without-remotes");
    run(&["init", path(&no_remotes)]);
    fs::write(no_remotes.join("a.wasm"), HEADER).unwrap();
    run(&["add", path(&no_remotes), "a.wasm"]);
    run(&["commit", path(&no_remotes), "-m", "no remote configuration"]);
    let before = snapshot(&no_remotes);
    let output = fixture
        .command(&["branch", path(&no_remotes), "-u", "origin/main"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(snapshot(&no_remotes), before);
    let report = fixture.json(&["branch", path(&no_remotes), "-vv"]);
    assert!(branch(&report, "main")["upstream"].is_null());
    assert_eq!(snapshot(&no_remotes), before);
}

#[test]
fn upstream_resolution_reads_the_new_tracking_tip_after_fetch_without_moving_local_branch() {
    let fixture = Fixture::new();
    fixture.fetch();
    fixture.ok(&["branch", fixture.repo(), "-u", "origin/main"]);
    let local_head = fixture.head("HEAD");
    fs::write(fixture.source.join("a.wasm"), UNKNOWN).unwrap();
    run(&["add", path(&fixture.source), "a.wasm"]);
    run(&["commit", path(&fixture.source), "-m", "remote update"]);
    fixture.publish("main");
    assert_eq!(fixture.head("@{u}"), local_head);
    fixture.fetch();
    let remote_head = tip(&fixture.source);
    assert_eq!(fixture.head("@{u}"), remote_head);
    assert_eq!(fixture.head("main@{upstream}"), remote_head);
    assert_eq!(fixture.head("HEAD"), local_head);
    assert!(!fixture.local.join(".uwgit/index").exists());
    fixture.ok(&["fsck", fixture.repo()]);
}

#[test]
fn upstream_metadata_commands_obey_index_remote_and_writer_locks_without_partial_updates() {
    let fixture = Fixture::new();
    fixture.fetch();
    for lock in ["index.lock", "remote.lock", "write.lock"] {
        let file = fixture.local.join(format!(".uwgit/{lock}"));
        fs::write(&file, b"fixed held lock").unwrap();
        fixture.reject(&["branch", fixture.repo(), "-u", "origin/main"]);
        fs::remove_file(file).unwrap();
    }
    fixture.ok(&["branch", fixture.repo(), "-u", "origin/main"]);
    for lock in ["index.lock", "remote.lock", "write.lock"] {
        let file = fixture.local.join(format!(".uwgit/{lock}"));
        fs::write(&file, b"fixed held lock").unwrap();
        fixture.reject(&["branch", fixture.repo(), "--unset-upstream"]);
        fixture.reject(&["branch", fixture.repo(), "-vv"]);
        fixture.reject(&["rev-parse", fixture.repo(), "@{u}"]);
        fs::remove_file(file).unwrap();
    }
    assert_eq!(fixture.head("@{u}"), fixture.head("origin/main"));
}
fn tip(repository: &Path) -> String {
    run(&["rev-parse", path(repository), "HEAD"]).trim().into()
}
