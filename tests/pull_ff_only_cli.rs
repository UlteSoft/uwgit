//! Fixed pull fast-forward policy workflows over real loopback HTTP and a
//! local SSH/stdio shim. Fetch may retain verified objects and remote tracking;
//! refusing integration must preserve local refs, index and working bytes.
#![cfg(unix)]

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const A: &str = "modules/a.wasm";
const B: &str = "nested/b.wasm";
const C: &str = "added/c.wasm";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-pull-ff-only-{}-{}",
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
fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}
fn command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    command
        .args(args)
        .env_remove("UWGIT_REMOTE_TOKEN")
        .env_remove("UWGIT_SSH_PROGRAM")
        .env_remove("UWGIT_REMOTE_PROGRAM");
    command
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn run(args: &[&str]) -> String {
    success(command(args).output().unwrap())
}
fn write(repository: &Path, name: &str, value: u8) -> Vec<u8> {
    let bytes = [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat();
    let destination = repository.join(name);
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::write(destination, &bytes).unwrap();
    bytes
}
fn tip(repository: &Path, revision: &str) -> String {
    run(&["rev-parse", path(repository), revision])
        .trim()
        .to_owned()
}
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
}
fn snapshot(repository: &Path, allow_fetch: bool) -> BTreeMap<PathBuf, Entry> {
    fn visit(
        root: &Path,
        directory: &Path,
        allow_fetch: bool,
        output: &mut BTreeMap<PathBuf, Entry>,
    ) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();
            let relative = entry_path.strip_prefix(root).unwrap();
            if allow_fetch
                && [
                    ".uwgit/objects",
                    ".uwgit/tmp",
                    ".uwgit/remotes/origin.tracking.json",
                    ".uwgit/remotes/peer.tracking.json",
                ]
                .iter()
                .any(|excluded| relative == Path::new(excluded))
            {
                continue;
            }
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                output.insert(relative.to_owned(), Entry::Directory);
                visit(root, &entry_path, allow_fetch, output);
            } else {
                output.insert(
                    relative.to_owned(),
                    Entry::File(fs::read(&entry_path).unwrap()),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(repository, repository, allow_fetch, &mut output);
    output
}
struct Server(Child);
impl Server {
    fn start(root: &Path) -> (Self, String) {
        let mut child = command(&["server", "--root", path(root), "--listen", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            sender.send(line).unwrap();
        });
        let line = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        reader.join().unwrap();
        let startup: Value = serde_json::from_str(&line).unwrap();
        let address = startup["listen"].as_str().unwrap();
        assert!(address.starts_with("127.0.0.1:"));
        (Self(child), format!("http://{address}/upstream.git"))
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Fixture {
    // Stop the HTTP child before the temporary repository owner is dropped.
    _server: Option<Server>,
    temp: Temp,
    producer: PathBuf,
    upstream: PathBuf,
    url: String,
    ssh: Option<PathBuf>,
    base: String,
}
impl Fixture {
    fn new(ssh: bool) -> Self {
        let temp = Temp::new();
        let producer = temp.path("producer");
        let upstream = temp.path("upstream.git");
        run(&["init", path(&producer)]);
        write(&producer, A, 1);
        write(&producer, B, 1);
        run(&["add", path(&producer), A, B]);
        run(&["commit", path(&producer), "-m", "base tree"]);
        run(&["branch", path(&producer), "feature"]);
        let base = tip(&producer, "HEAD");
        // The service store has no index, so local unbundle can publish its
        // branch without weakening tracked-worktree receive protection.
        run(&["clone", path(&producer), path(&upstream)]);
        let (server, url, shim) = if ssh {
            let shim = temp.path("ssh-shim");
            fs::write(&shim, b"#!/bin/sh\nset -eu\nexec \"$UWGIT_FF_TEST_BINARY\" server --stdio --root \"$UWGIT_FF_TEST_ROOT\"\n").unwrap();
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
            (
                None,
                format!("ssh://test@localhost{}/upstream.git", temp.0.display()),
                Some(shim),
            )
        } else {
            let (server, url) = Server::start(&temp.0);
            (Some(server), url, None)
        };
        Self {
            _server: server,
            temp,
            producer,
            upstream,
            url,
            ssh: shim,
            base,
        }
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut child = command(args);
        if let Some(shim) = &self.ssh {
            child
                .env("UWGIT_SSH_PROGRAM", shim)
                .env("UWGIT_FF_TEST_BINARY", env!("CARGO_BIN_EXE_wasm-git"))
                .env("UWGIT_FF_TEST_ROOT", &self.temp.0);
        }
        child
    }
    fn run(&self, args: &[&str]) -> String {
        success(self.command(args).output().unwrap())
    }
    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.run(args)).unwrap()
    }
    fn clone_worktree(&self, name: &str) -> PathBuf {
        let destination = self.temp.path(name);
        self.run(&["clone", &self.url, path(&destination)]);
        run(&[
            "restore",
            path(&destination),
            "--source",
            "HEAD",
            "--staged",
            "--worktree",
        ]);
        destination
    }
    fn publish(&self, branch: &str) -> String {
        let bundle = self.temp.path(&format!(
            "publication-{}.bundle",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        run(&["bundle", path(&self.producer), path(&bundle)]);
        run(&["unbundle", path(&self.upstream), path(&bundle), branch]);
        tip(&self.producer, "HEAD")
    }
    fn assert_fetched(&self, local: &Path, remote: &str, id: &str) {
        let tracking: Value = serde_json::from_slice(
            &fs::read(local.join(format!(".uwgit/remotes/{remote}.tracking.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(tracking["state"]["branches"]["main"], id);
        assert_eq!(tip(local, &format!("{remote}/main")), id);
        // The new tip is readable despite the refused local integration.
        assert_eq!(tip(local, id), id);
    }
}

#[test]
fn explicit_and_default_pull_ff_only_fast_forward_unborn_and_ancestor_cases() {
    for ssh in [false, true] {
        let fixture = Fixture::new(ssh);
        let local = fixture.clone_worktree("local");
        fixture.run(&["remote", path(&local), "add", "peer", &fixture.url]);
        run(&["switch", path(&fixture.producer), "feature"]);
        let expected = write(&fixture.producer, A, 2);
        run(&["add", path(&fixture.producer), A]);
        run(&["commit", path(&fixture.producer), "-m", "remote feature"]);
        let next = fixture.publish("feature");
        assert_eq!(tip(&fixture.upstream, "main"), fixture.base);

        // A flag after the message is still standalone. Explicitly choose the
        // remote feature, even though the service's advertised HEAD is main.
        let explicit = fixture.json(&[
            "pull",
            path(&local),
            "peer",
            "feature",
            "-m",
            "explicit",
            "--ff-only",
            "--allow-insecure-http",
        ]);
        assert_eq!(explicit["status"], "fast_forward");
        assert_eq!(tip(&local, "HEAD"), next);
        assert_eq!(tip(&local, "feature"), fixture.base);
        assert_eq!(fs::read(local.join(A)).unwrap(), expected);

        run(&["switch", path(&local), "feature"]);
        let default = fixture.json(&["pull", path(&local), "--ff-only"]);
        assert_eq!(default["status"], "fast_forward");
        assert_eq!(tip(&local, "HEAD"), next);
        assert_eq!(fs::read(local.join(A)).unwrap(), expected);
        let protected = snapshot(&local, true);
        let ancestor = fixture.json(&[
            "pull",
            path(&local),
            "origin",
            "main",
            "--ff-only",
            "--message",
            "--ff-only",
        ]);
        assert_eq!(ancestor["status"], "already_up_to_date");
        assert_eq!(ancestor["target"], fixture.base);
        assert_eq!(snapshot(&local, true), protected);

        let unborn = fixture.temp.path("unborn");
        run(&["init", path(&unborn)]);
        fixture.run(&["remote", path(&unborn), "add", "origin", &fixture.url]);
        let initialized = fixture.json(&["pull", path(&unborn), "origin", "feature", "--ff-only"]);
        assert_eq!(initialized["status"], "fast_forward");
        assert_eq!(tip(&unborn, "HEAD"), next);
        assert!(!unborn.join(".uwgit/index").exists());
        for repository in [&local, &unborn, &fixture.upstream] {
            run(&["fsck", path(repository)]);
        }
    }
}

#[test]
fn divergent_pull_ff_only_keeps_local_state_but_retains_fetch_objects_and_tracking() {
    for ssh in [false, true] {
        for conflict in [false, true] {
            let fixture = Fixture::new(ssh);
            let local = fixture.clone_worktree("local");
            write(&local, A, 2);
            run(&["add", path(&local), A]);
            run(&["commit", path(&local), "-m", "local divergence"]);
            let ours = tip(&local, "HEAD");
            let changed = if conflict { A } else { B };
            let expected = write(&fixture.producer, changed, 3);
            run(&["add", path(&fixture.producer), changed]);
            run(&["commit", path(&fixture.producer), "-m", "remote divergence"]);
            let theirs = fixture.publish("main");
            let protected = snapshot(&local, true);
            let old_tracking = fs::read(local.join(".uwgit/remotes/origin.tracking.json")).unwrap();
            let rejected = fixture
                .command(&["pull", path(&local), "--ff-only", "-m", "--ff-only"])
                .output()
                .unwrap();
            assert_eq!(rejected.status.code(), Some(1));
            let error = String::from_utf8(rejected.stderr).unwrap();
            assert!(error.contains("fast-forward"), "{error}");
            assert_eq!(tip(&local, "HEAD"), ours);
            assert_eq!(snapshot(&local, true), protected);
            assert_ne!(
                fs::read(local.join(".uwgit/remotes/origin.tracking.json")).unwrap(),
                old_tracking
            );
            fixture.assert_fetched(&local, "origin", &theirs);
            let exported = fixture.temp.path("fetched.wasm");
            run(&[
                "show",
                path(&local),
                &theirs,
                "--file",
                changed,
                "--output",
                path(&exported),
            ]);
            assert_eq!(fs::read(exported).unwrap(), expected);
            run(&["fsck", path(&local)]);
        }
    }
}

#[test]
fn fast_forward_pull_untracked_blocker_keeps_local_state_after_verified_fetch() {
    for ssh in [false, true] {
        let fixture = Fixture::new(ssh);
        let local = fixture.clone_worktree("local");
        write(&fixture.producer, C, 3);
        run(&["add", path(&fixture.producer), C]);
        run(&[
            "commit",
            path(&fixture.producer),
            "-m",
            "remote adds target",
        ]);
        let theirs = fixture.publish("main");
        let untracked = write(&local, C, 9);
        let protected = snapshot(&local, true);
        let rejected = fixture
            .command(&["pull", path(&local), "--ff-only"])
            .output()
            .unwrap();
        assert_eq!(rejected.status.code(), Some(1));
        assert_eq!(tip(&local, "HEAD"), fixture.base);
        assert_eq!(snapshot(&local, true), protected);
        fixture.assert_fetched(&local, "origin", &theirs);
        assert_eq!(fs::read(local.join(C)).unwrap(), untracked);
        run(&["fsck", path(&local)]);
    }
}

#[test]
fn pull_literal_ff_only_message_still_performs_default_clean_merge() {
    for message_option in ["-m", "--message"] {
        let fixture = Fixture::new(false);
        let local = fixture.clone_worktree("local");
        write(&local, A, 2);
        run(&["add", path(&local), A]);
        run(&["commit", path(&local), "-m", "local independent file"]);
        let ours = tip(&local, "HEAD");
        write(&fixture.producer, B, 3);
        run(&["add", path(&fixture.producer), B]);
        run(&[
            "commit",
            path(&fixture.producer),
            "-m",
            "remote independent file",
        ]);
        let theirs = fixture.publish("main");
        let merged = fixture.json(&["pull", path(&local), message_option, "--ff-only"]);
        assert_eq!(merged["status"], "merged");
        let info: Value = serde_json::from_str(&run(&["show", path(&local), "HEAD"])).unwrap();
        assert_eq!(info["message"], "--ff-only");
        assert_eq!(info["parents"], serde_json::json!([ours, theirs]));
    }
}

#[test]
fn pull_ff_only_flag_combinations_fail_before_fetch_and_true_help_does_no_io() {
    let fixture = Fixture::new(false);
    let local = fixture.clone_worktree("local");
    write(&fixture.producer, A, 4);
    run(&["add", path(&fixture.producer), A]);
    run(&[
        "commit",
        path(&fixture.producer),
        "-m",
        "not fetched on syntax errors",
    ]);
    let theirs = fixture.publish("main");
    let before = snapshot(&local, false);
    for suffix in [
        vec!["--ff-only", "--ff-only"],
        vec!["--ff-only", "-m", "--ff-only", "--ff-only"],
        vec!["--ff-only=true"],
        vec!["--ff-only", "--resolved-index", "-m", "message"],
        vec!["--ff-only", "--resolved", "file.wasm", "-m", "message"],
        vec!["--ff-only", "--expect-head", "HEAD", "-m", "message"],
        vec!["--ff-only", "--expect-branch", "main", "-m", "message"],
        vec!["--ff-only", "--no-ff", "-m", "message"],
        vec!["--ff-only", "-m"],
        vec!["--ff-only", "-m", "message", "--message", "duplicate"],
        vec![],
    ] {
        let mut args = vec!["pull", path(&local)];
        args.extend(suffix);
        let rejected = fixture.command(&args).output().unwrap();
        assert_eq!(rejected.status.code(), Some(1), "{args:?}");
        assert_eq!(snapshot(&local, false), before, "{args:?}");
    }
    assert!(!command(&["rev-parse", path(&local), &theirs])
        .output()
        .unwrap()
        .status
        .success());
    let missing = fixture.temp.path("missing-help-repository");
    let help = fixture.run(&["pull", path(&missing), "--ff-only", "--help"]);
    assert!(help.contains("--ff-only"));
    assert!(!missing.exists());
    let help_named_message =
        fixture.json(&["pull", path(&local), "--ff-only", "--message", "--help"]);
    assert_eq!(help_named_message["status"], "fast_forward");
    assert_eq!(tip(&local, "HEAD"), theirs);
}
