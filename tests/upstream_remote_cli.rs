//! Fixed upstream selection and acknowledgement workflows. No fuzzing.
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
use std::time::{Duration, Instant};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TOKEN: &str = "fixed-upstream-loopback-token";
const A: &str = "modules/a.wasm";
const B: &str = "nested/b.wasm";
fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = Path::new("/tmp").join(format!(
            "uwgit-upstream-{}-{}",
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
fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    cmd.args(args)
        .env_remove("UWGIT_REMOTE_TOKEN")
        .env_remove("UWGIT_SSH_PROGRAM")
        .env_remove("UWGIT_REMOTE_PROGRAM");
    cmd
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
fn tip(root: &Path, revision: &str) -> String {
    run(&["rev-parse", path(root), revision]).trim().to_owned()
}
fn write(root: &Path, name: &str, value: u8) {
    let p = root.join(name);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(
        p,
        [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat(),
    )
    .unwrap();
}
fn bindings(root: &Path) -> Value {
    let p = root.join(".uwgit/upstreams.json");
    if p.exists() {
        serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
    } else {
        serde_json::json!({"version":1,"branches":{}})
    }
}
fn binding(root: &Path, branch: &str, remote: &str, target: &str) {
    assert_eq!(
        bindings(root)["branches"][branch],
        serde_json::json!({"remote":remote,"branch":target})
    );
}
fn snapshot(root: &Path, fetch: bool) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, dir: &Path, fetch: bool, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            let rel = p.strip_prefix(root).unwrap();
            if fetch
                && (rel.starts_with(".uwgit/objects")
                    || rel.starts_with(".uwgit/tmp")
                    || rel.to_str().unwrap().ends_with(".tracking.json"))
            {
                continue;
            }
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                out.insert(rel.to_owned(), None);
                visit(root, &p, fetch, out);
            } else {
                out.insert(rel.to_owned(), Some(fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, fetch, &mut out);
    out
}
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Fixture {
    _server: Option<Server>,
    temp: Temp,
    producer: PathBuf,
    upstream: PathBuf,
    url: String,
    shim: Option<PathBuf>,
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
        run(&["commit", path(&producer), "-m", "upstream base"]);
        run(&["branch", path(&producer), "feature"]);
        let base = tip(&producer, "HEAD");
        run(&["clone", path(&producer), path(&upstream)]);
        let (server, url, shim) = if ssh {
            let shim = temp.path("ssh-shim");
            fs::write(&shim,b"#!/bin/sh\nset -eu\nexec \"$UWGIT_UPSTREAM_TEST_BINARY\" server --stdio --root \"$UWGIT_UPSTREAM_TEST_ROOT\" --allow-force\n").unwrap();
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
            (
                None,
                format!("ssh://test@localhost{}/upstream.git", temp.0.display()),
                Some(shim),
            )
        } else {
            let token = temp.path("http-token");
            fs::write(&token, format!("{TOKEN}\n")).unwrap();
            fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
            let mut child = command(&[
                "server",
                "--root",
                path(&temp.0),
                "--listen",
                "127.0.0.1:0",
                "--allow-write",
                "--allow-force",
                "--token-file",
                path(&token),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = thread::spawn(move || {
                let mut line = String::new();
                BufReader::new(stdout).read_line(&mut line).unwrap();
                tx.send(line).unwrap();
            });
            let line = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            reader.join().unwrap();
            let startup: Value = serde_json::from_str(&line).unwrap();
            (
                Some(Server(child)),
                format!(
                    "http://{}/upstream.git",
                    startup["listen"].as_str().unwrap()
                ),
                None,
            )
        };
        Self {
            _server: server,
            temp,
            producer,
            upstream,
            url,
            shim,
            base,
        }
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut child = command(args);
        if let Some(shim) = &self.shim {
            child
                .env("UWGIT_SSH_PROGRAM", shim)
                .env("UWGIT_UPSTREAM_TEST_BINARY", env!("CARGO_BIN_EXE_wasm-git"))
                .env("UWGIT_UPSTREAM_TEST_ROOT", &self.temp.0);
        } else {
            child.env("UWGIT_REMOTE_TOKEN", TOKEN);
        }
        child
    }
    fn run(&self, args: &[&str]) -> String {
        success(self.command(args).output().unwrap())
    }
    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.run(args)).unwrap()
    }
    fn failure(&self, args: &[&str]) -> String {
        let output = self.command(args).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        String::from_utf8(output.stderr).unwrap()
    }
    fn clone_worktree(&self, label: &str) -> PathBuf {
        let local = self.temp.path(label);
        self.run(&["clone", &self.url, path(&local)]);
        run(&[
            "restore",
            path(&local),
            "--source",
            "HEAD",
            "--staged",
            "--worktree",
        ]);
        local
    }
    fn advance(&self, branch: &str, value: u8) -> String {
        write(&self.producer, A, value);
        run(&["add", path(&self.producer), A]);
        run(&["commit", path(&self.producer), "-m", "remote advance"]);
        let bundle = self.temp.path(&format!(
            "{}.bundle",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        run(&["bundle", path(&self.producer), path(&bundle)]);
        run(&["unbundle", path(&self.upstream), path(&bundle), branch]);
        tip(&self.producer, "HEAD")
    }
}
#[test]
fn network_clone_binds_only_its_committed_advertised_head() {
    for ssh in [false, true] {
        let f = Fixture::new(ssh);
        let local = f.clone_worktree("clone");
        binding(&local, "main", "origin", "main");
        assert!(bindings(&local)["branches"]
            .as_object()
            .unwrap()
            .get("feature")
            .is_none());
        assert_eq!(tip(&local, "@{upstream}"), f.base);
        let local_copy = f.temp.path("local-copy");
        run(&["clone", path(&local), path(&local_copy)]);
        assert!(
            !local_copy.join(".uwgit/upstreams.json").exists(),
            "local clone must not inherit transport-local bindings"
        );
        let empty = f.temp.path("empty.git");
        run(&["init", path(&empty)]);
        let url = f.url.replace("/upstream.git", "/empty.git");
        let empty_clone = f.temp.path("empty-clone");
        f.run(&["clone", &url, path(&empty_clone)]);
        assert!(!empty_clone.join(".uwgit/upstreams.json").exists());
    }
}
#[test]
fn default_pull_uses_renamed_upstream_and_explicit_operands_have_clear_overrides() {
    for ssh in [false, true] {
        let f = Fixture::new(ssh);
        let local = f.clone_worktree("consumer");
        run(&["branch", path(&local), "-m", "main", "local"]);
        f.run(&["remote", path(&local), "rename", "origin", "team"]);
        binding(&local, "local", "team", "main");
        let next = f.advance("main", 2);
        assert_eq!(f.json(&["pull", path(&local), "--ff-only"])["target"], next);
        assert_eq!(tip(&local, "HEAD"), next);
        let feature = f.advance("feature", 3);
        assert_eq!(
            f.json(&["pull", path(&local), "team", "feature", "--ff-only"])["target"],
            feature
        );
        binding(&local, "local", "team", "main");
        assert_eq!(
            f.json(&["pull", path(&local), "team", "--ff-only"])["target"],
            next
        );
        f.run(&["remote", path(&local), "add", "backup", &f.url]);
        let before = snapshot(&local, true);
        assert!(f
            .failure(&["pull", path(&local), "backup", "--ff-only"])
            .contains("specify BRANCH"));
        assert_eq!(snapshot(&local, true), before);
        let bundle = f.temp.path("same-name.bundle");
        run(&["bundle", path(&f.producer), path(&bundle)]);
        run(&["unbundle", path(&f.upstream), path(&bundle), "local"]);
        assert_eq!(
            f.json(&["pull", path(&local), "backup", "--ff-only"])["target"],
            feature
        );
        binding(&local, "local", "team", "main");
        assert_eq!(
            fs::read(local.join(A)).unwrap(),
            fs::read(f.producer.join(A)).unwrap()
        );
    }
}
#[test]
fn simple_push_and_set_upstream_require_explicit_refspec_for_different_names() {
    for ssh in [false, true] {
        let f = Fixture::new(ssh);
        let local = f.clone_worktree("publisher");
        run(&["branch", path(&local), "-m", "main", "local"]);
        f.run(&["remote", path(&local), "rename", "origin", "team"]);
        let before = snapshot(&local, false);
        let remote_before = snapshot(&f.upstream, false);
        for tail in [
            vec![],
            vec!["-u"],
            vec!["--set-upstream"],
            vec!["team", "-u"],
        ] {
            let mut args = vec!["push", path(&local)];
            args.extend(tail);
            assert!(f.failure(&args).contains("simple push refused"));
            assert_eq!(snapshot(&local, false), before);
            assert_eq!(snapshot(&f.upstream, false), remote_before);
        }
        f.run(&[
            "push",
            path(&local),
            "team",
            "refs/heads/local:refs/heads/publication",
            "--set-upstream",
        ]);
        binding(&local, "local", "team", "publication");
        assert_eq!(tip(&f.upstream, "publication"), f.base);
        f.run(&["remote", path(&local), "add", "backup", &f.url]);
        f.run(&["push", path(&local), "backup", "-u"]);
        binding(&local, "local", "backup", "local");
        write(&local, A, 2);
        run(&["add", path(&local), A]);
        run(&[
            "commit",
            path(&local),
            "-m",
            "publish via configured backup",
        ]);
        let next = tip(&local, "HEAD");
        f.run(&["push", path(&local)]);
        assert_eq!(tip(&f.upstream, "local"), next);
        assert_eq!(tip(&f.upstream, "main"), f.base);
        run(&["tag", path(&local), "release"]);
        let before = snapshot(&local, false);
        let invalid = [
            vec!["team", "HEAD:main", "-u", "--tags"],
            vec!["team", "--delete", "publication", "-u"],
            vec!["team", "HEAD:main", "-u", "--set-upstream"],
            vec!["team", "release:main", "-u"],
            vec!["team", "refs/tags/release:main", "-u"],
            vec!["team", "HEAD~1:main", "-u"],
            vec!["team", "HEAD:refs/tags/newtag", "-u"],
            vec!["team", "main:main", "-u"],
        ];
        for tail in invalid {
            let mut args = vec!["push", path(&local)];
            args.extend(tail);
            f.failure(&args);
            assert_eq!(snapshot(&local, false), before);
        }
        let refspec = format!("{next}:main");
        f.failure(&["push", path(&local), "team", &refspec, "-u"]);
        assert_eq!(snapshot(&local, false), before);
    }
}
#[test]
fn rejected_push_does_not_create_binding_and_remove_clears_all_local_associations() {
    for ssh in [false, true] {
        let f = Fixture::new(ssh);
        let local = f.clone_worktree("divergent");
        run(&["branch", path(&local), "--unset-upstream"]);
        f.advance("main", 2);
        write(&local, A, 3);
        run(&["add", path(&local), A]);
        run(&["commit", path(&local), "-m", "local diverges"]);
        let before = snapshot(&local, false);
        assert!(f
            .failure(&["push", path(&local), "origin", "HEAD:main", "-u"])
            .contains("remote rejected request:"));
        assert_eq!(snapshot(&local, false), before);
        assert!(bindings(&local)["branches"].as_object().unwrap().is_empty());
        f.run(&["fetch", path(&local)]);
        run(&["branch", path(&local), "-u", "origin/feature"]);
        run(&["branch", path(&local), "other"]);
        run(&["branch", path(&local), "-u", "origin/main", "other"]);
        f.run(&["remote", path(&local), "rename", "origin", "renamed"]);
        binding(&local, "main", "renamed", "feature");
        binding(&local, "other", "renamed", "main");
        f.run(&["remote", path(&local), "remove", "renamed"]);
        assert!(bindings(&local)["branches"].as_object().unwrap().is_empty());
    }
}
fn wait_for(path: &Path) {
    let limit = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(Instant::now() < limit, "barrier was not reached");
        thread::sleep(Duration::from_millis(10));
    }
}
const ACK_SHIM: &str = r#"#!/usr/bin/python3
import json,os,pathlib,struct,subprocess,sys,time
request=sys.stdin.buffer.read()
n=struct.unpack('>I',request[8:12])[0]
kind=json.loads(request[20:20+n])['operation']['kind']
result=subprocess.run([os.environ['UWGIT_UPSTREAM_TEST_BINARY'],'server','--stdio','--root',os.environ['UWGIT_UPSTREAM_TEST_ROOT']],input=request,capture_output=True,check=True)
response=result.stdout
if kind in ['push','update_ref']:
 if os.environ.get('UWGIT_UPSTREAM_BAD_ACK')=='1':
  size=struct.unpack('>I',response[8:12])[0]
  metadata=json.loads(response[20:20+size]);metadata['tip']='0'*64
  encoded=json.dumps(metadata,separators=(',',':')).encode()
  response=response[:8]+struct.pack('>I',len(encoded))+response[12:20]+encoded+response[20+size:]
 else:
  pathlib.Path(os.environ['UWGIT_UPSTREAM_READY']).write_text('published')
  until=time.monotonic()+20
  while not pathlib.Path(os.environ['UWGIT_UPSTREAM_RELEASE']).exists():
   if time.monotonic()>until:raise SystemExit('fixed acknowledgement barrier timeout')
   time.sleep(.01)
sys.stdout.buffer.write(response)
"#;
#[test]
fn exact_acknowledgement_precedes_binding_and_local_tip_or_binding_cas_is_preserved() {
    for change_binding in [false, true] {
        let f = Fixture::new(true);
        let local = f.clone_worktree("publisher");
        let shim = f.temp.path("ack-shim");
        fs::write(&shim, ACK_SHIM).unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
        let ready = f.temp.path("published");
        let release = f.temp.path("release");
        let mut cmd = f.command(&["push", path(&local), "origin", "HEAD:publication", "-u"]);
        let child = cmd
            .env("UWGIT_SSH_PROGRAM", &shim)
            .env("UWGIT_UPSTREAM_READY", &ready)
            .env("UWGIT_UPSTREAM_RELEASE", &release)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for(&ready);
        assert_eq!(tip(&f.upstream, "publication"), f.base);
        if change_binding {
            run(&["branch", path(&local), "-u", "origin/feature"]);
        } else {
            write(&local, A, 2);
            run(&["add", path(&local), A]);
            run(&[
                "commit",
                path(&local),
                "-m",
                "tip changes while acknowledgement is delayed",
            ]);
        }
        let after_change = snapshot(&local, false);
        fs::write(&release, b"go").unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("published") && error.contains("upstream update failed"),
            "{error}"
        );
        assert_eq!(snapshot(&local, false), after_change);
        binding(
            &local,
            "main",
            "origin",
            if change_binding { "feature" } else { "main" },
        );
    }
}
#[test]
fn mismatching_acknowledgement_keeps_prior_upstream_even_after_remote_publication() {
    let f = Fixture::new(true);
    let local = f.clone_worktree("publisher");
    let shim = f.temp.path("wrong-ack");
    fs::write(&shim, ACK_SHIM).unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
    let before = snapshot(&local, false);
    let output = f
        .command(&["push", path(&local), "origin", "HEAD:publication", "-u"])
        .env("UWGIT_SSH_PROGRAM", &shim)
        .env("UWGIT_UPSTREAM_BAD_ACK", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("publication outcome is unknown"));
    assert_eq!(tip(&f.upstream, "publication"), f.base);
    assert_eq!(snapshot(&local, false), before);
    binding(&local, "main", "origin", "main");
}
