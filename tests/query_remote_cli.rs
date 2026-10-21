//! Fixed, advertisement-only queries. No object download or guest execution.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-query-remote-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn repo(&self) -> PathBuf {
        let repo = self.path("repo");
        success(command(&["init", s(&repo)]).output().unwrap());
        repo
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn s(path: &Path) -> &str {
    path.to_str().unwrap()
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
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout).unwrap()
}
fn run(args: &[&str]) -> String {
    success(command(args).output().unwrap())
}
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, dir: &Path, rows: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let name = path.strip_prefix(root).unwrap().to_owned();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                rows.insert(name, Entry::Symlink(fs::read_link(path).unwrap()));
            } else if kind.is_dir() {
                rows.insert(name, Entry::Directory);
                visit(root, &path, rows);
            } else {
                assert!(kind.is_file());
                rows.insert(name, Entry::File(fs::read(path).unwrap()));
            }
        }
    }
    let mut rows = BTreeMap::new();
    visit(root, root, &mut rows);
    rows
}
fn response() -> Value {
    json!({"version":1,"ok":true,"publication_unknown":false,"error":null,
        "state":{"format":1,"head":"main","branches":{"main":A,"topic":B},"tags":{"v1":A}},"tip":null})
}
fn frame_json(metadata: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = b"UWGRPC01".to_vec();
    bytes.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(metadata);
    bytes.extend_from_slice(payload);
    bytes
}
fn frame(metadata: &Value, payload: &[u8]) -> Vec<u8> {
    frame_json(&serde_json::to_vec(metadata).unwrap(), payload)
}
fn decode_request(bytes: &[u8]) -> Value {
    assert_eq!(&bytes[..8], b"UWGRPC01");
    let metadata = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let payload = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
    assert_eq!(payload, 0, "advertisement query sent an object payload");
    assert_eq!(bytes.len(), 20 + metadata);
    let request: Value = serde_json::from_slice(&bytes[20..]).unwrap();
    assert_eq!(request["version"], 1);
    assert_eq!(request["operation"], json!({"kind":"advertise"}));
    request
}
#[derive(Clone)]
struct Request {
    headers: String,
    metadata: Value,
}
struct Peer {
    address: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Peer {
    fn new(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        recorded.lock().unwrap().push(read_request(&mut stream));
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                        stream.write_all(&response).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixed query peer: {error}"),
                }
            }
        });
        Self {
            address,
            requests,
            stop,
            worker: Some(worker),
        }
    }
    fn url(&self) -> String {
        format!("http://{}/project.git", self.address)
    }
    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn read_request(stream: &mut TcpStream) -> Request {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
        assert!(header.len() <= 32768);
    }
    let headers = String::from_utf8(header).unwrap();
    assert!(headers.starts_with("POST /v1/uwgit HTTP/1.1\r\n"));
    let length = headers
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .unwrap()
        .1
        .trim()
        .parse::<usize>()
        .unwrap();
    assert!(length < 65536);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    Request {
        headers,
        metadata: decode_request(&body),
    }
}

#[test]
fn direct_queries_only_advertise_and_do_not_claim_to_verify_unavailable_objects() {
    let t = Temp::new();
    let peer = Peer::new(frame(&response(), &[]));
    let before = snapshot(&t.0);
    let output = command(&["ls-remote", &peer.url()])
        .current_dir(&t.0)
        .output()
        .unwrap();
    assert_eq!(
        success(output),
        format!("{A}\tHEAD\n{A}\trefs/heads/main\n{B}\trefs/heads/topic\n{A}\trefs/tags/v1\n")
    );
    let text = success(
        command(&["ls-remote", &peer.url(), "--json"])
            .current_dir(&t.0)
            .output()
            .unwrap(),
    );
    assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["advertised_only"], true);
    assert_eq!(report["objects_verified"], false);
    assert_eq!(report["unverified_objects"], true);
    assert_eq!(report["remote"], Value::Null);
    assert_eq!(report["references"].as_array().unwrap().len(), 4);
    assert_eq!(snapshot(&t.0), before);
    assert_eq!(peer.requests().len(), 2);
    assert!(peer
        .requests()
        .iter()
        .all(|request| request.metadata["repository"] == "project.git"));
}

#[test]
fn filters_tail_patterns_symbolic_head_and_no_match_status_have_exact_output() {
    let peer = Peer::new(frame(&response(), &[]));
    let url = peer.url();
    assert_eq!(
        run(&["ls-remote", &url, "--heads"]),
        format!("{A}\trefs/heads/main\n{B}\trefs/heads/topic\n")
    );
    assert_eq!(
        run(&["ls-remote", &url, "--branches"]),
        run(&["ls-remote", &url, "--heads"])
    );
    assert_eq!(
        run(&["ls-remote", &url, "--tags"]),
        format!("{A}\trefs/tags/v1\n")
    );
    assert_eq!(
        run(&["ls-remote", &url, "--heads", "--tags"]),
        format!("{A}\trefs/heads/main\n{B}\trefs/heads/topic\n{A}\trefs/tags/v1\n")
    );
    assert_eq!(
        run(&["ls-remote", &url, "--symref", "HEAD"]),
        format!("ref: refs/heads/main\tHEAD\n{A}\tHEAD\n")
    );
    let refs = run(&["ls-remote", &url, "--refs", "--symref"]);
    assert_eq!(
        refs,
        format!("{A}\trefs/heads/main\n{B}\trefs/heads/topic\n{A}\trefs/tags/v1\n")
    );
    assert_eq!(
        run(&["ls-remote", &url, "tags/v?"]),
        format!("{A}\trefs/tags/v1\n")
    );
    assert_eq!(
        run(&["ls-remote", &url, "*opic"]),
        format!("{B}\trefs/heads/topic\n")
    );
    assert_eq!(
        run(&["ls-remote", &url, "heads/main", "v1"]),
        format!("{A}\trefs/heads/main\n{A}\trefs/tags/v1\n")
    );
    assert_eq!(run(&["ls-remote", &url, "missing"]), "");
    let absent = command(&["ls-remote", &url, "--exit-code", "missing"])
        .output()
        .unwrap();
    assert_eq!(absent.status.code(), Some(2));
    assert!(absent.stdout.is_empty() && absent.stderr.is_empty());
    let absent = command(&["ls-remote", &url, "--json", "--exit-code", "missing"])
        .output()
        .unwrap();
    assert_eq!(absent.status.code(), Some(2));
    assert!(absent.stderr.is_empty());
    let report: Value = serde_json::from_slice(&absent.stdout).unwrap();
    assert_eq!(report["references"], json!([]));
}

#[test]
fn configured_remote_query_ignores_objects_tracking_and_existing_local_locks_without_writing() {
    let t = Temp::new();
    let repo = t.repo();
    let peer = Peer::new(frame(&response(), &[]));
    run(&["remote", s(&repo), "add", "origin", &peer.url()]);
    fs::write(
        repo.join(".uwgit/objects/not-an-object"),
        b"unrelated broken local store",
    )
    .unwrap();
    fs::write(
        repo.join(".uwgit/remotes/origin.tracking.json"),
        b"unrelated broken tracking",
    )
    .unwrap();
    for lock in ["write.lock", "remote.lock", "index.lock"] {
        fs::write(repo.join(".uwgit").join(lock), b"external owner").unwrap();
    }
    let before = snapshot(&repo);
    let report: Value = serde_json::from_str(&run(&["ls-remote", s(&repo), "--json"])).unwrap();
    assert_eq!(report["remote"], "origin");
    assert_eq!(
        run(&["ls-remote", s(&repo), "origin", "main"]),
        format!("{A}\trefs/heads/main\n")
    );
    assert_eq!(snapshot(&repo), before);
    assert_eq!(peer.requests().len(), 2);
}

#[test]
fn missing_or_invalid_configuration_never_creates_metadata_or_repairs_inputs() {
    let t = Temp::new();
    let repo = t.repo();
    let before = snapshot(&repo);
    let missing = command(&["ls-remote", s(&repo)]).output().unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stdout.is_empty());
    assert_eq!(snapshot(&repo), before);
    assert!(!repo.join(".uwgit/remotes").exists());
    fs::create_dir(repo.join(".uwgit/remotes")).unwrap();
    for contents in [
        b"invalid JSON".as_slice(),
        br#"{"version":2,"name":"origin","url":"http://localhost/x","allow_insecure_http":false}"#,
        br#"{"version":1,"name":"wrong","url":"http://localhost/x","allow_insecure_http":false}"#,
        br#"{"version":1,"name":"origin","url":"file:///tmp/x","allow_insecure_http":false}"#,
    ] {
        fs::write(repo.join(".uwgit/remotes/origin.json"), contents).unwrap();
        let before = snapshot(&repo);
        let output = command(&["ls-remote", s(&repo)]).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(snapshot(&repo), before);
    }
    fs::write(
        repo.join(".uwgit/remotes/origin.json"),
        vec![b' '; 1024 * 1024 + 1],
    )
    .unwrap();
    let before = snapshot(&repo);
    let output = command(&["ls-remote", s(&repo)]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(snapshot(&repo), before);
}

#[cfg(unix)]
#[test]
fn symlinked_remote_configuration_is_rejected_without_following_it_or_writing() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    let repo = t.repo();
    let peer = Peer::new(frame(&response(), &[]));
    let outside = t.path("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(
        outside.join("origin.json"),
        serde_json::to_vec(&json!({
            "version":1,"name":"origin","url":peer.url(),"allow_insecure_http":false
        }))
        .unwrap(),
    )
    .unwrap();
    let remotes = repo.join(".uwgit/remotes");
    fs::create_dir(&remotes).unwrap();
    symlink(outside.join("origin.json"), remotes.join("origin.json")).unwrap();
    let before = snapshot(&repo);
    let output = command(&["ls-remote", s(&repo)]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(snapshot(&repo), before);
    fs::remove_file(remotes.join("origin.json")).unwrap();
    fs::remove_dir(&remotes).unwrap();
    symlink(&outside, &remotes).unwrap();
    let before = snapshot(&repo);
    let output = command(&["ls-remote", s(&repo)]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(snapshot(&repo), before);
    assert!(peer.requests().is_empty());
}

#[test]
fn malformed_advertisements_and_nonempty_frames_fail_without_local_side_effects() {
    let t = Temp::new();
    let mut cases = Vec::new();
    cases.push(frame(&response(), b"unexpected object bytes"));
    let mut trailing = frame(&response(), &[]);
    trailing.push(0);
    cases.push(trailing);
    for (key, value) in [
        ("version", json!(2)),
        ("tip", json!(A)),
        ("state", Value::Null),
        ("ok", json!(false)),
        ("error", json!("inconsistent success")),
        ("publication_unknown", json!(true)),
    ] {
        let mut modified = response();
        modified[key] = value;
        cases.push(frame(&modified, &[]));
    }
    for (key, value) in [
        ("format", json!(2)),
        ("head", json!("refs/heads/main")),
        ("branches", json!({"main":"invalid ID"})),
        ("unexpected", json!(true)),
    ] {
        let mut modified = response();
        modified["state"][key] = value;
        cases.push(frame(&modified, &[]));
    }
    let duplicate = serde_json::to_string(&response()).unwrap().replacen(
        &format!("\"main\":\"{A}\""),
        &format!("\"main\":\"{A}\",\"main\":\"{B}\""),
        1,
    );
    cases.push(frame_json(duplicate.as_bytes(), &[]));
    for bytes in cases {
        let peer = Peer::new(bytes);
        let before = snapshot(&t.0);
        let output = command(&["ls-remote", &peer.url()])
            .current_dir(&t.0)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(snapshot(&t.0), before);
        assert_eq!(peer.requests().len(), 1);
    }
}

#[test]
fn invalid_options_and_patterns_fail_before_contacting_the_remote() {
    let peer = Peer::new(frame(&response(), &[]));
    let url = peer.url();
    let long = "x".repeat(1025);
    for tail in [
        vec!["--json", "--json"],
        vec!["--heads", "--branches"],
        vec!["--unknown"],
        vec!["[main]"],
        vec!["main\\*"],
        vec!["bad\nname"],
        vec![&long],
    ] {
        let mut args = vec!["ls-remote", &url];
        args.extend(tail);
        let output = command(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty());
    }
    assert!(run(&["ls-remote", "--help"]).contains("no objects are downloaded"));
    assert!(peer.requests().is_empty());
}

#[test]
fn unborn_head_has_a_symbolic_target_but_no_fabricated_id_or_matching_id_exit() {
    let mut empty = response();
    empty["state"]["branches"] = json!({});
    empty["state"]["tags"] = json!({});
    let peer = Peer::new(frame(&empty, &[]));
    let url = peer.url();
    assert_eq!(run(&["ls-remote", &url]), "");
    let symbolic = command(&["ls-remote", &url, "--symref", "--exit-code"])
        .output()
        .unwrap();
    assert_eq!(symbolic.status.code(), Some(2));
    assert_eq!(symbolic.stdout, b"ref: refs/heads/main\tHEAD\n");
    assert!(symbolic.stderr.is_empty());
    assert_eq!(run(&["ls-remote", &url, "--symref", "--refs"]), "");
    let report: Value =
        serde_json::from_str(&run(&["ls-remote", &url, "--json", "--symref"])).unwrap();
    assert_eq!(report["head_tip"], Value::Null);
    assert_eq!(report["references"], json!([]));
    assert_eq!(
        report["symbolic_refs"],
        json!([{"name":"HEAD","target":"refs/heads/main"}])
    );
}

#[test]
fn http_query_uses_the_existing_private_token_and_safe_cleartext_policy() {
    let peer = Peer::new(frame(&response(), &[]));
    success(
        command(&["ls-remote", &peer.url(), "--allow-insecure-http"])
            .env("UWGIT_REMOTE_TOKEN", "fixed-query-token")
            .output()
            .unwrap(),
    );
    assert!(peer.requests()[0]
        .headers
        .to_ascii_lowercase()
        .contains("authorization: bearer fixed-query-token\r\n"));
    let denied = command(&["ls-remote", "http://192.0.2.1/project.git"])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(1));
    assert!(String::from_utf8(denied.stderr)
        .unwrap()
        .contains("requires --allow-insecure-http"));
    let invalid = command(&["ls-remote", &peer.url()])
        .env("UWGIT_REMOTE_TOKEN", "bad\ntoken")
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(1));
    assert_eq!(peer.requests().len(), 1);
}

#[cfg(unix)]
#[test]
fn ssh_query_preserves_safe_arguments_and_sends_only_the_advertise_frame() {
    use std::os::unix::fs::PermissionsExt;
    let t = Temp::new();
    let shim = t.path("ssh-query");
    let reply = t.path("response");
    let request = t.path("request");
    let argv = t.path("arguments");
    fs::write(&reply, frame(&response(), &[])).unwrap();
    fs::write(&shim, b"#!/bin/sh\nset -eu\ntest -z \"${UWGIT_REMOTE_TOKEN+x}\"\nprintf '%s\\n' \"$@\" > \"$UWGIT_QUERY_ARGV\"\ncat > \"$UWGIT_QUERY_REQUEST\"\ncat \"$UWGIT_QUERY_REPLY\"\n").unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
    let output = command(&[
        "ls-remote",
        "ssh://query@localhost:2222/tmp/query'root/project.git",
        "--heads",
    ])
    .env("UWGIT_SSH_PROGRAM", &shim)
    .env("UWGIT_REMOTE_PROGRAM", "program with ' quote")
    .env("UWGIT_QUERY_ARGV", &argv)
    .env("UWGIT_QUERY_REQUEST", &request)
    .env("UWGIT_QUERY_REPLY", &reply)
    .env("UWGIT_REMOTE_TOKEN", "must-not-reach-ssh")
    .output()
    .unwrap();
    assert_eq!(
        success(output),
        format!("{A}\trefs/heads/main\n{B}\trefs/heads/topic\n")
    );
    assert_eq!(
        decode_request(&fs::read(request).unwrap())["repository"],
        "project.git"
    );
    let args = fs::read_to_string(argv).unwrap();
    assert!(args.starts_with(
        "-T\n-o\nBatchMode=yes\n-o\nConnectTimeout=10\n-p\n2222\n--\nquery@localhost\n"
    ));
    assert!(args.contains("'program with '\\'' quote' server --stdio --root '/tmp/query'\\''root'"));
    assert!(!args.contains("must-not-reach-ssh"));
    assert!(!t.path(".uwgit").exists());
}
