//! Fixed remote workflows. The bridge retains real framed stdio server behavior;
//! it only supplies the HTTP envelope, so client transport and repository receive
//! semantics are exercised together without an external service or credentials.
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = PathBuf::from("/tmp").join(format!(
            "uwgit-remotes-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&run(args)).unwrap()
}
fn failure(args: &[&str]) -> String {
    let output = command(args).output().unwrap();
    assert!(!output.status.success(), "unexpected success: {args:?}");
    String::from_utf8(output.stderr).unwrap()
}
fn wasm(path: &str, value: u8) {
    // A valid MVP module followed by an unknown custom section named x. The
    // original bytes are significant even though the core validator ignores x.
    std::fs::write(
        path,
        [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat(),
    )
    .unwrap();
}
fn tip(root: &str, revision: &str) -> String {
    json(&["show", root, revision])["id"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn stdio(root: &Path, packet: &[u8]) -> Vec<u8> {
    let mut child = command(&[
        "server",
        "--stdio",
        "--root",
        root.to_str().unwrap(),
        "--allow-force",
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child.stdin.take().unwrap().write_all(packet).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
#[derive(Clone, Copy)]
enum Alter {
    None,
    Trailing,
    StateMismatch,
    UpdateTrailing,
    PublicationUnknown,
    InvalidSuccessUnknown,
}
struct Bridge {
    address: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Bridge {
    fn new(root: &Path, token: Option<&str>, alter: Alter) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let root = root.to_owned();
        let token = token.map(str::to_owned);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let packet = read_http(&mut stream, token.as_deref());
                        let mut response = stdio(&root, &packet);
                        match alter {
                            Alter::None => {}
                            Alter::Trailing => response.push(0x5a),
                            Alter::UpdateTrailing => {
                                let length =
                                    u32::from_be_bytes(packet[8..12].try_into().unwrap()) as usize;
                                let metadata: Value =
                                    serde_json::from_slice(&packet[20..20 + length]).unwrap();
                                if metadata["operation"]["kind"] == "update_ref" {
                                    response.push(0x5a);
                                }
                            }
                            Alter::PublicationUnknown | Alter::InvalidSuccessUnknown => {
                                let request_length =
                                    u32::from_be_bytes(packet[8..12].try_into().unwrap()) as usize;
                                let request: Value =
                                    serde_json::from_slice(&packet[20..20 + request_length])
                                        .unwrap();
                                if request["operation"]["kind"] == "update_ref" {
                                    let length =
                                        u32::from_be_bytes(response[8..12].try_into().unwrap())
                                            as usize;
                                    let mut metadata: Value =
                                        serde_json::from_slice(&response[20..20 + length]).unwrap();
                                    metadata["publication_unknown"] = true.into();
                                    if matches!(alter, Alter::PublicationUnknown) {
                                        metadata["ok"] = false.into();
                                        metadata["error"] =
                                            "fixed post-publication I/O failure".into();
                                    }
                                    let encoded = serde_json::to_vec(&metadata).unwrap();
                                    let mut changed = response[..8].to_vec();
                                    changed
                                        .extend_from_slice(&(encoded.len() as u32).to_be_bytes());
                                    changed.extend_from_slice(&response[12..20]);
                                    changed.extend_from_slice(&encoded);
                                    changed.extend_from_slice(&response[20 + length..]);
                                    response = changed;
                                }
                            }
                            Alter::StateMismatch => {
                                assert_eq!(&response[..8], b"UWGRPC01");
                                let length = u32::from_be_bytes(response[8..12].try_into().unwrap())
                                    as usize;
                                let mut metadata: Value =
                                    serde_json::from_slice(&response[20..20 + length]).unwrap();
                                metadata["state"]["head"] = "different".into();
                                let encoded = serde_json::to_vec(&metadata).unwrap();
                                let mut changed = response[..8].to_vec();
                                changed.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
                                changed.extend_from_slice(&response[12..20]);
                                changed.extend_from_slice(&encoded);
                                changed.extend_from_slice(&response[20 + length..]);
                                response = changed;
                            }
                        }
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                        stream.write_all(&response).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("HTTP bridge: {e}"),
                }
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }
    fn url(&self, repository: &str) -> String {
        format!("http://{}/{repository}", self.address)
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn read_http(stream: &mut TcpStream, token: Option<&str>) -> Vec<u8> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
        assert!(header.len() < 32768);
    }
    let header = String::from_utf8(header).unwrap();
    assert!(header.starts_with("POST /v1/uwgit HTTP/1.1\r\n"));
    let fields: Vec<_> = header
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim()))
        .collect();
    let length: usize = fields
        .iter()
        .find(|(key, _)| key == "content-length")
        .unwrap()
        .1
        .parse()
        .unwrap();
    assert!(length < 1024 * 1024);
    let authorization = fields
        .iter()
        .find(|(key, _)| key == "authorization")
        .map(|(_, value)| *value);
    let expected = token.map(|token| format!("Bearer {token}"));
    assert_eq!(authorization, expected.as_deref());
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet).unwrap();
    packet
}

#[test]
fn named_remote_configuration_is_strict_and_reversible() {
    let temp = Temp::new();
    let repo = temp.path("repo");
    run(&["init", &repo]);
    assert_eq!(json(&["remote", &repo]), serde_json::json!([]));
    run(&["remote", &repo, "add", "origin", "https://example.org/repo"]);
    assert!(
        failure(&["remote", &repo, "add", "origin", "https://example.org/repo"])
            .contains("already exists")
    );
    run(&["remote", &repo, "rename", "origin", "upstream"]);
    let shown = json(&["remote", &repo, "show", "upstream"]);
    assert_eq!(shown["remote"]["url"], "https://example.org/repo");
    assert_eq!(shown["tracking"], Value::Null);
    assert!(failure(&[
        "remote",
        &repo,
        "add",
        "bad",
        "http://user:password@host/repo"
    ])
    .contains("user"));
    assert!(failure(&[
        "remote",
        &repo,
        "add",
        "../outside",
        "https://example.org/repo"
    ])
    .contains("names"));
    run(&["remote", &repo, "remove", "upstream"]);
    assert_eq!(json(&["remote", &repo, "-v"]), serde_json::json!([]));
    run(&[
        "remote",
        &repo,
        "add",
        "origin",
        "http://example.invalid/repo",
    ]);
    assert!(failure(&["fetch", &repo]).contains("--allow-insecure-http"));
    let path = Path::new(&repo).join(".uwgit/remotes/origin.json");
    let mut metadata: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    metadata["unexpected"] = true.into();
    std::fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert!(failure(&["remote", &repo, "show", "origin"]).contains("unknown field"));
}

#[test]
fn http_clone_fetch_pull_push_and_explicit_force_lease_preserve_history() {
    let temp = Temp::new();
    let upstream = temp.path("upstream");
    let local = temp.path("local");
    let module = temp.path("input.wasm");
    wasm(&module, 1);
    run(&["init", &upstream]);
    run(&["commit", &upstream, &module, "-m", "base"]);
    run(&["branch", &upstream, "feature"]);
    run(&["tag", &upstream, "v1"]);
    let initial = tip(&upstream, "HEAD");
    let bridge = Bridge::new(&temp.0, None, Alter::None);
    let url = bridge.url("upstream");
    run(&["clone", &url, &local]);
    assert_eq!(tip(&local, "HEAD"), initial);
    assert_eq!(tip(&local, "feature"), initial);
    assert_eq!(tip(&local, "v1"), initial);
    wasm(&module, 2);
    run(&["commit", &upstream, &module, "-m", "remote next"]);
    let remote_next = tip(&upstream, "HEAD");
    run(&["fetch", &local]);
    assert_eq!(tip(&local, "HEAD"), initial);
    assert_eq!(tip(&local, "origin/main"), remote_next);
    let pulled = json(&["pull", &local, "origin", "main", "-m", "integrate"]);
    assert_eq!(pulled["status"], "fast_forward");
    assert_eq!(tip(&local, "HEAD"), remote_next);
    wasm(&module, 3);
    run(&["commit", &local, &module, "-m", "local next"]);
    let local_next = tip(&local, "HEAD");
    run(&["push", &local]);
    assert_eq!(tip(&upstream, "HEAD"), local_next);
    wasm(&module, 4);
    run(&["commit", &upstream, &module, "-m", "diverge remote"]);
    let divergence = tip(&upstream, "HEAD");
    wasm(&module, 5);
    run(&["commit", &local, &module, "-m", "diverge local"]);
    let final_local = tip(&local, "HEAD");
    assert!(failure(&["push", &local]).contains("non-fast-forward"));
    assert_eq!(tip(&upstream, "HEAD"), divergence);
    let conflict = command(&[
        "pull",
        &local,
        "origin",
        "main",
        "-m",
        "conflict stays explicit",
    ])
    .output()
    .unwrap();
    assert_eq!(
        conflict.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&conflict.stderr)
    );
    let report: Value = serde_json::from_slice(&conflict.stdout).unwrap();
    assert_eq!(report["status"], "conflict");
    assert_eq!(tip(&local, "HEAD"), final_local);
    assert!(failure(&["push", &local, "--force-with-lease", &initial]).contains("expectation"));
    run(&["push", &local, "--force-with-lease", &divergence]);
    assert_eq!(tip(&upstream, "HEAD"), final_local);
    run(&[
        "push",
        &local,
        "origin",
        "feature:publication",
        "--force-with-lease",
        "absent",
    ]);
    assert_eq!(tip(&upstream, "publication"), initial);
    let metadata =
        std::fs::read_to_string(Path::new(&local).join(".uwgit/remotes/origin.json")).unwrap();
    assert!(!metadata.contains("Authorization"));
    run(&["fsck", &local]);
    run(&["fsck", &upstream]);
}

#[test]
fn tag_push_reports_partial_results_and_remote_deletion_uses_exact_leases() {
    let temp = Temp::new();
    let upstream = temp.path("upstream");
    let local = temp.path("local");
    let module = temp.path("input.wasm");
    wasm(&module, 1);
    run(&["init", &upstream]);
    run(&["commit", &upstream, &module, "-m", "base"]);
    let initial = tip(&upstream, "HEAD");
    let bridge = Bridge::new(&temp.0, None, Alter::None);
    run(&["clone", &bridge.url("upstream"), &local]);
    wasm(&module, 2);
    run(&["commit", &local, &module, "-m", "next"]);
    let next = tip(&local, "HEAD");
    run(&["push", &local]);
    run(&["tag", &local, "release"]);
    run(&[
        "push",
        &local,
        "origin",
        "refs/tags/release:refs/tags/remote_release",
    ]);
    assert_eq!(tip(&upstream, "refs/tags/remote_release"), next);
    run(&["tag", &local, "a_published"]);
    run(&["tag", &local, "z_conflict", &initial]);
    run(&["tag", &upstream, "z_conflict"]);
    let output = command(&["push", &local, "origin", "--tags"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "partial");
    assert_eq!(report["atomic"], false);
    let updates = report["updates"].as_array().unwrap();
    assert_eq!(
        updates
            .iter()
            .find(|value| value["name"] == "a_published")
            .unwrap()["status"],
        "pushed"
    );
    assert_eq!(
        updates
            .iter()
            .find(|value| value["name"] == "z_conflict")
            .unwrap()["status"],
        "rejected"
    );
    assert_eq!(tip(&upstream, "refs/tags/a_published"), next);
    assert_eq!(tip(&upstream, "refs/tags/z_conflict"), next);
    run(&[
        "push",
        &local,
        "origin",
        "refs/tags/z_conflict:refs/tags/z_conflict",
        "--force-with-lease",
        &next,
    ]);
    assert_eq!(tip(&upstream, "refs/tags/z_conflict"), initial);
    assert!(failure(&[
        "push",
        &local,
        "origin",
        "--delete",
        "refs/tags/remote_release",
        "--force-with-lease",
        &initial
    ])
    .contains("expectation"));
    run(&[
        "push",
        &local,
        "origin",
        "--delete",
        "refs/tags/remote_release",
    ]);
    assert!(failure(&["show", &upstream, "refs/tags/remote_release"]).contains("unknown revision"));
    run(&["push", &local, "origin", "HEAD:refs/heads/temporary"]);
    run(&["push", &local, "--delete", "temporary"]);
    assert!(failure(&["show", &upstream, "refs/heads/temporary"]).contains("unknown revision"));
    assert!(failure(&["push", &local, "origin", "--delete", "main"]).contains("checked-out"));
    assert_eq!(tip(&upstream, "HEAD"), next);
    run(&["fsck", &upstream]);
}

#[test]
fn unknown_tag_acknowledgement_preserves_uncertainty_and_stops_later_publication() {
    let temp = Temp::new();
    let upstream = temp.path("upstream");
    let local = temp.path("local");
    let module = temp.path("input.wasm");
    wasm(&module, 1);
    run(&["init", &upstream]);
    run(&["commit", &upstream, &module, "-m", "base"]);
    let bridge = Bridge::new(&temp.0, None, Alter::None);
    run(&["clone", &bridge.url("upstream"), &local]);
    run(&["tag", &local, "a_first"]);
    run(&["tag", &local, "z_not_attempted"]);
    let faulty = Bridge::new(&temp.0, None, Alter::UpdateTrailing);
    run(&["remote", &local, "add", "faulty", &faulty.url("upstream")]);
    let output = command(&["push", &local, "faulty", "--tags"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "unknown");
    let updates = report["updates"].as_array().unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0]["name"], "a_first");
    assert_eq!(updates[0]["status"], "unknown");
    assert_eq!(updates[1]["name"], "z_not_attempted");
    assert_eq!(updates[1]["status"], "not_attempted");
    // The acknowledgement was corrupt after a real publication. Calling this
    // rejection would mislead a retrying user about an already visible tag.
    assert_eq!(tip(&upstream, "refs/tags/a_first"), tip(&local, "HEAD"));
    assert!(failure(&["show", &upstream, "refs/tags/z_not_attempted"]).contains("unknown revision"));
}

#[test]
fn typed_publication_uncertainty_and_invalid_success_both_stop_tag_push() {
    for alteration in [Alter::PublicationUnknown, Alter::InvalidSuccessUnknown] {
        let temp = Temp::new();
        let upstream = temp.path("upstream");
        let local = temp.path("local");
        let module = temp.path("input.wasm");
        wasm(&module, 1);
        run(&["init", &upstream]);
        run(&["commit", &upstream, &module, "-m", "base"]);
        let bridge = Bridge::new(&temp.0, None, alteration);
        run(&["clone", &bridge.url("upstream"), &local]);
        run(&["tag", &local, "a_first"]);
        run(&["tag", &local, "z_not_attempted"]);
        let output = command(&["push", &local, "--tags"]).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["status"], "unknown");
        let updates = report["updates"].as_array().unwrap();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0]["status"], "unknown");
        assert!(updates[0]["error"]
            .as_str()
            .unwrap()
            .starts_with("remote publication outcome is unknown:"));
        assert_eq!(updates[1]["status"], "not_attempted");
        assert_eq!(tip(&upstream, "refs/tags/a_first"), tip(&local, "HEAD"));
        assert!(
            failure(&["show", &upstream, "refs/tags/z_not_attempted"]).contains("unknown revision")
        );
    }
}

#[test]
fn empty_http_clone_authentication_and_rejected_response_leave_no_destination() {
    let temp = Temp::new();
    let upstream = temp.path("upstream");
    run(&["init", &upstream]);
    let bridge = Bridge::new(&temp.0, Some("fixed-private-token"), Alter::None);
    let url = bridge.url("upstream");
    let destination = temp.path("empty-clone");
    success(
        command(&["clone", &url, &destination])
            .env("UWGIT_REMOTE_TOKEN", "fixed-private-token")
            .output()
            .unwrap(),
    );
    assert_eq!(json(&["fsck", &destination])["commits"], 0);
    assert_eq!(
        std::fs::read(Path::new(&destination).join(".uwgit/HEAD")).unwrap(),
        b"main\n"
    );
    drop(bridge);
    for (index, alteration) in [Alter::Trailing, Alter::StateMismatch]
        .into_iter()
        .enumerate()
    {
        let bridge = Bridge::new(&temp.0, None, alteration);
        let destination = temp.path(&format!("rejected-{index}"));
        let error = failure(&["clone", &bridge.url("upstream"), &destination]);
        assert!(
            error.contains(if index == 0 {
                "trailing"
            } else {
                "advertisement"
            }),
            "{error}"
        );
        assert!(!Path::new(&destination).exists());
    }
}

#[test]
fn invalid_http_tokens_are_rejected_before_network_or_destination_creation() {
    let temp = Temp::new();
    let inputs = [
        String::new(),
        "bad\nheader".into(),
        "non_ascii_令牌".into(),
        "a".repeat(4097),
    ];
    for (index, token) in inputs.into_iter().enumerate() {
        let destination = temp.path(&format!("invalid-token-{index}"));
        // Port 1 supplies no test service. A token error, rather than a transport
        // connection error, proves malformed authentication never starts curl.
        let output = command(&["clone", "http://127.0.0.1:1/upstream", &destination])
            .env("UWGIT_REMOTE_TOKEN", token)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("1..4096 printable ASCII"), "{error}");
        assert!(!Path::new(&destination).exists());
    }
}

#[cfg(unix)]
#[test]
fn ssh_transport_passes_safe_arguments_and_never_forwards_the_http_token() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new();
    let root = temp.path("quote'root");
    std::fs::create_dir(&root).unwrap();
    let upstream = Path::new(&root)
        .join("upstream")
        .to_string_lossy()
        .into_owned();
    let local = temp.path("local");
    let module = temp.path("input.wasm");
    wasm(&module, 1);
    run(&["init", &upstream]);
    run(&["commit", &upstream, &module, "-m", "over ssh"]);
    let shim = temp.path("ssh-shim");
    let log = temp.path("ssh-argv");
    std::fs::write(&shim, b"#!/bin/sh\nset -eu\ntest -z \"${UWGIT_REMOTE_TOKEN+x}\"\nprintf '%s\\n' \"$@\" > \"$UWGIT_TEST_SSH_LOG\"\nexec \"$UWGIT_TEST_BINARY\" server --stdio --root \"$UWGIT_TEST_ROOT\" --allow-force\n").unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let url = format!("ssh://test@localhost:2222{root}/upstream");
    success(
        command(&["clone", &url, &local])
            .env("UWGIT_SSH_PROGRAM", &shim)
            .env("UWGIT_REMOTE_PROGRAM", "path with ' quote")
            .env("UWGIT_TEST_BINARY", env!("CARGO_BIN_EXE_wasm-git"))
            .env("UWGIT_TEST_ROOT", &root)
            .env("UWGIT_TEST_SSH_LOG", &log)
            .env("UWGIT_REMOTE_TOKEN", "must-never-reach-ssh")
            .output()
            .unwrap(),
    );
    assert_eq!(tip(&local, "HEAD"), tip(&upstream, "HEAD"));
    let arguments = std::fs::read_to_string(log).unwrap();
    assert!(arguments.starts_with(
        "-T\n-o\nBatchMode=yes\n-o\nConnectTimeout=10\n-p\n2222\n--\ntest@localhost\n"
    ));
    assert!(arguments.contains("'path with '\\'' quote' server --stdio --root '"));
    assert!(arguments.contains("quote'\\''root'"));
    assert!(!arguments.contains("must-never-reach-ssh"));
}

#[test]
fn literal_help_and_transport_flag_messages_survive_pull_option_parsing() {
    let module_bytes = |left: i32, right: i32| {
        wat::parse_str(format!(
            "(module (func (result i32) i32.const {left}) (func (result i32) i32.const {right}))"
        ))
        .unwrap()
    };
    for (message, message_flag, real_transport_flag) in [
        ("--help", "-m", false),
        ("-h", "--message", false),
        ("--allow-insecure-http", "-m", false),
        ("--allow-insecure-http", "--message", true),
    ] {
        let temp = Temp::new();
        let upstream = temp.path("upstream");
        let local = temp.path("local");
        let module = temp.path("input.wasm");
        std::fs::write(&module, module_bytes(0, 0)).unwrap();
        run(&["init", &upstream]);
        run(&["commit", &upstream, &module, "-m", "base"]);
        let bridge = Bridge::new(&temp.0, None, Alter::None);
        run(&["clone", &bridge.url("upstream"), &local]);
        std::fs::write(&module, module_bytes(0, 2)).unwrap();
        run(&[
            "commit",
            &upstream,
            &module,
            "-m",
            "upstream changes second function",
        ]);
        let theirs = tip(&upstream, "HEAD");
        std::fs::write(&module, module_bytes(1, 0)).unwrap();
        run(&[
            "commit",
            &local,
            &module,
            "-m",
            "local changes first function",
        ]);
        let ours = tip(&local, "HEAD");
        let mut args = vec!["pull", &local, "origin", "main", message_flag, message];
        if real_transport_flag {
            args.push("--allow-insecure-http");
        }
        let report = json(&args);
        assert_eq!(report["status"], "merged", "{message}");
        let info = json(&["show", &local, "HEAD"]);
        assert_eq!(info["message"], message);
        assert_eq!(info["parents"], serde_json::json!([ours, theirs]));
        let exported = temp.path("merged.wasm");
        run(&["show", &local, "HEAD", "--output", &exported]);
        assert_eq!(std::fs::read(&exported).unwrap(), module_bytes(1, 2));
        let before_help = tip(&local, "HEAD");
        let help = run(&["pull", &local, "--help"]);
        assert!(help.contains("pull <DIR>"));
        assert_eq!(tip(&local, "HEAD"), before_help);
    }
}

#[cfg(unix)]
#[test]
fn ssh_clone_accepts_server_repository_names_without_widening_remote_config_names() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new();
    let shim = temp.path("repository-name-ssh");
    std::fs::write(&shim, b"#!/bin/sh\nset -eu\nexec \"$UWGIT_NAME_TEST_BINARY\" server --stdio --root \"$UWGIT_NAME_TEST_ROOT\"\n").unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (index, name) in ["project.git".to_owned(), "r".repeat(65), "s".repeat(128)]
        .iter()
        .enumerate()
    {
        let project = temp.path(name);
        let module = temp.path("named-input.wasm");
        wasm(&module, (index + 1) as u8);
        let expected = std::fs::read(&module).unwrap();
        run(&["init", &project]);
        run(&[
            "commit",
            &project,
            &module,
            "-m",
            "original named repository bytes",
        ]);
        let initial = tip(&project, "HEAD");
        let local = temp.path(&format!("named-clone-{index}"));
        let url = format!("ssh://test@localhost{}/{name}", temp.0.display());
        success(
            command(&["clone", &url, &local])
                .env("UWGIT_SSH_PROGRAM", &shim)
                .env("UWGIT_NAME_TEST_BINARY", env!("CARGO_BIN_EXE_wasm-git"))
                .env("UWGIT_NAME_TEST_ROOT", &temp.0)
                .output()
                .unwrap(),
        );
        assert_eq!(tip(&local, "HEAD"), initial);
        let exported = temp.path(&format!("named-export-{index}.wasm"));
        run(&["show", &local, "HEAD", "--output", &exported]);
        assert_eq!(std::fs::read(exported).unwrap(), expected);
        run(&["fsck", &local]);
        if index == 0 {
            assert!(failure(&["remote", &local, "add", &"n".repeat(65), &url]).contains("names"));
        }
    }
}

#[test]
fn default_pull_tracks_the_current_branch_and_missing_peer_branch_keeps_local_files() {
    let temp = Temp::new();
    let upstream = temp.path("upstream");
    let producer = temp.path("producer");
    let consumer = temp.path("consumer");
    run(&["init", &upstream]);
    let upstream_file = Path::new(&upstream).join("module.wasm");
    wasm(upstream_file.to_str().unwrap(), 1);
    run(&["add", &upstream, "module.wasm"]);
    run(&["commit", &upstream, "-m", "base tree on main and feature"]);
    run(&["branch", &upstream, "feature"]);
    let base = tip(&upstream, "HEAD");
    let bridge = Bridge::new(&temp.0, None, Alter::None);
    let url = bridge.url("upstream");
    for repository in [&producer, &consumer] {
        run(&["clone", &url, repository]);
        run(&["switch", repository, "feature"]);
        run(&[
            "restore",
            repository,
            "--source",
            "HEAD",
            "--staged",
            "--worktree",
        ]);
    }
    let producer_file = Path::new(&producer).join("module.wasm");
    wasm(producer_file.to_str().unwrap(), 2);
    run(&["add", &producer, "module.wasm"]);
    run(&[
        "commit",
        &producer,
        "-m",
        "advance only the remote feature branch",
    ]);
    let feature_tip = tip(&producer, "HEAD");
    run(&["push", &producer]);
    assert_eq!(tip(&upstream, "HEAD"), base);
    assert_eq!(tip(&upstream, "feature"), feature_tip);
    let pulled = json(&["pull", &consumer, "-m", "follow the current feature branch"]);
    assert_eq!(pulled["status"], "fast_forward");
    assert_eq!(pulled["target"], feature_tip);
    assert_eq!(tip(&consumer, "HEAD"), feature_tip);
    assert_eq!(tip(&consumer, "main"), base);
    let consumer_file = Path::new(&consumer).join("module.wasm");
    assert_eq!(
        std::fs::read(&consumer_file).unwrap(),
        std::fs::read(&producer_file).unwrap()
    );

    run(&["switch", &consumer, "-c", "local_only"]);
    let head_path = Path::new(&consumer).join(".uwgit/HEAD");
    let index_path = Path::new(&consumer).join(".uwgit/index");
    let local_ref = Path::new(&consumer).join(".uwgit/refs/local_only");
    let before = (
        std::fs::read(&head_path).unwrap(),
        std::fs::read(&index_path).unwrap(),
        std::fs::read(&local_ref).unwrap(),
        std::fs::read(&consumer_file).unwrap(),
    );
    wasm(producer_file.to_str().unwrap(), 3);
    run(&["add", &producer, "module.wasm"]);
    run(&["commit", &producer, "-m", "another remote feature update"]);
    let latest = tip(&producer, "HEAD");
    run(&["push", &producer]);
    let rejected = command(&[
        "pull",
        &consumer,
        "origin",
        "-m",
        "do not guess the remote HEAD branch",
    ])
    .output()
    .unwrap();
    assert_eq!(rejected.status.code(), Some(1));
    let reason = String::from_utf8(rejected.stderr).unwrap();
    assert!(
        reason.contains("local_only") && reason.contains("specify BRANCH"),
        "{reason}"
    );
    assert_eq!(tip(&consumer, "HEAD"), feature_tip);
    assert_eq!(tip(&consumer, "origin/feature"), latest);
    assert_eq!(
        (
            std::fs::read(&head_path).unwrap(),
            std::fs::read(&index_path).unwrap(),
            std::fs::read(&local_ref).unwrap(),
            std::fs::read(&consumer_file).unwrap(),
        ),
        before
    );
    let explicit = json(&[
        "pull",
        &consumer,
        "origin",
        "main",
        "-m",
        "explicitly select server main",
    ]);
    assert_eq!(explicit["status"], "already_up_to_date");
    assert_eq!(explicit["target"], base);
    assert_eq!(tip(&consumer, "HEAD"), feature_tip);
    assert_eq!(
        (
            std::fs::read(&head_path).unwrap(),
            std::fs::read(&index_path).unwrap(),
            std::fs::read(&local_ref).unwrap(),
            std::fs::read(&consumer_file).unwrap(),
        ),
        before
    );
    for repository in [&upstream, &producer, &consumer] {
        run(&["fsck", repository]);
    }
}

// Only the old fetch response is delayed. The listener stays available so a
// second fetch can publish its newer tracking before the first is released.
struct FetchBarrierBridge {
    address: String,
    captured: std::sync::mpsc::Receiver<()>,
    release: Option<std::sync::mpsc::Sender<()>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl FetchBarrierBridge {
    fn new(root: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let root = root.to_owned();
        let (captured_sender, captured) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = thread::spawn(move || {
            let mut request_index = 0;
            let mut released = Some(released);
            let mut delayed = None;
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let packet = read_http(&mut stream, None);
                        let response = stdio(&root, &packet);
                        if request_index == 1 {
                            // Request zero was the clone. Capture the next fetch
                            // completely before allowing the upstream to change.
                            let length =
                                u32::from_be_bytes(packet[8..12].try_into().unwrap()) as usize;
                            let metadata: Value =
                                serde_json::from_slice(&packet[20..20 + length]).unwrap();
                            assert_eq!(metadata["operation"]["kind"], "fetch");
                            let released = released.take().unwrap();
                            let captured_sender = captured_sender.clone();
                            delayed = Some(thread::spawn(move || {
                                captured_sender.send(()).unwrap();
                                released
                                    .recv_timeout(Duration::from_secs(25))
                                    .expect("old fetch response was not released");
                                Self::respond(&mut stream, &response);
                            }));
                        } else {
                            Self::respond(&mut stream, &response);
                        }
                        request_index += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("gated HTTP bridge: {error}"),
                }
            }
            if let Some(delayed) = delayed {
                delayed.join().unwrap();
            }
        });
        Self {
            address,
            captured,
            release: Some(release),
            stop,
            thread: Some(thread),
        }
    }
    fn respond(stream: &mut TcpStream, response: &[u8]) {
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
        stream.write_all(response).unwrap();
    }
    fn url(&self) -> String {
        format!("http://{}/upstream", self.address)
    }
    fn wait_for_old_response(&self) {
        self.captured
            .recv_timeout(Duration::from_secs(10))
            .expect("first fetch did not capture its old response");
    }
    fn release_old_response(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
    }
}
impl Drop for FetchBarrierBridge {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn overlapping_fetches_compare_complete_tracking_and_allow_later_remote_rewinds() {
    use std::collections::BTreeMap;
    fn local_files(repository: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap();
                if [
                    ".uwgit/objects",
                    ".uwgit/tmp",
                    ".uwgit/remote.lock",
                    ".uwgit/remotes/origin.tracking.json",
                ]
                .iter()
                .any(|excluded| relative == Path::new(excluded))
                {
                    continue;
                }
                let kind = entry.file_type().unwrap();
                assert!(!kind.is_symlink());
                if kind.is_dir() {
                    visit(root, &path, files);
                } else {
                    files.insert(relative.to_owned(), std::fs::read(&path).unwrap());
                }
            }
        }
        let mut files = BTreeMap::new();
        visit(repository, repository, &mut files);
        files
    }

    // Cover both absent and present baselines. The final case changes only tags:
    // comparing a branch tip alone must not permit the stale response to win.
    for (has_tracking, advances_tip) in [(false, true), (true, true), (true, false)] {
        let temp = Temp::new();
        let producer = temp.path("producer");
        let upstream = temp.path("upstream");
        let local = temp.path("local");
        run(&["init", &producer]);
        let producer_file = Path::new(&producer).join("module.wasm");
        wasm(producer_file.to_str().unwrap(), 1);
        run(&["add", &producer, "module.wasm"]);
        run(&["commit", &producer, "-m", "old remote tree"]);
        let old = tip(&producer, "HEAD");
        // Receive into a separate server store without a tracked worktree.
        run(&["clone", &producer, &upstream]);
        let mut bridge = FetchBarrierBridge::new(&temp.0);
        let url = bridge.url();
        run(&["remote", &producer, "add", "origin", &url]);
        run(&["clone", &url, &local]);
        run(&[
            "restore",
            &local,
            "--source",
            "HEAD",
            "--staged",
            "--worktree",
        ]);
        if !has_tracking {
            run(&["remote", &local, "remove", "origin"]);
            run(&["remote", &local, "add", "origin", &url]);
        }
        let tracking_path = Path::new(&local).join(".uwgit/remotes/origin.tracking.json");
        assert_eq!(tracking_path.exists(), has_tracking);

        // Keep an independently staged edit, a further unstaged edit, a local
        // tag and an untracked file throughout every fetch and rejected update.
        let local_file = Path::new(&local).join("module.wasm");
        wasm(local_file.to_str().unwrap(), 7);
        run(&["add", &local, "module.wasm"]);
        wasm(local_file.to_str().unwrap(), 8);
        run(&["tag", &local, "local_only"]);
        std::fs::write(Path::new(&local).join("notes.txt"), b"untracked bytes").unwrap();
        let protected = local_files(Path::new(&local));
        let delayed = command(&["fetch", &local])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        bridge.wait_for_old_response();

        if advances_tip {
            wasm(producer_file.to_str().unwrap(), 2);
            run(&["add", &producer, "module.wasm"]);
            run(&["commit", &producer, "-m", "new remote tree"]);
            run(&["push", &producer]);
        }
        let new = tip(&upstream, "HEAD");
        run(&["tag", &upstream, "new_remote_tag"]);
        run(&["fetch", &local]);
        let published = std::fs::read(&tracking_path).unwrap();
        let tracking: Value = serde_json::from_slice(&published).unwrap();
        assert_eq!(tracking["state"]["branches"]["main"], new);
        assert_eq!(tracking["state"]["tags"]["new_remote_tag"], new);
        assert_eq!(tip(&local, "origin/main"), new);
        assert_eq!(local_files(Path::new(&local)), protected);

        bridge.release_old_response();
        let stale = delayed.wait_with_output().unwrap();
        assert_eq!(stale.status.code(), Some(1));
        let error = String::from_utf8(stale.stderr).unwrap();
        assert!(
            error.contains("remote tracking changed while fetching"),
            "{error}"
        );
        assert!(error.contains("objects were installed"), "{error}");
        assert!(error.contains("tracking was not updated"), "{error}");
        assert!(error.contains("retry fetch"), "{error}");
        assert_eq!(std::fs::read(&tracking_path).unwrap(), published);
        assert_eq!(tip(&local, "origin/main"), new);
        assert_eq!(tip(&local, "HEAD"), old);
        assert_eq!(local_files(Path::new(&local)), protected);
        let export = temp.path("newly-fetched.wasm");
        run(&[
            "show",
            &local,
            &new,
            "--file",
            "module.wasm",
            "--output",
            &export,
        ]);
        assert_eq!(
            std::fs::read(export).unwrap(),
            std::fs::read(&producer_file).unwrap()
        );

        if advances_tip {
            // A fresh observation of an actual force-pushed rewind is valid.
            // The CAS compares its entry baseline, not the commit ancestry.
            run(&[
                "push",
                &local,
                "origin",
                &format!("{old}:main"),
                "--force-with-lease",
                &new,
            ]);
            assert_eq!(tip(&upstream, "HEAD"), old);
            run(&["fetch", &local]);
            assert_eq!(tip(&local, "origin/main"), old);
            let rewound: Value =
                serde_json::from_slice(&std::fs::read(&tracking_path).unwrap()).unwrap();
            assert_eq!(rewound["state"]["branches"]["main"], old);
            assert_eq!(rewound["state"]["tags"]["new_remote_tag"], new);
            assert_eq!(local_files(Path::new(&local)), protected);
        }
        run(&["fsck", &local]);
        run(&["fsck", &upstream]);
    }
}
