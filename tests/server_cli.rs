//! Fixed real-server loopback and stdio workflows. No Wasm execution or fuzzing.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TOKEN: &str = "fixed-server-regression-token";
const WASM: &[u8] = b"\0asm\x01\0\0\0";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-server-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn repository(&self, name: &str) -> PathBuf {
        let path = self.path(name);
        run(&["init", path.to_str().unwrap()]);
        path
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    command.args(args).env_remove("UWGIT_REMOTE_TOKEN");
    command
}
fn run(args: &[&str]) -> String {
    let output = command(args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn tip(repo: &Path) -> String {
    run(&["rev-parse", repo.to_str().unwrap(), "HEAD"])
        .trim()
        .into()
}
fn commit(temp: &Temp, repo: &Path, suffix: u8) -> String {
    let path = temp.path("input.wasm");
    fs::write(&path, [WASM, &[0, 3, 1, b'x', suffix]].concat()).unwrap();
    run(&[
        "commit",
        repo.to_str().unwrap(),
        path.to_str().unwrap(),
        "-m",
        "fixed input",
    ]);
    tip(repo)
}
fn bundle(temp: &Temp, repo: &Path, name: &str) -> Vec<u8> {
    let output = temp.path(name);
    run(&["bundle", repo.to_str().unwrap(), output.to_str().unwrap()]);
    fs::read(output).unwrap()
}
fn metadata(repo: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(base: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(base, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(base).unwrap().into(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(repo, &repo.join(".uwgit"), &mut files);
    files
}
fn packet(repository: &str, operation: Value, payload: &[u8]) -> Vec<u8> {
    let metadata =
        serde_json::to_vec(&json!({"version":1,"repository":repository,"operation":operation}))
            .unwrap();
    let mut bytes = b"UWGRPC01".to_vec();
    bytes.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&metadata);
    bytes.extend_from_slice(payload);
    bytes
}
fn decode(bytes: &[u8]) -> (Value, Vec<u8>) {
    assert!(bytes.len() >= 20);
    assert_eq!(&bytes[..8], b"UWGRPC01");
    let metadata = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let payload = usize::try_from(u64::from_be_bytes(bytes[12..20].try_into().unwrap())).unwrap();
    assert_eq!(bytes.len(), 20 + metadata + payload);
    (
        serde_json::from_slice(&bytes[20..20 + metadata]).unwrap(),
        bytes[20 + metadata..].to_vec(),
    )
}
struct Server {
    child: Option<Child>,
    address: SocketAddr,
}
impl Server {
    fn start(temp: &Temp, maximum: usize, write: bool, force: bool) -> Self {
        Self::start_with_token(temp, maximum, write, force, format!("{TOKEN}\n").as_bytes())
    }
    fn start_with_token(
        temp: &Temp,
        maximum: usize,
        write: bool,
        force: bool,
        token_bytes: &[u8],
    ) -> Self {
        let token = temp.path("server-token");
        fs::write(&token, token_bytes).unwrap();
        let maximum = maximum.to_string();
        let mut cmd = command(&[
            "server",
            "--root",
            temp.0.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--max-connections",
            &maximum,
            "--token-file",
            token.to_str().unwrap(),
        ]);
        if write {
            cmd.arg("--allow-write");
        }
        if force {
            cmd.arg("--allow-force");
        }
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut server = Self {
            child: Some(child),
            address: "127.0.0.1:0".parse().unwrap(),
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
        });
        let startup = match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(line)) if !line.is_empty() => line,
            other => {
                let mut child = server.child.take().unwrap();
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "server did not advertise readiness: {other:?}; {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };
        let startup: Value = serde_json::from_str(&startup).unwrap();
        assert_eq!(startup["read_only"], !write);
        assert_eq!(startup["protocol"], 1);
        server.address = startup["listen"].as_str().unwrap().parse().unwrap();
        server
    }
    fn raw(&self, request: &[u8]) -> (u16, Vec<u8>) {
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() <= 16 * 1024);
        }
        let headers = std::str::from_utf8(&header).unwrap();
        let status = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert!(length <= 64 * 1024 * 1024);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        (status, body)
    }
    fn request(&self, bytes: &[u8], token: Option<&str>) -> (u16, Vec<u8>) {
        let authorization = token.map_or(String::new(), |token| {
            format!("Authorization: Bearer {token}\r\n")
        });
        let mut request = format!("POST /v1/uwgit HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n{authorization}\r\n", bytes.len()).into_bytes();
        request.extend_from_slice(bytes);
        self.raw(&request)
    }
    fn finish(mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.child.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "finite server did not exit after its exact connection budget"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "server failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn stdio(temp: &Temp, bytes: &[u8]) -> Output {
    let mut child = command(&["server", "--stdio", "--root", temp.0.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn actual_http_server_authenticates_and_remains_read_only_by_default() {
    let temp = Temp::new();
    let repo = temp.repository("project");
    let id = commit(&temp, &repo, 1);
    let bytes = bundle(&temp, &repo, "read-only.bundle");
    let before = metadata(&repo);
    let server = Server::start(&temp, 4, false, false);
    let request = packet("project", json!({"kind":"advertise"}), &[]);
    assert_eq!(server.request(&request, None).0, 401);
    assert_eq!(server.request(&request, Some("wrong-token")).0, 401);
    let (status, body) = server.request(&request, Some(TOKEN));
    assert_eq!(status, 200);
    let (response, payload) = decode(&body);
    assert_eq!(response["ok"], true);
    assert!(payload.is_empty());
    assert_eq!(response["state"]["branches"]["main"], id);
    let request = packet(
        "project",
        json!({"kind":"push","branch":"main","expected":id,"force":false}),
        &bytes,
    );
    let (status, body) = server.request(&request, Some(TOKEN));
    assert_eq!(status, 200);
    let (response, _) = decode(&body);
    assert_eq!(response["ok"], false);
    assert_eq!(response["publication_unknown"], false);
    assert!(response["error"].as_str().unwrap().contains("read-only"));
    server.finish();
    assert_eq!(metadata(&repo), before);
}

#[test]
fn early_http_rejections_deliver_complete_bodies_with_unread_request_input() {
    let temp = Temp::new();
    let repo = temp.repository("project");
    let before = metadata(&repo);
    let server = Server::start(&temp, 4, false, false);
    // Fixed bytes deliberately remain unread by authentication/framing checks.
    // A reset while reading headers or the exact Content-Length is a failure.
    let body = vec![b'x'; 256 * 1024];
    let authorization = format!("Authorization: Bearer {TOKEN}\r\n");
    for (headers, expected_status, expected_body) in [
        (
            format!("Content-Length: {}\r\n", body.len()),
            401,
            "authentication required",
        ),
        (
            format!(
                "{authorization}Content-Length: 0\r\nContent-Length: {}\r\n",
                body.len()
            ),
            400,
            "duplicate HTTP header",
        ),
        (
            format!("{authorization}Content-Length: 67108865\r\n"),
            413,
            "Content-Length must not exceed 64 MiB",
        ),
        (
            format!(
                "{authorization}Content-Length: {}\r\nExpect: unsupported\r\n",
                body.len()
            ),
            417,
            "unsupported Expect",
        ),
    ] {
        let mut request =
            format!("POST /v1/uwgit HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n").into_bytes();
        request.extend_from_slice(&body);
        let (status, received) = server.raw(&request);
        assert_eq!(status, expected_status);
        assert_eq!(received, expected_body.as_bytes());
    }
    server.finish();
    assert_eq!(metadata(&repo), before);
}

#[test]
fn actual_http_push_acknowledges_only_successful_cas_and_force_policy() {
    let temp = Temp::new();
    let repo = temp.repository("project");
    let old = commit(&temp, &repo, 1);
    let old_bundle = bundle(&temp, &repo, "old.bundle");
    let source = temp.path("source");
    run(&["clone", repo.to_str().unwrap(), source.to_str().unwrap()]);
    let new = commit(&temp, &source, 2);
    let next = bundle(&temp, &source, "next.bundle");
    let server = Server::start(&temp, 4, true, false);
    let before = metadata(&repo);
    let stale = packet(
        "project",
        json!({"kind":"push","branch":"main","expected":null,"force":false}),
        &next,
    );
    let (_, body) = server.request(&stale, Some(TOKEN));
    let (response, _) = decode(&body);
    assert_eq!(response["ok"], false);
    assert_eq!(response["publication_unknown"], false);
    assert!(response["error"]
        .as_str()
        .unwrap()
        .contains("reference changed"));
    assert_eq!(metadata(&repo), before);
    let request = packet(
        "project",
        json!({"kind":"push","branch":"main","expected":old,"force":false}),
        &next,
    );
    let (_, body) = server.request(&request, Some(TOKEN));
    let (response, payload) = decode(&body);
    assert_eq!(response["ok"], true);
    assert_eq!(response["tip"], new);
    assert_eq!(response["state"], Value::Null);
    assert!(payload.is_empty());
    assert_eq!(tip(&repo), new);
    let before = metadata(&repo);
    let (_, body) = server.request(&request, Some(TOKEN));
    assert_eq!(decode(&body).0["ok"], false);
    assert_eq!(metadata(&repo), before);
    let force = packet(
        "project",
        json!({"kind":"push","branch":"main","expected":new,"force":true}),
        &old_bundle,
    );
    let (_, body) = server.request(&force, Some(TOKEN));
    let (response, _) = decode(&body);
    assert_eq!(response["ok"], false);
    assert!(response["error"].as_str().unwrap().contains("forced"));
    server.finish();
    assert_eq!(tip(&repo), new);
    let server = Server::start(&temp, 1, true, true);
    let (_, body) = server.request(&force, Some(TOKEN));
    let (response, _) = decode(&body);
    assert_eq!(response["ok"], true);
    assert_eq!(response["tip"], old);
    server.finish();
    assert_eq!(tip(&repo), old);
}

#[test]
fn actual_http_framing_rejects_ambiguous_lengths_and_malformed_rpc() {
    let temp = Temp::new();
    let repo = temp.repository("project");
    let before = metadata(&repo);
    let server = Server::start(&temp, 6, false, false);
    for request in [
        "POST /v1/uwgit HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        "POST /v1/uwgit HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
    ] {
        assert_eq!(server.raw(request.as_bytes()).0, 400);
    }
    let authorization = format!("Authorization: Bearer {TOKEN}\r\n");
    assert_eq!(
        server
            .raw(format!("POST /v1/uwgit HTTP/1.1\r\nHost: x\r\n{authorization}\r\n").as_bytes())
            .0,
        411
    );
    assert_eq!(server.raw(format!("POST /v1/uwgit HTTP/1.1\r\nHost: x\r\n{authorization}Content-Length: +1\r\n\r\n").as_bytes()).0, 400);
    assert_eq!(server.raw(format!("POST /v1/uwgit HTTP/1.1\r\nHost: x\r\n{authorization}Content-Length: 67108865\r\n\r\n").as_bytes()).0, 413);
    let mut bad = packet("project", json!({"kind":"fetch"}), &[]);
    bad.push(0);
    let (status, body) = server.request(&bad, Some(TOKEN));
    assert_eq!(status, 200);
    let (response, _) = decode(&body);
    assert_eq!(response["ok"], false);
    assert!(response["error"].as_str().unwrap().contains("trailing"));
    server.finish();
    assert_eq!(metadata(&repo), before);
}

#[test]
fn stdio_is_one_complete_framed_request_and_rejects_trailing_or_traversal() {
    let temp = Temp::new();
    let repo = temp.repository("project");
    let before = metadata(&repo);
    let request = packet("project", json!({"kind":"fetch"}), &[]);
    let output = stdio(&temp, &request);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (response, payload) = decode(&output.stdout);
    assert_eq!(response["ok"], true);
    assert_eq!(response["state"]["head"], "main");
    assert!(payload.starts_with(b"UWGB\0\0\0\x01"));
    let mut extra = request.clone();
    extra.push(0);
    let output = stdio(&temp, &extra);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trailing"));
    let output = stdio(
        &temp,
        &packet("../project", json!({"kind":"advertise"}), &[]),
    );
    assert!(output.status.success());
    let (response, _) = decode(&output.stdout);
    assert_eq!(response["ok"], false);
    assert!(response["error"]
        .as_str()
        .unwrap()
        .contains("repository name"));
    assert_eq!(metadata(&repo), before);
}

#[test]
fn write_service_requires_authentication_and_stdio_rejects_http_only_constraints() {
    let temp = Temp::new();
    temp.repository("project");
    for args in [
        vec![
            "server",
            "--root",
            temp.0.to_str().unwrap(),
            "--allow-write",
            "--listen",
            "127.0.0.1:0",
        ],
        vec![
            "server",
            "--stdio",
            "--root",
            temp.0.to_str().unwrap(),
            "--max-connections",
            "1",
        ],
        vec![
            "server",
            "--stdio",
            "--root",
            temp.0.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ],
    ] {
        let output = command(&args).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn omitted_nullable_mutation_fields_never_delete_or_publish_a_reference() {
    let temp = Temp::new();
    let project = temp.repository("project");
    let initial = commit(&temp, &project, 1);
    run(&["branch", project.to_str().unwrap(), "temporary"]);
    run(&["tag", project.to_str().unwrap(), "release"]);
    let incoming = bundle(&temp, &project, "nullable-field.bundle");
    let cases: [(Value, &[u8], &str); 4] = [
        (
            json!({"kind":"update_ref","namespace":"tag","name":"release","expected":initial,"force":false}),
            &[],
            "new",
        ),
        (
            json!({"kind":"update_ref","namespace":"branch","name":"temporary","expected":initial,"force":false}),
            &[],
            "new",
        ),
        (
            json!({"kind":"update_ref","namespace":"tag","name":"new_tag","new":initial,"force":false}),
            &incoming,
            "expected",
        ),
        (
            json!({"kind":"push","branch":"new_branch","force":false}),
            &incoming,
            "expected",
        ),
    ];
    let server = Server::start(&temp, cases.len() + 2, true, false);
    let before = metadata(&project);
    for (operation, payload, missing) in cases {
        let bytes = packet("project", operation, payload);
        let (status, body) = server.request(&bytes, Some(TOKEN));
        assert_eq!(status, 200);
        let (response, payload) = decode(&body);
        assert_eq!(response["ok"], false);
        assert_eq!(response["publication_unknown"], false);
        let error = response["error"].as_str().unwrap();
        assert!(
            error.contains("missing field") && error.contains(missing),
            "{error}"
        );
        assert!(payload.is_empty());
        assert_eq!(metadata(&project), before);
        let rejected = stdio(&temp, &bytes);
        assert!(!rejected.status.success());
        assert!(rejected.stdout.is_empty());
        let error = String::from_utf8(rejected.stderr).unwrap();
        assert!(
            error.contains("missing field") && error.contains(missing),
            "{error}"
        );
        assert_eq!(metadata(&project), before);
    }
    for (namespace, name, directory) in
        [("tag", "release", "tags"), ("branch", "temporary", "refs")]
    {
        let bytes = packet(
            "project",
            json!({"kind":"update_ref","namespace":namespace,"name":name,"expected":initial,"new":null,"force":false}),
            &[],
        );
        let (status, body) = server.request(&bytes, Some(TOKEN));
        assert_eq!(status, 200);
        let (response, payload) = decode(&body);
        assert_eq!(response["ok"], true);
        assert!(response["tip"].is_null());
        assert!(payload.is_empty());
        assert!(!project.join(".uwgit").join(directory).join(name).exists());
    }
    server.finish();
    assert_eq!(tip(&project), initial);
    run(&["fsck", project.to_str().unwrap()]);
}

#[test]
fn full_length_http_tokens_authenticate_with_or_without_one_final_line_feed() {
    for length in [4095, 4096] {
        for newline in [false, true] {
            let temp = Temp::new();
            temp.repository("project");
            let token = "T".repeat(length);
            let mut file = token.as_bytes().to_vec();
            if newline {
                file.push(b'\n');
            }
            let server = Server::start_with_token(&temp, 1, false, false, &file);
            let bytes = packet("project", json!({"kind":"fetch"}), &[]);
            let (status, body) = server.request(&bytes, Some(&token));
            assert_eq!(status, 200);
            let (response, payload) = decode(&body);
            assert_eq!(response["ok"], true);
            assert_eq!(response["publication_unknown"], false);
            assert!(!payload.is_empty());
            server.finish();
        }
    }
}

#[test]
fn actual_http_clone_accepts_dotted_and_65_to_128_byte_repository_names() {
    let temp = Temp::new();
    let names = ["project.git".to_owned(), "r".repeat(65), "s".repeat(128)];
    let mut repositories = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let project = temp.repository(name);
        let initial = commit(&temp, &project, (index + 1) as u8);
        let expected = fs::read(temp.path("input.wasm")).unwrap();
        repositories.push((name, initial, expected));
    }
    let server = Server::start(&temp, repositories.len(), false, false);
    for (index, (name, initial, expected)) in repositories.into_iter().enumerate() {
        let url = format!("http://{}/{name}", server.address);
        let local = temp.path(&format!("named-clone-{index}"));
        let result = command(&["clone", &url, local.to_str().unwrap()])
            .env("UWGIT_REMOTE_TOKEN", TOKEN)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(tip(&local), initial);
        let exported = temp.path(&format!("named-export-{index}.wasm"));
        run(&[
            "show",
            local.to_str().unwrap(),
            "HEAD",
            "--output",
            exported.to_str().unwrap(),
        ]);
        assert_eq!(fs::read(exported).unwrap(), expected);
        run(&["fsck", local.to_str().unwrap()]);
    }
    server.finish();
}
