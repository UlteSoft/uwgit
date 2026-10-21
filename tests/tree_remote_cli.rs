//! Fixed multi-module repository workflows over the real HTTP service and the
//! SSH client/stdio boundary. Tree metadata and every Wasm byte are preserved.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const TOKEN: &str = "fixed-tree-transport-token";
const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const A: &str = "modules/a.wasm";
const B: &str = "nested/性能.wasm";
const C: &str = "new/c.wasm";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-tree-remote-{}-{}",
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
fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    cmd.args(args)
        .env_remove("UWGIT_SSH_PROGRAM")
        .env_remove("UWGIT_REMOTE_PROGRAM")
        .env_remove("UWGIT_REMOTE_TOKEN");
    cmd
}
fn output(result: Output) -> String {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn run(args: &[&str]) -> String {
    output(command(args).output().unwrap())
}
fn value(args: &[&str]) -> Value {
    serde_json::from_str(&run(args)).unwrap()
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn tip(repository: &Path) -> String {
    run(&["rev-parse", path(repository), "HEAD"]).trim().into()
}
fn wasm(value: u8) -> Vec<u8> {
    [HEADER, &[0, 3, 1, b'x', value]].concat()
}
fn write(repository: &Path, name: &str, bytes: &[u8]) {
    let file = repository.join(name);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, bytes).unwrap();
}
fn seed(temp: &Temp) -> (PathBuf, PathBuf, String) {
    let work = temp.path("work");
    let repositories = temp.path("repositories");
    fs::create_dir(&repositories).unwrap();
    let upstream = repositories.join("project");
    run(&["init", path(&work)]);
    write(&work, A, &wasm(1));
    write(&work, B, &wasm(2));
    run(&["add", path(&work), A, B]);
    run(&["commit", path(&work), "-m", "two original modules"]);
    run(&["tag", path(&work), "base"]);
    run(&["branch", path(&work), "feature"]);
    let initial = tip(&work);
    // The service store has no tracked index or worktree: receiving its HEAD
    // must not weaken the existing protection for an actively tracked worktree.
    run(&["clone", path(&work), path(&upstream)]);
    (work, upstream, initial)
}
fn export(repository: &Path, revision: &str, file: &str, destination: &Path, expected: &[u8]) {
    run(&[
        "show",
        path(repository),
        revision,
        "--file",
        file,
        "--output",
        path(destination),
    ]);
    assert_eq!(fs::read(destination).unwrap(), expected);
}
fn metadata(repository: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            assert!(!entry.file_type().unwrap().is_symlink());
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), result);
            } else {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(repository, &repository.join(".uwgit"), &mut result);
    result
}
fn rpc_packet(operation: &Value, payload: &[u8]) -> Vec<u8> {
    let metadata =
        serde_json::to_vec(&json!({"version":1,"repository":"project","operation":operation}))
            .unwrap();
    let mut packet = b"UWGRPC01".to_vec();
    packet.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    packet.extend_from_slice(&metadata);
    packet.extend_from_slice(payload);
    packet
}
fn rpc_metadata(packet: &[u8]) -> Value {
    assert_eq!(&packet[..8], b"UWGRPC01");
    let length = u32::from_be_bytes(packet[8..12].try_into().unwrap()) as usize;
    assert_eq!(u64::from_be_bytes(packet[12..20].try_into().unwrap()), 0);
    assert_eq!(packet.len(), 20 + length);
    serde_json::from_slice(&packet[20..]).unwrap()
}
fn stdio_rpc(root: &Path, operation: &Value, payload: &[u8]) -> Value {
    let mut child = command(&["server", "--stdio", "--root", path(root)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&rpc_packet(operation, payload))
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    rpc_metadata(&result.stdout)
}
struct Server {
    child: Child,
    address: SocketAddr,
}
impl Server {
    fn start(temp: &Temp) -> Self {
        let token = temp.path("http-token");
        fs::write(&token, format!("{TOKEN}\n")).unwrap();
        let mut child = command(&[
            "server",
            "--root",
            path(&temp.path("repositories")),
            "--listen",
            "127.0.0.1:0",
            "--allow-write",
            "--token-file",
            path(&token),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
        });
        let mut server = Self {
            child,
            address: "127.0.0.1:0".parse().unwrap(),
        };
        let ready = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("real HTTP server readiness")
            .unwrap();
        let ready: Value = serde_json::from_str(&ready).unwrap();
        server.address = ready["listen"].as_str().unwrap().parse().unwrap();
        assert_eq!(ready["protocol"], 1);
        assert_eq!(ready["read_only"], false);
        server
    }
    fn url(&self) -> String {
        format!("http://{}/project", self.address)
    }
    fn run(&self, args: &[&str]) -> String {
        output(
            command(args)
                .env("UWGIT_REMOTE_TOKEN", TOKEN)
                .output()
                .unwrap(),
        )
    }
    fn rpc(&self, operation: Value, payload: &[u8]) -> Value {
        let packet = rpc_packet(&operation, payload);
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(stream, "POST /v1/uwgit HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", packet.len()).unwrap();
        stream.write_all(&packet).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let boundary = response
            .windows(4)
            .position(|value| value == b"\r\n\r\n")
            .unwrap()
            + 4;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        rpc_metadata(&response[boundary..])
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn real_http_preserves_tree_paths_bytes_and_empty_trees_across_all_remote_operations() {
    let temp = Temp::new();
    let (work, upstream, initial) = seed(&temp);
    let server = Server::start(&temp);
    let client = temp.path("client");
    server.run(&["clone", &server.url(), path(&client)]);
    assert_eq!(tip(&client), initial);
    assert_eq!(
        run(&["rev-parse", path(&client), "feature"]).trim(),
        initial
    );
    assert_eq!(run(&["rev-parse", path(&client), "base"]).trim(), initial);
    export(&client, "HEAD", A, &temp.path("clone-a.wasm"), &wasm(1));
    export(&client, "HEAD", B, &temp.path("clone-b.wasm"), &wasm(2));
    run(&[
        "restore",
        path(&client),
        "--source",
        "HEAD",
        "--staged",
        "--worktree",
    ]);
    run(&["remote", path(&work), "add", "origin", &server.url()]);
    write(&work, A, &wasm(3));
    run(&["add", path(&work), A]);
    run(&["commit", path(&work), "-m", "change one module"]);
    let second = tip(&work);
    server.run(&["push", path(&work)]);
    server.run(&["fetch", path(&client)]);
    assert_eq!(tip(&client), initial);
    assert_eq!(
        run(&["rev-parse", path(&client), "origin/main"]).trim(),
        second
    );
    assert_eq!(fs::read(client.join(A)).unwrap(), wasm(1));
    server.run(&[
        "pull",
        path(&client),
        "origin",
        "main",
        "-m",
        "integrate remote tree",
    ]);
    assert_eq!(tip(&client), second);
    assert_eq!(fs::read(client.join(A)).unwrap(), wasm(3));
    assert_eq!(fs::read(client.join(B)).unwrap(), wasm(2));
    write(&client, A, &wasm(4));
    write(&client, C, &wasm(5));
    run(&["add", path(&client), A, C]);
    run(&["rm", path(&client), "--cached", B]);
    run(&["commit", path(&client), "-m", "change add and remove paths"]);
    let third = tip(&client);
    run(&["tag", path(&client), "release"]);
    server.run(&["push", path(&client)]);
    server.run(&["push", path(&client), "origin", "--tags"]);
    server.run(&["push", path(&client), "origin", "HEAD:temporary"]);
    server.run(&["push", path(&client), "origin", "--delete", "temporary"]);
    server.run(&[
        "push",
        path(&client),
        "origin",
        "--delete",
        "refs/tags/release",
    ]);
    assert_eq!(tip(&upstream), third);
    export(&upstream, "HEAD", A, &temp.path("pushed-a.wasm"), &wasm(4));
    export(&upstream, "HEAD", C, &temp.path("pushed-c.wasm"), &wasm(5));
    let report = value(&[
        "diff",
        &initial,
        &third,
        "--repo",
        path(&upstream),
        "--format",
        "json",
    ]);
    assert_eq!(report["kind"], "tree_diff");
    assert_eq!(report["binary_changed"], true);
    let files = report["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    for (file, status) in [(A, "modified"), (B, "deleted"), (C, "added")] {
        assert_eq!(
            files.iter().find(|value| value["path"] == file).unwrap()["status"],
            status
        );
    }
    let single = value(&[
        "diff",
        &initial,
        &third,
        "--repo",
        path(&upstream),
        "--file",
        A,
        "--format",
        "json",
    ]);
    assert_eq!(single["binary_changed"], true);
    assert!(!single["audit"]["edits"].as_array().unwrap().is_empty());
    run(&["rm", path(&client), "--cached", A, C]);
    run(&["commit", path(&client), "-m", "a real empty tree"]);
    server.run(&["push", path(&client)]);
    let empty = temp.path("empty-clone");
    server.run(&["clone", &server.url(), path(&empty)]);
    let inspection = value(&["inspect", "HEAD", "--repo", path(&empty), "--json"]);
    assert_eq!(inspection["kind"], "tree_inspect");
    assert_eq!(inspection["file_count"], 0);
    assert_eq!(inspection["files"], json!([]));
    assert_eq!(tip(&empty), tip(&client));
    for repository in [&upstream, &client, &empty] {
        run(&["fsck", path(repository)]);
    }
}

#[test]
fn http_bundle_preserves_legacy_parent_bytes_and_explicit_tree_anchor() {
    let temp = Temp::new();
    let work = temp.path("work");
    let repositories = temp.path("repositories");
    fs::create_dir(&repositories).unwrap();
    let old = temp.path("old.wasm");
    fs::write(&old, wasm(1)).unwrap();
    run(&["init", path(&work)]);
    run(&[
        "commit",
        path(&work),
        path(&old),
        "-m",
        "original pathless module",
    ]);
    let legacy = tip(&work);
    run(&["tag", path(&work), "original"]);
    // The caller explicitly binds the old pathless module to A before adding a
    // second file; transfer must preserve that recorded migration anchor.
    write(&work, A, &wasm(1));
    run(&["add", path(&work), A]);
    write(&work, B, &wasm(2));
    run(&["add", path(&work), B]);
    write(&work, A, &wasm(3));
    run(&["add", path(&work), A]);
    run(&["commit", path(&work), "-m", "tree with a legacy parent"]);
    let head = tip(&work);
    let upstream = repositories.join("project");
    run(&["clone", path(&work), path(&upstream)]);
    let server = Server::start(&temp);
    let client = temp.path("mixed-clone");
    server.run(&["clone", &server.url(), path(&client)]);
    assert_eq!(tip(&client), head);
    let info = value(&["show", path(&client), "HEAD"]);
    assert_eq!(info["format"], 2);
    assert_eq!(info["legacy_path"], A);
    assert_eq!(info["parents"], json!([legacy]));
    let original = temp.path("original-export.wasm");
    run(&[
        "show",
        path(&client),
        "original",
        "--output",
        path(&original),
    ]);
    assert_eq!(fs::read(original).unwrap(), wasm(1));
    export(&client, "HEAD", A, &temp.path("mixed-a.wasm"), &wasm(3));
    export(&client, "HEAD", B, &temp.path("mixed-b.wasm"), &wasm(2));
    run(&["fsck", path(&client)]);
}

fn object(kind: u8, payload: &[u8]) -> (String, Vec<u8>) {
    let mut encoded = b"UWGO\0\0\0\x01".to_vec();
    encoded.push(kind);
    encoded.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    encoded.extend_from_slice(payload);
    let id = format!("{:x}", Sha256::digest(&encoded));
    (id, encoded)
}
fn tree_bundle(
    tree_json: &[u8],
    blobs: &[(String, Vec<u8>)],
    corrupt_tree: bool,
) -> (String, Vec<u8>) {
    let (tree_id, mut tree) = object(3, tree_json);
    if corrupt_tree {
        *tree.last_mut().unwrap() ^= 1;
    }
    let commit_json = format!("{{\"format\":2,\"parents\":[],\"message\":\"fixed tree transfer\",\"tree\":\"{tree_id}\"}}");
    let (commit_id, commit) = object(2, commit_json.as_bytes());
    let manifest =
        format!("{{\"format\":3,\"head\":\"main\",\"refs\":{{\"main\":\"{commit_id}\"}}}}");
    let mut objects: BTreeMap<_, _> = blobs.iter().cloned().collect();
    objects.insert(tree_id, tree);
    objects.insert(commit_id.clone(), commit);
    let mut bundle = b"UWGB\0\0\0\x01".to_vec();
    bundle.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    bundle.extend_from_slice(manifest.as_bytes());
    bundle.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    for (id, bytes) in objects {
        bundle.extend_from_slice(id.as_bytes());
        bundle.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        bundle.extend_from_slice(&bytes);
    }
    (commit_id, bundle)
}

#[test]
fn invalid_tree_bundles_are_rejected_before_any_remote_object_or_ref_is_published() {
    let temp = Temp::new();
    let (_, upstream, _) = seed(&temp);
    let server = Server::start(&temp);
    let blob = object(1, &wasm(9));
    let missing = "0".repeat(64);
    let (wrong_id, wrong) = object(2, format!("{{\"format\":1,\"wasm\":\"{}\",\"parents\":[],\"message\":\"a commit is not a Wasm blob\"}}", blob.0).as_bytes());
    let cases = [
        (
            format!(
                "{{\"format\":1,\"entries\":{{\"../escape.wasm\":\"{}\"}}}}",
                blob.0
            ),
            vec![blob.clone()],
            false,
        ),
        (
            format!("{{\"format\":1,\"entries\":{{\"module.wasm\":\"{missing}\"}}}}"),
            vec![blob.clone()],
            false,
        ),
        (
            format!("{{\"format\":1,\"entries\":{{\"module.wasm\":\"{wrong_id}\"}}}}"),
            vec![blob.clone(), (wrong_id, wrong)],
            false,
        ),
        (
            format!(
                "{{\"format\":1,\"entries\":{{\"a.wasm\":\"{}\",\"a.wasm/child.wasm\":\"{}\"}}}}",
                blob.0, blob.0
            ),
            vec![blob.clone()],
            false,
        ),
        (
            format!(
                "{{\"format\":1,\"entries\":{{\"module.wasm\":\"{}\"}}}}",
                blob.0
            ),
            vec![blob],
            true,
        ),
    ];
    let before = metadata(&upstream);
    for (tree, blobs, corrupt) in cases {
        let (commit, bundle) = tree_bundle(tree.as_bytes(), &blobs, corrupt);
        let operation = json!({"kind":"update_ref","namespace":"branch","name":"rejected","expected":null,"new":commit,"force":false});
        let response = server.rpc(operation.clone(), &bundle);
        assert_eq!(response["ok"], false);
        assert_eq!(response["publication_unknown"], false);
        assert_eq!(metadata(&upstream), before);
        let response = stdio_rpc(&temp.path("repositories"), &operation, &bundle);
        assert_eq!(response["ok"], false);
        assert_eq!(response["publication_unknown"], false);
        assert_eq!(metadata(&upstream), before);
    }
    run(&["fsck", path(&upstream)]);
}

#[cfg(unix)]
#[test]
fn ssh_client_stdio_roundtrips_multi_module_and_empty_tree_bundles() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new();
    let (work, upstream, initial) = seed(&temp);
    let shim = temp.path("ssh-program");
    fs::write(&shim, b"#!/bin/sh\nset -eu\nexec \"$UWGIT_TREE_TEST_BINARY\" server --stdio --root \"$UWGIT_TREE_TEST_ROOT\"\n").unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
    let ssh = |args: &[&str]| {
        output(
            command(args)
                .env("UWGIT_SSH_PROGRAM", &shim)
                .env("UWGIT_TREE_TEST_BINARY", env!("CARGO_BIN_EXE_wasm-git"))
                .env("UWGIT_TREE_TEST_ROOT", temp.path("repositories"))
                .output()
                .unwrap(),
        )
    };
    let client = temp.path("ssh-client");
    let url = format!(
        "ssh://test@localhost{}/project",
        temp.path("repositories").display()
    );
    ssh(&["clone", &url, path(&client)]);
    assert_eq!(tip(&client), initial);
    export(&client, "HEAD", A, &temp.path("ssh-a.wasm"), &wasm(1));
    export(&client, "HEAD", B, &temp.path("ssh-b.wasm"), &wasm(2));
    run(&[
        "restore",
        path(&client),
        "--source",
        "HEAD",
        "--staged",
        "--worktree",
    ]);
    write(&client, A, &wasm(7));
    run(&["add", path(&client), A]);
    run(&["commit", path(&client), "-m", "SSH path update"]);
    run(&["tag", path(&client), "ssh_release"]);
    ssh(&["push", path(&client)]);
    ssh(&["push", path(&client), "origin", "--tags"]);
    ssh(&["push", path(&client), "origin", "HEAD:temporary"]);
    ssh(&["push", path(&client), "origin", "--delete", "temporary"]);
    ssh(&[
        "push",
        path(&client),
        "origin",
        "--delete",
        "refs/tags/ssh_release",
    ]);
    export(
        &upstream,
        "HEAD",
        A,
        &temp.path("ssh-pushed-a.wasm"),
        &wasm(7),
    );
    export(
        &upstream,
        "HEAD",
        B,
        &temp.path("ssh-pushed-b.wasm"),
        &wasm(2),
    );
    run(&["rm", path(&client), "--cached", A, B]);
    run(&["commit", path(&client), "-m", "SSH empty tree"]);
    ssh(&["push", path(&client)]);
    let empty = temp.path("ssh-empty");
    ssh(&["clone", &url, path(&empty)]);
    let inspection = value(&["inspect", "HEAD", "--repo", path(&empty), "--json"]);
    assert_eq!(inspection["file_count"], 0);
    assert_eq!(inspection["files"], json!([]));
    assert_eq!(tip(&empty), tip(&client));
    run(&["fsck", path(&work)]);
    run(&["fsck", path(&upstream)]);
}

type ResolutionFiles = BTreeMap<String, Vec<u8>>;
const RESOLVED_CHILD: &str = "modules/a.wasm/nested.wasm";
const UNKNOWN_FILE: &str = "audit/unknown-section.wasm";
const CUSTOM_FILE: &str = "audit/noncanonical-name.wasm";
const GC_FILE: &str = "features/gc.wasm";
const FUTURE_FILE: &str = "features/shared-memory.wasm";

fn resolution_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn resolution_worktree(repository: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let file = entry.path();
            if file == root.join(".uwgit") {
                continue;
            }
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            let relative = file.strip_prefix(root).unwrap().to_owned();
            if kind.is_dir() {
                result.insert(relative, None);
                visit(root, &file, result);
            } else {
                assert!(kind.is_file());
                result.insert(relative, Some(fs::read(file).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(repository, repository, &mut result);
    result
}

fn resolution_replay(audit: &Value, old: &[u8], new: &[u8]) {
    assert_eq!(audit["old"]["byte_len"], old.len());
    assert_eq!(audit["new"]["byte_len"], new.len());
    let (mut old_cursor, mut new_cursor) = (0, 0);
    let mut rebuilt = Vec::new();
    for edit in audit["edits"].as_array().unwrap() {
        let start = edit["old_span"]["start"].as_u64().unwrap() as usize;
        let end = edit["old_span"]["end"].as_u64().unwrap() as usize;
        let new_start = edit["new_span"]["start"].as_u64().unwrap() as usize;
        let new_end = edit["new_span"]["end"].as_u64().unwrap() as usize;
        assert!(old_cursor <= start && start <= end && end <= old.len());
        assert!(new_cursor <= new_start && new_start <= new_end && new_end <= new.len());
        assert_eq!(edit["old_hex"], resolution_hex(&old[start..end]));
        assert_eq!(edit["new_hex"], resolution_hex(&new[new_start..new_end]));
        assert_eq!(old[old_cursor..start], new[new_cursor..new_start]);
        rebuilt.extend_from_slice(&old[old_cursor..start]);
        rebuilt.extend_from_slice(&new[new_start..new_end]);
        old_cursor = end;
        new_cursor = new_end;
    }
    assert_eq!(old[old_cursor..], new[new_cursor..]);
    rebuilt.extend_from_slice(&old[old_cursor..]);
    assert_eq!(rebuilt, new);
}

fn resolution_witness(witness: &Value, bytes: Option<&[u8]>) {
    let Some(bytes) = bytes else {
        assert!(witness.is_null());
        return;
    };
    assert_eq!(witness["byte_len"], bytes.len());
    assert_eq!(witness["sha256"], format!("{:x}", Sha256::digest(bytes)));
    assert_eq!(witness["hex"], resolution_hex(bytes));
    assert_eq!(witness["audit"]["byte_len"], bytes.len());
}

fn resolution_evidence(
    report: &Value,
    base: &ResolutionFiles,
    ours: &ResolutionFiles,
    theirs: &ResolutionFiles,
    resolved: &ResolutionFiles,
) {
    assert_eq!(report["status"], "merged_resolved");
    assert_eq!(report["resolution_source"], "index");
    assert_eq!(report["index_updated"], false);
    assert_eq!(report["worktree_updated"], false);
    let evidence = &report["tree_manual_resolution"];
    assert_eq!(evidence["supplied_complete_tree"], true);
    assert!(!evidence["provenance"].as_str().unwrap().is_empty());
    assert!(evidence["legacy_path"].is_null());
    let paths: BTreeSet<_> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .chain(resolved.keys())
        .cloned()
        .collect();
    let rows = evidence["files"].as_array().unwrap();
    assert_eq!(rows.len(), paths.len());
    assert_eq!(
        rows.iter()
            .map(|row| row["path"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>(),
        paths
    );
    for row in rows {
        let name = row["path"].as_str().unwrap();
        for (side, files) in [
            ("base", base),
            ("ours", ours),
            ("theirs", theirs),
            ("resolved", resolved),
        ] {
            resolution_witness(&row[side], files.get(name).map(Vec::as_slice));
        }
        for (side, files) in [("from_ours", ours), ("from_theirs", theirs)] {
            let (old, new) = (files.get(name), resolved.get(name));
            let expected = match (old, new) {
                (None, None) => "absent",
                (None, Some(_)) => "added",
                (Some(_), None) => "deleted",
                (Some(left), Some(right)) if left == right => "unchanged",
                _ => "modified",
            };
            assert_eq!(row[side]["status"], expected);
            if expected == "modified" {
                resolution_replay(&row[side]["audit"], old.unwrap(), new.unwrap());
            } else {
                // Missing paths are not synthesized into empty Wasm modules.
                assert!(row[side]["audit"].is_null());
            }
        }
    }
}

fn resolution_profiles(repository: &Path, revision: &str) {
    for standard in ["core1", "core3", "all-known"] {
        let report = value(&[
            "inspect",
            revision,
            "--repo",
            path(repository),
            "--standard",
            standard,
            "--json",
        ]);
        let rows: BTreeMap<_, _> = report["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row["path"].as_str().unwrap(), row))
            .collect();
        assert_eq!(rows.len(), 6);
        let unknown = &rows[UNKNOWN_FILE]["report"]["audit"];
        assert_eq!(unknown["sections"][0]["id"], 14);
        assert_eq!(unknown["sections"][0]["status"], "opaque");
        let custom = &rows[CUSTOM_FILE]["report"]["audit"];
        assert_eq!(custom["sections"][0]["kind"], "custom:name");
        assert_eq!(custom["sections"][0]["status"], "opaque");
        assert_eq!(custom["standard"]["validation"], "valid");
        for name in [GC_FILE, FUTURE_FILE] {
            let audit = &rows[name]["report"]["audit"];
            assert_eq!(audit["standard"]["selected_standard"], standard);
            if standard == "core1" || (standard == "core3" && name == FUTURE_FILE) {
                assert_eq!(audit["standard"]["validation"], "invalid");
                assert!(audit["standard"]["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item["status"] == "recognized_but_disabled"));
            } else {
                assert_eq!(audit["standard"]["validation"], "valid");
            }
        }
    }
}

fn remote_resolution_scenario(
    temp: &Temp,
    upstream: &Path,
    url: &str,
    network: impl Fn(&[&str]) -> Output,
) {
    let transfer = |args: &[&str]| output(network(args));
    let left = temp.path("resolution-left");
    let right = temp.path("resolution-right");
    transfer(&["clone", url, path(&left)]);
    transfer(&["clone", url, path(&right)]);
    let initial = tip(&left);
    let base: ResolutionFiles = [(A.into(), wasm(1)), (B.into(), wasm(2))].into();
    for repository in [&left, &right] {
        run(&[
            "restore",
            path(repository),
            "--source",
            "HEAD",
            "--staged",
            "--worktree",
        ]);
    }
    let theirs: ResolutionFiles = [(A.into(), wasm(3)), (B.into(), wasm(4))].into();
    let ours: ResolutionFiles = [(A.into(), wasm(5)), (B.into(), wasm(6))].into();
    for (repository, files) in [(&left, &theirs), (&right, &ours)] {
        for (name, bytes) in files {
            write(repository, name, bytes);
        }
        run(&["add", path(repository), A, B]);
        run(&[
            "commit",
            path(repository),
            "-m",
            "independent conflicting modules",
        ]);
    }
    let (their_tip, our_tip) = (tip(&left), tip(&right));
    transfer(&["push", path(&left)]);
    let index_before = fs::read(right.join(".uwgit/index")).unwrap();
    let files_before = resolution_worktree(&right);
    let conflict = network(&[
        "pull",
        path(&right),
        "origin",
        "main",
        "-m",
        "report both file conflicts",
    ]);
    assert_eq!(
        conflict.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&conflict.stderr)
    );
    let conflict: Value = serde_json::from_slice(&conflict.stdout).unwrap();
    assert_eq!(conflict["status"], "conflict");
    assert_eq!(conflict["old_head"], our_tip);
    assert_eq!(conflict["target"], their_tip);
    for name in [A, B] {
        assert!(conflict["file_reports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == name && row["status"] == "conflict"));
    }
    assert_eq!(tip(&right), our_tip);
    assert_eq!(fs::read(right.join(".uwgit/index")).unwrap(), index_before);
    assert_eq!(resolution_worktree(&right), files_before);

    transfer(&["push", path(&right), "origin", "HEAD:review_right"]);
    let no_index = temp.path("no-index-resolution");
    transfer(&["clone", url, path(&no_index)]);
    assert!(!no_index.join(".uwgit/index").exists());
    assert_eq!(
        run(&["rev-parse", path(&no_index), "review_right"]).trim(),
        our_tip
    );
    let no_index_before = metadata(&no_index);
    let rejected = command(&[
        "merge",
        path(&no_index),
        &our_tip,
        "-m",
        "no supplied tree",
        "--resolved-index",
        "--expect-head",
        &their_tip,
    ])
    .output()
    .unwrap();
    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(metadata(&no_index), no_index_before);
    assert!(!no_index.join(".uwgit/index").exists());

    let unknown = [HEADER, &[14, 2, 0xaa, 0xbb]].concat();
    let custom = [HEADER, &[0, 9, 4, b'n', b'a', b'm', b'e', 1, 2, 0x80, 0]].concat();
    let gc =
        wat::parse_str("(module (type $s (struct (field i32))) (func struct.new_default $s drop))")
            .unwrap();
    // This recognized extension is still disabled by normative Core 3.
    let future = wat::parse_str("(module (memory 1 1 shared))").unwrap();
    let resolved: ResolutionFiles = [
        (RESOLVED_CHILD.into(), wasm(7)),
        (B.into(), wasm(8)),
        (UNKNOWN_FILE.into(), unknown),
        (CUSTOM_FILE.into(), custom),
        (GC_FILE.into(), gc),
        (FUTURE_FILE.into(), future),
    ]
    .into();
    run(&["rm", path(&right), "--cached", A]);
    fs::remove_file(right.join(A)).unwrap();
    for (name, bytes) in &resolved {
        write(&right, name, bytes);
    }
    run(&[
        "add",
        path(&right),
        RESOLVED_CHILD,
        B,
        UNKNOWN_FILE,
        CUSTOM_FILE,
        GC_FILE,
        FUTURE_FILE,
    ]);
    // The reviewed index, not a later dirty worktree, is the supplied result.
    write(&right, B, &wasm(99));
    fs::write(right.join("local-note"), b"untracked caller bytes").unwrap();
    let supplied_index = fs::read(right.join(".uwgit/index")).unwrap();
    let dirty_worktree = resolution_worktree(&right);
    let before_rejected = metadata(&right);
    let rejected = command(&[
        "merge",
        path(&right),
        &their_tip,
        "-m",
        "stale review",
        "--resolved-index",
        "--expect-head",
        &initial,
    ])
    .output()
    .unwrap();
    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(metadata(&right), before_rejected);
    assert_eq!(resolution_worktree(&right), dirty_worktree);
    let merged = value(&[
        "merge",
        path(&right),
        &their_tip,
        "-m",
        "reviewed complete index",
        "--resolved-index",
        "--expect-head",
        &our_tip,
    ]);
    resolution_evidence(&merged, &base, &ours, &theirs, &resolved);
    let merged_tip = tip(&right);
    assert_eq!(
        value(&["show", path(&right), "HEAD"])["parents"],
        json!([our_tip, their_tip])
    );
    assert_eq!(
        fs::read(right.join(".uwgit/index")).unwrap(),
        supplied_index
    );
    assert_eq!(resolution_worktree(&right), dirty_worktree);
    run(&["tag", path(&right), "reviewed_resolution"]);
    transfer(&["push", path(&right)]);
    transfer(&["push", path(&right), "origin", "--tags"]);
    for (index, (name, bytes)) in resolved.iter().enumerate() {
        export(
            upstream,
            "HEAD",
            name,
            &temp.path(&format!("resolved-export-{index}.wasm")),
            bytes,
        );
    }
    let prefix_diff = value(&[
        "diff",
        &initial,
        &merged_tip,
        "--repo",
        path(upstream),
        "--format",
        "json",
    ]);
    for (name, status) in [(A, "deleted"), (RESOLVED_CHILD, "added")] {
        assert!(prefix_diff["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == name && row["status"] == status));
    }
    resolution_profiles(upstream, &merged_tip);
    let left_index = fs::read(left.join(".uwgit/index")).unwrap();
    let left_worktree = resolution_worktree(&left);
    transfer(&["fetch", path(&left)]);
    assert_eq!(tip(&left), their_tip);
    assert_eq!(fs::read(left.join(".uwgit/index")).unwrap(), left_index);
    assert_eq!(resolution_worktree(&left), left_worktree);
    transfer(&[
        "pull",
        path(&left),
        "origin",
        "main",
        "-m",
        "file becomes directory",
    ]);
    assert_eq!(tip(&left), merged_tip);
    assert!(left.join(A).is_dir());
    for (name, bytes) in &resolved {
        assert_eq!(fs::read(left.join(name)).unwrap(), *bytes);
    }

    run(&["restore", path(&right), "--source", "HEAD", B]);
    run(&["rm", path(&right), "--cached", RESOLVED_CHILD]);
    fs::remove_file(right.join(RESOLVED_CHILD)).unwrap();
    fs::remove_dir(right.join(A)).unwrap();
    write(&right, A, &wasm(20));
    run(&["add", path(&right), A]);
    run(&["commit", path(&right), "-m", "directory becomes file"]);
    let reverse_tip = tip(&right);
    transfer(&["push", path(&right)]);
    transfer(&[
        "pull",
        path(&left),
        "origin",
        "main",
        "-m",
        "receive directory to file",
    ]);
    assert_eq!(tip(&left), reverse_tip);
    assert!(left.join(A).is_file());
    assert_eq!(fs::read(left.join(A)).unwrap(), wasm(20));
    assert!(!left.join(RESOLVED_CHILD).exists());
    let reverse_diff = value(&[
        "diff",
        &merged_tip,
        &reverse_tip,
        "--repo",
        path(upstream),
        "--format",
        "json",
    ]);
    for (name, status) in [(A, "added"), (RESOLVED_CHILD, "deleted")] {
        assert!(reverse_diff["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == name && row["status"] == status));
    }
    let reverse: ResolutionFiles = resolved
        .iter()
        .filter(|(name, _)| name.as_str() != RESOLVED_CHILD)
        .map(|(name, bytes)| (name.clone(), bytes.clone()))
        .chain([(A.into(), wasm(20))])
        .collect();
    for (name, bytes) in &reverse {
        assert_eq!(fs::read(left.join(name)).unwrap(), *bytes);
    }

    // A real empty index is a complete intentional tree, rather than no index.
    let mut empty_theirs = reverse.clone();
    empty_theirs.insert(B.into(), wasm(21));
    let mut empty_ours = reverse.clone();
    empty_ours.insert(B.into(), wasm(22));
    for (repository, bytes) in [(&left, wasm(21)), (&right, wasm(22))] {
        write(repository, B, &bytes);
        run(&["add", path(repository), B]);
        run(&[
            "commit",
            path(repository),
            "-m",
            "divergence before empty resolution",
        ]);
    }
    let (empty_their_tip, empty_our_tip) = (tip(&left), tip(&right));
    transfer(&["push", path(&left)]);
    transfer(&["fetch", path(&right)]);
    run(&[
        "rm",
        path(&right),
        "--cached",
        A,
        B,
        UNKNOWN_FILE,
        CUSTOM_FILE,
        GC_FILE,
        FUTURE_FILE,
    ]);
    let empty_index = fs::read(right.join(".uwgit/index")).unwrap();
    let retained_worktree = resolution_worktree(&right);
    let empty_report = value(&[
        "merge",
        path(&right),
        &empty_their_tip,
        "-m",
        "explicit empty tree resolution",
        "--resolved-index",
        "--expect-head",
        &empty_our_tip,
    ]);
    resolution_evidence(
        &empty_report,
        &reverse,
        &empty_ours,
        &empty_theirs,
        &ResolutionFiles::new(),
    );
    let empty_tip = tip(&right);
    assert_eq!(
        value(&["show", path(&right), "HEAD"])["parents"],
        json!([empty_our_tip, empty_their_tip])
    );
    assert_eq!(fs::read(right.join(".uwgit/index")).unwrap(), empty_index);
    assert_eq!(resolution_worktree(&right), retained_worktree);
    run(&["tag", path(&right), "empty_resolution"]);
    transfer(&["push", path(&right)]);
    transfer(&["push", path(&right), "origin", "--tags"]);
    let before_empty_fetch = resolution_worktree(&left);
    let index_before_empty_fetch = fs::read(left.join(".uwgit/index")).unwrap();
    transfer(&["fetch", path(&left)]);
    assert_eq!(tip(&left), empty_their_tip);
    assert_eq!(resolution_worktree(&left), before_empty_fetch);
    assert_eq!(
        fs::read(left.join(".uwgit/index")).unwrap(),
        index_before_empty_fetch
    );
    transfer(&[
        "pull",
        path(&left),
        "origin",
        "main",
        "-m",
        "receive empty resolved tree",
    ]);
    assert_eq!(tip(&left), empty_tip);
    for name in reverse.keys() {
        assert!(!left.join(name).exists());
    }
    let empty_clone = temp.path("resolved-empty-clone");
    transfer(&["clone", url, path(&empty_clone)]);
    assert_eq!(tip(&empty_clone), empty_tip);
    assert_eq!(
        run(&["rev-parse", path(&empty_clone), "reviewed_resolution"]).trim(),
        merged_tip
    );
    assert_eq!(
        run(&["rev-parse", path(&empty_clone), "empty_resolution"]).trim(),
        empty_tip
    );
    assert_eq!(
        run(&["rev-parse", path(&empty_clone), "feature"]).trim(),
        initial
    );
    assert_eq!(
        run(&["rev-parse", path(&empty_clone), "review_right"]).trim(),
        our_tip
    );
    let inspection = value(&["inspect", "HEAD", "--repo", path(&empty_clone), "--json"]);
    assert_eq!(inspection["file_count"], 0);
    assert_eq!(inspection["files"], json!([]));
    assert_eq!(
        value(&["show", path(&empty_clone), "HEAD"])["parents"],
        json!([empty_our_tip, empty_their_tip])
    );
    assert_eq!(
        value(&["show", path(&empty_clone), &merged_tip])["parents"],
        json!([our_tip, their_tip])
    );
    for (index, (name, bytes)) in resolved.iter().enumerate() {
        export(
            &empty_clone,
            "reviewed_resolution",
            name,
            &temp.path(&format!("historical-export-{index}.wasm")),
            bytes,
        );
    }
    for repository in [upstream, &left, &right, &empty_clone, &no_index] {
        run(&["fsck", path(repository)]);
    }
}

#[test]
fn real_http_transfers_reviewed_index_merges_prefix_conversions_and_empty_resolution() {
    let temp = Temp::new();
    let (_, upstream, _) = seed(&temp);
    let server = Server::start(&temp);
    remote_resolution_scenario(&temp, &upstream, &server.url(), |args| {
        command(args)
            .env("UWGIT_REMOTE_TOKEN", TOKEN)
            .output()
            .unwrap()
    });
}

#[cfg(unix)]
#[test]
fn ssh_stdio_transfers_reviewed_index_merges_prefix_conversions_and_empty_resolution() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new();
    let (_, upstream, _) = seed(&temp);
    let shim = temp.path("resolution-ssh-program");
    fs::write(&shim, b"#!/bin/sh\nset -eu\nexec \"$UWGIT_TREE_TEST_BINARY\" server --stdio --root \"$UWGIT_TREE_TEST_ROOT\"\n").unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
    let url = format!(
        "ssh://test@localhost{}/project",
        temp.path("repositories").display()
    );
    remote_resolution_scenario(&temp, &upstream, &url, |args| {
        command(args)
            .env("UWGIT_SSH_PROGRAM", &shim)
            .env("UWGIT_TREE_TEST_BINARY", env!("CARGO_BIN_EXE_wasm-git"))
            .env("UWGIT_TREE_TEST_ROOT", temp.path("repositories"))
            .output()
            .unwrap()
    });
}
