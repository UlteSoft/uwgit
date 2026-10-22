use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-notes-{}-{}",
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
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn execute(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = execute(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim_end().into()
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn fail(args: &[&str]) {
    assert!(!execute(args).status.success(), "{args:?}");
}
fn seed(root: &Path) -> String {
    ok(&["init", p(root)]);
    fs::write(root.join("a.wasm"), b"\0asm\x01\0\0\0").unwrap();
    ok(&["add", p(root), "a.wasm"]);
    ok(&["commit", p(root), "-m", "root"]);
    ok(&["rev-parse", p(root), "HEAD"])
}
fn objects(root: &Path) -> usize {
    fs::read_dir(root.join(".uwgit/objects")).unwrap().count()
}

#[test]
fn notes_add_append_force_copy_and_atomic_removal_preserve_head_index_and_work_bytes() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let head = seed(&root);
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    let bytes = fs::read(root.join("a.wasm")).unwrap();
    let first = json(&["notes", p(&root), "add", "-m", "模块注释", &head]);
    assert_eq!(ok(&["notes", p(&root), "show"]), "模块注释");
    let before = objects(&root);
    fail(&["notes", p(&root), "add", "-m", "duplicate"]);
    assert_eq!(objects(&root), before);
    json(&["notes", p(&root), "append", "-m", "second"]);
    assert_eq!(ok(&["notes", p(&root), "show"]), "模块注释\n\nsecond");
    json(&["notes", p(&root), "add", "-f", "-m", "--help"]);
    assert_eq!(ok(&["notes", p(&root), "show"]), "--help");
    let tree = json(&["ls-tree", p(&root), "HEAD"]);
    let blob = tree["entries"][0]["object_id"].as_str().unwrap();
    json(&["notes", p(&root), "copy", &head, blob]);
    assert_eq!(ok(&["notes", p(&root), "show", blob]), "--help");
    fail(&["notes", p(&root), "remove", &head, &"f".repeat(64)]);
    assert_eq!(
        json(&["notes", p(&root), "list"])["notes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    json(&["notes", p(&root), "remove", &head, blob]);
    assert!(json(&["notes", p(&root), "list"])["notes"]
        .as_array()
        .unwrap()
        .is_empty());
    let latest = json(&["log", p(&root), "uwgit-notes-commits"]);
    assert!(latest
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["id"] == first["commit"]));
    assert_eq!(ok(&["rev-parse", p(&root), "HEAD"]), head);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), bytes);
}

#[test]
fn notes_are_valid_original_wasm_modules_and_transfer_in_native_clones_and_bundles() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let peer = temp.path("peer");
    let head = seed(&root);
    let added = json(&["notes", p(&root), "add", "-m", "retained text"]);
    let note_path = format!("{head}.wasm");
    let module = temp.path("note.wasm");
    ok(&[
        "show",
        p(&root),
        added["commit"].as_str().unwrap(),
        "--file",
        &note_path,
        "--output",
        p(&module),
    ]);
    let bytes = fs::read(&module).unwrap();
    wasmparser::Validator::new().validate_all(&bytes).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("retained text"));
    ok(&["clone", p(&root), p(&peer)]);
    assert_eq!(ok(&["notes", p(&peer), "show"]), "retained text");
    assert_eq!(
        ok(&["rev-parse", p(&peer), "uwgit-notes-commits"]),
        added["commit"].as_str().unwrap()
    );
    let bundle = temp.path("history.uwgb");
    ok(&["bundle", p(&root), p(&bundle)]);
    let imported = temp.path("imported");
    ok(&["init", p(&imported)]);
    ok(&["unbundle", p(&imported), p(&bundle), "incoming"]);
    ok(&[
        "update-ref",
        p(&imported),
        "refs/heads/uwgit-notes-commits",
        added["commit"].as_str().unwrap(),
        &"0".repeat(64),
    ]);
    assert_eq!(ok(&["notes", p(&imported), "show", &head]), "retained text");
    ok(&["fsck", p(&peer)]);
    ok(&["fsck", p(&imported)]);
}

#[test]
fn namespaces_and_checked_out_notes_branches_are_independent_and_protected() {
    let temp = Temp::new();
    let root = temp.path("repo");
    let linked = temp.path("notes-tree");
    seed(&root);
    json(&["notes", p(&root), "--ref", "sdk", "add", "-m", "sdk"]);
    assert!(json(&["notes", p(&root), "list"])["notes"]
        .as_array()
        .unwrap()
        .is_empty());
    json(&["worktree", p(&root), "add", p(&linked), "uwgit-notes-sdk"]);
    let before = objects(&root);
    fail(&["notes", p(&root), "--ref", "sdk", "append", "-m", "blocked"]);
    assert_eq!(objects(&root), before);
    assert_eq!(ok(&["notes", p(&root), "--ref", "sdk", "show"]), "sdk");
    json(&["worktree", p(&root), "remove", p(&linked)]);
    json(&["notes", p(&root), "--ref", "sdk", "append", "-m", "allowed"]);
}

#[test]
fn malformed_namespace_or_foreign_notes_layout_cannot_publish_partial_changes() {
    let temp = Temp::new();
    let root = temp.path("repo");
    seed(&root);
    ok(&["branch", p(&root), "uwgit-notes-bad"]);
    let before = objects(&root);
    fail(&["notes", p(&root), "--ref", "bad", "add", "-m", "blocked"]);
    fail(&[
        "notes",
        p(&root),
        "--ref",
        "../escape",
        "add",
        "-m",
        "blocked",
    ]);
    fail(&["notes", p(&root), "add", "-m", "missing", &"f".repeat(64)]);
    assert_eq!(objects(&root), before);
    assert!(!root.join(".uwgit/notes.json").exists());
    ok(&["fsck", p(&root)]);
}
