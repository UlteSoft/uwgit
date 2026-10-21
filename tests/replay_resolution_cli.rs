//! Fixed explicitly reviewed single-parent replay cases. No fuzz or guest execution.
//! All fixtures, malformed metadata, locks and outputs remain below /tmp.
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const UNKNOWN: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp {
    base: PathBuf,
    repo: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let base = PathBuf::from(format!(
            "/tmp/uwgit-replay-resolution-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let repo = base.join("repo");
        ok(&["init", s(&repo)]);
        Self { base, repo }
    }
    fn root(&self) -> &str {
        s(&self.repo)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.repo.join(name)
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.path(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn stage(&self, name: &str, bytes: &[u8]) {
        self.write(name, bytes);
        ok(&["add", self.root(), "--", name]);
    }
    fn head(&self) -> String {
        ok(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn commit(&self, message: &str) -> String {
        ok(&["commit", self.root(), "-m", message]);
        self.head()
    }
    fn entries(&self, revision: &str) -> Value {
        let info = value(&["show", self.root(), revision]);
        value(&[
            "cat-file",
            self.root(),
            "-p",
            info["tree"].as_str().unwrap(),
        ])["entries"]
            .clone()
    }
    fn stored(&self, path: &str) -> Vec<u8> {
        let entries = self.entries("HEAD");
        let output = self.base.join(format!(
            "witness-{}",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        ok(&[
            "cat-file",
            self.root(),
            entries[path].as_str().unwrap(),
            "--output",
            s(&output),
        ]);
        fs::read(output).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = invoke(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn value(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn module(a: i32, b: i32) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (func (result i32) i32.const {a}) (func (result i32) i32.const {b}))"
    ))
    .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                files.insert(relative, Entry::Symlink(fs::read_link(path).unwrap()));
            } else if kind.is_dir() {
                files.insert(relative, Entry::Directory);
                visit(root, &path, files);
            } else {
                assert!(kind.is_file());
                files.insert(relative, Entry::File(fs::read(path).unwrap()));
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}
fn worktree(t: &Temp) -> BTreeMap<PathBuf, Entry> {
    snapshot(&t.repo)
        .into_iter()
        .filter(|(path, _)| !path.starts_with(".uwgit"))
        .collect()
}
fn unchanged_at(root: &Path, args: &[&str]) {
    let before = snapshot(root);
    let output = invoke(args);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        snapshot(root),
        before,
        "rejected replay changed state: {args:?}"
    );
}
fn unchanged(t: &Temp, args: &[&str]) {
    unchanged_at(&t.repo, args);
}
fn resolve(t: &Temp, operation: &str, target: &str, head: &str, extra: &[&str]) -> Value {
    let mut args = vec![
        operation,
        t.root(),
        target,
        "--resolved-index",
        "--expect-head",
        head,
    ];
    args.extend_from_slice(extra);
    value(&args)
}
fn file<'a>(report: &'a Value, path: &str) -> &'a Value {
    report["file_reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == path)
        .unwrap()
}
fn conflicting_history(t: &Temp) -> (String, String, String) {
    t.stage("a.wasm", &module(0, 0));
    t.stage("delete.wasm", HEADER);
    let base = t.commit("base");
    ok(&["branch", t.root(), "topic"]);
    t.stage("a.wasm", &module(1, 0));
    let ours = t.commit("ours");
    ok(&["switch", t.root(), "topic"]);
    t.stage("a.wasm", &module(2, 0));
    t.stage("target-only.wasm", HEADER);
    let target = t.commit("target");
    ok(&["switch", t.root(), "main"]);
    (base, ours, target)
}

#[test]
fn reviewed_cherry_pick_commits_one_parent_and_preserves_complete_index_and_dirty_worktree() {
    let t = Temp::new();
    let (base, ours, target) = conflicting_history(&t);
    let before = snapshot(&t.repo);
    let conflict = invoke(&["cherry-pick", t.root(), "topic"]);
    assert_eq!(conflict.status.code(), Some(2));
    let conflict: Value = serde_json::from_slice(&conflict.stdout).unwrap();
    assert_eq!(conflict["branch"], "main");
    assert_eq!(conflict["old_head"], ours);
    assert_eq!(conflict["target"], target);
    assert_eq!(conflict["selected_parent"], base);
    assert_eq!(conflict["mainline"], 1);
    assert_eq!(snapshot(&t.repo), before);
    let resolved = module(9, 0);
    t.stage("a.wasm", &resolved);
    t.stage("target-only.wasm", HEADER);
    t.stage("chosen/unknown.wasm", UNKNOWN);
    ok(&["rm", t.root(), "--cached", "--", "delete.wasm"]);
    t.write("a.wasm", b"unfinished editor bytes\0\xff");
    fs::remove_file(t.path("chosen/unknown.wasm")).unwrap();
    t.write("private.txt", b"untracked private data");
    let index = fs::read(t.path(".uwgit/index")).unwrap();
    let working = worktree(&t);
    let report = resolve(
        &t,
        "cherry-pick",
        &target,
        &ours,
        &["--expect-branch", "main", "-m", "--help"],
    );
    assert_eq!(report["status"], "committed_resolved");
    assert_eq!(report["resolution_source"], "index");
    assert_eq!(report["automatic_replay_checked"], false);
    assert_eq!(report["pending_state_required"], false);
    assert_eq!(report["index_updated"], false);
    assert_eq!(report["worktree_updated"], false);
    assert_eq!(report["parents"], serde_json::json!([ours]));
    assert_eq!(report["selected_parent"], base);
    assert_eq!(report["mainline"], 1);
    assert_eq!(report["target"], target);
    let commit = value(&["show", t.root(), "HEAD"]);
    assert_eq!(commit["parents"], report["parents"]);
    assert_eq!(commit["message"], "--help");
    assert_eq!(t.stored("a.wasm"), resolved);
    assert_eq!(t.stored("chosen/unknown.wasm"), UNKNOWN);
    assert_eq!(t.stored("target-only.wasm"), HEADER);
    assert!(t.entries("HEAD").get("delete.wasm").is_none());
    assert_eq!(file(&report, "a.wasm")["from_head"]["status"], "modified");
    assert!(!file(&report, "a.wasm")["from_head"]["audit"].is_null());
    assert_eq!(
        file(&report, "delete.wasm")["from_head"]["status"],
        "deleted"
    );
    assert_eq!(
        file(&report, "chosen/unknown.wasm")["resolved"]["hex"],
        hex(UNKNOWN)
    );
    assert!(!file(&report, "chosen/unknown.wasm")["resolved"]["audit"].is_null());
    assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
    assert_eq!(worktree(&t), working);
    assert_eq!(ok(&["rev-parse", t.root(), "topic"]).trim(), target);
    value(&["fsck", t.root()]);
}

#[test]
fn root_targets_allow_reviewed_empty_trees_without_a_prior_conflict_or_pending_state() {
    for operation in ["cherry-pick", "revert"] {
        let t = Temp::new();
        t.stage("a.wasm", &module(0, 0));
        let root = t.commit("root");
        t.stage("a.wasm", &module(1, 0));
        let head = t.commit("current head");
        ok(&["rm", t.root(), "--cached", "a.wasm"]);
        let index = fs::read(t.path(".uwgit/index")).unwrap();
        let working = worktree(&t);
        unchanged(
            &t,
            &[
                operation,
                t.root(),
                &root,
                "--resolved-index",
                "--expect-head",
                &head,
                "--mainline",
                "1",
            ],
        );
        let report = resolve(&t, operation, &root, &head, &[]);
        assert_eq!(report["status"], "committed_resolved");
        assert!(report["mainline"].is_null());
        assert!(report["selected_parent"].is_null());
        assert_eq!(report["parents"], serde_json::json!([head]));
        assert_eq!(
            file(&report, "a.wasm")["intended_change"]["status"],
            if operation == "revert" {
                "deleted"
            } else {
                "added"
            }
        );
        assert_eq!(file(&report, "a.wasm")["from_head"]["status"], "deleted");
        assert_eq!(t.entries("HEAD"), serde_json::json!({}));
        assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
        assert_eq!(worktree(&t), working);
        value(&["fsck", t.root()]);
    }
}

#[test]
fn reviewed_merge_mainline_two_keeps_single_parent_and_reverses_the_intended_delta() {
    for operation in ["cherry-pick", "revert"] {
        let t = Temp::new();
        t.stage("a.wasm", &module(0, 0));
        t.commit("base");
        ok(&["branch", t.root(), "topic"]);
        t.stage("a.wasm", &module(1, 0));
        t.commit("ours");
        ok(&["switch", t.root(), "topic"]);
        let parent_bytes = module(0, 2);
        t.stage("a.wasm", &parent_bytes);
        let parent = t.commit("theirs");
        ok(&["switch", t.root(), "main"]);
        let merged = value(&["merge", t.root(), "topic", "-m", "merge"]);
        assert_eq!(merged["status"], "merged");
        let target = t.head();
        let merged_bytes = module(1, 2);
        t.stage("a.wasm", UNKNOWN);
        t.write("a.wasm", b"unstaged bytes");
        unchanged(
            &t,
            &[
                operation,
                t.root(),
                &target,
                "--resolved-index",
                "--expect-head",
                &target,
            ],
        );
        unchanged(
            &t,
            &[
                operation,
                t.root(),
                &target,
                "--resolved-index",
                "--expect-head",
                &target,
                "--mainline",
                "0",
            ],
        );
        unchanged(
            &t,
            &[
                operation,
                t.root(),
                &target,
                "--resolved-index",
                "--expect-head",
                &target,
                "--mainline",
                "3",
            ],
        );
        let working = worktree(&t);
        let index = fs::read(t.path(".uwgit/index")).unwrap();
        let report = resolve(
            &t,
            operation,
            &target,
            &target,
            &["--mainline", "2", "--message", "--ff-only"],
        );
        assert_eq!(report["parents"], serde_json::json!([target]));
        assert_eq!(report["selected_parent"], parent);
        assert_eq!(report["mainline"], 2);
        let row = file(&report, "a.wasm");
        let (before, after) = if operation == "revert" {
            (&merged_bytes, &parent_bytes)
        } else {
            (&parent_bytes, &merged_bytes)
        };
        assert_eq!(row["base"]["hex"], hex(before));
        assert_eq!(row["theirs"]["hex"], hex(after));
        assert_eq!(row["intended_change"]["status"], "modified");
        assert_eq!(value(&["show", t.root(), "HEAD"])["message"], "--ff-only");
        assert_eq!(t.stored("a.wasm"), UNKNOWN);
        assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
        assert_eq!(worktree(&t), working);
    }
}

#[test]
fn malformed_review_ids_options_and_same_tip_wrong_branch_are_zero_write_errors() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    let target = t.commit("target root");
    t.stage("a.wasm", &module(1, 0));
    let head = t.commit("head");
    ok(&["branch", t.root(), "same-tip"]);
    ok(&["switch", t.root(), "same-tip"]);
    let entries = t.entries("HEAD");
    let blob = entries["a.wasm"].as_str().unwrap();
    t.stage("a.wasm", UNKNOWN);
    let missing = "a".repeat(64);
    let upper = target.to_uppercase();
    for bad in ["HEAD", &target[..8], upper.as_str(), missing.as_str(), blob] {
        unchanged(
            &t,
            &[
                "cherry-pick",
                t.root(),
                bad,
                "--resolved-index",
                "--expect-head",
                &head,
            ],
        );
    }
    for bad in ["HEAD", &head[..8], "--help", "-h", target.as_str()] {
        unchanged(
            &t,
            &[
                "revert",
                t.root(),
                &target,
                "--resolved-index",
                "--expect-head",
                bad,
            ],
        );
    }
    for args in [
        vec!["cherry-pick", t.root(), &target, "--resolved-index"],
        vec!["cherry-pick", t.root(), &target, "--expect-head", &head],
        vec![
            "cherry-pick",
            t.root(),
            &target,
            "--resolved-index",
            "--expect-head",
            &head,
            "--expect-branch",
            "main",
        ],
        vec![
            "revert",
            t.root(),
            &target,
            "--resolved-index",
            "--resolved-index",
            "--expect-head",
            &head,
        ],
        vec![
            "rebase",
            t.root(),
            &target,
            "--resolved-index",
            "--expect-head",
            &head,
        ],
    ] {
        unchanged(&t, &args);
    }
    unchanged(&t, &["branch", t.root(), &target, &head]);
    unchanged(&t, &["branch", t.root(), &head, &target]);
    let report = resolve(
        &t,
        "cherry-pick",
        &target,
        &head,
        &["--expect-branch", "same-tip"],
    );
    assert_eq!(report["branch"], "same-tip");
    assert_eq!(report["parents"], serde_json::json!([head]));
}

#[test]
fn missing_invalid_or_locked_index_and_unborn_head_never_publish_a_resolution() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    let head = t.commit("root");
    let clone = t.base.join("without-index");
    ok(&["clone", t.root(), s(&clone)]);
    unchanged_at(
        &clone,
        &[
            "cherry-pick",
            s(&clone),
            &head,
            "--resolved-index",
            "--expect-head",
            &head,
        ],
    );
    for name in ["index.lock", "write.lock"] {
        let lock = t.path(&format!(".uwgit/{name}"));
        fs::write(&lock, b"held fixed lock").unwrap();
        unchanged(
            &t,
            &[
                "revert",
                t.root(),
                &head,
                "--resolved-index",
                "--expect-head",
                &head,
            ],
        );
        fs::remove_file(lock).unwrap();
    }
    let index = t.path(".uwgit/index");
    let original = fs::read(&index).unwrap();
    let files = BTreeMap::from([
        ("bad".to_owned(), HEADER),
        ("bad/child.wasm".to_owned(), HEADER),
    ]);
    let payload = format!(
        "{{\"format\":2,\"files\":{},\"legacy_path\":null}}\n",
        serde_json::to_string(&files).unwrap()
    );
    let mut corrupt = b"UWGITIDX\x02".to_vec();
    corrupt.extend_from_slice(payload.as_bytes());
    fs::write(&index, corrupt).unwrap();
    unchanged(
        &t,
        &[
            "cherry-pick",
            t.root(),
            &head,
            "--resolved-index",
            "--expect-head",
            &head,
        ],
    );
    fs::write(index, original).unwrap();
    let unborn = Temp::new();
    unborn.stage("a.wasm", HEADER);
    unchanged(
        &unborn,
        &[
            "revert",
            unborn.root(),
            &head,
            "--resolved-index",
            "--expect-head",
            &head,
        ],
    );
}

#[test]
fn dangling_store_corruption_is_rejected_before_any_resolution_objects_are_installed() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    let root = t.commit("root");
    t.stage("a.wasm", &module(3, 0));
    let dangling = t.commit("unreferenced history");
    let entries = t.entries(&dangling);
    let blob = entries["a.wasm"].as_str().unwrap();
    ok(&["reset", t.root(), "--hard", &root]);
    t.stage("a.wasm", UNKNOWN);
    fs::write(
        t.path(&format!(".uwgit/objects/{blob}")),
        b"tampered dangling blob",
    )
    .unwrap();
    unchanged(
        &t,
        &[
            "cherry-pick",
            t.root(),
            &root,
            "--resolved-index",
            "--expect-head",
            &root,
        ],
    );
}

#[test]
fn reviewed_legacy_replay_requires_the_explicit_index_anchor_and_rejects_other_bindings() {
    let t = Temp::new();
    let input = t.base.join("legacy.wasm");
    fs::write(&input, module(0, 1)).unwrap();
    ok(&["commit", t.root(), s(&input), "-m", "legacy root"]);
    let legacy = t.head();
    t.stage("chosen.wasm", &module(2, 1));
    t.stage("other.wasm", UNKNOWN);
    t.write("chosen.wasm", b"preserved unfinished legacy work");
    let index = fs::read(t.path(".uwgit/index")).unwrap();
    let working = worktree(&t);
    let report = resolve(&t, "cherry-pick", &legacy, &legacy, &[]);
    assert_eq!(report["legacy_path"], "chosen.wasm");
    assert_eq!(report["parents"], serde_json::json!([legacy]));
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["legacy_path"],
        "chosen.wasm"
    );
    assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
    assert_eq!(worktree(&t), working);
    let other = Temp::new();
    ok(&["commit", other.root(), s(&input), "-m", "legacy root"]);
    other.stage("different.wasm", &module(3, 1));
    let target = other.commit("other anchor");
    let bundle = t.base.join("other.bundle");
    ok(&["bundle", other.root(), s(&bundle)]);
    ok(&["unbundle", t.root(), s(&bundle), "incoming"]);
    let head = t.head();
    unchanged(
        &t,
        &[
            "revert",
            t.root(),
            &target,
            "--resolved-index",
            "--expect-head",
            &head,
        ],
    );
    value(&["fsck", t.root()]);
}

#[cfg(unix)]
#[test]
fn metadata_only_resolution_never_reads_or_replaces_a_tracked_worktree_symlink() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    let root = t.commit("root");
    t.stage("a.wasm", UNKNOWN);
    fs::remove_file(t.path("a.wasm")).unwrap();
    let private = t.base.join("outside.txt");
    fs::write(&private, b"preserve symlink target").unwrap();
    std::os::unix::fs::symlink(&private, t.path("a.wasm")).unwrap();
    let working = worktree(&t);
    let index = fs::read(t.path(".uwgit/index")).unwrap();
    let report = resolve(&t, "revert", &root, &root, &[]);
    assert_eq!(report["status"], "committed_resolved");
    assert_eq!(t.stored("a.wasm"), UNKNOWN);
    assert_eq!(worktree(&t), working);
    assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(private).unwrap(), b"preserve symlink target");
}
