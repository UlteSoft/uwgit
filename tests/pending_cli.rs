//! Fixed, persisted single-target conflict workflows. No fuzz or guest execution.
use serde_json::{json, Value};
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
            "/tmp/uwgit-pending-{}-{}",
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
    fn pending(&self) -> PathBuf {
        self.path(".uwgit/pending.json")
    }
    fn record(&self, operation: &str, target: &str) -> Value {
        let output = invoke(&[
            operation,
            self.root(),
            target,
            "--record-conflict",
            "-m",
            "--help",
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{operation}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn stored(&self, path: &str) -> Vec<u8> {
        let commit = value(&["show", self.root(), "HEAD"]);
        let tree = value(&[
            "cat-file",
            self.root(),
            "-p",
            commit["tree"].as_str().unwrap(),
        ]);
        let output = self.base.join(format!(
            "export-{}",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        ok(&[
            "cat-file",
            self.root(),
            tree["entries"][path].as_str().unwrap(),
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
fn module(value: i32) -> Vec<u8> {
    wat::parse_str(format!("(module (func (result i32) i32.const {value}))")).unwrap()
}
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, directory: &Path, rows: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                rows.insert(relative, Entry::Symlink(fs::read_link(path).unwrap()));
            } else if kind.is_dir() {
                rows.insert(relative, Entry::Directory);
                visit(root, &path, rows);
            } else {
                assert!(kind.is_file());
                rows.insert(relative, Entry::File(fs::read(path).unwrap()));
            }
        }
    }
    let mut rows = BTreeMap::new();
    visit(root, root, &mut rows);
    rows
}
fn worktree(t: &Temp) -> BTreeMap<PathBuf, Entry> {
    snapshot(&t.repo)
        .into_iter()
        .filter(|(path, _)| !path.starts_with(".uwgit"))
        .collect()
}
fn rejected(t: &Temp, args: &[&str]) -> String {
    let before = snapshot(&t.repo);
    let output = invoke(args);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        snapshot(&t.repo),
        before,
        "rejected operation changed state: {args:?}"
    );
    String::from_utf8(output.stderr).unwrap()
}
fn conflicting_history(t: &Temp, operation: &str) -> (String, String) {
    t.stage("a.wasm", &module(0));
    t.stage("retained.wasm", HEADER);
    t.commit("base");
    ok(&["branch", t.root(), "topic"]);
    t.stage("a.wasm", &module(1));
    let ours = t.commit("ours");
    ok(&["switch", t.root(), "topic"]);
    t.stage("a.wasm", &module(2));
    let target = t.commit("target");
    ok(&["switch", t.root(), "main"]);
    if operation == "revert" {
        t.stage("a.wasm", &module(3));
        (t.commit("after target"), ours)
    } else {
        (ours, target)
    }
}

#[test]
fn recording_is_explicit_and_changes_only_the_pending_record_on_conflict() {
    for operation in ["merge", "cherry-pick", "revert"] {
        let t = Temp::new();
        let (head, target) = conflicting_history(&t, operation);
        let before = snapshot(&t.repo);
        let plain = invoke(&[operation, t.root(), &target, "-m", "stateless"]);
        assert_eq!(plain.status.code(), Some(2));
        assert_eq!(snapshot(&t.repo), before);
        let report = t.record(operation, &target);
        assert_eq!(report["status"], "conflict");
        assert_eq!(t.head(), head);
        assert!(t.pending().is_file());
        let mut recorded = snapshot(&t.repo);
        recorded.remove(Path::new(".uwgit/pending.json"));
        assert_eq!(recorded, before);
        let status = value(&["status", t.root()]);
        assert_eq!(status["pending"]["operation"], operation);
        assert_eq!(status["pending"]["stale"], false);
        assert!(status["pending"].get("baseline_index").is_none());
        rejected(
            &t,
            &[
                operation,
                t.root(),
                &target,
                "--record-conflict",
                "-m",
                "again",
            ],
        );
        let quit = value(&[operation, t.root(), "--quit"]);
        assert_eq!(quit["status"], "quit");
        assert_eq!(snapshot(&t.repo), before);
    }
}

#[test]
fn continue_uses_the_complete_index_and_correct_parents_without_touching_work_files() {
    for operation in ["merge", "cherry-pick", "revert"] {
        let t = Temp::new();
        let (head, target) = conflicting_history(&t, operation);
        t.record(operation, &target);
        let resolved = module(9);
        t.stage("a.wasm", &resolved);
        t.stage("new/unknown.wasm", UNKNOWN);
        ok(&["rm", t.root(), "--cached", "--", "retained.wasm"]);
        t.write("a.wasm", b"unfinished editor data\0\xff");
        fs::remove_file(t.path("new/unknown.wasm")).unwrap();
        t.write("private.txt", b"private untracked bytes");
        let raw = fs::read(t.path(".uwgit/index")).unwrap();
        let working = worktree(&t);
        rejected(&t, &[operation, t.root(), "--continue"]);
        let report = value(&[operation, t.root(), "--continue", "--resolved-index"]);
        assert_eq!(report["status"], "continued");
        assert_eq!(report["index_updated"], false);
        assert_eq!(report["worktree_updated"], false);
        assert_eq!(
            report["tree_manual_resolution"]["supplied_complete_tree"],
            true
        );
        let witness = report["tree_manual_resolution"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["path"] == "new/unknown.wasm")
            .unwrap();
        assert_eq!(witness["resolved"]["hex"], "0061736d01000000ff01fe");
        assert!(!witness["resolved"]["audit"].is_null());
        let commit = value(&["show", t.root(), "HEAD"]);
        let parents = if operation == "merge" {
            json!([head, target])
        } else {
            json!([head])
        };
        assert_eq!(commit["parents"], parents);
        assert_eq!(commit["message"], "--help");
        assert_eq!(t.stored("a.wasm"), resolved);
        assert_eq!(t.stored("new/unknown.wasm"), UNKNOWN);
        assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), raw);
        assert_eq!(worktree(&t), working);
        assert!(!t.pending().exists());
        assert!(value(&["status", t.root()]).get("pending").is_none());
        rejected(&t, &[operation, t.root(), "--continue", "--resolved-index"]);
    }
}

#[test]
fn abort_and_single_target_skip_restore_exact_baseline_but_preserve_new_work_files() {
    for (operation, control) in [
        ("merge", "--abort"),
        ("cherry-pick", "--abort"),
        ("revert", "--abort"),
        ("cherry-pick", "--skip"),
        ("revert", "--skip"),
    ] {
        let t = Temp::new();
        let (head, target) = conflicting_history(&t, operation);
        let raw = fs::read(t.path(".uwgit/index")).unwrap();
        let original_a = fs::read(t.path("a.wasm")).unwrap();
        t.record(operation, &target);
        t.stage("a.wasm", UNKNOWN);
        t.stage("new.wasm", HEADER);
        ok(&["rm", t.root(), "--cached", "--", "retained.wasm"]);
        fs::remove_file(t.path("retained.wasm")).unwrap();
        t.write("a.wasm", b"not yet a wasm module");
        t.write("private.txt", b"preserve");
        let report = value(&[operation, t.root(), control]);
        assert_eq!(
            report["status"],
            if control == "--skip" {
                "skipped"
            } else {
                "aborted"
            }
        );
        assert_eq!(t.head(), head);
        assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), raw);
        assert_eq!(fs::read(t.path("a.wasm")).unwrap(), original_a);
        assert_eq!(fs::read(t.path("retained.wasm")).unwrap(), HEADER);
        assert_eq!(fs::read(t.path("new.wasm")).unwrap(), HEADER);
        assert_eq!(fs::read(t.path("private.txt")).unwrap(), b"preserve");
        assert!(!t.pending().exists());
        assert!(value(&["status", t.root()])["untracked"]
            .as_array()
            .unwrap()
            .contains(&json!("new.wasm")));
    }
}

#[test]
fn abort_refuses_new_directory_or_symlink_obstructions_before_restoring_any_file() {
    let t = Temp::new();
    let (_, target) = conflicting_history(&t, "merge");
    t.record("merge", &target);
    t.stage("a.wasm", UNKNOWN);
    ok(&["rm", t.root(), "--cached", "--", "retained.wasm"]);
    fs::remove_file(t.path("retained.wasm")).unwrap();
    t.write("retained.wasm/child.wasm", HEADER);
    ok(&["add", t.root(), "--", "retained.wasm/child.wasm"]);
    rejected(&t, &["merge", t.root(), "--abort"]);
    fs::remove_file(t.path("retained.wasm/child.wasm")).unwrap();
    fs::remove_dir(t.path("retained.wasm")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("a.wasm", t.path("retained.wasm")).unwrap();
        rejected(&t, &["merge", t.root(), "--abort"]);
        fs::remove_file(t.path("retained.wasm")).unwrap();
    }
    value(&["merge", t.root(), "--quit"]);
}

#[test]
fn quit_forgets_only_the_operation_and_the_default_index_remains_absent_on_abort() {
    let t = Temp::new();
    let (head, target) = conflicting_history(&t, "merge");
    t.record("merge", &target);
    t.stage("a.wasm", UNKNOWN);
    t.write("a.wasm", b"dirty editor bytes");
    let index = fs::read(t.path(".uwgit/index")).unwrap();
    let working = worktree(&t);
    value(&["merge", t.root(), "--quit"]);
    assert_eq!(t.head(), head);
    assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
    assert_eq!(worktree(&t), working);
    ok(&[
        "restore",
        t.root(),
        "--source",
        "HEAD",
        "--staged",
        "--worktree",
    ]);
    fs::remove_file(t.path(".uwgit/index")).unwrap();
    t.record("merge", &target);
    rejected(&t, &["merge", t.root(), "--continue", "--resolved-index"]);
    t.stage("new.wasm", UNKNOWN);
    let working = worktree(&t);
    value(&["merge", t.root(), "--abort"]);
    assert!(!t.path(".uwgit/index").exists());
    assert_eq!(worktree(&t), working);
    assert_eq!(t.head(), head);
}

#[test]
fn pending_guards_history_writes_but_allows_explicit_index_preparation_and_queries() {
    let t = Temp::new();
    let (_, target) = conflicting_history(&t, "merge");
    t.record("merge", &target);
    for tail in [
        vec!["commit", "-m", "ordinary"],
        vec!["commit", "--amend", "-m", "amend"],
        vec!["switch", "topic"],
        vec!["switch", "-c", "new"],
        vec!["checkout", "topic"],
        vec!["checkout", "-b", "new"],
        vec!["reset", "--hard", "HEAD"],
        vec!["reset", "--soft", "HEAD"],
        vec!["reset", "HEAD"],
        vec!["stash", "push"],
        vec!["stash", "apply", "0"],
        vec!["stash", "pop", "0"],
        vec!["branch", "-m", "renamed"],
        vec!["branch", "-m", "main", "renamed"],
        vec!["branch", "-D", "main"],
    ] {
        let mut args = vec![tail[0], t.root()];
        args.extend_from_slice(&tail[1..]);
        assert!(rejected(&t, &args).contains("pending"), "{args:?}");
    }
    rejected(&t, &["merge", t.root(), "topic", "-m", "new merge"]);
    rejected(&t, &["cherry-pick", t.root(), "topic"]);
    rejected(&t, &["revert", t.root(), "HEAD"]);
    rejected(&t, &["rebase", t.root(), "topic"]);
    rejected(&t, &["pull", t.root(), "--ff-only"]);
    assert!(rejected(&t, &["commit", t.root(), "a.wasm", "-m", "file commit"]).contains("pending"));
    t.stage("a.wasm", UNKNOWN);
    ok(&["reset", t.root(), "--", "a.wasm"]);
    ok(&["restore", t.root(), "--", "a.wasm"]);
    ok(&["branch", t.root(), "unrelated"]);
    ok(&["branch", t.root(), "-m", "unrelated", "renamed"]);
    ok(&["branch", t.root(), "-d", "renamed"]);
    ok(&["config", t.root(), "user.name", "pending editor"]);
    value(&["diff", t.root(), "--format", "json"]);
    value(&["status", t.root()]);
    ok(&["fsck", t.root()]);
    value(&["merge", t.root(), "--quit"]);
}

#[test]
fn immutable_target_is_retained_and_wrong_operation_or_changed_head_cannot_resume() {
    let t = Temp::new();
    let (head, target) = conflicting_history(&t, "merge");
    t.record("merge", &target);
    for operation in ["cherry-pick", "revert"] {
        rejected(&t, &[operation, t.root(), "--continue", "--resolved-index"]);
        rejected(&t, &[operation, t.root(), "--abort"]);
        rejected(&t, &[operation, t.root(), "--quit"]);
    }
    rejected(&t, &["merge", t.root(), "--skip"]);
    ok(&["branch", t.root(), "-D", "topic"]);
    ok(&["branch", t.root(), "topic", "HEAD"]);
    t.stage("a.wasm", &module(9));
    value(&["merge", t.root(), "--continue", "--resolved-index"]);
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["parents"],
        json!([head, target])
    );

    let t = Temp::new();
    let (_, target) = conflicting_history(&t, "merge");
    t.record("merge", &target);
    let foreign = ok(&["rev-parse", t.root(), "topic"]);
    fs::write(t.path(".uwgit/refs/main"), format!("{}\n", foreign.trim())).unwrap();
    assert_eq!(value(&["status", t.root()])["pending"]["stale"], true);
    rejected(&t, &["merge", t.root(), "--continue", "--resolved-index"]);
    rejected(&t, &["merge", t.root(), "--abort"]);
    value(&["merge", t.root(), "--quit"]);
    assert_eq!(t.head(), foreign.trim());

    let t = Temp::new();
    let (head, target) = conflicting_history(&t, "merge");
    t.record("merge", &target);
    ok(&["branch", t.root(), "same-tip", "HEAD"]);
    fs::write(t.path(".uwgit/HEAD"), b"same-tip\n").unwrap();
    assert_eq!(value(&["status", t.root()])["pending"]["stale"], true);
    rejected(&t, &["merge", t.root(), "--continue", "--resolved-index"]);
    rejected(&t, &["merge", t.root(), "--abort"]);
    value(&["merge", t.root(), "--quit"]);
    assert_eq!(t.head(), head);
    assert_eq!(
        ok(&["branch", t.root()])
            .lines()
            .filter(|line| line.starts_with('*'))
            .count(),
        1
    );
}

#[test]
fn invalid_control_forms_help_and_locks_do_not_change_pending_or_tracked_bytes() {
    let t = Temp::new();
    let (_, target) = conflicting_history(&t, "merge");
    t.record("merge", &target);
    for tail in [
        vec!["--continue", "--resolved-index", "--abort"],
        vec!["--quit", "--quit"],
        vec!["--abort", "-m", "message"],
        vec!["--continue", "--resolved-index", "topic"],
        vec!["topic", "--continue", "--resolved-index"],
        vec!["--record-conflict", "--abort"],
        vec!["--quit", "--resolved-index"],
    ] {
        let mut args = vec!["merge", t.root()];
        args.extend(tail);
        rejected(&t, &args);
    }
    for lock in ["index.lock", "write.lock"] {
        t.write(&format!(".uwgit/{lock}"), b"occupied");
        rejected(&t, &["merge", t.root(), "--abort"]);
        rejected(&t, &["merge", t.root(), "--continue", "--resolved-index"]);
        rejected(&t, &["merge", t.root(), "--quit"]);
        fs::remove_file(t.path(&format!(".uwgit/{lock}"))).unwrap();
    }
    let before = snapshot(&t.repo);
    ok(&["merge", t.root(), "--continue", "--help"]);
    assert_eq!(snapshot(&t.repo), before);
    value(&["merge", t.root(), "--quit"]);
}

#[test]
fn corrupt_or_redirected_pending_metadata_cannot_authorize_a_history_write() {
    let t = Temp::new();
    let (_, target) = conflicting_history(&t, "merge");
    t.record("merge", &target);
    let raw = fs::read(t.pending()).unwrap();
    fs::write(t.pending(), b"not json\n").unwrap();
    for args in [
        vec!["status", t.root()],
        vec!["merge", t.root(), "--continue", "--resolved-index"],
        vec!["merge", t.root(), "--abort"],
        vec!["merge", t.root(), "--quit"],
        vec!["commit", t.root(), "-m", "ordinary"],
    ] {
        rejected(&t, &args);
    }
    fs::write(t.pending(), &raw).unwrap();
    #[cfg(unix)]
    {
        let outside = t.base.join("external-pending.json");
        fs::write(&outside, &raw).unwrap();
        fs::remove_file(t.pending()).unwrap();
        std::os::unix::fs::symlink(&outside, t.pending()).unwrap();
        rejected(&t, &["merge", t.root(), "--quit"]);
        assert_eq!(fs::read(&outside).unwrap(), raw);
        fs::remove_file(t.pending()).unwrap();
        fs::write(t.pending(), &raw).unwrap();
    }
    value(&["merge", t.root(), "--quit"]);
}

#[test]
fn pending_status_reports_an_unavailable_index_without_claiming_a_clean_tree() {
    let t = Temp::new();
    let (_, target) = conflicting_history(&t, "merge");
    let original = fs::read(t.path(".uwgit/index")).unwrap();
    fs::write(t.path(".uwgit/index"), b"broken index").unwrap();
    rejected(&t, &["status", t.root()]);
    fs::write(t.path(".uwgit/index"), &original).unwrap();
    t.record("merge", &target);
    fs::write(t.path(".uwgit/index"), b"broken index").unwrap();
    let before = snapshot(&t.repo);
    let report = value(&["status", t.root()]);
    assert_eq!(report["index_available"], false);
    assert!(!report["index_error"].as_str().unwrap().is_empty());
    assert!(report["files"].is_null());
    assert!(report["staged"].is_null());
    assert_eq!(report["worktree"], "unavailable");
    assert_eq!(report["pending"]["phase"], "conflict");
    assert_eq!(report["pending"]["stale"], false);
    assert_eq!(snapshot(&t.repo), before);
    rejected(&t, &["merge", t.root(), "--continue", "--resolved-index"]);
    value(&["merge", t.root(), "--abort"]);
    assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), original);
}
