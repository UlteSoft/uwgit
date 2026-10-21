//! Fixed checkout, restore-selector and path-reset workflows. No fuzz input.
//! Every fixture and output stays below /tmp; modules are stored, never run.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const UNKNOWN: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
const HEADER: &[u8] = b"\0asm\x01\0\0\0";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp {
    base: PathBuf,
    repo: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let base = PathBuf::from(format!(
            "/tmp/uwgit-checkout-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let repo = base.join("repo");
        fs::create_dir(&repo).unwrap();
        ok(&["init", s(&repo)]);
        Self { base, repo }
    }
    fn root(&self) -> &str {
        s(&self.repo)
    }
    fn path(&self, path: &str) -> PathBuf {
        self.repo.join(path)
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.path(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn stage(&self, path: &str, bytes: &[u8]) {
        self.write(path, bytes);
        ok(&["add", self.root(), "--", path]);
    }
    fn read(&self, path: &str) -> Vec<u8> {
        fs::read(self.path(path)).unwrap()
    }
    fn commit(&self, message: &str) -> String {
        ok(&["commit", self.root(), "-m", message]);
        self.head()
    }
    fn head(&self) -> String {
        ok(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn staged(&self, path: &str) -> Vec<u8> {
        let output = self.base.join(format!(
            "index-witness-{}",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        ok(&[
            "restore",
            self.root(),
            "--file",
            path,
            "--output",
            s(&output),
        ]);
        let bytes = fs::read(&output).unwrap();
        fs::remove_file(output).unwrap();
        bytes
    }
    fn tracked(&self) -> BTreeSet<String> {
        ok(&["ls-files", self.root()])
            .lines()
            .map(String::from)
            .collect()
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
        "{args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
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
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn walk(root: &Path, directory: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                out.insert(relative, Entry::Symlink(fs::read_link(path).unwrap()));
            } else if kind.is_dir() {
                out.insert(relative, Entry::Directory);
                walk(root, &path, out);
            } else {
                assert!(kind.is_file(), "unexpected fixture kind: {path:?}");
                out.insert(relative, Entry::File(fs::read(path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}
fn unchanged(t: &Temp, args: &[&str]) {
    let before = snapshot(&t.base);
    let output = invoke(args);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        snapshot(&t.base),
        before,
        "rejection changed files: {args:?}"
    );
}
fn metadata_without_index(t: &Temp) -> BTreeMap<PathBuf, Entry> {
    let mut result = snapshot(&t.path(".uwgit"));
    result.remove(Path::new("index"));
    result
}
fn worktree(t: &Temp) -> BTreeMap<PathBuf, Entry> {
    snapshot(&t.repo)
        .into_iter()
        .filter(|(path, _)| !path.starts_with(".uwgit"))
        .collect()
}

#[test]
fn checkout_switches_branches_and_creates_from_explicit_or_current_revision() {
    let t = Temp::new();
    let old = module(1, 2);
    let new = module(3, 4);
    t.stage("a.wasm", &old);
    t.stage("nested/b.wasm", UNKNOWN);
    let base = t.commit("base files");
    ok(&["branch", t.root(), "before"]);
    t.stage("a.wasm", &new);
    let latest = t.commit("new first file");
    ok(&["checkout", t.root(), "before"]);
    assert_eq!(t.head(), base);
    assert_eq!(t.read("a.wasm"), old);
    assert_eq!(t.read("nested/b.wasm"), UNKNOWN);
    assert_eq!(value(&["status", t.root()])["branch"], "before");
    ok(&["checkout", t.root(), "-b", "reviewed", &latest]);
    assert_eq!(t.head(), latest);
    assert_eq!(t.read("a.wasm"), new);
    assert_eq!(value(&["status", t.root()])["branch"], "reviewed");
    ok(&["checkout", t.root(), "-b", "same-tip"]);
    assert_eq!(t.head(), latest);
    assert_eq!(value(&["status", t.root()])["branch"], "same-tip");
    unchanged(&t, &["checkout", t.root(), "-b", "same-tip"]);
    ok(&["checkout", t.root(), "main"]);
    assert_eq!(t.head(), latest);
    ok(&["fsck", t.root()]);
}

#[test]
fn checkout_index_paths_and_revision_paths_preserve_head_and_unselected_staged_bytes() {
    let t = Temp::new();
    let old = module(0, 0);
    let staged = module(1, 0);
    let dirty = module(2, 0);
    t.stage("a.wasm", &old);
    t.stage("b.wasm", HEADER);
    let base = t.commit("base");
    t.stage("a.wasm", &staged);
    t.stage("b.wasm", UNKNOWN);
    t.write("a.wasm", &dirty);
    t.write("b.wasm", b"unselected unfinished bytes");
    let index = t.read(".uwgit/index");
    let metadata = metadata_without_index(&t);
    ok(&["checkout", t.root(), "--", "a.wasm"]);
    assert_eq!(t.read("a.wasm"), staged);
    assert_eq!(t.read(".uwgit/index"), index);
    assert_eq!(t.read("b.wasm"), b"unselected unfinished bytes");
    ok(&["checkout", t.root(), &base, "--", "a.wasm"]);
    assert_eq!(t.read("a.wasm"), old);
    assert_eq!(t.staged("a.wasm"), old);
    assert_eq!(t.staged("b.wasm"), UNKNOWN);
    assert_eq!(t.read("b.wasm"), b"unselected unfinished bytes");
    assert_eq!(t.head(), base);
    assert_eq!(metadata_without_index(&t), metadata);
}

#[test]
fn checkout_overlay_keeps_source_absences_while_default_restore_records_deletions() {
    let t = Temp::new();
    ok(&["commit", t.root(), "--allow-empty", "-m", "empty source"]);
    let empty = t.head();
    let old = module(0, 0);
    let new = module(1, 0);
    t.stage("nested/a.wasm", &old);
    let base = t.commit("one file");
    t.stage("nested/a.wasm", &new);
    t.stage("nested/added.wasm", UNKNOWN);
    t.stage("outside.wasm", HEADER);
    let head = t.commit("additional files");
    let metadata = metadata_without_index(&t);
    t.write("nested/a.wasm", b"dirty first file");
    t.write("nested/added.wasm", b"dirty source-absent file");
    ok(&["checkout", t.root(), &base, "--", "nested/"]);
    assert_eq!(t.read("nested/a.wasm"), old);
    assert_eq!(t.read("nested/added.wasm"), b"dirty source-absent file");
    assert_eq!(t.staged("nested/added.wasm"), UNKNOWN);
    assert_eq!(t.read("outside.wasm"), HEADER);
    unchanged(
        &t,
        &["checkout", t.root(), &base, "--", "nested/added.wasm"],
    );
    unchanged(&t, &["checkout", t.root(), &empty, "--", "."]);
    unchanged(&t, &["checkout", t.root(), &empty, "--", "nested"]);
    ok(&["checkout", t.root(), &base, "--", "."]);
    assert_eq!(t.read("nested/added.wasm"), b"dirty source-absent file");
    assert_eq!(t.read("outside.wasm"), HEADER);
    ok(&[
        "restore",
        t.root(),
        "--source",
        &base,
        "--staged",
        "--worktree",
        "--",
        "nested/",
    ]);
    assert!(!t.path("nested/added.wasm").exists());
    assert!(!t.tracked().contains("nested/added.wasm"));
    assert_eq!(t.read("outside.wasm"), HEADER);
    assert_eq!(t.head(), head);
    assert_eq!(metadata_without_index(&t), metadata);
}

#[test]
fn delimiter_literal_option_paths_never_trigger_help_export_or_branch_creation() {
    let t = Temp::new();
    let paths = ["--file", "-h", "--help", "--", "-b"];
    for path in paths {
        t.stage(path, UNKNOWN);
    }
    let head = t.commit("literal option names");
    let metadata = metadata_without_index(&t);
    let index = t.read(".uwgit/index");
    for path in paths {
        t.write(path, b"dirty literal path");
    }
    ok(&[
        "checkout",
        t.root(),
        "--",
        "--file",
        "-h",
        "--help",
        "--",
        "-b",
    ]);
    for path in paths {
        assert_eq!(t.read(path), UNKNOWN);
        t.write(path, b"dirty revision-selected literal");
    }
    ok(&[
        "checkout",
        t.root(),
        &head,
        "--",
        "--file",
        "-h",
        "--help",
        "--",
        "-b",
    ]);
    for path in paths {
        assert_eq!(t.read(path), UNKNOWN);
        assert_eq!(t.staged(path), UNKNOWN);
    }
    assert_eq!(t.read(".uwgit/index"), index);
    assert_eq!(t.head(), head);
    assert_eq!(metadata_without_index(&t), metadata);
}

#[test]
fn true_help_has_no_io_and_empty_or_misplaced_path_delimiters_are_rejected() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    t.commit("base");
    let missing = t.base.join("must-not-exist");
    let before = snapshot(&t.base);
    for args in [
        vec!["checkout", s(&missing), "--help"],
        vec!["checkout", s(&missing), "-h"],
        vec!["checkout", s(&missing), "-b", "new", "--help"],
        vec!["checkout", s(&missing), "HEAD", "unused-output", "--help"],
    ] {
        assert!(ok(&args).contains("checkout"));
        assert!(!missing.exists());
        assert_eq!(snapshot(&t.base), before);
    }
    for args in [
        vec!["checkout", t.root(), "--"],
        vec!["checkout", t.root(), "HEAD", "--"],
        vec!["checkout", t.root(), "-b", "new", "--", "a.wasm"],
        vec!["restore", t.root(), "--"],
        vec!["restore", t.root(), "--staged", "--"],
    ] {
        unchanged(&t, &args);
    }
}

#[test]
fn old_checkout_export_remains_exclusive_and_guards_metadata_with_literal_file_operands() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    t.stage("--", UNKNOWN);
    t.commit("export tree");
    let metadata = snapshot(&t.path(".uwgit"));
    for (name, selector) in [("selected.wasm", "a.wasm"), ("literal.wasm", "--")] {
        let output = t.base.join(name);
        ok(&["checkout", t.root(), "HEAD", s(&output), "--file", selector]);
        assert_eq!(
            fs::read(&output).unwrap(),
            if selector == "--" { UNKNOWN } else { HEADER }
        );
        assert_eq!(snapshot(&t.path(".uwgit")), metadata);
        unchanged(
            &t,
            &["checkout", t.root(), "HEAD", s(&output), "--file", selector],
        );
    }
    let equals = t.base.join("equals.wasm");
    ok(&["checkout", t.root(), "HEAD", s(&equals), "--file=--"]);
    assert_eq!(fs::read(equals).unwrap(), UNKNOWN);
    let blocked = t.path(".uwgit/index.lock");
    unchanged(
        &t,
        &[
            "checkout",
            t.root(),
            "HEAD",
            s(&blocked),
            "--file",
            "a.wasm",
        ],
    );
    assert_eq!(snapshot(&t.path(".uwgit")), metadata);
    let legacy = Temp::new();
    let input = legacy.base.join("legacy-input.wasm");
    fs::write(&input, UNKNOWN).unwrap();
    ok(&["commit", legacy.root(), s(&input), "-m", "legacy bytes"]);
    let legacy_metadata = snapshot(&legacy.path(".uwgit"));
    let output = legacy.base.join("legacy-export.wasm");
    ok(&["checkout", legacy.root(), "HEAD", s(&output)]);
    assert_eq!(fs::read(&output).unwrap(), UNKNOWN);
    assert_eq!(snapshot(&legacy.path(".uwgit")), legacy_metadata);
    unchanged(&legacy, &["checkout", legacy.root(), "HEAD", s(&output)]);
}

#[test]
fn checkout_switch_preflights_dirty_files_and_late_untracked_obstructions() {
    let t = Temp::new();
    let old = module(0, 0);
    let new = module(1, 0);
    t.stage("a.wasm", &old);
    let base = t.commit("base");
    ok(&["branch", t.root(), "before"]);
    t.stage("a.wasm", &new);
    t.stage("late/added.wasm", UNKNOWN);
    let target = t.commit("target adds a later file");
    ok(&["branch", t.root(), "target"]);
    ok(&["checkout", t.root(), "before"]);
    t.write("a.wasm", b"dirty editor bytes");
    unchanged(&t, &["checkout", t.root(), "target"]);
    unchanged(&t, &["checkout", t.root(), "-b", "dirty-copy", &target]);
    ok(&["checkout", t.root(), "--", "a.wasm"]);
    t.write("late/added.wasm", b"untracked non-Wasm blocker");
    unchanged(&t, &["checkout", t.root(), "target"]);
    unchanged(&t, &["checkout", t.root(), "-b", "blocked-copy", &target]);
    assert_eq!(t.head(), base);
    fs::remove_file(t.path("late/added.wasm")).unwrap();
    fs::create_dir(t.path("late/added.wasm")).unwrap();
    unchanged(&t, &["checkout", t.root(), "target"]);
    fs::remove_dir(t.path("late/added.wasm")).unwrap();
    ok(&["checkout", t.root(), "target"]);
    assert_eq!(t.head(), target);
    assert_eq!(t.read("a.wasm"), new);
    assert_eq!(t.read("late/added.wasm"), UNKNOWN);
}

#[cfg(unix)]
#[test]
fn checkout_and_restore_refuse_metadata_and_symlink_paths_without_touching_other_selections() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    t.stage("nested/b.wasm", UNKNOWN);
    let head = t.commit("base");
    t.write("a.wasm", b"must not restore before rejecting later path");
    let outside = t.base.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("b.wasm"), b"private bytes").unwrap();
    fs::remove_file(t.path("nested/b.wasm")).unwrap();
    fs::remove_dir(t.path("nested")).unwrap();
    symlink(&outside, t.path("nested")).unwrap();
    for args in [
        vec!["checkout", t.root(), "--", "a.wasm", "nested/b.wasm"],
        vec!["checkout", t.root(), &head, "--", "a.wasm", "nested/b.wasm"],
        vec!["restore", t.root(), "--", "a.wasm", "nested/"],
        vec!["checkout", t.root(), "--", "a.wasm", ".uwgit/HEAD"],
        vec!["restore", t.root(), "--", "a.wasm", ".UWGIT/index"],
    ] {
        unchanged(&t, &args);
    }
    let metadata_alias = t.repo.join("metadata-alias");
    symlink(t.path(".uwgit"), &metadata_alias).unwrap();
    let blocked = metadata_alias.join("index.lock");
    unchanged(
        &t,
        &[
            "checkout",
            t.root(),
            "HEAD",
            s(&blocked),
            "--file",
            "a.wasm",
        ],
    );
    assert_eq!(fs::read(outside.join("b.wasm")).unwrap(), b"private bytes");
}

#[test]
fn restore_selectors_expand_directories_and_dot_and_preflight_every_argument() {
    let t = Temp::new();
    let a = module(1, 2);
    t.stage("a.wasm", &a);
    t.stage("nested/b.wasm", UNKNOWN);
    t.stage("nested/deep/c.wasm", HEADER);
    let head = t.commit("selectors");
    let index = t.read(".uwgit/index");
    t.write("a.wasm", b"dirty root");
    t.write("nested/b.wasm", b"dirty nested");
    t.write("nested/deep/c.wasm", b"dirty deep");
    ok(&["restore", t.root(), "--", "./nested/"]);
    assert_eq!(t.read("nested/b.wasm"), UNKNOWN);
    assert_eq!(t.read("nested/deep/c.wasm"), HEADER);
    assert_eq!(t.read("a.wasm"), b"dirty root");
    ok(&["restore", t.root(), "--", "./"]);
    assert_eq!(t.read("a.wasm"), a);
    assert_eq!(t.read(".uwgit/index"), index);
    t.write("a.wasm", b"dirty root again");
    t.write("nested/b.wasm", b"dirty nested again");
    for args in [
        vec!["restore", t.root(), "--", "missing.wasm"],
        vec!["restore", t.root(), "--", "a.wasm", "not-a-directory/"],
        vec!["restore", t.root(), "--", "nested", "nested//"],
        vec!["restore", t.root(), "--", "a.wasm", "nested/../"],
        vec!["restore", t.root(), "--", "a.wasm", "nested/./"],
        vec!["checkout", t.root(), "--", "a.wasm", "missing.wasm"],
        vec!["checkout", t.root(), &head, "--", "a.wasm", "missing.wasm"],
        vec![
            "restore",
            t.root(),
            "--source",
            &head,
            "--staged",
            "--worktree",
            "--",
            "a.wasm",
            "missing.wasm",
        ],
    ] {
        unchanged(&t, &args);
    }
    ok(&["restore", t.root()]);
    assert_eq!(t.read("a.wasm"), a);
    assert_eq!(t.read("nested/b.wasm"), UNKNOWN);
}

#[test]
fn selected_file_directory_transitions_preserve_overlay_absences_and_reset_only_the_index() {
    let t = Temp::new();
    t.stage("node", HEADER);
    t.stage("stable.wasm", UNKNOWN);
    let old = t.commit("node is a file");
    ok(&["mv", t.root(), "node", "node/深/child.wasm"]);
    t.stage("unrelated.wasm", UNKNOWN);
    let new = t.commit("node is a directory");
    ok(&["checkout", t.root(), &old, "--", "node"]);
    assert_eq!(t.read("node"), HEADER);
    assert_eq!(t.read("unrelated.wasm"), UNKNOWN);
    assert!(!t.tracked().contains("node/深/child.wasm"));
    unchanged(&t, &["restore", t.root(), "--", "node/"]);
    ok(&["checkout", t.root(), &new, "--", "node/深/child.wasm"]);
    assert_eq!(t.read("node/深/child.wasm"), HEADER);
    assert_eq!(t.read("unrelated.wasm"), UNKNOWN);
    t.write("node/private.txt", b"untracked sibling must not be deleted");
    unchanged(&t, &["checkout", t.root(), &old, "--", "node"]);
    fs::remove_file(t.path("node/private.txt")).unwrap();
    let dirty = worktree(&t);
    let metadata = metadata_without_index(&t);
    ok(&["reset", t.root(), &old, "--", "./node"]);
    assert_eq!(worktree(&t), dirty);
    assert_eq!(t.staged("node"), HEADER);
    assert!(!t.tracked().contains("node/深/child.wasm"));
    assert_eq!(t.staged("unrelated.wasm"), UNKNOWN);
    assert_eq!(metadata_without_index(&t), metadata);
    ok(&[
        "restore",
        t.root(),
        "--source",
        &new,
        "--staged",
        "--",
        "node",
    ]);
    ok(&[
        "restore",
        t.root(),
        "--source",
        &old,
        "--staged",
        "--worktree",
        "--",
        "node",
    ]);
    assert_eq!(t.read("node"), HEADER);
    ok(&[
        "restore",
        t.root(),
        "--source",
        &new,
        "--staged",
        "--worktree",
        "--",
        "node",
    ]);
    assert_eq!(t.read("node/深/child.wasm"), HEADER);
    assert_eq!(t.head(), new);
    assert_eq!(t.read("stable.wasm"), UNKNOWN);
    assert_eq!(t.read("unrelated.wasm"), UNKNOWN);
}

#[test]
fn selected_legacy_restore_requires_and_retains_the_recorded_explicit_anchor() {
    let t = Temp::new();
    let old = module(0, 1);
    let new = module(2, 1);
    let input = t.base.join("legacy-input.wasm");
    fs::write(&input, &old).unwrap();
    ok(&["commit", t.root(), s(&input), "-m", "unnamed legacy"]);
    let legacy = t.head();
    unchanged(
        &t,
        &[
            "restore",
            t.root(),
            "--source",
            &legacy,
            "--staged",
            "--worktree",
            "--",
            "chosen.wasm",
        ],
    );
    t.stage("chosen.wasm", &new);
    t.stage("other.wasm", UNKNOWN);
    let named = t.commit("explicit anchor and another file");
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["legacy_path"],
        "chosen.wasm"
    );
    ok(&[
        "restore",
        t.root(),
        "--source",
        &legacy,
        "--staged",
        "--worktree",
        "--",
        "./chosen.wasm",
    ]);
    assert_eq!(t.read("chosen.wasm"), old);
    assert_eq!(t.read("other.wasm"), UNKNOWN);
    assert_eq!(t.head(), named);
    unchanged(
        &t,
        &[
            "restore",
            t.root(),
            "--source",
            &legacy,
            "--staged",
            "--worktree",
            "--",
            "invented.wasm",
        ],
    );
    t.commit("restore the correctly mapped legacy bytes");
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["legacy_path"],
        "chosen.wasm"
    );
    assert_eq!(t.staged("chosen.wasm"), old);
    ok(&["fsck", t.root()]);
}

#[test]
fn path_reset_preserves_head_dirty_untracked_and_unselected_staged_content() {
    let t = Temp::new();
    let old = module(0, 0);
    let committed = module(1, 0);
    let staged = module(2, 0);
    for path in ["a.wasm", "b.wasm", "--hard", "--help"] {
        t.stage(path, &old);
    }
    let base = t.commit("old tree");
    t.stage("a.wasm", &committed);
    t.stage("b.wasm", &committed);
    t.stage("new.wasm", HEADER);
    let head = t.commit("new tree");
    for path in ["a.wasm", "b.wasm", "--hard", "--help", "new.wasm"] {
        t.stage(path, &staged);
        t.write(path, b"unstaged unfinished bytes");
    }
    t.write("private.txt", b"untracked raw bytes");
    let before_worktree = worktree(&t);
    let metadata = metadata_without_index(&t);
    ok(&["reset", t.root(), &base, "--", "./a.wasm"]);
    assert_eq!(t.staged("a.wasm"), old);
    assert_eq!(t.staged("b.wasm"), staged);
    assert_eq!(t.staged("new.wasm"), staged);
    ok(&["reset", t.root(), "--", "--hard", "--help"]);
    assert_eq!(t.staged("--hard"), old);
    assert_eq!(t.staged("--help"), old);
    ok(&["reset", t.root(), &base, "--", "new.wasm"]);
    assert!(!t.tracked().contains("new.wasm"));
    assert_eq!(t.read("new.wasm"), b"unstaged unfinished bytes");
    assert_eq!(worktree(&t), before_worktree);
    assert_eq!(t.head(), head);
    assert_eq!(metadata_without_index(&t), metadata);
    for args in [
        vec!["reset", t.root(), "--"],
        vec!["reset", t.root(), &base, "--"],
        vec!["reset", t.root(), "--hard", &base, "--", "a.wasm"],
        vec!["reset", t.root(), "--soft", "--", "a.wasm"],
        vec!["reset", t.root(), "--mixed", "--", "a.wasm"],
        vec!["reset", t.root(), &base, "--", "a.wasm", "missing.wasm"],
    ] {
        unchanged(&t, &args);
    }
    assert_eq!(t.head(), head);
}
