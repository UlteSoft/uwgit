//! Fixed fast-forward-only policy checks. No fuzzing or module execution.
//! All fixtures, repository state and exports stay under /tmp.
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
        let base = Path::new("/tmp").join(format!(
            "uwgit-ff-only-{}-{}",
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
        ok(&["add", self.root(), name]);
    }
    fn head(&self) -> String {
        ok(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn commit(&self, message: &str) -> String {
        ok(&["commit", self.root(), "-m", message]);
        self.head()
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
    let out = invoke(args);
    assert!(
        out.status.success(),
        "{args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
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
    fn walk(root: &Path, directory: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let name = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                entries.insert(name, Entry::Symlink(fs::read_link(path).unwrap()));
            } else if kind.is_dir() {
                entries.insert(name, Entry::Directory);
                walk(root, &path, entries);
            } else {
                assert!(kind.is_file(), "unexpected fixture kind: {path:?}");
                entries.insert(name, Entry::File(fs::read(path).unwrap()));
            }
        }
    }
    let mut entries = BTreeMap::new();
    walk(root, root, &mut entries);
    entries
}
fn rejected_without_changes(t: &Temp, args: &[&str]) -> String {
    let before = snapshot(&t.base);
    let out = invoke(args);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        snapshot(&t.base),
        before,
        "rejection changed state: {args:?}"
    );
    String::from_utf8(out.stderr).unwrap()
}
fn fork(t: &Temp) -> (String, String, String) {
    t.stage("a.wasm", &module(0, 0));
    t.stage("b.wasm", HEADER);
    let base = t.commit("base");
    ok(&["branch", t.root(), "incoming"]);
    t.stage("a.wasm", &module(1, 0));
    let ours = t.commit("ours changes first file");
    ok(&["checkout", t.root(), "incoming"]);
    t.stage("b.wasm", UNKNOWN);
    let theirs = t.commit("theirs changes second file");
    ok(&["checkout", t.root(), "main"]);
    (base, ours, theirs)
}

#[test]
fn ff_only_without_message_fast_forwards_the_exact_existing_tree_and_syncs_files() {
    let t = Temp::new();
    t.stage("a.wasm", &module(0, 0));
    t.stage("deleted.wasm", HEADER);
    let base = t.commit("base");
    let changed = module(1, 0);
    t.stage("a.wasm", &changed);
    t.stage("nested/future.wasm", UNKNOWN);
    ok(&["rm", t.root(), "deleted.wasm"]);
    let target = t.commit("target tree with addition and deletion");
    ok(&["branch", t.root(), "incoming"]);
    ok(&["reset", t.root(), "--hard", &base]);
    let objects = snapshot(&t.path(".uwgit/objects"));
    let outcome = value(&["merge", t.root(), "incoming", "--ff-only"]);
    assert_eq!(outcome["status"], "fast_forward");
    assert_eq!(outcome["old_head"], base);
    assert_eq!(outcome["target"], target);
    assert_eq!(outcome["commit"], target);
    assert_eq!(t.head(), target);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), changed);
    assert_eq!(fs::read(t.path("nested/future.wasm")).unwrap(), UNKNOWN);
    assert!(!t.path("deleted.wasm").exists());
    assert_eq!(snapshot(&t.path(".uwgit/objects")), objects);
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["parents"],
        serde_json::json!([base])
    );
    assert_eq!(value(&["status", t.root()])["staged"], false);
    ok(&["fsck", t.root()]);
}

#[test]
fn ancestor_and_same_tip_ff_only_are_noops_in_each_supported_flag_position() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    let base = t.commit("base");
    t.stage("a.wasm", UNKNOWN);
    let latest = t.commit("descendant");
    let before = snapshot(&t.base);
    for args in [
        vec!["merge", t.root(), "--ff-only", &base],
        vec!["merge", t.root(), &base, "--ff-only", "-m", "ignored"],
        vec![
            "merge",
            t.root(),
            "--ff-only",
            "HEAD",
            "--message",
            "--resolved",
        ],
        vec!["merge", t.root(), "HEAD", "-m", "--ff-only", "--ff-only"],
    ] {
        assert_eq!(value(&args)["status"], "already_up_to_date");
        assert_eq!(snapshot(&t.base), before);
    }
    assert_eq!(t.head(), latest);
}

#[test]
fn clean_divergence_is_rejected_before_objects_and_default_merge_still_combines_changes() {
    let t = Temp::new();
    let (_, ours, theirs) = fork(&t);
    for args in [
        vec!["merge", t.root(), "incoming", "--ff-only"],
        vec![
            "merge",
            t.root(),
            "--ff-only",
            &theirs,
            "-m",
            "must not synthesize",
        ],
    ] {
        assert!(rejected_without_changes(&t, &args).contains("fast-forward-only merge refused"));
    }
    assert_eq!(t.head(), ours);
    let outcome = value(&[
        "merge",
        t.root(),
        "incoming",
        "-m",
        "combine independent files",
    ]);
    assert_eq!(outcome["status"], "merged");
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["parents"],
        serde_json::json!([ours, theirs])
    );
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), module(1, 0));
    assert_eq!(fs::read(t.path("b.wasm")).unwrap(), UNKNOWN);
    ok(&["fsck", t.root()]);
}

#[test]
fn duplicate_flags_and_manual_modes_are_rejected_but_equal_message_operands_are_data() {
    let t = Temp::new();
    let (_, ours, theirs) = fork(&t);
    let supplied = t.path("a.wasm");
    for args in [
        vec!["merge", t.root(), "incoming", "--ff-only", "--ff-only"],
        vec![
            "merge",
            t.root(),
            "incoming",
            "-m",
            "m",
            "--ff-only",
            "--ff-only",
        ],
        vec!["merge", t.root(), "incoming", "--ff-only=true"],
        vec!["merge", t.root(), "--ff-only"],
        vec!["merge", t.root(), "incoming", "--ff-only", "-m"],
        vec![
            "merge",
            t.root(),
            &theirs,
            "-m",
            "m",
            "--resolved",
            s(&supplied),
            "--expect-head",
            &ours,
            "--ff-only",
        ],
        vec![
            "merge",
            t.root(),
            &theirs,
            "-m",
            "m",
            "--resolved-index",
            "--expect-head",
            &ours,
            "--ff-only",
        ],
        vec![
            "merge",
            t.root(),
            &theirs,
            "--ff-only",
            "--expect-head",
            &ours,
        ],
        vec![
            "merge",
            t.root(),
            &theirs,
            "--ff-only",
            "--expect-branch",
            "main",
        ],
    ] {
        rejected_without_changes(&t, &args);
    }
    let outcome = value(&["merge", t.root(), "incoming", "-m", "--ff-only"]);
    assert_eq!(outcome["status"], "merged");
    assert_eq!(value(&["show", t.root(), "HEAD"])["message"], "--ff-only");
}

#[test]
fn ff_only_help_does_not_open_a_missing_repository_or_create_any_paths() {
    let t = Temp::new();
    let absent = t.base.join("must-not-exist");
    let before = snapshot(&t.base);
    for args in [
        vec!["merge", s(&absent), "--ff-only", "--help"],
        vec!["merge", s(&absent), "HEAD", "--ff-only", "-h"],
        vec![
            "merge",
            s(&absent),
            "HEAD",
            "--ff-only",
            "-m",
            "--help",
            "--help",
        ],
    ] {
        assert!(ok(&args).contains("--ff-only"));
        assert!(!absent.exists());
        assert_eq!(snapshot(&t.base), before);
    }
}

#[test]
fn ff_only_checks_dirty_and_untracked_or_symlink_blockers_before_moving_the_branch() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    let base = t.commit("base");
    t.stage("a.wasm", &module(1, 0));
    t.stage("late/added.wasm", UNKNOWN);
    let target = t.commit("target");
    ok(&["branch", t.root(), "incoming"]);
    ok(&["reset", t.root(), "--hard", &base]);
    t.write("a.wasm", b"dirty work bytes");
    rejected_without_changes(&t, &["merge", t.root(), "incoming", "--ff-only"]);
    ok(&["restore", t.root(), "--", "a.wasm"]);
    t.write("late/added.wasm", b"untracked plain bytes");
    rejected_without_changes(&t, &["merge", t.root(), "incoming", "--ff-only"]);
    fs::remove_file(t.path("late/added.wasm")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        fs::remove_dir(t.path("late")).unwrap();
        let outside = t.base.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("private.txt"), b"private").unwrap();
        symlink(&outside, t.path("late")).unwrap();
        rejected_without_changes(&t, &["merge", t.root(), "incoming", "--ff-only"]);
        fs::remove_file(t.path("late")).unwrap();
    }
    assert_eq!(t.head(), base);
    assert_eq!(
        value(&["merge", t.root(), "--ff-only", "incoming"])["status"],
        "fast_forward"
    );
    assert_eq!(t.head(), target);
    assert_eq!(fs::read(t.path("late/added.wasm")).unwrap(), UNKNOWN);
}

#[test]
fn unborn_ff_only_advances_to_an_imported_tree_without_inventing_a_worktree() {
    let source = Temp::new();
    source.stage("nested/future.wasm", UNKNOWN);
    let target = source.commit("source");
    let bundle = source.base.join("source.bundle");
    ok(&["bundle", source.root(), s(&bundle)]);
    let dest = Temp::new();
    ok(&["unbundle", dest.root(), s(&bundle), "incoming"]);
    assert!(!dest.path(".uwgit/index").exists());
    let objects = snapshot(&dest.path(".uwgit/objects"));
    let outcome = value(&["merge", dest.root(), "--ff-only", "incoming"]);
    assert_eq!(outcome["status"], "fast_forward");
    assert!(outcome["old_head"].is_null());
    assert_eq!(dest.head(), target);
    assert!(!dest.path("nested").exists());
    assert!(!dest.path(".uwgit/index").exists());
    assert_eq!(snapshot(&dest.path(".uwgit/objects")), objects);
    ok(&["fsck", dest.root()]);
}

#[test]
fn ff_only_validates_unreachable_objects_and_rejects_unrelated_histories_without_writes() {
    let t = Temp::new();
    t.stage("a.wasm", HEADER);
    t.commit("local root");
    let unrelated = Temp::new();
    unrelated.stage("other.wasm", UNKNOWN);
    unrelated.commit("unrelated root");
    let bundle = unrelated.base.join("unrelated.bundle");
    ok(&["bundle", unrelated.root(), s(&bundle)]);
    ok(&["unbundle", t.root(), s(&bundle), "incoming"]);
    assert!(
        rejected_without_changes(&t, &["merge", t.root(), "incoming", "--ff-only"])
            .contains("fast-forward-only merge refused")
    );
    let corrupt = t.path(&format!(".uwgit/objects/{}", "f".repeat(64)));
    assert!(!corrupt.exists());
    fs::write(corrupt, b"malformed unreferenced object").unwrap();
    rejected_without_changes(&t, &["merge", t.root(), "HEAD", "--ff-only"]);
}
