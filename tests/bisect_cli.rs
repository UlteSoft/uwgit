//! Fixed no-checkout history classifications; run only in the admitted SSH cgroup.
//! Complete byte snapshots include the index, worktree, refs, objects and journals.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const WASM: &[u8] = b"\0asm\x01\0\0\0";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp {
    base: PathBuf,
    repo: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let base = PathBuf::from(format!(
            "/tmp/uwgit-bisect-{}-{}",
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
    fn path(&self, path: &str) -> PathBuf {
        self.repo.join(path)
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        let target = self.path(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    fn stage(&self, path: &str) {
        self.write(path, WASM);
        ok(&["add", self.root(), "--", path]);
    }
    fn commit(&self, message: &str) -> String {
        ok(&["commit", self.root(), "-m", message]);
        ok(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn bisect(&self, arguments: &[&str]) -> Value {
        let before = protected(&self.repo);
        let mut args = vec!["bisect", self.root()];
        args.extend_from_slice(arguments);
        let output = invoke(&args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(output.stdout.ends_with(b"\n") && !output.stdout.ends_with(b"\n\n"));
        assert_eq!(
            protected(&self.repo),
            before,
            "bisect changed more than its journal: {args:?}"
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["command"], "bisect");
        assert_eq!(result["schema_version"], 1);
        assert_eq!(result["no_checkout"], true);
        for field in [
            "head_updated",
            "index_updated",
            "worktree_updated",
            "pending_updated",
        ] {
            assert_eq!(result[field], false, "{field}");
        }
        assert_eq!(
            result["object_verification"],
            if arguments.first() == Some(&"reset") {
                "not_requested"
            } else {
                "full_snapshot"
            }
        );
        result
    }
    fn readonly(&self, action: &str) -> Value {
        let before = snapshot(&self.base);
        let result = self.bisect(&[action]);
        assert_eq!(
            snapshot(&self.base),
            before,
            "read-only bisect changed files"
        );
        assert_eq!(result["operation"], action);
        assert_eq!(result["changed"], false);
        result
    }
    fn reject(&self, arguments: &[&str]) {
        let before = snapshot(&self.base);
        let mut args = vec!["bisect", self.root()];
        args.extend_from_slice(arguments);
        let output = invoke(&args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(output.stdout.is_empty(), "error emitted a partial result");
        assert!(!output.stderr.is_empty());
        assert_eq!(
            snapshot(&self.base),
            before,
            "failed bisect changed files: {args:?}"
        );
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
        .env_remove("UWGIT_REMOTE_TOKEN")
        .env_remove("UWGIT_SSH_PROGRAM")
        .env_remove("UWGIT_REMOTE_PROGRAM")
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
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                result.insert(relative, Entry::Symlink(fs::read_link(path).unwrap()));
            } else if kind.is_dir() {
                result.insert(relative, Entry::Directory);
                visit(root, &path, result);
            } else {
                assert!(kind.is_file());
                result.insert(relative, Entry::File(fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}
fn protected(root: &Path) -> BTreeMap<PathBuf, Entry> {
    let mut result = snapshot(root);
    result.remove(Path::new(".uwgit/bisect.json"));
    result
}
fn ids(report: &Value, field: &str) -> BTreeSet<String> {
    report[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect()
}
fn set(values: &[&String]) -> BTreeSet<String> {
    values.iter().map(|id| (*id).clone()).collect()
}
fn linear(t: &Temp) -> Vec<String> {
    (0..7)
        .map(|number| {
            t.stage(&format!("steps/{number}.wasm"));
            t.commit(&format!("fixed linear C{number}"))
        })
        .collect()
}
struct Diamond {
    root: String,
    a1: String,
    a2: String,
    b1: String,
    b2: String,
    merge: String,
    tip: String,
}
fn diamond(t: &Temp) -> Diamond {
    t.stage("base.wasm");
    let root = t.commit("fixed diamond root");
    ok(&["branch", t.root(), "side"]);
    t.stage("main/a1.wasm");
    let a1 = t.commit("fixed A1");
    t.stage("main/a2.wasm");
    let a2 = t.commit("fixed A2");
    ok(&["switch", t.root(), "side"]);
    t.stage("side/b1.wasm");
    let b1 = t.commit("fixed B1");
    t.stage("side/b2.wasm");
    let b2 = t.commit("fixed B2");
    ok(&["switch", t.root(), "main"]);
    ok(&["merge", t.root(), "side", "-m", "fixed M"]);
    let merge = ok(&["rev-parse", t.root(), "HEAD"]).trim().to_owned();
    t.stage("tail.wasm");
    let tip = t.commit("fixed T");
    Diamond {
        root,
        a1,
        a2,
        b1,
        b2,
        merge,
        tip,
    }
}

#[test]
fn linear_default_candidate_classification_finds_boundary_without_checkout() {
    let t = Temp::new();
    let c = linear(&t);
    let mut report = t.bisect(&["start", "--no-checkout", &c[6], &c[0], "--json"]);
    assert_eq!(report["status"], "testing");
    assert_eq!(report["candidate"], c[3]);
    assert_eq!(ids(&report, "remaining"), c[1..].iter().cloned().collect());
    let generation = report["generation"].clone();
    let mut decisions = 0;
    while report["status"] == "testing" {
        let candidate = report["candidate"].as_str().unwrap();
        let position = c.iter().position(|id| id == candidate).unwrap();
        assert!((1..6).contains(&position));
        report = t.bisect(&[if position >= 4 { "bad" } else { "good" }]);
        decisions += 1;
        assert!(decisions <= 4);
        assert_eq!(report["generation"], generation);
    }
    assert_eq!(report["status"], "found");
    assert_eq!(report["first_bad"], c[4]);
    assert!(report["candidate"].is_null());
    assert_eq!(ids(&report, "suspects"), set(&[&c[4]]));
    assert_eq!(ok(&["rev-parse", t.root(), "HEAD"]).trim(), c[6]);
    t.reject(&["good"]);
    t.reject(&["bad"]);
    t.reject(&["skip"]);
}

#[test]
fn merge_dag_uses_balanced_tie_and_accepts_good_on_pruned_side_branch() {
    let t = Temp::new();
    let h = diamond(&t);
    let report = t.bisect(&["start", &h.tip, &h.root]);
    assert_eq!(
        ids(&report, "remaining"),
        set(&[&h.a1, &h.a2, &h.b1, &h.b2, &h.merge, &h.tip])
    );
    assert_eq!(report["candidate"], h.a2.as_str().min(h.b2.as_str()));
    let report = t.bisect(&["good", &h.a2]);
    assert_eq!(
        ids(&report, "remaining"),
        set(&[&h.b1, &h.b2, &h.merge, &h.tip])
    );
    assert_eq!(report["candidate"], h.b2);
    let report = t.bisect(&["bad", &h.b2]);
    assert_eq!(ids(&report, "remaining"), set(&[&h.b1, &h.b2]));
    assert!(ids(&report, "good").contains(&h.a2));
    let report = t.bisect(&["good", &h.b1]);
    assert_eq!(report["status"], "found");
    assert_eq!(report["first_bad"], h.b2);
}

#[test]
fn first_parent_fixes_domain_and_rejects_side_parent_as_initial_good() {
    let t = Temp::new();
    let h = diamond(&t);
    t.reject(&["start", "--first-parent", &h.tip, &h.b2]);
    let report = t.bisect(&["start", &h.tip, &h.root, "--first-parent"]);
    assert_eq!(report["first_parent"], true);
    assert_eq!(
        ids(&report, "remaining"),
        set(&[&h.a1, &h.a2, &h.merge, &h.tip])
    );
    assert_eq!(report["candidate"], h.a2);
    t.reject(&["good", &h.b2]);
    t.bisect(&["good", &h.a2]);
    let report = t.bisect(&["bad", &h.merge]);
    assert_eq!(report["first_bad"], h.merge);
    assert_eq!(report["status"], "found");
}

#[test]
fn skip_preserves_ambiguous_suspects_and_explicit_classification_unskips() {
    let t = Temp::new();
    let c = linear(&t);
    t.bisect(&["start", &c[4], &c[2]]);
    let report = t.bisect(&["skip"]);
    assert_eq!(report["status"], "ambiguous_skipped");
    assert_eq!(ids(&report, "suspects"), set(&[&c[3], &c[4]]));
    assert_eq!(ids(&report, "skip"), set(&[&c[3]]));
    assert!(report["candidate"].is_null() && report["first_bad"].is_null());
    assert!(ids(&report, "testable").is_empty());
    for action in ["good", "bad", "skip"] {
        t.reject(&[action]);
    }
    let report = t.bisect(&["good", &c[3]]);
    assert_eq!(report["first_bad"], c[4]);
    assert!(ids(&report, "skip").is_empty());
    assert_eq!(report["marks"][0]["kind"], "skip");
    t.bisect(&["reset"]);
    t.bisect(&["start", &c[4], &c[2]]);
    t.bisect(&["skip", &c[3]]);
    assert_eq!(t.bisect(&["bad", &c[3]])["first_bad"], c[3]);
}

#[test]
fn mark_batches_are_canonical_idempotent_and_atomic_on_late_invalid_member() {
    let t = Temp::new();
    let c = linear(&t);
    t.bisect(&["start", &c[6], &c[0]]);
    t.reject(&["good", &c[2], &c[6]]);
    let report = t.bisect(&["good", &c[2], &c[1], &c[2]]);
    let mut expected = vec![c[1].clone(), c[2].clone()];
    expected.sort();
    assert_eq!(report["marks"][0]["revisions"], json!(expected));
    let journal = fs::read(t.path(".uwgit/bisect.json")).unwrap();
    assert_eq!(t.bisect(&["good", &c[1], &c[2]])["changed"], false);
    assert_eq!(fs::read(t.path(".uwgit/bisect.json")).unwrap(), journal);
    t.reject(&["skip", &c[4], &c[1]]);
    let report = t.bisect(&["skip", &c[4], &c[3], &c[4]]);
    assert_eq!(ids(&report, "skip"), set(&[&c[3], &c[4]]));
    assert_eq!(report["candidate"], c[5]);
    let expected_state = (
        report["remaining"].clone(),
        report["skip"].clone(),
        report["candidate"].clone(),
    );
    t.bisect(&["reset"]);
    t.bisect(&["start", &c[6], &c[0]]);
    t.bisect(&["good", &c[1], &c[2]]);
    let report = t.bisect(&["skip", &c[3], &c[4]]);
    assert_eq!(
        (
            report["remaining"].clone(),
            report["skip"].clone(),
            report["candidate"].clone()
        ),
        expected_state
    );
}

#[test]
fn inconsistent_bounds_and_duplicate_start_never_publish_partial_state() {
    let t = Temp::new();
    let c = linear(&t);
    t.reject(&["start", &c[0], &c[0]]);
    t.reject(&["start", &c[2], &c[4]]);
    t.reject(&["start", &c[6], &c[0], "missing-good"]);
    for action in ["good", "bad", "skip"] {
        t.reject(&[action, &c[3]]);
    }
    t.bisect(&["start", &c[6], &c[0]]);
    t.reject(&["start", &c[4], &c[2]]);
    t.reject(&["good", &c[6]]);
    t.reject(&["bad", &c[0]]);
    t.reject(&["skip", &c[0]]);
    t.reject(&["skip", &c[6]]);
    t.bisect(&["bad", &c[4]]);
    t.reject(&["bad", &c[5]]);
    t.reject(&["good", &c[5]]);
}

#[test]
fn status_next_log_and_reset_preserve_repository_and_session_identity() {
    let t = Temp::new();
    let c = linear(&t);
    for action in ["status", "next", "log"] {
        let report = t.readonly(action);
        assert_eq!(report["status"], "inactive");
        assert_eq!(report["active"], false);
        assert!(report["generation"].is_null());
    }
    assert_eq!(t.bisect(&["reset"])["changed"], false);
    let start = t.bisect(&["start", &c[6], &c[0]]);
    t.bisect(&["good", &c[2]]);
    for action in ["status", "next", "log"] {
        let report = t.readonly(action);
        assert_eq!(report["generation"], start["generation"]);
        assert_eq!(report["original_bad"], c[6]);
        assert_eq!(report["initial_good"], json!([c[0]]));
        assert_eq!(report["marks"].as_array().unwrap().len(), 1);
    }
    assert_eq!(t.bisect(&["reset"])["changed"], true);
    assert!(!t.path(".uwgit/bisect.json").exists());
    assert_eq!(t.bisect(&["reset"])["changed"], false);
}

#[test]
fn dirty_missing_work_bad_index_and_unrelated_pending_are_not_dependencies() {
    let t = Temp::new();
    let c = linear(&t);
    t.write("steps/0.wasm", b"unfinished non-wasm editor bytes\0");
    fs::remove_file(t.path("steps/1.wasm")).unwrap();
    t.write("private/new.wasm", b"private untracked bytes");
    t.write(".uwgit/index", b"not a decodable index\0");
    t.write(".uwgit/pending.json", b"unrelated malformed pending\0");
    #[cfg(unix)]
    std::os::unix::fs::symlink("private/new.wasm", t.path("private-link")).unwrap();
    t.bisect(&["start", &c[6], &c[0]]);
    t.bisect(&["good", &c[2]]);
    t.readonly("status");
    t.bisect(&["reset"]);
    fs::remove_file(t.path(".uwgit/index")).unwrap();
    t.bisect(&["start", &c[4], &c[2]]);
    t.bisect(&["skip"]);
    t.bisect(&["reset"]);
    assert!(!t.path(".uwgit/index").exists());
}

#[test]
fn moving_refs_and_switching_head_do_not_retarget_frozen_candidate() {
    let t = Temp::new();
    let c = linear(&t);
    ok(&["branch", t.root(), "moving", &c[6]]);
    let start = t.bisect(&["start", "moving", &c[0]]);
    ok(&["branch", t.root(), "-D", "moving"]);
    ok(&["branch", t.root(), "moving", &c[1]]);
    t.stage("later.wasm");
    let later = t.commit("external ordinary history update during bisect");
    t.reject(&["bad", "HEAD"]);
    ok(&["switch", t.root(), "moving"]);
    let report = t.bisect(&["good"]);
    assert_eq!(report["original_bad"], c[6]);
    assert_eq!(report["generation"], start["generation"]);
    assert_eq!(report["marks"][0]["revisions"], json!([c[3]]));
    assert_eq!(ok(&["rev-parse", t.root(), "HEAD"]).trim(), c[1]);
    t.bisect(&["reset"]);
    assert_eq!(ok(&["rev-parse", t.root(), "HEAD"]).trim(), c[1]);
    assert_eq!(ok(&["rev-parse", t.root(), "main"]).trim(), later);
}

#[test]
fn exact_dotted_refs_and_describe_revisions_use_the_common_resolver() {
    let t = Temp::new();
    let c = linear(&t);
    ok(&["branch", t.root(), "a..b"]);
    ok(&["tag", t.root(), "tag..base", &c[0]]);
    let report = t.bisect(&["start", "a..b", "tag..base"]);
    assert_eq!(report["original_bad"], c[6]);
    assert_eq!(report["initial_good"], json!([c[0]]));
    t.bisect(&["reset"]);
    let description = ok(&["describe", t.root(), "HEAD", "--match=tag..base"]);
    assert!(description.starts_with("tag..base-6-g"));
    let report = t.bisect(&["start", description.trim(), "tag..base"]);
    assert_eq!(report["original_bad"], c[6]);
    t.bisect(&["reset"]);
    t.reject(&["start", "HEAD~1..HEAD", "tag..base"]);
}

#[test]
fn malformed_noncanonical_and_oversized_regular_journals_have_reset_escape() {
    let t = Temp::new();
    let c = linear(&t);
    t.bisect(&["start", &c[6], &c[0]]);
    let original = fs::read(t.path(".uwgit/bisect.json")).unwrap();
    let mut noncanonical = original.clone();
    noncanonical.push(b' ');
    let mut extra: Value = serde_json::from_slice(&original).unwrap();
    extra["unexpected"] = json!(true);
    let malformed = vec![
        b"not json\0".to_vec(),
        noncanonical,
        serde_json::to_vec(&extra).unwrap(),
        vec![b'x'; 1024 * 1024 + 1],
    ];
    for bytes in malformed {
        t.write(".uwgit/bisect.json", &bytes);
        for action in ["status", "next", "log", "good"] {
            t.reject(&[action]);
        }
        let report = t.bisect(&["reset"]);
        assert_eq!(report["changed"], true);
        assert_eq!(report["status"], "reset");
        assert!(!t.path(".uwgit/bisect.json").exists());
    }
}

#[test]
fn nonregular_journal_is_never_followed_or_removed() {
    let t = Temp::new();
    let c = linear(&t);
    fs::create_dir(t.path(".uwgit/bisect.json")).unwrap();
    for action in ["status", "reset"] {
        t.reject(&[action]);
    }
    fs::remove_dir(t.path(".uwgit/bisect.json")).unwrap();
    #[cfg(unix)]
    {
        let outside = t.base.join("outside-journal");
        fs::write(&outside, b"do not follow or remove").unwrap();
        std::os::unix::fs::symlink(&outside, t.path(".uwgit/bisect.json")).unwrap();
        t.reject(&["start", &c[6], &c[0]]);
        for action in ["status", "reset"] {
            t.reject(&[action]);
        }
    }
}

#[test]
fn verified_snapshot_and_writer_lock_are_required_but_reset_skips_object_decode() {
    let t = Temp::new();
    let c = linear(&t);
    t.bisect(&["start", &c[6], &c[0]]);
    t.write(".uwgit/write.lock", b"existing external writer\n");
    for action in ["status", "good", "reset"] {
        t.reject(&[action]);
    }
    fs::remove_file(t.path(".uwgit/write.lock")).unwrap();
    let object = t.path(&format!(".uwgit/objects/{}", c[6]));
    let original = fs::read(&object).unwrap();
    fs::write(&object, b"corrupt committed object").unwrap();
    for action in ["status", "next", "log", "good"] {
        t.reject(&[action]);
    }
    assert_eq!(t.bisect(&["reset"])["changed"], true);
    t.reject(&["start", &c[6], &c[0]]);
    t.reject(&["status"]);
    assert_eq!(t.bisect(&["reset"])["changed"], false);
    fs::write(object, original).unwrap();
    assert_eq!(t.readonly("status")["status"], "inactive");
}

#[test]
fn clone_and_bundle_transfer_history_without_local_bisect_state() {
    let t = Temp::new();
    let c = linear(&t);
    t.bisect(&["start", &c[6], &c[0]]);
    t.bisect(&["skip", &c[3]]);
    let original = snapshot(&t.repo);
    let bundle = t.base.join("history.bundle");
    ok(&["bundle", t.root(), s(&bundle)]);
    let clone = t.base.join("clone");
    ok(&["clone", t.root(), s(&clone)]);
    assert_eq!(snapshot(&t.repo), original);
    assert!(!clone.join(".uwgit/bisect.json").exists());
    let before = snapshot(&clone);
    let output = ok(&["bisect", s(&clone), "status"]);
    assert_eq!(
        serde_json::from_str::<Value>(&output).unwrap()["status"],
        "inactive"
    );
    assert_eq!(snapshot(&clone), before);
    let receiver = t.base.join("receiver");
    ok(&["init", s(&receiver)]);
    ok(&["unbundle", s(&receiver), s(&bundle), "imported"]);
    assert!(!receiver.join(".uwgit/bisect.json").exists());
    assert_eq!(
        serde_json::from_str::<Value>(&ok(&["bisect", s(&receiver), "status"])).unwrap()["status"],
        "inactive"
    );
}

#[test]
fn help_invalid_shapes_and_unborn_repository_do_not_create_session() {
    let t = Temp::new();
    let missing = t.base.join("missing");
    for args in [
        vec!["bisect", "--help"],
        vec!["bisect", "-h"],
        vec!["bisect", "help"],
        vec!["bisect", s(&missing), "help"],
    ] {
        let before = snapshot(&t.base);
        let output = invoke(&args);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("usage: wasm-git bisect"));
        assert_eq!(snapshot(&t.base), before);
    }
    for suffix in [
        vec!["run", "anything"],
        vec!["replay", "log"],
        vec!["terms"],
        vec!["start", "HEAD"],
        vec!["bad", "a", "b"],
        vec!["reset", "HEAD"],
        vec!["status", "HEAD"],
        vec!["good", "--first-parent"],
        vec!["status", "--no-checkout"],
        vec!["status", "--json", "--json"],
        vec!["status", "--unknown"],
        vec!["start", "HEAD", "HEAD~1", "--", "path"],
    ] {
        let before = snapshot(&t.base);
        let mut args = vec!["bisect", s(&missing)];
        args.extend(suffix);
        let output = invoke(&args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty() && !output.stderr.is_empty());
        assert_eq!(snapshot(&t.base), before);
    }
    t.reject(&["start", "HEAD", "HEAD"]);
    assert_eq!(t.readonly("status")["status"], "inactive");
    assert_eq!(t.bisect(&["reset"])["changed"], false);
    assert!(!t.path(".uwgit/bisect.json").exists() && !missing.exists());
}
