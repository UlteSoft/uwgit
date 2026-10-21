//! Fixed describe selection and formatting with complete repository byte snapshots.
//! Executed by the parent only in the admitted SSH Linux cgroup; no fuzz/guests.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const A: &[u8] = b"\0asm\x01\0\0\0";
const B: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
const C: &[u8] = b"\0asm\x01\0\0\0\0\x02\x01x";
const D: &[u8] = b"\0asm\x01\0\0\0\0\x03\x01q\x7f";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp {
    base: PathBuf,
    repo: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let base = PathBuf::from(format!(
            "/tmp/uwgit-describe-{}-{}",
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
    fn commit(&self, bytes: &[u8], message: &str) -> String {
        self.write("module.wasm", bytes);
        ok(&[
            "commit",
            self.root(),
            s(&self.path("module.wasm")),
            "-m",
            message,
        ]);
        ok(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn query(&self, args: &[&str], expected: i32) -> Output {
        let before = snapshot(&self.base);
        let output = invoke(args);
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{args:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            snapshot(&self.base),
            before,
            "query changed files: {args:?}"
        );
        output
    }
    fn text(&self, args: &[&str]) -> String {
        let output = self.query(args, 0);
        assert!(output.stderr.is_empty(), "{args:?}: {:?}", output.stderr);
        String::from_utf8(output.stdout).unwrap()
    }
    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.text(args)).unwrap()
    }
    fn reject(&self, args: &[&str]) {
        let output = self.query(args, 1);
        assert!(
            output.stdout.is_empty(),
            "failed query emitted partial result: {args:?}"
        );
        assert!(!output.stderr.is_empty(), "missing diagnostic: {args:?}");
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
fn value(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
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
struct History {
    t: Temp,
    first: String,
    second: String,
    tip: String,
}
impl History {
    fn new() -> Self {
        let t = Temp::new();
        let first = t.commit(A, "fixed first");
        ok(&["tag", t.root(), "v-base", &first]);
        let second = t.commit(B, "fixed second");
        let tip = t.commit(C, "fixed third");
        Self {
            t,
            first,
            second,
            tip,
        }
    }
}
fn object_ids(t: &Temp) -> Vec<String> {
    fs::read_dir(t.path(".uwgit/objects"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}
fn unique_prefix(t: &Temp, id: &str, minimum: usize) -> String {
    let ids = object_ids(t);
    for size in minimum.max(4)..=64 {
        let candidate = &id[..size];
        if ids
            .iter()
            .all(|other| other == id || !other.starts_with(candidate))
        {
            return candidate.into();
        }
    }
    panic!("full object ID must be unique")
}

#[test]
fn help_and_invalid_options_are_read_only_even_without_a_repository() {
    let t = Temp::new();
    let absent = t.base.join("absent");
    assert!(t.text(&["describe", "--help"]).contains("describe"));
    assert!(t
        .text(&["describe", s(&absent), "--help"])
        .contains("describe"));
    for args in [
        vec!["describe", t.root()],
        vec!["describe", t.root(), "--long", "--abbrev=0"],
        vec!["describe", s(&absent), "--abbrev=-1"],
        vec!["describe", s(&absent), "--abbrev=65"],
        vec!["describe", s(&absent), "--abbrev=+1"],
        vec!["describe", s(&absent), "--abbrev"],
        vec!["describe", s(&absent), "--abbrev", "--help"],
        vec!["describe", s(&absent), "--match"],
        vec!["describe", s(&absent), "--dirty"],
        vec!["describe", s(&absent), "--tags", "--tags"],
        vec!["describe", s(&absent), "--json", "--json"],
        vec!["describe", s(&absent), "HEAD", "extra"],
    ] {
        t.reject(&args);
    }
    assert!(!absent.exists());
}

#[test]
fn lightweight_exact_tag_default_tags_long_and_json_share_the_same_identity() {
    let t = Temp::new();
    let head = t.commit(A, "fixed exact tag");
    ok(&["tag", t.root(), "v1", &head]);
    assert_eq!(t.text(&["describe", t.root()]), "v1\n");
    assert_eq!(t.text(&["describe", t.root(), "--tags"]), "v1\n");
    assert_eq!(t.text(&["describe", t.root(), "--exact-match"]), "v1\n");
    assert_eq!(
        t.text(&["describe", t.root(), "--exact-match", "--always"]),
        "v1\n"
    );
    assert_eq!(t.text(&["describe", t.root(), "--abbrev=0"]), "v1\n");
    assert_eq!(
        t.text(&["describe", t.root(), "--long"]),
        format!("v1-0-g{}\n", &head[..12])
    );
    let report = t.json(&["describe", t.root(), "--json"]);
    assert_eq!(report["description"], "v1");
    assert_eq!(report["long"], false);
    assert_eq!(report["fallback"], false);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["commit"], head);
    assert_eq!(report["abbreviation"], &head[..12]);
    assert_eq!(report["tag"], "v1");
    assert_eq!(report["tag_commit"], head);
    assert_eq!(report["distance"], 0);
    assert_eq!(report["exact"], true);
    assert_eq!(report["first_parent"], false);
    assert_eq!(report["evaluated_tags"], 1);
    assert_eq!(report["requested_abbrev"], 12);
    assert!(report["selection_policy"].as_str().is_some());
}

#[test]
fn linear_distance_and_revision_forms_report_the_actual_target_prefix() {
    let h = History::new();
    let t = &h.t;
    assert_eq!(
        t.text(&["describe", t.root()]),
        format!("v-base-2-g{}\n", &h.tip[..12])
    );
    assert_eq!(
        t.text(&["describe", t.root(), "HEAD~1"]),
        format!("v-base-1-g{}\n", &h.second[..12])
    );
    assert_eq!(t.text(&["describe", t.root(), &h.first]), "v-base\n");
    assert_eq!(
        t.text(&["describe", t.root(), &h.tip[..16]]),
        format!("v-base-2-g{}\n", &h.tip[..12])
    );
    let described = t.text(&["describe", t.root()]).trim().to_owned();
    assert_eq!(
        t.text(&["rev-parse", t.root(), &described]),
        format!("{}\n", h.tip)
    );
    assert_eq!(
        t.text(&["rev-parse", t.root(), &format!("{described}~1")]),
        format!("{}\n", h.second)
    );
    assert_eq!(t.json(&["show", t.root(), &described])["id"], h.tip);
    for suffix in [
        h.tip[..12].to_owned(),
        h.tip[..12].to_ascii_uppercase(),
        h.tip.clone(),
    ] {
        let hint = format!("bogus-999-g{suffix}");
        assert_eq!(
            t.text(&["rev-parse", t.root(), &hint]),
            format!("{}\n", h.tip)
        );
    }
    // A real ref takes precedence over a descriptor-looking suffix hint.
    ok(&["branch", t.root(), &described, &h.first]);
    assert_eq!(
        t.text(&["rev-parse", t.root(), &described]),
        format!("{}\n", h.first)
    );
    assert_eq!(t.json(&["show", t.root(), &described])["id"], h.first);
    assert_eq!(
        t.text(&["rev-parse", t.root(), "HEAD"]),
        format!("{}\n", h.tip)
    );
    t.reject(&["describe", t.root(), "missing"]);
    t.reject(&["describe", t.root(), "--exact-match"]);
    t.reject(&["describe", t.root(), "--exact-match", "--always"]);
    // A future tag is not a candidate when describing one of its ancestors.
    ok(&["tag", t.root(), "a-future", &h.tip]);
    assert_eq!(t.text(&["describe", t.root(), &h.first]), "v-base\n");
    assert_eq!(
        t.text(&["describe", t.root(), &h.second]),
        format!("v-base-1-g{}\n", &h.second[..12])
    );
}

#[test]
fn equal_candidate_tags_use_ascii_names_and_exact_tags_precede_ancestors() {
    let h = History::new();
    let t = &h.t;
    ok(&["tag", t.root(), "z-alias", &h.first]);
    ok(&["tag", t.root(), "a-alias", &h.first]);
    assert_eq!(
        t.text(&["describe", t.root()]),
        format!("a-alias-2-g{}\n", &h.tip[..12])
    );
    ok(&["tag", t.root(), "z-exact", &h.tip]);
    assert_eq!(t.text(&["describe", t.root()]), "z-exact\n");
    ok(&["tag", t.root(), "a-exact", &h.tip]);
    assert_eq!(
        t.text(&["describe", t.root(), "--exact-match"]),
        "a-exact\n"
    );
}

#[test]
fn merge_distance_counts_dag_set_difference_and_first_parent_changes_both_closures() {
    let t = Temp::new();
    let base = t.commit(A, "fork");
    ok(&["tag", t.root(), "base", &base]);
    ok(&["branch", t.root(), "topic"]);
    t.commit(B, "main one");
    t.commit(C, "main two");
    let main = t.commit(A, "main three");
    ok(&["tag", t.root(), "main-point", &main]);
    ok(&["switch", t.root(), "topic"]);
    let side = t.commit(B, "side one");
    ok(&["tag", t.root(), "side-point", &side]);
    let topic = t.commit(C, "side two");
    ok(&["switch", t.root(), "main"]);
    t.write("resolved.wasm", D);
    ok(&[
        "merge",
        t.root(),
        &topic,
        "-m",
        "fixed two-parent merge",
        "--resolved",
        s(&t.path("resolved.wasm")),
        "--expect-head",
        &main,
    ]);
    let head = ok(&["rev-parse", t.root(), "HEAD"]).trim().to_owned();
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["parents"],
        json!([main, topic])
    );
    assert_eq!(
        t.text(&["describe", t.root()]),
        format!("main-point-3-g{}\n", &head[..12])
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--first-parent"]),
        format!("main-point-1-g{}\n", &head[..12])
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--match=base"]),
        format!("base-6-g{}\n", &head[..12])
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--first-parent", "--match=base"]),
        format!("base-4-g{}\n", &head[..12])
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--match=side-point"]),
        format!("side-point-5-g{}\n", &head[..12])
    );
    t.reject(&["describe", t.root(), "--first-parent", "--match=side-point"]);
    for (flag, distance, first_parent) in [(None, 3, false), (Some("--first-parent"), 1, true)] {
        let mut args = vec!["describe", t.root(), "--json"];
        if let Some(flag) = flag {
            args.push(flag);
        }
        let report = t.json(&args);
        assert_eq!(report["commit"], head);
        assert_eq!(report["tag"], "main-point");
        assert_eq!(report["tag_commit"], main);
        assert_eq!(report["distance"], distance);
        assert_eq!(report["first_parent"], first_parent);
        assert_eq!(report["exact"], false);
        assert_eq!(report["evaluated_tags"], 3);
    }
}

#[test]
fn match_exclude_or_lists_and_ordered_resets_select_only_allowed_local_tags() {
    let h = History::new();
    let t = &h.t;
    for name in ["release-2", "release-1", "scratch"] {
        ok(&["tag", t.root(), name, &h.tip]);
    }
    assert_eq!(
        t.text(&["describe", t.root(), "--match=release-?"]),
        "release-1\n"
    );
    assert_eq!(
        t.text(&[
            "describe",
            t.root(),
            "--match",
            "scratch",
            "--match",
            "release-*"
        ]),
        "release-1\n"
    );
    assert_eq!(
        t.text(&[
            "describe",
            t.root(),
            "--match=release-*",
            "--exclude=release-1"
        ]),
        "release-2\n"
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--match=missing", "--no-match"]),
        "release-1\n"
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--exclude=*", "--no-exclude"]),
        "release-1\n"
    );
    assert_eq!(
        t.text(&[
            "describe",
            t.root(),
            "--match=release-*",
            "--no-match",
            "--match=scratch"
        ]),
        "scratch\n"
    );
    t.reject(&[
        "describe",
        t.root(),
        "--match=release-*",
        "--exclude=release-*",
    ]);
    t.reject(&["describe", t.root(), "--match", "--help"]);
    assert_eq!(
        t.text(&["describe", t.root(), "--exclude", "--help"]),
        "release-1\n"
    );
    for pattern in ["[rs]*", "release\\-1", ""] {
        t.reject(&["describe", t.root(), "--match", pattern]);
    }
    let report = t.json(&[
        "describe",
        t.root(),
        "--json",
        "--match=release-*",
        "--exclude=release-1",
    ]);
    assert_eq!(report["tag"], "release-2");
    assert_eq!(report["tag_commit"], h.tip);
    assert_eq!(report["evaluated_tags"], 1);
    assert_eq!(report["match"], json!(["release-*"]));
    assert_eq!(report["exclude"], json!(["release-1"]));
}

#[test]
fn abbreviation_bounds_use_unique_prefixes_of_the_complete_physical_store() {
    let h = History::new();
    let t = &h.t;
    assert_eq!(
        t.text(&["describe", t.root(), "--abbrev=1"]),
        format!("v-base-2-g{}\n", unique_prefix(t, &h.tip, 1))
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--abbrev=2"]),
        format!("v-base-2-g{}\n", unique_prefix(t, &h.tip, 2))
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--abbrev=3"]),
        format!("v-base-2-g{}\n", unique_prefix(t, &h.tip, 3))
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--abbrev", "64"]),
        format!("v-base-2-g{}\n", h.tip)
    );
    assert_eq!(t.text(&["describe", t.root(), "--abbrev=0"]), "v-base\n");
    assert_eq!(
        t.text(&[
            "describe",
            t.root(),
            "--match=absent",
            "--always",
            "--abbrev=0"
        ]),
        format!("{}\n", h.tip)
    );
    assert_eq!(
        t.text(&[
            "describe",
            t.root(),
            "--match=absent",
            "--always",
            "--abbrev=1"
        ]),
        format!("{}\n", unique_prefix(t, &h.tip, 1))
    );
    t.reject(&["describe", t.root(), "--long", "--abbrev=0"]);
    for (flag, requested) in [("--abbrev=1", 1), ("--abbrev=2", 2), ("--abbrev=3", 3)] {
        let report = t.json(&["describe", t.root(), "--json", flag]);
        assert_eq!(report["requested_abbrev"], requested);
        assert_eq!(report["abbreviation"], unique_prefix(t, &h.tip, requested));
        assert_eq!(report["distance"], 2);
        assert_eq!(report["tag_commit"], h.first);
        assert_eq!(report["commit"], h.tip);
    }
}

#[test]
fn untagged_always_fallback_is_explicit_and_never_invents_a_tag() {
    let t = Temp::new();
    let head = t.commit(B, "no tags");
    t.reject(&["describe", t.root()]);
    t.reject(&["describe", t.root(), "--exact-match", "--always"]);
    assert_eq!(
        t.text(&["describe", t.root(), "--always"]),
        format!("{}\n", &head[..12])
    );
    assert_eq!(
        t.text(&["describe", t.root(), "--always", "--abbrev=0"]),
        format!("{head}\n")
    );
    let report = t.json(&["describe", t.root(), "--always", "--json"]);
    assert_eq!(report["description"], &head[..12]);
    assert_eq!(report["fallback"], true);
    assert_eq!(report["long"], false);
    assert_eq!(report["commit"], head);
    assert_eq!(report["abbreviation"], &head[..12]);
    assert!(
        report["tag"].is_null() && report["tag_commit"].is_null() && report["distance"].is_null()
    );
    assert_eq!(report["exact"], false);
    assert_eq!(report["first_parent"], false);
    assert_eq!(report["evaluated_tags"], 0);
    assert_eq!(report["requested_abbrev"], 12);
}

#[test]
fn unrelated_malformed_index_pending_dirty_missing_work_and_symlinks_are_ignored() {
    let h = History::new();
    let t = &h.t;
    let plain = t.text(&["describe", t.root()]);
    let report = t.json(&["describe", t.root(), "--json"]);
    t.write(".uwgit/index", b"fixed malformed index\0\xff");
    t.write(".uwgit/pending.json", b"fixed malformed pending\0\xff");
    t.write("module.wasm", b"unfinished non-Wasm editor data\0");
    t.write("private.txt", b"untracked private bytes");
    #[cfg(unix)]
    std::os::unix::fs::symlink("private.txt", t.path("private-link")).unwrap();
    assert_eq!(t.text(&["describe", t.root()]), plain);
    assert_eq!(t.json(&["describe", t.root(), "--json"]), report);
    fs::remove_file(t.path("module.wasm")).unwrap();
    assert_eq!(t.text(&["describe", t.root()]), plain);
    t.reject(&["describe", t.root(), "--match=absent"]);
}

#[test]
fn authoritative_corruption_and_writer_locks_are_reported_without_repairs() {
    let h = History::new();
    let t = &h.t;
    for (path, bytes) in [
        (".uwgit/refs/main", b"not-an-object-id\n".as_slice()),
        (".uwgit/reflog", b"fixed truncated reflog\0".as_slice()),
        (
            ".uwgit/remotes/origin.tracking.json",
            b"{bad fixed tracking".as_slice(),
        ),
        (
            ".uwgit/write.lock",
            b"fixed existing writer lock\n".as_slice(),
        ),
    ] {
        let before = fs::read(t.path(path)).ok();
        t.write(path, bytes);
        t.reject(&["describe", t.root(), "--always"]);
        if let Some(bytes) = before {
            t.write(path, &bytes);
        } else {
            fs::remove_file(t.path(path)).unwrap();
        }
    }
    let object = t.path(&format!(".uwgit/objects/{}", h.first));
    let before = fs::read(&object).unwrap();
    fs::write(&object, b"fixed corrupted commit object").unwrap();
    t.reject(&["describe", t.root()]);
    fs::write(&object, before).unwrap();
    assert_eq!(
        t.text(&["describe", t.root()]),
        format!("v-base-2-g{}\n", &h.tip[..12])
    );
}
