//! Fixed committed-object queries with complete byte-for-byte read-only checks.
//! Executed by the parent only in the admitted SSH Linux cgroup; no fuzz/guests.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const A: &[u8] = b"\0asm\x01\0\0\0";
const B: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
const C: &[u8] = b"\0asm\x01\0\0\0\0\x02\x01x";
const D: &[u8] = b"\0asm\x01\0\0\0\0\x03\x01q\x7f";
const QUOTED: &str = "one space \"中文\".wasm";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp {
    base: PathBuf,
    repo: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let base = PathBuf::from(format!(
            "/tmp/uwgit-query-{}-{}",
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
    fn stage(&self, path: &str, bytes: &[u8]) {
        self.write(path, bytes);
        ok(&["add", self.root(), "--", path]);
    }
    fn commit(&self, message: &str) -> String {
        ok(&["commit", self.root(), "-m", message]);
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
    tip: String,
    tree: String,
    entries: BTreeMap<String, String>,
}
impl History {
    fn new() -> Self {
        let t = Temp::new();
        t.stage("a.wasm", A);
        t.stage("duplicate.wasm", A);
        t.stage("nested/b.wasm", B);
        t.stage(QUOTED, C);
        let first = t.commit("first exact modules");
        ok(&["branch", t.root(), "feature"]);
        ok(&["branch", t.root(), "mainline"]);
        ok(&["tag", t.root(), "base", &first]);
        t.stage("orphan.wasm", D);
        ok(&["reset", t.root(), "--mixed", "HEAD"]);
        // Staging retains bytes in the index rather than installing an object.
        // Copy one real encoded blob from an independent legacy repository;
        // preserve its actual ID and bytes instead of inventing an envelope.
        let donor = Temp::new();
        let input = donor.base.join("input.wasm");
        fs::write(&input, D).unwrap();
        ok(&[
            "commit",
            donor.root(),
            s(&input),
            "-m",
            "independent orphan donor",
        ]);
        let donor_commit = value(&["show", donor.root(), "HEAD"]);
        let orphan = donor_commit["wasm"].as_str().unwrap();
        fs::copy(
            donor.path(&format!(".uwgit/objects/{orphan}")),
            t.path(&format!(".uwgit/objects/{orphan}")),
        )
        .unwrap();
        t.stage("a.wasm", C);
        let tip = t.commit("reuse an existing blob");
        ok(&["tag", t.root(), "release", &tip]);
        let commit = value(&["show", t.root(), "HEAD"]);
        let tree = commit["tree"].as_str().unwrap().to_owned();
        let object = value(&["cat-file", t.root(), "-p", &tree]);
        let entries = object["entries"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(path, id)| (path.clone(), id.as_str().unwrap().into()))
            .collect();
        Self {
            t,
            first,
            tip,
            tree,
            entries,
        }
    }
    fn refs(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("refs/heads/feature".into(), self.first.clone()),
            ("refs/heads/main".into(), self.tip.clone()),
            ("refs/heads/mainline".into(), self.first.clone()),
            ("refs/tags/base".into(), self.first.clone()),
            ("refs/tags/release".into(), self.tip.clone()),
        ])
    }
    fn tracking(&self) {
        // A fixed, already-fetched tracking record, using the published transport
        // schema. No remote process is needed for local provenance queries.
        self.t.write(".uwgit/remotes/origin.tracking.json", serde_json::to_string(&json!({
            "version":1,"remote":"origin","url":"ssh://test@localhost/tmp/query.git",
            "state":{"format":1,"head":"main","branches":{"main":self.first},"tags":{"remote-only":self.tip}}
        })).unwrap().as_bytes());
        ok(&[
            "remote",
            self.t.root(),
            "add",
            "origin",
            "ssh://test@localhost/tmp/query.git",
        ]);
        ok(&["branch", self.t.root(), "-u", "origin/main"]);
    }
}
fn text_refs(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(|line| {
            let (id, name) = line.split_once(' ').unwrap();
            (name.into(), id.into())
        })
        .collect()
}
fn entry_map(report: &Value) -> BTreeMap<String, String> {
    report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().unwrap().into(),
                entry["object_id"].as_str().unwrap().into(),
            )
        })
        .collect()
}

#[test]
fn empty_queries_and_help_do_not_create_repository_or_metadata() {
    let t = Temp::new();
    for command in [
        "ls-tree",
        "show-ref",
        "for-each-ref",
        "count-objects",
        "ls-remote",
    ] {
        assert!(t.text(&[command, "--help"]).contains(command));
    }
    let missing = t.base.join("not-created");
    for command in [
        "ls-tree",
        "show-ref",
        "for-each-ref",
        "count-objects",
        "ls-remote",
    ] {
        assert!(t.text(&[command, s(&missing), "--help"]).contains(command));
    }
    let missing = t.query(&["show-ref", t.root()], 1);
    assert!(missing.stdout.is_empty() && missing.stderr.is_empty());
    assert_eq!(t.text(&["for-each-ref", t.root()]), "");
    let refs: Value =
        serde_json::from_slice(&t.query(&["show-ref", t.root(), "--json"], 1).stdout).unwrap();
    assert_eq!(refs["refs"], json!([]));
    assert_eq!(refs["head"], "main");
    assert!(refs["head_tip"].is_null());
    let counts = t.json(&["count-objects", t.root(), "-v"]);
    for field in [
        "objects",
        "payload_bytes",
        "stored_bytes",
        "reachable_objects",
        "unreachable_objects",
        "root_commits",
    ] {
        assert_eq!(counts[field], 0, "{field}");
    }
    for kind in ["commit", "tree", "wasm"] {
        assert_eq!(counts["by_kind"][kind]["objects"], 0);
    }
    t.reject(&["ls-tree", t.root(), "HEAD"]);
}

#[test]
fn tree_queries_report_real_flat_ids_exact_stored_lengths_and_no_invented_modes() {
    let h = History::new();
    let t = &h.t;
    let report = t.json(&["ls-tree", t.root(), "HEAD"]);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["kind"], "commit");
    assert_eq!(report["object_id"], h.tip);
    assert_eq!(report["commit"], h.tip);
    assert_eq!(report["tree"], h.tree);
    assert_eq!(report["named"], true);
    assert!(report["legacy"].is_null());
    assert_eq!(entry_map(&report), h.entries);
    assert!(!h.entries.contains_key("nested"));
    for row in report["entries"].as_array().unwrap() {
        let path = row["path"].as_str().unwrap();
        let id = row["object_id"].as_str().unwrap();
        let stored = fs::read(t.path(&format!(".uwgit/objects/{id}"))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&stored)), id);
        assert_eq!(row["stored_byte_len"], stored.len() as u64);
        let expected: &[u8] = match path {
            "a.wasm" | QUOTED => C,
            "duplicate.wasm" => A,
            "nested/b.wasm" => B,
            _ => panic!("unexpected path"),
        };
        assert_eq!(row["byte_len"], expected.len() as u64);
        assert_eq!(row["kind"], "wasm");
        assert!(row.get("mode").is_none() && row.get("directory").is_none());
        assert!(stored.ends_with(expected));
    }
    assert_eq!(t.json(&["ls-tree", t.root(), "HEAD", "-r"]), report);
    assert_eq!(h.entries["a.wasm"], h.entries[QUOTED]);
}

#[test]
fn tree_revision_selector_and_direct_tree_views_preserve_true_provenance() {
    let h = History::new();
    let t = &h.t;
    let direct = t.json(&["ls-tree", t.root(), &h.tree]);
    assert_eq!(direct["kind"], "tree");
    assert_eq!(direct["object_id"], h.tree);
    assert_eq!(direct["tree"], h.tree);
    assert!(direct["commit"].is_null() && direct["legacy_path"].is_null());
    assert_eq!(entry_map(&direct), h.entries);
    assert_eq!(t.json(&["ls-tree", t.root(), "HEAD~1"])["commit"], h.first);
    assert_eq!(
        t.json(&["ls-tree", t.root(), &h.tip[..16]])["commit"],
        h.tip
    );
    let selected = t.json(&["ls-tree", t.root(), "HEAD", "--", "nested", QUOTED]);
    assert_eq!(
        entry_map(&selected),
        BTreeMap::from([
            ("nested/b.wasm".into(), h.entries["nested/b.wasm"].clone()),
            (QUOTED.into(), h.entries[QUOTED].clone())
        ])
    );
    assert_eq!(
        entry_map(&t.json(&["ls-tree", t.root(), "HEAD", "--", "."])),
        h.entries
    );
    assert_eq!(
        entry_map(&t.json(&["ls-tree", t.root(), "HEAD", "--", "nested/"])),
        entry_map(&t.json(&["ls-tree", t.root(), "HEAD", "--", "nested"]))
    );
    t.reject(&["ls-tree", t.root(), "HEAD", "--", "a.wasm/"]);
    t.reject(&["ls-tree", t.root(), "HEAD", "--", "nested/b"]);
    t.reject(&["ls-tree", t.root(), "HEAD", "--", "a.wasm", "missing"]);
    t.reject(&["ls-tree", t.root(), &h.tree[..16]]);
    t.reject(&["ls-tree", t.root(), &h.entries["a.wasm"]]);
}

#[test]
fn raw_tree_name_and_object_outputs_are_exact_utf8_nul_records() {
    let h = History::new();
    let t = &h.t;
    let mut names = Vec::new();
    let mut objects = Vec::new();
    for (name, id) in &h.entries {
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        objects.extend_from_slice(id.as_bytes());
        objects.push(0);
    }
    assert_eq!(
        t.query(&["ls-tree", t.root(), "HEAD", "--name-only", "-z"], 0)
            .stdout,
        names
    );
    assert_eq!(
        t.query(&["ls-tree", t.root(), "HEAD", "--object-only", "-z"], 0)
            .stdout,
        objects
    );
    assert_eq!(
        t.text(&["ls-tree", t.root(), "HEAD", "--name-only"]),
        h.entries
            .keys()
            .map(|path| format!("{path}\n"))
            .collect::<String>()
    );
    t.reject(&["ls-tree", t.root(), "HEAD", "-z"]);
    t.reject(&["ls-tree", t.root(), "HEAD", "--name-only", "--object-only"]);
}

#[test]
fn refs_text_json_filters_head_and_suffix_boundary_are_explicit() {
    let h = History::new();
    h.tracking();
    let t = &h.t;
    let mut expected = h.refs();
    expected.insert("refs/remotes/origin/main".into(), h.first.clone());
    assert_eq!(text_refs(&t.text(&["show-ref", t.root()])), expected);
    let report = t.json(&["show-ref", t.root(), "--json"]);
    assert_eq!(report["head"], "main");
    assert_eq!(report["head_tip"], h.tip);
    let rows = report["refs"].as_array().unwrap();
    assert_eq!(rows.len(), expected.len());
    for row in rows {
        let name = row["name"].as_str().unwrap();
        assert_eq!(row["id"], expected[name]);
        assert_eq!(row["kind"], "commit");
        let file = fs::read(t.path(&format!(".uwgit/objects/{}", expected[name]))).unwrap();
        assert_eq!(row["stored_byte_len"], file.len() as u64);
        assert_eq!(
            row["byte_len"].as_u64().unwrap(),
            ok(&["cat-file", t.root(), "-s", &expected[name]])
                .trim()
                .parse::<u64>()
                .unwrap()
        );
        assert_eq!(row["current"], name == "refs/heads/main");
        if name == "refs/heads/main" {
            assert_eq!(row["upstream"], json!({"remote":"origin","branch":"main"}));
        } else {
            assert!(row["upstream"].is_null());
        }
    }
    let heads = text_refs(&t.text(&["show-ref", t.root(), "--branches"]));
    assert_eq!(
        heads,
        expected
            .iter()
            .filter(|(name, _)| name.starts_with("refs/heads/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    );
    let tags = text_refs(&t.text(&["show-ref", t.root(), "--tags"]));
    assert_eq!(tags.len(), 2);
    let union = text_refs(&t.text(&["show-ref", t.root(), "--heads", "--tags"]));
    assert_eq!(union.len(), 5);
    assert_eq!(
        text_refs(&t.text(&["show-ref", t.root(), "main"])),
        BTreeMap::from([
            ("refs/heads/main".into(), h.tip.clone()),
            ("refs/remotes/origin/main".into(), h.first.clone())
        ])
    );
    assert_eq!(
        text_refs(&t.text(&["show-ref", t.root(), "feature", "release"])),
        BTreeMap::from([
            ("refs/heads/feature".into(), h.first.clone()),
            ("refs/tags/release".into(), h.tip.clone())
        ])
    );
    for filter in ["--heads", "--tags"] {
        assert_eq!(
            t.text(&["show-ref", t.root(), "--head", filter, "missing"]),
            format!("{} HEAD\n", h.tip)
        );
    }
    assert_eq!(
        t.text(&["show-ref", t.root(), "--hash", "--tags", "release"]),
        format!("{}\n", h.tip)
    );
}

#[test]
fn exact_ref_verification_is_all_or_nothing_and_quiet_absence_is_silent() {
    let h = History::new();
    let t = &h.t;
    assert_eq!(
        t.text(&["show-ref", t.root(), "--verify", "HEAD"]),
        format!("{} HEAD\n", h.tip)
    );
    assert_eq!(
        t.text(&[
            "show-ref",
            t.root(),
            "--verify",
            "--heads",
            "refs/tags/base"
        ]),
        format!("{} refs/tags/base\n", h.first)
    );
    assert_eq!(
        t.text(&[
            "show-ref",
            t.root(),
            "--verify",
            "--tags",
            "refs/heads/main"
        ]),
        format!("{} refs/heads/main\n", h.tip)
    );
    for args in [
        vec!["show-ref", t.root(), "--verify"],
        vec!["show-ref", t.root(), "--verify", "main"],
        vec![
            "show-ref",
            t.root(),
            "--verify",
            "refs/heads/main",
            "refs/tags/missing",
        ],
        vec![
            "show-ref",
            t.root(),
            "--head",
            "--verify",
            "refs/heads/missing",
        ],
    ] {
        t.reject(&args);
    }
    let quiet = t.query(
        &[
            "show-ref",
            t.root(),
            "--verify",
            "--quiet",
            "refs/heads/missing",
        ],
        1,
    );
    assert!(quiet.stdout.is_empty() && quiet.stderr.is_empty());
    let quiet = t.query(
        &["show-ref", t.root(), "--verify", "-q", "refs/heads/main"],
        0,
    );
    assert!(quiet.stdout.is_empty() && quiet.stderr.is_empty());
    let absent = t.query(&["show-ref", t.root(), "absent"], 1);
    assert!(absent.stdout.is_empty() && absent.stderr.is_empty());
    t.reject(&["show-ref", t.root(), "--quiet", "--json"]);
    t.reject(&["show-ref", t.root(), "--quiet", "--hash"]);
}

#[test]
fn ref_prefix_glob_patterns_and_absence_have_fixed_unambiguous_semantics() {
    let h = History::new();
    let t = &h.t;
    let expected = h.refs();
    let default = expected
        .iter()
        .map(|(name, id)| format!("{id} commit\t{name}\n"))
        .collect::<String>();
    assert_eq!(t.text(&["for-each-ref", t.root()]), default);
    assert_eq!(
        t.text(&[
            "for-each-ref",
            t.root(),
            "--format=%(refname)",
            "refs/heads/main"
        ]),
        "refs/heads/main\n"
    );
    assert_eq!(
        t.text(&["for-each-ref", t.root(), "--format=%(refname)", "refs/tags"]),
        "refs/tags/base\nrefs/tags/release\n"
    );
    assert_eq!(
        t.text(&[
            "for-each-ref",
            t.root(),
            "--format=%(refname)",
            "refs/heads/*",
            "refs/tags/ba?e"
        ]),
        "refs/heads/feature\nrefs/heads/main\nrefs/heads/mainline\nrefs/tags/base\n"
    );
    assert_eq!(t.text(&["for-each-ref", t.root(), "refs/heads/mai"]), "");
    assert_eq!(t.text(&["for-each-ref", t.root(), "refs/absent"]), "");
    t.reject(&["for-each-ref", t.root(), "refs/heads/[mf]*"]);
    t.reject(&["for-each-ref", t.root(), "refs/heads/ma\\in"]);
}

#[test]
fn ref_formats_sort_order_counts_and_ascii_escapes_match_declared_subset() {
    let h = History::new();
    h.tracking();
    let t = &h.t;
    let bytes = t.query(&["for-each-ref",t.root(),"--format=%(HEAD)|%(refname)|%(objectname)|%(objecttype)|%(objectsize)|%(upstream)|%%|%00|%0a","refs/heads/main"],0).stdout;
    let size = ok(&["cat-file", t.root(), "-s", &h.tip]);
    assert_eq!(
        bytes,
        format!(
            "*|refs/heads/main|{}|commit|{}|refs/remotes/origin/main|%|\0|\n\n",
            h.tip,
            size.trim()
        )
        .into_bytes()
    );
    assert_eq!(
        t.text(&[
            "for-each-ref",
            t.root(),
            "--format",
            "%(refname)",
            "--sort=-refname",
            "--count=2"
        ]),
        "refs/tags/release\nrefs/tags/base\n"
    );
    let all = t.text(&["for-each-ref", t.root(), "--format=%(refname)"]);
    assert_eq!(
        t.text(&[
            "for-each-ref",
            t.root(),
            "--format=%(refname)",
            "--count",
            "0"
        ]),
        all
    );
    // Last sort is primary. Equal object IDs retain ascending refname ties.
    let mut rows: Vec<_> = h.refs().into_iter().collect();
    rows.push(("refs/remotes/origin/main".into(), h.first.clone()));
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    assert_eq!(
        t.text(&[
            "for-each-ref",
            t.root(),
            "--format=%(refname)",
            "--sort=refname",
            "--sort=-objectname"
        ]),
        rows.iter()
            .map(|(name, _)| format!("{name}\n"))
            .collect::<String>()
    );
    let mut by_size: Vec<_> = rows
        .iter()
        .map(|(name, id)| {
            (
                name.clone(),
                ok(&["cat-file", t.root(), "-s", id])
                    .trim()
                    .parse::<u64>()
                    .unwrap(),
            )
        })
        .collect();
    by_size.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    assert_eq!(
        t.text(&[
            "for-each-ref",
            t.root(),
            "--format=%(refname)",
            "--sort=objectsize"
        ]),
        by_size
            .iter()
            .map(|(name, _)| format!("{name}\n"))
            .collect::<String>()
    );
    for option in [
        "--format=%(unknown)",
        "--format=%ff",
        "--format=%(refname:short)",
        "--sort=authordate",
        "--count=-1",
    ] {
        t.reject(&["for-each-ref", t.root(), option]);
    }
}

#[test]
fn object_counts_use_unique_physical_objects_payload_bytes_and_explicit_roots() {
    let h = History::new();
    h.tracking();
    let t = &h.t;
    let report = t.json(&["count-objects", t.root(), "-v", "-H"]);
    let mut counts: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for entry in fs::read_dir(t.path(".uwgit/objects")).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        let id = entry.file_name().into_string().unwrap();
        assert!(ids.insert(id.clone()));
        let bytes = fs::read(entry.path()).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), id);
        let kind = ok(&["cat-file", t.root(), "-t", &id]).trim().to_owned();
        let payload: u64 = ok(&["cat-file", t.root(), "-s", &id])
            .trim()
            .parse()
            .unwrap();
        let row = counts.entry(kind).or_default();
        row.0 += 1;
        row.1 += payload;
        row.2 += bytes.len() as u64;
    }
    assert_eq!(report["objects"], 8);
    assert_eq!(report["reachable_objects"], 7);
    assert_eq!(report["unreachable_objects"], 1);
    assert_eq!(report["root_commits"], 2);
    assert_eq!(
        report["payload_bytes"],
        counts.values().map(|v| v.1).sum::<u64>()
    );
    assert_eq!(
        report["stored_bytes"],
        counts.values().map(|v| v.2).sum::<u64>()
    );
    for (kind, (objects, payload, stored)) in counts {
        let row = &report["by_kind"][&kind];
        assert_eq!(row["objects"], objects);
        assert_eq!(row["payload_bytes"], payload);
        assert_eq!(row["stored_bytes"], stored);
        assert_eq!(
            row["unreachable_objects"],
            if kind == "wasm" { 1 } else { 0 }
        );
        assert_eq!(
            row["reachable_objects"].as_u64().unwrap()
                + row["unreachable_objects"].as_u64().unwrap(),
            objects
        );
    }
    assert_eq!(report["storage"], "loose_uncompressed_sha256");
    assert_eq!(report["disk_allocation_reported"], false);
    assert_eq!(report["packs_supported"], false);
    assert!(
        report["payload_human"].as_str().is_some() && report["stored_human"].as_str().is_some()
    );
    let policy = report["root_policy"].as_str().unwrap();
    assert!(
        policy.contains("reflog")
            && policy.contains("index_excluded")
            && policy.contains("not_a_deletion")
    );
    let concise = t.json(&["count-objects", t.root()]);
    assert!(
        concise.get("by_kind").is_none()
            && concise.get("packs_supported").is_none()
            && concise.get("payload_human").is_none()
    );
}

#[test]
fn corrupt_index_pending_and_dirty_missing_work_do_not_obstruct_committed_queries() {
    let h = History::new();
    h.tracking();
    let t = &h.t;
    let tree = t.json(&["ls-tree", t.root(), "HEAD"]);
    let refs = t.json(&["show-ref", t.root(), "--json"]);
    let formatted = t.text(&[
        "for-each-ref",
        t.root(),
        "--format=%(refname)|%(HEAD)|%(upstream)",
    ]);
    let counts = t.json(&["count-objects", t.root(), "-v"]);
    t.write(".uwgit/index", b"invalid fixed index\0");
    t.write(".uwgit/pending.json", b"invalid fixed pending\xff\0");
    t.write("a.wasm", b"unfinished non-Wasm editor bytes\0");
    fs::remove_file(t.path("nested/b.wasm")).unwrap();
    t.write("private.txt", b"untracked private bytes");
    #[cfg(unix)]
    std::os::unix::fs::symlink("private.txt", t.path("private-link")).unwrap();
    assert_eq!(t.json(&["ls-tree", t.root(), "HEAD"]), tree);
    assert_eq!(t.json(&["show-ref", t.root(), "--json"]), refs);
    assert_eq!(
        t.text(&[
            "for-each-ref",
            t.root(),
            "--format=%(refname)|%(HEAD)|%(upstream)"
        ]),
        formatted
    );
    assert_eq!(t.json(&["count-objects", t.root(), "-v"]), counts);
    t.reject(&["ls-tree", t.root(), "HEAD", "--", "absent"]);
}

#[test]
fn valid_local_conflict_journal_and_staged_resolution_remain_entirely_unchanged() {
    let t = Temp::new();
    let base = wat::parse_str("(module (func (result i32) i32.const 0))").unwrap();
    let ours = wat::parse_str("(module (func (result i32) i32.const 1))").unwrap();
    let theirs = wat::parse_str("(module (func (result i32) i32.const 2))").unwrap();
    t.stage("a.wasm", &base);
    t.commit("base");
    ok(&["branch", t.root(), "topic"]);
    t.stage("a.wasm", &ours);
    t.commit("ours");
    ok(&["switch", t.root(), "topic"]);
    t.stage("a.wasm", &theirs);
    t.commit("theirs");
    ok(&["switch", t.root(), "main"]);
    let record = invoke(&[
        "merge",
        t.root(),
        "topic",
        "--record-conflict",
        "-m",
        "pending query fixture",
    ]);
    assert_eq!(record.status.code(), Some(2));
    assert!(t.path(".uwgit/pending.json").is_file());
    let original_index = fs::read(t.path(".uwgit/index")).unwrap();
    let original_counts = t.json(&["count-objects", t.root(), "-v"]);
    t.stage("a.wasm", D);
    t.write("a.wasm", b"more unfinished editor bytes");
    assert_ne!(fs::read(t.path(".uwgit/index")).unwrap(), original_index);
    let head = ok(&["rev-parse", t.root(), "HEAD"]).trim().to_owned();
    assert_eq!(t.json(&["ls-tree", t.root(), "HEAD"])["commit"], head);
    assert_eq!(t.json(&["show-ref", t.root(), "--json"])["head_tip"], head);
    assert!(t
        .text(&["for-each-ref", t.root()])
        .contains("refs/heads/topic"));
    let counts = t.json(&["count-objects", t.root(), "-v"]);
    assert_eq!(
        counts, original_counts,
        "unpublished staged bytes are not installed objects or query roots"
    );
}

#[test]
fn legacy_blob_witness_and_empty_named_tree_are_distinct_without_guessed_paths() {
    let legacy = Temp::new();
    let input = legacy.base.join("input.wasm");
    fs::write(&input, B).unwrap();
    ok(&["commit", legacy.root(), s(&input), "-m", "legacy bytes"]);
    let show = value(&["show", legacy.root(), "HEAD"]);
    let report = legacy.json(&["ls-tree", legacy.root(), "HEAD"]);
    assert_eq!(report["named"], false);
    assert_eq!(report["entries"], json!([]));
    assert!(report["tree"].is_null());
    assert_eq!(report["legacy"]["object_id"], show["wasm"]);
    assert_eq!(report["legacy"]["kind"], "wasm");
    assert_eq!(report["legacy"]["byte_len"], B.len() as u64);
    assert_eq!(
        report["legacy"]["stored_byte_len"],
        fs::metadata(legacy.path(&format!(
            ".uwgit/objects/{}",
            show["wasm"].as_str().unwrap()
        )))
        .unwrap()
        .len()
    );
    legacy.reject(&["ls-tree", legacy.root(), "HEAD", "--name-only"]);
    legacy.reject(&["ls-tree", legacy.root(), "HEAD", "--object-only"]);
    legacy.reject(&["ls-tree", legacy.root(), "HEAD", "--", "input.wasm"]);
    let empty = Temp::new();
    ok(&[
        "commit",
        empty.root(),
        "--allow-empty",
        "-m",
        "empty named tree",
    ]);
    let report = empty.json(&["ls-tree", empty.root(), "HEAD"]);
    assert_eq!(report["named"], true);
    assert_eq!(report["entries"], json!([]));
    assert!(report["tree"].as_str().is_some());
    assert!(report["legacy"].is_null());
    assert_eq!(
        empty.text(&["ls-tree", empty.root(), "HEAD", "--name-only"]),
        ""
    );
}

#[test]
fn corrupt_authoritative_metadata_objects_and_writer_locks_fail_without_repairs() {
    let h = History::new();
    let t = &h.t;
    let queries = [
        vec!["ls-tree", t.root(), "HEAD"],
        vec!["show-ref", t.root(), "--json"],
        vec!["for-each-ref", t.root()],
        vec!["count-objects", t.root()],
    ];
    for (path, bytes) in [
        (".uwgit/reflog", b"broken fixed reflog\0".as_slice()),
        (".uwgit/refs/main", b"not-an-object-id\n".as_slice()),
        (
            ".uwgit/remotes/origin.tracking.json",
            b"{broken fixed tracking".as_slice(),
        ),
        (
            ".uwgit/upstreams.json",
            b"{broken fixed upstream".as_slice(),
        ),
        (".uwgit/write.lock", b"fixed crashed writer\n".as_slice()),
    ] {
        let original = fs::read(t.path(path)).ok();
        t.write(path, bytes);
        for args in &queries {
            t.reject(args);
        }
        if let Some(bytes) = original {
            t.write(path, &bytes);
        } else {
            fs::remove_file(t.path(path)).unwrap();
        }
    }
    let path = t.path(&format!(".uwgit/objects/{}", h.entries["a.wasm"]));
    let original = fs::read(&path).unwrap();
    fs::write(&path, b"corrupt fixed object bytes").unwrap();
    for args in &queries {
        t.reject(args);
    }
    fs::write(path, original).unwrap();
    for args in [
        vec!["ls-tree", t.root(), "HEAD", "--unknown"],
        vec!["show-ref", t.root(), "--unknown"],
        vec!["for-each-ref", t.root(), "--format"],
        vec!["for-each-ref", t.root(), "--sort"],
        vec!["count-objects", t.root(), "--unknown"],
        vec!["count-objects", t.root(), "extra"],
    ] {
        t.reject(&args);
    }
}
