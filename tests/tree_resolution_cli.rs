//! Explicit fixed CLI cases for staged whole-tree merge resolution. No fuzzing.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = Path::new("/tmp").join(format!(
            "uwgit-tree-resolution-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        run(&["init", s(&p)]);
        Self(p)
    }
    fn root(&self) -> &str {
        s(&self.0)
    }
    fn path(&self, p: &str) -> PathBuf {
        self.0.join(p)
    }
    fn stage(&self, p: &str, b: &[u8]) {
        let dest = self.path(p);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(dest, b).unwrap();
        run(&["add", self.root(), p]);
    }
    fn commit(&self, m: &str) -> String {
        run(&["commit", self.root(), "-m", m]);
        run(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}
fn invoke(a: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(a)
        .output()
        .unwrap()
}
fn run(a: &[&str]) -> String {
    let o = invoke(a);
    assert!(
        o.status.success(),
        "{a:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap()
}
fn value(a: &[&str]) -> Value {
    serde_json::from_str(&run(a)).unwrap()
}
fn fail(a: &[&str]) -> String {
    let o = invoke(a);
    assert!(!o.status.success(), "{a:?}: unexpected success");
    String::from_utf8(o.stderr).unwrap()
}
fn module(a: i32, b: i32) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (func (result i32) i32.const {a}) (func (result i32) i32.const {b}))"
    ))
    .unwrap()
}
fn opaque(n: u8) -> Vec<u8> {
    let mut b = HEADER.to_vec();
    b.extend_from_slice(&[14, 1, n]);
    b
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(base: &Path, p: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for e in fs::read_dir(p).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                out.insert(p.strip_prefix(base).unwrap().into(), None);
                visit(base, &p, out);
            } else {
                out.insert(
                    p.strip_prefix(base).unwrap().into(),
                    Some(fs::read(&p).unwrap()),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
fn fork(t: &Temp) -> (String, String, String) {
    t.stage("a.wasm", &module(0, 0));
    t.stage("kept.wasm", HEADER);
    let base = t.commit("base");
    run(&["branch", t.root(), "right"]);
    t.stage("a.wasm", &module(1, 0));
    let ours = t.commit("ours");
    run(&["switch", t.root(), "right"]);
    t.stage("a.wasm", &module(2, 0));
    let theirs = t.commit("theirs");
    run(&["switch", t.root(), "main"]);
    (base, ours, theirs)
}
fn assert_witness(w: &Value, b: &[u8]) {
    assert_eq!(w["byte_len"], b.len());
    assert_eq!(w["sha256"], format!("{:x}", Sha256::digest(b)));
    assert_eq!(
        w["hex"],
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    );
    assert_eq!(
        w["audit"],
        serde_json::to_value(wasm_git::audit::inspect(b).unwrap()).unwrap()
    );
}
fn replay(old: &[u8], new: &[u8], report: &Value) {
    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    let mut actual = Vec::new();
    let mut cursor = 0;
    for e in report["edits"].as_array().unwrap() {
        let a = e["old_span"]["start"].as_u64().unwrap() as usize;
        let b = e["old_span"]["end"].as_u64().unwrap() as usize;
        let new_start = e["new_span"]["start"].as_u64().unwrap() as usize;
        let new_end = e["new_span"]["end"].as_u64().unwrap() as usize;
        assert_eq!(&old[a..b], unhex(e["old_hex"].as_str().unwrap()));
        actual.extend_from_slice(&old[cursor..a]);
        assert_eq!(actual.len(), new_start);
        let inserted = unhex(e["new_hex"].as_str().unwrap());
        assert_eq!(inserted, new[new_start..new_end]);
        actual.extend_from_slice(&inserted);
        cursor = b;
    }
    actual.extend_from_slice(&old[cursor..]);
    assert_eq!(actual, new);
}

#[test]
fn staged_resolution_preserves_dirty_and_deleted_worktree_and_audits_both_parents() {
    let t = Temp::new();
    let (base, ours, theirs) = fork(&t);
    let before = snapshot(&t.0);
    let automatic = invoke(&["merge", t.root(), &theirs, "-m", "review"]);
    assert_eq!(automatic.status.code(), Some(2));
    assert_eq!(snapshot(&t.0), before);
    let chosen = opaque(0xff);
    t.stage("a.wasm", &chosen);
    t.stage("新規.wasm", HEADER);
    run(&["rm", t.root(), "--cached", "kept.wasm"]);
    fs::write(t.path("a.wasm"), b"unstaged invalid header").unwrap();
    fs::remove_file(t.path("新規.wasm")).unwrap();
    fs::write(t.path("untracked.txt"), b"preserve").unwrap();
    let index = fs::read(t.path(".uwgit/index")).unwrap();
    let work = snapshot(&t.0)
        .into_iter()
        .filter(|(p, _)| !p.starts_with(".uwgit"))
        .collect::<BTreeMap<_, _>>();
    // A ref whose name looks like the target ID cannot redirect an immutable lease.
    let before_reserved = snapshot(&t.0);
    fail(&["branch", t.root(), &theirs, &ours]);
    assert_eq!(snapshot(&t.0), before_reserved);
    let report = value(&[
        "merge",
        t.root(),
        &theirs,
        "--resolved-index",
        "--expect-head",
        &ours,
        "--expect-branch",
        "main",
        "-m",
        "explicit tree",
    ]);
    assert_eq!(report["status"], "merged_resolved");
    assert_eq!(report["resolution_source"], "index");
    assert_eq!(report["index_updated"], false);
    assert_eq!(report["worktree_updated"], false);
    assert_eq!(report["base"], base);
    assert_eq!(report["target"], theirs);
    assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
    assert_eq!(
        snapshot(&t.0)
            .into_iter()
            .filter(|(p, _)| !p.starts_with(".uwgit"))
            .collect::<BTreeMap<_, _>>(),
        work
    );
    let commit = value(&["show", t.root(), "HEAD"]);
    assert_eq!(commit["format"], 2);
    assert_eq!(commit["parents"], json!([ours, theirs]));
    let manual = &report["tree_manual_resolution"];
    assert_eq!(manual["supplied_complete_tree"], true);
    let rows = manual["files"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let a = rows.iter().find(|r| r["path"] == "a.wasm").unwrap();
    assert_witness(&a["resolved"], &chosen);
    assert_witness(&a["ours"], &module(1, 0));
    assert_witness(&a["theirs"], &module(2, 0));
    replay(&module(1, 0), &chosen, &a["from_ours"]["audit"]);
    replay(&module(2, 0), &chosen, &a["from_theirs"]["audit"]);
    let deleted = rows.iter().find(|r| r["path"] == "kept.wasm").unwrap();
    assert!(deleted["resolved"].is_null());
    assert_eq!(deleted["from_ours"]["status"], "deleted");
    assert_witness(&deleted["ours"], HEADER);
    let added = rows.iter().find(|r| r["path"] == "新規.wasm").unwrap();
    assert!(added["base"].is_null());
    assert!(added["ours"].is_null());
    assert_witness(&added["resolved"], HEADER);
    run(&["fsck", t.root()]);
}

#[test]
fn invalid_leases_branch_and_locks_never_publish_staged_bytes() {
    let t = Temp::new();
    let (base, ours, theirs) = fork(&t);
    t.stage("a.wasm", &opaque(99));
    run(&["branch", t.root(), "same-tip", &ours]);
    let before = snapshot(&t.0);
    for (head, target, branch) in [
        (base.as_str(), theirs.as_str(), "main"),
        (ours.as_str(), "right", "main"),
        (ours.as_str(), theirs.as_str(), "same-tip"),
        (ours.as_str(), ours.as_str(), "main"),
    ] {
        fail(&[
            "merge",
            t.root(),
            target,
            "-m",
            "reject",
            "--resolved-index",
            "--expect-head",
            head,
            "--expect-branch",
            branch,
        ]);
        assert_eq!(snapshot(&t.0), before);
    }
    for name in ["index.lock", "write.lock"] {
        let lock = t.path(&format!(".uwgit/{name}"));
        fs::write(&lock, b"held by test").unwrap();
        let locked = snapshot(&t.0);
        fail(&[
            "merge",
            t.root(),
            &theirs,
            "-m",
            "locked",
            "--resolved-index",
            "--expect-head",
            &ours,
        ]);
        assert_eq!(snapshot(&t.0), locked);
        fs::remove_file(lock).unwrap();
    }
    assert_eq!(snapshot(&t.0), before);
    fail(&[
        "merge",
        t.root(),
        &theirs,
        "-m",
        "reject",
        "--resolved-index",
        "--resolved",
        "unused.wasm",
        "--expect-head",
        &ours,
    ]);
    assert_eq!(snapshot(&t.0), before);
    let index = t.path(".uwgit/index");
    let original = fs::read(&index).unwrap();
    fs::write(&index, b"corrupt index").unwrap();
    let corrupt = snapshot(&t.0);
    fail(&[
        "merge",
        t.root(),
        &theirs,
        "-m",
        "reject",
        "--resolved-index",
        "--expect-head",
        &ours,
    ]);
    assert_eq!(snapshot(&t.0), corrupt);
    fs::write(index, original).unwrap();
}

#[test]
fn empty_index_is_a_real_resolution_but_a_missing_index_is_not() {
    let t = Temp::new();
    let (_, ours, theirs) = fork(&t);
    let clone = t.path("bare-clone");
    run(&["clone", t.root(), s(&clone)]);
    let before = snapshot(&clone);
    let error = fail(&[
        "merge",
        s(&clone),
        &theirs,
        "-m",
        "no staged choice",
        "--resolved-index",
        "--expect-head",
        &ours,
    ]);
    assert!(error.contains("index"));
    assert_eq!(snapshot(&clone), before);
    run(&["rm", t.root(), "--cached", "a.wasm", "kept.wasm"]);
    let index = fs::read(t.path(".uwgit/index")).unwrap();
    let work = fs::read(t.path("a.wasm")).unwrap();
    let report = value(&[
        "merge",
        t.root(),
        &theirs,
        "-m",
        "resolve to no files",
        "--resolved-index",
        "--expect-head",
        &ours,
    ]);
    assert_eq!(report["status"], "merged_resolved");
    let inspection = value(&["inspect", "HEAD", "--repo", t.root(), "--json"]);
    assert_eq!(inspection["file_count"], 0);
    assert_eq!(inspection["files"], json!([]));
    assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), work);
    let commit = value(&["show", t.root(), "HEAD"]);
    assert_eq!(commit["parents"], json!([ours, theirs]));
    run(&["fsck", t.root()]);
}

#[test]
fn v1_history_requires_an_explicit_path_and_keeps_original_commit_bytes() {
    let t = Temp::new();
    let input = t.path("legacy-input.wasm");
    fs::write(&input, module(0, 0)).unwrap();
    run(&["commit", t.root(), s(&input), "-m", "legacy base"]);
    let base = run(&["rev-parse", t.root(), "HEAD"]).trim().to_owned();
    run(&["branch", t.root(), "right"]);
    fs::write(&input, module(1, 0)).unwrap();
    run(&["commit", t.root(), s(&input), "-m", "legacy ours"]);
    let ours = run(&["rev-parse", t.root(), "HEAD"]).trim().to_owned();
    run(&["switch", t.root(), "right"]);
    fs::write(&input, module(2, 0)).unwrap();
    run(&["commit", t.root(), s(&input), "-m", "legacy theirs"]);
    let theirs = run(&["rev-parse", t.root(), "HEAD"]).trim().to_owned();
    run(&["switch", t.root(), "main"]);
    t.stage("named/original.wasm", &opaque(7));
    t.stage("new.wasm", HEADER);
    let index = fs::read(t.path(".uwgit/index")).unwrap();
    let report = value(&[
        "merge",
        t.root(),
        &theirs,
        "-m",
        "explicit legacy promotion",
        "--resolved-index",
        "--expect-head",
        &ours,
    ]);
    assert_eq!(report["base"], base);
    assert_eq!(
        report["tree_manual_resolution"]["legacy_path"],
        "named/original.wasm"
    );
    assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["parents"],
        json!([ours, theirs])
    );
    let export = t.path("old-export.wasm");
    run(&["show", t.root(), &base, "--output", s(&export)]);
    assert_eq!(fs::read(export).unwrap(), module(0, 0));
    run(&["fsck", t.root()]);
}

#[test]
fn resolution_help_and_bad_arguments_are_readonly_and_option_text_is_a_message() {
    let t = Temp::new();
    let absent = t.path("absent");
    assert!(invoke(&["merge", s(&absent), "--resolved-index", "--help"])
        .status
        .success());
    assert!(!absent.exists());
    let (_, ours, theirs) = fork(&t);
    let before = snapshot(&t.0);
    fail(&[
        "merge",
        t.root(),
        &theirs,
        "--resolved-index",
        "-m",
        "missing lease",
    ]);
    assert_eq!(snapshot(&t.0), before);
    // Create clean non-overlapping edits for the ordinary automatic route.
    run(&["reset", t.root(), "--hard", "HEAD~1"]);
    t.stage("a.wasm", &module(0, 2));
    t.commit("independent current edit");
    let result = value(&["merge", t.root(), &ours, "-m", "--resolved-index"]);
    assert_eq!(result["status"], "merged");
    assert!(result.get("resolution_source").is_none());
    assert_eq!(
        value(&["show", t.root(), "HEAD"])["message"],
        "--resolved-index"
    );
}
