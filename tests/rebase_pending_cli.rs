//! Fixed linear rebase journals, complete-index resolution, and exact recovery.
//! No fuzz, generated corpus, or guest execution.
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
            "/tmp/uwgit-rebase-pending-{}-{}",
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
    fn commit(&self, message: &str) -> String {
        ok(&["commit", self.root(), "-m", message]);
        self.head()
    }
    fn head(&self) -> String {
        ok(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn journal(&self) -> Value {
        serde_json::from_slice(&fs::read(self.path(".uwgit/pending.json")).unwrap()).unwrap()
    }
    fn index(&self) -> Option<Vec<u8>> {
        match fs::read(self.path(".uwgit/index")) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("{error}"),
        }
    }
    fn record(&self) -> Value {
        report(&["rebase", self.root(), "main", "--record-conflict"], 2)
    }
    fn restore_progress(&self) {
        let journal = self.journal();
        let progress = journal["rebase"]["progress_tip"].as_str().unwrap();
        ok(&[
            "restore",
            self.root(),
            "--source",
            progress,
            "--staged",
            "--worktree",
        ]);
    }
    fn stored(&self, revision: &str) -> BTreeMap<String, Vec<u8>> {
        let commit = value(&["show", self.root(), revision]);
        let tree = value(&[
            "cat-file",
            self.root(),
            "-p",
            commit["tree"].as_str().unwrap(),
        ]);
        tree["entries"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, id)| {
                let output = self.base.join(format!(
                    "export-{}",
                    SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ));
                ok(&[
                    "cat-file",
                    self.root(),
                    id.as_str().unwrap(),
                    "--output",
                    s(&output),
                ]);
                (name.clone(), fs::read(output).unwrap())
            })
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
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn value(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn report(args: &[&str], code: i32) -> Value {
    let output = invoke(args);
    assert_eq!(
        output.status.code(),
        Some(code),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn module(number: i32) -> Vec<u8> {
    wat::parse_str(format!("(module (func (result i32) i32.const {number}))")).unwrap()
}
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, dir: &Path, rows: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(dir).unwrap() {
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
        .filter(|(name, _)| !name.starts_with(".uwgit"))
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
        "rejection changed repository: {args:?}"
    );
    String::from_utf8(output.stderr).unwrap()
}
struct History {
    head: String,
    upstream: String,
    fork: String,
    queue: Vec<String>,
}
fn history(t: &Temp) -> History {
    t.stage("a.wasm", &module(0));
    t.stage("b.wasm", &module(0));
    t.stage("kept.wasm", HEADER);
    let fork = t.commit("base");
    ok(&["branch", t.root(), "feature"]);
    t.stage("a.wasm", &module(1));
    t.stage("b.wasm", &module(1));
    let upstream = t.commit("upstream");
    ok(&["switch", t.root(), "feature"]);
    t.stage("automatic.wasm", UNKNOWN);
    let automatic = t.commit("automatic");
    t.stage("a.wasm", &module(2));
    let first = t.commit("first conflict");
    t.stage("b.wasm", &module(2));
    let second = t.commit("second conflict");
    t.stage("tail.wasm", HEADER);
    let tail = t.commit("tail");
    History {
        head: tail.clone(),
        upstream,
        fork,
        queue: vec![automatic, first, second, tail],
    }
}
fn continue_first(t: &Temp) -> Value {
    t.restore_progress();
    t.stage("a.wasm", &module(9));
    report(&["rebase", t.root(), "--continue", "--resolved-index"], 2)
}
fn reflog_len(t: &Temp) -> usize {
    value(&["reflog", t.root()]).as_array().unwrap().len()
}

#[test]
fn recording_is_explicit_and_freezes_the_queue_without_publishing_automatic_steps() {
    let t = Temp::new();
    let h = history(&t);
    let before = snapshot(&t.repo);
    let stateless = report(&["rebase", t.root(), "main"], 2);
    assert_eq!(stateless["stopped_at"], h.queue[1]);
    assert_eq!(snapshot(&t.repo), before);
    let index = t.index();
    let work = worktree(&t);
    let logs = reflog_len(&t);
    let recorded = t.record();
    assert_eq!(recorded["status"], "conflict");
    assert_eq!(recorded["index_updated"], false);
    assert_eq!(recorded["worktree_updated"], false);
    assert_eq!(t.head(), h.head);
    assert_eq!(reflog_len(&t), logs);
    assert_eq!(t.index(), index);
    assert_eq!(worktree(&t), work);
    let saved = t.journal();
    assert_eq!(saved["head"], h.head);
    assert_eq!(saved["target"], h.queue[1]);
    assert_eq!(saved["rebase"]["upstream"], h.upstream);
    assert_eq!(saved["rebase"]["onto"], h.upstream);
    assert_eq!(saved["rebase"]["fork_base"], h.fork);
    assert_eq!(saved["rebase"]["queue"], json!(h.queue));
    assert_eq!(saved["rebase"]["cursor"], 1);
    assert_eq!(saved["rebase"]["steps"][0]["action"], "automatic");
    let progress = saved["rebase"]["progress_tip"].as_str().unwrap();
    let stored = t.stored(progress);
    assert_eq!(stored["automatic.wasm"], UNKNOWN);
    assert_eq!(stored["a.wasm"], module(1));
    assert!(!stored.contains_key("tail.wasm"));
    let status = value(&["status", t.root()]);
    assert_eq!(status["pending"]["operation"], "rebase");
    assert_eq!(status["pending"]["stale"], false);
    assert_eq!(status["pending"]["rebase"]["queue_length"], 4);
    assert_eq!(status["pending"]["rebase"]["cursor"], 1);
    assert!(status["pending"].get("baseline_index").is_none());
    value(&["rebase", t.root(), "--quit"]);
}

#[test]
fn two_resolutions_preserve_dirty_index_and_work_and_publish_only_the_final_tip() {
    let t = Temp::new();
    let h = history(&t);
    t.record();
    let logs = reflog_len(&t);
    t.restore_progress();
    t.stage("a.wasm", &module(9));
    t.write("a.wasm", &module(10));
    let index = t.index();
    let work = worktree(&t);
    let next = report(&["rebase", t.root(), "--continue", "--resolved-index"], 2);
    assert_eq!(next["stopped_at"], h.queue[2]);
    assert_eq!(next["manual_resolutions"].as_array().unwrap().len(), 1);
    assert_eq!(t.head(), h.head);
    assert_eq!(reflog_len(&t), logs);
    assert_eq!(t.index(), index);
    assert_eq!(worktree(&t), work);
    assert_eq!(t.journal()["rebase"]["cursor"], 2);
    t.restore_progress();
    t.stage("b.wasm", &module(9));
    t.write("b.wasm", &module(10));
    t.write("untracked.wasm", UNKNOWN);
    let index = t.index();
    let work = worktree(&t);
    let done = value(&["rebase", t.root(), "--continue", "--resolved-index"]);
    assert_eq!(done["status"], "rebased");
    assert_eq!(done["pending_cleared"], true);
    assert_eq!(done["index_updated"], false);
    assert_eq!(done["worktree_updated"], false);
    assert_eq!(done["manual_resolutions"].as_array().unwrap().len(), 2);
    assert_eq!(done["commits"].as_array().unwrap().len(), 4);
    assert_eq!(t.index(), index);
    assert_eq!(worktree(&t), work);
    assert_eq!(reflog_len(&t), logs + 1);
    assert!(!t.path(".uwgit/pending.json").exists());
    let stored = t.stored("HEAD");
    assert_eq!(stored["a.wasm"], module(9));
    assert_eq!(stored["b.wasm"], module(9));
    assert_eq!(stored["automatic.wasm"], UNKNOWN);
    assert_eq!(stored["tail.wasm"], HEADER);
    assert!(!stored.contains_key("untracked.wasm"));
    let mut cursor = t.head();
    for message in ["tail", "second conflict", "first conflict", "automatic"] {
        let commit = value(&["show", t.root(), &cursor]);
        assert_eq!(commit["message"], message);
        let parents = commit["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 1);
        cursor = parents[0].as_str().unwrap().into();
    }
    assert_eq!(cursor, h.upstream);
    ok(&["fsck", t.root()]);
}

#[test]
fn a_complete_manual_index_can_delete_nonconflicting_paths_without_automatic_completion() {
    let t = Temp::new();
    history(&t);
    t.record();
    t.restore_progress();
    t.stage("a.wasm", UNKNOWN);
    ok(&[
        "rm",
        t.root(),
        "--cached",
        "--force",
        "--",
        "b.wasm",
        "kept.wasm",
        "automatic.wasm",
    ]);
    let index = t.index();
    let work = worktree(&t);
    let next = report(&["rebase", t.root(), "--continue", "--resolved-index"], 2);
    assert_eq!(t.index(), index);
    assert_eq!(worktree(&t), work);
    let manual = &next["manual_resolutions"][0];
    assert_eq!(
        manual["tree_manual_resolution"]["supplied_complete_tree"],
        true
    );
    let files = t.stored(manual["commit"].as_str().unwrap());
    assert_eq!(files, BTreeMap::from([("a.wasm".into(), UNKNOWN.to_vec())]));
    let witness = manual["tree_manual_resolution"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "a.wasm")
        .unwrap();
    assert_eq!(witness["resolved"]["hex"], "0061736d01000000ff01fe");
    assert!(!witness["resolved"]["audit"].is_null());
    value(&["rebase", t.root(), "--skip"]);
    assert_eq!(
        t.stored("HEAD"),
        BTreeMap::from([
            ("a.wasm".into(), UNKNOWN.to_vec()),
            ("tail.wasm".into(), HEADER.to_vec()),
        ])
    );
    assert_eq!(t.index(), index);
    assert_eq!(worktree(&t), work);
}

#[test]
fn skip_replays_the_remaining_queue_without_reading_or_replacing_a_broken_index() {
    let t = Temp::new();
    let h = history(&t);
    t.record();
    continue_first(&t);
    fs::write(t.path(".uwgit/index"), b"damaged index kept by skip").unwrap();
    t.write("a.wasm", UNKNOWN);
    t.write("new.wasm", HEADER);
    let index = t.index();
    let work = worktree(&t);
    let logs = reflog_len(&t);
    let done = value(&["rebase", t.root(), "--skip"]);
    assert_eq!(done["status"], "rebased");
    assert_eq!(done["steps"][2]["action"], "skipped");
    assert_eq!(done["steps"][2]["source"], h.queue[2]);
    assert_eq!(done["steps"][2]["commit"], Value::Null);
    assert_eq!(done["commits"].as_array().unwrap().len(), 3);
    assert_eq!(done["index_updated"], false);
    assert_eq!(done["worktree_updated"], false);
    assert_eq!(t.index(), index);
    assert_eq!(worktree(&t), work);
    assert_eq!(reflog_len(&t), logs + 1);
    let stored = t.stored("HEAD");
    assert_eq!(stored["a.wasm"], module(9));
    assert_eq!(stored["b.wasm"], module(1));
    assert_eq!(stored["tail.wasm"], HEADER);
}

#[test]
fn abort_after_manual_progress_restores_the_original_tracked_domain_and_raw_index() {
    let t = Temp::new();
    let h = history(&t);
    let baseline = t.index();
    let original = worktree(&t);
    t.record();
    continue_first(&t);
    t.stage("created.wasm", UNKNOWN);
    let _ = fs::remove_file(t.path("tail.wasm"));
    t.write("a.wasm", UNKNOWN);
    fs::write(t.path(".uwgit/index"), b"broken current index").unwrap();
    let logs = reflog_len(&t);
    let aborted = value(&["rebase", t.root(), "--abort"]);
    assert_eq!(aborted["status"], "aborted");
    assert_eq!(t.head(), h.head);
    assert_eq!(reflog_len(&t), logs);
    assert_eq!(t.index(), baseline);
    let mut expected = original;
    expected.insert(PathBuf::from("created.wasm"), Entry::File(UNKNOWN.into()));
    assert_eq!(worktree(&t), expected);
    assert!(!t.path(".uwgit/pending.json").exists());
    assert_eq!(
        value(&["status", t.root()])["untracked"],
        json!(["created.wasm"])
    );
}

#[test]
fn blockers_refuse_abort_before_any_write_and_quit_preserves_all_user_bytes() {
    let t = Temp::new();
    history(&t);
    t.record();
    fs::remove_file(t.path("a.wasm")).unwrap();
    t.write("a.wasm/child.wasm", UNKNOWN);
    rejected(&t, &["rebase", t.root(), "--abort"]);
    let index = t.index();
    let work = worktree(&t);
    let head = t.head();
    let quit = value(&["rebase", t.root(), "--quit"]);
    assert_eq!(quit["status"], "quit");
    assert_eq!(t.index(), index);
    assert_eq!(worktree(&t), work);
    assert_eq!(t.head(), head);
    assert!(!t.path(".uwgit/pending.json").exists());
}

#[test]
fn an_originally_absent_index_is_not_invented_or_used_to_claim_a_clean_resolution() {
    let t = Temp::new();
    let h = history(&t);
    fs::remove_file(t.path(".uwgit/index")).unwrap();
    t.record();
    assert_eq!(t.journal()["baseline_index"], Value::Null);
    rejected(&t, &["rebase", t.root(), "--continue", "--resolved-index"]);
    t.stage("a.wasm", UNKNOWN);
    t.write("later.wasm", HEADER);
    let work = worktree(&t);
    value(&["rebase", t.root(), "--abort"]);
    assert_eq!(t.head(), h.head);
    assert_eq!(t.index(), None);
    assert_eq!(worktree(&t), work);
}

#[test]
fn clean_recorded_rebase_rejects_untracked_file_and_directory_collisions_before_storage() {
    for directory in [false, true] {
        let t = Temp::new();
        t.stage("a.wasm", HEADER);
        t.commit("base");
        ok(&["branch", t.root(), "feature"]);
        t.stage("upstream.wasm", UNKNOWN);
        t.commit("upstream");
        ok(&["switch", t.root(), "feature"]);
        t.stage("a.wasm", &module(3));
        t.commit("clean replay");
        if directory {
            t.write("upstream.wasm/private.wasm", HEADER);
        } else {
            t.write("upstream.wasm", HEADER);
        }
        rejected(&t, &["rebase", t.root(), "main", "--record-conflict"]);
        assert!(!t.path(".uwgit/pending.json").exists());
    }
}

#[test]
fn clean_recorded_rebase_updates_an_existing_clean_workspace_but_keeps_no_index_absent() {
    for indexed in [true, false] {
        let t = Temp::new();
        t.stage("a.wasm", HEADER);
        t.commit("base");
        ok(&["branch", t.root(), "feature"]);
        t.stage("upstream.wasm", UNKNOWN);
        let upstream = t.commit("upstream");
        ok(&["switch", t.root(), "feature"]);
        t.stage("a.wasm", &module(3));
        t.commit("clean replay");
        if !indexed {
            fs::remove_file(t.path(".uwgit/index")).unwrap();
        }
        let work = worktree(&t);
        let done = value(&["rebase", t.root(), "main", "--record-conflict"]);
        assert_eq!(done["status"], "rebased");
        assert_eq!(done["existing_clean_workspace_synchronized"], indexed);
        assert!(done.get("index_updated").is_none());
        assert!(done.get("worktree_updated").is_none());
        assert!(!t.path(".uwgit/pending.json").exists());
        assert_eq!(
            value(&["show", t.root(), "HEAD"])["parents"],
            json!([upstream])
        );
        assert_eq!(t.stored("HEAD")["upstream.wasm"], UNKNOWN);
        if indexed {
            assert_eq!(fs::read(t.path("upstream.wasm")).unwrap(), UNKNOWN);
            assert_eq!(value(&["status", t.root()])["staged"], false);
        } else {
            assert_eq!(t.index(), None);
            assert_eq!(worktree(&t), work);
        }
    }
}

#[test]
fn frozen_upstream_and_queue_survive_ref_replacement_and_stale_bindings_only_allow_quit() {
    let t = Temp::new();
    let h = history(&t);
    t.record();
    ok(&["branch", t.root(), "-D", "main"]);
    ok(&["branch", t.root(), "main", "HEAD"]);
    continue_first(&t);
    let frozen = t.journal();
    assert_eq!(frozen["rebase"]["upstream"], h.upstream);
    assert_eq!(frozen["rebase"]["queue"], json!(h.queue));
    value(&["rebase", t.root(), "--skip"]);
    let automatic = value(&[
        "show",
        t.root(),
        frozen["rebase"]["steps"][0]["commit"].as_str().unwrap(),
    ]);
    assert_eq!(automatic["parents"], json!([h.upstream]));
    for same_tip_other_branch in [false, true] {
        let t = Temp::new();
        let h = history(&t);
        t.record();
        if same_tip_other_branch {
            ok(&["branch", t.root(), "same-tip", "HEAD"]);
            fs::write(t.path(".uwgit/HEAD"), b"same-tip\n").unwrap();
        } else {
            fs::write(t.path(".uwgit/refs/feature"), format!("{}\n", h.upstream)).unwrap();
        }
        assert_eq!(value(&["status", t.root()])["pending"]["stale"], true);
        rejected(&t, &["rebase", t.root(), "--continue", "--resolved-index"]);
        rejected(&t, &["rebase", t.root(), "--skip"]);
        rejected(&t, &["rebase", t.root(), "--abort"]);
        let head = t.head();
        let work = worktree(&t);
        let index = t.index();
        value(&["rebase", t.root(), "--quit"]);
        assert_eq!(t.head(), head);
        assert_eq!(t.index(), index);
        assert_eq!(worktree(&t), work);
    }
}

#[test]
fn pending_controls_locks_partial_status_and_history_guards_are_consistent() {
    let t = Temp::new();
    history(&t);
    t.record();
    for args in [
        vec!["rebase", t.root(), "--continue"],
        vec!["rebase", t.root(), "main", "--continue", "--resolved-index"],
        vec!["rebase", t.root(), "--skip", "--resolved-index"],
        vec!["rebase", t.root(), "--abort", "--onto", "main"],
        vec![
            "rebase",
            t.root(),
            "--quit",
            "--continue",
            "--resolved-index",
        ],
        vec![
            "rebase",
            t.root(),
            "main",
            "--record-conflict",
            "--record-conflict",
        ],
        vec!["merge", t.root(), "--continue", "--resolved-index"],
        vec!["cherry-pick", t.root(), "--skip"],
        vec!["revert", t.root(), "--abort"],
        vec!["commit", t.root(), "-m", "blocked"],
        vec!["switch", t.root(), "main"],
        vec!["checkout", t.root(), "main"],
        vec!["reset", t.root(), "--hard", "HEAD"],
        vec!["rebase", t.root(), "main"],
        vec!["pull", t.root(), "--ff-only"],
    ] {
        rejected(&t, &args);
    }
    ok(&["config", t.root(), "user.name", "resolving rebase"]);
    t.stage("a.wasm", UNKNOWN);
    ok(&["reset", t.root(), "--", "a.wasm"]);
    ok(&["restore", t.root(), "--", "a.wasm"]);
    fs::write(t.path(".uwgit/index.lock"), b"external index owner").unwrap();
    rejected(&t, &["rebase", t.root(), "--skip"]);
    rejected(&t, &["rebase", t.root(), "--abort"]);
    rejected(&t, &["rebase", t.root(), "--quit"]);
    fs::remove_file(t.path(".uwgit/index.lock")).unwrap();
    fs::write(t.path(".uwgit/index"), b"corrupt").unwrap();
    let partial = value(&["status", t.root()]);
    assert_eq!(partial["index_available"], false);
    assert_eq!(partial["worktree"], "unavailable");
    assert_eq!(partial["pending"]["operation"], "rebase");
    assert_eq!(partial["pending"]["rebase"]["cursor"], 1);
    let before = snapshot(&t.repo);
    assert!(ok(&["rebase", t.root(), "--help"]).contains("--record-conflict"));
    assert_eq!(snapshot(&t.repo), before);
    value(&["rebase", t.root(), "--abort"]);
}

#[test]
fn onto_is_frozen_independently_of_the_upstream_fork_and_later_ref_updates() {
    let t = Temp::new();
    let h = history(&t);
    ok(&["branch", t.root(), "new-base", &h.fork]);
    // A separate committed destination deliberately has a distinct identity
    // while retaining the two upstream edits that force both source conflicts.
    ok(&["switch", t.root(), "new-base"]);
    t.stage("a.wasm", &module(1));
    t.stage("b.wasm", &module(1));
    t.stage("destination.wasm", UNKNOWN);
    let onto = t.commit("separate destination");
    ok(&["switch", t.root(), "feature"]);
    report(
        &[
            "rebase",
            t.root(),
            "main",
            "--onto",
            "new-base",
            "--record-conflict",
        ],
        2,
    );
    let saved = t.journal();
    assert_eq!(saved["rebase"]["upstream"], h.upstream);
    assert_eq!(saved["rebase"]["onto"], onto);
    assert_eq!(saved["rebase"]["fork_base"], h.fork);
    assert_eq!(saved["rebase"]["queue"], json!(h.queue));
    ok(&["branch", t.root(), "-D", "new-base"]);
    ok(&["branch", t.root(), "new-base", "HEAD"]);
    continue_first(&t);
    let done = value(&["rebase", t.root(), "--skip"]);
    assert_eq!(done["onto"], onto);
    assert_eq!(t.stored("HEAD")["destination.wasm"], UNKNOWN);
}

#[test]
fn legacy_history_requires_an_explicit_anchor_and_abort_restores_old_index_encoding() {
    let t = Temp::new();
    let old = t.path("old.wasm");
    t.write("old.wasm", &module(0));
    ok(&["commit", t.root(), s(&old), "-m", "legacy base"]);
    ok(&["branch", t.root(), "feature"]);
    t.write("old.wasm", &module(1));
    ok(&["commit", t.root(), s(&old), "-m", "legacy upstream"]);
    ok(&["switch", t.root(), "feature"]);
    t.write("old.wasm", &module(2));
    ok(&["commit", t.root(), s(&old), "-m", "legacy source"]);
    rejected(&t, &["rebase", t.root(), "main", "--record-conflict"]);
    ok(&["add", t.root(), "old.wasm"]);
    let bytes = module(2);
    let mut raw = b"UWGITIDX\x01".to_vec();
    raw.extend_from_slice(&(b"old.wasm".len() as u64).to_le_bytes());
    raw.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    raw.extend_from_slice(b"old.wasm");
    raw.extend_from_slice(&bytes);
    fs::write(t.path(".uwgit/index"), &raw).unwrap();
    let head = t.head();
    let recorded = t.record();
    assert_eq!(recorded["status"], "conflict");
    assert_eq!(t.journal()["legacy_path"], "old.wasm");
    t.stage("old.wasm", UNKNOWN);
    value(&["rebase", t.root(), "--abort"]);
    assert_eq!(t.head(), head);
    assert_eq!(t.index(), Some(raw));
    assert_eq!(fs::read(t.path("old.wasm")).unwrap(), bytes);
}
