//! Native queue invariants and independent Git reference fixtures.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "uwgit-queue-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        ok(&["init", path.to_str().unwrap()]);
        Self(path)
    }
    fn root(&self) -> &str {
        self.0.to_str().unwrap()
    }
    fn write(&self, path: &str, n: u8) {
        fs::write(self.0.join(path), wasm(n)).unwrap();
    }
    fn stage(&self) {
        ok(&["add", self.root(), "-A"]);
    }
    fn commit(&self, message: &str) -> String {
        self.stage();
        ok(&["commit", self.root(), "-m", message]);
        self.head()
    }
    fn head(&self) -> String {
        ok(&["rev-parse", self.root(), "HEAD"])
    }
    fn switch(&self, name: &str) {
        ok(&["switch", self.root(), name]);
    }
    fn index(&self) -> Vec<u8> {
        fs::read(self.0.join(".uwgit/index")).unwrap()
    }
    fn no_pending(&self) {
        assert!(!self.0.join(".uwgit/pending.json").exists());
    }
    fn assert_file(&self, path: &str, n: u8) {
        assert_eq!(fs::read(self.0.join(path)).unwrap(), wasm(n), "{path}");
    }
    fn fixture(&self, conflicting: bool) -> [String; 4] {
        self.write("a.wasm", 1);
        self.write("b.wasm", 1);
        let base = self.commit("base");
        ok(&["branch", self.root(), "source"]);
        self.switch("source");
        self.write("a.wasm", 2);
        let first = self.commit("first");
        self.write("b.wasm", 2);
        let second = self.commit("second");
        self.switch("main");
        self.write("c.wasm", 9);
        if conflicting {
            self.write("a.wasm", 3);
            self.write("b.wasm", 3);
        }
        let ours = self.commit("ours");
        [base, first, second, ours]
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(args: &[&str], input: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
fn ok(args: &[&str]) -> String {
    let o = run(args, None);
    assert!(
        o.status.success(),
        "{args:?}: {}\n{}",
        String::from_utf8_lossy(&o.stderr),
        String::from_utf8_lossy(&o.stdout)
    );
    String::from_utf8(o.stdout).unwrap().trim_end().to_owned()
}
fn value(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}
fn stop(args: &[&str], reason: &str) -> Value {
    let o = run(args, None);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{args:?}: {}\n{}",
        String::from_utf8_lossy(&o.stderr),
        String::from_utf8_lossy(&o.stdout)
    );
    let report: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(report["status"], reason);
    report
}
fn fail(args: &[&str]) {
    assert!(!run(args, None).status.success(), "{args:?}");
}
fn wasm(n: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', n]].concat()
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), out);
            } else {
                out.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}
fn commits(t: &Temp) -> u64 {
    value(&["count-objects", t.root(), "-v"])["by_kind"]["commit"]["objects"]
        .as_u64()
        .unwrap()
}

#[test]
fn bare_lists_and_ranges_freeze_order_and_revert_runs_children_first() {
    for range in [false, true] {
        let t = Temp::new();
        let [base, first, second, ours] = t.fixture(false);
        let r = t.root();
        let selector = format!("{base}..{second}");
        let args = if range {
            vec!["cherry-pick", r, selector.as_str()]
        } else {
            vec!["cherry-pick", r, &first, &second]
        };
        let report = value(&args);
        assert_eq!(report["queue"], json!([first, second]));
        assert_eq!(report["status"], "committed");
        assert_eq!(report["cursor"], 2);
        assert_eq!(report["head_updated"], true);
        t.no_pending();
        let tip = t.head();
        let parent = value(&["show", r, &tip])["parents"][0]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(value(&["show", r, &tip])["message"], "second");
        assert_eq!(value(&["show", r, &parent])["parents"], json!([ours]));
        assert_eq!(value(&["show", r, &parent])["message"], "first");
        t.assert_file("a.wasm", 2);
        t.assert_file("b.wasm", 2);
        t.assert_file("c.wasm", 9);
        let report = value(&["revert", r, &format!("{ours}..{tip}")]);
        assert_eq!(report["queue"], json!([tip, parent]));
        t.assert_file("a.wasm", 1);
        t.assert_file("b.wasm", 1);
        t.assert_file("c.wasm", 9);
        assert_eq!(value(&["show", r, "HEAD~2"])["id"], tip);
        ok(&["fsck", r]);
        t.no_pending();
    }
}

#[test]
fn no_commit_preserves_head_staged_inputs_and_unaffected_editor_bytes_without_synthetic_commits() {
    let t = Temp::new();
    let [base, first, _, ours] = t.fixture(false);
    let r = t.root();
    t.switch("source");
    t.write("d.wasm", 4);
    let third = t.commit("add d");
    t.switch("main");
    t.write("b.wasm", 8);
    ok(&["add", r, "b.wasm"]);
    fs::write(t.0.join("c.wasm"), b"dirty editor bytes").unwrap();
    let count = commits(&t);
    // Select first plus the add-only third commit; never replay second's b edit.
    let report = value(&["cherry-pick", r, "-n", &first, &third]);
    assert_eq!(report["status"], "staged");
    assert_eq!(report["progress_kind"], "tree");
    assert_eq!(
        ok(&["cat-file", r, "-t", report["progress"].as_str().unwrap()]),
        "tree"
    );
    assert_eq!(t.head(), ours);
    assert_eq!(commits(&t), count);
    assert_eq!(fs::read(t.0.join("c.wasm")).unwrap(), b"dirty editor bytes");
    t.assert_file("a.wasm", 2);
    t.assert_file("b.wasm", 8);
    t.assert_file("d.wasm", 4);
    assert!(value(&["status", r])["staged"].as_bool().unwrap());
    t.no_pending();
    ok(&["commit", r, "-m", "one reviewed commit"]);
    assert_eq!(value(&["show", r, "HEAD"])["parents"], json!([ours]));
    assert_eq!(value(&["show", r, &base])["message"], "base");
    ok(&["fsck", r]);
}

#[test]
fn consecutive_conflicts_write_original_stages_and_continue_uses_each_reviewed_complete_index() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(true);
    let r = t.root();
    let first_stop = stop(&["cherry-pick", r, &first, &second], "conflict");
    assert_eq!(first_stop["cursor"], 0);
    assert_eq!(t.head(), ours);
    let rows = value(&["ls-files", r, "-s", "--json", "--", "a.wasm"]);
    assert_eq!(rows["entries"].as_array().unwrap().len(), 3);
    for (row, n) in rows["entries"].as_array().unwrap().iter().zip([1, 3, 2]) {
        let export = t.0.join(format!("stage-{n}.bin"));
        ok(&[
            "cat-file",
            r,
            row["object_id"].as_str().unwrap(),
            "--output",
            export.to_str().unwrap(),
        ]);
        assert_eq!(fs::read(export).unwrap(), wasm(n));
    }
    fail(&["cherry-pick", r, "--continue", "--resolved-index"]);
    t.write("a.wasm", 4);
    ok(&["add", r, "a.wasm"]);
    let next = stop(
        &["cherry-pick", r, "--continue", "--resolved-index"],
        "conflict",
    );
    assert_eq!(next["cursor"], 1);
    assert_eq!(next["target"], second);
    assert_eq!(t.head(), ours);
    let progress = next["progress"].as_str().unwrap();
    assert_eq!(value(&["show", r, progress])["parents"], json!([ours]));
    // Later editor changes on an unchanged path are retained, not silently staged.
    t.write("a.wasm", 5);
    t.write("b.wasm", 4);
    ok(&["add", r, "b.wasm"]);
    let result = value(&["cherry-pick", r, "--continue", "--resolved-index"]);
    assert_eq!(result["status"], "committed");
    assert_eq!(value(&["show", r, "HEAD"])["parents"], json!([progress]));
    t.assert_file("a.wasm", 5);
    t.assert_file("b.wasm", 4);
    let export = t.0.join("committed-a.bin");
    ok(&[
        "show",
        r,
        "HEAD",
        "--file",
        "a.wasm",
        "--output",
        export.to_str().unwrap(),
    ]);
    assert_eq!(fs::read(export).unwrap(), wasm(4));
    t.no_pending();
    ok(&["fsck", r]);
}

#[test]
fn skip_advances_one_target_and_all_skips_restore_the_original_tree_without_new_commits() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(true);
    let r = t.root();
    let count = commits(&t);
    stop(&["cherry-pick", r, &first, &second], "conflict");
    t.write("a.wasm", 7);
    let next = stop(&["cherry-pick", r, "--skip"], "conflict");
    assert_eq!(next["target"], second);
    assert_eq!(next["cursor"], 1);
    t.assert_file("a.wasm", 3);
    let done = value(&["cherry-pick", r, "--skip"]);
    assert_eq!(done["status"], "unchanged");
    assert_eq!(done["head_updated"], false);
    assert_eq!(t.head(), ours);
    assert_eq!(commits(&t), count);
    t.assert_file("b.wasm", 3);
    t.no_pending();
}

#[test]
fn skip_keeps_unrelated_staged_work_files_and_unstaged_edits_outside_the_stopped_source() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(true);
    let r = t.root();
    let count = commits(&t);
    fs::write(t.0.join("c.wasm"), b"initial editor bytes").unwrap();
    stop(&["cherry-pick", r, "-n", &first, &second], "conflict");
    t.write("new.wasm", 9);
    ok(&["add", r, "new.wasm"]);
    fs::write(t.0.join("c.wasm"), b"later unrelated edit").unwrap();
    stop(&["cherry-pick", r, "--skip"], "conflict");
    t.assert_file("new.wasm", 9);
    assert!(!ok(&["ls-files", r]).contains("new.wasm"));
    assert_eq!(
        fs::read(t.0.join("c.wasm")).unwrap(),
        b"later unrelated edit"
    );
    value(&["cherry-pick", r, "--skip"]);
    assert_eq!(t.head(), ours);
    assert_eq!(commits(&t), count);
    t.assert_file("new.wasm", 9);
    assert_eq!(
        fs::read(t.0.join("c.wasm")).unwrap(),
        b"later unrelated edit"
    );
    t.no_pending();
}

#[test]
fn skip_restores_preexisting_no_commit_dirty_bytes_on_the_affected_path() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(true);
    let r = t.root();
    fs::write(t.0.join("a.wasm"), b"original non-Wasm editor bytes").unwrap();
    let baseline = t.index();
    stop(&["cherry-pick", r, "-n", &first, &second], "conflict");
    t.write("a.wasm", 9);
    ok(&["add", r, "a.wasm"]);
    stop(&["cherry-pick", r, "--skip"], "conflict");
    assert_eq!(
        fs::read(t.0.join("a.wasm")).unwrap(),
        b"original non-Wasm editor bytes"
    );
    value(&["cherry-pick", r, "--abort"]);
    assert_eq!(t.index(), baseline);
    assert_eq!(t.head(), ours);
    assert_eq!(
        fs::read(t.0.join("a.wasm")).unwrap(),
        b"original non-Wasm editor bytes"
    );
    t.no_pending();
}

#[test]
fn skip_after_an_earlier_manual_resolution_keeps_untouched_initial_dirty_bytes() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(true);
    let r = t.root();
    let count = commits(&t);
    fs::write(
        t.0.join("b.wasm"),
        b"initial editor bytes kept across both stops",
    )
    .unwrap();
    stop(&["cherry-pick", r, "-n", &first, &second], "conflict");
    t.write("a.wasm", 4);
    ok(&["add", r, "a.wasm"]);
    stop(
        &["cherry-pick", r, "--continue", "--resolved-index"],
        "conflict",
    );
    let report = value(&["cherry-pick", r, "--skip"]);
    assert_eq!(report["status"], "staged");
    assert_eq!(
        fs::read(t.0.join("b.wasm")).unwrap(),
        b"initial editor bytes kept across both stops"
    );
    assert_eq!(t.head(), ours);
    assert_eq!(commits(&t), count);
    t.assert_file("a.wasm", 4);
    t.no_pending();
}

#[test]
fn later_automatic_replay_cannot_discard_an_unrelated_dirty_path_after_skip() {
    let t = Temp::new();
    let [_, first, second, _] = t.fixture(false);
    let r = t.root();
    t.write("a.wasm", 3);
    t.commit("ours conflict only in a");
    stop(&["cherry-pick", r, &first, &second], "conflict");
    t.write("b.wasm", 9);
    let before = snapshot(&t.0);
    fail(&["cherry-pick", r, "--skip"]);
    assert_eq!(snapshot(&t.0), before);
    t.write("b.wasm", 1);
    value(&["cherry-pick", r, "--skip"]);
    t.assert_file("a.wasm", 3);
    t.assert_file("b.wasm", 2);
    t.no_pending();
}

#[test]
fn skip_restores_the_original_sparse_omission_and_index_flags_after_conflict_expansion() {
    let t = Temp::new();
    let [_, first, _, ours] = t.fixture(true);
    let r = t.root();
    ok(&[
        "update-index",
        r,
        "--skip-worktree",
        "--fsmonitor-valid",
        "a.wasm",
    ]);
    fs::remove_file(t.0.join("a.wasm")).unwrap();
    let baseline = t.index();
    stop(&["cherry-pick", r, "--sequence", &first], "conflict");
    let stopped: Value = serde_json::from_slice(&t.index()[9..]).unwrap();
    t.assert_file("a.wasm", 3);
    t.write("a.wasm", 9);
    ok(&["add", r, "a.wasm"]);
    value(&["cherry-pick", r, "--skip"]);
    assert_eq!(t.head(), ours);
    // Skip restores every original image and sparse flag. The explicit add
    // also saved real conflict sides, which remain in the version 5 extension.
    let mut expected: Value = serde_json::from_slice(&baseline[9..]).unwrap();
    expected["format"] = serde_json::json!(5);
    expected["resolve_undo"] = stopped["conflicts"].clone();
    let raw = t.index();
    assert!(raw.starts_with(b"UWGITIDX\x05"));
    assert_eq!(
        serde_json::from_slice::<Value>(&raw[9..]).unwrap(),
        expected
    );
    assert!(!t.0.join("a.wasm").exists());
    assert!(ok(&["ls-files", r, "-t"]).contains("S a.wasm"));
    t.no_pending();
}

#[test]
fn abort_restores_raw_flags_staged_inputs_sparse_absence_and_dirty_initial_bytes() {
    let t = Temp::new();
    let [_, first, _, ours] = t.fixture(true);
    let r = t.root();
    t.switch("source");
    t.write("generated.wasm", 4);
    let add = t.commit("generate");
    t.switch("main");
    t.write("b.wasm", 8);
    ok(&["add", r, "b.wasm"]);
    ok(&["update-index", r, "--skip-worktree", "c.wasm"]);
    fs::remove_file(t.0.join("c.wasm")).unwrap();
    fs::write(t.0.join("b.wasm"), b"original dirty bytes").unwrap();
    let raw = t.index();
    stop(&["cherry-pick", r, "-n", &add, &first], "conflict");
    assert!(t.0.join("generated.wasm").exists());
    fs::write(t.0.join("later.wasm"), wasm(9)).unwrap();
    t.write("a.wasm", 7);
    value(&["cherry-pick", r, "--abort"]);
    assert_eq!(t.head(), ours);
    assert_eq!(t.index(), raw);
    assert_eq!(
        fs::read(t.0.join("b.wasm")).unwrap(),
        b"original dirty bytes"
    );
    assert!(!t.0.join("c.wasm").exists());
    assert!(!t.0.join("generated.wasm").exists());
    t.assert_file("a.wasm", 3);
    t.assert_file("later.wasm", 9);
    t.no_pending();
}

#[test]
fn quit_preserves_unmerged_index_and_editor_bytes_and_pending_guards_retain_progress() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(true);
    let r = t.root();
    stop(&["cherry-pick", r, &first, &second], "conflict");
    t.write("a.wasm", 9);
    let before = t.index();
    fail(&["commit", r, "-m", "not a continuation"]);
    fail(&["switch", r, "source"]);
    value(&["gc", r, "--prune=now"]);
    value(&["cherry-pick", r, "--quit"]);
    assert_eq!(t.head(), ours);
    assert_eq!(t.index(), before);
    t.assert_file("a.wasm", 9);
    t.no_pending();
}

#[test]
fn invalid_late_merge_parent_or_target_is_rejected_before_any_object_or_file_is_written() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(false);
    let r = t.root();
    let tree = ok(&["write-tree", r]);
    let merge = ok(&[
        "commit-tree",
        r,
        &tree,
        "-p",
        &ours,
        "-p",
        &second,
        "-m",
        "merge",
    ]);
    let before = snapshot(&t.0);
    for last in [merge.as_str(), "not-a-revision"] {
        fail(&["cherry-pick", r, &first, last]);
        assert_eq!(snapshot(&t.0), before);
    }
    for opts in [
        vec!["-n", "--ff"],
        vec!["--ff", "-x"],
        vec!["--empty=bogus"],
        vec!["--mainline", "0"],
    ] {
        let mut args = vec!["cherry-pick", r, &first, &second];
        args.extend(opts);
        fail(&args);
        assert_eq!(snapshot(&t.0), before);
    }
    t.no_pending();
}

#[test]
fn root_add_delete_and_mainline_keep_real_absent_sides() {
    let t = Temp::new();
    let [_, first, second, _] = t.fixture(false);
    let r = t.root();
    // A root tree introduces only its real paths, leaving unrelated current paths.
    t.switch("source");
    ok(&["rm", r, "a.wasm"]);
    let deleted = t.commit("delete a");
    let id = ok(&["cat-file", r, "-p", "HEAD"]);
    let info: Value = serde_json::from_str(&id).unwrap();
    let tree_info = value(&["cat-file", r, "-p", info["tree"].as_str().unwrap()]);
    let image = tree_info["entries"]["b.wasm"].as_str().unwrap();
    let out = run(
        &["mktree", r],
        Some(format!("100644 wasm {image}\troot.wasm\n").as_bytes()),
    );
    assert!(out.status.success());
    let root_tree = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    let root = ok(&["commit-tree", r, &root_tree, "-m", "new root"]);
    t.switch("main");
    value(&["cherry-pick", r, "--sequence", &root]);
    t.assert_file("root.wasm", 2);
    t.assert_file("b.wasm", 1);
    t.assert_file("a.wasm", 1);
    t.assert_file("c.wasm", 9);
    // Deletion needs an actual matching parent image.
    value(&["cherry-pick", r, "--sequence", &first]);
    value(&["cherry-pick", r, "--sequence", &deleted]);
    assert!(!t.0.join("a.wasm").exists());
    let current = t.head();
    let tree = ok(&["write-tree", r]);
    let merge = ok(&[
        "commit-tree",
        r,
        &tree,
        "-p",
        &second,
        "-p",
        &current,
        "-m",
        "merge deletion",
    ]);
    value(&["revert", r, "--sequence", "--mainline", "1", &merge]);
    t.assert_file("a.wasm", 2);
    t.no_pending();
    ok(&["fsck", r]);
}

#[test]
fn fast_forward_reuses_exact_original_commits_and_detached_replay_keeps_source_branch() {
    let t = Temp::new();
    let [base, first, second, ours] = t.fixture(false);
    let r = t.root();
    ok(&["reset", r, "--hard", &base]);
    let before = snapshot(&t.0.join(".uwgit/objects"));
    let report = value(&["cherry-pick", r, "--ff", &first, &second]);
    assert_eq!(t.head(), second);
    assert_eq!(report["steps"][0]["action"], "fast-forward");
    assert_eq!(snapshot(&t.0.join(".uwgit/objects")), before);
    ok(&["switch", r, "--detach", &ours]);
    value(&["cherry-pick", r, &first, &second]);
    assert_eq!(value(&["status", r])["detached"], true);
    assert_eq!(ok(&["rev-parse", r, "source"]), second);
    assert_eq!(ok(&["rev-parse", r, "main"]), second);
    t.assert_file("c.wasm", 9);
    t.no_pending();
}

#[test]
fn empty_policies_distinguish_original_empty_from_redundant_changes_and_bind_source_messages() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(false);
    let r = t.root();
    let tree = ok(&["write-tree", r]);
    let empty = ok(&["commit-tree", r, &tree, "-p", &ours, "-m", "original empty"]);
    stop(&["cherry-pick", r, "--empty=drop", &empty], "empty");
    assert_eq!(value(&["cherry-pick", r, "--skip"])["status"], "unchanged");
    value(&["cherry-pick", r, "--allow-empty", &empty]);
    assert_eq!(value(&["show", r, "HEAD"])["message"], "original empty");
    value(&["cherry-pick", r, "-x", &first, &second]);
    assert_eq!(
        value(&["show", r, "HEAD"])["message"],
        format!("second\n\n(cherry picked from commit {second})")
    );
    let head = t.head();
    let count = commits(&t);
    assert_eq!(
        value(&["cherry-pick", r, "--empty", "drop", &first, &second])["status"],
        "unchanged"
    );
    assert_eq!(t.head(), head);
    assert_eq!(commits(&t), count);
    value(&[
        "cherry-pick",
        r,
        "--empty=keep",
        "-m",
        "--help",
        &first,
        &second,
    ]);
    assert_eq!(value(&["show", r, "HEAD"])["message"], "--help");
    assert_eq!(commits(&t), count + 2);
    t.no_pending();
}

#[test]
fn stdin_and_reverse_are_frozen_and_invalid_input_or_replacements_preserve_everything() {
    let t = Temp::new();
    let [_, first, second, _] = t.fixture(true);
    let r = t.root();
    let before = snapshot(&t.0);
    for input in [
        b"\xff\n".as_slice(),
        format!("{first}\nmissing\n").as_bytes(),
    ] {
        assert!(!run(&["cherry-pick", r, "--stdin"], Some(input))
            .status
            .success());
        assert_eq!(snapshot(&t.0), before);
    }
    let input = format!("{first}\n{second}\n{first}\n");
    let o = run(
        &["cherry-pick", r, "--stdin", "--reverse"],
        Some(input.as_bytes()),
    );
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let report: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(report["queue"], json!([second, first]));
    assert_eq!(report["target"], second);
    let before = snapshot(&t.0);
    fail(&[
        "cherry-pick",
        r,
        "--continue",
        "--resolved-index",
        "--empty=keep",
    ]);
    fail(&["revert", r, "--abort"]);
    assert_eq!(snapshot(&t.0), before);
    value(&["cherry-pick", r, "--abort"]);
    t.no_pending();
}

#[test]
fn native_wasm_disjoint_function_changes_compose_exact_bytes_across_the_queue() {
    fn module(a: i32, b: i32) -> Vec<u8> {
        wat::parse_str(format!(
            "(module (func (result i32) i32.const {a}) (func (result i32) i32.const {b}))"
        ))
        .unwrap()
    }
    let t = Temp::new();
    let r = t.root();
    fs::write(t.0.join("a.wasm"), module(0, 0)).unwrap();
    t.commit("base");
    ok(&["branch", r, "source"]);
    t.switch("source");
    fs::write(t.0.join("a.wasm"), module(1, 0)).unwrap();
    let first = t.commit("function one");
    t.write("b.wasm", 2);
    let second = t.commit("add b");
    t.switch("main");
    fs::write(t.0.join("a.wasm"), module(0, 9)).unwrap();
    t.commit("function two");
    value(&["cherry-pick", r, &first, &second]);
    assert_eq!(fs::read(t.0.join("a.wasm")).unwrap(), module(1, 9));
    t.assert_file("b.wasm", 2);
    ok(&["fsck", r]);
}

#[test]
fn file_directory_conflicts_preserve_all_original_stages_and_abort_the_whole_prefix() {
    let t = Temp::new();
    let r = t.root();
    t.write("slot.wasm", 1);
    let base = t.commit("base");
    ok(&["branch", r, "source"]);
    t.switch("source");
    ok(&["rm", r, "slot.wasm"]);
    fs::create_dir(t.0.join("slot.wasm")).unwrap();
    t.write("slot.wasm/child.wasm", 2);
    let target = t.commit("file to directory");
    t.switch("main");
    t.write("slot.wasm", 3);
    t.commit("ours edit");
    let raw = t.index();
    let head = t.head();
    let report = stop(&["cherry-pick", r, "--sequence", &target], "conflict");
    assert_eq!(report["cursor"], 0);
    t.assert_file("slot.wasm", 3);
    let rows = value(&["ls-files", r, "--unmerged", "--json"]);
    let rows = rows["entries"].as_array().unwrap();
    assert!(rows
        .iter()
        .any(|row| row["path"] == "slot.wasm" && row["stage"] == 1));
    assert!(rows
        .iter()
        .any(|row| row["path"] == "slot.wasm" && row["stage"] == 2));
    assert!(rows
        .iter()
        .any(|row| row["path"] == "slot.wasm/child.wasm" && row["stage"] == 3));
    value(&["cherry-pick", r, "--abort"]);
    assert_eq!(t.index(), raw);
    assert_eq!(t.head(), head);
    t.assert_file("slot.wasm", 3);
    assert_ne!(head, base);
    t.no_pending();
}

#[test]
fn late_untracked_obstruction_refuses_the_complete_queue_before_installing_a_clean_prefix() {
    let t = Temp::new();
    let [_, first, _, _] = t.fixture(false);
    let r = t.root();
    t.switch("source");
    t.write("new.wasm", 2);
    let later = t.commit("new path");
    t.switch("main");
    t.write("new.wasm", 9);
    let before = snapshot(&t.0);
    fail(&["cherry-pick", r, &first, &later]);
    assert_eq!(snapshot(&t.0), before);
    t.no_pending();
}

#[test]
fn replay_deletes_skipped_absence_and_materializes_only_an_actual_conflict_then_abort_reinstates_it(
) {
    let t = Temp::new();
    let [_, first, _, _] = t.fixture(false);
    let r = t.root();
    t.switch("source");
    ok(&["rm", r, "a.wasm"]);
    let deletion = t.commit("delete a");
    t.switch("main");
    value(&["cherry-pick", r, "--sequence", &first]);
    ok(&["update-index", r, "--skip-worktree", "a.wasm"]);
    fs::remove_file(t.0.join("a.wasm")).unwrap();
    value(&["cherry-pick", r, "--sequence", &deletion]);
    assert!(!t.0.join("a.wasm").exists());
    assert!(!ok(&["ls-files", r]).contains("a.wasm"));
    // Restore a different committed ours image, omit it, and force a real content conflict.
    t.write("a.wasm", 3);
    t.commit("new ours");
    ok(&["update-index", r, "--skip-worktree", "a.wasm"]);
    fs::remove_file(t.0.join("a.wasm")).unwrap();
    let raw = t.index();
    stop(&["cherry-pick", r, "--sequence", &first], "conflict");
    t.assert_file("a.wasm", 3);
    value(&["cherry-pick", r, "--abort"]);
    assert_eq!(t.index(), raw);
    assert!(!t.0.join("a.wasm").exists());
    t.no_pending();
}

#[test]
fn no_commit_conflict_exports_a_real_tree_progress_and_continues_without_creating_commits() {
    let t = Temp::new();
    let [_, first, second, ours] = t.fixture(true);
    let r = t.root();
    let count = commits(&t);
    let report = stop(&["cherry-pick", r, "-n", &first, &second], "conflict");
    assert_eq!(report["progress_kind"], "tree");
    let review = t.0.join("review");
    let export = value(&["mergetool", r, "--output", review.to_str().unwrap()]);
    assert_eq!(export["ours_kind"], "tree");
    assert_eq!(
        ok(&["cat-file", r, "-t", export["ours"].as_str().unwrap()]),
        "tree"
    );
    for (side, n) in [("base", 1), ("local", 3), ("remote", 2)] {
        assert_eq!(
            fs::read(export["files"][0][side]["file"].as_str().unwrap()).unwrap(),
            wasm(n)
        );
    }
    t.write("a.wasm", 4);
    ok(&["add", r, "a.wasm"]);
    stop(
        &["cherry-pick", r, "--continue", "--resolved-index"],
        "conflict",
    );
    t.write("b.wasm", 4);
    ok(&["add", r, "b.wasm"]);
    let report = value(&["cherry-pick", r, "--continue", "--resolved-index"]);
    assert_eq!(report["status"], "staged");
    assert_eq!(report["commits"], json!([]));
    assert!(report["commit"].is_null());
    for row in report["manual_resolutions"].as_array().unwrap() {
        assert!(row["commit"].is_null());
        assert_eq!(row["result_kind"], "tree");
        assert_eq!(
            ok(&["cat-file", r, "-t", row["result"].as_str().unwrap()]),
            "tree"
        );
    }
    assert_eq!(t.head(), ours);
    assert_eq!(commits(&t), count);
    t.assert_file("a.wasm", 4);
    t.assert_file("b.wasm", 4);
    t.no_pending();
}

#[test]
fn real_git_reference_matches_order_parent_counts_files_and_no_commit_in_separate_fixtures() {
    fn git(root: &Path, args: &[&str]) -> String {
        let o = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap().trim_end().into()
    }
    for no_commit in [false, true] {
        let t = Temp::new();
        let [_, first, second, ours] = t.fixture(false);
        let r = t.root();
        let g = t.0.join("reference");
        fs::create_dir(&g).unwrap();
        git(&g, &["init", "-b", "main"]);
        for path in ["a.wasm", "b.wasm"] {
            fs::write(g.join(path), wasm(1)).unwrap();
        }
        git(&g, &["add", "."]);
        git(&g, &["commit", "-m", "base"]);
        git(&g, &["switch", "-c", "source"]);
        fs::write(g.join("a.wasm"), wasm(2)).unwrap();
        git(&g, &["commit", "-am", "first"]);
        let g1 = git(&g, &["rev-parse", "HEAD"]);
        fs::write(g.join("b.wasm"), wasm(2)).unwrap();
        git(&g, &["commit", "-am", "second"]);
        let g2 = git(&g, &["rev-parse", "HEAD"]);
        git(&g, &["switch", "main"]);
        fs::write(g.join("c.wasm"), wasm(9)).unwrap();
        git(&g, &["add", "."]);
        git(&g, &["commit", "-m", "ours"]);
        let gh = git(&g, &["rev-parse", "HEAD"]);
        if no_commit {
            value(&["cherry-pick", r, "-n", &first, &second]);
            git(&g, &["cherry-pick", "-n", &g1, &g2]);
        } else {
            value(&["cherry-pick", r, &first, &second]);
            git(&g, &["cherry-pick", &g1, &g2]);
        }
        for path in ["a.wasm", "b.wasm", "c.wasm"] {
            assert_eq!(
                fs::read(t.0.join(path)).unwrap(),
                fs::read(g.join(path)).unwrap()
            );
        }
        if no_commit {
            assert_eq!(t.head(), ours);
            assert_eq!(git(&g, &["rev-parse", "HEAD"]), gh);
        } else {
            assert_eq!(value(&["show", r, "HEAD~2"])["id"], ours);
            assert_eq!(
                git(&g, &["rev-list", "--count", &format!("{gh}..HEAD")]),
                "2"
            );
            value(&["revert", r, "HEAD~2..HEAD"]);
            git(&g, &["revert", "--no-edit", "HEAD~2..HEAD"]);
            for path in ["a.wasm", "b.wasm", "c.wasm"] {
                assert_eq!(
                    fs::read(t.0.join(path)).unwrap(),
                    fs::read(g.join(path)).unwrap()
                );
            }
        }
    }
}
