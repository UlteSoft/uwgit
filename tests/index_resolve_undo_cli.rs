use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const UNKNOWN: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
struct Temp {
    directory: PathBuf,
    repo: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "uwgit-resolve-undo-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let repo = directory.join("repo");
        ok(&["init", p(&repo)], None);
        Self { directory, repo }
    }
    fn root(&self) -> &str {
        p(&self.repo)
    }
    fn path(&self, path: &str) -> PathBuf {
        self.repo.join(path)
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        let full = self.path(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, bytes).unwrap();
    }
    fn stage(&self, path: &str, bytes: &[u8]) {
        self.write(path, bytes);
        ok(&["add", self.root(), "--", path], None);
    }
    fn commit(&self) -> String {
        ok(&["commit", self.root(), "-m", "real Wasm images"], None);
        ok(&["rev-parse", self.root(), "HEAD"], None)
    }
    fn index(&self) -> Vec<u8> {
        fs::read(self.path(".uwgit/index")).unwrap()
    }
    fn ids(&self) -> Vec<String> {
        [wasm(1), wasm(2), UNKNOWN.to_vec()]
            .iter()
            .map(|bytes| ok(&["hash-object", self.root(), "-w", "--stdin"], Some(bytes)))
            .collect()
    }
    fn seed(&self, path: &str, mask: u8) -> Vec<String> {
        let ids = self.ids();
        let mut records = format!("0 0\t{path}\n");
        for stage in 1..=3 {
            if mask & (1 << (stage - 1)) != 0 {
                records.push_str(&format!("100644 {} {stage}\t{path}\n", ids[stage - 1]));
            }
        }
        ok(
            &["update-index", self.root(), "--index-info"],
            Some(records.as_bytes()),
        );
        ids
    }
    fn reject(&self, args: &[&str], input: Option<&[u8]>) {
        let before = files(&self.repo);
        let output = run(args, input);
        assert!(!output.status.success(), "unexpected success: {args:?}");
        assert_eq!(
            files(&self.repo),
            before,
            "failed command changed files: {args:?}"
        );
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
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
fn ok(args: &[&str], input: Option<&[u8]>) -> String {
    let output = run(args, input);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end_matches('\n')
        .into()
}
fn value(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args, None)).unwrap()
}
fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, dir: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(root, &entry.path(), result);
            } else if kind.is_file() {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().into(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn resolution_lists_original_unpublished_images_with_stage_tags_paths_and_nul() {
    let t = Temp::new();
    let ids = t.seed("modules/a.wasm", 7);
    t.write("modules/a.wasm", UNKNOWN);
    let mut before = files(&t.repo);
    ok(&["add", t.root(), "modules/a.wasm"], None);
    assert!(t.index().starts_with(b"UWGITIDX\x05"));
    before.insert(PathBuf::from(".uwgit/index"), t.index());
    assert_eq!(files(&t.repo), before);
    let expected = ids
        .iter()
        .enumerate()
        .map(|(n, id)| format!("100644 {id} {}\tmodules/a.wasm", n + 1))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        ok(&["ls-files", t.root(), "--resolve-undo"], None),
        expected
    );
    assert_eq!(ok(&["ls-files", t.root()], None), "modules/a.wasm");
    let output = run(
        &[
            "ls-files",
            t.root(),
            "--resolve-undo",
            "-t",
            "-z",
            "--deduplicate",
            "--",
            "modules/*.wasm",
        ],
        None,
    );
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        expected
            .split('\n')
            .map(|row| format!("U {row}\0"))
            .collect::<String>()
            .as_bytes()
    );
    let rows = value(&["ls-files", t.root(), "--resolve-undo", "--json"]);
    assert_eq!(rows["entries"].as_array().unwrap().len(), 3);
    for (n, row) in rows["entries"].as_array().unwrap().iter().enumerate() {
        assert_eq!(row["object_id"], ids[n]);
        assert_eq!(row["stage"], n + 1);
        assert_eq!(row["resolve_undo"], true);
        assert_eq!(row["reason"], "U");
    }
    assert_eq!(
        ok(
            &[
                "ls-files",
                t.root(),
                "--cached",
                "--stage",
                "--resolve-undo"
            ],
            None
        ),
        format!("100644 {} 0\tmodules/a.wasm\n{expected}", ids[2])
    );
    assert_eq!(
        ok(
            &["ls-files", t.root(), "--resolve-undo", "--", "other.wasm"],
            None
        ),
        ""
    );
    t.reject(
        &["ls-files", t.root(), "--resolve-undo", "--format=%(path)"],
        None,
    );
}

#[test]
fn every_missing_side_combination_survives_deleted_resolution_and_consumed_reinstatement() {
    for mask in 1..=7 {
        let t = Temp::new();
        t.seed("a.wasm", mask);
        let original = ok(&["ls-files", t.root(), "--unmerged"], None);
        t.write("a.wasm", b"raw private editor contents");
        ok(
            &["update-index", t.root(), "--force-remove", "a.wasm"],
            None,
        );
        assert_eq!(
            ok(&["ls-files", t.root(), "--resolve-undo"], None),
            original
        );
        let restored = value(&["update-index", t.root(), "--unresolve", "a.wasm"]);
        assert_eq!(restored["restored"], json!(["a.wasm"]));
        assert_eq!(ok(&["ls-files", t.root(), "--unmerged"], None), original);
        assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
        assert_eq!(
            fs::read(t.path("a.wasm")).unwrap(),
            b"raw private editor contents"
        );
        let before = files(&t.repo);
        ok(
            &[
                "update-index",
                t.root(),
                "--unresolve",
                "a.wasm",
                "absent.wasm",
            ],
            None,
        );
        assert_eq!(files(&t.repo), before);
        t.reject(&["write-tree", t.root()], None);
    }
}

#[test]
fn all_explicit_resolution_writers_keep_the_complete_original_sides() {
    for mode in [
        "add",
        "rm",
        "path",
        "remove",
        "force-remove",
        "cacheinfo",
        "index-info",
        "zero",
        "restore",
        "merge-index",
    ] {
        let t = Temp::new();
        t.stage("a.wasm", &wasm(9));
        let head = t.commit();
        let ids = t.seed("a.wasm", 7);
        if mode == "merge-index" {
            ok(
                &["update-index", t.root(), "--index-info"],
                Some(format!("100644 {} 1\ta.wasm\n", ids[1]).as_bytes()),
            );
        }
        let original = ok(&["ls-files", t.root(), "-u"], None);
        if mode == "remove" {
            fs::remove_file(t.path("a.wasm")).unwrap();
        }
        let work = fs::read(t.path("a.wasm")).ok();
        match mode {
            "add" => {
                ok(&["add", t.root(), "a.wasm"], None);
            }
            "rm" => {
                ok(&["rm", t.root(), "--cached", "--force", "a.wasm"], None);
            }
            "path" => {
                ok(&["update-index", t.root(), "a.wasm"], None);
            }
            "remove" => {
                ok(&["update-index", t.root(), "--remove", "a.wasm"], None);
            }
            "force-remove" => {
                ok(
                    &["update-index", t.root(), "--force-remove", "a.wasm"],
                    None,
                );
            }
            "cacheinfo" => {
                ok(
                    &[
                        "update-index",
                        t.root(),
                        "--cacheinfo",
                        &format!("100644,{},a.wasm", ids[2]),
                    ],
                    None,
                );
            }
            "index-info" => {
                ok(
                    &["update-index", t.root(), "--index-info"],
                    Some(format!("100644 {}\ta.wasm\n", ids[2]).as_bytes()),
                );
            }
            "zero" => {
                ok(
                    &["update-index", t.root(), "--index-info"],
                    Some(b"0 0\ta.wasm\n"),
                );
            }
            "restore" => {
                ok(
                    &[
                        "restore",
                        t.root(),
                        "--source",
                        &head,
                        "--staged",
                        "--",
                        "a.wasm",
                    ],
                    None,
                );
            }
            "merge-index" => {
                ok(&["merge-index", t.root(), "--all"], None);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            ok(&["ls-files", t.root(), "--resolve-undo"], None),
            original,
            "writer {mode}"
        );
        assert_eq!(fs::read(t.path("a.wasm")).ok(), work, "writer {mode}");
        assert_eq!(ok(&["rev-parse", t.root(), "HEAD"], None), head);
        ok(&["update-index", t.root(), "--unresolve", "a.wasm"], None);
        assert_eq!(ok(&["ls-files", t.root(), "-u"], None), original);
    }
}

#[test]
fn structural_undo_requires_a_valid_complete_selection_and_never_changes_work_files() {
    let t = Temp::new();
    let ids = t.ids();
    ok(
        &["update-index", t.root(), "--index-info"],
        Some(
            format!(
                "100644 {} 2\tnode\n100644 {} 3\tnode/child.wasm\n",
                ids[0], ids[2]
            )
            .as_bytes(),
        ),
    );
    let original = ok(&["ls-files", t.root(), "-u"], None);
    t.write("node/child.wasm", UNKNOWN);
    ok(&["rm", t.root(), "--cached", "--force", "node"], None);
    ok(&["add", t.root(), "node/child.wasm"], None);
    assert_eq!(
        ok(&["ls-files", t.root(), "--resolve-undo"], None),
        original
    );
    t.reject(&["update-index", t.root(), "--unresolve", "node"], None);
    ok(
        &["update-index", t.root(), "--unresolve", "--stdin", "-z"],
        Some(b"node\0node/child.wasm\0node\0"),
    );
    assert_eq!(ok(&["ls-files", t.root(), "-u"], None), original);
    assert_eq!(fs::read(t.path("node/child.wasm")).unwrap(), UNKNOWN);
    assert!(t.path("node").is_dir());
}

#[test]
fn an_already_unmerged_path_keeps_new_sides_when_its_older_undo_is_consumed() {
    let t = Temp::new();
    let ids = t.seed("a.wasm", 7);
    t.stage("a.wasm", UNKNOWN);
    ok(
        &["update-index", t.root(), "--index-info"],
        Some(format!("100644 {} 2\ta.wasm\n", ids[2]).as_bytes()),
    );
    let active = ok(&["ls-files", t.root(), "-u"], None);
    assert_eq!(active.lines().count(), 1);
    assert_ne!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
    ok(&["update-index", t.root(), "--unresolve", "a.wasm"], None);
    assert_eq!(ok(&["ls-files", t.root(), "-u"], None), active);
    assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), UNKNOWN);
}

#[test]
fn stash_restores_undo_images_and_explicit_whole_tree_reset_discards_them() {
    let t = Temp::new();
    t.stage("a.wasm", &wasm(9));
    t.commit();
    t.seed("a.wasm", 7);
    t.stage("a.wasm", UNKNOWN);
    let saved = ok(&["ls-files", t.root(), "--resolve-undo"], None);
    ok(
        &["stash", t.root(), "push", "-m", "saved original sides"],
        None,
    );
    assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
    ok(&["stash", t.root(), "pop", "0"], None);
    assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), saved);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), UNKNOWN);
    ok(&["reset", t.root(), "--mixed", "HEAD"], None);
    assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), UNKNOWN);
}

#[test]
fn malformed_batches_dry_runs_locks_and_clear_controls_preserve_all_other_state() {
    let t = Temp::new();
    let ids = t.seed("a.wasm", 7);
    t.write("a.wasm", UNKNOWN);
    ok(&["add", t.root(), "a.wasm"], None);
    let before = files(&t.repo);
    ok(
        &[
            "update-index",
            t.root(),
            "--unresolve",
            "--dry-run",
            "a.wasm",
        ],
        None,
    );
    ok(
        &[
            "update-index",
            t.root(),
            "--clear-resolve-undo",
            "--dry-run",
        ],
        None,
    );
    assert_eq!(files(&t.repo), before);
    let cacheinfo = format!("100644,{},a.wasm", ids[0]);
    for args in [
        vec!["update-index", t.root(), "--unresolve", "a.wasm", "../bad"],
        vec![
            "update-index",
            t.root(),
            "--unresolve",
            "--refresh",
            "a.wasm",
        ],
        vec!["update-index", t.root(), "--clear-resolve-undo", "a.wasm"],
        vec![
            "update-index",
            t.root(),
            "--clear-resolve-undo",
            "--index-info",
        ],
        vec![
            "update-index",
            t.root(),
            "--unresolve",
            "--cacheinfo",
            &cacheinfo,
        ],
    ] {
        t.reject(&args, None);
    }
    t.reject(
        &["update-index", t.root(), "--unresolve", "--stdin", "-z"],
        Some(b"a.wasm\0../bad\0"),
    );
    fs::write(t.path(".uwgit/index.lock"), b"other writer").unwrap();
    t.reject(&["update-index", t.root(), "--unresolve", "a.wasm"], None);
    t.reject(&["update-index", t.root(), "--clear-resolve-undo"], None);
    fs::remove_file(t.path(".uwgit/index.lock")).unwrap();
    let stages = ok(&["ls-files", t.root(), "--stage"], None);
    let work = fs::read(t.path("a.wasm")).unwrap();
    ok(&["update-index", t.root(), "--clear-resolve-undo"], None);
    assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
    assert_eq!(ok(&["ls-files", t.root(), "--stage"], None), stages);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), work);
    let clean = files(&t.repo);
    ok(&["update-index", t.root(), "--unresolve"], None);
    ok(
        &["update-index", t.root(), "--unresolve", "missing.wasm"],
        None,
    );
    ok(&["update-index", t.root(), "--clear-resolve-undo"], None);
    assert_eq!(files(&t.repo), clean);
    let empty = Temp::new();
    ok(
        &["update-index", empty.root(), "--unresolve", "missing.wasm"],
        None,
    );
    ok(
        &["update-index", empty.root(), "--clear-resolve-undo"],
        None,
    );
    assert!(!empty.path(".uwgit/index").exists());
}

#[test]
fn undo_coexists_with_flags_and_intents_and_unresolve_removes_only_selected_entry_flags() {
    let t = Temp::new();
    t.stage("stable.wasm", &wasm(7));
    ok(
        &["update-index", t.root(), "--skip-worktree", "stable.wasm"],
        None,
    );
    t.seed("a.wasm", 7);
    t.stage("a.wasm", UNKNOWN);
    ok(
        &["update-index", t.root(), "--assume-unchanged", "a.wasm"],
        None,
    );
    t.write("later.wasm", &wasm(1));
    ok(&["add", t.root(), "-N", "later.wasm"], None);
    let before = value(&["ls-files", t.root(), "--json"]);
    assert_eq!(before["index_format"], 5);
    // The saved sides remain real images even if the current path later
    // becomes a no-image intent-to-add entry.
    ok(
        &["update-index", t.root(), "--force-remove", "a.wasm"],
        None,
    );
    ok(&["add", t.root(), "-N", "a.wasm"], None);
    let saved = ok(&["ls-files", t.root(), "--resolve-undo"], None);
    assert_eq!(saved.lines().count(), 3);
    assert!(!saved.contains(" - 0\t"));
    ok(&["update-index", t.root(), "--unresolve", "a.wasm"], None);
    let after = value(&["ls-files", t.root(), "--json"]);
    for path in ["stable.wasm", "later.wasm"] {
        let row = |v: &Value| {
            v["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["path"] == path)
                .unwrap()
                .clone()
        };
        assert_eq!(row(&before), row(&after));
    }
    for row in after["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["path"] == "a.wasm")
    {
        assert_eq!(row["assume_unchanged"], false);
    }
}

#[test]
fn linked_worktrees_have_independent_undo_records_and_full_read_tree_clears_them() {
    let t = Temp::new();
    t.stage("a.wasm", &wasm(8));
    let head = t.commit();
    ok(&["branch", t.root(), "other"], None);
    let linked = t.directory.join("linked");
    ok(&["worktree", t.root(), "add", p(&linked), "other"], None);
    let linked_index = fs::read(linked.join(".uwgit/index")).unwrap();
    t.seed("a.wasm", 7);
    t.stage("a.wasm", UNKNOWN);
    assert_eq!(fs::read(linked.join(".uwgit/index")).unwrap(), linked_index);
    assert_eq!(ok(&["ls-files", p(&linked), "--resolve-undo"], None), "");
    let saved = ok(&["ls-files", t.root(), "--resolve-undo"], None);
    ok(&["update-index", p(&linked), "--clear-resolve-undo"], None);
    assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), saved);
    ok(&["read-tree", t.root(), &head], None);
    assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), UNKNOWN);
}

fn rebase_history(t: &Temp) -> String {
    t.stage("a.wasm", &wasm(1));
    t.commit();
    ok(&["branch", t.root(), "feature"], None);
    t.stage("a.wasm", &wasm(2));
    t.commit();
    ok(&["switch", t.root(), "feature"], None);
    t.stage("a.wasm", &wasm(3));
    t.commit();
    t.stage("tail.wasm", &wasm(4));
    t.commit()
}

#[test]
fn recorded_rebase_can_unresolve_review_again_and_preserve_undo_across_publication() {
    let t = Temp::new();
    let head = rebase_history(&t);
    let output = run(&["rebase", t.root(), "main", "--record-conflict"], None);
    assert_eq!(output.status.code(), Some(2));
    let original = ok(&["ls-files", t.root(), "-u"], None);
    t.stage("a.wasm", UNKNOWN);
    assert_eq!(
        ok(&["ls-files", t.root(), "--resolve-undo"], None),
        original
    );
    ok(&["update-index", t.root(), "--unresolve", "a.wasm"], None);
    t.reject(
        &["rebase", t.root(), "--continue", "--resolved-index"],
        None,
    );
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), UNKNOWN);
    assert_eq!(ok(&["rev-parse", t.root(), "HEAD"], None), head);
    ok(&["add", t.root(), "a.wasm"], None);
    let done = value(&["rebase", t.root(), "--continue", "--resolved-index"]);
    assert_eq!(done["status"], "rebased");
    assert_eq!(
        ok(&["ls-files", t.root(), "--resolve-undo"], None),
        original
    );
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), UNKNOWN);
    assert_eq!(fs::read(t.path("tail.wasm")).unwrap(), wasm(4));
    assert!(!t.path(".uwgit/pending.json").exists());
    ok(&["fsck", t.root()], None);
}

#[test]
fn recorded_rebase_abort_restores_the_original_v5_index_and_skip_keeps_saved_sides() {
    for abort in [true, false] {
        let t = Temp::new();
        let head = rebase_history(&t);
        t.seed("a.wasm", 7);
        t.stage("a.wasm", &wasm(3));
        let baseline = t.index();
        let saved = ok(&["ls-files", t.root(), "--resolve-undo"], None);
        let output = run(&["rebase", t.root(), "main", "--record-conflict"], None);
        assert_eq!(output.status.code(), Some(2));
        t.stage("a.wasm", UNKNOWN);
        let resolved = ok(&["ls-files", t.root(), "--resolve-undo"], None);
        if abort {
            ok(&["rebase", t.root(), "--abort"], None);
            assert_eq!(t.index(), baseline);
            assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), saved);
            assert_eq!(ok(&["rev-parse", t.root(), "HEAD"], None), head);
            assert_eq!(fs::read(t.path("a.wasm")).unwrap(), wasm(3));
        } else {
            ok(&["rebase", t.root(), "--skip"], None);
            assert_eq!(
                ok(&["ls-files", t.root(), "--resolve-undo"], None),
                resolved
            );
            assert_eq!(fs::read(t.path("a.wasm")).unwrap(), wasm(2));
            assert!(!t.path(".uwgit/pending.json").exists());
        }
    }
}

fn seed_images(t: &Temp, path: &str, images: [&[u8]; 3]) {
    let mut records = format!("0 0\t{path}\n");
    for (n, bytes) in images.into_iter().enumerate() {
        let id = ok(&["hash-object", t.root(), "-w", "--stdin"], Some(bytes));
        records.push_str(&format!("100644 {id} {}\t{path}\n", n + 1));
    }
    ok(
        &["update-index", t.root(), "--index-info"],
        Some(records.as_bytes()),
    );
}

#[test]
fn merge_restore_recreates_selected_original_sides_and_preserves_every_other_file() {
    for command in ["checkout", "restore"] {
        for mask in [6, 7] {
            for resolved in [false, true] {
                let t = Temp::new();
                t.stage("stable.wasm", &wasm(8));
                let head = t.commit();
                t.write("stable.wasm", b"raw editor bytes, not a module\n");
                t.seed("a.wasm", mask);
                let stages = ok(&["ls-files", t.root(), "-u"], None);
                if resolved {
                    t.stage("a.wasm", &wasm(9));
                } else {
                    t.write("a.wasm", b"incomplete edit");
                }
                let mut expected = files(&t.repo);
                let report = ok(&[command, t.root(), "--merge", "--", "a.wasm"], None);
                assert!(report.contains("ours fallbacks: 1"), "{report}");
                assert_eq!(fs::read(t.path("a.wasm")).unwrap(), wasm(2));
                assert_eq!(ok(&["ls-files", t.root(), "-u"], None), stages);
                assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
                if resolved {
                    expected.insert(PathBuf::from(".uwgit/index"), t.index());
                }
                expected.insert(PathBuf::from("a.wasm"), wasm(2));
                assert_eq!(files(&t.repo), expected);
                assert_eq!(ok(&["rev-parse", t.root(), "HEAD"], None), head);
                t.reject(&["write-tree", t.root()], None);
                // Repeating -m does not rewrite an already unmerged index.
                ok(&[command, t.root(), "-m", "--", "a.wasm"], None);
                assert_eq!(files(&t.repo), expected);
            }
        }
    }
}

#[test]
fn merge_restore_synthesizes_disjoint_wasm_sections_without_resolving_the_index() {
    let pair = |a: u8, b: u8| [wasm(a), vec![0, 3, 1, b'y', b]].concat();
    for command in ["checkout", "restore"] {
        let t = Temp::new();
        let base = pair(1, 1);
        let ours = pair(2, 1);
        let theirs = pair(1, 3);
        seed_images(&t, "a.wasm", [&base, &ours, &theirs]);
        let before = t.index();
        t.write("a.wasm", b"raw edit to replace");
        let report = ok(&[command, t.root(), "-m", "--", "a.wasm"], None);
        assert!(
            report.contains("native Wasm merges: 1; ours fallbacks: 0"),
            "{report}"
        );
        assert_eq!(fs::read(t.path("a.wasm")).unwrap(), pair(2, 3));
        assert_eq!(t.index(), before);
        t.reject(&["write-tree", t.root()], None);
    }
}

#[test]
fn merge_restore_keeps_original_unknown_bytes_when_three_way_synthesis_is_unavailable() {
    let t = Temp::new();
    let ours = [UNKNOWN, &[0x81]].concat();
    let theirs = [UNKNOWN, &[0x82]].concat();
    seed_images(&t, "a.wasm", [UNKNOWN, &ours, &theirs]);
    let before = t.index();
    t.write("a.wasm", b"raw edit");
    let report = ok(&["restore", t.root(), "-m", "-W", "--", "a.wasm"], None);
    assert!(report.contains("ours fallback: a.wasm:"), "{report}");
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), ours);
    assert_eq!(t.index(), before);
}

#[test]
fn merge_restore_missing_live_sides_and_mixed_batch_fail_before_any_writes() {
    for mask in 1..=5 {
        for resolved in [false, true] {
            let t = Temp::new();
            t.seed("good.wasm", 7);
            t.write("good.wasm", b"raw good edit");
            t.seed("z-missing.wasm", mask);
            if resolved {
                t.stage("z-missing.wasm", &wasm(8));
            } else {
                t.write("z-missing.wasm", b"raw missing-side edit");
            }
            for command in ["checkout", "restore"] {
                t.reject(&[command, t.root(), "-m", "--", "."], None);
            }
        }
    }
}

#[test]
fn merge_restore_selects_undo_with_shared_magic_and_consumes_only_selected_records() {
    let t = Temp::new();
    for path in ["modules/a.wasm", "modules/b.wasm", "--merge"] {
        t.seed(path, 7);
        t.stage(path, &wasm(9));
    }
    let saved = ok(&["ls-files", t.root(), "--resolve-undo"], None);
    ok(
        &[
            "checkout",
            t.root(),
            "-m",
            "--",
            ":(icase)MODULES/*.WASM",
            ":(exclude)modules/b.wasm",
        ],
        None,
    );
    assert_eq!(fs::read(t.path("modules/a.wasm")).unwrap(), wasm(2));
    assert_eq!(fs::read(t.path("modules/b.wasm")).unwrap(), wasm(9));
    let remaining = saved
        .lines()
        .filter(|line| !line.ends_with("\tmodules/a.wasm"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        ok(&["ls-files", t.root(), "--resolve-undo"], None),
        remaining
    );
    t.reject(
        &["restore", t.root(), "-m", "--", "modules", "absent"],
        None,
    );
    ok(
        &["restore", t.root(), "-m", "--", ":(literal)--merge"],
        None,
    );
    assert_eq!(fs::read(t.path("--merge")).unwrap(), wasm(2));
}

#[test]
fn side_restore_handles_mixed_stage_zero_and_actual_absent_sides() {
    for (mode, mask, present) in [
        ("--ours", 5, false),
        ("--theirs", 3, false),
        ("--ours", 7, true),
    ] {
        let t = Temp::new();
        t.stage("stable.wasm", &wasm(8));
        t.write("stable.wasm", b"dirty regular image");
        t.seed("a.wasm", mask);
        t.write("a.wasm", b"dirty unmerged image");
        let index = t.index();
        ok(&["restore", t.root(), mode, "--", "."], None);
        assert_eq!(fs::read(t.path("stable.wasm")).unwrap(), wasm(8));
        assert_eq!(fs::read(t.path("a.wasm")).ok(), present.then(|| wasm(2)));
        assert_eq!(t.index(), index);
    }
}

#[test]
fn ignore_unmerged_preserves_conflict_edits_and_all_index_metadata() {
    let t = Temp::new();
    t.stage("stable.wasm", &wasm(8));
    t.write("stable.wasm", b"raw regular edit");
    t.seed("a.wasm", 7);
    t.write("a.wasm", b"unfinished conflict edit");
    let mut expected = files(&t.repo);
    ok(&["restore", t.root(), "--ignore-unmerged", "--", "."], None);
    expected.insert(PathBuf::from("stable.wasm"), wasm(8));
    assert_eq!(files(&t.repo), expected);
    ok(
        &["restore", t.root(), "--ignore-unmerged", "--", "a.wasm"],
        None,
    );
    assert_eq!(files(&t.repo), expected);
    t.reject(
        &["restore", t.root(), "--ignore-unmerged", "--", "absent"],
        None,
    );
}

#[test]
fn conflict_restore_respects_skip_and_reinstates_flags_only_with_explicit_override() {
    let t = Temp::new();
    t.seed("a.wasm", 7);
    t.stage("a.wasm", &wasm(9));
    ok(
        &["update-index", t.root(), "--skip-worktree", "a.wasm"],
        None,
    );
    fs::remove_file(t.path("a.wasm")).unwrap();
    let before = files(&t.repo);
    for mode in ["--merge", "--ours", "--ignore-unmerged"] {
        ok(&["restore", t.root(), mode, "--", "a.wasm"], None);
        assert_eq!(files(&t.repo), before);
    }
    ok(
        &[
            "checkout",
            t.root(),
            "--ignore-skip-worktree-bits",
            "-m",
            "--",
            "a.wasm",
        ],
        None,
    );
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), wasm(2));
    let index: Value = serde_json::from_slice(&t.index()[9..]).unwrap();
    assert!(index.get("flags").is_none());
    assert!(index.get("resolve_undo").is_none());
    assert_eq!(ok(&["ls-files", t.root(), "-u"], None).lines().count(), 3);
}

#[test]
fn deleted_undo_names_do_not_grant_permission_to_overwrite_untracked_files() {
    let t = Temp::new();
    t.seed("revived.wasm", 7);
    t.write("revived.wasm", &wasm(9));
    ok(
        &["update-index", t.root(), "--force-remove", "revived.wasm"],
        None,
    );
    t.write("revived.wasm", b"untracked file created after resolution");
    t.reject(
        &["restore", t.root(), "--merge", "--", "revived.wasm"],
        None,
    );
    fs::remove_file(t.path("revived.wasm")).unwrap();
    ok(
        &["restore", t.root(), "--merge", "--", "revived.wasm"],
        None,
    );
    assert_eq!(fs::read(t.path("revived.wasm")).unwrap(), wasm(2));
    assert_eq!(ok(&["ls-files", t.root(), "--resolve-undo"], None), "");
}

#[test]
fn structural_merge_restore_refuses_incomplete_sides_and_side_restore_handles_both_trees() {
    let t = Temp::new();
    let ids = t.ids();
    ok(
        &["update-index", t.root(), "--index-info"],
        Some(
            format!(
                "100644 {} 2\tnode\n100644 {} 3\tnode/child.wasm\n",
                ids[0], ids[2]
            )
            .as_bytes(),
        ),
    );
    t.write("node/child.wasm", UNKNOWN);
    ok(&["rm", t.root(), "--cached", "--force", "node"], None);
    ok(&["add", t.root(), "node/child.wasm"], None);
    t.reject(
        &[
            "restore",
            t.root(),
            "--merge",
            "--",
            "node",
            ":(exclude)node/child.wasm",
        ],
        None,
    );
    t.reject(&["restore", t.root(), "--merge", "--", "node"], None);
    ok(
        &[
            "update-index",
            t.root(),
            "--unresolve",
            "node",
            "node/child.wasm",
        ],
        None,
    );
    let index = t.index();
    ok(&["checkout", t.root(), "--ours", "--", "node"], None);
    assert_eq!(fs::read(t.path("node")).unwrap(), wasm(1));
    ok(&["checkout", t.root(), "--theirs", "--", "node"], None);
    assert_eq!(fs::read(t.path("node/child.wasm")).unwrap(), UNKNOWN);
    assert_eq!(t.index(), index);
    t.write("node/untracked.txt", b"protect untracked descendant");
    t.reject(&["checkout", t.root(), "--ours", "--", "node"], None);
}

#[test]
fn conflict_restore_rejects_invalid_combinations_intents_and_index_locks_before_writes() {
    let t = Temp::new();
    t.stage("stable.wasm", &wasm(8));
    t.commit();
    t.seed("a.wasm", 7);
    t.stage("a.wasm", &wasm(9));
    for options in [
        vec!["--merge", "--ours"],
        vec!["-m", "--theirs"],
        vec!["-m", "--merge"],
        vec!["--merge", "--source", "HEAD"],
        vec!["--merge", "--staged"],
        vec!["--merge", "--output", "outside.wasm"],
        vec!["--ignore-unmerged", "--staged"],
    ] {
        let mut args = vec!["restore", t.root()];
        args.extend(options);
        args.extend(["--", "a.wasm"]);
        t.reject(&args, None);
    }
    t.reject(&["checkout", t.root(), "-m", "main"], None);
    t.reject(
        &["checkout", t.root(), "--merge", "HEAD", "--", "a.wasm"],
        None,
    );
    t.reject(&["restore", t.root(), "--merge"], None);
    t.reject(&["restore", t.root(), "--merge", "--"], None);
    t.write("intent.wasm", &wasm(4));
    ok(&["add", t.root(), "-N", "intent.wasm"], None);
    t.reject(&["restore", t.root(), "--merge", "--", "."], None);
    fs::write(t.path(".uwgit/index.lock"), b"another writer").unwrap();
    t.reject(&["restore", t.root(), "--merge", "--", "a.wasm"], None);
}

#[cfg(unix)]
#[test]
fn merge_restore_symlinks_and_special_obstructions_preserve_index_and_external_bytes() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    t.seed("a.wasm", 7);
    t.stage("a.wasm", &wasm(9));
    let outside = t.directory.join("outside.wasm");
    fs::write(&outside, b"protected external editor image").unwrap();
    fs::remove_file(t.path("a.wasm")).unwrap();
    symlink(&outside, t.path("a.wasm")).unwrap();
    t.reject(&["restore", t.root(), "--merge", "--", "a.wasm"], None);
    assert_eq!(
        fs::read(&outside).unwrap(),
        b"protected external editor image"
    );
    assert!(fs::symlink_metadata(t.path("a.wasm"))
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file(t.path("a.wasm")).unwrap();
    assert!(Command::new("mkfifo")
        .arg(t.path("a.wasm"))
        .status()
        .unwrap()
        .success());
    t.reject(&["restore", t.root(), "--merge", "--", "a.wasm"], None);
}

#[test]
fn replay_can_recreate_merge_then_abort_without_altering_the_frozen_queue() {
    let t = Temp::new();
    let head = rebase_history(&t);
    let before_rebase = t.index();
    let stopped = run(&["rebase", t.root(), "main", "--record-conflict"], None);
    assert_eq!(stopped.status.code(), Some(2));
    let stages = ok(&["ls-files", t.root(), "-u"], None);
    t.stage("a.wasm", UNKNOWN);
    let mut expected = files(&t.repo);
    ok(&["restore", t.root(), "--merge", "--", "a.wasm"], None);
    expected.insert(PathBuf::from(".uwgit/index"), t.index());
    expected.insert(PathBuf::from("a.wasm"), wasm(2));
    assert_eq!(files(&t.repo), expected);
    assert_eq!(ok(&["ls-files", t.root(), "-u"], None), stages);
    assert_eq!(ok(&["rev-parse", t.root(), "HEAD"], None), head);
    t.reject(
        &["rebase", t.root(), "--continue", "--resolved-index"],
        None,
    );
    ok(&["rebase", t.root(), "--abort"], None);
    assert_eq!(t.index(), before_rebase);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), wasm(3));
}

#[test]
fn linked_worktree_merge_restore_remains_local_and_can_continue_the_replay_queue() {
    let t = Temp::new();
    let head = rebase_history(&t);
    let linked = t.directory.join("linked");
    ok(
        &["worktree", t.root(), "add", "--detach", p(&linked), &head],
        None,
    );
    let linked_before = files(&linked);
    let stopped = run(&["rebase", t.root(), "main", "--record-conflict"], None);
    assert_eq!(stopped.status.code(), Some(2));
    t.stage("a.wasm", UNKNOWN);
    ok(&["checkout", t.root(), "-m", "--", "a.wasm"], None);
    assert_eq!(files(&linked), linked_before);
    t.stage("a.wasm", UNKNOWN);
    let done = value(&["rebase", t.root(), "--continue", "--resolved-index"]);
    assert_eq!(done["status"], "rebased");
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), UNKNOWN);
    assert_eq!(fs::read(t.path("tail.wasm")).unwrap(), wasm(4));
    assert!(!t.path(".uwgit/pending.json").exists());
    assert_eq!(files(&linked), linked_before);
    ok(&["fsck", t.root()], None);
}

#[cfg(unix)]
#[test]
fn ignored_and_unselected_conflict_symlinks_are_preserved_without_being_followed() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    t.stage("regular.wasm", &wasm(8));
    t.write("regular.wasm", b"raw dirty regular bytes");
    t.seed("ignored.wasm", 7);
    let outside = t.directory.join("protected.wasm");
    fs::write(&outside, b"external raw image").unwrap();
    symlink(&outside, t.path("ignored.wasm")).unwrap();
    let mut expected = files(&t.repo);
    ok(&["restore", t.root(), "--ignore-unmerged", "--", "."], None);
    expected.insert(PathBuf::from("regular.wasm"), wasm(8));
    assert_eq!(files(&t.repo), expected);
    t.write("regular.wasm", b"raw edit again");
    ok(&["restore", t.root(), "--ours", "--", "regular.wasm"], None);
    assert_eq!(files(&t.repo), expected);
    assert_eq!(fs::read(&outside).unwrap(), b"external raw image");
    assert!(fs::symlink_metadata(t.path("ignored.wasm"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn conflict_option_spelling_remains_literal_when_used_as_an_export_operand() {
    let t = Temp::new();
    t.stage("--ours", &wasm(8));
    let outside = t.directory.join("export.wasm");
    let before = files(&t.repo);
    ok(
        &[
            "restore",
            t.root(),
            "--file",
            "--ours",
            "--output",
            p(&outside),
        ],
        None,
    );
    assert_eq!(fs::read(outside).unwrap(), wasm(8));
    assert_eq!(files(&t.repo), before);
}
