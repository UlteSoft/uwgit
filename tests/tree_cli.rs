//! Fixed multi-module tree workflows; all fixture data stays under /tmp.
//! Modules are stored/audited, never executed. No generated or fuzz input.
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const A: &[u8] = b"\0asm\x01\0\0\0";
const B: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
const C: &[u8] = b"\0asm\x01\0\0\0\0\x02\x01x";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = PathBuf::from(format!(
            "/tmp/uwgit-tree-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        success(&["init", p.to_str().unwrap()]);
        Self(p)
    }
    fn root(&self) -> &str {
        self.0.to_str().unwrap()
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().into()
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        let p = self.0.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, bytes).unwrap();
    }
    fn commit(&self, msg: &str) -> String {
        success(&["commit", self.root(), "-m", msg]);
        success(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn entries(&self, rev: &str) -> Value {
        let info = json(&["show", self.root(), rev]);
        json(&[
            "cat-file",
            self.root(),
            "-p",
            info["tree"].as_str().unwrap(),
        ])["entries"]
            .clone()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn success(args: &[&str]) -> String {
    let out = invoke(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn failure(args: &[&str]) {
    let out = invoke(args);
    assert!(!out.status.success(), "unexpected success {args:?}");
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&success(args)).unwrap()
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for e in fs::read_dir(path).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let k = p.strip_prefix(root).unwrap().to_path_buf();
            if e.file_type().unwrap().is_dir() {
                result.insert(k, None);
                walk(root, &p, result);
            } else if e.file_type().unwrap().is_symlink() {
                result.insert(
                    k,
                    Some(
                        fs::read_link(p)
                            .unwrap()
                            .to_string_lossy()
                            .as_bytes()
                            .to_vec(),
                    ),
                );
            } else {
                result.insert(k, Some(fs::read(p).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

#[test]
fn every_export_rejects_metadata_destinations_and_preserves_repository_state() {
    let tree = Temp::new();
    tree.write("module.wasm", A);
    success(&["add", tree.root(), "module.wasm"]);
    let first = tree.commit("base module");
    tree.write("module.wasm", C);
    success(&["add", tree.root(), "module.wasm"]);
    let second = tree.commit("custom section");
    let entries = tree.entries("HEAD");
    let blob = entries["module.wasm"].as_str().unwrap();
    tree.write("module.wasm", B);
    success(&["stash", tree.root(), "push"]);
    tree.write("input-old.wasm", A);
    tree.write("input-new.wasm", C);
    let old_input = tree.path("input-old.wasm");
    let new_input = tree.path("input-new.wasm");
    let patch = tree.path("reference.patch");
    success(&["patch", &old_input, &new_input, "--output", &patch]);
    let patch_bytes = fs::read(&patch).unwrap();
    let bundle = tree.path("reference.bundle");
    success(&["bundle", tree.root(), &bundle]);
    let bundle_bytes = fs::read(&bundle).unwrap();
    let legacy = Temp::new();
    success(&["commit", legacy.root(), &old_input, "-m", "legacy module"]);
    let mut blocked_parents = vec![tree.0.join(".uwgit")];
    #[cfg(unix)]
    {
        let alias = tree.0.join("metadata-alias");
        std::os::unix::fs::symlink(tree.0.join(".uwgit"), &alias).unwrap();
        blocked_parents.push(alias);
    }
    let commands: Vec<(&str, Vec<&str>, &[u8])> = vec![
        (
            "show-tree",
            vec![
                "show",
                tree.root(),
                "HEAD",
                "--file",
                "module.wasm",
                "--output",
            ],
            C,
        ),
        (
            "checkout-tree",
            vec!["checkout", tree.root(), "HEAD", "--file", "module.wasm"],
            C,
        ),
        (
            "restore",
            vec![
                "restore",
                tree.root(),
                "--source",
                "HEAD",
                "--file",
                "module.wasm",
                "--output",
            ],
            C,
        ),
        (
            "stash",
            vec!["stash", tree.root(), "apply", "0", "--output"],
            B,
        ),
        (
            "cat-file",
            vec!["cat-file", tree.root(), blob, "--output"],
            C,
        ),
        (
            "show-legacy",
            vec!["show", legacy.root(), "HEAD", "--output"],
            A,
        ),
        (
            "checkout-legacy",
            vec!["checkout", legacy.root(), "HEAD"],
            A,
        ),
        ("bundle", vec!["bundle", tree.root()], &bundle_bytes),
        (
            "patch-file",
            vec!["patch", &old_input, &new_input, "--output"],
            &patch_bytes,
        ),
        (
            "apply-file",
            vec!["apply", &old_input, &patch, "--output"],
            C,
        ),
        (
            "patch-repo",
            vec![
                "patch",
                &first,
                &second,
                "--repo",
                tree.root(),
                "--file",
                "module.wasm",
                "--output",
            ],
            &patch_bytes,
        ),
        (
            "apply-repo",
            vec![
                "apply",
                &first,
                &patch,
                "--repo",
                tree.root(),
                "--file",
                "module.wasm",
                "--output",
            ],
            C,
        ),
    ];
    for (label, prefix, expected) in commands {
        let before = snapshot(&tree.0);
        let legacy_before = snapshot(&legacy.0);
        for parent in &blocked_parents {
            let destination = parent.join("index.lock");
            let mut args = prefix.clone();
            args.push(destination.to_str().unwrap());
            let output = invoke(&args);
            assert!(
                !output.status.success(),
                "{label}: unexpected export to {destination:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("output must be outside repository metadata"),
                "{label}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(snapshot(&tree.0), before, "{label}: tree state changed");
            assert_eq!(
                snapshot(&legacy.0),
                legacy_before,
                "{label}: legacy state changed"
            );
        }
        let metadata_before = snapshot(&tree.0.join(".uwgit"));
        let destination = tree.path(&format!("export-{label}"));
        let mut args = prefix;
        args.push(&destination);
        success(&args);
        assert_eq!(
            fs::read(destination).unwrap(),
            expected,
            "{label}: wrong export"
        );
        assert_eq!(snapshot(&tree.0.join(".uwgit")), metadata_before);
        assert_eq!(snapshot(&legacy.0), legacy_before);
        assert_eq!(fs::read(tree.path("module.wasm")).unwrap(), C);
    }
    success(&["status", tree.root()]);
    success(&["fsck", tree.root()]);
    success(&["fsck", legacy.root()]);
}

#[test]
fn path_delimiters_keep_flag_shaped_filenames_literal_across_tree_commands() {
    for path in ["--help", "-h", "--cached", "--source"] {
        let t = Temp::new();
        t.write(path, A);
        success(&["add", t.root(), "--", path]);
        let first = t.commit("literal flag path");
        assert_eq!(success(&["ls-files", t.root()]).trim(), path);
        t.write(path, B);
        success(&["add", t.root(), "--", path]);
        t.write(path, C);
        let index = fs::read(t.path(".uwgit/index")).unwrap();
        success(&["mv", t.root(), "--", path, "moved.wasm"]);
        assert!(!Path::new(&t.path(path)).exists());
        assert_eq!(fs::read(t.path("moved.wasm")).unwrap(), C);
        let staged_output = t.path("staged-export.wasm");
        success(&[
            "restore",
            t.root(),
            "--output",
            &staged_output,
            "--",
            "moved.wasm",
        ]);
        assert_eq!(fs::read(staged_output).unwrap(), B);
        success(&["mv", t.root(), "--", "moved.wasm", path]);
        assert_eq!(fs::read(t.path(path)).unwrap(), C);
        assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
        success(&["restore", t.root(), "--", path]);
        assert_eq!(fs::read(t.path(path)).unwrap(), B);
        success(&["restore", t.root(), "--source", &first, "--", path]);
        assert_eq!(fs::read(t.path(path)).unwrap(), A);
        assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index);
        success(&[
            "restore",
            t.root(),
            "--source",
            &first,
            "--staged",
            "--worktree",
            "--",
            path,
        ]);
        success(&["rm", t.root(), "--cached", "--", path]);
        assert_eq!(fs::read(t.path(path)).unwrap(), A);
        assert_eq!(success(&["ls-files", t.root()]).trim(), "");
        success(&["restore", t.root(), "--staged", "--", path]);
        assert_eq!(success(&["ls-files", t.root()]).trim(), path);
        t.write("obstruction.wasm", C);
        let before = snapshot(&t.0);
        failure(&["mv", t.root(), "--", path, "obstruction.wasm"]);
        assert_eq!(snapshot(&t.0), before);
        failure(&["mv", t.root(), "--", path, ".uwgit/index.lock"]);
        assert_eq!(snapshot(&t.0), before);
        success(&["rm", t.root(), "--", path]);
        assert!(!Path::new(&t.path(path)).exists());
        assert_eq!(fs::read(t.path("obstruction.wasm")).unwrap(), C);
        assert_eq!(success(&["ls-files", t.root()]).trim(), "");
        let removed = json(&["status", t.root()]);
        assert_eq!(removed["files"][0]["path"], path);
        assert_eq!(removed["files"][0]["staged"], "deleted");
        assert_eq!(removed["files"][0]["worktree"], "clean");
    }
}

#[test]
fn help_before_path_delimiter_returns_without_opening_repository() {
    let t = Temp::new();
    let prospective = t.path("must-not-be-created");
    let before = snapshot(&t.0);
    for args in [
        vec!["add", prospective.as_str(), "--help", "--", "--cached"],
        vec!["rm", prospective.as_str(), "-h", "--", "--source"],
        vec!["mv", prospective.as_str(), "--help", "--", "old", "new"],
        vec!["restore", prospective.as_str(), "-h", "--", "--source"],
    ] {
        assert!(success(&args).contains("tree commands:"));
        assert!(!Path::new(&prospective).exists());
        assert_eq!(snapshot(&t.0), before);
    }
}

#[test]
fn add_accumulates_raw_files_and_mv_versions_the_path() {
    let t = Temp::new();
    t.write("a.wasm", A);
    t.write("nested/b.wasm", B);
    success(&["add", t.root(), "a.wasm"]);
    success(&["add", t.root(), "nested/b.wasm"]);
    assert_eq!(
        success(&["ls-files", t.root()]).trim(),
        "a.wasm\nnested/b.wasm"
    );
    let first = t.commit("two raw modules");
    let entries = t.entries(&first);
    assert_eq!(entries.as_object().unwrap().len(), 2);
    assert_eq!(json(&["show", t.root(), "HEAD"])["format"], 2);
    let raw = t.path("raw.wasm");
    success(&[
        "cat-file",
        t.root(),
        entries["nested/b.wasm"].as_str().unwrap(),
        "--output",
        &raw,
    ]);
    assert_eq!(fs::read(raw).unwrap(), B);
    success(&["mv", t.root(), "nested/b.wasm", "renamed/b.wasm"]);
    let second = t.commit("version path rename");
    assert_ne!(first, second);
    let entries = t.entries("HEAD");
    assert!(entries.get("nested/b.wasm").is_none());
    assert!(entries.get("renamed/b.wasm").is_some());
    assert!(entries.get("a.wasm").is_some());
    assert_eq!(fs::read(t.path("renamed/b.wasm")).unwrap(), B);
}

#[test]
fn final_deletion_and_initial_allow_empty_create_real_empty_trees() {
    let t = Temp::new();
    success(&["commit", t.root(), "--allow-empty", "-m", "empty root"]);
    assert_eq!(t.entries("HEAD"), serde_json::json!({}));
    t.write("a.wasm", A);
    t.write("b.wasm", B);
    success(&["add", t.root(), "a.wasm", "b.wasm"]);
    t.commit("files");
    success(&["rm", t.root(), "a.wasm", "b.wasm"]);
    let empty = t.commit("remove all files");
    assert!(fs::read(t.path(".uwgit/index"))
        .unwrap()
        .starts_with(b"UWGITIDX\x02"));
    assert_eq!(t.entries("HEAD"), serde_json::json!({}));
    success(&["reset", t.root(), "--hard", "HEAD~1"]);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), A);
    assert_eq!(fs::read(t.path("b.wasm")).unwrap(), B);
    success(&["reset", t.root(), "--hard", &empty]);
    assert!(!Path::new(&t.path("a.wasm")).exists());
    assert!(!Path::new(&t.path("b.wasm")).exists());
    failure(&["commit", t.root(), "-m", "unchanged empty"]);
}

#[test]
fn batch_stage_remove_and_late_restore_conflicts_do_not_partially_write() {
    let t = Temp::new();
    t.write("a.wasm", A);
    t.write("z.wasm", B);
    success(&["add", t.root(), "a.wasm", "z.wasm"]);
    let base = t.commit("base");
    success(&["branch", t.root(), "base"]);
    t.write("a.wasm", C);
    t.write("later/new.wasm", B);
    success(&["add", t.root(), "a.wasm", "later/new.wasm"]);
    t.commit("target");
    success(&["branch", t.root(), "target"]);
    success(&["reset", t.root(), "--hard", &base]);
    t.write("later/new.wasm", A);
    let before = snapshot(&t.0);
    for args in [
        vec!["add", t.root(), "a.wasm", "../outside.wasm"],
        vec!["rm", t.root(), "a.wasm", "not-tracked.wasm"],
        vec!["restore", t.root(), "--source", "target"],
        vec!["reset", t.root(), "--hard", "target"],
        vec!["switch", t.root(), "target"],
    ] {
        failure(&args);
        assert_eq!(snapshot(&t.0), before);
    }
    fs::remove_file(t.path("later/new.wasm")).unwrap();
    success(&["switch", t.root(), "target"]);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), C);
    assert_eq!(fs::read(t.path("later/new.wasm")).unwrap(), B);
}

#[test]
fn restore_subset_and_staged_only_preserve_other_dirty_worktree_bytes() {
    let t = Temp::new();
    t.write("a.wasm", A);
    t.write("b.wasm", B);
    success(&["add", t.root(), "a.wasm", "b.wasm"]);
    t.commit("base");
    t.write("a.wasm", C);
    t.write("b.wasm", C);
    success(&["restore", t.root(), "a.wasm"]);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), A);
    assert_eq!(fs::read(t.path("b.wasm")).unwrap(), C);
    success(&["add", t.root(), "b.wasm"]);
    success(&["restore", t.root(), "--staged", "b.wasm"]);
    assert_eq!(fs::read(t.path("b.wasm")).unwrap(), C);
    let s = json(&["status", t.root()]);
    let row = s["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"] == "b.wasm")
        .unwrap();
    assert_eq!(row["staged"], "clean");
    assert_eq!(row["worktree"], "modified");
}

#[test]
fn stash_restores_add_delete_and_dirty_files_and_late_conflict_keeps_everything() {
    let t = Temp::new();
    t.write("a.wasm", A);
    t.write("z.wasm", A);
    success(&["add", t.root(), "a.wasm", "z.wasm"]);
    t.commit("base");
    t.write("a.wasm", B);
    t.write("new.wasm", C);
    success(&["add", t.root(), "a.wasm", "new.wasm"]);
    success(&["rm", t.root(), "z.wasm"]);
    t.write("a.wasm", b"unfinished\0\xff");
    success(&["stash", t.root(), "push"]);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), A);
    assert_eq!(fs::read(t.path("z.wasm")).unwrap(), A);
    assert!(!Path::new(&t.path("new.wasm")).exists());
    success(&["stash", t.root(), "apply", "0"]);
    assert_eq!(fs::read(t.path("a.wasm")).unwrap(), b"unfinished\0\xff");
    assert_eq!(fs::read(t.path("new.wasm")).unwrap(), C);
    assert!(!Path::new(&t.path("z.wasm")).exists());
    success(&["reset", t.root(), "--hard"]);
    t.write("z.wasm", B);
    success(&["add", t.root(), "z.wasm"]);
    t.commit("later conflicting file");
    let before = snapshot(&t.0);
    failure(&["stash", t.root(), "pop", "0"]);
    assert_eq!(snapshot(&t.0), before);
    assert_eq!(json(&["stash", t.root(), "list"])[0]["id"], 0);
}

#[test]
fn v1_binary_index_and_explicit_first_add_anchor_promote_without_guessing_names() {
    let t = Temp::new();
    let input = t.path("input.wasm");
    fs::write(&input, A).unwrap();
    success(&["commit", t.root(), &input, "-m", "legacy raw"]);
    let old = success(&["rev-parse", t.root(), "HEAD"]).trim().to_owned();
    assert_eq!(json(&["status", t.root()])["legacy_head_unmapped"], true);
    let clone = t.path("clone");
    success(&["clone", t.root(), &clone]);
    assert_eq!(success(&["ls-files", &clone]).trim(), "");
    let path = "chosen/old.wasm";
    t.write(path, A);
    let mut bytes = b"UWGITIDX\x01".to_vec();
    bytes.extend_from_slice(&(path.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(A.len() as u64).to_le_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(A);
    fs::write(t.path(".uwgit/index"), bytes).unwrap();
    assert_eq!(json(&["status", t.root()])["staged"], false);
    let promoted = t.commit("explicit v1 filename");
    assert_ne!(promoted, old);
    assert_eq!(json(&["show", t.root(), "HEAD"])["legacy_path"], path);
    assert_eq!(json(&["show", t.root(), &old])["format"], 1);
    t.write("another.wasm", B);
    success(&["add", t.root(), "another.wasm"]);
    t.commit("second module");
    assert_eq!(t.entries("HEAD").as_object().unwrap().len(), 2);
    let export = t.path("legacy-output.wasm");
    success(&["checkout", t.root(), &old, &export]);
    assert_eq!(fs::read(export).unwrap(), A);
}

#[test]
fn restore_retains_explicit_v1_anchor_and_rejects_other_tree_anchor_before_writes() {
    let legacy = Temp::new();
    let input = legacy.path("raw-input.wasm");
    fs::write(&input, A).unwrap();
    success(&["commit", legacy.root(), &input, "-m", "unnamed original"]);
    let original = success(&["rev-parse", legacy.root(), "HEAD"])
        .trim()
        .to_owned();
    let chosen = "chosen/original.wasm";
    legacy.write(chosen, A);
    success(&["add", legacy.root(), chosen]);

    let pure = Temp::new();
    pure.write("replacement.wasm", B);
    success(&["add", pure.root(), "replacement.wasm"]);
    pure.commit("independent named tree without legacy anchor");
    assert!(json(&["show", pure.root(), "HEAD"])["legacy_path"].is_null());
    let bundle = pure.path("pure.uwgb");
    success(&["bundle", pure.root(), &bundle]);
    success(&["unbundle", legacy.root(), &bundle, "pure"]);

    for both in [false, true] {
        if both {
            success(&["reset", legacy.root(), "--mixed", &original]);
        }
        let mut args = vec!["restore", legacy.root(), "--source", "pure", "--staged"];
        if both {
            args.push("--worktree");
        }
        success(&args);
        let encoded = fs::read(legacy.path(".uwgit/index")).unwrap();
        let index: Value =
            serde_json::from_slice(encoded.strip_prefix(b"UWGITIDX\x02").unwrap()).unwrap();
        assert_eq!(index["legacy_path"], chosen);
        let status = json(&["status", legacy.root()]);
        assert_eq!(status["legacy_head_unmapped"], false);
        legacy.commit(if both {
            "restore both and upgrade"
        } else {
            "restore staged and upgrade"
        });
        assert_eq!(
            json(&["show", legacy.root(), "HEAD"])["legacy_path"],
            chosen
        );
        assert_eq!(legacy.entries("HEAD").as_object().unwrap().len(), 1);
        if both {
            assert_eq!(fs::read(legacy.path("replacement.wasm")).unwrap(), B);
            assert!(!Path::new(&legacy.path(chosen)).exists());
        }
    }

    let other = Temp::new();
    let input = other.path("other-raw.wasm");
    fs::write(&input, A).unwrap();
    success(&[
        "commit",
        other.root(),
        &input,
        "-m",
        "other unnamed original",
    ]);
    other.write("different/original.wasm", A);
    success(&["add", other.root(), "different/original.wasm"]);
    other.commit("different explicit anchor");
    let bundle = other.path("other.uwgb");
    success(&["bundle", other.root(), &bundle]);
    success(&["unbundle", legacy.root(), &bundle, "other-anchor"]);
    let before = snapshot(&legacy.0);
    for flags in [vec![], vec!["--staged"], vec!["--staged", "--worktree"]] {
        let mut args = vec!["restore", legacy.root(), "--source", "other-anchor"];
        args.extend(flags);
        failure(&args);
        assert_eq!(snapshot(&legacy.0), before);
    }
}

#[test]
fn explicit_restore_file_selects_index_even_when_path_is_also_a_branch_name() {
    for multiple in [false, true] {
        let t = Temp::new();
        let path = "main.wasm";
        t.write(path, A);
        success(&["add", t.root(), path]);
        if multiple {
            t.write("other.wasm", C);
            success(&["add", t.root(), "other.wasm"]);
        }
        let base = t.commit("base bytes and a same-named ref");
        success(&["branch", t.root(), path]);
        t.write(path, B);
        success(&["add", t.root(), path]);
        let index_before = fs::read(t.path(".uwgit/index")).unwrap();
        let output = t.path("index-export.wasm");
        success(&["restore", t.root(), "--file", path, "--output", &output]);
        assert_eq!(fs::read(&output).unwrap(), B);
        let literal_output = t.path("literal-index-export.wasm");
        success(&["restore", t.root(), "--output", &literal_output, "--", path]);
        assert_eq!(fs::read(literal_output).unwrap(), B);
        assert_eq!(fs::read(t.path(path)).unwrap(), B);
        assert_eq!(fs::read(t.path(".uwgit/index")).unwrap(), index_before);
        assert_eq!(success(&["rev-parse", t.root(), "HEAD"]).trim(), base);
        let legacy_output = t.path("revision-export.wasm");
        if multiple {
            let before = snapshot(&t.0);
            failure(&["restore", t.root(), path, "--output", &legacy_output]);
            assert_eq!(snapshot(&t.0), before);
        } else {
            success(&["restore", t.root(), path, "--output", &legacy_output]);
            assert_eq!(fs::read(legacy_output).unwrap(), A);
        }
    }
}

#[test]
fn explicit_add_after_soft_reset_to_v1_anchors_without_dropping_other_staged_files() {
    let tree = Temp::new();
    tree.write("chosen.wasm", A);
    tree.write("retained.wasm", B);
    success(&["add", tree.root(), "chosen.wasm", "retained.wasm"]);
    tree.commit("independent pure tree");

    let legacy = Temp::new();
    let input = legacy.path("input.wasm");
    fs::write(&input, C).unwrap();
    success(&[
        "commit",
        legacy.root(),
        &input,
        "-m",
        "unnamed prior history",
    ]);
    let old = success(&["rev-parse", legacy.root(), "HEAD"])
        .trim()
        .to_owned();
    let bundle = legacy.path("legacy.uwgb");
    success(&["bundle", legacy.root(), &bundle]);
    success(&["unbundle", tree.root(), &bundle, "old"]);
    success(&["reset", tree.root(), "--soft", "old"]);

    let before = snapshot(&tree.0);
    let status = json(&["status", tree.root()]);
    assert_eq!(status["legacy_head_unmapped"], true);
    assert_eq!(status["head"], old);
    assert_eq!(status["files"].as_array().unwrap().len(), 2);
    failure(&["diff", tree.root(), "--cached", "--format", "json"]);
    assert_eq!(snapshot(&tree.0), before);

    // The explicit add chooses only the old module's path; it must preserve
    // retained.wasm already staged by the previous complete tree.
    success(&["add", tree.root(), "chosen.wasm"]);
    assert_eq!(
        json(&["status", tree.root()])["legacy_head_unmapped"],
        false
    );
    assert_eq!(
        success(&["ls-files", tree.root()]).trim(),
        "chosen.wasm\nretained.wasm"
    );
    tree.commit("explicit mapping after soft reset");
    let info = json(&["show", tree.root(), "HEAD"]);
    assert_eq!(info["legacy_path"], "chosen.wasm");
    assert_eq!(info["parents"], serde_json::json!([old]));
    let entries = tree.entries("HEAD");
    assert_eq!(entries.as_object().unwrap().len(), 2);
    for (path, expected) in [("chosen.wasm", A), ("retained.wasm", B)] {
        let destination = tree.path(&format!("export-{path}"));
        success(&[
            "cat-file",
            tree.root(),
            entries[path].as_str().unwrap(),
            "--output",
            &destination,
        ]);
        assert_eq!(fs::read(destination).unwrap(), expected);
    }
    let destination = tree.path("original-v1.wasm");
    success(&["checkout", tree.root(), &old, &destination]);
    assert_eq!(fs::read(destination).unwrap(), C);
}

#[test]
fn status_scans_only_regular_untracked_wasm_and_diff_retains_add_delete_bytes() {
    let t = Temp::new();
    t.write("a.wasm", A);
    t.write("b.wasm", B);
    t.write("readme.txt", b"not wasm");
    success(&["add", t.root(), "a.wasm"]);
    t.commit("one");
    assert_eq!(
        json(&["status", t.root()])["untracked"],
        serde_json::json!(["b.wasm"])
    );
    success(&["add", t.root(), "b.wasm"]);
    success(&["rm", t.root(), "a.wasm"]);
    let diff = json(&["diff", t.root(), "--cached", "--format", "json"]);
    assert_eq!(diff["kind"], "tree_diff");
    assert_eq!(diff["summary"]["added"], 1);
    assert_eq!(diff["summary"]["deleted"], 1);
    let rows = diff["files"].as_array().unwrap();
    for (path, side, bytes) in [("a.wasm", "old", A), ("b.wasm", "new", B)] {
        let row = rows.iter().find(|r| r["path"] == path).unwrap();
        assert_eq!(row["content"]["side"], side);
        assert_eq!(row["content"]["byte_len"], bytes.len());
        assert_eq!(
            row["content"]["hex"],
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
}

#[test]
fn corrupt_v2_index_paths_duplicates_and_unknown_fields_are_never_silently_repaired() {
    let t = Temp::new();
    t.write("a.wasm", A);
    success(&["add", t.root(), "a.wasm"]);
    t.commit("base");
    for payload in [
        r#"{"format":2,"files":{"../bad":[0,97,115,109,1,0,0,0]},"legacy_path":null}"#,
        r#"{"format":2,"files":{},"legacy_path":null,"unknown":true}"#,
        r#"{"format":2,"files":{"a.wasm":[0,97,115,109,1,0,0,0],"a.wasm":[0,97,115,109,1,0,0,0]},"legacy_path":null}"#,
    ] {
        let mut bytes = b"UWGITIDX\x02".to_vec();
        bytes.extend_from_slice(payload.as_bytes());
        bytes.push(b'\n');
        fs::write(t.path(".uwgit/index"), bytes).unwrap();
        let before = snapshot(&t.0);
        failure(&["add", t.root(), "a.wasm"]);
        failure(&["status", t.root()]);
        assert_eq!(snapshot(&t.0), before);
    }
}
