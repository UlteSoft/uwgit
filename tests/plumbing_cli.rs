use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-plumbing-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        ok(&["init", path(&root)], None);
        Self(root)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}
fn execute(args: &[&str], input: Option<&[u8]>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
fn ok(args: &[&str], input: Option<&[u8]>) -> String {
    let output = execute(args, input);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_owned()
}
fn fail(args: &[&str], input: Option<&[u8]>) {
    let output = execute(args, input);
    assert!(!output.status.success(), "unexpected success: {args:?}");
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}
fn files(root: &Path) -> usize {
    fs::read_dir(root.join(".uwgit/objects")).unwrap().count()
}
fn blob(root: &Path, value: u8) -> String {
    ok(
        &["hash-object", path(root), "-w", "--stdin"],
        Some(&wasm(value)),
    )
}
fn tree(root: &Path, blob: &str) -> String {
    ok(
        &["mktree", path(root)],
        Some(format!("100644 wasm {blob}\ta.wasm\n").as_bytes()),
    )
}
fn commit(root: &Path, tree: &str, parent: Option<&str>, message: &str) -> String {
    let mut args = vec!["commit-tree", path(root), tree, "-m", message];
    if let Some(parent) = parent {
        args.extend(["-p", parent]);
    }
    ok(&args, None)
}

fn three_index_trees(root: &Path) -> (String, String, String, [String; 3]) {
    let blobs = [blob(root, 1), blob(root, 2), blob(root, 3)];
    let trees = blobs.iter().map(|id| tree(root, id)).collect::<Vec<_>>();
    (trees[0].clone(), trees[1].clone(), trees[2].clone(), blobs)
}

#[test]
fn ls_files_filters_original_images_work_changes_ignores_and_structural_obstructions() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let id = blob(root, 1);
    ok(
        &["update-index", r, "--index-info"],
        Some(format!("100644 {id}\ta.wasm\n100644 {id}\tb.wasm\n").as_bytes()),
    );
    fs::write(root.join("a.wasm"), wasm(2)).unwrap();
    fs::write(root.join("other.txt"), b"raw untracked bytes").unwrap();
    fs::write(root.join("ignored.log"), b"log").unwrap();
    fs::write(root.join(".gitignore"), "*.log\nb.wasm\nblocked/\n").unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/.uwgitignore"), "*.tmp\n!keep.tmp\n").unwrap();
    fs::write(root.join("nested/ignored.tmp"), b"ignore").unwrap();
    fs::write(root.join("nested/keep.tmp"), b"keep").unwrap();
    fs::create_dir(root.join("blocked")).unwrap();
    fs::write(root.join("blocked/.gitignore"), "!keep.txt\n").unwrap();
    fs::write(root.join("blocked/keep.txt"), b"parent exclusion wins").unwrap();
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    assert_eq!(ok(&["ls-files", r, "-m"], None), "a.wasm\nb.wasm");
    assert_eq!(ok(&["ls-files", r, "-d", "-t"], None), "R b.wasm");
    assert_eq!(
        ok(&["ls-files", r, "-d", "-m"], None),
        "a.wasm\nb.wasm\nb.wasm"
    );
    assert_eq!(
        ok(&["ls-files", r, "-d", "-m", "--deduplicate"], None),
        "a.wasm\nb.wasm"
    );
    assert_eq!(
        ok(&["ls-files", r, "-i", "-c", "--exclude-standard"], None),
        "b.wasm"
    );
    let ignored = ok(&["ls-files", r, "-i", "-o", "--exclude-standard"], None);
    assert_eq!(
        ignored,
        "blocked/.gitignore\nblocked/keep.txt\nignored.log\nnested/ignored.tmp"
    );
    let others = ok(&["ls-files", r, "-o", "--exclude-standard"], None);
    assert_eq!(
        others,
        ".gitignore\nnested/.uwgitignore\nnested/keep.tmp\nother.txt"
    );
    assert_eq!(
        ok(&["ls-files", r, "-i", "-o", "-x", "*.txt"], None),
        "blocked/keep.txt\nother.txt"
    );
    // Query selectors are permissive by default; strict mode checks the index.
    assert_eq!(ok(&["ls-files", r, "--", "unknown.wasm"], None), "");
    fail(&["ls-files", r, "--error-unmatch", "--", "other.txt"], None);
    fail(&["ls-files", r, "-i", "-o"], None);
    fs::remove_file(root.join("a.wasm")).unwrap();
    fs::create_dir(root.join("a.wasm")).unwrap();
    fs::write(root.join("a.wasm/obstruction.txt"), b"retain").unwrap();
    assert_eq!(
        ok(&["ls-files", r, "-k", "-t"], None),
        "K a.wasm/obstruction.txt"
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
}

#[test]
fn ls_files_formats_and_custom_exclude_sources_remain_read_only() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let id = blob(root, 1);
    ok(
        &["update-index", r, "--index-info"],
        Some(format!("100644 {id}\ta.wasm\n").as_bytes()),
    );
    fs::write(root.join("a.wasm"), wasm(1)).unwrap();
    fs::write(root.join("one.txt"), b"one").unwrap();
    fs::write(root.join("rules.ignore"), "*.txt\n").unwrap();
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    let formatted = execute(&["ls-files",r,"--format=%(objectmode) %(objecttype) %(objectname) %(stage) %(objectsize)%x09%(path)%%","-z"],None);
    assert!(formatted.status.success());
    assert_eq!(
        formatted.stdout,
        format!("100644 wasm {id} 0 {}\ta.wasm%\0", wasm(1).len()).into_bytes()
    );
    assert_eq!(
        ok(
            &[
                "ls-files",
                r,
                "-i",
                "-o",
                "-X",
                path(&root.join("rules.ignore"))
            ],
            None
        ),
        "one.txt"
    );
    assert_eq!(
        ok(
            &[
                "ls-files",
                r,
                "-i",
                "-o",
                "--exclude-per-directory",
                "rules.ignore"
            ],
            None
        ),
        "one.txt"
    );
    for field in ["%(invented)", "%xzz", "%xFF", "%(path", "%"] {
        fail(&["ls-files", r, &format!("--format={field}")], None);
    }
    fail(&["ls-files", r, "--format=%(path)", "--others"], None);
    fail(
        &["ls-files", r, "--exclude-per-directory", "../outside"],
        None,
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(1));
}

#[test]
fn checkout_index_materializes_exact_images_with_complete_preflight_and_no_index_changes() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let one = blob(root, 1);
    let two = blob(root, 2);
    ok(
        &["update-index", r, "--index-info"],
        Some(format!("100644 {one}\ta.wasm\n100644 {two}\tb.wasm\n").as_bytes()),
    );
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    ok(&["checkout-index", r], None);
    assert!(!root.join("a.wasm").exists());
    fs::write(root.join("a.wasm"), b"editor bytes").unwrap();
    fail(&["checkout-index", r, "--all"], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), b"editor bytes");
    assert!(!root.join("b.wasm").exists());
    ok(&["checkout-index", r, "-a", "-f", "--dry-run"], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), b"editor bytes");
    ok(&["checkout-index", r, "-a", "-f", "-n"], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(1));
    assert!(!root.join("b.wasm").exists());
    ok(&["checkout-index", r, "-a", "--prefix", "export/"], None);
    assert_eq!(fs::read(root.join("export/a.wasm")).unwrap(), wasm(1));
    assert_eq!(fs::read(root.join("export/b.wasm")).unwrap(), wasm(2));
    fail(
        &["checkout-index", r, "-a", "--prefix", "../escaped/"],
        None,
    );
    fs::create_dir(root.join(".git")).unwrap();
    fs::write(root.join(".git/a.wasm"), b"foreign metadata").unwrap();
    fail(&["checkout-index", r, "-a", "-f", "--prefix=.git/"], None);
    assert_eq!(
        fs::read(root.join(".git/a.wasm")).unwrap(),
        b"foreign metadata"
    );
    assert!(!root.join(".git/b.wasm").exists());
    ok(&["checkout-index", r, "--stdin", "-z"], Some(b"b.wasm\0"));
    assert_eq!(fs::read(root.join("b.wasm")).unwrap(), wasm(2));
    ok(
        &["checkout-index", r, "-q", "--", "unknown.wasm", "a.wasm"],
        None,
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), b"main\n");
}

#[test]
fn checkout_index_temporary_stages_export_original_bytes_and_absent_sides() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let one = blob(root, 1);
    let two = blob(root, 2);
    ok(
        &["update-index", r, "--index-info"],
        Some(
            format!("100644 {one} 1\ta.wasm\n100644 {two} 3\ta.wasm\n100644 {one}\tb.wasm\n")
                .as_bytes(),
        ),
    );
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    let inventory = || fs::read_dir(root).unwrap().count();
    let initial = inventory();
    fail(
        &[
            "checkout-index",
            r,
            "--temp",
            "--",
            "b.wasm",
            "unknown.wasm",
        ],
        None,
    );
    assert_eq!(inventory(), initial);
    ok(
        &["checkout-index", r, "--stage=all", "-a", "--dry-run"],
        None,
    );
    assert_eq!(inventory(), initial);
    let output = execute(&["checkout-index", r, "--stage=all", "-a", "-z"], None);
    assert!(output.status.success());
    assert_eq!(output.stdout.last(), Some(&0));
    let line = std::str::from_utf8(&output.stdout[..output.stdout.len() - 1]).unwrap();
    let (names, path) = line.split_once('\t').unwrap();
    assert_eq!(path, "a.wasm");
    let names: Vec<_> = names.split(' ').collect();
    assert_eq!(names.len(), 3);
    assert_eq!(names[1], ".");
    assert_eq!(fs::read(root.join(names[0])).unwrap(), wasm(1));
    assert_eq!(fs::read(root.join(names[2])).unwrap(), wasm(2));
    assert!(!root.join("a.wasm").exists());
    fail(&["checkout-index", r, "--stage=2", "--", "a.wasm"], None);
    ok(&["checkout-index", r, "--stage=3", "--", "a.wasm"], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn checkout_index_rejects_symlinks_and_unselected_directory_obstructions_even_with_force() {
    use std::os::unix::fs::symlink;
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let one = blob(root, 1);
    ok(
        &["update-index", r, "--index-info"],
        Some(format!("100644 {one}\ta.wasm\n100644 {one}\tb.wasm\n").as_bytes()),
    );
    fs::create_dir(root.join("b.wasm")).unwrap();
    fs::write(root.join("b.wasm/keep"), b"retain").unwrap();
    fail(&["checkout-index", r, "-a", "-f"], None);
    assert!(!root.join("a.wasm").exists());
    assert_eq!(fs::read(root.join("b.wasm/keep")).unwrap(), b"retain");
    fs::remove_file(root.join("b.wasm/keep")).unwrap();
    fs::remove_dir(root.join("b.wasm")).unwrap();
    symlink(root.join("a.wasm"), root.join("b.wasm")).unwrap();
    fail(&["checkout-index", r, "-a", "-f"], None);
    assert!(!root.join("a.wasm").exists());
    assert!(fs::symlink_metadata(root.join("b.wasm"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn unresolved_index_cannot_be_used_as_a_complete_manual_history_resolution() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let (base, ours, theirs, _) = three_index_trees(root);
    ok(&["read-tree", r, &base], None);
    ok(&["commit", r, "-m", "base"], None);
    let ancestor = ok(&["rev-parse", r, "HEAD"], None);
    let target = commit(root, &theirs, Some(&ancestor), "other side");
    ok(&["read-tree", r, &ours], None);
    ok(&["commit", r, "-m", "our side"], None);
    let head = ok(&["rev-parse", r, "HEAD"], None);
    ok(&["read-tree", r, "-m", &base, &ours, &theirs], None);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    let objects = files(root);
    for command in ["merge", "cherry-pick", "revert"] {
        fail(
            &[
                command,
                r,
                &target,
                "--resolved-index",
                "--expect-head",
                &head,
                "-m",
                "must remain unresolved",
            ],
            None,
        );
        assert_eq!(ok(&["rev-parse", r, "HEAD"], None), head);
        assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
        assert_eq!(files(root), objects);
    }
    // Saved stashes are complete snapshots. A canonical but unmerged saved
    // index must not be read as an empty resolved tree by list/apply.
    let payload = std::str::from_utf8(&before[9..]).unwrap().trim_end();
    let saved = format!("{{\"format\":2,\"next_id\":1,\"entries\":[{{\"id\":0,\"message\":\"unmerged\",\"base\":\"{head}\",\"index\":{payload},\"worktree\":{{}}}}]}}\n");
    fs::write(root.join(".uwgit/stash"), saved).unwrap();
    fail(&["stash", r, "list"], None);
    fail(&["stash", r, "apply", "0"], None);
    assert_eq!(ok(&["rev-parse", r, "HEAD"], None), head);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
}

#[test]
fn directory_file_conflicts_keep_side_images_and_restore_without_losing_unrelated_work() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let one = blob(root, 1);
    let two = blob(root, 2);
    let empty = ok(&["mktree", r], Some(b""));
    let ours = ok(
        &["mktree", r],
        Some(format!("100644 wasm {one}\tmodule\n").as_bytes()),
    );
    let theirs = ok(
        &["mktree", r],
        Some(format!("100644 wasm {two}\tmodule/child.wasm\n").as_bytes()),
    );
    ok(&["read-tree", r, &ours], None);
    fs::write(root.join("module"), wasm(1)).unwrap();
    ok(&["read-tree", r, "-m", "-u", &empty, &ours, &theirs], None);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    assert_eq!(
        ok(&["ls-files", r, "-u"], None),
        format!("100644 {one} 2\tmodule\n100644 {two} 3\tmodule/child.wasm")
    );
    assert_eq!(fs::read(root.join("module")).unwrap(), wasm(1));
    assert_eq!(
        execute(&["merge-index", r, "--all"], None).status.code(),
        Some(2)
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    // A stage must be a valid original tree; invalid batched input is atomic.
    fail(
        &["update-index", r, "--index-info"],
        Some(format!("100644 {two} 2\tmodule/child.wasm\n").as_bytes()),
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    ok(&["restore", r, "--theirs", "--", "."], None);
    assert_eq!(fs::read(root.join("module/child.wasm")).unwrap(), wasm(2));
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    let status: Value = serde_json::from_str(&ok(&["status", r], None)).unwrap();
    assert_eq!(status["unmerged"].as_array().unwrap().len(), 2);
    ok(
        &["rm", r, "--force", "--", "module", "module/child.wasm"],
        None,
    );
    assert!(!root.join("module").exists());
    assert_eq!(ok(&["ls-files", r], None), "");
    ok(&["read-tree", r, "-m", &empty, &ours, &theirs], None);
    ok(&["restore", r, "--theirs", "--", "."], None);
    ok(&["add", r, "-A"], None);
    assert_eq!(ok(&["write-tree", r], None), theirs);

    let (_, o, t, _) = three_index_trees(root);
    ok(&["read-tree", r, "-m", &empty, &o, &t], None);
    fs::write(root.join("a.wasm"), b"unresolved editor bytes").unwrap();
    let unchanged = blob(root, 8);
    ok(
        &[
            "update-index",
            r,
            "--add",
            "--cacheinfo",
            &format!("100644,{unchanged},keep.wasm"),
        ],
        None,
    );
    fs::write(root.join("keep.wasm"), wasm(9)).unwrap();
    // Restoring a resolved path must not erase another unselected conflict.
    ok(&["restore", r, "--", "keep.wasm"], None);
    assert_eq!(
        fs::read(root.join("a.wasm")).unwrap(),
        b"unresolved editor bytes"
    );
    assert_eq!(fs::read(root.join("keep.wasm")).unwrap(), wasm(8));
}

#[test]
fn read_tree_update_preserves_unaffected_dirty_bytes_and_rejects_dirty_replacements() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let one = blob(root, 1);
    let two = blob(root, 2);
    let base = ok(
        &["mktree", r],
        Some(format!("100644 wasm {one}\ta.wasm\n100644 wasm {one}\tb.wasm\n").as_bytes()),
    );
    let target = ok(
        &["mktree", r],
        Some(format!("100644 wasm {two}\ta.wasm\n100644 wasm {one}\tb.wasm\n").as_bytes()),
    );
    ok(&["read-tree", r, &base], None);
    fs::write(root.join("a.wasm"), wasm(1)).unwrap();
    fs::write(root.join("b.wasm"), b"preserve unsaved bytes").unwrap();
    ok(&["read-tree", r, "-u", &target], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    assert_eq!(
        fs::read(root.join("b.wasm")).unwrap(),
        b"preserve unsaved bytes"
    );
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    fs::write(root.join("a.wasm"), b"do not discard").unwrap();
    fail(&["read-tree", r, "-u", &base], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), b"do not discard");
    assert_eq!(
        fs::read(root.join("b.wasm")).unwrap(),
        b"preserve unsaved bytes"
    );
}

#[test]
fn read_tree_unmerged_stages_preserve_each_original_side_until_explicit_resolution() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let (base, ours, theirs, ids) = three_index_trees(root);
    std::fs::write(root.join("a.wasm"), wasm(9)).unwrap();
    ok(&["read-tree", r, "-m", &base, &ours, &theirs], None);
    let original = fs::read(root.join(".uwgit/index")).unwrap();
    assert!(original.starts_with(b"UWGITIDX\x03"));
    let rows = ok(&["ls-files", r, "--unmerged"], None);
    for (number, id) in ids.iter().enumerate() {
        assert!(rows.contains(&format!("100644 {id} {}\ta.wasm", number + 1)));
    }
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(9));
    let objects = files(root);
    fail(&["write-tree", r], None);
    fail(
        &["commit", r, "-m", "must not publish unresolved images"],
        None,
    );
    assert_eq!(files(root), objects);
    ok(&["restore", r, "--ours", "--", "a.wasm"], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), original);
    ok(&["checkout", r, "--theirs", "--", "a.wasm"], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(3));
    fs::write(root.join("untracked.wasm"), wasm(9)).unwrap();
    ok(&["clean", r, "-f", "-x", "-d"], None);
    assert!(root.join("a.wasm").exists());
    assert!(!root.join("untracked.wasm").exists());
    let status: Value = serde_json::from_str(&ok(&["status", r], None)).unwrap();
    assert_eq!(
        status["unmerged"][0]["stages"],
        serde_json::json!([1, 2, 3])
    );
    ok(&["add", r, "a.wasm"], None);
    assert_eq!(ok(&["ls-files", r, "-u"], None), "");
    assert_eq!(ok(&["write-tree", r], None), theirs);
    ok(&["fsck", r], None);
}

#[test]
fn index_info_binary_framing_and_batch_errors_keep_index_and_work_bytes_unchanged() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let one = blob(root, 1);
    let two = blob(root, 2);
    let records = format!("100644 {one} 1\ta.wasm\0100644 wasm {two} 3\ta.wasm\0");
    ok(
        &["update-index", r, "--index-info", "-z"],
        Some(records.as_bytes()),
    );
    let output = execute(&["ls-files", r, "-s", "-z"], None);
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("100644 {one} 1\ta.wasm\0100644 {two} 3\ta.wasm\0").into_bytes()
    );
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    for records in [
        format!("100644 {one}\tb.wasm\n100644 {}\tc.wasm\n", "f".repeat(64)),
        format!("100755 {one}\tb.wasm\n"),
        format!("100644 {one} 4\ta.wasm\n"),
        "0 0 4\ta.wasm\n".into(),
        format!("100644 {one}\t../outside\n"),
    ] {
        fail(
            &["update-index", r, "--index-info"],
            Some(records.as_bytes()),
        );
        assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    }
    ok(&["update-index", r, "--index-info"], Some(b"0 0\ta.wasm\n"));
    assert_eq!(ok(&["ls-files", r], None), "");
    fs::write(root.join(".uwgit/index.lock"), b"held").unwrap();
    fail(
        &["update-index", r, "--index-info"],
        Some(format!("100644 {one}\ta.wasm\n").as_bytes()),
    );
    assert_eq!(fs::read(root.join(".uwgit/index.lock")).unwrap(), b"held");
}

#[test]
fn cacheinfo_and_update_index_use_native_images_without_touching_worktree_or_head() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    fs::write(root.join("a.wasm"), wasm(1)).unwrap();
    fail(&["update-index", r, "a.wasm"], None);
    ok(&["update-index", r, "--add", "a.wasm"], None);
    assert_eq!(files(root), 0);
    let id = blob(root, 2);
    let entry = format!("100644,{id},b.wasm");
    fail(&["update-index", r, "--cacheinfo", &entry], None);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    ok(
        &[
            "update-index",
            r,
            "--add",
            "--cacheinfo",
            &entry,
            "--dry-run",
        ],
        None,
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    ok(&["update-index", r, "--add", "--cacheinfo", &entry], None);
    assert!(!root.join("b.wasm").exists());
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(1));
    fs::remove_file(root.join("a.wasm")).unwrap();
    ok(&["update-index", r, "--remove", "a.wasm"], None);
    fs::write(root.join("b.wasm"), b"uncommitted local bytes").unwrap();
    ok(&["update-index", r, "--force-remove", "b.wasm"], None);
    assert_eq!(
        fs::read(root.join("b.wasm")).unwrap(),
        b"uncommitted local bytes"
    );
    assert_eq!(ok(&["ls-files", r], None), "");
    assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), b"main\n");
}

#[test]
fn read_tree_prefix_dry_run_and_worktree_updates_preflight_all_obstructions() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let (base, ours, _, _) = three_index_trees(root);
    ok(&["read-tree", r, &base], None);
    fs::write(root.join("a.wasm"), wasm(1)).unwrap();
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    ok(&["read-tree", r, "-n", "-u", &ours], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(1));
    ok(&["read-tree", r, "-u", &ours], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    ok(&["read-tree", r, "--prefix", "vendor/", &base], None);
    assert_eq!(ok(&["ls-files", r], None), "a.wasm\nvendor/a.wasm");
    assert!(!root.join("vendor/a.wasm").exists());
    assert_eq!(ok(&["write-tree", r, "--prefix=vendor/"], None), base);
    let objects = files(root);
    fail(&["write-tree", r, "--prefix=a.wasm"], None);
    assert_eq!(files(root), objects);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    fail(&["read-tree", r, "--prefix", "vendor", &ours], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    fs::write(root.join("untracked.wasm"), wasm(8)).unwrap();
    let id = blob(root, 3);
    let obstruction = ok(
        &["mktree", r],
        Some(format!("100644 wasm {id}\ta.wasm\n100644 wasm {id}\tuntracked.wasm\n").as_bytes()),
    );
    fail(&["read-tree", r, "-u", &obstruction], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
    assert_eq!(fs::read(root.join("untracked.wasm")).unwrap(), wasm(8));
}

#[test]
fn merge_index_uses_the_wasm_three_way_engine_and_keeps_unresolved_original_images() {
    let temp = Temp::new();
    let root = &temp.0;
    let r = path(root);
    let module = |x: u8, y: u8| {
        [
            b"\0asm\x01\0\0\0".as_slice(),
            &[0, 3, 1, b'x', x, 0, 3, 1, b'y', y],
        ]
        .concat()
    };
    let mut trees = Vec::new();
    for bytes in [module(1, 1), module(2, 1), module(1, 2)] {
        let id = ok(&["hash-object", r, "-w", "--stdin"], Some(&bytes));
        trees.push(tree(root, &id));
    }
    ok(
        &["read-tree", r, "-m", &trees[0], &trees[1], &trees[2]],
        None,
    );
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    ok(&["merge-index", r, "--all", "--dry-run"], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    ok(&["merge-index", r, "--all"], None);
    assert_eq!(ok(&["ls-files", r, "--unmerged"], None), "");
    ok(&["restore", r, "--", "a.wasm"], None);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), module(2, 2));
    let (base, ours, theirs, _) = three_index_trees(root);
    ok(&["read-tree", r, "-m", &base, &ours, &theirs], None);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    let conflict = execute(&["merge-index", r, "--all"], None);
    assert_eq!(conflict.status.code(), Some(2));
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
}

#[test]
fn object_hashes_payloads_and_graphs_roundtrip_without_touching_head() {
    let temp = Temp::new();
    let root = &temp.0;
    let bytes = wasm(7);
    let dry = ok(&["hash-object", path(root), "--stdin"], Some(&bytes));
    let mut envelope = b"UWGO\0\0\0\x01".to_vec();
    envelope.push(1);
    envelope.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    envelope.extend_from_slice(&bytes);
    assert_eq!(dry, format!("{:x}", Sha256::digest(&envelope)));
    assert_eq!(files(root), 0);
    let blob = blob(root, 7);
    assert_eq!(blob, dry);
    assert_eq!(
        fs::read(root.join(".uwgit/objects").join(&blob)).unwrap(),
        envelope
    );
    let tree = tree(root, &blob);
    let id = commit(root, &tree, None, "first");
    assert_eq!(ok(&["cat-file", path(root), "-t", &tree], None), "tree");
    assert_eq!(ok(&["cat-file", path(root), "-t", &id], None), "commit");
    let exported = root.join("copy.wasm");
    ok(
        &["cat-file", path(root), &blob, "--output", path(&exported)],
        None,
    );
    assert_eq!(fs::read(exported).unwrap(), bytes);
    assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), b"main\n");
    assert!(!root.join(".uwgit/index").exists());
    assert_eq!(fs::read_dir(root.join(".uwgit/refs")).unwrap().count(), 0);
    ok(&["fsck", path(root)], None);
}

#[test]
fn tree_and_commit_rejections_publish_nothing() {
    let temp = Temp::new();
    let root = &temp.0;
    let blob = blob(root, 1);
    let before = files(root);
    for record in [
        format!("100644 wasm {blob}\t../outside\n"),
        format!("100644 tree {blob}\ta\n"),
        format!("100644 wasm {blob}\ta\n100644 wasm {blob}\ta\n"),
        format!("100644 wasm {}\ta\n", "f".repeat(64)),
        format!("100644 wasm {blob}\ta\n100644 wasm {blob}\ta/b\n"),
    ] {
        fail(&["mktree", path(root)], Some(record.as_bytes()));
        assert_eq!(files(root), before);
    }
    fail(
        &["hash-object", path(root), "-w", "--stdin"],
        Some(b"not a Wasm file"),
    );
    fail(&["commit-tree", path(root), &blob, "-m", "bad"], None);
    let tree = tree(root, &blob);
    let first = commit(root, &tree, None, "first");
    let before = files(root);
    fail(
        &[
            "commit-tree",
            path(root),
            &tree,
            "-m",
            "duplicate",
            "-p",
            &first,
            "-p",
            &first,
        ],
        None,
    );
    assert_eq!(files(root), before);
}

#[test]
fn ref_leases_creation_update_deletion_and_checked_out_protection() {
    let temp = Temp::new();
    let root = &temp.0;
    let blob = blob(root, 1);
    let tree = tree(root, &blob);
    let first = commit(root, &tree, None, "first");
    let second = commit(root, &tree, Some(&first), "second");
    let zero = "0".repeat(64);
    ok(
        &["update-ref", path(root), "refs/heads/topic", &first, &zero],
        None,
    );
    let before = fs::read(root.join(".uwgit/reflog")).unwrap();
    fail(
        &["update-ref", path(root), "refs/heads/topic", &second, &zero],
        None,
    );
    assert_eq!(fs::read(root.join(".uwgit/reflog")).unwrap(), before);
    ok(
        &[
            "update-ref",
            path(root),
            "refs/heads/topic",
            &second,
            &first,
        ],
        None,
    );
    fail(
        &["update-ref", path(root), "refs/heads/main", &first, &zero],
        None,
    );
    fail(
        &["update-ref", path(root), "-d", "refs/heads/topic", &first],
        None,
    );
    ok(
        &["update-ref", path(root), "-d", "refs/heads/topic", &second],
        None,
    );
    assert_eq!(fs::read_dir(root.join(".uwgit/refs")).unwrap().count(), 0);
    ok(&["fsck", path(root)], None);
}

#[test]
fn read_and_write_tree_leave_work_bytes_and_branch_unchanged() {
    let temp = Temp::new();
    let root = &temp.0;
    fs::write(root.join("a.wasm"), wasm(1)).unwrap();
    ok(&["add", path(root), "a.wasm"], None);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    let tree = ok(&["write-tree", path(root)], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    fs::write(root.join("a.wasm"), b"dirty work bytes").unwrap();
    ok(&["read-tree", path(root), "--empty"], None);
    assert_eq!(ok(&["ls-files", path(root)], None), "");
    ok(&["read-tree", path(root), &tree], None);
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
    assert_eq!(fs::read(root.join("a.wasm")).unwrap(), b"dirty work bytes");
    assert_eq!(fs::read(root.join(".uwgit/HEAD")).unwrap(), b"main\n");
}

#[test]
fn revision_walk_ranges_first_parent_reverse_and_limits_follow_the_actual_dag() {
    let temp = Temp::new();
    let root = &temp.0;
    let blob = blob(root, 1);
    let tree = tree(root, &blob);
    let first = commit(root, &tree, None, "first");
    let left = commit(root, &tree, Some(&first), "left");
    let right = commit(root, &tree, Some(&first), "right");
    let merge = ok(
        &[
            "commit-tree",
            path(root),
            &tree,
            "-p",
            &left,
            "-p",
            &right,
            "-m",
            "merge",
        ],
        None,
    );
    let rows = ok(&["rev-list", path(root), &merge], None);
    assert_eq!(rows.lines().next(), Some(merge.as_str()));
    assert_eq!(rows.lines().last(), Some(first.as_str()));
    assert_eq!(rows.lines().count(), 4);
    assert_eq!(
        ok(&["rev-list", path(root), "--first-parent", &merge], None),
        format!("{merge}\n{left}\n{first}")
    );
    assert_eq!(
        ok(
            &[
                "rev-list",
                path(root),
                "--reverse",
                "-n",
                "2",
                "--first-parent",
                &merge
            ],
            None
        ),
        format!("{left}\n{merge}")
    );
    assert_eq!(
        ok(
            &[
                "rev-list",
                path(root),
                "--count",
                &format!("{first}..{merge}")
            ],
            None
        ),
        "3"
    );
    assert_eq!(ok(&["rev-list", path(root), "--count", "--all"], None), "0");
}

#[test]
fn malformed_options_help_literal_messages_and_locks_have_no_side_effects() {
    for command in [
        "hash-object",
        "mktree",
        "write-tree",
        "read-tree",
        "commit-tree",
        "update-ref",
        "rev-list",
    ] {
        ok(&[command, "--help"], None);
    }
    let temp = Temp::new();
    let root = &temp.0;
    let blob = blob(root, 1);
    let tree = tree(root, &blob);
    let id = commit(root, &tree, None, "--help");
    let value: Value =
        serde_json::from_str(&ok(&["cat-file", path(root), "-p", &id], None)).unwrap();
    assert_eq!(value["message"], "--help");
    let before = files(root);
    fs::write(root.join(".uwgit/write.lock"), b"held").unwrap();
    fail(
        &["hash-object", path(root), "-w", "--stdin"],
        Some(&wasm(9)),
    );
    assert_eq!(files(root), before);
    fs::remove_file(root.join(".uwgit/write.lock")).unwrap();
    fail(&["rev-list", path(root), "--invented"], None);
    fail(&["read-tree", path(root), "--empty", &tree], None);
    assert_eq!(files(root), before);
}
