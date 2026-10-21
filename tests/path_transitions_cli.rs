//! Fixed file/directory transitions and pre-publication obstruction checks.
//! No fuzz input; all temporary state lives below /tmp.
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const A: &[u8] = b"\0asm\x01\0\0\0";
const B: &[u8] = b"\0asm\x01\0\0\0\0\x02\x01b";
const C: &[u8] = b"\0asm\x01\0\0\0\0\x02\x01c";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = PathBuf::from(format!(
            "/tmp/uwgit-path-transitions-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        ok(&["init", path.to_str().unwrap()]);
        Self(path)
    }
    fn root(&self) -> &str {
        self.0.to_str().unwrap()
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn read(&self, path: &str) -> Vec<u8> {
        fs::read(self.0.join(path)).unwrap()
    }
    fn commit(&self, message: &str) -> String {
        ok(&["commit", self.root(), "-m", message]);
        ok(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn history(&self) -> (String, String) {
        self.write("left", A);
        self.write("right/deep/old.wasm", B);
        self.write("stable.wasm", C);
        ok(&[
            "add",
            self.root(),
            "left",
            "right/deep/old.wasm",
            "stable.wasm",
        ]);
        let first = self.commit("file and directory");
        ok(&["branch", self.root(), "before"]);
        ok(&["mv", self.root(), "left", "left/深/模块.wasm"]);
        ok(&["mv", self.root(), "right/deep/old.wasm", "right"]);
        let second = self.commit("exchange file and directory roles");
        ok(&["branch", self.root(), "after"]);
        (first, second)
    }
    fn assert_before(&self) {
        assert_eq!(self.read("left"), A);
        assert_eq!(self.read("right/deep/old.wasm"), B);
        assert_eq!(self.read("stable.wasm"), C);
    }
    fn assert_after(&self) {
        assert_eq!(self.read("left/深/模块.wasm"), A);
        assert_eq!(self.read("right"), B);
        assert_eq!(self.read("stable.wasm"), C);
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
fn ok(args: &[&str]) -> String {
    let out = invoke(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn rejected(args: &[&str]) -> String {
    let out = invoke(args);
    assert!(!out.status.success(), "unexpected success: {args:?}");
    String::from_utf8(out.stderr).unwrap()
}
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn walk(root: &Path, directory: &Path, output: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                output.insert(relative, Entry::Symlink(fs::read_link(path).unwrap()));
            } else if kind.is_dir() {
                output.insert(relative, Entry::Directory);
                walk(root, &path, output);
            } else {
                output.insert(relative, Entry::File(fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}
fn no_change(t: &Temp, args: &[&str]) -> String {
    let before = snapshot(&t.0);
    let error = rejected(args);
    assert_eq!(
        snapshot(&t.0),
        before,
        "rejected command changed files: {args:?}"
    );
    error
}

#[test]
fn unicode_multilevel_prefix_exchange_switch_reset_restore_and_audit() {
    let t = Temp::new();
    let (first, second) = t.history();
    t.assert_after();
    ok(&["switch", t.root(), "before"]);
    t.assert_before();
    ok(&["switch", t.root(), "after"]);
    t.assert_after();
    ok(&["reset", t.root(), "--hard", &first]);
    t.assert_before();
    ok(&["reset", t.root(), "--hard", &second]);
    t.assert_after();
    // Restore both the complete target and the index without changing HEAD.
    ok(&[
        "restore",
        t.root(),
        "--source",
        &first,
        "--staged",
        "--worktree",
    ]);
    t.assert_before();
    let status: Value = serde_json::from_str(&ok(&["status", t.root()])).unwrap();
    assert_eq!(status["staged"], true);
    let diff: Value =
        serde_json::from_str(&ok(&["diff", t.root(), "--cached", "--format", "json"])).unwrap();
    assert_eq!(diff["summary"]["added"], 2);
    assert_eq!(diff["summary"]["deleted"], 2);
    ok(&[
        "restore",
        t.root(),
        "--source",
        &second,
        "--staged",
        "--worktree",
    ]);
    t.assert_after();
    assert_eq!(ok(&["rev-parse", t.root(), "HEAD"]).trim(), second);
    ok(&["fsck", t.root()]);
}

#[test]
fn directory_replacement_checks_every_untracked_file_and_empty_subdirectory_before_publication() {
    let t = Temp::new();
    t.history();
    ok(&["switch", t.root(), "before"]);
    // This filename sorts after the owned child and contains no Wasm header.
    t.write("right/zz-private.txt", b"untracked non-Wasm data\0\xff");
    for args in [
        vec!["switch", t.root(), "after"],
        vec!["reset", t.root(), "--hard", "after"],
        vec![
            "restore",
            t.root(),
            "--source",
            "after",
            "--staged",
            "--worktree",
        ],
        vec!["mv", t.root(), "right/deep/old.wasm", "right"],
    ] {
        assert!(no_change(&t, &args).contains("untracked"));
    }
    fs::remove_file(t.0.join("right/zz-private.txt")).unwrap();
    fs::create_dir_all(t.0.join("right/empty/untracked")).unwrap();
    assert!(no_change(&t, &["switch", t.root(), "after"]).contains("untracked directory"));
    fs::remove_dir(t.0.join("right/empty/untracked")).unwrap();
    fs::remove_dir(t.0.join("right/empty")).unwrap();
    ok(&["switch", t.root(), "after"]);
    t.assert_after();
}

#[test]
fn retained_or_untracked_parent_files_and_dirty_owned_files_prevent_branch_publication() {
    let t = Temp::new();
    t.history();
    ok(&["switch", t.root(), "before"]);
    t.write("stable.wasm", b"unfinished editor bytes");
    no_change(&t, &["switch", t.root(), "after"]);
    t.write("stable.wasm", C);
    ok(&["rm", t.root(), "--cached", "left"]);
    t.commit("left is now untracked");
    for args in [
        vec!["reset", t.root(), "--hard", "after"],
        vec!["switch", t.root(), "after"],
    ] {
        assert!(no_change(&t, &args).contains("blocks target directory"));
    }
}

#[test]
fn index_lock_and_ref_lock_leave_whole_prefix_exchange_unchanged() {
    let t = Temp::new();
    t.history();
    ok(&["switch", t.root(), "before"]);
    t.write(".uwgit/index.lock", b"held index lock");
    no_change(&t, &["switch", t.root(), "after"]);
    no_change(&t, &["reset", t.root(), "--hard", "after"]);
    fs::remove_file(t.0.join(".uwgit/index.lock")).unwrap();
    t.write(".uwgit/write.lock", b"held repository lock");
    no_change(&t, &["switch", t.root(), "after"]);
    no_change(&t, &["reset", t.root(), "--hard", "after"]);
    fs::remove_file(t.0.join(".uwgit/write.lock")).unwrap();
    ok(&["switch", t.root(), "after"]);
    t.assert_after();
}

#[cfg(unix)]
#[test]
fn symlink_anywhere_in_replaced_directory_or_target_parent_is_rejected_without_changes() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    t.history();
    ok(&["switch", t.root(), "before"]);
    symlink("../../stable.wasm", t.0.join("right/zz-link")).unwrap();
    for args in [
        vec!["switch", t.root(), "after"],
        vec!["reset", t.root(), "--hard", "after"],
        vec!["mv", t.root(), "right/deep/old.wasm", "right"],
    ] {
        assert!(no_change(&t, &args).contains("symlink"));
    }
    fs::remove_file(t.0.join("right/zz-link")).unwrap();
    symlink("right", t.0.join("redirect")).unwrap();
    assert!(no_change(&t, &["mv", t.root(), "left", "redirect/deep/new.wasm"]).contains("symlink"));
    ok(&["switch", t.root(), "after"]);
    t.assert_after();
}

#[test]
fn stash_push_apply_pop_preserve_staged_prefix_transitions_and_dirty_raw_bytes() {
    let t = Temp::new();
    t.write("module", A);
    ok(&["add", t.root(), "module"]);
    t.commit("file");
    ok(&["mv", t.root(), "module", "module/深/module.wasm"]);
    t.write("module/深/module.wasm", b"unfinished\0\xff");
    ok(&["stash", t.root(), "push", "-m", "prefix transition"]);
    assert_eq!(t.read("module"), A);
    ok(&["stash", t.root(), "apply", "0"]);
    assert_eq!(t.read("module/深/module.wasm"), b"unfinished\0\xff");
    assert_eq!(ok(&["ls-files", t.root()]).trim(), "module/深/module.wasm");
    ok(&["reset", t.root(), "--hard"]);
    assert_eq!(t.read("module"), A);
    ok(&["stash", t.root(), "pop", "0"]);
    assert_eq!(t.read("module/深/module.wasm"), b"unfinished\0\xff");
    let list: Value = serde_json::from_str(&ok(&["stash", t.root(), "list"])).unwrap();
    assert_eq!(list, serde_json::json!([]));
}

#[test]
fn stash_late_untracked_obstruction_is_detected_before_stash_or_worktree_publication() {
    let t = Temp::new();
    t.write("module", A);
    ok(&["add", t.root(), "module"]);
    t.commit("file");
    ok(&["mv", t.root(), "module", "module/深/module.wasm"]);
    t.write("module/zz-private.txt", b"private untracked bytes");
    assert!(no_change(&t, &["stash", t.root(), "push"]).contains("untracked"));
    assert!(!t.0.join(".uwgit/stash").exists());
    fs::remove_file(t.0.join("module/zz-private.txt")).unwrap();
    ok(&["stash", t.root(), "push"]);
    ok(&["stash", t.root(), "pop", "0"]);
    assert_eq!(t.read("module/深/module.wasm"), A);
}

#[test]
fn mv_prefix_transition_preserves_staged_and_unstaged_bytes_separately() {
    let t = Temp::new();
    t.write("module", A);
    t.write("other.wasm", C);
    ok(&["add", t.root(), "module", "other.wasm"]);
    t.commit("base");
    t.write("module", B);
    ok(&["add", t.root(), "module"]);
    t.write("module", b"raw dirty bytes");
    t.write("other.wasm", b"unrelated dirty bytes");
    ok(&["mv", t.root(), "module", "module/深/module.wasm"]);
    assert_eq!(t.read("module/深/module.wasm"), b"raw dirty bytes");
    assert_eq!(t.read("other.wasm"), b"unrelated dirty bytes");
    t.commit("move staged module");
    let output = t.0.join("export.wasm");
    ok(&[
        "show",
        t.root(),
        "HEAD",
        "--file",
        "module/深/module.wasm",
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(fs::read(output).unwrap(), B);
    ok(&["mv", t.root(), "module/深/module.wasm", "module"]);
    assert_eq!(t.read("module"), b"raw dirty bytes");
    assert_eq!(t.read("other.wasm"), b"unrelated dirty bytes");
}

#[test]
fn merge_and_history_replay_preflight_prefix_obstructions_then_synchronize_complete_trees() {
    let t = Temp::new();
    let (_, selected) = t.history();
    ok(&["switch", t.root(), "before"]);
    t.write("stable.wasm", B);
    ok(&["add", t.root(), "stable.wasm"]);
    let ours = t.commit("independent file change");
    t.write("right/zz-private.txt", b"late non-Wasm obstruction");
    for args in [
        vec!["cherry-pick", t.root(), &selected],
        vec!["rebase", t.root(), "after"],
        vec!["merge", t.root(), "after", "-m", "must preflight"],
    ] {
        assert!(no_change(&t, &args).contains("untracked"));
    }
    fs::remove_file(t.0.join("right/zz-private.txt")).unwrap();
    ok(&["cherry-pick", t.root(), &selected]);
    assert_eq!(t.read("left/深/模块.wasm"), A);
    assert_eq!(t.read("right"), B);
    assert_eq!(t.read("stable.wasm"), B);
    ok(&["revert", t.root(), "HEAD"]);
    assert_eq!(t.read("left"), A);
    assert_eq!(t.read("right/deep/old.wasm"), B);
    assert_eq!(t.read("stable.wasm"), B);
    ok(&["reset", t.root(), "--hard", &ours]);
    ok(&["rebase", t.root(), "after"]);
    assert_eq!(t.read("left/深/模块.wasm"), A);
    assert_eq!(t.read("right"), B);
    assert_eq!(t.read("stable.wasm"), B);
    ok(&["reset", t.root(), "--hard", &ours]);
    ok(&["merge", t.root(), "after", "-m", "merge prefix transition"]);
    assert_eq!(t.read("left/深/模块.wasm"), A);
    assert_eq!(t.read("right"), B);
    assert_eq!(t.read("stable.wasm"), B);
    ok(&["fsck", t.root()]);
}
