use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-diff-plumbing-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        ok(&["init", p(&root)]);
        Self(root)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim_end().into()
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}
#[test]
fn commit_index_and_worktree_are_three_independently_compared_byte_snapshots() {
    let temp = Temp::new();
    let root = &temp.0;
    fs::write(root.join("a.wasm"), wasm(1)).unwrap();
    ok(&["add", p(root), "a.wasm"]);
    ok(&["commit", p(root), "-m", "one"]);
    let old = ok(&["rev-parse", p(root), "HEAD"]);
    fs::write(root.join("a.wasm"), wasm(2)).unwrap();
    ok(&["add", p(root), "a.wasm"]);
    fs::write(root.join("a.wasm"), wasm(3)).unwrap();
    let index = fs::read(root.join(".uwgit/index")).unwrap();
    for command in [
        vec!["diff-files", p(root)],
        vec!["diff-index", p(root), "HEAD", "--cached"],
        vec!["diff-index", p(root), "HEAD"],
    ] {
        let report: Value = serde_json::from_str(&ok(&command)).unwrap();
        assert_eq!(report["files"][0]["status"], "modified");
        assert!(report["files"][0]["diff"].is_object());
    }
    assert_eq!(
        run(&["diff-files", p(root), "--quiet"]).status.code(),
        Some(1)
    );
    assert_eq!(
        ok(&["diff-index", p(root), "HEAD", "--cached", "--name-status"]),
        "M\ta.wasm"
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
    ok(&["commit", p(root), "-m", "staged two"]);
    let new = ok(&["rev-parse", p(root), "HEAD"]);
    assert_eq!(
        ok(&["diff-tree", p(root), &old, &new, "--name-only"]),
        "a.wasm"
    );
    let output = run(&[
        "diff-tree",
        p(root),
        &old,
        &new,
        "--name-status",
        "-z",
        "--exit-code",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"M\0a.wasm\0");
}
#[test]
fn exact_path_filters_additions_deletions_and_invalid_modes_never_write() {
    let temp = Temp::new();
    let root = &temp.0;
    fs::create_dir(root.join("modules")).unwrap();
    fs::write(root.join("modules/a.wasm"), wasm(1)).unwrap();
    ok(&["add", p(root), "modules/a.wasm"]);
    ok(&["commit", p(root), "-m", "base"]);
    let old = ok(&["rev-parse", p(root), "HEAD"]);
    ok(&["rm", p(root), "modules/a.wasm"]);
    fs::write(root.join("b.wasm"), wasm(9)).unwrap();
    ok(&["add", p(root), "b.wasm"]);
    ok(&["commit", p(root), "-m", "change"]);
    let new = ok(&["rev-parse", p(root), "HEAD"]);
    let before = fs::read(root.join(".uwgit/index")).unwrap();
    assert_eq!(
        ok(&[
            "diff-tree",
            p(root),
            &old,
            &new,
            "--name-status",
            "--",
            "modules/"
        ]),
        "D\tmodules/a.wasm"
    );
    assert_eq!(ok(&["diff-files", p(root), "--name-only"]), "");
    assert_eq!(
        run(&["diff-tree", p(root), &old, &new, "-z"]).status.code(),
        Some(1)
    );
    assert_eq!(
        run(&["diff-tree", p(root), &old, &new, "--", "missing"])
            .status
            .code(),
        Some(1)
    );
    assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), before);
}
