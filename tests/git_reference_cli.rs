//! Compare public invariants with a real Git executable in separate fixtures.
//! The uwgit process never invokes Git; only this independent reference test does.
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-git-reference-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
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
fn uw(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn git(root: &Path, args: &[&str]) -> Output {
    Command::new("git")
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
        .unwrap()
}
fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}

#[test]
fn real_git_index_stages_and_native_wasm_stages_have_the_same_original_side_images() {
    let temp = Temp::new();
    let native = temp.path("native-stages");
    let reference = temp.path("git-stages");
    success(uw(&["init", p(&native)]));
    fs::create_dir(&reference).unwrap();
    success(git(&reference, &["init", "-b", "main"]));
    let (mut native_ids, mut git_ids) = (Vec::new(), Vec::new());
    for value in 1..=3 {
        for root in [&native, &reference] {
            fs::write(root.join("a.wasm"), wasm(value)).unwrap();
        }
        success(uw(&["add", p(&native), "a.wasm"]));
        success(uw(&["commit", p(&native), "-m", &format!("value {value}")]));
        native_ids.push(
            String::from_utf8(success(uw(&["rev-parse", p(&native), "HEAD"])))
                .unwrap()
                .trim()
                .to_owned(),
        );
        success(git(&reference, &["add", "a.wasm"]));
        success(git(
            &reference,
            &["commit", "-m", &format!("value {value}")],
        ));
        git_ids.push(
            String::from_utf8(success(git(&reference, &["rev-parse", "HEAD"])))
                .unwrap()
                .trim()
                .to_owned(),
        );
    }
    success(uw(&["reset", p(&native), "--hard", &native_ids[1]]));
    success(git(&reference, &["reset", "--hard", &git_ids[1]]));
    success(uw(&[
        "read-tree",
        p(&native),
        "-m",
        &native_ids[0],
        &native_ids[1],
        &native_ids[2],
    ]));
    success(git(
        &reference,
        &["read-tree", "-m", &git_ids[0], &git_ids[1], &git_ids[2]],
    ));
    let native_rows =
        String::from_utf8(success(uw(&["ls-files", p(&native), "--unmerged"]))).unwrap();
    let git_rows =
        String::from_utf8(success(git(&reference, &["ls-files", "--unmerged"]))).unwrap();
    assert_eq!(native_rows.lines().count(), 3);
    assert_eq!(git_rows.lines().count(), 3);
    for (native_row, git_row) in native_rows.lines().zip(git_rows.lines()) {
        let (native_header, native_path) = native_row.split_once('\t').unwrap();
        let (git_header, git_path) = git_row.split_once('\t').unwrap();
        let n: Vec<_> = native_header.split_whitespace().collect();
        let g: Vec<_> = git_header.split_whitespace().collect();
        assert_eq!((n[0], n[2], native_path), (g[0], g[2], git_path));
        let exported = temp.path(&format!("stage-{}.wasm", n[2]));
        success(uw(&[
            "cat-file",
            p(&native),
            n[1],
            "--output",
            p(&exported),
        ]));
        assert_eq!(
            fs::read(exported).unwrap(),
            success(git(&reference, &["cat-file", "blob", g[1]]))
        );
    }
    let native_exports = String::from_utf8(success(uw(&[
        "checkout-index",
        p(&native),
        "--stage=all",
        "--all",
    ])))
    .unwrap();
    let git_exports = String::from_utf8(success(git(
        &reference,
        &["checkout-index", "--stage=all", "--all"],
    )))
    .unwrap();
    let (native_names, native_path) = native_exports.trim_end().split_once('\t').unwrap();
    let (git_names, git_path) = git_exports.trim_end().split_once('\t').unwrap();
    assert_eq!(native_path, git_path);
    for (native_name, git_name) in native_names.split(' ').zip(git_names.split(' ')) {
        assert_eq!(
            fs::read(native.join(native_name)).unwrap(),
            fs::read(reference.join(git_name)).unwrap()
        );
    }
    success(uw(&["restore", p(&native), "--ours", "--", "a.wasm"]));
    success(git(&reference, &["checkout", "--ours", "--", "a.wasm"]));
    assert_eq!(
        fs::read(native.join("a.wasm")).unwrap(),
        fs::read(reference.join("a.wasm")).unwrap()
    );
    success(uw(&["add", p(&native), "a.wasm"]));
    success(git(&reference, &["add", "a.wasm"]));
    assert!(success(uw(&["ls-files", p(&native), "--unmerged"])).is_empty());
    assert!(success(git(&reference, &["ls-files", "--unmerged"])).is_empty());
    success(uw(&[
        "checkout-index",
        p(&native),
        "--all",
        "--prefix=.export-",
    ]));
    success(git(
        &reference,
        &["checkout-index", "--all", "--prefix=.export-"],
    ));
    assert_eq!(
        fs::read(native.join(".export-a.wasm")).unwrap(),
        fs::read(reference.join(".export-a.wasm")).unwrap()
    );
    for root in [&native, &reference] {
        fs::write(root.join("a.wasm"), wasm(9)).unwrap();
        fs::write(root.join(".gitignore"), "*.log\n").unwrap();
        fs::write(root.join("ignored.log"), b"log").unwrap();
    }
    assert_eq!(
        success(uw(&["ls-files", p(&native), "--modified"])),
        success(git(&reference, &["ls-files", "--modified"]))
    );
    assert_eq!(
        success(uw(&[
            "ls-files",
            p(&native),
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
            "*.log"
        ])),
        success(git(
            &reference,
            &[
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "--",
                "*.log"
            ]
        ))
    );
    for root in [&native, &reference] {
        fs::remove_file(root.join("a.wasm")).unwrap();
    }
    assert_eq!(
        success(uw(&["ls-files", p(&native), "--deleted"])),
        success(git(&reference, &["ls-files", "--deleted"]))
    );
}
#[test]
fn real_git_and_native_wasm_history_agree_on_worktree_isolation_and_branch_leases() {
    let temp = Temp::new();
    let native = temp.path("native");
    let reference = temp.path("reference");
    let native_linked = temp.path("native-linked");
    let reference_linked = temp.path("reference-linked");
    fs::create_dir(&reference).unwrap();
    success(git(&reference, &["init", "-b", "main"]));
    success(uw(&["init", p(&native)]));
    for root in [&native, &reference] {
        fs::write(root.join("a.wasm"), wasm(1)).unwrap();
    }
    success(uw(&["add", p(&native), "a.wasm"]));
    success(uw(&["commit", p(&native), "-m", "root"]));
    success(git(&reference, &["add", "a.wasm"]));
    success(git(&reference, &["commit", "-m", "root"]));
    success(uw(&["branch", p(&native), "feature/topic"]));
    success(git(&reference, &["branch", "feature/topic"]));
    success(uw(&[
        "worktree",
        p(&native),
        "add",
        p(&native_linked),
        "feature/topic",
    ]));
    success(git(
        &reference,
        &["worktree", "add", p(&reference_linked), "feature/topic"],
    ));
    for root in [&native_linked, &reference_linked] {
        fs::write(root.join("a.wasm"), wasm(2)).unwrap();
    }
    success(uw(&["add", p(&native_linked), "a.wasm"]));
    success(uw(&["commit", p(&native_linked), "-m", "linked change"]));
    success(git(&reference_linked, &["add", "a.wasm"]));
    success(git(&reference_linked, &["commit", "-m", "linked change"]));
    assert_eq!(
        success(uw(&["rev-list", p(&native), "--count", "feature/topic"])),
        success(git(&reference, &["rev-list", "--count", "feature/topic"]))
    );
    assert_eq!(
        fs::read(native.join("a.wasm")).unwrap(),
        fs::read(reference.join("a.wasm")).unwrap()
    );
    assert!(!uw(&["branch", p(&native), "-D", "feature/topic"])
        .status
        .success());
    assert!(!git(&reference, &["branch", "-D", "feature/topic"])
        .status
        .success());
    for root in [&native_linked, &reference_linked] {
        fs::write(root.join("untracked.txt"), b"keep").unwrap();
    }
    assert!(!uw(&["worktree", p(&native), "remove", p(&native_linked)])
        .status
        .success());
    assert!(
        !git(&reference, &["worktree", "remove", p(&reference_linked)])
            .status
            .success()
    );
    success(uw(&[
        "worktree",
        p(&native),
        "remove",
        p(&native_linked),
        "--force",
    ]));
    success(git(
        &reference,
        &["worktree", "remove", "--force", p(&reference_linked)],
    ));
    assert!(!native_linked.exists());
    assert!(!reference_linked.exists());
    success(uw(&["fsck", p(&native)]));
    success(git(&reference, &["fsck", "--full"]));
}
#[test]
fn real_git_and_native_cleanup_preserve_ignored_and_tracked_bytes() {
    let temp = Temp::new();
    let native = temp.path("native");
    let reference = temp.path("reference");
    fs::create_dir(&reference).unwrap();
    success(git(&reference, &["init", "-b", "main"]));
    success(uw(&["init", p(&native)]));
    for root in [&native, &reference] {
        fs::write(root.join("a.wasm"), wasm(1)).unwrap();
        fs::write(root.join(".gitignore"), "*.log\n").unwrap();
        fs::write(root.join("keep.log"), b"keep").unwrap();
        fs::write(root.join("remove.txt"), b"remove").unwrap();
    }
    success(uw(&["add", p(&native), "a.wasm"]));
    success(uw(&["commit", p(&native), "-m", "root"]));
    success(git(&reference, &["add", "a.wasm"]));
    success(git(&reference, &["commit", "-m", "root"]));
    let plan: Value = serde_json::from_slice(&success(uw(&[
        "clean",
        p(&native),
        "-n",
        "-e",
        ".gitignore",
    ])))
    .unwrap();
    assert_eq!(plan["files"], serde_json::json!(["remove.txt"]));
    assert_eq!(
        String::from_utf8(success(git(
            &reference,
            &["clean", "-n", "-e", ".gitignore"]
        )))
        .unwrap(),
        "Would remove remove.txt\n"
    );
    success(uw(&["clean", p(&native), "-f", "-e", ".gitignore"]));
    success(git(&reference, &["clean", "-f", "-e", ".gitignore"]));
    for name in ["a.wasm", "keep.log", ".gitignore"] {
        assert_eq!(
            fs::read(native.join(name)).unwrap(),
            fs::read(reference.join(name)).unwrap()
        );
    }
    assert!(!native.join("remove.txt").exists());
    assert!(!reference.join("remove.txt").exists());
}
