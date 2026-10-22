use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::pathspec::{self, Pathspec};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-pathspec-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
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
fn uw(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = uw(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn wasm(value: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat()
}
fn set(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|value| (*value).into()).collect()
}

#[test]
fn selectors_cover_glob_literal_case_directory_and_exclusion_semantics() {
    let candidates = set(&[
        "a.wasm",
        "B.WASM",
        "dir/a.wasm",
        "dir/sub/b.wasm",
        "a[1].wasm",
        "brace{a,b}.wasm",
        "dir.txt/child.wasm",
    ]);
    for (selectors, expected) in [
        (
            vec!["*.wasm", ":!dir/"],
            vec![
                "a.wasm",
                "a[1].wasm",
                "brace{a,b}.wasm",
                "dir.txt/child.wasm",
            ],
        ),
        (
            vec![":(glob)*.wasm"],
            vec!["a.wasm", "a[1].wasm", "brace{a,b}.wasm"],
        ),
        (
            vec![":(glob)dir/**/*.wasm"],
            vec!["dir/a.wasm", "dir/sub/b.wasm"],
        ),
        (vec![":(literal)a[1].wasm"], vec!["a[1].wasm"]),
        (vec![":(icase,glob)b.wasm"], vec!["B.WASM"]),
        (vec![":/dir/", ":^dir/sub/"], vec!["dir/a.wasm"]),
        (vec![":(exclude)*.wasm"], vec!["B.WASM"]),
        (vec!["brace{a,b}.wasm"], vec!["brace{a,b}.wasm"]),
        (vec!["dir.txt"], vec!["dir.txt/child.wasm"]),
    ] {
        assert_eq!(
            pathspec::select(
                &candidates,
                &selectors.iter().map(|s| (*s).into()).collect::<Vec<_>>()
            )
            .unwrap(),
            set(&expected),
            "{selectors:?}"
        );
    }
    assert_eq!(
        pathspec::select(&candidates, &[":".into()]).unwrap(),
        candidates
    );
    assert_eq!(
        pathspec::select(&candidates, &["a.wasm".into(), ":!a.wasm".into()]).unwrap(),
        BTreeSet::new()
    );
    for invalid in [
        ":(literal,glob)a",
        ":(glob)a**b",
        ":(glob)***",
        ":(icase,icase)a",
        ":(attr:binary)a",
        "../a",
        "a//b",
        "a/../b",
        "/a",
        ":(top)../a",
        ":(glob).uwgit/**",
        "a\n",
    ] {
        assert!(Pathspec::new(&[invalid.into()]).is_err(), "{invalid:?}");
    }
    assert!(Pathspec::new(&[":".into(), "a".into()]).is_err());
}

#[test]
fn real_git_pathspec_selection_matches_native_flat_wasm_candidates() {
    let temp = Temp::new();
    git(&temp.0, &["init", "-b", "main"]);
    let names = [
        "a.wasm",
        "B.WASM",
        "dir/a.wasm",
        "dir/sub/b.wasm",
        "a[1].wasm",
        "brace{a,b}.wasm",
        "dir.txt/child.wasm",
    ];
    for name in names {
        fs::create_dir_all(temp.0.join(name).parent().unwrap()).unwrap();
        fs::write(temp.0.join(name), wasm(1)).unwrap();
    }
    git(&temp.0, &["add", "."]);
    let candidates = set(&names);
    for selectors in [
        vec!["*.wasm"],
        vec!["dir/*.wasm"],
        vec![":(glob)*.wasm"],
        vec![":(glob)**/*.wasm"],
        vec![":(glob)dir/**/*.wasm", ":!dir/sub/"],
        vec![":(literal)a[1].wasm"],
        vec![":(icase,glob)b.wasm"],
        vec!["brace{a,b}.wasm"],
        vec![":^dir/"],
        vec!["dir.txt"],
    ] {
        let mut args = vec!["ls-files", "--"];
        args.extend(&selectors);
        let reference: BTreeSet<_> = git(&temp.0, &args).lines().map(str::to_owned).collect();
        let native = pathspec::select(
            &candidates,
            &selectors.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(native, reference, "{selectors:?}");
    }
}

#[test]
fn native_add_all_update_dry_run_ignore_and_restore_pathspecs_preserve_other_bytes() {
    let temp = Temp::new();
    let root = p(&temp.0);
    ok(&["init", root]);
    fs::create_dir(temp.0.join("modules")).unwrap();
    for name in ["a.wasm", "modules/b.wasm", "ignored.wasm"] {
        fs::write(temp.0.join(name), wasm(1)).unwrap();
    }
    fs::write(temp.0.join(".gitignore"), "ignored.wasm\n").unwrap();
    fs::write(temp.0.join("notes.txt"), b"ordinary local text").unwrap();
    ok(&["add", root, "-A", "-n"]);
    assert!(!temp.0.join(".uwgit/index").exists());
    ok(&["add", root, "-A"]);
    assert_eq!(
        ok(&["ls-files", root]).lines().collect::<BTreeSet<_>>(),
        ["a.wasm", "modules/b.wasm"].into()
    );
    ok(&["commit", root, "-m", "root"]);
    fs::write(temp.0.join("a.wasm"), wasm(2)).unwrap();
    fs::remove_file(temp.0.join("modules/b.wasm")).unwrap();
    fs::write(temp.0.join("c.wasm"), wasm(3)).unwrap();
    ok(&["add", root, "-u"]);
    assert_eq!(ok(&["ls-files", root]).trim(), "a.wasm");
    ok(&["add", root, "-f", "ignored.wasm"]);
    let before = fs::read(temp.0.join(".uwgit/index")).unwrap();
    assert!(!uw(&["add", root, "a.wasm", "missing*"]).status.success());
    assert_eq!(fs::read(temp.0.join(".uwgit/index")).unwrap(), before);
    ok(&[
        "restore",
        root,
        "--source",
        "HEAD",
        "--staged",
        "--worktree",
        "--",
        "*.wasm",
        ":!a.wasm",
    ]);
    assert_eq!(fs::read(temp.0.join("a.wasm")).unwrap(), wasm(2));
    assert_eq!(fs::read(temp.0.join("modules/b.wasm")).unwrap(), wasm(1));
    assert_eq!(
        fs::read(temp.0.join("notes.txt")).unwrap(),
        b"ordinary local text"
    );
    let names = ok(&[
        "ls-tree",
        root,
        "HEAD",
        "--name-only",
        "--",
        ":(glob)modules/*.wasm",
    ]);
    assert_eq!(names.trim(), "modules/b.wasm");
    ok(&["fsck", root]);
}
