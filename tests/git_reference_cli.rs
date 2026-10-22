//! Compare public invariants with a real Git executable in separate fixtures.
//! The uwgit process never invokes Git; only this independent reference test does.
use serde_json::Value;
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

fn reference_updates(
    root: &Path,
    native: bool,
    records: &str,
    nul: bool,
    allow_failures: bool,
) -> Output {
    reference_updates_with_flags(root, native, records, nul, allow_failures, false)
}

fn reference_updates_with_flags(
    root: &Path,
    native: bool,
    records: &str,
    nul: bool,
    allow_failures: bool,
    no_deref: bool,
) -> Output {
    let mut command = if native {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
        command.args(["update-ref", p(root), "--stdin"]);
        command
    } else {
        let mut command = Command::new("git");
        command.args(["-C", p(root), "update-ref", "--stdin"]);
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        command
    };
    if allow_failures {
        command.arg("--batch-updates");
    }
    if no_deref {
        command.arg("--no-deref");
    }
    if nul {
        command.arg("-z");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(records.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn native_reference_transaction_leases_and_control_match_independent_git_fixtures() {
    fn input(root: &Path, native: bool, records: &str, nul: bool) -> Output {
        reference_updates(root, native, records, nul, false)
    }
    let temp = Temp::new();
    let native = temp.path("native-refs");
    let reference = temp.path("git-refs");
    success(uw(&["init", p(&native)]));
    fs::create_dir(&reference).unwrap();
    success(git(&reference, &["init", "-b", "main"]));
    let (mut native_ids, mut git_ids) = (Vec::new(), Vec::new());
    for value in [1, 2] {
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
    for (root, is_native, ids, zero) in [
        (&native, true, &native_ids, "0".repeat(64)),
        (&reference, false, &git_ids, "0".repeat(40)),
    ] {
        success(input(
            root,
            is_native,
            &format!(
                "create refs/heads/topic {}\ncreate refs/tags/old {}\n",
                ids[0], ids[0]
            ),
            false,
        ));
        let output = success(input(root, is_native, &format!("start\nupdate refs/heads/topic {} {}\ncreate refs/tags/release {}\ndelete refs/tags/old {}\nverify refs/heads/main {}\nprepare\ncommit\n", ids[1], ids[0], ids[1], ids[0], ids[1]), false));
        assert_eq!(output, b"start: ok\nprepare: ok\ncommit: ok\n");
        let failed = input(
            root,
            is_native,
            &format!(
                "create refs/tags/rejected {}\nupdate refs/heads/topic {} {}\n",
                ids[0], ids[0], ids[0]
            ),
            false,
        );
        assert!(!failed.status.success());
        // EOF after explicit prepare and explicit abort both leave no ref.
        success(input(
            root,
            is_native,
            &format!("start\ncreate refs/tags/uncommitted {}\nprepare\n", ids[0]),
            false,
        ));
        success(input(
            root,
            is_native,
            &format!(
                "start\ncreate refs/tags/aborted {}\nprepare\nabort\n",
                ids[0]
            ),
            false,
        ));
        success(input(
            root,
            is_native,
            &format!(
                "update refs/tags/release\0{}\0{}\0verify refs/tags/missing\0\0",
                ids[0], ids[1]
            ),
            true,
        ));
        success(input(
            root,
            is_native,
            &format!("update refs/tags/release {zero} {}\n", ids[0]),
            false,
        ));
        let query = |name: &str| {
            if is_native {
                uw(&["rev-parse", p(root), name])
            } else {
                git(root, &["rev-parse", "--verify", name])
            }
        };
        for name in [
            "refs/tags/old",
            "refs/tags/rejected",
            "refs/tags/uncommitted",
            "refs/tags/aborted",
            "refs/tags/release",
        ] {
            assert!(!query(name).status.success(), "{name}");
        }
        assert_eq!(
            String::from_utf8(success(query("refs/heads/topic")))
                .unwrap()
                .trim(),
            ids[1]
        );
        // Compare actual original Wasm bytes, not unrelated native/Git hashes.
        if is_native {
            let exported = temp.path("exported.wasm");
            success(uw(&[
                "show",
                p(root),
                "topic",
                "--file",
                "a.wasm",
                "--output",
                p(&exported),
            ]));
            assert_eq!(fs::read(exported).unwrap(), wasm(2));
        } else {
            assert_eq!(success(git(root, &["show", "topic:a.wasm"])), wasm(2));
        }
    }
}

#[test]
fn native_partial_reference_batches_match_git_rejections_control_and_final_ref_values() {
    let temp = Temp::new();
    let native = temp.path("native-partial");
    let reference = temp.path("git-partial");
    success(uw(&["init", p(&native)]));
    fs::create_dir(&reference).unwrap();
    success(git(&reference, &["init", "-b", "main"]));
    let (mut native_ids, mut git_ids) = (Vec::new(), Vec::new());
    for value in [1, 2] {
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
    let tree: Value =
        serde_json::from_slice(&success(uw(&["ls-tree", p(&native), "HEAD"]))).unwrap();
    let native_wrong_type = tree["entries"][0]["object_id"].as_str().unwrap();
    let git_wrong_type =
        String::from_utf8(success(git(&reference, &["rev-parse", "HEAD^{tree}"]))).unwrap();
    let cases=[
        ("missing", "create refs/tags/accepted SECOND\nupdate refs/heads/missing FIRST SECOND\n",false,true),
        ("wrong-old", "create refs/tags/accepted SECOND\nupdate refs/heads/topic FIRST FIRST\n",false,true),
        ("existing", "create refs/tags/accepted SECOND\ncreate refs/heads/topic FIRST\n",false,true),
        ("missing-object", "create refs/tags/accepted SECOND\ncreate refs/heads/bad ABSENT\n",false,true),
        ("wrong-type", "create refs/tags/accepted SECOND\ncreate refs/heads/bad TYPE\n",false,true),
        ("two-new", "create refs/heads/new/child FIRST\ncreate refs/heads/new SECOND\ncreate refs/tags/accepted SECOND\n",false,true),
        ("existing-prefix", "create refs/heads/existing FIRST\nupdate refs/heads/existing/child SECOND FIRST\n",false,true),
        ("delete", "delete refs/tags/obsolete FIRST\nupdate refs/heads/missing FIRST SECOND\n",false,true),
        ("prepared-abort", "start\ncreate refs/tags/accepted SECOND\nupdate refs/heads/missing FIRST SECOND\nprepare\nabort\n",false,true),
        ("prepared-eof", "create refs/tags/accepted SECOND\nupdate refs/heads/missing FIRST SECOND\nprepare\n",false,true),
        ("start-adopts-eof", "create refs/tags/accepted SECOND\nupdate refs/heads/missing FIRST SECOND\nstart\n",false,true),
        ("start-adopts-commit", "create refs/tags/accepted SECOND\nupdate refs/heads/missing FIRST SECOND\nstart\ncommit\n",false,true),
        ("prepared-commit", "start\ncreate refs/tags/accepted SECOND\nupdate refs/heads/missing FIRST SECOND\nprepare\ncommit\n",false,true),
        ("nul", "create refs/tags/accepted\0SECOND\0update refs/heads/missing\0FIRST\0SECOND\0",true,true),
        ("invalid-revision", "create refs/tags/accepted SECOND\ncreate refs/heads/bad no-such-revision\n",false,false),
        ("duplicate", "create refs/tags/accepted SECOND\ncreate refs/tags/accepted FIRST\n",false,false),
        ("zero-create", "create refs/tags/accepted SECOND\ncreate refs/tags/zero ZERO\n",false,false),
    ];
    for (case, template, nul, expected_success) in cases {
        let mut observations = Vec::new();
        for (root, is_native, ids, width, wrong_type) in [
            (&native, true, &native_ids, 64, native_wrong_type),
            (&reference, false, &git_ids, 40, git_wrong_type.trim()),
        ] {
            let all_refs = if is_native {
                success(uw(&["show-ref", p(root)]))
            } else {
                success(git(root, &["show-ref"]))
            };
            for line in String::from_utf8(all_refs).unwrap().lines() {
                let name = line.split_once(' ').unwrap().1;
                if name == "refs/heads/main" {
                    continue;
                }
                if is_native {
                    success(uw(&["update-ref", p(root), "-d", name]));
                } else {
                    success(git(root, &["update-ref", "-d", name]));
                }
            }
            for (name, id) in [
                ("refs/heads/topic", &ids[1]),
                ("refs/heads/existing/child", &ids[0]),
                ("refs/tags/obsolete", &ids[0]),
            ] {
                if is_native {
                    success(uw(&["update-ref", p(root), name, id]));
                } else {
                    success(git(root, &["update-ref", name, id]));
                }
            }
            let zero = "0".repeat(width);
            let absent = "f".repeat(width);
            let records = template
                .replace("FIRST", &ids[0])
                .replace("SECOND", &ids[1])
                .replace("ZERO", &zero)
                .replace("ABSENT", &absent)
                .replace("TYPE", wrong_type);
            let outcome = reference_updates(root, is_native, &records, nul, true);
            assert_eq!(
                outcome.status.success(),
                expected_success,
                "{case}, native={is_native}: {}",
                String::from_utf8_lossy(&outcome.stderr)
            );
            let normalize = |value: Vec<u8>| {
                String::from_utf8(value)
                    .unwrap()
                    .replace(&ids[0], "FIRST")
                    .replace(&ids[1], "SECOND")
                    .replace(wrong_type, "TYPE")
                    .replace(&zero, "ZERO")
                    .replace(&absent, "ABSENT")
            };
            let refs = if is_native {
                success(uw(&["show-ref", p(root)]))
            } else {
                success(git(root, &["show-ref"]))
            };
            observations.push((normalize(outcome.stdout), normalize(refs)));
            assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
        }
        assert_eq!(observations[0], observations[1], "{case}");
    }
}

#[test]
fn native_head_transactions_match_git_symbolic_oid_leases_and_pointer_only_outcomes() {
    let temp = Temp::new();
    let native = temp.path("native-head-refs");
    let reference = temp.path("git-head-refs");
    success(uw(&["init", p(&native)]));
    fs::create_dir(&reference).unwrap();
    success(git(&reference, &["init", "-b", "main"]));
    let (mut native_ids, mut git_ids) = (Vec::new(), Vec::new());
    for value in [1, 2] {
        for root in [&native, &reference] {
            fs::write(root.join("a.wasm"), wasm(value)).unwrap();
        }
        success(uw(&["add", p(&native), "a.wasm"]));
        success(uw(&[
            "commit",
            p(&native),
            "-m",
            &format!("head value {value}"),
        ]));
        native_ids.push(
            String::from_utf8(success(uw(&["rev-parse", p(&native), "HEAD"])))
                .unwrap()
                .trim()
                .to_owned(),
        );
        success(git(&reference, &["add", "a.wasm"]));
        success(git(
            &reference,
            &["commit", "-m", &format!("head value {value}")],
        ));
        git_ids.push(
            String::from_utf8(success(git(&reference, &["rev-parse", "HEAD"])))
                .unwrap()
                .trim()
                .to_owned(),
        );
    }
    let cases=[
        ("target-lease","symbolic","symref-update HEAD refs/heads/topic ref refs/heads/main\n",false,true,true),
        ("oid-lease","symbolic","symref-update HEAD refs/heads/topic oid SECOND\n",false,true,true),
        ("wrong-target","symbolic","symref-update HEAD refs/heads/topic ref refs/heads/wrong\n",false,true,true),
        ("wrong-oid","symbolic","symref-update HEAD refs/heads/topic oid FIRST\n",false,true,true),
        ("verify","symbolic","symref-verify HEAD refs/heads/main\n",false,true,true),
        ("verify-wrong","symbolic","symref-verify HEAD refs/heads/topic\n",false,true,true),
        ("verify-detached","detached","symref-verify HEAD refs/heads/main\n",false,true,true),
        ("detached-target","detached","symref-update HEAD refs/heads/topic ref refs/heads/main\n",false,true,true),
        ("reattach-oid","detached","symref-update HEAD refs/heads/topic oid FIRST\n",false,true,true),
        ("detach","symbolic","update HEAD FIRST SECOND\n",false,true,true),
        ("verify-oid","symbolic","verify HEAD SECOND\n",false,true,true),
        ("unborn-verify","unborn","verify HEAD ZERO\n",false,true,true),
        ("unborn-attach","unborn","symref-update HEAD refs/heads/topic oid ZERO\n",false,true,true),
        ("unborn-retarget","unborn","symref-update HEAD refs/heads/another ref refs/heads/unborn\n",false,true,true),
        ("create-and-attach","symbolic","create refs/heads/reviewed FIRST\nsymref-update HEAD refs/heads/reviewed ref refs/heads/main\n",false,true,true),
        ("final-destination-tip","symbolic","update refs/heads/topic SECOND FIRST\nsymref-update HEAD refs/heads/topic ref refs/heads/main\n",false,true,true),
        ("abort","symbolic","start\ncreate refs/tags/reviewed FIRST\nsymref-update HEAD refs/heads/topic ref refs/heads/main\nprepare\nabort\n",false,true,true),
        ("prepared-eof","symbolic","create refs/tags/reviewed FIRST\nsymref-update HEAD refs/heads/topic ref refs/heads/main\nprepare\n",false,true,true),
        ("partial-commit","symbolic","start\ncreate refs/tags/reviewed FIRST\nsymref-update HEAD refs/heads/topic ref refs/heads/wrong\nprepare\ncommit\n",false,true,true),
        ("nul-target","symbolic","symref-update HEAD\0refs/heads/topic\0ref\0refs/heads/main\0",true,true,true),
        ("nul-unleased","symbolic","symref-update HEAD\0refs/heads/topic\0\0\0",true,true,true),
        ("one-option","symbolic","option no-deref\nsymref-update HEAD refs/heads/topic ref refs/heads/main\n",false,true,false),
        ("bad-mode","symbolic","create refs/tags/reviewed FIRST\nsymref-update HEAD refs/heads/topic invalid refs/heads/main\n",false,false,true),
        ("verify-needs-no-deref","symbolic","symref-verify HEAD refs/heads/main\n",false,false,false),
    ];
    for (case, initial, template, nul, expected_success, no_deref) in cases {
        let mut observations = Vec::new();
        for (root, is_native, ids, width) in [
            (&native, true, &native_ids, 64),
            (&reference, false, &git_ids, 40),
        ] {
            if is_native {
                success(uw(&["symbolic-ref", p(root), "HEAD", "refs/heads/main"]));
            } else {
                success(git(root, &["symbolic-ref", "HEAD", "refs/heads/main"]));
            }
            let refs = if is_native {
                success(uw(&["show-ref", p(root)]))
            } else {
                success(git(root, &["show-ref"]))
            };
            for line in String::from_utf8(refs).unwrap().lines() {
                let name = line.split_once(' ').unwrap().1;
                if name == "refs/heads/main" {
                    continue;
                }
                if is_native {
                    success(uw(&["update-ref", p(root), "-d", name]));
                } else {
                    success(git(root, &["update-ref", "-d", name]));
                }
            }
            if is_native {
                success(uw(&["update-ref", p(root), "refs/heads/topic", &ids[0]]));
            } else {
                success(git(root, &["update-ref", "refs/heads/topic", &ids[0]]));
            }
            if initial == "detached" {
                if is_native {
                    success(uw(&["update-ref", p(root), "--no-deref", "HEAD", &ids[0]]));
                } else {
                    success(git(root, &["update-ref", "--no-deref", "HEAD", &ids[0]]));
                }
            } else if initial == "unborn" {
                if is_native {
                    success(uw(&["symbolic-ref", p(root), "HEAD", "refs/heads/unborn"]));
                } else {
                    success(git(root, &["symbolic-ref", "HEAD", "refs/heads/unborn"]));
                }
            }
            let native_index = if is_native {
                Some(fs::read(root.join(".uwgit/index")).unwrap())
            } else {
                None
            };
            let records = template
                .replace("FIRST", &ids[0])
                .replace("SECOND", &ids[1])
                .replace("ZERO", &"0".repeat(width));
            let output =
                reference_updates_with_flags(root, is_native, &records, nul, true, no_deref);
            assert_eq!(
                output.status.success(),
                expected_success,
                "{case}, native={is_native}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let response = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(|line| {
                    if line.starts_with("rejected ") {
                        let fields = line.splitn(5, ' ').collect::<Vec<_>>();
                        format!("rejected {} {}", fields[1], fields[4])
                    } else {
                        line.into()
                    }
                })
                .collect::<Vec<String>>();
            let head = fs::read_to_string(root.join(if is_native {
                ".uwgit/HEAD"
            } else {
                ".git/HEAD"
            }))
            .unwrap();
            let head = head.trim();
            let identity = if is_native && !ids.iter().any(|id| id == head) {
                format!("refs/heads/{head}")
            } else {
                head.strip_prefix("ref: ").unwrap_or(head).into()
            };
            let refs = if is_native {
                success(uw(&["show-ref", p(root)]))
            } else {
                success(git(root, &["show-ref"]))
            };
            let normalize =
                |value: String| value.replace(&ids[0], "FIRST").replace(&ids[1], "SECOND");
            observations.push((
                response,
                normalize(identity),
                normalize(String::from_utf8(refs).unwrap()),
            ));
            assert_eq!(fs::read(root.join("a.wasm")).unwrap(), wasm(2));
            if let Some(index) = native_index {
                assert_eq!(fs::read(root.join(".uwgit/index")).unwrap(), index);
            }
        }
        assert_eq!(observations[0], observations[1], "{case}");
    }
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

#[test]
fn recorded_merge_and_rebase_match_real_git_conflict_sides_clean_paths_and_parent_counts() {
    for operation in ["merge", "rebase"] {
        let t = Temp::new();
        let native = t.path("native");
        let reference = t.path("reference");
        fs::create_dir(&reference).unwrap();
        success(git(&reference, &["init", "-b", "main"]));
        success(uw(&["init", p(&native)]));
        for root in [&native, &reference] {
            fs::write(root.join("a.wasm"), wasm(1)).unwrap();
            fs::write(root.join("gone.wasm"), wasm(1)).unwrap();
        }
        let commit = |message: &str| {
            success(uw(&["add", p(&native), "-A"]));
            success(uw(&["commit", p(&native), "-m", message]));
            success(git(&reference, &["add", "-A"]));
            success(git(&reference, &["commit", "-m", message]));
        };
        commit("base");
        success(uw(&["branch", p(&native), "source"]));
        success(git(&reference, &["branch", "source"]));
        success(uw(&["switch", p(&native), "source"]));
        success(git(&reference, &["switch", "source"]));
        for root in [&native, &reference] {
            fs::write(root.join("a.wasm"), wasm(2)).unwrap();
            fs::write(root.join("incoming.wasm"), wasm(8)).unwrap();
            fs::remove_file(root.join("gone.wasm")).unwrap();
        }
        commit("incoming");
        success(uw(&["switch", p(&native), "main"]));
        success(git(&reference, &["switch", "main"]));
        for root in [&native, &reference] {
            fs::write(root.join("a.wasm"), wasm(3)).unwrap();
            fs::write(root.join("local.wasm"), wasm(9)).unwrap();
        }
        commit("local");
        if operation == "rebase" {
            success(uw(&["switch", p(&native), "source"]));
            success(git(&reference, &["switch", "source"]));
        }
        let target = if operation == "merge" {
            "source"
        } else {
            "main"
        };
        let head = success(uw(&["rev-parse", p(&native), "HEAD"]));
        let stopped = if operation == "merge" {
            uw(&[
                operation,
                p(&native),
                target,
                "--record-conflict",
                "-m",
                "reviewed merge",
            ])
        } else {
            uw(&[operation, p(&native), target, "--record-conflict"])
        };
        assert_eq!(
            stopped.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&stopped.stderr)
        );
        assert_eq!(success(uw(&["rev-parse", p(&native), "HEAD"])), head);
        let stopped = if operation == "merge" {
            git(&reference, &["merge", "--no-edit", target])
        } else {
            git(&reference, &["rebase", target])
        };
        assert_eq!(stopped.status.code(), Some(1));
        let native_rows: Value = serde_json::from_slice(&success(uw(&[
            "ls-files",
            p(&native),
            "--unmerged",
            "--json",
        ])))
        .unwrap();
        let reference_rows =
            String::from_utf8(success(git(&reference, &["ls-files", "--unmerged"]))).unwrap();
        let rows = native_rows["entries"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        for (native_row, reference_row) in rows.iter().zip(reference_rows.lines()) {
            let fields = reference_row.split_whitespace().collect::<Vec<_>>();
            assert_eq!(native_row["stage"].as_u64().unwrap().to_string(), fields[2]);
            assert_eq!(native_row["path"], fields[3]);
            let out = t.path(&format!("side-{}", fields[2]));
            success(uw(&[
                "cat-file",
                p(&native),
                native_row["object_id"].as_str().unwrap(),
                "--output",
                p(&out),
            ]));
            assert_eq!(
                fs::read(out).unwrap(),
                success(git(&reference, &["cat-file", "blob", fields[1]]))
            );
        }
        for path in ["incoming.wasm", "local.wasm"] {
            assert_eq!(
                fs::read(native.join(path)).unwrap(),
                fs::read(reference.join(path)).unwrap()
            );
        }
        assert!(!native.join("gone.wasm").exists());
        assert!(!reference.join("gone.wasm").exists());
        for root in [&native, &reference] {
            fs::write(root.join("a.wasm"), wasm(4)).unwrap();
        }
        success(uw(&["add", p(&native), "a.wasm"]));
        success(git(&reference, &["add", "a.wasm"]));
        success(uw(&[
            operation,
            p(&native),
            "--continue",
            "--resolved-index",
        ]));
        if operation == "merge" {
            success(git(&reference, &["commit", "-m", "reviewed merge"]));
        } else {
            success(git(
                &reference,
                &["-c", "core.editor=true", "rebase", "--continue"],
            ));
        }
        let commit: Value =
            serde_json::from_slice(&success(uw(&["show", p(&native), "HEAD"]))).unwrap();
        let parents = String::from_utf8(success(git(
            &reference,
            &["rev-list", "--parents", "-n", "1", "HEAD"],
        )))
        .unwrap();
        assert_eq!(
            commit["parents"].as_array().unwrap().len(),
            parents.split_whitespace().count() - 1
        );
        for path in ["a.wasm", "incoming.wasm", "local.wasm"] {
            assert_eq!(
                fs::read(native.join(path)).unwrap(),
                fs::read(reference.join(path)).unwrap()
            );
        }
        assert!(!native.join("gone.wasm").exists());
        success(uw(&["fsck", p(&native)]));
        success(git(&reference, &["fsck", "--full"]));
    }
}
