//! Independent graph expectations and real-Git reference checks use equivalent
//! topologies, never compatible objects or a Git backend inside the product.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    native: PathBuf,
    git: PathBuf,
    native_tree: String,
    git_tree: String,
    nodes: BTreeMap<String, (String, String)>,
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn text(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-graph-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let native = root.join("native");
        let git = root.join("git");
        fs::create_dir(&git).unwrap();
        let mut fixture = Self {
            root,
            native,
            git,
            native_tree: String::new(),
            git_tree: String::new(),
            nodes: BTreeMap::new(),
        };
        text(
            Command::new(env!("CARGO_BIN_EXE_wasm-git"))
                .args(["init", p(&fixture.native)])
                .output()
                .unwrap(),
        );
        text(fixture.git(&["init", "-b", "main"]));
        fixture.native_tree = text(fixture.uw(&["mktree"]));
        fixture.git_tree = text(fixture.git(&["mktree"]));
        fixture
    }
    fn uw(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wasm-git"))
            .arg(args[0])
            .arg(&self.native)
            .args(&args[1..])
            .output()
            .unwrap()
    }
    fn git(&self, args: &[&str]) -> Output {
        Command::new("git")
            .arg("-C")
            .arg(&self.git)
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
    fn node(&mut self, label: &str, parents: &[&str]) {
        let mut uw = vec!["commit-tree", self.native_tree.as_str(), "-m", label];
        let mut git = vec!["commit-tree", self.git_tree.as_str(), "-m", label];
        for parent in parents {
            let (u, g) = &self.nodes[*parent];
            uw.extend(["-p", u]);
            git.extend(["-p", g]);
        }
        let pair = (text(self.uw(&uw)), text(self.git(&git)));
        assert!(self.nodes.insert(label.into(), pair).is_none());
    }
    fn id(&self, label: &str) -> &str {
        &self.nodes[label].0
    }
    fn publish(&self, branch: &str, label: &str) {
        let reference = format!("refs/heads/{branch}");
        text(self.uw(&["update-ref", &reference, self.id(label)]));
        text(self.git(&["update-ref", &reference, &self.nodes[label].1]));
    }
    fn graph(&mut self) {
        for (label, parents) in [
            ("root", vec![]),
            ("x", vec!["root"]),
            ("y", vec!["root"]),
            ("left", vec!["x", "y"]),
            ("right", vec!["y", "x"]),
            ("later", vec!["left"]),
            ("other", vec![]),
        ] {
            self.node(label, &parents);
        }
    }
    fn labels(&self, output: Output, native: bool) -> BTreeSet<String> {
        assert!(
            matches!(output.status.code(), Some(0 | 1)),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|id| {
                self.nodes
                    .iter()
                    .find(|(_, pair)| if native { pair.0 == id } else { pair.1 == id })
                    .unwrap()
                    .0
                    .clone()
            })
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn metadata(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), result);
            } else {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().into(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

#[test]
fn criss_cross_multiple_bases_and_ancestor_exit_codes_are_read_only() {
    let mut f = Fixture::new();
    f.graph();
    fs::write(
        f.native.join(".uwgit/index"),
        b"unrelated invalid index bytes",
    )
    .unwrap();
    fs::write(f.native.join("a.wasm"), b"untracked original bytes").unwrap();
    let before = metadata(&f.native);
    let bases: Vec<String> =
        serde_json::from_str(&text(f.uw(&["merge-base", f.id("left"), f.id("right")]))).unwrap();
    assert_eq!(
        bases.into_iter().collect::<BTreeSet<_>>(),
        [f.id("x").to_owned(), f.id("y").to_owned()].into()
    );
    assert_eq!(
        f.labels(
            f.uw(&["merge-base", "--all", f.id("left"), f.id("right")]),
            true
        ),
        ["x".into(), "y".into()].into()
    );
    assert!(
        matches!(text(f.uw(&["merge-base", "--text", f.id("left"), f.id("right")])).as_str(), id if id == f.id("x") || id == f.id("y"))
    );
    assert_eq!(
        f.uw(&["merge-base", "--is-ancestor", f.id("root"), f.id("later")])
            .status
            .code(),
        Some(0)
    );
    for args in [
        vec!["--is-ancestor", f.id("left"), f.id("right")],
        vec!["--all", f.id("root"), f.id("other")],
    ] {
        let output = f.uw(&[&["merge-base"], args.as_slice()].concat());
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for args in [
        vec!["--is-ancestor", "missing", f.id("root")],
        vec!["--all", "--independent", f.id("root")],
        vec!["--octopus", "--fork-point", "topic"],
        vec!["--is-ancestor", f.id("root")],
    ] {
        let output = f.uw(&[&["merge-base"], args.as_slice()].concat());
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(metadata(&f.native), before);
}

#[test]
fn hypothetical_multi_tip_octopus_and_independent_queries_use_actual_ancestry() {
    let mut f = Fixture::new();
    f.graph();
    assert_eq!(
        text(f.uw(&[
            "merge-base",
            "--text",
            f.id("later"),
            f.id("left"),
            f.id("other")
        ])),
        f.id("left")
    );
    let octopus = f.uw(&[
        "merge-base",
        "--octopus",
        f.id("later"),
        f.id("left"),
        f.id("other"),
    ]);
    assert_eq!(octopus.status.code(), Some(1));
    assert!(octopus.stdout.is_empty());
    assert_eq!(
        text(f.uw(&["merge-base", "--octopus", f.id("x")])),
        f.id("x")
    );
    assert_eq!(
        f.labels(
            f.uw(&[
                "merge-base",
                "--independent",
                f.id("root"),
                f.id("left"),
                f.id("later"),
                f.id("right"),
                f.id("later")
            ]),
            true
        ),
        ["later".into(), "right".into()].into()
    );
    assert_eq!(
        f.uw(&["merge-base", "--independent"]).status.code(),
        Some(1)
    );
}

#[test]
fn reflog_fork_points_require_a_unique_witnessed_reference_tip() {
    let mut f = Fixture::new();
    f.node("root", &[]);
    f.node("old", &["root"]);
    f.node("rewritten", &["root"]);
    f.node("topic", &["old"]);
    f.node("from-root", &["root"]);
    f.node("both", &["old", "rewritten"]);
    f.publish("upstream", "old");
    f.publish("upstream", "rewritten");
    f.publish("topic", "topic");
    text(f.uw(&["symbolic-ref", "HEAD", "refs/heads/topic"]));
    text(f.git(&["symbolic-ref", "HEAD", "refs/heads/topic"]));
    let before = metadata(&f.native);
    for (args, git_args, expected) in [
        (
            vec!["--fork-point", "upstream", f.id("topic")],
            vec!["--fork-point", "upstream", f.nodes["topic"].1.as_str()],
            Some("old"),
        ),
        (
            vec!["--fork-point", "refs/heads/upstream"],
            vec!["--fork-point", "refs/heads/upstream"],
            Some("old"),
        ),
        (
            vec!["--fork-point", "upstream", f.id("from-root")],
            vec!["--fork-point", "upstream", f.nodes["from-root"].1.as_str()],
            None,
        ),
        (
            vec!["--fork-point", "upstream", f.id("both")],
            vec!["--fork-point", "upstream", f.nodes["both"].1.as_str()],
            None,
        ),
    ] {
        let native = f.uw(&[&["merge-base"], args.as_slice()].concat());
        let reference = f.git(&[&["merge-base"], git_args.as_slice()].concat());
        assert_eq!(native.status.code(), reference.status.code());
        let expected: BTreeSet<String> = expected.into_iter().map(str::to_owned).collect();
        assert_eq!(f.labels(native, true), expected);
        assert_eq!(f.labels(reference, false), expected);
    }
    assert_eq!(
        text(f.uw(&["merge-base", "--text", "upstream", f.id("topic")])),
        f.id("root")
    );
    let invalid = f.uw(&["merge-base", "--fork-point", f.id("old"), f.id("topic")]);
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(metadata(&f.native), before);
}

#[test]
fn independent_git_reference_matches_all_pair_bases_ancestry_and_symmetric_sets() {
    let mut f = Fixture::new();
    f.graph();
    let before = metadata(&f.native);
    for (left, native_left, git_left) in f.nodes.iter().map(|(name, pair)| (name, &pair.0, &pair.1))
    {
        for (right, (native_right, git_right)) in &f.nodes {
            let native = f.uw(&["merge-base", "--all", native_left, native_right]);
            let reference = f.git(&["merge-base", "--all", git_left, git_right]);
            assert_eq!(
                native.status.code(),
                reference.status.code(),
                "{left} {right}"
            );
            assert_eq!(
                f.labels(native, true),
                f.labels(reference, false),
                "{left} {right}"
            );
            assert_eq!(
                f.uw(&["merge-base", "--is-ancestor", native_left, native_right])
                    .status
                    .code(),
                f.git(&["merge-base", "--is-ancestor", git_left, git_right])
                    .status
                    .code(),
                "{left} {right}"
            );
            assert_eq!(
                f.labels(
                    f.uw(&["rev-list", &format!("{native_left}...{native_right}")]),
                    true
                ),
                f.labels(
                    f.git(&["rev-list", &format!("{git_left}...{git_right}")]),
                    false
                ),
                "{left} {right}"
            );
        }
    }
    assert_eq!(metadata(&f.native), before);
}

#[test]
fn corrupt_graph_and_malformed_symmetric_ranges_fail_without_publication() {
    let mut f = Fixture::new();
    f.graph();
    for range in [
        format!("{}....{}", f.id("left"), f.id("right")),
        format!("{}...missing", f.id("left")),
    ] {
        assert!(!f.uw(&["rev-list", &range]).status.success());
    }
    fs::remove_file(f.native.join(".uwgit/objects").join(f.id("root"))).unwrap();
    let before = metadata(&f.native);
    let output = f.uw(&["merge-base", "--is-ancestor", f.id("left"), f.id("right")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(metadata(&f.native), before);
}
