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

fn query_graph() -> Fixture {
    let mut f = Fixture::new();
    f.graph();
    for (name, label) in [
        ("Base", "root"),
        ("alpha", "x"),
        ("beta", "y"),
        ("release/Left", "left"),
        ("release/right", "right"),
        ("main", "later"),
        ("unrelated", "other"),
    ] {
        if name == "main" {
            // Native update-ref protects the checked-out branch, including an
            // unborn one. Establish its tip through the supported HEAD reset.
            text(f.uw(&["reset", "--soft", f.id(label)]));
            text(f.git(&["update-ref", "refs/heads/main", &f.nodes[label].1]));
        } else {
            f.publish(name, label);
        }
    }
    for (name, label) in [("base", "root"), ("release", "later")] {
        let name = format!("refs/tags/{name}");
        text(f.uw(&["update-ref", &name, f.id(label)]));
        text(f.git(&["update-ref", &name, &f.nodes[label].1]));
    }
    f
}

fn query_text(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn native_reference_selection_matches_independent_git_dag_filters_for_both_commands() {
    let f = query_graph();
    let before = metadata(&f.native);
    let filters = [
        vec!["--contains", "alpha"],
        vec!["--no-contains", "beta"],
        vec!["--merged", "main"],
        vec!["--no-merged", "release/Left"],
        vec!["--contains", "alpha", "--contains", "beta"],
        vec!["--contains", "Base", "--contains", "unrelated"],
        vec!["--no-contains", "alpha", "--no-contains", "beta"],
        vec!["--merged", "alpha", "--merged", "beta"],
        vec!["--no-merged", "alpha", "--no-merged", "beta"],
        vec!["--contains", "alpha", "--no-contains", "beta"],
        vec!["--merged", "main", "--no-merged", "beta"],
        vec!["--points-at", "main"],
        vec!["--points-at", "Base", "--points-at", "beta"],
        vec!["--contains=refs/tags/base", "--points-at=main"],
        vec!["--contains"],
        vec!["--no-contains"],
        vec!["--merged"],
        vec!["--no-merged"],
        vec!["--contains=main^2"],
        vec![
            "--contains=main^",
            "--contains=unrelated",
            "--no-merged=beta",
        ],
    ];
    for command in ["for-each-ref", "branch"] {
        for filter in &filters {
            let mut args = vec![command, "--format=%(refname)"];
            args.extend_from_slice(filter);
            // main has only one parent; a malformed ancestor must fail even
            // when subsequent output selection would otherwise be empty.
            if filter == &["--contains=main^2"] {
                assert!(!f.uw(&args).status.success());
                assert!(!f.git(&args).status.success());
            } else {
                assert_eq!(
                    query_text(f.uw(&args)),
                    query_text(f.git(&args)),
                    "{args:?}"
                );
            }
            assert_eq!(metadata(&f.native), before);
        }
    }
}

#[test]
fn graph_filters_have_fixed_native_expectations_including_both_merge_parents() {
    let f = query_graph();
    for (filter, names) in [
        (
            vec!["--contains", "alpha"],
            vec!["alpha", "main", "release/Left", "release/right"],
        ),
        (
            vec!["--no-contains", "alpha"],
            vec!["Base", "beta", "unrelated"],
        ),
        (
            vec!["--merged", "release/Left"],
            vec!["Base", "alpha", "beta", "release/Left"],
        ),
        (
            vec!["--no-merged", "release/Left"],
            vec!["main", "release/right", "unrelated"],
        ),
        (
            vec!["--merged", "release/Left", "--no-merged", "release/right"],
            vec!["release/Left"],
        ),
        (
            vec!["--contains", "alpha", "--no-contains", "beta"],
            vec!["alpha"],
        ),
        (
            vec!["--contains", "Base", "--contains", "unrelated"],
            vec![
                "Base",
                "alpha",
                "beta",
                "main",
                "release/Left",
                "release/right",
                "unrelated",
            ],
        ),
    ] {
        let mut args = vec!["branch", "--list", "--format=%(refname:lstrip=2)"];
        args.extend(filter);
        let expected = names
            .iter()
            .map(|name| format!("{name}\n"))
            .collect::<String>();
        assert_eq!(query_text(f.uw(&args)), expected, "{args:?}");
    }
}

#[test]
fn graph_query_name_formats_case_sort_exclusions_and_omitted_empty_match_git() {
    let f = query_graph();
    f.publish("Alpha", "y");
    f.publish("topic/deep/leaf", "later");
    for command in ["for-each-ref", "branch"] {
        let queries = [
            vec!["--format=%(HEAD)|%(refname:short)|%(refname:lstrip=1)|%(refname:rstrip=1)"],
            vec!["--format=%(refname:lstrip=-2)|%(refname:rstrip=-2)|%(refname:strip=2)"],
            vec!["--format=%(refname:lstrip=100)|%(refname:rstrip=-100)"],
            vec!["--format=%(refname)", "--ignore-case", "--sort=refname"],
            vec!["--format=%(refname)", "--sort=-refname"],
            vec![
                "--format=%(refname)",
                "--sort=refname:lstrip=2",
                "--sort=HEAD",
            ],
            vec!["--format=", "--omit-empty"],
            vec!["--format=%(upstream)", "--omit-empty"],
            vec!["--format=%%:%00:%09:%0a:%(refname)"],
        ];
        for query in queries {
            let mut args = vec![command];
            args.extend(query);
            assert_eq!(
                query_text(f.uw(&args)),
                query_text(f.git(&args)),
                "{args:?}"
            );
        }
    }
    for query in [
        vec!["--exclude=refs/tags"],
        vec!["--exclude=refs/heads/release/*", "--exclude=refs/tags/base"],
        vec![
            "--ignore-case",
            "--exclude=REFS/HEADS/ALPHA",
            "refs/HEADS/*",
        ],
        vec!["--count=2", "--contains=Base", "--sort=-refname"],
        vec!["refs/heads/*"],
        vec!["refs/heads/**"],
        vec!["refs/heads/**/leaf"],
        vec!["refs/heads/release**"],
        vec!["refs/heads/release/**"],
        vec!["refs/heads/release*/*"],
        vec!["refs/heads/*/*/*"],
        vec!["refs/heads/{alpha,beta}"],
    ] {
        let mut args = vec!["for-each-ref", "--format=%(refname)"];
        args.extend(query);
        assert_eq!(
            query_text(f.uw(&args)),
            query_text(f.git(&args)),
            "{args:?}"
        );
    }
    for query in [
        vec!["--list", "release/*"],
        vec!["--list", "--ignore-case", "ALPHA"],
        vec!["--list", "--", "topic/*", "unrelated"],
        vec!["--contains=Base", "release/*"],
    ] {
        let mut args = vec!["branch", "--format=%(refname)"];
        args.extend(query);
        assert_eq!(
            query_text(f.uw(&args)),
            query_text(f.git(&args)),
            "{args:?}"
        );
    }
}

#[test]
fn native_query_short_names_stay_qualified_when_other_refs_or_objects_are_ambiguous() {
    let f = query_graph();
    text(f.uw(&["tag", "alpha", "main"]));
    // A stored commit prefix also competes with a branch even if that commit
    // has no visible ref. Name filtering must not erase either ambiguity.
    let prefix = &f.id("other")[..8];
    text(f.uw(&["branch", prefix, "main"]));
    for name in ["alpha", prefix] {
        let full = format!("refs/heads/{name}");
        assert_eq!(
            query_text(f.uw(&["for-each-ref", "--format=%(refname:short)", &full])),
            format!("{full}\n")
        );
        assert_eq!(
            query_text(f.uw(&["branch", "--list", "--format=%(refname:short)", name])),
            format!("{full}\n")
        );
    }
}

#[test]
fn branch_query_defaults_detached_unborn_heads_and_bad_operands_are_read_only() {
    let f = Fixture::new();
    assert_eq!(query_text(f.uw(&["branch", "--show-current"])), "main\n");
    assert_eq!(query_text(f.uw(&["branch", "--list"])), "");
    let failed = f.uw(&["for-each-ref", "--contains", "--format=%(refname)"]);
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    let f = query_graph();
    text(f.uw(&["switch", "--detach", "main"]));
    assert_eq!(query_text(f.uw(&["branch", "--show-current"])), "");
    let before = metadata(&f.native);
    assert!(!query_text(f.uw(&["branch", "--list", "--format=%(HEAD)"])).contains('*'));
    for command in ["branch", "for-each-ref"] {
        for bad in [
            "--contains=missing",
            "--points-at=missing",
            "--contains=",
            "--sort=authordate",
            "--format=%(author)",
            "--format=%(refname:lstrip=9223372036854775808)",
        ] {
            let out = f.uw(&[command, bad]);
            assert!(!out.status.success(), "{command} {bad}");
            assert!(out.stdout.is_empty());
            assert_eq!(metadata(&f.native), before);
        }
        let args = [
            command,
            "--format=%(refname)",
            "--contains=missing",
            "no-match",
        ];
        assert!(!f.uw(&args).status.success());
    }
    assert_eq!(metadata(&f.native), before);
}

#[test]
fn native_point_queries_accept_real_noncommit_objects_without_inventing_matching_refs() {
    let f = query_graph();
    for (native, tree) in [(true, &f.native_tree), (false, &f.git_tree)] {
        for command in ["branch", "for-each-ref"] {
            let args = [command, "--points-at", tree, "--format=%(refname)"];
            assert_eq!(
                query_text(if native { f.uw(&args) } else { f.git(&args) }),
                ""
            );
        }
    }
    assert_eq!(
        query_text(f.uw(&["for-each-ref", "--points-at=HEAD^{tree}"])),
        ""
    );
    assert_eq!(
        query_text(f.uw(&["for-each-ref", "--points-at", &f.native_tree[..12]])),
        ""
    );
    let out = f.uw(&["for-each-ref", "--merged", &f.native_tree]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn native_remote_branch_views_match_git_namespace_and_displayed_name_filters() {
    let f = query_graph();
    let url = "ssh://test@localhost/tmp/ref-query.git";
    text(f.uw(&["remote", "add", "origin", url]));
    fs::write(f.native.join(".uwgit/remotes/origin.tracking.json"),serde_json::to_vec(&serde_json::json!({"version":1,"remote":"origin","url":url,"state":{"format":1,"head":"main","branches":{"main":f.id("right")},"tags":{}}})).unwrap()).unwrap();
    text(f.git(&["remote", "add", "origin", url]));
    text(f.git(&[
        "update-ref",
        "refs/remotes/origin/main",
        &f.nodes["right"].1,
    ]));
    let before = metadata(&f.native);
    for query in [
        vec!["-r"],
        vec!["-a"],
        vec!["-r", "--list", "origin/*"],
        vec!["-a", "--list", "remotes/*"],
        vec!["-a", "--list", "origin/*"],
        vec!["-a", "--contains=alpha"],
        vec!["-r", "--no-merged=main"],
    ] {
        let mut args = vec!["branch", "--format=%(refname)"];
        args.extend(query);
        assert_eq!(
            query_text(f.uw(&args)),
            query_text(f.git(&args)),
            "{args:?}"
        );
        assert_eq!(metadata(&f.native), before);
    }
}

#[test]
fn default_head_graph_filters_and_current_branch_use_the_calling_linked_worktree() {
    let f = query_graph();
    text(f.uw(&["branch", "linked-topic", "alpha"]));
    let linked = f.root.join("linked");
    text(f.uw(&["worktree", "add", p(&linked), "linked-topic"]));
    let before = metadata(&f.native);
    let linked_before = metadata(&linked);
    let run = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
        cmd.args([args[0], p(&linked)]).args(&args[1..]);
        query_text(cmd.output().unwrap())
    };
    assert_eq!(run(&["branch", "--show-current"]), "linked-topic\n");
    assert_eq!(query_text(f.uw(&["branch", "--show-current"])), "main\n");
    assert_eq!(
        run(&["branch", "--contains", "--format=%(refname:lstrip=2)"]),
        "alpha\nlinked-topic\nmain\nrelease/Left\nrelease/right\n"
    );
    assert_eq!(
        query_text(f.uw(&["branch", "--contains", "--format=%(refname:lstrip=2)"])),
        "main\n"
    );
    assert_eq!(metadata(&f.native), before);
    assert_eq!(metadata(&linked), linked_before);
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
