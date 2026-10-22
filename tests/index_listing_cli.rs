use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const WASM: &[u8] = b"\0asm\x01\0\0\0";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-index-listing-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        ok(&["init", p(&root)], None);
        Self(root)
    }
    fn root(&self) -> &str {
        p(&self.0)
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn stage(&self, path: &str, bytes: &[u8]) {
        self.write(path, bytes);
        ok(&["add", self.root(), "--", path], None);
    }
    fn commit(&self) -> String {
        ok(&["commit", self.root(), "-m", "original images"], None);
        ok(&["rev-parse", self.root(), "HEAD"], None)
    }
    fn query(&self, flags: &[&str]) -> String {
        let mut args = vec!["ls-files", self.root()];
        args.extend_from_slice(flags);
        let before = files(&self.0);
        let result = ok(&args, None);
        assert_eq!(files(&self.0), before, "read-only query: {args:?}");
        result
    }
    fn reject(&self, flags: &[&str]) {
        let mut args = vec!["ls-files", self.root()];
        args.extend_from_slice(flags);
        let before = files(&self.0);
        let output = run(&args, None);
        assert!(!output.status.success(), "unexpected success: {args:?}");
        assert!(
            output.stdout.is_empty(),
            "failed listing leaked partial rows"
        );
        assert_eq!(files(&self.0), before);
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
fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, rows: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in fs::read_dir(path).unwrap() {
            let e = e.unwrap();
            let kind = e.file_type().unwrap();
            if kind.is_dir() {
                visit(root, &e.path(), rows);
            } else if kind.is_file() {
                rows.insert(
                    e.path().strip_prefix(root).unwrap().into(),
                    fs::read(e.path()).unwrap(),
                );
            } else if kind.is_symlink() {
                rows.insert(
                    e.path().strip_prefix(root).unwrap().into(),
                    fs::read_link(e.path())
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                );
            }
        }
    }
    let mut rows = BTreeMap::new();
    visit(root, root, &mut rows);
    rows
}
fn wasm(value: u32) -> Vec<u8> {
    [WASM, &[0, 6, 1, b'x'], value.to_le_bytes().as_slice()].concat()
}
fn id(kind: u8, bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"UWGO\0\0\0\x01");
    hash.update([kind]);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    format!("{:x}", hash.finalize())
}

#[test]
fn directory_folding_obeys_index_ownership_ignores_empty_trees_and_precise_pathspecs() {
    let t = Temp::new();
    t.stage("tracked/a.wasm", WASM);
    for dir in ["empty", "onlyempty/deep", "ignored-empty"] {
        fs::create_dir_all(t.0.join(dir)).unwrap();
    }
    for file in [
        "d/a.wasm",
        "d/sub/b.wasm",
        "d/note.txt",
        "onlyignored/a.tmp",
        "tracked/extra/a.wasm",
        "visible/a.tmp",
        "visible/b.wasm",
    ] {
        t.write(file, b"raw\n");
    }
    t.write(".gitignore", b"*.tmp\nignored-empty/\n");
    assert_eq!(
        t.query(&["--others", "--directory", "--exclude-standard"]),
        ".gitignore\nd/\nempty/\nonlyempty/\nonlyignored/\ntracked/extra/\nvisible/"
    );
    assert_eq!(
        t.query(&[
            "--others",
            "--directory",
            "--exclude-standard",
            "--no-empty-directory"
        ]),
        ".gitignore\nd/\ntracked/extra/\nvisible/"
    );
    for (selectors, expected) in [
        (vec!["d/a.wasm"], "d/a.wasm"),
        (vec!["d/"], "d/"),
        (
            vec!["*.wasm"],
            "d/a.wasm\nd/sub/b.wasm\ntracked/extra/a.wasm\nvisible/b.wasm",
        ),
        (vec!["d", ":(exclude)d/a.wasm"], "d/"),
        (vec!["tracked"], "tracked/extra/"),
    ] {
        let mut args = vec!["--others", "--directory", "--exclude-standard", "--"];
        args.extend(selectors);
        assert_eq!(t.query(&args), expected);
    }
    assert_eq!(t.query(&["--directory"]), "tracked/a.wasm");
    assert_eq!(
        t.query(&["--others", "--no-empty-directory", "--exclude-standard"]),
        t.query(&["--others", "--exclude-standard"])
    );
    assert_eq!(
        t.query(&["--others", "--ignored", "--directory", "--exclude-standard"]),
        "ignored-empty/\nonlyignored/\nvisible/a.tmp"
    );
    assert_eq!(
        t.query(&[
            "--others",
            "--ignored",
            "--directory",
            "--exclude-standard",
            "--no-empty-directory"
        ]),
        "onlyignored/\nvisible/a.tmp"
    );
    let rows: Value =
        serde_json::from_str(&t.query(&["--others", "--directory", "--json", "--", "d/"])).unwrap();
    assert_eq!(rows["entries"][0]["directory"], true);
    assert_eq!(rows["entries"][0]["object_id"], Value::Null);
    assert_eq!(
        t.query(&["--others", "--directory", "-t", "-z", "--", "d/"]),
        "? d/\0"
    );
}

#[test]
fn unrelated_exclude_files_are_not_read_by_a_precisely_selected_worktree_query() {
    let t = Temp::new();
    t.write("good.txt", b"selected\n");
    t.write("unrelated/private.txt", b"unselected\n");
    t.write("unrelated/.gitignore", b"\xff");
    assert_eq!(
        t.query(&["--others", "--exclude-standard", "--", "good.txt"]),
        "good.txt"
    );
    assert_eq!(
        t.query(&[
            "--others",
            "--directory",
            "--exclude-standard",
            "--",
            "good.txt"
        ]),
        "good.txt"
    );
    assert_eq!(
        t.query(&[
            "--others",
            "--directory",
            "--exclude-standard",
            "--",
            ".",
            ":(exclude)unrelated"
        ]),
        "good.txt"
    );
    t.reject(&[
        "--others",
        "--exclude-standard",
        "--",
        "unrelated/private.txt",
    ]);
}

#[test]
#[cfg(unix)]
fn directories_do_not_hide_nested_repositories_symlinks_or_special_files() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    t.write("outer/nested/.git", b"gitdir: /unrelated\n");
    t.write("outer/nested/private.txt", b"nested user bytes");
    t.write("outer/plain.txt", b"ordinary\n");
    t.write("links/plain.txt", b"ordinary\n");
    symlink("../outer/nested", t.0.join("links/alias")).unwrap();
    t.write("broken/plain.txt", b"ordinary\n");
    symlink("absent", t.0.join("broken/alias")).unwrap();
    t.write("marker/nested/private.txt", b"nested user bytes");
    symlink("absent", t.0.join("marker/nested/.uwgit")).unwrap();
    t.write("marker/plain.txt", b"ordinary\n");
    t.write("special/plain.txt", b"ordinary\n");
    assert!(Command::new("mkfifo")
        .arg(t.0.join("special/pipe"))
        .status()
        .unwrap()
        .success());
    assert_eq!(
        t.query(&["--others", "--directory"]),
        "broken/plain.txt\nlinks/plain.txt\nmarker/plain.txt\nouter/plain.txt\nspecial/plain.txt"
    );
    assert_eq!(
        fs::read(t.0.join("outer/nested/private.txt")).unwrap(),
        b"nested user bytes"
    );
}

#[test]
fn abbreviations_consider_unselected_unpublished_images_and_saved_original_sides() {
    let t = Temp::new();
    let mut prefixes = BTreeMap::new();
    let (first, second, first_id, second_id) = (0u32..=65536)
        .find_map(|n| {
            let bytes = wasm(n);
            let full = id(1, &bytes);
            let prefix = full[..4].to_owned();
            prefixes
                .insert(prefix, (bytes.clone(), full.clone()))
                .map(|(previous, old)| (previous, bytes, old, full))
        })
        .unwrap();
    t.stage("a.wasm", &first);
    t.stage("b.wasm", &second);
    assert_eq!(
        ok(&["hash-object", t.root(), "--stdin"], Some(&first)),
        first_id
    );
    let length = first_id
        .bytes()
        .zip(second_id.bytes())
        .take_while(|(a, b)| a == b)
        .count()
        + 1;
    let expected = format!("100644 {} 0\ta.wasm", &first_id[..length]);
    assert_eq!(
        t.query(&["--stage", "--abbrev=4", "--", "a.wasm"]),
        expected
    );
    assert_eq!(
        t.query(&["--stage", "--abbrev=3", "--", "a.wasm"]),
        expected
    );
    let rows: Value =
        serde_json::from_str(&t.query(&["--json", "--abbrev=4", "--", "a.wasm"])).unwrap();
    assert_eq!(rows["entries"][0]["object_id"], first_id);
    assert_eq!(rows["entries"][0]["object_abbrev"], first_id[..length]);
    assert_eq!(
        t.query(&[
            "--format=%(objectname) %(path)",
            "--abbrev=4",
            "--",
            "a.wasm"
        ]),
        format!("{} a.wasm", &first_id[..length])
    );
    assert_eq!(fs::read_dir(t.0.join(".uwgit/objects")).unwrap().count(), 0);

    ok(&["hash-object", t.root(), "-w", "--stdin"], Some(&second));
    ok(
        &["update-index", t.root(), "--force-remove", "b.wasm"],
        None,
    );
    ok(
        &["update-index", t.root(), "--index-info"],
        Some(format!("100644 {second_id} 2\told.wasm\n").as_bytes()),
    );
    ok(
        &["update-index", t.root(), "--force-remove", "old.wasm"],
        None,
    );
    fs::remove_file(t.0.join(".uwgit/objects").join(&second_id)).unwrap();
    assert_eq!(
        t.query(&["--stage", "--abbrev=4", "--", "a.wasm"]),
        expected
    );
    let undo = t.query(&["--resolve-undo", "--abbrev=4"]);
    assert_eq!(undo, format!("100644 {} 2\told.wasm", &second_id[..length]));
    for flag in ["--abbrev=0", "--abbrev=64"] {
        assert_eq!(
            t.query(&["--stage", flag, "--", "a.wasm"]),
            format!("100644 {first_id} 0\ta.wasm")
        );
    }
    assert_eq!(
        t.query(&["--format=%(objectname)", "--abbrev", "--", "a.wasm"]),
        first_id[..12]
    );
    t.reject(&["--abbrev=65"]);
    t.reject(&["--abbrev=-1"]);
    t.reject(&["--abbrev=no"]);
}

#[test]
fn abbreviations_extend_for_a_stored_native_tree_even_when_the_wasm_image_is_unpublished() {
    let t = Temp::new();
    let base = ok(&["hash-object", t.root(), "-w", "--stdin"], Some(WASM));
    let mut trees = BTreeMap::new();
    for n in 0..2048 {
        let path = format!("candidate{n}.wasm");
        let bytes = format!("{{\"format\":1,\"entries\":{{\"{path}\":\"{base}\"}}}}");
        let full = id(3, bytes.as_bytes());
        trees.insert(full[..4].to_owned(), (path, full));
    }
    let (bytes, full, (path, tree_id)) = (0..65536)
        .find_map(|n| {
            let bytes = wasm(n);
            let full = id(1, &bytes);
            trees
                .get(&full[..4])
                .map(|tree| (bytes, full.clone(), tree.clone()))
        })
        .unwrap();
    let tree = ok(
        &["mktree", t.root()],
        Some(format!("100644 wasm {base}\t{path}\n").as_bytes()),
    );
    assert_eq!(tree, tree_id);
    t.stage("unpublished.wasm", &bytes);
    let rows: Value = serde_json::from_str(&t.query(&["--json", "--abbrev=4"])).unwrap();
    let abbreviation = rows["entries"][0]["object_abbrev"].as_str().unwrap();
    assert!(
        abbreviation.len() > 4
            && full.starts_with(abbreviation)
            && !tree_id.starts_with(abbreviation)
    );
    assert!(!t.0.join(".uwgit/objects").join(full).exists());
}

#[test]
fn historical_tree_supplements_names_without_replacing_index_images_or_making_stages() {
    let t = Temp::new();
    for path in ["keep.wasm", "gone.wasm", "dir/child.wasm"] {
        t.stage(path, WASM);
    }
    let head = t.commit();
    let tree: Value =
        serde_json::from_str(&ok(&["ls-tree", t.root(), "HEAD", "--json"], None)).unwrap();
    let tree = tree["tree"].as_str().unwrap();
    ok(&["read-tree", t.root(), "--empty"], None);
    fs::remove_dir_all(t.0.join("dir")).unwrap();
    t.stage("dir", &wasm(3));
    t.stage("keep.wasm", &wasm(4));
    t.stage("new.wasm", WASM);
    let expected = "dir\ndir/child.wasm\ngone.wasm\nkeep.wasm\nnew.wasm";
    assert_eq!(t.query(&["--with-tree", &head]), expected);
    assert_eq!(t.query(&["--with-tree", tree]), expected);
    assert_eq!(
        t.query(&["--with-tree", "HEAD", "--error-unmatch", "--", "gone.wasm"]),
        "gone.wasm"
    );
    t.reject(&["--error-unmatch", "--", "gone.wasm"]);
    let rows: Value = serde_json::from_str(&t.query(&["--with-tree", "HEAD", "--json"])).unwrap();
    let gone = rows["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "gone.wasm")
        .unwrap();
    assert_eq!(gone["source"], "tree");
    assert_eq!(gone["source_object"], head);
    assert_eq!(gone["index_entry"], false);
    assert_eq!(gone["stage"], Value::Null);
    let keep = rows["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "keep.wasm")
        .unwrap();
    assert_eq!(keep["object_id"], id(1, &wasm(4)));
    assert_eq!(
        t.query(&[
            "--with-tree",
            "HEAD",
            "--format=%(stage) %(path)",
            "--",
            "gone.wasm"
        ]),
        "- gone.wasm"
    );
    assert_eq!(t.query(&["--with-tree", "HEAD", "--others"]), "");
    assert_eq!(
        t.query(&["--with-tree", "HEAD", "--deleted", "--", "gone.wasm"]),
        ""
    );
    fs::remove_file(t.0.join("gone.wasm")).unwrap();
    assert_eq!(
        t.query(&["--with-tree", "HEAD", "--deleted", "--", "gone.wasm"]),
        "gone.wasm"
    );
    t.reject(&["--with-tree", "HEAD", "--stage"]);
    t.reject(&["--with-tree", "HEAD", "--unmerged"]);
    t.reject(&["--with-tree", "absent"]);
}

#[test]
fn unnamed_history_and_malformed_or_unmatched_queries_fail_before_emitting_any_rows() {
    let t = Temp::new();
    t.write("legacy.wasm", WASM);
    ok(
        &[
            "commit",
            t.root(),
            p(&t.0.join("legacy.wasm")),
            "-m",
            "unnamed history",
        ],
        None,
    );
    t.reject(&["--with-tree", "HEAD"]);
    t.stage("a.wasm", WASM);
    for args in [
        vec!["--error-unmatch", "--", "a.wasm", "absent.wasm"],
        vec!["--format=%(eolinfo:other)"],
        vec!["--format=%(path)", "--eol"],
        vec!["--json", "-z"],
        vec!["--others", "--ignored", "--directory"],
    ] {
        t.reject(&args);
    }
    fs::write(t.0.join(".uwgit/index.lock"), b"held").unwrap();
    t.reject(&["--eol"]);
    t.reject(&["--others", "--directory"]);
    fs::remove_file(t.0.join(".uwgit/index.lock")).unwrap();
}

#[test]
fn eol_queries_inspect_original_work_bytes_even_for_hidden_entries_and_never_convert_them() {
    let t = Temp::new();
    let cases: [(&str, &[u8], &str); 8] = [
        ("a.wasm", b"one\ntwo\n", "lf"),
        ("b.wasm", b"one\r\ntwo\r\n", "crlf"),
        ("c.wasm", b"one\r\ntwo\n", "mixed"),
        ("d.wasm", b"one\rtwo", "-text"),
        ("e.wasm", b"", "none"),
        ("f.wasm", WASM, "-text"),
        ("g.wasm", b"plain", "none"),
        ("h.wasm", b"\x01\n", "-text"),
    ];
    for (path, _, _) in cases {
        t.stage(path, WASM);
    }
    ok(
        &["update-index", t.root(), "--assume-unchanged", "a.wasm"],
        None,
    );
    ok(
        &["update-index", t.root(), "--skip-worktree", "b.wasm"],
        None,
    );
    for (path, bytes, _) in cases {
        t.write(path, bytes);
    }
    t.write(".gitattributes", b"*.wasm text eol=crlf\n");
    let rows: Value = serde_json::from_str(&t.query(&["--eol", "--json"])).unwrap();
    assert!(rows["eol_policy"]
        .as_str()
        .unwrap()
        .contains("original_bytes_no_conversion"));
    for ((path, _, kind), row) in cases.iter().zip(rows["entries"].as_array().unwrap()) {
        assert_eq!(row["path"], *path);
        assert_eq!(row["eol_index"], "-text");
        assert_eq!(row["eol_worktree"], *kind);
        assert_eq!(row["eol_attribute"], "");
    }
    assert_eq!(
        t.query(&[
            "--format=%(eolinfo:index)|%(eolinfo:worktree)|%(eolattr)|%(path)",
            "--",
            "a.wasm"
        ]),
        "-text|lf||a.wasm"
    );
    assert_eq!(
        t.query(&["--eol", "-s", "--abbrev=4", "--", "a.wasm"]),
        format!(
            "100644 {} 0\ti/{:<5} w/{:<5} attr/{:<17}\ta.wasm",
            &id(1, WASM)[..4],
            "-text",
            "lf",
            ""
        )
    );
    t.stage("intent.wasm", WASM);
    ok(
        &["update-index", t.root(), "--force-remove", "intent.wasm"],
        None,
    );
    ok(&["add", t.root(), "-N", "intent.wasm"], None);
    let intent: Value =
        serde_json::from_str(&t.query(&["--eol", "--json", "--", "intent.wasm"])).unwrap();
    assert_eq!(intent["entries"][0]["eol_index"], "");
    assert_eq!(intent["entries"][0]["eol_worktree"], "-text");
    fs::remove_file(t.0.join("c.wasm")).unwrap();
    assert_eq!(
        t.query(&["--format=%(eolinfo:worktree)", "--", "c.wasm"]),
        ""
    );
    fs::remove_file(t.0.join("d.wasm")).unwrap();
    fs::create_dir(t.0.join("d.wasm")).unwrap();
    assert_eq!(
        t.query(&["--format=%(eolinfo:worktree)", "--", "d.wasm"]),
        ""
    );
}

#[test]
#[cfg(unix)]
fn eol_never_follows_worktree_symlinks_and_directory_rows_have_no_fabricated_images() {
    use std::os::unix::fs::symlink;
    let t = Temp::new();
    t.stage("a.wasm", WASM);
    t.write("private.txt", b"private editor contents\n");
    fs::remove_file(t.0.join("a.wasm")).unwrap();
    symlink("private.txt", t.0.join("a.wasm")).unwrap();
    let rows: Value = serde_json::from_str(&t.query(&["--eol", "--json", "--", "a.wasm"])).unwrap();
    assert_eq!(rows["entries"][0]["eol_worktree"], "");
    t.write("data/child.txt", b"text\r\n");
    let rows: Value = serde_json::from_str(&t.query(&[
        "--others",
        "--directory",
        "--eol",
        "--json",
        "--",
        "data",
    ]))
    .unwrap();
    assert_eq!(rows["entries"][0]["directory"], true);
    assert_eq!(rows["entries"][0]["object_id"], Value::Null);
    assert_eq!(rows["entries"][0]["eol_index"], "");
    assert_eq!(rows["entries"][0]["eol_worktree"], "");
    assert_eq!(
        fs::read(t.0.join("private.txt")).unwrap(),
        b"private editor contents\n"
    );
}
