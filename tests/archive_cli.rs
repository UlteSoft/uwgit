//! Fixed raw committed-file exports. Parent executes only in SSH Linux cgroup.
//! No randomized inputs, fuzz, guest execution, or extraction into repositories.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const A: &[u8] = b"\0asm\x01\0\0\0";
const UNKNOWN: &[u8] = b"\0asm\x01\0\0\0\xff\x01\xfe";
const CUSTOM: &[u8] = b"\0asm\x01\0\0\0\0\x03\x01q\x7f";
const QUOTED: &str = "one space \"中文\".wasm";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp {
    base: PathBuf,
    repo: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let base = PathBuf::from(format!(
            "/tmp/uwgit-archive-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let repo = base.join("repo");
        ok(&["init", s(&repo)]);
        Self { base, repo }
    }
    fn root(&self) -> &str {
        s(&self.repo)
    }
    fn path(&self, path: &str) -> PathBuf {
        self.repo.join(path)
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        let target = self.path(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    fn stage(&self, path: &str, bytes: &[u8]) {
        self.write(path, bytes);
        ok(&["add", self.root(), "--", path]);
    }
    fn commit(&self, message: &str) -> String {
        ok(&["commit", self.root(), "-m", message]);
        ok(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn export(&self, revision: &str, name: &str, flags: &[&str]) -> (Value, Vec<u8>) {
        let output = self.base.join(name);
        let before = snapshot(&self.repo);
        let mut args = vec!["archive", self.root(), revision, "--output", s(&output)];
        args.extend_from_slice(flags);
        let result = invoke(&args);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stderr.is_empty());
        assert_eq!(
            snapshot(&self.repo),
            before,
            "archive changed repository/worktree"
        );
        assert!(result.stdout.ends_with(b"\n") && !result.stdout.ends_with(b"\n\n"));
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        let bytes = fs::read(&output).unwrap();
        assert_eq!(report["output"], s(&output));
        assert_eq!(report["archive_sha256"], sha(&bytes));
        assert_eq!(report["archive_byte_len"], bytes.len() as u64);
        assert_eq!(report["format"], "tar");
        assert_eq!(report["tar_format"], "ustar");
        let entries = read_tar(&bytes);
        assert_eq!(report["file_count"], entries.len() as u64);
        assert_eq!(report["files"].as_array().unwrap().len(), entries.len());
        for row in report["files"].as_array().unwrap() {
            let name = row["archive_path"].as_str().unwrap();
            assert_eq!(row["byte_len"], entries[name].len() as u64);
            assert_eq!(row["raw_sha256"], sha(&entries[name]));
        }
        (report, bytes)
    }
    fn reject(&self, args: &[&str]) -> String {
        let before = snapshot(&self.base);
        let result = invoke(args);
        assert_eq!(
            result.status.code(),
            Some(1),
            "{args:?}: {:?}",
            result.stderr
        );
        assert!(
            result.stdout.is_empty(),
            "failed archive emitted partial stdout"
        );
        assert!(!result.stderr.is_empty());
        assert_eq!(snapshot(&self.base), before, "failed archive changed files");
        String::from_utf8(result.stderr).unwrap()
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .env_remove("UWGIT_REMOTE_TOKEN")
        .env_remove("UWGIT_SSH_PROGRAM")
        .env_remove("UWGIT_REMOTE_PROGRAM")
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let result = invoke(args);
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn value(args: &[&str]) -> Value {
    serde_json::from_str(&ok(args)).unwrap()
}

#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Entry>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                result.insert(relative, Entry::Symlink(fs::read_link(path).unwrap()));
            } else if kind.is_dir() {
                result.insert(relative, Entry::Directory);
                visit(root, &path, result);
            } else {
                assert!(kind.is_file());
                result.insert(relative, Entry::File(fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn octal(field: &[u8]) -> usize {
    let text = std::str::from_utf8(field)
        .unwrap()
        .trim_matches(['\0', ' ']);
    usize::from_str_radix(text, 8).unwrap()
}
fn cstring(field: &[u8]) -> &str {
    let len = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    std::str::from_utf8(&field[..len]).unwrap()
}

/// Independent fixed-field reader: rejects extended headers, links, directory
/// entries, extra trailing blocks, wrong checksum, and nonzero entry padding.
fn read_tar(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    assert_eq!(bytes.len() % 512, 0);
    let (mut offset, mut names, mut entries) = (0, Vec::new(), BTreeMap::new());
    loop {
        let header = &bytes[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            assert_eq!(bytes.len() - offset, 1024);
            assert!(bytes[offset..].iter().all(|byte| *byte == 0));
            break;
        }
        assert_eq!(&header[257..265], b"ustar\0\x30\x30");
        assert_eq!(header[156], b'0');
        assert!(header[157..257].iter().all(|byte| *byte == 0));
        assert!(header[265..329].iter().all(|byte| *byte == 0));
        assert_eq!(octal(&header[100..108]), 0o644);
        for range in [108..116, 116..124, 136..148, 329..337, 337..345] {
            assert_eq!(octal(&header[range]), 0);
        }
        assert_eq!(&header[154..156], b"\0 ");
        let checksum = octal(&header[148..156]);
        let actual: usize = header
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                if (148..156).contains(&i) {
                    usize::from(b' ')
                } else {
                    usize::from(*byte)
                }
            })
            .sum();
        assert_eq!(checksum, actual);
        let name = cstring(&header[..100]);
        let prefix = cstring(&header[345..500]);
        let name = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        assert!(!name.is_empty() && !name.ends_with('/'));
        let size = octal(&header[124..136]);
        let start = offset + 512;
        let end = start + size;
        let next = end + (512 - size % 512) % 512;
        assert!(bytes[end..next].iter().all(|byte| *byte == 0));
        assert!(entries
            .insert(name.clone(), bytes[start..end].to_vec())
            .is_none());
        names.push(name);
        offset = next;
    }
    assert_eq!(names, entries.keys().cloned().collect::<Vec<_>>());
    entries
}

fn populated() -> (Temp, String, String) {
    let t = Temp::new();
    t.stage("a.wasm", A);
    t.stage("nested/文件.wasm", UNKNOWN);
    t.stage(QUOTED, CUSTOM);
    let first = t.commit("raw original modules");
    ok(&["tag", t.root(), "base", &first]);
    t.stage("a.wasm", CUSTOM);
    let tip = t.commit("changed one committed file");
    (t, first, tip)
}

#[test]
fn help_and_format_list_are_exact_and_do_not_open_a_repository() {
    let t = Temp::new();
    let before = snapshot(&t.base);
    for flag in ["--list", "-l"] {
        let result = invoke(&["archive", flag]);
        assert_eq!(result.status.code(), Some(0));
        assert_eq!(result.stdout, b"tar\n");
        assert!(result.stderr.is_empty());
    }
    for flag in ["--help", "-h"] {
        let result = invoke(&["archive", flag]);
        assert!(result.status.success());
        assert!(String::from_utf8(result.stdout)
            .unwrap()
            .contains("POSIX ustar"));
    }
    let missing = t.base.join("missing");
    t.reject(&["archive", s(&missing), "HEAD", "--prefix", "--help"]);
    assert_eq!(snapshot(&t.base), before);
}

#[test]
fn tar_preserves_raw_committed_bytes_and_reports_real_provenance_and_policy() {
    let (t, _, tip) = populated();
    let (report, bytes) = t.export("HEAD", "all.tar", &[]);
    assert_eq!(report["object_id"], tip);
    assert_eq!(report["commit"], tip);
    assert_eq!(report["kind"], "commit");
    assert_eq!(report["tree"], value(&["show", t.root(), "HEAD"])["tree"]);
    assert!(report["legacy_path"].is_null() && report["stored_legacy_path"].is_null());
    assert_eq!(report["legacy_name_explicit"], false);
    assert_eq!(
        report["metadata_policy"],
        json!({"source":"export_policy", "stored_metadata":false,
        "entry_type":"regular_file", "mode_octal":"0644", "uid":0, "gid":0, "mtime":0,
        "uname":"", "gname":"", "path_encoding":"UTF-8 bytes",
        "encoding_boundary":"ustar byte fields; UTF-8 names require a UTF-8-aware consumer"})
    );
    assert_eq!(
        read_tar(&bytes),
        BTreeMap::from([
            ("a.wasm".into(), CUSTOM.to_vec()),
            ("nested/文件.wasm".into(), UNKNOWN.to_vec()),
            (QUOTED.into(), CUSTOM.to_vec())
        ])
    );
}

#[test]
fn prefix_normalization_is_deterministic_and_filename_suffix_does_not_select_compression() {
    let (t, _, _) = populated();
    let (a, first) = t.export("HEAD", "first.zip", &["--prefix", "release"]);
    let (b, second) = t.export("HEAD", "second.tar", &["--prefix=release/", "--format=tar"]);
    assert_eq!(first, second);
    assert_eq!(a["prefix"], "release/");
    assert_eq!(b["prefix"], "release/");
    assert!(read_tar(&first)
        .keys()
        .all(|name| name.starts_with("release/")));
    assert!(read_tar(&first)
        .keys()
        .all(|name| !name.contains("MANIFEST")));
}

#[test]
fn selectors_match_exact_files_or_directory_descendants_and_each_must_match() {
    let (t, _, _) = populated();
    let (_, dir) = t.export("HEAD", "dir.tar", &["--", "nested/"]);
    assert_eq!(
        read_tar(&dir),
        BTreeMap::from([("nested/文件.wasm".into(), UNKNOWN.to_vec())])
    );
    let (_, overlap) = t.export(
        "HEAD",
        "overlap.tar",
        &["--", "nested", "nested/文件.wasm", QUOTED],
    );
    assert_eq!(read_tar(&overlap).len(), 2);
    let (_, all) = t.export("HEAD", "dot.tar", &["--", "."]);
    let (_, all_slash) = t.export("HEAD", "dot-slash.tar", &["--", "./"]);
    assert_eq!(all, all_slash);
    for selectors in [
        vec!["a.wasm/"],
        vec!["nested/文"],
        vec!["a.wasm", "missing"],
        vec!["nested//"],
        vec!["././a.wasm"],
        vec![".", "../bad"],
    ] {
        let output = t.base.join("absent.tar");
        let mut args = vec!["archive", t.root(), "HEAD", "-o", s(&output), "--"];
        args.extend_from_slice(&selectors);
        t.reject(&args);
    }
}

#[test]
fn commit_tags_ancestry_prefixes_and_direct_tree_keep_actual_source_identity() {
    let (t, first, tip) = populated();
    let tree = value(&["show", t.root(), "HEAD"])["tree"]
        .as_str()
        .unwrap()
        .to_owned();
    let (direct, bytes) = t.export(&tree, "tree.tar", &[]);
    let (_, committed) = t.export("HEAD", "commit.tar", &[]);
    assert_eq!(bytes, committed);
    assert_eq!(direct["kind"], "tree");
    assert_eq!(direct["object_id"], tree);
    assert_eq!(direct["tree"], tree);
    assert!(direct["commit"].is_null() && direct["stored_legacy_path"].is_null());
    for (index, revision) in ["base", "HEAD~1", first.as_str(), &first[..16]]
        .iter()
        .enumerate()
    {
        let (report, bytes) = t.export(revision, &format!("old{index}.tar"), &[]);
        assert_eq!(report["commit"], first);
        assert_eq!(read_tar(&bytes)["a.wasm"], A);
    }
    assert_eq!(t.export(&tip[..16], "tip.tar", &[]).0["commit"], tip);
    let out = t.base.join("invalid.tar");
    t.reject(&["archive", t.root(), &tree[..16], "-o", s(&out)]);
    let blob = value(&["cat-file", t.root(), "-p", &tree])["entries"]["a.wasm"]
        .as_str()
        .unwrap()
        .to_owned();
    t.reject(&["archive", t.root(), &blob, "-o", s(&out)]);
}

#[test]
fn malformed_index_pending_and_dirty_or_missing_work_are_not_archive_inputs() {
    let (t, _, _) = populated();
    let (_, clean) = t.export("HEAD", "clean.tar", &[]);
    fs::write(t.path(".uwgit/index"), b"malformed index retained").unwrap();
    fs::write(t.path(".uwgit/pending.json"), b"malformed journal retained").unwrap();
    t.write("a.wasm", b"uncommitted invalid work");
    fs::remove_file(t.path("nested/文件.wasm")).unwrap();
    t.write("private.txt", b"untracked private");
    let (_, dirty) = t.export("HEAD", "dirty.tar", &[]);
    assert_eq!(clean, dirty);
}

#[test]
fn full_width_name_and_prefix_and_utf8_names_are_preserved_without_extensions() {
    let t = Temp::new();
    let name = format!("{}.wasm", "n".repeat(95));
    let prefix = format!("{}pp", "中".repeat(51));
    assert_eq!(name.len(), 100);
    assert_eq!(prefix.len(), 155);
    t.stage(&name, UNKNOWN);
    t.commit("ustar full-width fields");
    let (report, bytes) = t.export("HEAD", "full-width.tar", &["--prefix", &prefix]);
    let full = format!("{prefix}/{name}");
    assert_eq!(full.len(), 256);
    assert_eq!(
        read_tar(&bytes),
        BTreeMap::from([(full.clone(), UNKNOWN.to_vec())])
    );
    assert_eq!(&bytes[..100], name.as_bytes());
    assert_eq!(&bytes[345..500], prefix.as_bytes());
    assert_eq!(report["files"][0]["archive_path"], full);
    let utf8_name = format!("{}xx.wasm", "文".repeat(31));
    assert_eq!(utf8_name.len(), 100);
    t.stage(&utf8_name, A);
    t.commit("utf8 full-width name");
    let (_, bytes) = t.export("HEAD", "utf8.tar", &["--", &utf8_name]);
    assert_eq!(read_tar(&bytes)[&utf8_name], A);
    assert_eq!(&bytes[..100], utf8_name.as_bytes());
}

#[test]
fn unrepresentable_long_paths_fail_before_any_output_without_truncation_or_pax() {
    let t = Temp::new();
    let long = format!("{}.wasm", "x".repeat(96));
    assert_eq!(long.len(), 101);
    t.stage("good.wasm", A);
    t.stage(&long, UNKNOWN);
    t.commit("one unrepresentable name");
    let out = t.base.join("rejected.tar");
    assert!(t
        .reject(&["archive", t.root(), "HEAD", "-o", s(&out)])
        .contains("cannot be represented"));
    let (_, selected) = t.export("HEAD", "selected.tar", &["--", "good.wasm"]);
    assert_eq!(read_tar(&selected).len(), 1);
    let prefix = "p".repeat(156);
    assert!(t
        .reject(&[
            "archive",
            t.root(),
            "HEAD",
            "-o",
            s(&out),
            "--prefix",
            &prefix,
            "--",
            "good.wasm"
        ])
        .contains("cannot be represented"));
}

#[test]
fn a_real_empty_tree_exports_exactly_two_zero_blocks_and_no_invented_entry() {
    let t = Temp::new();
    ok(&[
        "commit",
        t.root(),
        "--allow-empty",
        "-m",
        "empty committed tree",
    ]);
    let tree = value(&["show", t.root(), "HEAD"])["tree"]
        .as_str()
        .unwrap()
        .to_owned();
    let (report, bytes) = t.export("HEAD", "empty.tar", &[]);
    assert_eq!(bytes, vec![0; 1024]);
    assert_eq!(report["files"], json!([]));
    assert_eq!(report["file_count"], 0);
    let (_, direct) = t.export(&tree, "empty-direct.tar", &["--prefix", "empty"]);
    assert_eq!(direct, bytes);
    let output = t.base.join("unmatched.tar");
    t.reject(&["archive", t.root(), "HEAD", "-o", s(&output), "--", "."]);
}

#[test]
fn legacy_modules_require_explicit_names_and_export_unknown_bytes_without_guessing() {
    let t = Temp::new();
    let input = t.base.join("original.wasm");
    fs::write(&input, UNKNOWN).unwrap();
    ok(&["commit", t.root(), s(&input), "-m", "unnamed legacy module"]);
    let output = t.base.join("missing-name.tar");
    assert!(t
        .reject(&["archive", t.root(), "HEAD", "-o", s(&output)])
        .contains("explicit --legacy-path"));
    let (report, bytes) = t.export(
        "HEAD",
        "legacy.tar",
        &[
            "--legacy-path",
            "chosen/export.wasm",
            "--prefix",
            "package",
            "--",
            "chosen/",
        ],
    );
    assert_eq!(
        read_tar(&bytes),
        BTreeMap::from([("package/chosen/export.wasm".into(), UNKNOWN.to_vec())])
    );
    assert_eq!(report["legacy_path"], "chosen/export.wasm");
    assert_eq!(report["legacy_name_explicit"], true);
    assert!(report["tree"].is_null() && report["stored_legacy_path"].is_null());
    assert_eq!(report["files"][0]["raw_sha256"], sha(UNKNOWN));
}

#[test]
fn named_trees_with_a_legacy_binding_keep_that_fact_but_reject_legacy_renaming() {
    let t = Temp::new();
    let input = t.base.join("legacy.wasm");
    fs::write(&input, A).unwrap();
    ok(&["commit", t.root(), s(&input), "-m", "legacy root"]);
    let chosen = "chosen/stored.wasm";
    t.write(chosen, A);
    let mut raw = b"UWGITIDX\x01".to_vec();
    raw.extend_from_slice(&(chosen.len() as u64).to_le_bytes());
    raw.extend_from_slice(&(A.len() as u64).to_le_bytes());
    raw.extend_from_slice(chosen.as_bytes());
    raw.extend_from_slice(A);
    fs::write(t.path(".uwgit/index"), raw).unwrap();
    t.commit("promote explicit binding to named tree");
    let (report, bytes) = t.export("HEAD", "named.tar", &[]);
    assert_eq!(
        read_tar(&bytes),
        BTreeMap::from([(chosen.into(), A.to_vec())])
    );
    assert_eq!(report["stored_legacy_path"], chosen);
    assert!(report["legacy_path"].is_null());
    assert_eq!(report["legacy_name_explicit"], false);
    let out = t.base.join("rename.tar");
    t.reject(&[
        "archive",
        t.root(),
        "HEAD",
        "-o",
        s(&out),
        "--legacy-path",
        chosen,
    ]);
    t.reject(&[
        "archive",
        t.root(),
        "HEAD",
        "-o",
        s(&out),
        "--legacy-path",
        "other.wasm",
    ]);
}

#[test]
fn invalid_options_prefixes_and_paths_are_rejected_before_opening_missing_repositories() {
    let t = Temp::new();
    let missing = t.base.join("missing");
    let out = t.base.join("none.tar");
    for flag in [
        "--remote",
        "--add-file",
        "--worktree-attributes",
        "--mtime",
        "--unknown",
        "--format=zip",
    ] {
        t.reject(&["archive", s(&missing), "HEAD", "-o", s(&out), flag]);
    }
    for path in [
        "",
        "/absolute",
        "../escape",
        "a/../b",
        ".",
        "a//b",
        "x/",
        ".UwGiT",
        "a/.uwgit/b",
        "C:drive",
        "a\\b",
        "a\nb",
    ] {
        t.reject(&[
            "archive",
            s(&missing),
            "HEAD",
            "-o",
            s(&out),
            "--legacy-path",
            path,
        ]);
    }
    for prefix in [
        "",
        "/absolute",
        "../escape",
        ".",
        "a//b",
        "a//",
        ".uwgit/",
        "a/.UwGiT/b",
        "a\\b",
        "a\tb",
    ] {
        t.reject(&[
            "archive",
            s(&missing),
            "HEAD",
            "-o",
            s(&out),
            "--prefix",
            prefix,
        ]);
    }
    for flags in [
        vec!["--format", "tar", "--format=tar"],
        vec!["-o", "other.tar"],
        vec!["--prefix", "a", "--prefix=b"],
        vec!["--legacy-path", "a", "--legacy-path=b"],
        vec!["--list", "-l"],
        vec!["--"],
        vec!["--", "../bad"],
    ] {
        let mut args = vec!["archive", s(&missing), "HEAD", "-o", s(&out)];
        args.extend_from_slice(&flags);
        t.reject(&args);
    }
    for args in [
        vec!["archive", "--list", s(&missing)],
        vec!["archive", "--list", "--format", "tar"],
        vec!["archive", s(&missing), "HEAD"],
    ] {
        t.reject(&args);
    }
    assert!(!missing.exists() && !out.exists());
}

#[test]
fn output_publication_refuses_overwrite_metadata_aliases_directories_and_staging_leaks() {
    let (t, _, _) = populated();
    let out = t.base.join("existing.tar");
    fs::write(&out, b"retain existing output").unwrap();
    t.reject(&["archive", t.root(), "HEAD", "-o", s(&out)]);
    t.reject(&["archive", t.root(), "HEAD", "-o", t.root()]);
    t.reject(&[
        "archive",
        t.root(),
        "HEAD",
        "-o",
        s(&t.path(".uwgit/new.tar")),
    ]);
    t.reject(&[
        "archive",
        t.root(),
        "HEAD",
        "-o",
        s(&t.base.join("missing/late.tar")),
    ]);
    let (_, bytes) = t.export("HEAD", "complete.tar", &[]);
    assert!(!bytes.is_empty());
    assert!(!snapshot(&t.base)
        .keys()
        .any(|path| path.to_string_lossy().contains(".uwgit-output-")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let alias = t.base.join("metadata-alias");
        symlink(t.path(".uwgit"), &alias).unwrap();
        t.reject(&["archive", t.root(), "HEAD", "-o", s(&alias.join("new.tar"))]);
        let link = t.base.join("existing-link.tar");
        symlink(&out, &link).unwrap();
        t.reject(&["archive", t.root(), "HEAD", "-o", s(&link)]);
    }
}

#[test]
fn corrupt_objects_and_unknown_revisions_fail_without_output_and_describe_names_replay() {
    let (t, _, _) = populated();
    let described = ok(&["describe", t.root(), "HEAD"]).trim().to_owned();
    let (_, described_bytes) = t.export(&described, "description.tar", &[]);
    let (_, head_bytes) = t.export("HEAD", "head.tar", &[]);
    assert_eq!(described_bytes, head_bytes);
    let out = t.base.join("failed.tar");
    t.reject(&["archive", t.root(), "missing", "-o", s(&out)]);
    let head = ok(&["rev-parse", t.root(), "HEAD"]).trim().to_owned();
    let object = t.path(&format!(".uwgit/objects/{head}"));
    let mut raw = fs::read(&object).unwrap();
    raw[0] ^= 1;
    fs::write(object, raw).unwrap();
    t.reject(&["archive", t.root(), "HEAD", "-o", s(&out)]);
}
