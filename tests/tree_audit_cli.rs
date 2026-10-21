//! Fixed file-tree presentation and exact byte evidence. Every fixture and
//! artifact lives in /tmp; no Wasm code or generated fuzz corpus is executed.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::patch::BytePatch;
use wasmparser::{Operator, Parser, Payload};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const A: &str = "modules/a.wasm";
const B: &str = "nested/b.wasm";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-tree-audit-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn repository(&self) -> PathBuf {
        let repo = self.path("repo");
        run(&["init", path(&repo)]);
        repo
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn run(args: &[&str]) -> String {
    let output = invoke(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&run(args)).unwrap()
}
fn failure(args: &[&str]) -> String {
    let output = invoke(args);
    assert!(!output.status.success(), "unexpected success: {args:?}");
    String::from_utf8(output.stderr).unwrap()
}
fn write(repo: &Path, file: &str, bytes: &[u8]) {
    let file = repo.join(file);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, bytes).unwrap();
}
fn stage(repo: &Path, file: &str, bytes: &[u8]) {
    write(repo, file, bytes);
    run(&["add", path(repo), file]);
}
fn commit(repo: &Path, message: &str) -> String {
    run(&["commit", path(repo), "-m", message]);
    run(&["rev-parse", path(repo), "HEAD"]).trim().into()
}
fn module(value: i32) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (func (export \"f\") (result i32) i32.const {value}))"
    ))
    .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn span(value: &Value, bytes: &[u8]) -> (usize, usize) {
    let start = usize::try_from(value["start"].as_u64().unwrap()).unwrap();
    let end = usize::try_from(value["end"].as_u64().unwrap()).unwrap();
    assert!(start <= end && end <= bytes.len());
    (start, end)
}
fn replay(report: &Value, old: &[u8], new: &[u8]) {
    let (mut old_cursor, mut new_cursor) = (0, 0);
    let mut rebuilt = Vec::new();
    for edit in report["audit"]["edits"].as_array().unwrap() {
        let (start, end) = span(&edit["old_span"], old);
        let (new_start, new_end) = span(&edit["new_span"], new);
        assert!(start >= old_cursor && new_start >= new_cursor);
        assert_eq!(old[old_cursor..start], new[new_cursor..new_start]);
        assert_eq!(unhex(edit["old_hex"].as_str().unwrap()), old[start..end]);
        assert_eq!(
            unhex(edit["new_hex"].as_str().unwrap()),
            new[new_start..new_end]
        );
        rebuilt.extend_from_slice(&old[old_cursor..start]);
        rebuilt.extend_from_slice(&new[new_start..new_end]);
        old_cursor = end;
        new_cursor = new_end;
    }
    assert_eq!(old[old_cursor..], new[new_cursor..]);
    rebuilt.extend_from_slice(&old[old_cursor..]);
    assert_eq!(rebuilt, new);
}
fn witness(value: &Value, bytes: &[u8], side: &str) {
    assert_eq!(value["side"], side);
    assert_eq!(value["byte_len"], bytes.len());
    assert_eq!(value["sha256"], sha(bytes));
    assert_eq!(value["span"], json!({"start":0,"end":bytes.len()}));
    assert_eq!(value["hex"], hex(bytes));
}
fn rows(report: &Value) -> BTreeMap<String, &Value> {
    report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["path"].as_str().unwrap().to_owned(), row))
        .collect()
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let file = entry.path();
            assert!(!entry.file_type().unwrap().is_symlink());
            let key = file.strip_prefix(root).unwrap().to_owned();
            if entry.file_type().unwrap().is_dir() {
                result.insert(key, None);
                visit(root, &file, result);
            } else {
                result.insert(key, Some(fs::read(file).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}
fn query_readonly(temp: &Temp, args: &[&str]) -> Value {
    let before = snapshot(&temp.0);
    let result = json(args);
    assert_eq!(snapshot(&temp.0), before);
    result
}

#[test]
fn complete_tree_reports_every_path_and_replays_exact_module_changes() {
    let temp = Temp::new();
    let repo = temp.repository();
    let old = module(1);
    let new = module(2);
    let removed = module(3);
    let added = [HEADER, &[14, 2, 0xaa, 0xbb]].concat();
    stage(&repo, A, &old);
    stage(&repo, "removed.wasm", &removed);
    stage(&repo, "same.wasm", HEADER);
    let first = commit(&repo, "old tree");
    stage(&repo, A, &new);
    stage(&repo, "added.wasm", &added);
    run(&["rm", path(&repo), "--cached", "removed.wasm"]);
    let second = commit(&repo, "modify add delete and keep");
    let inspected = query_readonly(
        &temp,
        &["inspect", &second, "--repo", path(&repo), "--json"],
    );
    assert_eq!(inspected["schema_version"], 2);
    assert_eq!(inspected["kind"], "tree_inspect");
    assert_eq!(inspected["file_count"], 3);
    let inspected = rows(&inspected);
    for (file, bytes) in [
        (A, new.as_slice()),
        ("added.wasm", added.as_slice()),
        ("same.wasm", HEADER),
    ] {
        let report = &inspected[file]["report"];
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["input"]["file"], file);
        assert_eq!(report["audit"]["byte_len"], bytes.len());
        assert_eq!(
            report["audit"],
            serde_json::to_value(wasm_git::audit::inspect(bytes).unwrap()).unwrap()
        );
    }
    let difference = query_readonly(
        &temp,
        &[
            "diff",
            &first,
            &second,
            "--repo",
            path(&repo),
            "--format",
            "json",
        ],
    );
    assert_eq!(difference["schema_version"], 2);
    assert_eq!(difference["kind"], "tree_diff");
    assert_eq!(difference["tree_changed"], true);
    assert_eq!(
        difference["summary"],
        json!({"added":1,"deleted":1,"modified":1,"unchanged":1})
    );
    let entries = rows(&difference);
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[A]["status"], "modified");
    replay(&entries[A]["diff"], &old, &new);
    assert_eq!(entries["same.wasm"]["status"], "unchanged");
    replay(&entries["same.wasm"]["diff"], HEADER, HEADER);
    for (file, bytes, status, side) in [
        ("removed.wasm", removed.as_slice(), "deleted", "old"),
        ("added.wasm", added.as_slice(), "added", "new"),
    ] {
        let row = entries[file];
        assert_eq!(row["status"], status);
        assert!(row["diff"].is_null());
        witness(&row["content"], bytes, side);
        assert_eq!(row["audit"]["byte_len"], bytes.len());
        assert!(row[if side == "old" { "new" } else { "old" }].is_null());
        let selected = query_readonly(
            &temp,
            &[
                "diff",
                &first,
                &second,
                "--repo",
                path(&repo),
                "--file",
                file,
                "--format",
                "json",
            ],
        );
        assert_eq!(selected["schema_version"], 2);
        assert_eq!(selected["files"].as_array().unwrap().len(), 1);
        assert_eq!(selected["files"][0], *row);
    }
    let selected = query_readonly(
        &temp,
        &[
            "diff",
            &first,
            &second,
            "--repo",
            path(&repo),
            "--file",
            A,
            "--format",
            "json",
        ],
    );
    assert_eq!(selected["schema_version"], 1);
    assert_eq!(selected["inputs"]["old"]["file"], A);
    assert_eq!(selected["inputs"]["new"]["file"], A);
    replay(&selected, &old, &new);
    run(&["rm", path(&repo), "--cached", A, "added.wasm", "same.wasm"]);
    let empty = commit(&repo, "empty tree");
    let inspection = query_readonly(&temp, &["inspect", &empty, "--repo", path(&repo), "--json"]);
    assert_eq!(inspection["file_count"], 0);
    assert_eq!(inspection["files"], json!([]));
    let identical = query_readonly(
        &temp,
        &[
            "diff",
            &empty,
            &empty,
            "--repo",
            path(&repo),
            "--format",
            "json",
        ],
    );
    assert_eq!(identical["binary_changed"], false);
    assert_eq!(identical["files"], json!([]));
}

#[test]
fn selected_file_exports_and_patch_apply_are_exact_and_never_clobber_a_destination() {
    let temp = Temp::new();
    let repo = temp.repository();
    let old = module(10);
    let new = module(11);
    stage(&repo, A, &old);
    stage(&repo, B, &module(99));
    let first = commit(&repo, "two files");
    stage(&repo, A, &new);
    let second = commit(&repo, "only selected file changes");
    let shown = query_readonly(&temp, &["show", path(&repo), &second, "--file", A]);
    witness(&shown["content"], &new, "selected");
    let exported = temp.path("show.wasm");
    run(&[
        "show",
        path(&repo),
        &second,
        "--file",
        A,
        "--output",
        path(&exported),
    ]);
    assert_eq!(fs::read(&exported).unwrap(), new);
    let checked_out = temp.path("checkout.wasm");
    run(&[
        "checkout",
        path(&repo),
        &first,
        "--file",
        A,
        path(&checked_out),
    ]);
    assert_eq!(fs::read(&checked_out).unwrap(), old);
    let before = snapshot(&temp.0);
    failure(&[
        "show",
        path(&repo),
        &first,
        "--file",
        A,
        "--output",
        path(&exported),
    ]);
    failure(&[
        "checkout",
        path(&repo),
        &second,
        "--file",
        A,
        path(&checked_out),
    ]);
    assert_eq!(snapshot(&temp.0), before);
    let patch_path = temp.path("selected.uwpatch");
    let created = json(&[
        "patch",
        &first,
        &second,
        "--repo",
        path(&repo),
        "--file",
        A,
        "--output",
        path(&patch_path),
    ]);
    assert_eq!(created["inputs"]["old"]["file"], A);
    assert_eq!(created["inputs"]["new"]["file"], A);
    let encoded = fs::read(&patch_path).unwrap();
    let patch = BytePatch::from_bytes(&encoded).unwrap();
    assert_eq!(patch.apply(&old).unwrap(), new);
    let checked = query_readonly(
        &temp,
        &[
            "apply",
            &first,
            path(&patch_path),
            "--repo",
            path(&repo),
            "--file",
            A,
            "--check",
        ],
    );
    assert_eq!(checked["written"], false);
    replay(&checked, &old, &new);
    let replayed = temp.path("applied.wasm");
    json(&[
        "apply",
        &first,
        path(&patch_path),
        "--repo",
        path(&repo),
        "--file",
        A,
        "--output",
        path(&replayed),
    ]);
    assert_eq!(fs::read(&replayed).unwrap(), new);
    let forbidden = temp.path("must-not-create.uwpatch");
    let before = snapshot(&temp.0);
    failure(&[
        "patch",
        &first,
        &second,
        "--repo",
        path(&repo),
        "--output",
        path(&forbidden),
    ]);
    failure(&[
        "apply",
        &first,
        path(&patch_path),
        "--repo",
        path(&repo),
        "--check",
    ]);
    failure(&[
        "patch",
        &first,
        &second,
        "--repo",
        path(&repo),
        "--file",
        "absent.wasm",
        "--output",
        path(&forbidden),
    ]);
    assert_eq!(snapshot(&temp.0), before);
    assert!(!forbidden.exists());
}

#[test]
fn file_trace_stops_at_introduction_and_does_not_cross_delete_then_reintroduction() {
    let temp = Temp::new();
    let repo = temp.repository();
    run(&[
        "commit",
        path(&repo),
        "--allow-empty",
        "-m",
        "no modules yet",
    ]);
    let empty = run(&["rev-parse", path(&repo), "HEAD"]).trim().to_owned();
    stage(&repo, A, &module(1));
    let introduced = commit(&repo, "introduce exact path");
    stage(&repo, A, &module(2));
    let changed = commit(&repo, "edit exact path");
    run(&["rm", path(&repo), "--cached", A]);
    let deleted = commit(&repo, "delete path");
    stage(&repo, A, &module(1));
    let reintroduced = commit(&repo, "new introduction at the same path");
    let first = query_readonly(
        &temp,
        &[
            "trace",
            path(&repo),
            &introduced,
            "--file",
            A,
            "--path",
            "module",
        ],
    );
    assert_eq!(first["selection"]["file"], A);
    assert_eq!(first["trace"]["complete"], true);
    let edges = first["trace"]["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["parent"], empty);
    assert_eq!(edges[0]["status"], "file_absent");
    assert!(edges[0]["parent_wasm"].is_null());
    assert!(first["trace"]["frontier"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["reason"] == "file_introduced_at_path" && item["parent"] == empty));
    let ordinary = query_readonly(
        &temp,
        &[
            "trace",
            path(&repo),
            &changed,
            "--file",
            A,
            "--path",
            "module",
        ],
    );
    assert!(ordinary["trace"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["parent"] == introduced && !edge["parent_wasm"].is_null()));
    let last = query_readonly(
        &temp,
        &[
            "trace",
            path(&repo),
            &reintroduced,
            "--file",
            A,
            "--path",
            "module",
        ],
    );
    let edges = last["trace"]["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["parent"], deleted);
    assert_eq!(edges[0]["status"], "file_absent");
    let nodes = last["trace"]["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0]["commit"], reintroduced);
    let before = snapshot(&temp.0);
    assert!(failure(&[
        "trace",
        path(&repo),
        &deleted,
        "--file",
        A,
        "--path",
        "module"
    ])
    .contains("absent"));
    assert_eq!(snapshot(&temp.0), before);
}

#[test]
fn recorded_legacy_anchor_does_not_invent_an_old_copy_of_a_new_second_path() {
    let temp = Temp::new();
    let repo = temp.repository();
    let old = module(1);
    let added = module(2);
    let old_path = temp.path("legacy.wasm");
    fs::write(&old_path, &old).unwrap();
    run(&[
        "commit",
        path(&repo),
        path(&old_path),
        "-m",
        "pathless legacy",
    ]);
    let legacy = run(&["rev-parse", path(&repo), "HEAD"]).trim().to_owned();
    let legacy_trace = query_readonly(
        &temp,
        &[
            "trace",
            path(&repo),
            &legacy,
            "--file",
            A,
            "--path",
            "module",
        ],
    );
    assert_eq!(
        legacy_trace["selection"]["file_identity"],
        "explicit selected path; legacy commits have no filename"
    );
    assert!(legacy_trace["selection"]["legacy_path"].is_null());
    stage(&repo, A, &old);
    stage(&repo, B, &added);
    let tree = commit(&repo, "anchor original at A and add B");
    let selected = query_readonly(
        &temp,
        &[
            "diff",
            &legacy,
            &tree,
            "--repo",
            path(&repo),
            "--file",
            B,
            "--format",
            "json",
        ],
    );
    assert_eq!(selected["schema_version"], 2);
    let row = &selected["files"][0];
    assert_eq!(row["path"], B);
    assert_eq!(row["status"], "added");
    assert!(row["old"].is_null());
    witness(&row["content"], &added, "new");
    let full = query_readonly(
        &temp,
        &[
            "diff",
            &legacy,
            &tree,
            "--repo",
            path(&repo),
            "--format",
            "json",
        ],
    );
    let entries = rows(&full);
    assert_eq!(entries[A]["status"], "unchanged");
    assert_eq!(entries[B]["status"], "added");
    let trace = query_readonly(
        &temp,
        &["trace", path(&repo), &tree, "--file", B, "--path", "module"],
    );
    let edge = &trace["trace"]["edges"][0];
    assert_eq!(trace["selection"]["legacy_path"], A);
    assert_eq!(edge["parent"], legacy);
    assert_eq!(edge["status"], "file_absent");
    assert!(edge["parent_wasm"].is_null());
    let original = query_readonly(
        &temp,
        &["trace", path(&repo), &tree, "--file", A, "--path", "module"],
    );
    assert!(original["trace"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["parent"] == legacy && !edge["parent_wasm"].is_null()));
    let output = temp.path("not-a-patch.uwpatch");
    let before = snapshot(&temp.0);
    failure(&[
        "patch",
        &legacy,
        &tree,
        "--repo",
        path(&repo),
        "--file",
        B,
        "--output",
        path(&output),
    ]);
    assert_eq!(snapshot(&temp.0), before);
}

fn check_audit(module: &Value, bytes: &[u8]) {
    assert_eq!(module["byte_len"], bytes.len());
    let mut cursor = 8;
    for section in module["sections"].as_array().unwrap() {
        let (start, end) = span(&section["span"], bytes);
        assert_eq!(start, cursor);
        cursor = end;
    }
    assert_eq!(cursor, bytes.len());
    for evidence in module["standard"]["evidence"].as_array().unwrap() {
        let (start, end) = span(&evidence["span"], bytes);
        assert_eq!(evidence["raw_hex"], hex(&bytes[start..end]));
    }
}
fn regions(module: &Value) -> Vec<&Value> {
    fn collect<'a>(entries: &'a [Value], result: &mut Vec<&'a Value>) {
        for entry in entries {
            result.push(entry);
            collect(entry["children"].as_array().unwrap(), result);
        }
    }
    let mut result = Vec::new();
    for section in module["sections"].as_array().unwrap() {
        collect(section["regions"].as_array().unwrap(), &mut result);
    }
    result
}
fn sentinel_operators(module: &Value, bytes: &[u8]) {
    let regions = regions(module);
    let mut count = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.unwrap() {
            let mut reader = body.get_operators_reader().unwrap();
            while !reader.eof() {
                let start = reader.original_position();
                let operator = reader.read().unwrap();
                let end = reader.original_position();
                if matches!(operator, Operator::I32Const { value: 79225 }) {
                    count += 1;
                    assert!(regions
                        .iter()
                        .any(|region| region["span"] == json!({"start":start,"end":end})
                            && region["description"].as_str().unwrap().contains("79225")));
                }
            }
        }
    }
    assert_eq!(count, 2);
}

#[test]
fn each_file_retains_unknown_custom_and_new_feature_locations_under_core1() {
    let temp = Temp::new();
    let repo = temp.repository();
    let unknown = [
        HEADER,
        &[
            14, 3, 0x41, 1, 0x0b, 1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 10, 7, 1, 5, 0, 0x41, 42, 0x1a,
            0x0b,
        ],
    ]
    .concat();
    let custom = [HEADER, &[0, 9, 4, b'n', b'a', b'm', b'e', 1, 2, 0x80, 0]].concat();
    let gc = wat::parse_str("(module (type $s (struct (field i32))) (func struct.new_default $s drop i32.const 79225 drop) (func i32.const 79225 drop))").unwrap();
    let eh = wat::parse_str("(module (tag $e) (func (block $caught (try_table (catch $e $caught) throw $e)) i32.const 79225 drop) (func i32.const 79225 drop))").unwrap();
    for (file, bytes) in [
        ("unknown.wasm", &unknown),
        ("custom.wasm", &custom),
        ("gc.wasm", &gc),
        ("exceptions.wasm", &eh),
    ] {
        stage(&repo, file, bytes);
    }
    let revision = commit(&repo, "independent feature and convention frontiers");
    for standard in ["core1", "core3"] {
        let report = query_readonly(
            &temp,
            &[
                "inspect",
                &revision,
                "--repo",
                path(&repo),
                "--standard",
                standard,
                "--json",
            ],
        );
        let files = rows(&report);
        assert_eq!(files.len(), 4);
        for (file, bytes) in [
            ("unknown.wasm", &unknown),
            ("custom.wasm", &custom),
            ("gc.wasm", &gc),
            ("exceptions.wasm", &eh),
        ] {
            let audit = &files[file]["report"]["audit"];
            check_audit(audit, bytes);
            assert_eq!(audit["standard"]["selected_standard"], standard);
            assert_eq!(files[file]["report"]["input"]["file"], file);
        }
        let unknown_audit = &files["unknown.wasm"]["report"]["audit"];
        assert_eq!(unknown_audit["sections"][0]["id"], 14);
        assert_eq!(unknown_audit["sections"][0]["status"], "opaque");
        assert!(regions(unknown_audit)
            .iter()
            .any(|region| region["description"].as_str().unwrap().contains("42")));
        let custom_audit = &files["custom.wasm"]["report"]["audit"];
        assert_eq!(custom_audit["sections"][0]["kind"], "custom:name");
        assert_eq!(custom_audit["sections"][0]["status"], "opaque");
        assert_eq!(custom_audit["standard"]["validation"], "valid");
        for (file, bytes) in [("gc.wasm", &gc), ("exceptions.wasm", &eh)] {
            let audit = &files[file]["report"]["audit"];
            sentinel_operators(audit, bytes);
            if standard == "core1" {
                assert_eq!(audit["standard"]["validation"], "invalid");
                assert!(audit["standard"]["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item["status"] == "recognized_but_disabled"));
            } else {
                assert_eq!(audit["standard"]["validation"], "valid");
            }
        }
    }
}

#[test]
fn corrupt_or_zero_length_worktree_bytes_are_binary_changes_and_not_missing_paths() {
    let temp = Temp::new();
    let repo = temp.repository();
    let original = module(1);
    stage(&repo, A, &original);
    stage(&repo, B, HEADER);
    commit(&repo, "valid tracked bytes");
    let mut corrupt = original.clone();
    corrupt[0] = b'X';
    write(&repo, A, &corrupt);
    let invalid = query_readonly(
        &temp,
        &["diff", path(&repo), "--file", A, "--format", "json"],
    );
    assert_eq!(invalid["schema_version"], 1);
    assert_eq!(invalid["binary_changed"], true);
    assert_eq!(invalid["audit"]["exact_minimal"], false);
    witness(
        &invalid["audit"]["binary_witnesses"]["old"],
        &original,
        "old",
    );
    witness(
        &invalid["audit"]["binary_witnesses"]["new"],
        &corrupt,
        "new",
    );
    replay(&invalid, &original, &corrupt);
    write(&repo, A, &[]);
    let empty = query_readonly(&temp, &["diff", path(&repo), "--format", "json"]);
    let files = rows(&empty);
    let row = files[A];
    assert_eq!(row["status"], "modified");
    assert!(!row["new"].is_null());
    assert!(row["content"].is_null());
    let pair = &row["diff"];
    witness(&pair["audit"]["binary_witnesses"]["new"], &[], "new");
    assert_eq!(pair["audit"]["new"]["view"], "binary");
    assert_eq!(pair["audit"]["new"]["byte_len"], 0);
    replay(pair, &original, &[]);
    fs::remove_file(repo.join(A)).unwrap();
    let missing = query_readonly(&temp, &["diff", path(&repo), "--format", "json"]);
    let files = rows(&missing);
    let row = files[A];
    assert_eq!(row["status"], "deleted");
    assert!(row["new"].is_null());
    assert!(row["diff"].is_null());
    witness(&row["content"], &original, "old");
}
