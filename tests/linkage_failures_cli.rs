//! Fixed malformed import/export names and kinds; no Wasm guest is executed.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const PROFILES: [&str; 4] = ["core1", "core2", "core3", "all-known"];
const CASES: [&str; 6] = [
    "ordinary-module-utf8",
    "ordinary-item-utf8",
    "compact1-second-name-utf8",
    "compact2-second-name-utf8",
    "export-name-utf8",
    "export-exact-kind",
];
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-linkage-cli-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.path(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn success(arguments: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(arguments)
        .output()
        .expect("execute wasm-git");
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn run_json(arguments: &[&str]) -> Value {
    serde_json::from_str(&success(arguments)).expect("CLI JSON")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn span(start: usize, end: usize) -> Value {
    json!({"start": start, "end": end})
}
fn range(value: &Value, bytes: &[u8]) -> (usize, usize) {
    let start = usize::try_from(value["start"].as_u64().unwrap()).unwrap();
    let end = usize::try_from(value["end"].as_u64().unwrap()).unwrap();
    assert!(start <= end && end <= bytes.len());
    (start, end)
}
fn section(bytes: &mut Vec<u8>, kind: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[kind, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

struct Fixture {
    bytes: Vec<u8>,
    parent: String,
    child: String,
    suffix: Value,
    bad: Value,
    operators: [usize; 2],
}
fn fixture(label: &str, new: bool) -> Fixture {
    let bad = if new { 0xfe } else { 0xff };
    let (kind, payload, offset, field) = match label {
        "ordinary-module-utf8" => (2, vec![1, 1, bad, 1, b'f', 0, 0], 2, "module_name/utf8"),
        "ordinary-item-utf8" => (2, vec![1, 1, b'm', 1, bad, 0, 0], 4, "item_name/utf8"),
        "compact1-second-name-utf8" => (
            2,
            vec![1, 1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, bad, 0, 0],
            11,
            "item[1]/name/utf8",
        ),
        "compact2-second-name-utf8" => (
            2,
            vec![1, 1, b'm', 0, 0x7e, 0, 0, 2, 1, b'a', 1, bad],
            11,
            "item[1]/name/utf8",
        ),
        "export-name-utf8" => (7, vec![1, 1, bad, 0, 0], 2, "name/utf8"),
        "export-exact-kind" => (7, vec![1, 1, b'e', 0x20, u8::from(new)], 3, "external_kind"),
        _ => panic!("unknown fixed case {label}"),
    };
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    if kind == 7 {
        section(&mut bytes, 3, &[2, 0, 0]);
    }
    let start = section(&mut bytes, kind, &payload);
    if kind == 2 {
        section(&mut bytes, 3, &[2, 0, 0]);
    }
    // Two real functions make either export index valid if its kind were legal.
    let code = section(
        &mut bytes,
        10,
        &[2, 5, 0, 0x41, 42, 0x1a, 0x0b, 5, 0, 0x41, 43, 0x1a, 0x0b],
    );
    let parent = format!(
        "{}[0]/undecoded",
        if kind == 2 { "import" } else { "export" }
    );
    Fixture {
        bytes,
        child: format!("{parent}/{field}"),
        parent,
        suffix: span(start + 1, start + payload.len()),
        bad: span(start + offset, start + offset + 1),
        operators: [code + 3, code + 9],
    }
}
fn collect<'a>(entries: &'a Value, result: &mut Vec<&'a Value>) {
    for entry in entries.as_array().unwrap() {
        result.push(entry);
        if let Some(children) = entry.get("regions") {
            collect(children, result);
        }
        if let Some(children) = entry.get("children") {
            collect(children, result);
        }
    }
}
fn regions(audit: &Value) -> Vec<&Value> {
    let mut result = Vec::new();
    collect(&audit["sections"], &mut result);
    result
}
fn find<'a>(audit: &'a Value, path: &str) -> &'a Value {
    regions(audit)
        .into_iter()
        .find(|entry| entry["path"] == path)
        .unwrap_or_else(|| panic!("missing physical path {path}"))
}
fn raw_audit(audit: &Value, input: &Fixture) {
    assert_eq!(audit["byte_len"], input.bytes.len());
    for entry in regions(audit) {
        range(&entry["span"], &input.bytes);
    }
    for evidence in audit["standard"]["evidence"].as_array().unwrap() {
        let (a, b) = range(&evidence["span"], &input.bytes);
        assert_eq!(evidence["raw_hex"], hex(&input.bytes[a..b]));
    }
}
fn check_inspection(report: &Value, input: &Fixture) {
    let audit = &report["audit"];
    raw_audit(audit, input);
    assert_eq!(report["function_analysis"]["available"], false);
    assert_eq!(audit["validation"], "failed_or_unsupported");
    assert_eq!(audit["standard"]["validation"], "invalid");
    assert_eq!(audit["standard"]["validator_valid"], false);
    let parent = find(audit, &input.parent);
    let child = find(audit, &input.child);
    assert_eq!(parent["span"], input.suffix);
    assert_eq!(parent["standard_support"]["status"], "invalid_encoding");
    assert_eq!(child["span"], input.bad);
    assert_eq!(child["feature"], "invalid_encoding");
    assert_eq!(child["standard_support"]["status"], "invalid_encoding");
    let evidence: Vec<_> = audit["standard"]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["path"] == input.child)
        .collect();
    assert!(!evidence.is_empty());
    assert!(evidence
        .iter()
        .all(|entry| entry["span"] == input.bad && entry["status"] == "invalid_encoding"));
    for (index, offset) in input.operators.into_iter().enumerate() {
        let operator = find(audit, &format!("code[0]/function[{index}]/operator[0]"));
        assert_eq!(operator["span"], span(offset, offset + 2));
        assert_eq!(&input.bytes[offset..offset + 2], &[0x41, 42 + index as u8]);
        assert_eq!(operator["standard_support"]["status"], "supported");
    }
}

#[test]
fn ordinary_names_and_export_kinds_have_precise_invalid_encoding_evidence() {
    let temp = Temp::new();
    for label in [CASES[0], CASES[1], CASES[4], CASES[5]] {
        for new in [false, true] {
            let input = fixture(label, new);
            let path = temp.write(&format!("{label}-{new}.wasm"), &input.bytes);
            for profile in PROFILES {
                check_inspection(
                    &run_json(&["inspect", &path, "--json", "--standard", profile]),
                    &input,
                );
                let text = success(&[
                    "diff",
                    &path,
                    &path,
                    "--format",
                    "text",
                    "--standard",
                    profile,
                ]);
                assert!(text.contains(&format!("invalid_encoding {}", input.child)));
                let (start, end) = range(&input.bad, &input.bytes);
                assert!(text.contains(&format!("binary={}", hex(&input.bytes[start..end]))));
            }
            assert_eq!(std::fs::read(path).unwrap(), input.bytes);
        }
    }
}

#[test]
fn a_bad_second_compact_name_withdraws_its_group_but_keeps_the_known_bad_field() {
    let temp = Temp::new();
    for label in [CASES[2], CASES[3]] {
        let input = fixture(label, false);
        let path = temp.write(&format!("{label}.wasm"), &input.bytes);
        for profile in PROFILES {
            let report = run_json(&["inspect", &path, "--json", "--standard", profile]);
            check_inspection(&report, &input);
            assert!(regions(&report["audit"]).iter().all(|entry| {
                !entry["path"]
                    .as_str()
                    .unwrap()
                    .starts_with("import[0]/group[0]")
            }));
            assert!(
                report["audit"]["standard"]["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|entry| {
                        !entry["path"]
                            .as_str()
                            .unwrap()
                            .starts_with("import[0]/group[0]")
                    }),
                "the valid first name cannot publish a partial group or shared type"
            );
            assert!(find(&report["audit"], "code[0]/function[0]")["description"]
                .as_str()
                .unwrap()
                .contains("function_index=unknown"));
        }
        assert_eq!(std::fs::read(path).unwrap(), input.bytes);
    }
}

fn replay(old: &[u8], new: &[u8], edits: &Value) {
    let (mut a, mut b) = (0, 0);
    let mut output = Vec::new();
    for edit in edits.as_array().unwrap() {
        let (x, y) = range(&edit["old_span"], old);
        let (u, v) = range(&edit["new_span"], new);
        assert!(a <= x && b <= u);
        assert_eq!(&old[a..x], &new[b..u]);
        assert_eq!(edit["old_hex"], hex(&old[x..y]));
        assert_eq!(edit["new_hex"], hex(&new[u..v]));
        output.extend_from_slice(&old[a..x]);
        output.extend_from_slice(&new[u..v]);
        a = y;
        b = v;
    }
    assert_eq!(&old[a..], &new[b..]);
    output.extend_from_slice(&old[a..]);
    assert_eq!(output, new);
}

#[test]
fn malformed_linkage_bytes_roundtrip_through_profile_diff_and_bidirectional_patches() {
    let temp = Temp::new();
    for label in CASES {
        let a = fixture(label, false);
        let b = fixture(label, true);
        let a_path = temp.write(&format!("{label}-old.wasm"), &a.bytes);
        let b_path = temp.write(&format!("{label}-new.wasm"), &b.bytes);
        for (direction, old, new, old_path, new_path) in [
            ("forward", &a, &b, &a_path, &b_path),
            ("reverse", &b, &a, &b_path, &a_path),
        ] {
            let mut expected = None;
            for profile in PROFILES {
                let report = run_json(&[
                    "diff",
                    old_path,
                    new_path,
                    "--format",
                    "json",
                    "--standard",
                    profile,
                ]);
                assert_eq!(report["binary_changed"], true);
                assert_eq!(report["function_analysis"]["available"], false);
                raw_audit(&report["audit"]["old"], old);
                raw_audit(&report["audit"]["new"], new);
                replay(&old.bytes, &new.bytes, &report["audit"]["edits"]);
                if let Some(previous) = &expected {
                    assert_eq!(previous, &report["audit"]["edits"]);
                } else {
                    expected = Some(report["audit"]["edits"].clone());
                }
            }
            let patch = temp.path(&format!("{label}-{direction}.patch"));
            let applied = temp.path(&format!("{label}-{direction}.wasm"));
            run_json(&["patch", old_path, new_path, "--output", &patch]);
            let encoded = std::fs::read(&patch).unwrap();
            let stored: Value = serde_json::from_slice(&encoded).unwrap();
            replay(&old.bytes, &new.bytes, &stored["edits"]);
            run_json(&["apply", old_path, &patch, "--output", &applied]);
            assert_eq!(std::fs::read(applied).unwrap(), new.bytes);
            assert_eq!(std::fs::read(patch).unwrap(), encoded);
        }
        assert_eq!(std::fs::read(a_path).unwrap(), a.bytes);
        assert_eq!(std::fs::read(b_path).unwrap(), b.bytes);
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                result.insert(relative, None);
                visit(root, &path, result);
            } else {
                result.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn precise_failure_paths_survive_commits_and_match_range_traces_without_invented_events() {
    for label in CASES {
        let temp = Temp::new();
        let old = fixture(label, false);
        let new = fixture(label, true);
        let old_path = temp.write("old.wasm", &old.bytes);
        let new_path = temp.write("new.wasm", &new.bytes);
        let repo = temp.path("repo");
        success(&["init", &repo]);
        success(&["commit", &repo, &old_path, "-m", "old malformed linkage"]);
        success(&["commit", &repo, &new_path, "-m", "new malformed linkage"]);
        let before = snapshot(Path::new(&repo));
        let (start, end) = range(&new.bad, &new.bytes);
        let numeric = format!("{start}:{end}");
        let named = run_json(&["trace", &repo, "HEAD", "--path", &new.child]);
        let ranged = run_json(&["trace", &repo, "HEAD", "--range", &numeric]);
        assert_eq!(named["selection"]["span"], new.bad);
        assert_eq!(named["trace"], ranged["trace"]);
        assert_eq!(named["repository_verified"], true);
        assert_eq!(named["trace"]["complete"], true);
        assert_eq!(named["trace"]["identity_unproven"], true);
        let edges = named["trace"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        let edge = &edges[0];
        let events = edge["events"].as_array().unwrap();
        if label == "export-exact-kind" {
            assert_eq!(&old.bytes[start..end], &[0x20]);
            assert_eq!(&new.bytes[start..end], &[0x20]);
            assert!(
                events.is_empty(),
                "an unchanged forbidden kind is not an index-edit event"
            );
            assert!(
                edge["gap_mappings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|mapping| {
                        mapping["child"]["span"] == new.bad && mapping["parent"]["span"] == old.bad
                    }),
                "the selected original 20 byte must be retained by an equal-gap mapping"
            );
            assert_eq!(old.bytes[end], 0);
            assert_eq!(new.bytes[end], 1);
        } else {
            assert!(
                !events.is_empty(),
                "the selected invalid UTF-8 byte actually changed"
            );
        }
        for event in events {
            let edit = &event["edit"];
            let (a, b) = range(&edit["old_span"], &old.bytes);
            let (c, d) = range(&edit["new_span"], &new.bytes);
            assert_eq!(edit["old_hex"], hex(&old.bytes[a..b]));
            assert_eq!(edit["new_hex"], hex(&new.bytes[c..d]));
        }
        let checked = run_json(&["fsck", &repo]);
        assert_eq!(checked["commits"], 2);
        assert_eq!(checked["wasm_blobs"], 2);
        assert_eq!(
            snapshot(Path::new(&repo)),
            before,
            "trace and fsck must preserve every repo file and directory"
        );
        assert_eq!(std::fs::read(old_path).unwrap(), old.bytes);
        assert_eq!(std::fs::read(new_path).unwrap(), new.bytes);
    }
}
