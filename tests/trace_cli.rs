//! Physical-byte history queries. All repositories, fixtures and outputs stay
//! in /tmp; no Wasm fixture is executed.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use wasmparser::{Operator, Parser, Payload, Validator, WasmFeatures};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct History {
    directory: PathBuf,
    repo: String,
    bytes: BTreeMap<String, Vec<u8>>,
}

impl History {
    fn new(label: &str) -> Self {
        let directory = Path::new("/tmp").join(format!(
            "uwgit-trace-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let repo = directory.join("repo").to_string_lossy().into_owned();
        success(&["init", &repo]);
        Self {
            directory,
            repo,
            bytes: BTreeMap::new(),
        }
    }

    fn commit(&mut self, bytes: &[u8], message: &str) -> String {
        let path = self.directory.join("input.wasm");
        std::fs::write(&path, bytes).unwrap();
        let id = success(&["commit", &self.repo, path.to_str().unwrap(), "-m", message])
            .split_whitespace()
            .last()
            .unwrap()
            .to_owned();
        assert_eq!(id.len(), 64);
        self.bytes.insert(id.clone(), bytes.to_vec());
        id
    }

    fn trace(&self, revision: &str, start: usize, end: usize) -> Value {
        let range = format!("{start}:{end}");
        self.query(&["trace", &self.repo, revision, "--range", &range])
    }

    fn query(&self, arguments: &[&str]) -> Value {
        let before = snapshot(&self.directory);
        let result = run_json(arguments);
        assert_eq!(
            snapshot(&self.directory),
            before,
            "trace must leave no files, locks or refs changed"
        );
        assert_eq!(result["schema_version"], 1);
        assert_eq!(result["repository_verified"], true);
        assert_eq!(result["trace"]["identity_unproven"], true);
        result
    }
}

impl Drop for History {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn invoke(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(arguments)
        .output()
        .expect("execute wasm-git")
}

fn success(arguments: &[&str]) -> String {
    let output = invoke(arguments);
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn run_json(arguments: &[&str]) -> Value {
    serde_json::from_str(&success(arguments)).expect("trace emits JSON")
}

fn snapshot(directory: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
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
    visit(directory, directory, &mut result);
    result
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn span(start: usize, end: usize) -> Value {
    json!({"start": start, "end": end})
}

fn physical_range(value: &Value, bytes: &[u8]) -> (usize, usize) {
    let start = usize::try_from(value["start"].as_u64().expect("physical start")).unwrap();
    let end = usize::try_from(value["end"].as_u64().expect("physical end")).unwrap();
    assert!(start <= end && end <= bytes.len());
    (start, end)
}

fn leb(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let byte = value as u8 & 0x7f;
        value >>= 7;
        result.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            return result;
        }
    }
}

// Arbitrary custom data is a valid core module and gives exact, independent
// byte landmarks without making instruction or function identity assumptions.
fn custom(payload: &[u8]) -> (Vec<u8>, usize) {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&leb(payload.len() + 2));
    bytes.extend_from_slice(&[1, b'x']);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    valid(&bytes);
    (bytes, start)
}

fn append_named_custom(bytes: &mut Vec<u8>, name: &str, payload: &[u8]) -> usize {
    let mut outer = leb(name.len());
    outer.extend_from_slice(name.as_bytes());
    let prefix_len = outer.len();
    outer.extend_from_slice(payload);
    bytes.push(0);
    bytes.extend(leb(outer.len()));
    let data_start = bytes.len() + prefix_len;
    bytes.extend(outer);
    data_start
}

fn named_payload_fixture(name: &str, payload: &[u8]) -> (Vec<u8>, usize, usize) {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    let start = append_named_custom(&mut bytes, name, payload);
    let end = bytes.len();
    (bytes, start, end)
}

fn producer_payload(name: &str, version: &str) -> (Vec<u8>, usize) {
    let mut data = vec![1, 8];
    data.extend_from_slice(b"language");
    data.push(1);
    let value_start = data.len();
    data.extend(leb(name.len()));
    data.extend_from_slice(name.as_bytes());
    data.extend(leb(version.len()));
    data.extend_from_slice(version.as_bytes());
    (data, value_start)
}

fn producer_fixture(name: &str, version: &str) -> (Vec<u8>, usize, usize) {
    let (data, value_start) = producer_payload(name, version);
    let (bytes, start, end) = named_payload_fixture("producers", &data);
    (bytes, start + value_start, end)
}

fn assert_canonical_metadata_trace(
    old: Vec<u8>,
    new: Vec<u8>,
    path: &str,
    start: usize,
    end: usize,
) {
    assert!(path.is_ascii());
    let mut history = History::new("canonical-metadata-path");
    let root = history.commit(&old, "original metadata bytes");
    let tip = history.commit(&new, "metadata bytes changed; no identity assertion");
    let named = history.query(&["trace", &history.repo, &tip, "--path", path]);
    let numeric = history.trace(&tip, start, end);
    assert_eq!(named["selection"]["span"], span(start, end));
    assert_eq!(named["selection"]["path"], path);
    assert_eq!(named["trace"], numeric["trace"]);
    assert_eq!(named["trace"]["complete"], true);
    assert_eq!(named["trace"]["identity_unproven"], true);
    assert!(!edge(&named["trace"], &root, &tip)["events"]
        .as_array()
        .unwrap()
        .is_empty());
    verify_evidence(&history, &named);
    verify_evidence(&history, &numeric);
}

fn valid(bytes: &[u8]) {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .expect("valid fixture before deliberate unknown encoding");
}

fn wat(source: &str) -> Vec<u8> {
    let bytes = wat::parse_str(source).unwrap();
    valid(&bytes);
    bytes
}

fn edge<'a>(report: &'a Value, parent: &str, child: &str) -> &'a Value {
    report["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["parent"] == parent && edge["child"] == child)
        .expect("every selected parent edge must be retained")
}

fn node<'a>(report: &'a Value, commit: &str) -> &'a Value {
    report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["commit"] == commit)
        .expect("selected ancestor node")
}

fn has_selected(node: &Value, start: usize, end: usize, scope: &str) -> bool {
    node["selected"]
        .as_array()
        .unwrap()
        .iter()
        .any(|range| range["span"] == span(start, end) && range["scope"] == scope)
}

fn verify_evidence(history: &History, result: &Value) {
    let report = &result["trace"];
    let tip = report["tip"].as_str().unwrap();
    assert!(history.bytes.contains_key(tip));
    assert_eq!(report["query"], result["selection"]["span"]);
    physical_range(&report["query"], &history.bytes[tip]);
    for node in report["nodes"].as_array().unwrap() {
        let bytes = &history.bytes[node["commit"].as_str().unwrap()];
        for range in node["selected"].as_array().unwrap() {
            let (start, end) = physical_range(&range["span"], bytes);
            assert!(
                start < end,
                "empty anchors cannot become selected ancestor bytes"
            );
            assert!(matches!(
                range["scope"].as_str(),
                Some("requested" | "aligned" | "influence")
            ));
        }
    }
    for edge in report["edges"].as_array().unwrap() {
        let old = &history.bytes[edge["parent"].as_str().unwrap()];
        let new = &history.bytes[edge["child"].as_str().unwrap()];
        for gap in edge["gap_mappings"].as_array().unwrap() {
            let (old_start, old_end) = physical_range(&gap["parent"]["span"], old);
            let (new_start, new_end) = physical_range(&gap["child"]["span"], new);
            assert!(old_start < old_end && new_start < new_end);
            assert_eq!(
                hex(&old[old_start..old_end]),
                hex(&new[new_start..new_end]),
                "a gap mapping must bind actual equal bytes"
            );
        }
        for event in edge["events"].as_array().unwrap() {
            let edit = &event["edit"];
            let (old_start, old_end) = physical_range(&edit["old_span"], old);
            let (new_start, new_end) = physical_range(&edit["new_span"], new);
            assert_eq!(edit["old_hex"], hex(&old[old_start..old_end]));
            assert_eq!(edit["new_hex"], hex(&new[new_start..new_end]));
            assert!(old_start < old_end || new_start < new_end);
            for overlap in event["overlaps"].as_array().unwrap() {
                let (start, end) = physical_range(&overlap["span"], new);
                if overlap["kind"] == "boundary_touch" {
                    assert_eq!(start, end);
                    assert_eq!(new_start, new_end);
                    assert_eq!(start, new_start);
                } else {
                    assert_eq!(overlap["kind"], "byte_overlap");
                    assert!(start < end && new_start <= start && end <= new_end);
                }
            }
        }
        for range in edge["parent_influence"].as_array().unwrap() {
            let (start, end) = physical_range(&range["span"], old);
            assert!(start < end);
        }
    }
}

#[test]
fn exact_paths_select_physical_regions_and_empty_or_missing_paths_fail() {
    let mut history = History::new("paths");
    let bytes = wat("(module (func (result i32) i32.const 17))");
    let tip = history.commit(&bytes, "root");
    let module = wasm_git::audit::inspect(&bytes).unwrap();
    let code = module
        .sections
        .iter()
        .find(|section| section.id == 10)
        .unwrap();
    let function = code
        .regions
        .iter()
        .find(|region| region.path == "code[0]/function[0]")
        .unwrap();
    let operator = function
        .children
        .iter()
        .find(|region| region.path.ends_with("/operator[0]"))
        .unwrap();
    for (path, start, end) in [
        ("module", 0, bytes.len()),
        ("code[0]", code.span.start, code.span.end),
        (
            "code[0]/function[0]/operator[0]",
            operator.span.start,
            operator.span.end,
        ),
    ] {
        let selected = history.query(&["trace", &history.repo, "HEAD", "--path", path]);
        assert_eq!(
            selected["selection"],
            json!({"kind":"path", "path":path, "span":span(start,end)})
        );
        assert_eq!(selected["trace"]["tip"], tip);
        assert_eq!(selected["trace"]["complete"], true);
        assert_eq!(node(&selected["trace"], &tip)["status"], "root_snapshot");
        verify_evidence(&history, &selected);
    }
    assert_eq!(hex(&bytes[operator.span.start..operator.span.end]), "4111");
    let (empty, _) = custom(&[]);
    let empty_tip = history.commit(&empty, "empty custom payload");
    for path in [
        "",
        "absent",
        "code",
        "code[9]",
        "custom[0]/payload/opaque",
        "custom[0]/x/opaque",
    ] {
        let before = snapshot(&history.directory);
        let output = invoke(&["trace", &history.repo, &empty_tip, "--path", path]);
        assert!(
            !output.status.success(),
            "nonexistent or empty path {path:?}"
        );
        if path == "custom[0]/payload/opaque" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("empty region"));
        }
        if path == "custom[0]/x/opaque" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("not present"));
        }
        assert_eq!(snapshot(&history.directory), before);
    }
}

#[test]
fn canonical_metadata_paths_select_nul_slash_unicode_and_empty_names() {
    for (old_name, new_name) in [
        ("\0before", "\0after"),
        ("slash/旧名", "slash/新名"),
        ("", ""),
    ] {
        let (old, _, _) = named_payload_fixture(old_name, &[0x31, 0x42, 0x53]);
        let (new, start, end) = named_payload_fixture(new_name, &[0x31, 0x64, 0x53]);
        assert_canonical_metadata_trace(old, new, "custom[0]/payload/opaque", start, end);
        let (old, _, _) = producer_fixture(old_name, "version/旧");
        let (new, start, end) = producer_fixture(new_name, "version/新");
        assert_canonical_metadata_trace(
            old,
            new,
            "custom[0]/producers/language/value[0]",
            start,
            end,
        );
    }
}

#[test]
fn canonical_metadata_paths_do_not_put_fixed_long_names_into_process_arguments() {
    // One fixed length exceeds both the pinned100000 string limit and the
    // usual single-argument byte limit. Trace operates on raw module bytes.
    let name = "x".repeat(131_073);
    let (old, _, _) = named_payload_fixture(&name, &[0x31, 0x42, 0x53]);
    let (new, start, end) = named_payload_fixture(&name, &[0x31, 0x64, 0x53]);
    assert_canonical_metadata_trace(old, new, "custom[0]/payload/opaque", start, end);
    let (old, _, _) = producer_fixture(&name, "1");
    let (new, start, end) = producer_fixture(&name, "2");
    assert_canonical_metadata_trace(
        old,
        new,
        "custom[0]/producers/language/value[0]",
        start,
        end,
    );
}

#[test]
fn opaque_names_and_producer_metadata_do_not_change_function_identity_or_feature_policy() {
    let core =
        wat("(module (func (export \"run\") v128.const i32x4 0 0 0 0 drop i32.const 42 drop))");
    let metadata_module = |malformed: bool| {
        let mut bytes = core[..8].to_vec();
        let names = if malformed {
            // Duplicate function index0 violates the recognized fixed name map.
            vec![1, 7, 2, 0, 1, b'A', 0, 1, b'B']
        } else {
            vec![1, 4, 1, 0, 1, b'A']
        };
        append_named_custom(&mut bytes, "name", &names);
        let (producer, _) = producer_payload(
            if malformed {
                "\0compiler/新"
            } else {
                "\0compiler/旧"
            },
            if malformed { "2" } else { "1" },
        );
        append_named_custom(&mut bytes, "producers", &producer);
        append_named_custom(
            &mut bytes,
            "target_features",
            &[
                1,
                if malformed { b'-' } else { b'+' },
                4,
                b's',
                b'i',
                b'm',
                b'd',
            ],
        );
        bytes.extend_from_slice(&core[8..]);
        bytes
    };
    let old = metadata_module(false);
    let new = metadata_module(true);
    let mut history = History::new("metadata-projection");
    let root = history.commit(&old, "recognized optional metadata");
    let tip = history.commit(
        &new,
        "opaque names and renamed producer; physical metadata change",
    );
    for standard in ["core1", "core2", "core3", "all-known"] {
        let before = run_json(&[
            "inspect",
            &root,
            "--repo",
            &history.repo,
            "--standard",
            standard,
        ]);
        let after = run_json(&[
            "inspect",
            &tip,
            "--repo",
            &history.repo,
            "--standard",
            standard,
        ]);
        assert_eq!(before["function_analysis"]["available"], true);
        assert_eq!(after["function_analysis"]["available"], true);
        assert_eq!(
            before["module"]["functions"][0]["id"],
            after["module"]["functions"][0]["id"]
        );
        assert_eq!(
            before["module"]["functions"][0]["fingerprint"],
            after["module"]["functions"][0]["fingerprint"]
        );
        let expected = if standard == "core1" {
            "invalid"
        } else {
            "valid"
        };
        assert_eq!(before["audit"]["standard"]["validation"], expected);
        assert_eq!(after["audit"]["standard"]["validation"], expected);
        assert!(after["audit"]["sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| { section["kind"] == "custom:name" && section["status"] == "opaque" }));
        let diff = run_json(&[
            "diff",
            &root,
            &tip,
            "--repo",
            &history.repo,
            "--format",
            "json",
            "--standard",
            standard,
        ]);
        assert_eq!(diff["binary_changed"], true);
        assert!(!diff["audit"]["edits"].as_array().unwrap().is_empty());
        assert_eq!(diff["function_analysis"]["available"], true);
        assert_eq!(diff["summary"]["functions_changed"], 0);
        assert_eq!(diff["function_matches"].as_array().unwrap().len(), 1);
        assert_eq!(
            diff["function_matches"][0]["old_id"],
            diff["function_matches"][0]["new_id"]
        );
    }
    let inspected = wasm_git::audit::inspect(&new).unwrap();
    let value = inspected
        .sections
        .iter()
        .flat_map(|section| &section.regions)
        .flat_map(|region| &region.children)
        .find(|region| region.path == "custom[1]/producers/language/value[0]")
        .unwrap();
    let named = history.query(&[
        "trace",
        &history.repo,
        &tip,
        "--path",
        "custom[1]/producers/language/value[0]",
    ]);
    let numeric = history.trace(&tip, value.span.start, value.span.end);
    assert_eq!(named["trace"], numeric["trace"]);
    verify_evidence(&history, &named);
}

#[test]
fn unchanged_bytes_shift_across_insertions_without_claiming_identity() {
    let mut history = History::new("shift");
    let (old, old_data) = custom(&[0x31, 0x42, 0x53, 0x64, 0x75]);
    let (new, new_data) = custom(&[0x99, 0x31, 0x42, 0x53, 0x64, 0x75]);
    let root = history.commit(&old, "root");
    let tip = history.commit(&new, "prefix insertion");
    let result = history.trace("HEAD", new_data + 3, new_data + 5);
    assert_eq!(
        result["selection"],
        json!({"kind":"range","path":null,"span":span(new_data+3,new_data+5)})
    );
    let report = &result["trace"];
    assert_eq!(report["tip"], tip);
    assert_eq!(report["complete"], true);
    let mapping = &edge(report, &root, &tip)["gap_mappings"][0];
    assert_eq!(mapping["child"]["span"], span(new_data + 3, new_data + 5));
    assert_eq!(mapping["parent"]["span"], span(old_data + 2, old_data + 4));
    assert_eq!(hex(&old[old_data + 2..old_data + 4]), "5364");
    assert!(has_selected(
        node(report, &root),
        old_data + 2,
        old_data + 4,
        "aligned"
    ));
    verify_evidence(&history, &result);
}

#[test]
fn whole_old_change_blocks_expand_scope_and_influence_survives_unchanged_ancestors() {
    let mut history = History::new("influence");
    let (old, data) = custom(&[0x11, 0x21, 0x22, 0x23, 0x31]);
    let (new, _) = custom(&[0x11, 0x41, 0x42, 0x43, 0x31]);
    let root = history.commit(&old, "root");
    let before = history.commit(&old, "same original bytes");
    let changed = history.commit(&new, "replacement block");
    let tip = history.commit(&new, "same modified bytes");
    let result = history.trace(&tip, data + 2, data + 3);
    let report = &result["trace"];
    assert_eq!(report["complete"], true);
    let event = &edge(report, &before, &changed)["events"][0];
    assert_eq!(event["disposition"], "replacement_influence");
    assert_eq!(event["edit"]["old_span"], span(data + 1, data + 4));
    assert_eq!(event["edit"]["new_span"], span(data + 1, data + 4));
    assert_eq!(event["edit"]["old_hex"], "212223");
    assert_eq!(event["edit"]["new_hex"], "414243");
    assert_eq!(event["overlaps"][0]["span"], span(data + 2, data + 3));
    assert!(has_selected(
        node(report, &before),
        data + 1,
        data + 4,
        "influence"
    ));
    assert!(has_selected(
        node(report, &root),
        data + 1,
        data + 4,
        "influence"
    ));
    assert_eq!(
        edge(report, &root, &before)["gap_mappings"][0]["parent"]["scope"],
        "influence"
    );
    verify_evidence(&history, &result);
}

#[test]
fn introduced_bytes_stop_at_an_empty_old_anchor() {
    let mut history = History::new("introduction");
    let (old, _) = custom(&[0x31, 0x42, 0x53]);
    let (new, data) = custom(&[0x31, 0x99, 0x42, 0x53]);
    let root = history.commit(&old, "root");
    let tip = history.commit(&new, "new byte");
    let result = history.trace(&tip, data + 1, data + 2);
    let report = &result["trace"];
    assert_eq!(report["complete"], true);
    let incoming = edge(report, &root, &tip);
    assert!(incoming["parent_influence"].as_array().unwrap().is_empty());
    let event = &incoming["events"][0];
    assert_eq!(event["disposition"], "introduced_no_old_bytes");
    assert_eq!(event["edit"]["old_span"], span(data + 1, data + 1));
    assert_eq!(event["edit"]["new_span"], span(data + 1, data + 2));
    assert_eq!(event["edit"]["old_hex"], "");
    assert_eq!(event["edit"]["new_hex"], "99");
    assert!(report["frontier"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["reason"] == "introduced_no_old_bytes"));
    assert!(!report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["commit"] == root));
    verify_evidence(&history, &result);
}

#[test]
fn deletion_boundary_events_include_both_query_endpoints_and_eof() {
    for (label, old_payload, new_payload, query_offset, query_len, deleted_offset) in [
        (
            "start",
            vec![0x11, 0x22, 0x33, 0x44],
            vec![0x11, 0x33, 0x44],
            1,
            1,
            1,
        ),
        (
            "end",
            vec![0x11, 0x22, 0x33, 0x44],
            vec![0x11, 0x33, 0x44],
            0,
            1,
            1,
        ),
        ("eof", vec![0x11, 0x22, 0x33], vec![0x11, 0x22], 1, 1, 2),
    ] {
        let mut history = History::new(label);
        let (old, data) = custom(&old_payload);
        let (new, _) = custom(&new_payload);
        let root = history.commit(&old, "before deletion");
        let tip = history.commit(&new, "delete byte");
        let result = history.trace(&tip, data + query_offset, data + query_offset + query_len);
        let event = edge(&result["trace"], &root, &tip)["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["disposition"] == "deletion_boundary")
            .unwrap();
        assert_eq!(
            event["edit"]["old_span"],
            span(data + deleted_offset, data + deleted_offset + 1)
        );
        assert_eq!(
            event["edit"]["new_span"],
            span(data + deleted_offset, data + deleted_offset)
        );
        assert_eq!(
            event["edit"]["old_hex"],
            hex(&old_payload[deleted_offset..deleted_offset + 1])
        );
        assert_eq!(event["edit"]["new_hex"], "");
        assert_eq!(event["overlaps"][0]["kind"], "boundary_touch");
        assert_eq!(
            event["overlaps"][0]["span"],
            span(data + deleted_offset, data + deleted_offset)
        );
        assert!(has_selected(
            node(&result["trace"], &root),
            data + deleted_offset,
            data + deleted_offset + 1,
            "influence"
        ));
        verify_evidence(&history, &result);
    }
}

#[test]
fn repeated_bytes_have_alignment_relative_evidence_without_unique_origin_claims() {
    let mut history = History::new("repeated");
    let (old, data) = custom(b"ABAB");
    let (new, _) = custom(b"AB");
    let root = history.commit(&old, "two equal copies");
    let tip = history.commit(&new, "one equal copy");
    let result = history.trace(&tip, data, new.len());
    let incoming = edge(&result["trace"], &root, &tip);
    assert_eq!(incoming["exact_minimal"], true);
    assert!(!incoming["alignment"].as_str().unwrap().is_empty());
    assert_eq!(result["trace"]["identity_unproven"], true);
    let event = incoming["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["disposition"] == "deletion_boundary")
        .unwrap();
    assert_eq!(event["edit"]["old_hex"], "4142");
    assert_eq!(event["edit"]["new_hex"], "");
    let (start, end) = physical_range(&event["edit"]["old_span"], &old);
    assert_eq!(end - start, 2);
    assert!(
        start == data || start == data + 2,
        "either repeated occurrence depends on alignment"
    );
    verify_evidence(&history, &result);
}

#[test]
fn manual_merge_retains_ordered_parents_and_both_paths_to_the_common_ancestor() {
    let mut history = History::new("merge");
    let (base_bytes, data) = custom(&[0x11, 0x21, 0x31]);
    let (left_bytes, _) = custom(&[0x11, 0x22, 0x31]);
    let (right_bytes, _) = custom(&[0x11, 0x23, 0x31]);
    let (merged_bytes, _) = custom(&[0x11, 0x24, 0x31]);
    let base = history.commit(&base_bytes, "base");
    success(&["branch", &history.repo, "right", &base]);
    let left = history.commit(&left_bytes, "left");
    success(&["switch", &history.repo, "right"]);
    let right = history.commit(&right_bytes, "right");
    success(&["switch", &history.repo, "main"]);
    let resolved = history.directory.join("resolved.wasm");
    std::fs::write(&resolved, &merged_bytes).unwrap();
    let merged = run_json(&[
        "merge",
        &history.repo,
        &right,
        "-m",
        "reviewed resolution",
        "--resolved",
        resolved.to_str().unwrap(),
        "--expect-head",
        &left,
    ]);
    assert_eq!(merged["status"], "merged_resolved");
    let tip = merged["commit"].as_str().unwrap().to_owned();
    history.bytes.insert(tip.clone(), merged_bytes);
    let result = history.trace(&tip, data + 1, data + 2);
    let report = &result["trace"];
    assert_eq!(report["complete"], true);
    assert_eq!(node(report, &tip)["parents"], json!([left, right]));
    assert_eq!(report["edges"].as_array().unwrap().len(), 4);
    for (parent, child) in [
        (&left, &tip),
        (&right, &tip),
        (&base, &left),
        (&base, &right),
    ] {
        let event = &edge(report, parent, child)["events"][0];
        assert_eq!(event["disposition"], "replacement_influence");
        assert_eq!(event["edit"]["old_span"], span(data + 1, data + 2));
        assert_eq!(event["edit"]["new_span"], span(data + 1, data + 2));
    }
    assert!(has_selected(
        node(report, &base),
        data + 1,
        data + 2,
        "influence"
    ));
    assert_eq!(
        report["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|node| node["commit"] == base)
            .count(),
        1
    );
    verify_evidence(&history, &result);
    let range = format!("{}:{}", data + 1, data + 2);
    let stopped = history.query(&[
        "trace",
        &history.repo,
        &tip,
        "--range",
        &range,
        "--max-edges",
        "0",
    ]);
    assert_eq!(stopped["trace"]["complete"], false);
    assert_eq!(
        node(&stopped["trace"], &tip)["parents"],
        json!([left, right])
    );
    let frontier = stopped["trace"]["frontier"].as_array().unwrap();
    for parent in [&left, &right] {
        assert!(frontier.iter().any(|item| item["reason"] == "max_edges"
            && item["parent"] == *parent
            && item["child"] == tip));
    }
    verify_evidence(&history, &stopped);
}

#[test]
fn converging_parent_paths_union_distinct_ancestor_ranges_without_filling_the_hole() {
    let mut history = History::new("dag-union");
    let (base_bytes, data) = custom(&[0x11, 0x91, 0x92, 0x93, 0x22, 0x91, 0x92, 0x93, 0x66]);
    let (left_bytes, _) = custom(&[0x11, 0x91, 0x92, 0x93, 0x22, 0x66]);
    let (right_bytes, _) = custom(&[0x11, 0x22, 0x91, 0x92, 0x93, 0x66]);
    let (merged_bytes, _) = custom(&[0x11, 0x91, 0x92, 0x93, 0x66]);
    let base = history.commit(&base_bytes, "two repeated byte runs");
    success(&["branch", &history.repo, "right", &base]);
    let left = history.commit(&left_bytes, "preserve first run");
    success(&["switch", &history.repo, "right"]);
    let right = history.commit(&right_bytes, "preserve second run");
    success(&["switch", &history.repo, "main"]);
    let resolved = history.directory.join("resolved.wasm");
    std::fs::write(&resolved, &merged_bytes).unwrap();
    let outcome = run_json(&[
        "merge",
        &history.repo,
        &right,
        "-m",
        "both parent candidates",
        "--resolved",
        resolved.to_str().unwrap(),
        "--expect-head",
        &left,
    ]);
    let tip = outcome["commit"].as_str().unwrap().to_owned();
    history.bytes.insert(tip.clone(), merged_bytes);
    // The middle byte is separated from every deletion anchor on both routes.
    let result = history.trace(&tip, data + 2, data + 3);
    let root_node = node(&result["trace"], &base);
    assert_eq!(
        root_node["selected"],
        json!([
            {"span":span(data+2,data+3),"scope":"aligned"},
            {"span":span(data+6,data+7),"scope":"aligned"}
        ])
    );
    assert_eq!(hex(&base_bytes[data + 2..data + 3]), "92");
    assert_eq!(hex(&base_bytes[data + 6..data + 7]), "92");
    assert_eq!(
        edge(&result["trace"], &base, &left)["gap_mappings"][0]["parent"]["span"],
        span(data + 2, data + 3)
    );
    assert_eq!(
        edge(&result["trace"], &base, &right)["gap_mappings"][0]["parent"]["span"],
        span(data + 6, data + 7)
    );
    assert_eq!(result["trace"]["complete"], true);
    assert_eq!(result["trace"]["edges"].as_array().unwrap().len(), 4);
    verify_evidence(&history, &result);
}

#[test]
fn unknown_code_opaque_custom_and_noncanonical_leb_remain_traceable_as_raw_bytes() {
    let mut history = History::new("unknown");
    let mut old = wat("(module (func i32.const 1 drop))");
    let mut opcode = None;
    for payload in Parser::new(0).parse_all(&old) {
        if let Payload::CodeSectionEntry(body) = payload.unwrap() {
            let mut reader = body.get_operators_reader().unwrap();
            while !reader.eof() {
                let offset = reader.original_position();
                if matches!(reader.read().unwrap(), Operator::I32Const { .. }) {
                    opcode = Some(offset);
                }
            }
        }
    }
    let opcode = opcode.unwrap();
    old[opcode] = 0xff;
    old.extend_from_slice(&[0, 7, 4, b'n', b'a', b'm', b'e', 1, 0x80]);
    let mut new = old.clone();
    new[opcode] = 0xf5;
    *new.last_mut().unwrap() = 0x81;
    let root = history.commit(&old, "unknown code and opaque name");
    let tip = history.commit(&new, "raw unknown changes");
    for (start, end, old_hex, new_hex) in [
        (opcode, opcode + 1, "ff", "f5"),
        (new.len() - 1, new.len(), "80", "81"),
    ] {
        let result = history.trace(&tip, start, end);
        let incoming = edge(&result["trace"], &root, &tip);
        assert_eq!(incoming["events"][0]["edit"]["old_hex"], old_hex);
        assert_eq!(incoming["events"][0]["edit"]["new_hex"], new_hex);
        assert!(incoming["child_diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "unknown_operator"));
        assert!(incoming["child_diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "custom_opaque"));
        verify_evidence(&history, &result);
    }
    let mut old = b"\0asm\x01\0\0\0".to_vec();
    old.extend_from_slice(&[1, 5, 1, 0x60, 0, 1, 0x7f, 3, 2, 1, 0]);
    let mut new = old.clone();
    old.extend_from_slice(&[10, 6, 1, 4, 0, 0x41, 1, 0x0b]);
    new.extend_from_slice(&[10, 7, 1, 5, 0, 0x41, 0x81, 0, 0x0b]);
    valid(&old);
    valid(&new);
    let canonical = history.commit(&old, "canonical integer");
    let overlong = history.commit(&new, "overlong integer");
    let result = history.query(&[
        "trace",
        &history.repo,
        &overlong,
        "--path",
        "code[0]/function[0]/operator[0]",
    ]);
    assert_eq!(
        result["selection"]["span"],
        span(new.len() - 4, new.len() - 1)
    );
    let incoming = edge(&result["trace"], &canonical, &overlong);
    let edits = incoming["events"].as_array().unwrap();
    assert!(!edits.is_empty());
    assert!(edits
        .iter()
        .any(|event| event["edit"]["new_hex"].as_str().unwrap().contains("81")));
    verify_evidence(&history, &result);
}

#[test]
fn budgets_and_fallback_stop_propagation_with_explicit_incomplete_frontiers() {
    let mut history = History::new("limits");
    let (old, data) = custom(&[0x11, 0x21, 0x31]);
    let (new, _) = custom(&[0x11, 0x22, 0x31]);
    let root = history.commit(&old, "root");
    let tip = history.commit(&new, "change");
    let range = format!("{}:{}", data + 1, data + 2);
    for (option, reason) in [
        ("--max-edges", "max_edges"),
        ("--max-bytes", "max_compared_bytes"),
    ] {
        let result = history.query(&["trace", &history.repo, &tip, "--range", &range, option, "0"]);
        assert_eq!(result["trace"]["complete"], false);
        assert!(result["trace"]["frontier"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["reason"] == reason));
        assert_eq!(node(&result["trace"], &tip)["parents"], json!([root]));
        assert!(!result["trace"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["commit"] == root));
        verify_evidence(&history, &result);
    }
    let (old, data) = custom(&vec![0; 1200]);
    let (new, _) = custom(&vec![1; 1200]);
    let before = history.commit(&old, "large original payload");
    let after = history.commit(&new, "large replacement");
    assert!(!wasm_git::audit::compare(&old, &new).unwrap().exact_minimal);
    let result = history.trace(&after, data, new.len());
    let report = &result["trace"];
    assert_eq!(report["complete"], false);
    let stopped = edge(report, &before, &after);
    assert_eq!(stopped["status"], "stopped");
    assert_eq!(stopped["exact_minimal"], false);
    assert_eq!(stopped["stopped_reason"], "alignment_fallback");
    assert!(stopped["parent_influence"].as_array().unwrap().is_empty());
    assert!(report["frontier"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["reason"] == "alignment_fallback"));
    assert!(!report["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["commit"] == before));
    verify_evidence(&history, &result);
}

#[test]
fn range_selection_is_strict_and_rejections_do_not_mutate_history() {
    let mut history = History::new("invalid-ranges");
    let (bytes, _) = custom(b"range");
    let tip = history.commit(&bytes, "root");
    let too_long = format!("0:{}", bytes.len() + 1);
    for range in [
        "",
        "0",
        ":1",
        "0:",
        "0:0",
        "5:4",
        "-1:2",
        "+1:2",
        " 0:1",
        "0:1 ",
        "0:1:2",
        "0x0:1",
        "０:1",
        "0:18446744073709551616",
        too_long.as_str(),
    ] {
        let before = snapshot(&history.directory);
        let output = invoke(&["trace", &history.repo, &tip, "--range", range]);
        assert!(
            !output.status.success(),
            "invalid range {range:?} must fail"
        );
        assert_eq!(
            snapshot(&history.directory),
            before,
            "invalid range {range:?} wrote files"
        );
    }
    for arguments in [
        vec!["trace", &history.repo, &tip],
        vec![
            "trace",
            &history.repo,
            &tip,
            "--range",
            "0:1",
            "--path",
            "module",
        ],
        vec![
            "trace",
            &history.repo,
            &tip,
            "--range",
            "0:1",
            "--max-edges",
            "-1",
        ],
        vec![
            "trace",
            &history.repo,
            &tip,
            "--range",
            "0:1",
            "--max-bytes",
            "18446744073709551616",
        ],
    ] {
        let before = snapshot(&history.directory);
        assert!(!invoke(&arguments).status.success(), "{arguments:?}");
        assert_eq!(snapshot(&history.directory), before);
    }
}

#[test]
fn help_never_reads_even_nonexistent_or_locked_repositories() {
    let history = History::new("help");
    let missing = history
        .directory
        .join("absent")
        .to_string_lossy()
        .into_owned();
    let lock = Path::new(&history.repo).join(".uwgit/write.lock");
    std::fs::write(&lock, b"owned by another writer\n").unwrap();
    let before = snapshot(&history.directory);
    for arguments in [
        vec!["trace", "--help"],
        vec![
            "trace",
            &missing,
            "missing-revision",
            "--range",
            "bad",
            "--help",
        ],
        vec!["trace", &history.repo, "HEAD", "--path", "module", "--help"],
    ] {
        let output = invoke(&arguments);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
        assert_eq!(snapshot(&history.directory), before);
    }
}

#[test]
fn locked_or_corrupt_history_is_rejected_without_cleaning_someone_elses_files() {
    let mut history = History::new("corrupt");
    let (bytes, _) = custom(b"evidence");
    let root = history.commit(&bytes, "root");
    let tip = history.commit(&bytes, "same bytes, later commit");
    let lock = Path::new(&history.repo).join(".uwgit/write.lock");
    std::fs::write(&lock, b"another writer\n").unwrap();
    let before = snapshot(&history.directory);
    let output = invoke(&["trace", &history.repo, &tip, "--range", "0:1"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("locked"));
    assert_eq!(snapshot(&history.directory), before);
    std::fs::remove_file(lock).unwrap();
    // A valid tip must not hide corruption in an ancestor outside the range.
    let ancestor = Path::new(&history.repo).join(".uwgit/objects").join(root);
    let mut object = std::fs::read(&ancestor).unwrap();
    *object.last_mut().unwrap() ^= 1;
    std::fs::write(&ancestor, object).unwrap();
    let before = snapshot(&history.directory);
    assert!(!invoke(&["trace", &history.repo, &tip, "--range", "0:1"])
        .status
        .success());
    assert_eq!(snapshot(&history.directory), before);
}
