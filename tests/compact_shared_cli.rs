//! Fixed Compact2 CLI evidence; fixtures and repositories stay in /tmp.
//! These tests inspect bytes and history and never execute a Wasm guest.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const PROFILES: [&str; 4] = ["core1", "core2", "core3", "all-known"];
const SHARED: &str = "import[0]/group[0]/shared_type";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-compact-shared-{label}-{}-{}",
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
fn range(value: &Value, bytes: &[u8]) -> (usize, usize) {
    let start = usize::try_from(value["start"].as_u64().unwrap()).unwrap();
    let end = usize::try_from(value["end"].as_u64().unwrap()).unwrap();
    assert!(start <= end && end <= bytes.len());
    (start, end)
}
fn span(start: usize, end: usize) -> Value {
    json!({"start": start, "end": end})
}
fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}
fn regions<'a>(value: &'a Value, output: &mut Vec<&'a Value>) {
    if let Some(entries) = value.as_array() {
        for entry in entries {
            regions(entry, output);
        }
    } else if value["path"].is_string() {
        output.push(value);
        for key in ["regions", "children"] {
            if let Some(children) = value.get(key) {
                regions(children, output);
            }
        }
    }
}
fn all_regions(report: &Value) -> Vec<&Value> {
    let mut output = Vec::new();
    regions(&report["audit"]["sections"], &mut output);
    output
}
fn find<'a>(report: &'a Value, path: &str) -> &'a Value {
    all_regions(report)
        .into_iter()
        .find(|entry| entry["path"] == path)
        .unwrap_or_else(|| panic!("missing physical region {path}"))
}
fn raw_audit(audit: &Value, bytes: &[u8]) {
    assert_eq!(audit["byte_len"], bytes.len());
    let wrapper = json!({"audit": audit});
    for entry in all_regions(&wrapper) {
        range(&entry["span"], bytes);
        for key in ["header_span", "payload_span"] {
            if let Some(value) = entry.get(key) {
                range(value, bytes);
            }
        }
    }
    for evidence in audit["standard"]["evidence"].as_array().unwrap() {
        let (start, end) = range(&evidence["span"], bytes);
        assert_eq!(evidence["raw_hex"], hex(&bytes[start..end]));
    }
    let error = &audit["standard"]["validator_error"];
    if !error.is_null() {
        let (start, end) = range(&error["byte_context"]["span"], bytes);
        assert_eq!(error["byte_context"]["raw_hex"], hex(&bytes[start..end]));
        assert!(error["offset"].as_u64().unwrap() <= bytes.len() as u64);
    }
}

struct Fixture {
    bytes: Vec<u8>,
    shared: (usize, usize),
    operator: usize,
}
// The imported module name contains both a separator and NUL; item names also
// cover NUL and Unicode. Their bytes must not become a shared type's evidence.
fn compact(ty: &[u8], count: u8) -> Fixture {
    let mut group = vec![3, b'm', b':', 0, 0, 0x7e];
    let type_start = group.len();
    group.extend_from_slice(ty);
    let type_end = group.len();
    group.push(count);
    for name in ["a\0", "人"].into_iter().take(count as usize) {
        group.push(name.len() as u8);
        group.extend_from_slice(name.as_bytes());
    }
    module(
        &group,
        (type_start, type_end),
        if ty[0] == 0 || ty[0] == 0x20 {
            count
        } else {
            0
        },
    )
}
fn module(group: &[u8], shared: (usize, usize), function_imports: u8) -> Fixture {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    // Two identical, independently indexed function types allow a tag type-index edit.
    section(&mut bytes, 1, &[2, 0x60, 0, 0, 0x60, 0, 0]);
    let mut imports = vec![1];
    imports.extend_from_slice(group);
    let start = section(&mut bytes, 2, &imports) + 1;
    section(&mut bytes, 3, &[1, 0]);
    section(
        &mut bytes,
        7,
        &[1, 3, b'r', b'u', b'n', 0, function_imports],
    );
    // One independent defined body: locals=0, i32.const 42, drop, end.
    let code = section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
    Fixture {
        bytes,
        shared: (start + shared.0, start + shared.1),
        operator: code + 3,
    }
}
fn inspect(path: &str, profile: &str) -> Value {
    run_json(&["inspect", path, "--json", "--standard", profile])
}

#[test]
fn shared_types_have_wire_evidence_even_when_the_group_has_no_names() {
    let temp = Temp::new("profiles");
    for (label, ty, feature) in [
        ("memory64", &[2, 4, 1][..], "memory64"),
        ("tag", &[4, 0, 0][..], "exceptions"),
        ("exact", &[0x20, 0][..], "custom_descriptors"),
    ] {
        for count in 0..=2 {
            let input = compact(ty, count);
            let path = temp.write(&format!("{label}-{count}.wasm"), &input.bytes);
            for profile in PROFILES {
                let report = inspect(&path, profile);
                raw_audit(&report["audit"], &input.bytes);
                let shared = find(&report, SHARED);
                assert_eq!(shared["span"], span(input.shared.0, input.shared.1));
                assert_eq!(&input.bytes[input.shared.0..input.shared.1], ty);
                let status = if profile == "all-known" || (profile == "core3" && label != "exact") {
                    "supported"
                } else {
                    "recognized_but_disabled"
                };
                assert_eq!(
                    shared["standard_support"]["status"], status,
                    "{label}/{count}/{profile}"
                );
                let evidence: Vec<_> = report["audit"]["standard"]["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|entry| entry["path"] == SHARED && entry["feature"] == feature)
                    .collect();
                assert_eq!(evidence.len(), 1, "the encoded type is recorded once");
                assert_eq!(evidence[0]["span"], shared["span"]);
                assert_eq!(evidence[0]["raw_hex"], hex(ty));
                assert_eq!(evidence[0]["status"], status);
                assert!(
                    !report["audit"]["standard"]["evidence"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|entry| {
                            entry["feature"] == feature
                                && entry["path"].as_str().unwrap().contains("/import[")
                        }),
                    "a name span must not inherit separately encoded type flags"
                );
                let group = find(&report, "import[0]/group[0]");
                assert_eq!(
                    group["children"].as_array().unwrap().len(),
                    count as usize + 1
                );
                assert_eq!(report["function_analysis"]["available"], true);
                let imported = if label == "exact" { count as usize } else { 0 };
                assert_eq!(report["summary"]["imports"], count);
                assert_eq!(report["summary"]["imported_functions"], imported);
                assert_eq!(report["summary"]["functions"], imported + 1);
                let names = ["a\0", "人"];
                for (index, import) in report["module"]["imports"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .enumerate()
                {
                    assert_eq!(import["source_index"], index);
                    assert_eq!(import["module"], "m:\0");
                    assert_eq!(import["name"], names[index]);
                    if label == "exact" {
                        assert_eq!(import["type_ref"]["Func"]["exact"], true);
                    }
                }
                let functions = report["module"]["functions"].as_array().unwrap();
                for (index, function) in functions.iter().enumerate() {
                    assert_eq!(function["source_index"], index);
                }
                assert_eq!(functions[imported]["kind"], "Defined");
                assert_eq!(
                    find(&report, "code[0]/function[0]/operator[0]")["span"],
                    span(input.operator, input.operator + 2)
                );
                assert_eq!(
                    report["audit"]["validation"],
                    "valid_with_all_known_features"
                );
                assert_eq!(
                    report["audit"]["standard"]["validation"],
                    if profile == "all-known" {
                        "valid"
                    } else {
                        "invalid"
                    }
                );
            }
            assert_eq!(std::fs::read(path).unwrap(), input.bytes);
        }
    }
    for (label, group) in [
        ("ordinary", vec![1, b'm', 1, b'f', 0, 0]),
        ("compact1", vec![1, b'm', 0, 0x7f, 1, 1, b'f', 0, 0]),
    ] {
        let input = module(&group, (0, 0), 1);
        let path = temp.write(&format!("{label}.wasm"), &input.bytes);
        for profile in PROFILES {
            let report = inspect(&path, profile);
            raw_audit(&report["audit"], &input.bytes);
            assert!(all_regions(&report)
                .iter()
                .all(|entry| entry["path"] != SHARED));
            assert_eq!(report["function_analysis"]["available"], true);
            assert_eq!(report["summary"]["imported_functions"], 1);
            assert_eq!(report["module"]["functions"][1]["source_index"], 1);
        }
        assert_eq!(std::fs::read(path).unwrap(), input.bytes);
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, directory: &Path, output: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                output.insert(relative, None);
                visit(root, &path, output);
            } else {
                output.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

#[test]
fn exact_shared_type_paths_trace_the_same_physical_events_as_ranges() {
    for count in 0..=2 {
        let temp = Temp::new("trace");
        let old = compact(&[2, 4, 1], count);
        let new = compact(&[2, 0, 1], count);
        assert_eq!(old.shared, new.shared);
        let old_path = temp.write("old.wasm", &old.bytes);
        let new_path = temp.write("new.wasm", &new.bytes);
        let repo = temp.path("repo");
        success(&["init", &repo]);
        success(&["commit", &repo, &old_path, "-m", "shared memory64 type"]);
        success(&["commit", &repo, &new_path, "-m", "shared memory32 type"]);
        let before = snapshot(Path::new(&repo));
        let numeric = format!("{}:{}", new.shared.0, new.shared.1);
        let named = run_json(&["trace", &repo, "HEAD", "--path", SHARED]);
        let ranged = run_json(&["trace", &repo, "HEAD", "--range", &numeric]);
        assert_eq!(snapshot(Path::new(&repo)), before, "trace is read-only");
        assert_eq!(named["selection"]["span"], span(new.shared.0, new.shared.1));
        assert_eq!(named["selection"]["path"], SHARED);
        assert_eq!(named["trace"], ranged["trace"]);
        assert_eq!(named["repository_verified"], true);
        assert_eq!(named["trace"]["complete"], true);
        assert_eq!(named["trace"]["identity_unproven"], true);
        let edges = named["trace"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        let events = edges[0]["events"].as_array().unwrap();
        assert!(!events.is_empty());
        let flag = old.shared.0 + 1;
        assert!(
            events.iter().any(|event| {
                let (start, end) = range(&event["edit"]["old_span"], &old.bytes);
                start <= flag && flag < end
            }),
            "the changed original memory64 flag needs a physical event"
        );
        for event in events {
            let edit = &event["edit"];
            let (a, b) = range(&edit["old_span"], &old.bytes);
            let (c, d) = range(&edit["new_span"], &new.bytes);
            assert_eq!(edit["old_hex"], hex(&old.bytes[a..b]));
            assert_eq!(edit["new_hex"], hex(&new.bytes[c..d]));
        }
        assert_eq!(std::fs::read(old_path).unwrap(), old.bytes);
        assert_eq!(std::fs::read(new_path).unwrap(), new.bytes);
    }
}

fn replay(old: &[u8], new: &[u8], edits: &Value) {
    let (mut old_cursor, mut new_cursor) = (0, 0);
    let mut output = Vec::new();
    for edit in edits.as_array().unwrap() {
        let (a, b) = range(&edit["old_span"], old);
        let (c, d) = range(&edit["new_span"], new);
        assert!(old_cursor <= a && new_cursor <= c);
        assert_eq!(&old[old_cursor..a], &new[new_cursor..c]);
        assert_eq!(edit["old_hex"], hex(&old[a..b]));
        assert_eq!(edit["new_hex"], hex(&new[c..d]));
        output.extend_from_slice(&old[old_cursor..a]);
        output.extend_from_slice(&new[c..d]);
        old_cursor = b;
        new_cursor = d;
    }
    assert_eq!(&old[old_cursor..], &new[new_cursor..]);
    output.extend_from_slice(&old[old_cursor..]);
    assert_eq!(output, new);
}

#[test]
fn profile_diff_and_bidirectional_cli_patches_preserve_original_shared_type_bytes() {
    let temp = Temp::new("transport");
    for (label, old_type, new_type) in [
        ("memory", &[2, 4, 1][..], &[2, 0, 1][..]),
        ("tag", &[4, 0, 0][..], &[4, 0, 1][..]),
        ("exact", &[0x20, 0][..], &[0, 0][..]),
    ] {
        for count in 0..=2 {
            let a = compact(old_type, count);
            let b = compact(new_type, count);
            let a_path = temp.write(&format!("{label}-{count}-a.wasm"), &a.bytes);
            let b_path = temp.write(&format!("{label}-{count}-b.wasm"), &b.bytes);
            for (direction, old, new, old_path, new_path) in [
                ("forward", &a.bytes, &b.bytes, &a_path, &b_path),
                ("reverse", &b.bytes, &a.bytes, &b_path, &a_path),
            ] {
                let mut expected = None;
                for profile in PROFILES {
                    let difference = run_json(&[
                        "diff",
                        old_path,
                        new_path,
                        "--format",
                        "json",
                        "--standard",
                        profile,
                    ]);
                    assert_eq!(difference["binary_changed"], true);
                    raw_audit(&difference["audit"]["old"], old);
                    raw_audit(&difference["audit"]["new"], new);
                    replay(old, new, &difference["audit"]["edits"]);
                    assert!(difference["audit"]["edits"].as_array().unwrap().iter().any(|edit| {
                        ["old_context", "new_context"].into_iter().any(|side| {
                            edit[side].as_array().unwrap().iter().any(|entry| entry["path"] == SHARED)
                        })
                    }), "{label}/{count}/{direction}/{profile}: raw type changes need shared-type context");
                    if let Some(previous) = &expected {
                        assert_eq!(previous, &difference["audit"]["edits"]);
                    } else {
                        expected = Some(difference["audit"]["edits"].clone());
                    }
                }
                let patch_path = temp.path(&format!("{label}-{count}-{direction}.patch"));
                let output_path = temp.path(&format!("{label}-{count}-{direction}.wasm"));
                run_json(&["patch", old_path, new_path, "--output", &patch_path]);
                let encoded = std::fs::read(&patch_path).unwrap();
                let patch: Value = serde_json::from_slice(&encoded).unwrap();
                assert_eq!(patch["format"], "uwgit-byte-patch-v1");
                replay(old, new, &patch["edits"]);
                let applied = run_json(&["apply", old_path, &patch_path, "--output", &output_path]);
                assert_eq!(applied["written"], true);
                assert_eq!(std::fs::read(output_path).unwrap(), *new);
                assert_eq!(std::fs::read(patch_path).unwrap(), encoded);
            }
            assert_eq!(std::fs::read(a_path).unwrap(), a.bytes);
            assert_eq!(std::fs::read(b_path).unwrap(), b.bytes);
        }
    }
}

#[test]
fn damaged_compact_groups_publish_no_partial_shared_type_or_instance_fields() {
    let temp = Temp::new("malformed");
    for (label, tail) in [
        ("bad-type-empty", vec![0xff, 0]),
        ("bad-type-two", vec![0xff, 2, 1, b'a', 1, b'b']),
        (
            "bad-empty-count",
            vec![2, 4, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        ),
        // The upstream framing pass skips this string; expanding the names
        // later discovers its invalid UTF-8. No shared field may leak first.
        ("bad-name-utf8", vec![2, 4, 1, 1, 1, 0xff]),
    ] {
        let mut group = vec![1, b'm', 0, 0x7e];
        group.extend_from_slice(&tail);
        let input = module(&group, (0, 0), 0);
        let path = temp.write(&format!("{label}.wasm"), &input.bytes);
        for profile in PROFILES {
            let report = inspect(&path, profile);
            raw_audit(&report["audit"], &input.bytes);
            assert!(
                all_regions(&report).iter().all(|entry| {
                    !entry["path"]
                        .as_str()
                        .unwrap()
                        .starts_with("import[0]/group[0]")
                }),
                "{label}: no partial group or shared field can be published"
            );
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
                "{label}: no partial shared evidence or instance side effects"
            );
            let function = find(&report, "code[0]/function[0]");
            assert!(function["description"]
                .as_str()
                .unwrap()
                .contains("function_index=unknown"));
            let constant = find(&report, "code[0]/function[0]/operator[0]");
            assert_eq!(constant["span"], span(input.operator, input.operator + 2));
            assert_eq!(
                &input.bytes[input.operator..input.operator + 2],
                &[0x41, 42]
            );
            assert_eq!(constant["standard_support"]["status"], "supported");
            assert!(
                report["audit"]["standard"]["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| {
                        entry["path"] == "export[0]/entry[0]" && entry["status"] == "unknown"
                    }),
                "{label}: a later function use must expose its unknown combined index context"
            );
            assert_eq!(report["audit"]["standard"]["validation"], "invalid");
        }
        assert_eq!(std::fs::read(path).unwrap(), input.bytes);
    }
}
