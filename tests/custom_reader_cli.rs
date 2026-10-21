//! Fixed CLI checks for a disclosed, offset-preserving custom-name reader view.
//! Fixtures, repositories and outputs stay in /tmp; no Wasm guest is executed.
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::patch::BytePatch;

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const PROFILES: [&str; 4] = ["core1", "core2", "core3", "all-known"];
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-custom-reader-{label}-{}-{}",
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
    serde_json::from_str(&success(arguments)).expect("CLI JSON")
}

fn leb(mut value: usize) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let byte = value as u8 & 0x7f;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            return output;
        }
    }
}

fn section(output: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    output.push(id);
    output.extend(leb(payload.len()));
    let start = output.len();
    output.extend_from_slice(payload);
    start
}

#[derive(Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

impl Span {
    fn json(self) -> Value {
        json!({"start": self.start, "end": self.end})
    }
}

struct NameFrame {
    name: Span,
    data: Span,
    byte_len: usize,
}

struct Fixture {
    bytes: Vec<u8>,
    names: Vec<NameFrame>,
    operators: Vec<Span>,
}

fn custom(bytes: &mut Vec<u8>, name: &str, padding: bool, data: u8) -> NameFrame {
    let mut length = leb(name.len());
    if padding {
        *length.last_mut().unwrap() |= 0x80;
        length.push(0);
    }
    let mut payload = length;
    payload.extend_from_slice(name.as_bytes());
    let name_size = payload.len();
    payload.push(data);
    let start = section(bytes, 0, &payload);
    NameFrame {
        name: Span {
            start,
            end: start + name_size,
        },
        data: Span {
            start: start + name_size,
            end: start + payload.len(),
        },
        byte_len: name.len(),
    }
}

fn mvp(value: u8) -> Vec<Vec<u8>> {
    vec![vec![0x41, value], vec![0x1a], vec![0x0b]]
}

fn fixture(operators: &[Vec<u8>], names: &[(usize, &str, bool)], data: u8) -> Fixture {
    let mut bytes = HEADER.to_vec();
    let mut frames = Vec::new();
    for (_, name, padding) in names.iter().filter(|(position, _, _)| *position == 0) {
        frames.push(custom(&mut bytes, name, *padding, data));
    }
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[1, 0]);
    section(&mut bytes, 7, &[1, 3, b'r', b'u', b'n', 0, 0]);
    for (_, name, padding) in names.iter().filter(|(position, _, _)| *position == 1) {
        frames.push(custom(&mut bytes, name, *padding, data));
    }
    let mut body = vec![0];
    for operator in operators {
        body.extend_from_slice(operator);
    }
    let mut code = vec![1];
    code.extend(leb(body.len()));
    let locals_relative = code.len();
    code.extend_from_slice(&body);
    let payload_start = section(&mut bytes, 10, &code);
    let mut cursor = payload_start + locals_relative + 1;
    let spans = operators
        .iter()
        .map(|operator| {
            let span = Span {
                start: cursor,
                end: cursor + operator.len(),
            };
            cursor = span.end;
            span
        })
        .collect();
    for (_, name, padding) in names.iter().filter(|(position, _, _)| *position == 2) {
        frames.push(custom(&mut bytes, name, *padding, data));
    }
    Fixture {
        bytes,
        names: frames,
        operators: spans,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn physical_span(value: &Value, bytes: &[u8]) -> Span {
    let span = Span {
        start: usize::try_from(value["start"].as_u64().unwrap()).unwrap(),
        end: usize::try_from(value["end"].as_u64().unwrap()).unwrap(),
    };
    assert!(span.start <= span.end && span.end <= bytes.len());
    span
}

fn find_region<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if value["path"].as_str() == Some(path) {
        return Some(value);
    }
    if let Some(entries) = value.as_array() {
        return entries.iter().find_map(|entry| find_region(entry, path));
    }
    for key in ["regions", "children"] {
        if let Some(found) = value
            .get(key)
            .and_then(|entries| find_region(entries, path))
        {
            return Some(found);
        }
    }
    None
}

fn inspect(path: &str, standard: &str) -> Value {
    run_json(&["inspect", path, "--standard", standard, "--json"])
}

fn check_input(report: &Value, fixture: &Fixture) {
    let input = &report["audit"]["standard"]["validator_input"];
    let expected: Vec<_> = fixture
        .names
        .iter()
        .enumerate()
        .filter(|(_, name)| name.byte_len > 100_000)
        .collect();
    assert_eq!(
        input["kind"],
        if expected.is_empty() {
            "original_bytes"
        } else {
            "custom_name_projection"
        }
    );
    let projections = input["projections"].as_array().unwrap();
    assert_eq!(projections.len(), expected.len());
    for (projection, (index, name)) in projections.iter().zip(expected) {
        assert_eq!(projection["path"], format!("custom[{index}]/name"));
        assert_eq!(projection["name_span"], name.name.json());
        assert_eq!(
            projection["byte_span"],
            Span {
                start: name.name.start,
                end: name.name.start + 1
            }
            .json()
        );
        assert_eq!(
            projection["original_hex"],
            hex(&fixture.bytes[name.name.start..name.name.start + 1])
        );
        assert_eq!(projection["projected_hex"], "00");
    }
}

fn check_raw(report: &Value, bytes: &[u8]) {
    assert_eq!(report["audit"]["byte_len"], bytes.len());
    for evidence in report["audit"]["standard"]["evidence"].as_array().unwrap() {
        let span = physical_span(&evidence["span"], bytes);
        assert_eq!(evidence["raw_hex"], hex(&bytes[span.start..span.end]));
    }
    let error = &report["audit"]["standard"]["validator_error"];
    if !error.is_null() {
        let span = physical_span(&error["byte_context"]["span"], bytes);
        assert_eq!(
            error["byte_context"]["raw_hex"],
            hex(&bytes[span.start..span.end])
        );
        assert!(error["offset"].as_u64().unwrap() <= bytes.len() as u64);
    }
}

fn check_functions(report: &Value, fixture: &Fixture, baseline: &Value) {
    assert_eq!(report["function_analysis"]["available"], true);
    let functions = report["module"]["functions"].as_array().unwrap();
    let original = baseline["module"]["functions"].as_array().unwrap();
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0]["id"], original[0]["id"]);
    assert!(!functions[0]["fingerprint"].is_null());
    assert_eq!(functions[0]["fingerprint"], original[0]["fingerprint"]);
    let operators = functions[0]["operators"].as_array().unwrap();
    assert_eq!(operators.len(), fixture.operators.len());
    for (index, (operator, expected)) in operators.iter().zip(&fixture.operators).enumerate() {
        assert_eq!(operator["offset"], expected.start);
        let region = find_region(
            &report["audit"]["sections"],
            &format!("code[0]/function[0]/operator[{index}]"),
        )
        .unwrap();
        assert_eq!(region["span"], expected.json());
    }
}

#[test]
fn legal_long_outer_names_before_between_and_after_core_keep_function_identity_and_offsets() {
    let tmp = Temp::new("long");
    let baseline = fixture(&mvp(42), &[], 0xa5);
    let baseline_path = tmp.write("baseline.wasm", &baseline.bytes);
    let unicode = format!("{}a\0", "界".repeat(33_333));
    assert_eq!(unicode.len(), 100_001);
    let names = ["x".repeat(100_001), "y".repeat(131_073), unicode];
    for (position, name) in names.iter().enumerate() {
        let input = fixture(&mvp(42), &[(position, name.as_str(), false)], 0xa5);
        let path = tmp.write(&format!("long-{position}.wasm"), &input.bytes);
        for standard in PROFILES {
            let original = inspect(&baseline_path, standard);
            let result = inspect(&path, standard);
            check_input(&result, &input);
            check_raw(&result, &input.bytes);
            check_functions(&result, &input, &original);
            assert_eq!(
                result["audit"]["validation"],
                "valid_with_all_known_features"
            );
            assert_eq!(result["audit"]["standard"]["validation"], "valid");
            assert_eq!(result["audit"]["standard"]["validator_valid"], true);
        }
        assert_eq!(std::fs::read(&path).unwrap(), input.bytes);
    }
}

#[test]
fn threshold_and_padded_short_names_stay_original_while_raw_transport_stays_exact() {
    let tmp = Temp::new("transport");
    let threshold = "t".repeat(100_000);
    let ordinary = fixture(
        &mvp(42),
        &[
            (0, threshold.as_str(), true),
            (1, "short\0/%名字", false),
            (2, "", true),
        ],
        0xa5,
    );
    let ordinary_path = tmp.write("ordinary.wasm", &ordinary.bytes);
    let baseline = fixture(&mvp(42), &[], 0xa5);
    let baseline_path = tmp.write("baseline.wasm", &baseline.bytes);
    for standard in PROFILES {
        let result = inspect(&ordinary_path, standard);
        check_input(&result, &ordinary);
        check_raw(&result, &ordinary.bytes);
        check_functions(&result, &ordinary, &inspect(&baseline_path, standard));
    }

    let long = "l".repeat(100_001);
    let old = fixture(&mvp(42), &[(1, long.as_str(), false)], 0xa5);
    let new = fixture(&mvp(43), &[(1, long.as_str(), false)], 0xa6);
    let old_path = tmp.write("old.wasm", &old.bytes);
    let new_path = tmp.write("new.wasm", &new.bytes);
    let mut expected_edits = None;
    for standard in PROFILES {
        let result = run_json(&[
            "diff",
            &old_path,
            &new_path,
            "--standard",
            standard,
            "--format",
            "json",
        ]);
        assert_eq!(result["function_analysis"]["available"], true);
        assert_eq!(result["binary_changed"], true);
        let mut restored = Vec::new();
        let (mut old_cursor, mut new_cursor) = (0, 0);
        for edit in result["audit"]["edits"].as_array().unwrap() {
            let a = physical_span(&edit["old_span"], &old.bytes);
            let b = physical_span(&edit["new_span"], &new.bytes);
            assert!(old_cursor <= a.start && new_cursor <= b.start);
            assert_eq!(
                &old.bytes[old_cursor..a.start],
                &new.bytes[new_cursor..b.start]
            );
            assert_eq!(edit["old_hex"], hex(&old.bytes[a.start..a.end]));
            assert_eq!(edit["new_hex"], hex(&new.bytes[b.start..b.end]));
            restored.extend_from_slice(&old.bytes[old_cursor..a.start]);
            restored.extend_from_slice(&unhex(edit["new_hex"].as_str().unwrap()));
            old_cursor = a.end;
            new_cursor = b.end;
        }
        assert_eq!(&old.bytes[old_cursor..], &new.bytes[new_cursor..]);
        restored.extend_from_slice(&old.bytes[old_cursor..]);
        assert_eq!(restored, new.bytes);
        let edits = serde_json::to_vec(&result["audit"]["edits"]).unwrap();
        if let Some(previous) = &expected_edits {
            assert_eq!(previous, &edits);
        } else {
            expected_edits = Some(edits);
        }
    }
    for (label, before_path, after_path, before, after) in [
        (
            "forward",
            old_path.as_str(),
            new_path.as_str(),
            old.bytes.as_slice(),
            new.bytes.as_slice(),
        ),
        (
            "reverse",
            new_path.as_str(),
            old_path.as_str(),
            new.bytes.as_slice(),
            old.bytes.as_slice(),
        ),
    ] {
        let patch_path = tmp.path(&format!("{label}.uwgp"));
        run_json(&["patch", before_path, after_path, "--output", &patch_path]);
        let encoded = std::fs::read(&patch_path).unwrap();
        let patch = BytePatch::from_bytes(&encoded).unwrap();
        assert_eq!(encoded, patch.to_bytes().unwrap());
        assert_eq!(patch.apply(before).unwrap(), after);
        let output = tmp.path(&format!("{label}.wasm"));
        let checked = run_json(&["apply", before_path, &patch_path, "--check"]);
        assert_eq!(checked["written"], false);
        run_json(&["apply", before_path, &patch_path, "--output", &output]);
        assert_eq!(std::fs::read(output).unwrap(), after);
    }
    let repo = tmp.path("repo");
    success(&["init", &repo]);
    for (path, message) in [(&old_path, "original"), (&new_path, "changed")] {
        success(&["commit", &repo, path, "-m", message]);
    }
    let data = new.names[0].data;
    let range = format!("{}:{}", data.start, data.end);
    let named = run_json(&["trace", &repo, "HEAD", "--path", "custom[0]/payload/opaque"]);
    let numeric = run_json(&["trace", &repo, "HEAD", "--range", &range]);
    assert_eq!(named["selection"]["span"], data.json());
    assert_eq!(named["trace"], numeric["trace"]);
    assert_eq!(named["trace"]["complete"], true);
    assert_eq!(named["trace"]["identity_unproven"], true);
    for event in named["trace"]["edges"][0]["events"].as_array().unwrap() {
        let a = physical_span(&event["edit"]["old_span"], &old.bytes);
        let b = physical_span(&event["edit"]["new_span"], &new.bytes);
        assert_eq!(event["edit"]["old_hex"], hex(&old.bytes[a.start..a.end]));
        assert_eq!(event["edit"]["new_hex"], hex(&new.bytes[b.start..b.end]));
    }
    assert!(!Path::new(&repo).join(".uwgit/write.lock").exists());
    assert_eq!(std::fs::read(old_path).unwrap(), old.bytes);
    assert_eq!(std::fs::read(new_path).unwrap(), new.bytes);
}

#[test]
fn custom_projection_preserves_disabled_simd_and_real_core_error_offsets() {
    let tmp = Temp::new("core-errors");
    let long = "c".repeat(100_001);
    let mut constant = vec![0xfd, 0x0c];
    constant.extend_from_slice(&[0; 16]);
    let simd_ops = vec![constant, vec![0x1a], vec![0x41, 42], vec![0x1a], vec![0x0b]];
    let base = fixture(&simd_ops, &[], 0xa5);
    let input = fixture(&simd_ops, &[(1, long.as_str(), false)], 0xa5);
    let base_path = tmp.write("simd-base.wasm", &base.bytes);
    let input_path = tmp.write("simd-long.wasm", &input.bytes);
    for standard in PROFILES {
        let original = inspect(&base_path, standard);
        let result = inspect(&input_path, standard);
        check_input(&result, &input);
        check_raw(&result, &input.bytes);
        check_functions(&result, &input, &original);
        assert_eq!(
            result["audit"]["validation"],
            "valid_with_all_known_features"
        );
        if standard == "core1" {
            assert_eq!(result["audit"]["standard"]["validation"], "invalid");
            assert_eq!(result["audit"]["standard"]["validator_valid"], false);
            let simd = find_region(
                &result["audit"]["sections"],
                "code[0]/function[0]/operator[0]",
            )
            .unwrap();
            assert_eq!(
                simd["standard_support"]["status"],
                "recognized_but_disabled"
            );
            let delta = input.operators[0].start - base.operators[0].start;
            assert_eq!(
                result["audit"]["standard"]["validator_error"]["offset"]
                    .as_u64()
                    .unwrap(),
                original["audit"]["standard"]["validator_error"]["offset"]
                    .as_u64()
                    .unwrap()
                    + delta as u64
            );
        } else {
            assert_eq!(result["audit"]["standard"]["validation"], "valid");
        }
    }
    let cases = [
        (
            "unknown",
            vec![vec![0xff], vec![0x41, 42], vec![0x1a], vec![0x0b]],
            "unknown",
        ),
        (
            "bad-integer",
            vec![
                vec![0x41, 0x80, 0x80, 0x80, 0x80, 0x10],
                vec![0x1a],
                vec![0x0b],
            ],
            "invalid_encoding",
        ),
    ];
    for (label, operators, status) in cases {
        let base = fixture(&operators, &[], 0xa5);
        let input = fixture(&operators, &[(1, long.as_str(), false)], 0xa5);
        let base_path = tmp.write(&format!("{label}-base.wasm"), &base.bytes);
        let input_path = tmp.write(&format!("{label}-long.wasm"), &input.bytes);
        let original = inspect(&base_path, "all-known");
        let result = inspect(&input_path, "all-known");
        check_input(&result, &input);
        check_raw(&result, &input.bytes);
        assert_eq!(result["function_analysis"]["available"], false);
        assert_eq!(result["audit"]["standard"]["validator_valid"], false);
        let delta = input.operators[0].start - base.operators[0].start;
        assert_eq!(
            result["audit"]["standard"]["validator_error"]["offset"]
                .as_u64()
                .unwrap(),
            original["audit"]["standard"]["validator_error"]["offset"]
                .as_u64()
                .unwrap()
                + delta as u64
        );
        let opaque =
            find_region(&result["audit"]["sections"], "code[0]/function[0]/opaque").unwrap();
        assert_eq!(opaque["span"]["start"], input.operators[0].start);
        assert_eq!(opaque["standard_support"]["status"], status);
    }
}

#[test]
fn invalid_outer_names_framing_unknown_sections_and_components_are_never_repaired() {
    let tmp = Temp::new("invalid-outer");
    let base = fixture(&mvp(42), &[], 0xa5);
    let mut borrowed = HEADER.to_vec();
    section(&mut borrowed, 0, &[0xa1, 0x8d, 6, b'x']);
    // The next section's legal padded size100464 is itself valid UTF-8. A
    // reader accidentally extending into the next section could borrow enough
    // valid name bytes; the first custom payload has only one name byte.
    borrowed.extend_from_slice(&[0, 0xf0, 0x90, 0x86, 0x80, 0]);
    borrowed.push(0); // The following section has a valid empty custom name.
    borrowed.extend(std::iter::repeat_n(b'p', 100_463));
    borrowed.extend_from_slice(&base.bytes[8..]);
    assert!(std::str::from_utf8(&borrowed[13..13 + 100_001]).is_ok());

    let mut malformed_utf8 = HEADER.to_vec();
    let mut invalid_name = leb(100_001);
    invalid_name.extend(std::iter::repeat_n(b'x', 100_000));
    invalid_name.push(0xff);
    section(&mut malformed_utf8, 0, &invalid_name);
    malformed_utf8.extend_from_slice(&base.bytes[8..]);
    let mut overflow = HEADER.to_vec();
    section(&mut overflow, 0, &[0x80, 0x80, 0x80, 0x80, 0x10]);
    overflow.extend_from_slice(&base.bytes[8..]);
    let mut truncated = HEADER.to_vec();
    section(&mut truncated, 0, &[0x80]);
    truncated.extend_from_slice(&base.bytes[8..]);
    let mut framing = HEADER.to_vec();
    framing.extend_from_slice(&[0, 0x80]);
    let mut missing_payload = HEADER.to_vec();
    let mut payload = leb(100_001);
    payload.extend(std::iter::repeat_n(b'x', 100_001));
    missing_payload.push(0);
    missing_payload.extend(leb(payload.len() + 1));
    missing_payload.extend(payload);
    for (label, bytes) in [
        ("bounded-name", borrowed),
        ("bad-utf8", malformed_utf8),
        ("overflow", overflow),
        ("truncated-name", truncated),
        ("truncated-framing", framing),
        ("missing-payload", missing_payload),
    ] {
        let path = tmp.write(&format!("{label}.wasm"), &bytes);
        let result = inspect(&path, "all-known");
        check_raw(&result, &bytes);
        assert_eq!(result["function_analysis"]["available"], false, "{label}");
        assert_eq!(result["audit"]["validation"], "failed_or_unsupported");
        assert_eq!(result["audit"]["standard"]["validation"], "invalid");
        assert_eq!(
            result["audit"]["standard"]["validator_input"]["kind"],
            "original_bytes"
        );
        assert!(
            result["audit"]["standard"]["validator_input"]["projections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(result["audit"]["standard"]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["status"] == "invalid_encoding"));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    let long = "u".repeat(100_001);
    let mut unknown = HEADER.to_vec();
    custom(&mut unknown, &long, false, 0xa5);
    section(&mut unknown, 14, &[0xa5]);
    unknown.extend_from_slice(&base.bytes[8..]);
    let path = tmp.write("unknown-section.wasm", &unknown);
    let result = inspect(&path, "all-known");
    assert_eq!(result["function_analysis"]["available"], false);
    assert_eq!(result["audit"]["standard"]["validation"], "invalid");
    assert!(result["audit"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["code"] == "unknown_section"));
    check_raw(&result, &unknown);
    let component = tmp.write("component.wasm", b"\0asm\x0d\0\x01\0");
    let rejected = invoke(&["inspect", &component, "--json"]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("Component Model excluded"));
}
