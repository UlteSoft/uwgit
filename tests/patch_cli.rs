//! Offline patch publication and replay. All fixtures and outputs stay in /tmp;
//! Wasm is decoded and validated where applicable, but never executed.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::patch::{BytePatch, PatchEdit, PatchSpan};
use wasmparser::{Operator, Parser, Payload, Validator, WasmFeatures};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new(label: &str) -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-patch-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn invoke_at(arguments: &[&str], directory: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wasm-git"));
    command.args(arguments);
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    command.output().expect("execute wasm-git")
}

fn invoke(arguments: &[&str]) -> Output {
    invoke_at(arguments, None)
}

fn success_at(arguments: &[&str], directory: Option<&Path>) -> String {
    let output = invoke_at(arguments, directory);
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn success(arguments: &[&str]) -> String {
    success_at(arguments, None)
}

fn run_json(arguments: &[&str]) -> Value {
    serde_json::from_str(&success(arguments)).expect("JSON result")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn valid(bytes: &[u8]) {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .expect("fixture must be valid before deliberate opaque-byte mutations");
}

fn wat(source: &str) -> Vec<u8> {
    let bytes = wat::parse_str(source).expect("encode patch fixture");
    valid(&bytes);
    bytes
}

fn functions(a: i32, b: i32) -> Vec<u8> {
    wat(&format!(
        r#"(module
        (func (export "a") (result i32) i32.const {a})
        (func (export "b") (result i32) i32.const {b}))"#
    ))
}

// Include directory entries as well as file contents so --check cannot leave
// empty output directories, repository locks or temporary files unnoticed.
fn snapshot(directory: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(path).unwrap() {
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

fn metadata(patch: &BytePatch) -> Value {
    json!({
        "format": "uwgit-byte-patch-v1",
        "old_sha256": patch.old_sha256,
        "new_sha256": patch.new_sha256,
        "old_len": patch.old_len,
        "new_len": patch.new_len,
        "edit_count": patch.edits.len(),
    })
}

fn roundtrip(label: &str, old: &[u8], new: &[u8]) -> Value {
    let tmp = Temp::new(label);
    let old_path = tmp.path("old.wasm");
    let new_path = tmp.path("new.wasm");
    let patch_path = tmp.path("change.uwpatch");
    let output_path = tmp.path("replayed.wasm");
    std::fs::write(&old_path, old).unwrap();
    std::fs::write(&new_path, new).unwrap();
    let created = run_json(&["patch", &old_path, &new_path, "--output", &patch_path]);
    let encoded = std::fs::read(&patch_path).unwrap();
    let patch = BytePatch::from_bytes(&encoded).expect("CLI publishes canonical patch bytes");
    assert_eq!(patch.old_sha256, digest(old));
    assert_eq!(patch.new_sha256, digest(new));
    assert_eq!(patch.old_len, old.len() as u64);
    assert_eq!(patch.new_len, new.len() as u64);
    assert_eq!(encoded, serde_json::to_vec(&patch).unwrap());
    assert_eq!(created["schema_version"], 1);
    assert_eq!(created["written"], true);
    assert_eq!(created["output"], patch_path);
    assert_eq!(created["patch"], metadata(&patch));
    assert_eq!(created["inputs"]["old"]["path"], old_path);
    assert_eq!(created["inputs"]["new"]["path"], new_path);
    let before_check = snapshot(&tmp.0);
    let checked = run_json(&["apply", &old_path, &patch_path, "--check"]);
    assert_eq!(
        snapshot(&tmp.0),
        before_check,
        "--check must perform no writes"
    );
    assert_eq!(checked["schema_version"], 1);
    assert_eq!(checked["written"], false);
    assert!(checked["output"].is_null());
    assert_eq!(checked["patch"], metadata(&patch));
    assert_eq!(checked["inputs"]["old"]["path"], old_path);
    // Audit evidence is recomputed from the verified original and target bytes.
    let difference = run_json(&["diff", &old_path, &new_path, "--format", "json"]);
    assert_eq!(checked["audit"], difference["audit"]);
    let applied = run_json(&["apply", &old_path, &patch_path, "--output", &output_path]);
    assert_eq!(applied["schema_version"], 1);
    assert_eq!(applied["written"], true);
    assert_eq!(applied["output"], output_path);
    assert_eq!(applied["patch"], metadata(&patch));
    assert_eq!(applied["audit"], checked["audit"]);
    assert_eq!(std::fs::read(&output_path).unwrap(), new);
    assert_eq!(std::fs::read(&old_path).unwrap(), old);
    assert_eq!(std::fs::read(&patch_path).unwrap(), encoded);
    checked
}

#[test]
fn valid_core1_gc_references_and_exceptions_roundtrip_with_complete_audit() {
    let fixtures = [
        (
            "mvp",
            r#"(module (func (export "run") (result i32) i32.const 17))"#,
            "i32.const 17",
            "i32.const 18",
        ),
        (
            "gc",
            r#"(module
            (rec (type $node (struct (field $value (mut i32)) (field (ref null $node))))
                 (type $children (array (mut (ref null $node)))))
            (func (export "make") (result (ref $node)) struct.new_default $node)
            (func (export "get") (param (ref $node)) (result i32)
                local.get 0 struct.get $node $value))"#,
            "(field $value (mut i32))",
            "(field $value i32)",
        ),
        (
            "references",
            r#"(module
            (func (export "choose") (param externref) (result externref)
                local.get 0 ref.null extern i32.const 0 select (result externref)))"#,
            "extern",
            "func",
        ),
        (
            "exceptions",
            r#"(module (tag $signal (param i32))
            (func (export "run") (result i32)
                (block $caught (result i32)
                    (try_table (catch $signal $caught) i32.const 31 throw $signal)
                    i32.const 0)))"#,
            "i32.const 31",
            "i32.const 32",
        ),
        (
            "import-export",
            r#"(module
            (import "arbitrary.host/interface" "call" (func $call (param i32) (result i32)))
            (func (export "run") (param i32) (result i32) local.get 0 call $call))"#,
            "arbitrary.host/interface",
            "another.namespace/interface",
        ),
    ];
    for (label, source, from, to) in fixtures {
        let old = wat(source);
        let new = wat(&source.replace(from, to));
        let result = roundtrip(label, &old, &new);
        assert_eq!(
            result["audit"]["old"]["validation"],
            "valid_with_all_known_features"
        );
        assert_eq!(
            result["audit"]["new"]["validation"],
            "valid_with_all_known_features"
        );
        assert!(!result["audit"]["edits"].as_array().unwrap().is_empty());
    }
}

#[test]
fn unknown_instructions_and_malformed_custom_conventions_preserve_exact_bytes() {
    let mut old = wat("(module (func i32.const 1 drop))");
    let mut instruction_offset = None;
    for payload in Parser::new(0).parse_all(&old) {
        if let Payload::CodeSectionEntry(body) = payload.unwrap() {
            let mut reader = body.get_operators_reader().unwrap();
            while !reader.eof() {
                let position = reader.original_position();
                if matches!(reader.read().unwrap(), Operator::I32Const { .. }) {
                    instruction_offset = Some(position);
                }
            }
        }
    }
    old[instruction_offset.unwrap()] = 0xff;
    // "name" with a truncated function-name subsection is an opaque convention,
    // not a reason to reject or rewrite original module bytes.
    old.extend_from_slice(&[0, 7, 4, b'n', b'a', b'm', b'e', 1, 0x80]);
    let mut new = old.clone();
    new[instruction_offset.unwrap()] = 0xf5;
    *new.last_mut().unwrap() = 0x81;
    let checked = roundtrip("unknown-opaque", &old, &new);
    let evidence = checked["audit"].to_string();
    assert!(evidence.contains("unknown_operator"));
    assert!(evidence.contains("custom_opaque"));
    assert_ne!(
        checked["audit"]["new"]["validation"],
        "valid_with_all_known_features"
    );
}

#[test]
fn legal_noncanonical_leb_encodings_are_replayed_without_reencoding() {
    let mut old = b"\0asm\x01\0\0\0".to_vec();
    old.extend_from_slice(&[1, 5, 1, 0x60, 0, 1, 0x7f, 3, 2, 1, 0]);
    let mut new = old.clone();
    old.extend_from_slice(&[10, 6, 1, 4, 0, 0x41, 1, 0x0b]);
    new.extend_from_slice(&[10, 7, 1, 5, 0, 0x41, 0x81, 0, 0x0b]);
    valid(&old);
    valid(&new);
    let checked = roundtrip("overlong-leb", &old, &new);
    assert_eq!(checked["audit"]["changed"], true);
}

#[test]
fn insertion_deletion_and_identity_patches_replay_exactly() {
    let base = wat("(module)");
    let mut with_custom = base.clone();
    with_custom.extend_from_slice(&[0, 5, 1, b'x', 0, 0xff, 0x80]);
    valid(&with_custom);
    roundtrip("insert", &base, &with_custom);
    roundtrip("delete", &with_custom, &base);
    let checked = roundtrip("identity", &with_custom, &with_custom);
    assert_eq!(checked["patch"]["edit_count"], 0);
    assert_eq!(checked["audit"]["changed"], false);
}

fn reject_without_writes(tmp: &Temp, old: &str, patch: &str, label: &str) -> String {
    let output_path = tmp.path(&format!("rejected-{label}.wasm"));
    let before = snapshot(&tmp.0);
    let checked = invoke(&["apply", old, patch, "--check"]);
    assert!(
        !checked.status.success(),
        "{label}: --check must reject invalid input"
    );
    assert_eq!(
        snapshot(&tmp.0),
        before,
        "{label}: failed check mutated files"
    );
    let applied = invoke(&["apply", old, patch, "--output", &output_path]);
    assert!(
        !applied.status.success(),
        "{label}: --output must reject invalid input"
    );
    assert!(
        !Path::new(&output_path).exists(),
        "{label}: rejected output exists"
    );
    assert_eq!(
        snapshot(&tmp.0),
        before,
        "{label}: failed apply mutated files"
    );
    String::from_utf8_lossy(&applied.stderr).into_owned()
}

#[test]
fn wrong_base_is_rejected_even_when_every_edited_old_byte_matches() {
    let tmp = Temp::new("wrong-base");
    let old = functions(41, 53);
    let new = functions(47, 53);
    let wrong = functions(41, 59);
    assert_eq!(old.len(), wrong.len());
    let patch = wasm_git::patch::create(&old, &new).unwrap();
    for edit in &patch.edits {
        assert_eq!(
            hex(&wrong[edit.old_span.start as usize..edit.old_span.end as usize]),
            edit.old_hex,
            "the full-file hash must reject changes outside patch spans"
        );
    }
    let old_path = tmp.path("wrong.wasm");
    let patch_path = tmp.path("change.uwpatch");
    std::fs::write(&old_path, wrong).unwrap();
    std::fs::write(&patch_path, patch.to_bytes().unwrap()).unwrap();
    let error = reject_without_writes(&tmp, &old_path, &patch_path, "wrong-base");
    assert!(error.contains("old_sha256"));
}

fn changed_hex(encoded: &str) -> String {
    let mut bytes = encoded.as_bytes().to_vec();
    assert!(!bytes.is_empty());
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).unwrap()
}

#[test]
fn tampered_metadata_spans_and_payloads_are_rejected_before_output_creation() {
    let tmp = Temp::new("tamper");
    let old = functions(41, 53);
    let new = functions(47, 59);
    let patch = wasm_git::patch::create(&old, &new).unwrap();
    assert!(
        patch.edits.len() >= 2,
        "fixture has separated instruction edits"
    );
    let old_path = tmp.path("old.wasm");
    std::fs::write(&old_path, &old).unwrap();
    let mut cases = Vec::new();
    let mut malformed = patch.clone();
    malformed.edits.reverse();
    cases.push(("out-of-order", malformed));
    let mut malformed = patch.clone();
    malformed.edits[1].old_span = malformed.edits[0].old_span.clone();
    malformed.edits[1].old_hex = malformed.edits[0].old_hex.clone();
    cases.push(("old-overlap", malformed));
    let mut malformed = patch.clone();
    malformed.edits[1].new_span = malformed.edits[0].new_span.clone();
    malformed.edits[1].new_hex = malformed.edits[0].new_hex.clone();
    cases.push(("new-overlap", malformed));
    let mut malformed = patch.clone();
    malformed.edits[0].old_span.end = malformed.edits[1].old_span.start + 1;
    malformed.edits[0].old_hex =
        hex(&old
            [malformed.edits[0].old_span.start as usize..malformed.edits[0].old_span.end as usize]);
    cases.push(("old-overlap-with-increasing-starts", malformed));
    let mut malformed = patch.clone();
    malformed.edits[0].new_span.end = malformed.edits[1].new_span.start + 1;
    malformed.edits[0].new_hex =
        hex(&new
            [malformed.edits[0].new_span.start as usize..malformed.edits[0].new_span.end as usize]);
    cases.push(("new-overlap-with-increasing-starts", malformed));
    let mut malformed = patch.clone();
    malformed.new_sha256 = "0".repeat(64);
    cases.push(("target-hash", malformed));
    let mut malformed = patch.clone();
    malformed.old_sha256 = "0".repeat(64);
    cases.push(("base-hash", malformed));
    let mut malformed = patch.clone();
    malformed.edits[0].old_hex = changed_hex(&malformed.edits[0].old_hex);
    cases.push(("old-payload", malformed));
    let mut malformed = patch.clone();
    malformed.edits[0].new_hex = changed_hex(&malformed.edits[0].new_hex);
    cases.push(("new-payload", malformed));
    let mut malformed = patch.clone();
    malformed.old_len += 1;
    cases.push(("old-length", malformed));
    let mut malformed = patch.clone();
    malformed.new_len = u64::MAX;
    cases.push(("untrusted-large-target-length", malformed));
    let mut malformed = patch.clone();
    malformed.edits[0].old_span.end = malformed.old_len + 1;
    cases.push(("out-of-bounds", malformed));
    let mut malformed = patch.clone();
    malformed.format = "future-patch-format".into();
    cases.push(("unknown-format", malformed));
    let mut malformed = patch.clone();
    malformed.edits[0].new_hex.push('0');
    cases.push(("odd-hex", malformed));
    let mut malformed = patch.clone();
    malformed.edits[0].new_hex = "AF".into();
    cases.push(("uppercase-hex", malformed));
    let mut malformed = patch.clone();
    let span = malformed.edits[0].old_span.clone();
    malformed.edits.insert(
        0,
        PatchEdit {
            old_span: PatchSpan {
                start: span.start,
                end: span.start,
            },
            new_span: PatchSpan {
                start: span.start,
                end: span.start,
            },
            old_hex: String::new(),
            new_hex: String::new(),
        },
    );
    cases.push(("empty-edit", malformed));
    let mut malformed = patch.clone();
    malformed.edits[0].new_hex = malformed.edits[0].old_hex.clone();
    cases.push(("no-op-edit", malformed));
    for (label, malformed) in cases {
        let patch_path = tmp.path(&format!("{label}.uwpatch"));
        // Keep canonical field order while bypassing the creator's checks: these
        // cases must reach the protocol/replay validation, not fail reordering.
        std::fs::write(&patch_path, serde_json::to_vec(&malformed).unwrap()).unwrap();
        let error = reject_without_writes(&tmp, &old_path, &patch_path, label);
        if label == "target-hash" || label == "new-payload" {
            assert!(error.contains("new_sha256"), "{label}: {error}");
        }
        if label == "old-payload" {
            assert!(error.contains("old_hex"), "{label}: {error}");
        }
    }
}

#[test]
fn noncanonical_or_ambiguous_json_cannot_be_applied() {
    let tmp = Temp::new("protocol");
    let old = functions(41, 53);
    let new = functions(47, 53);
    let patch = wasm_git::patch::create(&old, &new).unwrap();
    let canonical = patch.to_bytes().unwrap();
    let old_path = tmp.path("old.wasm");
    std::fs::write(&old_path, &old).unwrap();
    let text = String::from_utf8(canonical.clone()).unwrap();
    let mut newline = canonical.clone();
    newline.push(b'\n');
    let duplicate = text.replacen(
        "{\"format\":",
        "{\"format\":\"uwgit-byte-patch-v1\",\"format\":",
        1,
    );
    let unknown = text.replacen('{', "{\"untrusted_claim\":true,", 1);
    let escaped = text.replacen("uwgit", "\\u0075wgit", 1);
    let cases = [
        ("pretty", serde_json::to_vec_pretty(&patch).unwrap()),
        ("newline", newline),
        ("duplicate", duplicate.into_bytes()),
        ("unknown-field", unknown.into_bytes()),
        ("alternate-escape", escaped.into_bytes()),
        ("truncated", canonical[..canonical.len() - 1].to_vec()),
    ];
    for (label, bytes) in cases {
        let patch_path = tmp.path(&format!("{label}.uwpatch"));
        std::fs::write(&patch_path, bytes).unwrap();
        reject_without_writes(&tmp, &old_path, &patch_path, label);
    }
}

#[test]
fn output_destinations_and_apply_mode_are_explicit_and_never_overwrite() {
    let tmp = Temp::new("destinations");
    let old_path = tmp.path("old.wasm");
    let new_path = tmp.path("new.wasm");
    let patch_path = tmp.path("change.uwpatch");
    let existing = tmp.path("existing");
    std::fs::write(&old_path, functions(41, 53)).unwrap();
    std::fs::write(&new_path, functions(47, 53)).unwrap();
    run_json(&["patch", &old_path, &new_path, "--output", &patch_path]);
    std::fs::write(&existing, b"keep original destination bytes").unwrap();
    let before = snapshot(&tmp.0);
    for arguments in [
        vec!["patch", &old_path, &new_path, "--output", &existing],
        vec!["apply", &old_path, &patch_path, "--output", &existing],
        vec!["apply", &old_path, &patch_path],
        vec![
            "apply",
            &old_path,
            &patch_path,
            "--check",
            "--output",
            &existing,
        ],
    ] {
        let result = invoke(&arguments);
        assert!(!result.status.success(), "{arguments:?} must be refused");
        assert_eq!(
            snapshot(&tmp.0),
            before,
            "refusal must leave files untouched"
        );
    }
}

fn commit(repo: &str, input: &str, bytes: &[u8], message: &str) -> String {
    std::fs::write(input, bytes).unwrap();
    success(&["commit", repo, input, "-m", message])
        .split_whitespace()
        .last()
        .unwrap()
        .to_owned()
}

#[test]
fn immutable_repository_inputs_can_be_replayed_in_an_independent_clone() {
    let tmp = Temp::new("repository");
    let source = tmp.path("source");
    let clone = tmp.path("clone");
    let input = tmp.path("input.wasm");
    let old = functions(41, 53);
    let new = functions(47, 59);
    success(&["init", &source]);
    let base = commit(&source, &input, &old, "base");
    success(&["clone", &source, &clone]);
    let target = commit(&source, &input, &new, "target");
    assert_eq!(base.len(), 64);
    assert_eq!(target.len(), 64);
    let source_before = snapshot(Path::new(&source));
    let clone_before = snapshot(Path::new(&clone));
    let difference = run_json(&[
        "diff", "HEAD", "HEAD", "--repo", &source, "--format", "json",
    ]);
    assert_eq!(difference["binary_changed"], false);
    assert_eq!(difference["inputs"]["old"]["commit"], target);
    assert_eq!(difference["inputs"]["new"]["commit"], target);
    let inspected = run_json(&["inspect", "HEAD", "--repo", &source, "--json"]);
    assert_eq!(inspected["input"]["commit"], target);
    // The patch filename intentionally equals an existing branch: PATCH must
    // remain a filesystem input even when --repo is present.
    let patch_path = tmp.path("main");
    let created = run_json(&[
        "patch",
        &base,
        "HEAD",
        "--repo",
        &source,
        "--output",
        &patch_path,
    ]);
    assert_eq!(created["inputs"]["old"]["commit"], base);
    assert_eq!(created["inputs"]["new"]["commit"], target);
    assert_eq!(snapshot(Path::new(&source)), source_before);
    assert_eq!(snapshot(Path::new(&clone)), clone_before);
    let before_check = snapshot(&tmp.0);
    let checked: Value = serde_json::from_str(&success_at(
        &["apply", "HEAD", "main", "--repo", &clone, "--check"],
        Some(&tmp.0),
    ))
    .unwrap();
    assert_eq!(checked["inputs"]["old"]["commit"], base);
    assert_eq!(checked["inputs"]["patch"]["path"], "main");
    assert_eq!(checked["written"], false);
    assert_eq!(snapshot(&tmp.0), before_check);
    let output_path = tmp.path("replayed.wasm");
    let applied: Value = serde_json::from_str(&success_at(
        &[
            "apply",
            &base,
            "main",
            "--repo",
            &clone,
            "--output",
            &output_path,
        ],
        Some(&tmp.0),
    ))
    .unwrap();
    assert_eq!(applied["inputs"]["old"]["commit"], base);
    assert_eq!(applied["patch"], created["patch"]);
    assert_eq!(applied["audit"], checked["audit"]);
    assert_eq!(std::fs::read(output_path).unwrap(), new);
    assert_eq!(snapshot(Path::new(&source)), source_before);
    assert_eq!(snapshot(Path::new(&clone)), clone_before);
    success(&["fsck", &source]);
    success(&["fsck", &clone]);
}

#[test]
fn command_help_exits_successfully_without_reading_inputs_or_writing_outputs() {
    let tmp = Temp::new("help");
    let missing_old = tmp.path("missing-old");
    let missing_new = tmp.path("missing-new");
    let destination = tmp.path("must-not-exist");
    let before = snapshot(&tmp.0);
    for arguments in [
        vec!["patch", "--help"],
        vec!["apply", "--help"],
        vec!["inspect", "--help"],
        vec!["diff", "--help"],
        vec![
            "patch",
            &missing_old,
            &missing_new,
            "--output",
            &destination,
            "--help",
        ],
        vec![
            "apply",
            &missing_old,
            &missing_new,
            "--output",
            &destination,
            "--help",
        ],
    ] {
        let result = invoke(&arguments);
        assert!(
            result.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("Usage:"));
        assert_eq!(snapshot(&tmp.0), before);
    }
}
