use std::process::Command;

fn wasm_git_bin() -> std::path::PathBuf {
    std::env::var_os("CARGO_BIN_EXE_wasm-git")
        .expect("CARGO_BIN_EXE_wasm-git must be set by cargo")
        .into()
}

fn fixture_path(name: &str) -> String {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    format!("{dir}/tests/fixtures/{name}")
}

// ---------------------------------------------------------------------------
// Shared test fixture helpers
// ---------------------------------------------------------------------------

fn format_c_to_wasm_skip(reason: &str) -> String {
    format!("skipped: C-to-Wasm compiler unavailable ({reason})")
}

fn assert_json_stdout(output: &std::process::Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "expected exit 0, got: {}",
        output.status
    );
    serde_json::from_slice(&output.stdout).expect("stdout is not valid JSON")
}

fn assert_failure_stderr_contains(output: &std::process::Output, expected: &str) {
    assert!(
        !output.status.success(),
        "expected non-zero exit, got success"
    );
    let stderr = String::from_utf8(output.stderr.clone()).expect("stderr is not valid UTF-8");
    assert!(
        stderr.contains(expected),
        "expected stderr to contain '{expected}', but got:\n{stderr}"
    );
}

fn temp_artifact_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wasm-git-test-{label}-pid{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    dir
}

#[test]
fn cli_function_analysis_respects_unknown_declaration_frontiers() {
    fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
        assert!(payload.len() < 128);
        bytes.extend_from_slice(&[id, payload.len() as u8]);
        bytes.extend_from_slice(payload);
    }
    fn fixed(extra: &[(u8, &[u8])], body: &[u8], types: &[u8]) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(&mut bytes, 1, types);
        for (id, payload) in extra.iter().filter(|(id, _)| *id == 2) {
            section(&mut bytes, *id, payload);
        }
        section(&mut bytes, 3, &[1, 0]);
        for (id, payload) in extra.iter().filter(|(id, _)| *id != 2) {
            section(&mut bytes, *id, payload);
        }
        let mut code = vec![1, body.len() as u8];
        code.extend_from_slice(body);
        section(&mut bytes, 10, &code);
        bytes
    }
    fn has_mvp_constant(audit: &serde_json::Value, bytes: &[u8]) -> bool {
        fn find(regions: &[serde_json::Value], bytes: &[u8]) -> bool {
            regions.iter().any(|region| {
                let start = region["span"]["start"].as_u64().unwrap() as usize;
                let end = region["span"]["end"].as_u64().unwrap() as usize;
                assert!(start <= end && end <= bytes.len());
                (region["path"].as_str().unwrap().starts_with("code[0]/")
                    && region["path"].as_str().unwrap().contains("/operator[")
                    && bytes[start..end] == [0x41, 42])
                    || find(region["children"].as_array().unwrap(), bytes)
            })
        }
        audit["sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|section| find(section["regions"].as_array().unwrap(), bytes))
    }
    let mvp = [0, 0x41, 42, 0x1a, 0x0b];
    let types = [1, 0x60, 0, 0];
    let cases = [
        (
            "type",
            fixed(
                &[],
                &[0, 2, 2, 0x0b, 0x41, 42, 0x1a, 0x0b],
                &[3, 0x60, 0, 0, 0x60, 1, 0xff, 0, 0, 0x60, 0, 0],
            ),
        ),
        (
            "import",
            fixed(
                &[(2, &[2, 0, 0, 3, 0xff, 0, 0, 0, 0, 0, 0])],
                &[0, 0x10, 0, 0x41, 42, 0x1a, 0x0b],
                &types,
            ),
        ),
        (
            "table",
            fixed(
                &[(4, &[3, 0x70, 0, 0, 0xff, 0, 0, 0, 0x6f, 0, 0])],
                &[
                    0, 0xfc, 0x10, 0, 0x1a, 0xfc, 0x10, 2, 0x1a, 0x41, 42, 0x1a, 0x0b,
                ],
                &types,
            ),
        ),
        (
            "global",
            fixed(
                &[(
                    6,
                    &[
                        3, 0x7f, 0, 0x41, 0, 0x0b, 0xff, 0, 0, 0xd0, 0x70, 0x0b, 0x7f, 0, 0x41, 0,
                        0x0b,
                    ],
                )],
                &[0, 0x23, 0, 0x1a, 0x23, 2, 0x1a, 0x41, 42, 0x1a, 0x0b],
                &types,
            ),
        ),
        (
            "element",
            fixed(
                &[(9, &[3, 5, 0x70, 0, 5, 0xff, 0, 0, 5, 0x70, 0])],
                &mvp,
                &types,
            ),
        ),
    ];
    let directory = temp_artifact_dir("function-analysis-value-frontier");
    let valid = fixed(&[], &mvp, &types);
    let valid_path = directory.join("valid.wasm");
    std::fs::write(&valid_path, &valid).unwrap();
    for (name, bytes) in cases {
        let bad_path = directory.join(format!("{name}.wasm"));
        std::fs::write(&bad_path, &bytes).unwrap();
        for standard in ["core1", "core2", "core3", "all-known"] {
            let inspected = Command::new(wasm_git_bin())
                .arg("inspect")
                .arg(&bad_path)
                .args(["--json", "--standard", standard])
                .output()
                .unwrap();
            let json = assert_json_stdout(&inspected);
            assert_eq!(
                json["function_analysis"]["available"], false,
                "{name}/{standard}"
            );
            assert!(json["module"].is_null());
            assert!(json["summary"].is_null());
            let reason = json["function_analysis"]["reason"].as_str().unwrap();
            assert!(reason.contains(&format!("{name}[0]")), "{reason}");
            assert!(reason.contains("lossless binary audit"), "{reason}");
            assert_eq!(json["audit"]["byte_len"], bytes.len() as u64);
            assert!(has_mvp_constant(&json["audit"], &bytes));
            let compared = Command::new(wasm_git_bin())
                .arg("diff")
                .arg(&bad_path)
                .arg(&valid_path)
                .args(["--format", "json", "--standard", standard])
                .output()
                .unwrap();
            let diff = assert_json_stdout(&compared);
            assert_eq!(
                diff["function_analysis"]["available"], false,
                "{name}/{standard}"
            );
            assert!(diff["summary"].is_null());
            assert!(diff["function_matches"].as_array().unwrap().is_empty());
            assert!(diff["changes"].as_array().unwrap().is_empty());
            assert_eq!(diff["binary_changed"], true);
            assert!(!diff["audit"]["edits"].as_array().unwrap().is_empty());
            assert_eq!(diff["audit"]["old"]["byte_len"], bytes.len() as u64);
            assert_eq!(diff["audit"]["new"]["byte_len"], valid.len() as u64);
            assert!(has_mvp_constant(&diff["audit"]["old"], &bytes));
            assert!(has_mvp_constant(&diff["audit"]["new"], &valid));
        }
        for format in [vec!["--format", "text"], vec!["--short"]] {
            let output = Command::new(wasm_git_bin())
                .arg("diff")
                .arg(&bad_path)
                .arg(&valid_path)
                .args(format)
                .env("NO_COLOR", "1")
                .output()
                .unwrap();
            assert!(output.status.success());
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(
                text.contains("Function comparison unavailable"),
                "{name}: {text}"
            );
            assert!(text.contains("lossless binary audit"), "{name}: {text}");
        }
    }

    let mut bare_value = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bare_value, 1, &[1, 0x60, 1, 0, 0]);
    let bare_path = directory.join("bare-value.wasm");
    std::fs::write(&bare_path, &bare_value).unwrap();
    for standard in ["core1", "core2", "core3", "all-known"] {
        let inspected = Command::new(wasm_git_bin())
            .arg("inspect")
            .arg(&bare_path)
            .args(["--json", "--standard", standard])
            .output()
            .unwrap();
        let json = assert_json_stdout(&inspected);
        assert_eq!(json["function_analysis"]["available"], false);
        assert!(json["function_analysis"]["reason"]
            .as_str()
            .unwrap()
            .contains("invalid Core encoding"));
        assert!(json["module"].is_null());
        assert!(json["summary"].is_null());
        assert!(json["audit"]["sections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|section| section["status"] == "decoded"));
        assert!(json["audit"]["standard"]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["status"] == "invalid_encoding"));
        let compared = Command::new(wasm_git_bin())
            .arg("diff")
            .arg(&bare_path)
            .arg(&valid_path)
            .args(["--format", "json", "--standard", standard])
            .output()
            .unwrap();
        let diff = assert_json_stdout(&compared);
        assert_eq!(diff["function_analysis"]["available"], false);
        assert!(diff["function_analysis"]["reason"]
            .as_str()
            .unwrap()
            .contains("invalid Core encoding"));
        assert!(diff["summary"].is_null());
        assert_eq!(diff["binary_changed"], true);
        assert!(!diff["audit"]["edits"].as_array().unwrap().is_empty());
        assert_eq!(diff["audit"]["old"]["byte_len"], bare_value.len() as u64);
        assert_eq!(diff["audit"]["new"]["byte_len"], valid.len() as u64);
    }

    let mut custom = valid;
    section(
        &mut custom,
        0,
        &[
            9, b'p', b'r', b'o', b'd', b'u', b'c', b'e', b'r', b's', 0x80,
        ],
    );
    let simd =
        wat::parse_str("(module (func v128.const i32x4 0 0 0 0 drop i32.const 42 drop))").unwrap();
    for (label, bytes) in [("opaque-custom", custom), ("disabled-simd", simd)] {
        let path = directory.join(format!("{label}.wasm"));
        std::fs::write(&path, &bytes).unwrap();
        let inspected = Command::new(wasm_git_bin())
            .arg("inspect")
            .arg(&path)
            .args(["--json", "--standard", "core1"])
            .output()
            .unwrap();
        let json = assert_json_stdout(&inspected);
        assert_eq!(json["function_analysis"]["available"], true, "{label}");
        assert!(!json["module"].is_null());
        assert!(!json["summary"].is_null());
        assert!(has_mvp_constant(&json["audit"], &bytes));
        if label == "opaque-custom" {
            assert!(json["audit"]["sections"]
                .as_array()
                .unwrap()
                .iter()
                .any(|section| { section["id"] == 0 && section["status"] == "opaque" }));
        } else {
            assert_eq!(json["audit"]["standard"]["validation"], "invalid");
            assert!(json["audit"]["standard"]["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| {
                    entry["feature"] == "simd" && entry["status"] == "recognized_but_disabled"
                }));
        }
        let compared = Command::new(wasm_git_bin())
            .arg("diff")
            .arg(&path)
            .arg(&path)
            .args(["--format", "json", "--standard", "core1"])
            .output()
            .unwrap();
        let diff = assert_json_stdout(&compared);
        assert_eq!(diff["function_analysis"]["available"], true, "{label}");
        assert_eq!(diff["binary_changed"], false);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

fn binding_fixture(old: &str, new: &str) -> (serde_json::Value, String, Vec<u8>, Vec<u8>) {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let directory = std::path::Path::new("/tmp").join(format!(
        "uwgit-binding-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    let old = wat::parse_str(old).unwrap();
    let new = wat::parse_str(new).unwrap();
    for bytes in [&old, &new] {
        wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all())
            .validate_all(bytes)
            .unwrap();
    }
    let old_path = directory.join("old.wasm");
    let new_path = directory.join("new.wasm");
    std::fs::write(&old_path, &old).unwrap();
    std::fs::write(&new_path, &new).unwrap();
    let result = Command::new(wasm_git_bin())
        .arg("diff")
        .arg(&old_path)
        .arg(&new_path)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let json = assert_json_stdout(&result);
    let output = Command::new(wasm_git_bin())
        .arg("diff")
        .arg(&old_path)
        .arg(&new_path)
        .args(["--format", "text"])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    (json, text, old, new)
}

fn changed_caller<'a>(
    report: &'a serde_json::Value,
    export: &str,
) -> Option<&'a serde_json::Value> {
    let id = format!("func:export:{export}:");
    report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["kind"] == "function_changed")
        .map(|change| &change["function"])
        .find(|function| function["old_id"].as_str().unwrap().starts_with(&id))
}

fn verify_binding_position(bytes: &[u8], site: &serde_json::Value) {
    let mut found = false;
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        if let wasmparser::Payload::CodeSectionEntry(body) = payload.unwrap() {
            let mut reader = body.get_operators_reader().unwrap();
            let mut index = 0;
            while !reader.eof() {
                let offset = reader.original_position();
                let operator = reader.read().unwrap();
                if offset as u64 == site["offset"].as_u64().unwrap() {
                    let (opcode, target) = match operator {
                        wasmparser::Operator::Call { function_index } => ("Call", function_index),
                        wasmparser::Operator::ReturnCall { function_index } => {
                            ("ReturnCall", function_index)
                        }
                        wasmparser::Operator::RefFunc { function_index } => {
                            ("RefFunc", function_index)
                        }
                        _ => panic!("binding offset must point to the reported function reference"),
                    };
                    assert_eq!(site["opcode"], opcode);
                    assert_eq!(site["operator_index"], index);
                    assert_eq!(site["function_index"], target);
                    assert_eq!(site["target"]["source_index"], target);
                    found = true;
                }
                index += 1;
            }
        }
    }
    assert!(
        found,
        "binding physical offset must belong to one real decoded operator"
    );
}

#[test]
fn cli_import_reordering_reports_each_call_site_even_when_target_sets_and_bytes_match() {
    for opcode in ["call", "return_call"] {
        let old = format!(
            r#"(module
            (import "m" "a" (func (result i32)))
            (import "m" "b" (func (result i32)))
            (func (export "run") (result i32) {opcode} 0))"#
        );
        let new = old
            .replace("\"a\"", "\"tmp\"")
            .replace("\"b\"", "\"a\"")
            .replace("\"tmp\"", "\"b\"");
        let (report, text, old_bytes, new_bytes) = binding_fixture(&old, &new);
        let caller = changed_caller(&report, "run")
            .expect("same raw operand must still expose the changed binding");
        assert_eq!(caller["direct_calls_changed"], false);
        assert!(caller["operators"].as_array().unwrap().is_empty());
        let binding = &caller["call_bindings"][0];
        assert_eq!(binding["relation"], "different_target");
        assert_eq!(binding["pairing"], "opcode_alignment");
        assert_eq!(binding["target_changed"], true);
        assert_eq!(binding["identity_unproven"], true);
        assert_eq!(binding["old"]["function_index"], 0);
        assert_eq!(binding["new"]["function_index"], 0);
        assert_eq!(binding["old"]["target"]["import"]["name"], "a");
        assert_eq!(binding["new"]["target"]["import"]["name"], "b");
        verify_binding_position(&old_bytes, &binding["old"]);
        verify_binding_position(&new_bytes, &binding["new"]);
        assert!(text.contains("call/reference target changes: 1"));
        assert!(text.contains("different_target"));
        assert!(text.contains("identity_unproven=true"));
    }
    let old = r#"(module
        (import "m" "a" (func (result i32)))
        (import "m" "b" (func (result i32)))
        (func (export "run") (result i32) call 0 drop call 1))"#;
    let new = old
        .replace("\"a\"", "\"tmp\"")
        .replace("\"b\"", "\"a\"")
        .replace("\"tmp\"", "\"b\"");
    let (report, _, a, b) = binding_fixture(old, &new);
    let bindings = changed_caller(&report, "run").unwrap()["call_bindings"]
        .as_array()
        .unwrap();
    assert_eq!(
        bindings.len(),
        2,
        "sort/dedup of the target set cannot substitute for call-site evidence"
    );
    for (binding, index, old_name, new_name) in
        [(&bindings[0], 0, "a", "b"), (&bindings[1], 2, "b", "a")]
    {
        assert_eq!(binding["old"]["operator_index"], index);
        assert_eq!(binding["new"]["operator_index"], index);
        assert_eq!(binding["old"]["target"]["import"]["name"], old_name);
        assert_eq!(binding["new"]["target"]["import"]["name"], new_name);
        assert_eq!(binding["target_changed"], true);
        verify_binding_position(&a, &binding["old"]);
        verify_binding_position(&b, &binding["new"]);
    }
}

#[test]
fn cli_defined_reordering_and_ref_func_expose_candidate_target_changes() {
    for reference in [false, true] {
        let suffix = if reference {
            r#"(elem declare func 0 1) (func (export "run") (result funcref) ref.func 0)"#
        } else {
            r#"(func (export "run") (result i32) call 0)"#
        };
        let old = format!(
            "(module (func (result i32) i32.const 1) (func (result i32) i32.const 2) {suffix})"
        );
        let new = format!(
            "(module (func (result i32) i32.const 2) (func (result i32) i32.const 1) {suffix})"
        );
        let (report, _, a, b) = binding_fixture(&old, &new);
        let caller = changed_caller(&report, "run").unwrap();
        assert!(caller["operators"].as_array().unwrap().is_empty());
        let binding = &caller["call_bindings"][0];
        assert_eq!(binding["target_changed"], true);
        assert_eq!(binding["old"]["function_index"], 0);
        assert_eq!(binding["new"]["function_index"], 0);
        assert_eq!(binding["target_match"]["old_source_index"], 0);
        assert_eq!(binding["target_match"]["new_source_index"], 1);
        assert_eq!(binding["target_match"]["ambiguous"], false);
        assert_eq!(binding["identity_unproven"], true);
        verify_binding_position(&a, &binding["old"]);
        verify_binding_position(&b, &binding["new"]);
    }
}

#[test]
fn cli_callee_implementation_change_does_not_claim_a_caller_binding_change() {
    let old = r#"(module (func (export "target") (result i32) i32.const 1)
        (func (export "run") (result i32) call 0))"#;
    let new = old.replace("i32.const 1", "i32.const 2");
    let (report, _, _, _) = binding_fixture(old, &new);
    assert!(changed_caller(&report, "target").is_some());
    assert!(changed_caller(&report, "run").is_none());
    assert_eq!(report["summary"]["functions_changed"], 1);
}

#[test]
fn cli_unexported_wrapper_survives_a_leaf_implementation_change() {
    let old = r#"(module
        (func $leaf (result i32) i32.const 1)
        (func $wrapper (result i32) call $leaf))"#;
    let new = old.replace("i32.const 1", "i32.const 2");
    let (report, _, _, _) = binding_fixture(old, &new);
    assert_eq!(report["summary"]["functions_added"], 0);
    assert_eq!(report["summary"]["functions_removed"], 0);
    assert_eq!(report["summary"]["functions_changed"], 1);
    let matches = report["function_matches"].as_array().unwrap();
    let wrapper = matches
        .iter()
        .find(|matched| matched["old_source_index"] == 1)
        .expect("the unexported wrapper must retain a candidate correspondence");
    assert_eq!(wrapper["new_source_index"], 1);
    assert_eq!(wrapper["ambiguous"], false);
    let leaf = matches
        .iter()
        .find(|matched| matched["old_source_index"] == 0)
        .unwrap();
    assert_eq!(leaf["new_source_index"], 0);
    let changed = report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["kind"] == "function_changed")
        .map(|change| &change["function"])
        .collect::<Vec<_>>();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["old_id"], leaf["old_id"]);
    assert_eq!(changed[0]["new_id"], leaf["new_id"]);
    assert!(!changed[0]["operators"].as_array().unwrap().is_empty());
    assert!(changed[0]["call_bindings"].as_array().unwrap().is_empty());
    for note in report["call_binding_notes"].as_array().unwrap() {
        for binding in note["call_bindings"].as_array().unwrap() {
            assert_ne!(binding["target_changed"], true);
        }
    }
}

#[test]
fn cli_index_relocation_is_distinct_from_a_target_change_and_nop_insertion_aligns_sites() {
    let old = r#"(module (func (export "target") (result i32) i32.const 1)
        (func (export "run") (result i32) call 0))"#;
    let new = r#"(module (import "m" "unused" (func))
        (func (export "target") (result i32) i32.const 1)
        (func (export "run") (result i32) call 1))"#;
    let (report, _, a, b) = binding_fixture(old, new);
    let caller = changed_caller(&report, "run").unwrap();
    assert_eq!(caller["direct_calls_changed"], true);
    assert!(!caller["operators"].as_array().unwrap().is_empty());
    let binding = &caller["call_bindings"][0];
    assert_eq!(binding["relation"], "same_target_index_relocated");
    assert_eq!(binding["target_changed"], false);
    assert_eq!(binding["old"]["function_index"], 0);
    assert_eq!(binding["new"]["function_index"], 1);
    verify_binding_position(&a, &binding["old"]);
    verify_binding_position(&b, &binding["new"]);
    let inserted = old.replace("call 0", "nop call 0");
    let (report, _, _, _) = binding_fixture(old, &inserted);
    let caller = changed_caller(&report, "run").unwrap();
    assert!(
        caller["call_bindings"].as_array().unwrap().is_empty(),
        "an inserted nop must not invent removed/redirected call sites"
    );
}

#[test]
fn cli_identical_recursive_and_duplicate_import_modules_have_no_invented_changes() {
    for source in [
        r#"(module (func $f (export "run") call $f))"#,
        r#"(module (import "m" "f" (func)) (import "m" "f" (func)) (func (export "run") call 0))"#,
    ] {
        let (report, _, _, _) = binding_fixture(source, source);
        assert_eq!(report["binary_changed"], false);
        assert_eq!(report["summary"]["functions_changed"], 0);
        assert!(report["changes"].as_array().unwrap().is_empty());
        assert!(report["call_binding_notes"].as_array().unwrap().is_empty());
    }
    let old =
        r#"(module (import "m" "f" (func)) (import "m" "f" (func)) (func (export "run") call 0))"#;
    let shifted = r#"(module (import "m" "unused" (func)) (import "m" "f" (func)) (import "m" "f" (func)) (func (export "run") call 1))"#;
    let (report, _, _, _) = binding_fixture(old, shifted);
    let binding = &changed_caller(&report, "run").unwrap()["call_bindings"][0];
    assert_eq!(binding["relation"], "ambiguous_target");
    assert!(binding["target_changed"].is_null());
    assert_eq!(binding["target_match"]["ambiguous"], true);
    assert_eq!(
        binding["old"]["target"]["import"],
        binding["new"]["target"]["import"]
    );
    let only_memory = old.replace("(func (export", "(memory 1) (func (export");
    let (report, text, _, _) = binding_fixture(old, &only_memory);
    assert_eq!(report["summary"]["functions_changed"], 0);
    assert!(changed_caller(&report, "run").is_none());
    let note = report["call_binding_notes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|note| {
            note["old_id"]
                .as_str()
                .unwrap()
                .starts_with("func:export:run:")
        })
        .unwrap();
    assert_eq!(note["call_bindings"][0]["relation"], "ambiguous_target");
    assert!(note["call_bindings"][0]["target_changed"].is_null());
    assert!(text.contains("no known function modification counted"));
}

#[test]
fn cli_unexported_start_caller_retains_binding_differences() {
    let old = r#"(module
        (import "lib.test" "get_argc" (func (result i32)))
        (import "lib.test" "get_argv_buf_size" (func (result i32)))
        (func $assert (param i32 i32) local.get 0 local.get 1 i32.ne if unreachable end)
        (func $start call 0 i32.const 3 call $assert call 1 i32.const 16 call $assert)
        (start $start))"#;
    let new = old
        .replace("\"get_argc\"", "\"tmp\"")
        .replace("\"get_argv_buf_size\"", "\"get_argc\"")
        .replace("\"tmp\"", "\"get_argv_buf_size\"");
    let (report, _, a, b) = binding_fixture(old, &new);
    let caller = report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["kind"] == "function_changed")
        .map(|change| &change["function"])
        .find(|function| {
            function["call_bindings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|binding| binding["target_changed"] == true)
                .count()
                == 2
        })
        .expect("unexported real-source start role must retain candidate binding evidence");
    assert_eq!(caller["direct_calls_changed"], false);
    assert!(caller["operators"].as_array().unwrap().is_empty());
    for binding in caller["call_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|binding| binding["target_changed"] == true)
    {
        verify_binding_position(&a, &binding["old"]);
        verify_binding_position(&b, &binding["new"]);
    }
}

#[test]
fn format_c_to_wasm_skip_exact_string() {
    let msg = format_c_to_wasm_skip("compiler missing");
    assert_eq!(
        msg,
        "skipped: C-to-Wasm compiler unavailable (compiler missing)"
    );
}

#[test]
fn cli_inspect_valid_module_emits_json() {
    let output = Command::new(wasm_git_bin())
        .args(["inspect", &fixture_path("old.wasm"), "--json"])
        .output()
        .expect("failed to execute wasm-git inspect");
    let json = assert_json_stdout(&output);
    assert!(
        json.get("module").and_then(|v| v.as_object()).is_some(),
        "stdout should contain a module object"
    );
    let funcs = json.pointer("/summary/functions").and_then(|v| v.as_u64());
    assert_eq!(funcs, Some(1), "summary.functions should be 1");
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty on successful inspect, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_inspect_default_format_emits_json() {
    let output = Command::new(wasm_git_bin())
        .args(["inspect", &fixture_path("old.wasm")])
        .output()
        .expect("failed to execute wasm-git inspect");
    let json = assert_json_stdout(&output);
    assert!(
        json.get("module").and_then(|v| v.as_object()).is_some(),
        "stdout should contain a module object"
    );
    let funcs = json.pointer("/summary/functions").and_then(|v| v.as_u64());
    assert_eq!(funcs, Some(1), "summary.functions should be 1");
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty on successful inspect, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_diff_text_shows_canonical_change() {
    let output = Command::new(wasm_git_bin())
        .args([
            "diff",
            &fixture_path("old.wasm"),
            &fixture_path("new.wasm"),
            "--format",
            "text",
        ])
        .output()
        .expect("failed to execute wasm-git diff");
    assert!(output.status.success(), "diff should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("abi: unchanged"), "ABI should be unchanged");
    assert!(
        stdout.contains("1 matched, 1 changed"),
        "should report 1 match, 1 change"
    );
    assert!(
        stdout.contains("~ op[1]: LocalGet { local_index: 1 } -> I32Const { value: 1 }"),
        "should show the canonical operator replacement"
    );
}

#[test]
fn cli_diff_default_format_is_text() {
    let output = Command::new(wasm_git_bin())
        .args(["diff", &fixture_path("old.wasm"), &fixture_path("new.wasm")])
        .output()
        .expect("failed to execute wasm-git diff");
    assert!(output.status.success(), "diff should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("abi: unchanged"),
        "default output should be text"
    );
    assert!(
        stdout.contains("~ op[1]: LocalGet { local_index: 1 } -> I32Const { value: 1 }"),
        "should show canonical operator replacement"
    );
}

#[test]
fn cli_duplicate_function_changes_keep_ambiguity_in_every_output_format() {
    let directory = temp_artifact_dir("duplicate-change-ambiguity");
    for (label, old_values, new_values) in [
        ("both-change", [0, 0], [1, 1]),
        ("old-duplicates", [0, 0], [0, 1]),
        ("new-duplicates", [0, 1], [0, 0]),
    ] {
        let module = |values: [i32; 2]| {
            wat::parse_str(format!(
                "(module (func (result i32) i32.const {}) (func (result i32) i32.const {}))",
                values[0], values[1]
            ))
            .unwrap()
        };
        let old = directory.join(format!("{label}-old.wasm"));
        let new = directory.join(format!("{label}-new.wasm"));
        std::fs::write(&old, module(old_values)).unwrap();
        std::fs::write(&new, module(new_values)).unwrap();
        let output = Command::new(wasm_git_bin())
            .arg("diff")
            .arg(&old)
            .arg(&new)
            .args(["--format", "json"])
            .output()
            .unwrap();
        let json = assert_json_stdout(&output);
        assert_eq!(json["binary_changed"], true, "{label}");
        assert_eq!(json["function_analysis"]["available"], true, "{label}");
        let matches = json["function_matches"].as_array().unwrap();
        assert_eq!(matches.len(), 2, "{label}");
        for paired in matches {
            assert_eq!(paired["ambiguous"], true, "{label}: {paired}");
            assert_eq!(paired["confidence"], 0.5, "{label}: {paired}");
        }
        for (arguments, expected) in [
            (vec!["--format", "text"], "ambiguous=true"),
            (vec!["--short"], "ambiguous function pairings: 2"),
        ] {
            let output = Command::new(wasm_git_bin())
                .arg("diff")
                .arg(&old)
                .arg(&new)
                .args(arguments)
                .env("NO_COLOR", "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{label}: {}", output.status);
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains(expected), "{label}: {text}");
            if expected == "ambiguous=true" {
                assert_eq!(text.matches(expected).count(), 2, "{label}: {text}");
                assert!(!text.contains("ambiguous=false"), "{label}: {text}");
            }
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cli_diff_json_shows_structured_output() {
    let output = Command::new(wasm_git_bin())
        .args([
            "diff",
            &fixture_path("old.wasm"),
            &fixture_path("new.wasm"),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to execute wasm-git diff");
    assert!(output.status.success(), "diff --format json should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(r#""kind": "replace""#),
        "JSON should contain replace kind"
    );
    assert!(
        stdout.contains(r#""old_id": "func:export:add:type:i32,i32->i32""#),
        "JSON should contain old function ID"
    );
    assert!(
        stdout.contains("LocalGet { local_index: 1 }"),
        "JSON should contain old operator text"
    );
    assert!(
        stdout.contains("I32Const { value: 1 }"),
        "JSON should contain new operator text"
    );
}

#[test]
fn cli_diff_short_shows_compact_summary() {
    let output = Command::new(wasm_git_bin())
        .args([
            "diff",
            &fixture_path("old.wasm"),
            &fixture_path("new.wasm"),
            "--short",
        ])
        .output()
        .expect("failed to execute wasm-git diff --short");
    assert!(output.status.success(), "diff --short should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("1 matched, 1 changed"));
    assert!(stdout.contains("changes: 1 total, 1 functions"));
    assert!(!stdout.contains("Function matches:"));
    assert!(!stdout.contains("~ op[1]:"));
}

#[test]
fn cli_diff_short_overrides_json_format() {
    let output = Command::new(wasm_git_bin())
        .args([
            "diff",
            &fixture_path("old.wasm"),
            &fixture_path("new.wasm"),
            "--format",
            "json",
            "--short",
        ])
        .output()
        .expect("failed to execute wasm-git diff --format json --short");
    assert!(output.status.success(), "diff --short should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Summary:"));
    assert!(!stdout.contains(r#""function_matches""#));
}

#[test]
fn cli_inspect_malformed_bytes_prints_error() {
    let dir = temp_artifact_dir("inspect-malformed");
    let bad_path = dir.join("bad.wasm");
    std::fs::write(&bad_path, b"not wasm binary data").expect("failed to write temp file");

    let output = Command::new(wasm_git_bin())
        .args(["inspect", &bad_path.to_string_lossy()])
        .output()
        .expect("failed to execute wasm-git inspect");
    assert!(!output.status.success(), "should exit with error");
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty on parse error, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("wasm parse error:"),
        "stderr should contain parse error: {stderr}"
    );

    std::fs::remove_file(&bad_path).ok();
}

#[test]
fn cli_inspect_nonexistent_file_prints_error() {
    let output = Command::new(wasm_git_bin())
        .args(["inspect", "/tmp/wasm-git-test-nonexistent.wasm"])
        .output()
        .expect("failed to execute wasm-git inspect");
    assert_failure_stderr_contains(&output, "error:");
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty on file-not-found error, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn cli_inspect_missing_args_prints_usage() {
    let output = Command::new(wasm_git_bin())
        .arg("inspect")
        .output()
        .expect("failed to execute wasm-git inspect");
    assert!(!output.status.success(), "should exit with error");
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty on usage error, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("usage:"), "stderr should print usage");
}

#[test]
fn cli_diff_missing_args_prints_usage() {
    let output = Command::new(wasm_git_bin())
        .arg("diff")
        .output()
        .expect("failed to execute wasm-git diff");
    assert!(!output.status.success(), "should exit with error");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("usage:"), "stderr should print usage");
}

#[test]
fn cli_unknown_command_prints_usage() {
    let output = Command::new(wasm_git_bin())
        .arg("blargh")
        .output()
        .expect("failed to execute wasm-git");
    assert!(!output.status.success(), "should exit with error");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unknown command:"),
        "stderr should mention unknown command"
    );
    assert!(stderr.contains("usage:"), "stderr should print usage");
}

#[test]
fn cli_no_command_prints_usage() {
    let output = Command::new(wasm_git_bin())
        .output()
        .expect("failed to execute wasm-git");
    assert!(!output.status.success(), "should exit with error");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("usage:"), "stderr should print usage");
}

#[test]
fn cli_diff_malformed_bytes_prints_error() {
    let dir = temp_artifact_dir("diff-malformed");
    let bad_path = dir.join("bad.wasm");
    std::fs::write(&bad_path, b"not wasm binary data").expect("failed to write temp file");

    let output = Command::new(wasm_git_bin())
        .args([
            "diff",
            &bad_path.to_string_lossy(),
            &fixture_path("old.wasm"),
        ])
        .output()
        .expect("failed to execute wasm-git diff");
    assert!(
        !output.status.success(),
        "should exit with error on malformed input"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("wasm parse error:"),
        "stderr should contain parse error: {stderr}"
    );

    std::fs::remove_file(&bad_path).ok();
}

#[test]
fn cli_diff_nonexistent_file_prints_error() {
    let output = Command::new(wasm_git_bin())
        .args([
            "diff",
            &fixture_path("old.wasm"),
            "/tmp/wasm-git-test-diff-nonexistent.wasm",
        ])
        .output()
        .expect("failed to execute wasm-git diff");
    assert!(!output.status.success(), "should exit with error");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("error:"),
        "stderr should contain error prefix"
    );
}

// ---------------------------------------------------------------------------
// C-to-Wasm integration: compile .c → .wasm, diff, assert change signal
// ---------------------------------------------------------------------------

fn compile_c_to_wasm(compiler: &str, src: &str, dst: &std::path::Path) -> Result<(), String> {
    let output = Command::new(compiler)
        .args([
            "--target=wasm32-unknown-unknown",
            "-nostdlib",
            "-Wl,--no-entry",
            "-Wl,--export=add",
            "-O0",
            "-o",
        ])
        .arg(dst)
        .arg(src)
        .output()
        .map_err(|e| format!("compiler unavailable ({e})"))?;
    if !output.status.success() {
        return Err(format!(
            "compiler failed ({})",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[test]
fn c_to_wasm_diff_detects_c_change() {
    let compiler_required = std::env::var_os("WASM_GIT_CC").is_some();
    let compiler = std::env::var("WASM_GIT_CC").unwrap_or_else(|_| "clang".to_string());

    let dir = temp_artifact_dir("c-to-wasm-diff");
    let v1_wasm = dir.join("add_v1.wasm");
    let v2_wasm = dir.join("add_v2.wasm");
    let v1_c = fixture_path("c/add_v1.c");
    let v2_c = fixture_path("c/add_v2.c");

    if let Err(reason) = compile_c_to_wasm(&compiler, &v1_c, &v1_wasm) {
        assert!(
            !compiler_required,
            "explicit WASM_GIT_CC must work: {reason}"
        );
        println!("{}", format_c_to_wasm_skip(&reason));
        return;
    }
    if let Err(reason) = compile_c_to_wasm(&compiler, &v2_c, &v2_wasm) {
        assert!(
            !compiler_required,
            "explicit WASM_GIT_CC must work: {reason}"
        );
        println!("{}", format_c_to_wasm_skip(&reason));
        return;
    }

    let inspect_v1 = Command::new(wasm_git_bin())
        .args(["inspect", &v1_wasm.to_string_lossy(), "--json"])
        .output()
        .expect("inspect add_v1.wasm failed");
    let json_v1 = assert_json_stdout(&inspect_v1);
    assert!(
        json_v1
            .pointer("/summary/functions")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            >= 1,
        "add_v1.wasm should export at least one function"
    );

    let inspect_v2 = Command::new(wasm_git_bin())
        .args(["inspect", &v2_wasm.to_string_lossy(), "--json"])
        .output()
        .expect("inspect add_v2.wasm failed");
    let json_v2 = assert_json_stdout(&inspect_v2);
    assert!(
        json_v2
            .pointer("/summary/functions")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            >= 1,
        "add_v2.wasm should export at least one function"
    );

    let diff = Command::new(wasm_git_bin())
        .args([
            "diff",
            &v1_wasm.to_string_lossy(),
            &v2_wasm.to_string_lossy(),
            "--format",
            "json",
        ])
        .output()
        .expect("diff failed");
    let diff_json = assert_json_stdout(&diff);

    let functions_changed = diff_json
        .pointer("/summary/functions_changed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let operator_replacements = diff_json
        .pointer("/summary/operator_replacements")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    assert!(
        functions_changed >= 1 || operator_replacements >= 1,
        "expected at least one changed function or operator replacement, \
         got functions_changed={functions_changed} operator_replacements={operator_replacements}"
    );

    let changes = diff_json.pointer("/changes").and_then(|v| v.as_array());
    assert!(
        changes.is_some_and(|a| !a.is_empty()),
        "expected non-empty changes array in diff JSON output"
    );
}
