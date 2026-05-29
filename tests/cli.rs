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
    let compiler = std::env::var("WASM_GIT_CC").unwrap_or_else(|_| "clang".to_string());

    let dir = temp_artifact_dir("c-to-wasm-diff");
    let v1_wasm = dir.join("add_v1.wasm");
    let v2_wasm = dir.join("add_v2.wasm");
    let v1_c = fixture_path("c/add_v1.c");
    let v2_c = fixture_path("c/add_v2.c");

    if let Err(reason) = compile_c_to_wasm(&compiler, &v1_c, &v1_wasm) {
        println!("{}", format_c_to_wasm_skip(&reason));
        return;
    }
    if let Err(reason) = compile_c_to_wasm(&compiler, &v2_c, &v2_wasm) {
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
