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

#[test]
fn cli_inspect_valid_module_emits_json() {
    let output = Command::new(wasm_git_bin())
        .args(["inspect", &fixture_path("old.wasm"), "--json"])
        .output()
        .expect("failed to execute wasm-git inspect");
    assert!(output.status.success(), "inspect should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(r#""module""#),
        "stdout should contain module key"
    );
    assert!(
        stdout.contains(r#""summary""#),
        "stdout should contain summary key"
    );
    assert!(
        stdout.contains(r#""functions": 1"#),
        "should report 1 function"
    );
    assert!(stdout.contains("LocalGet"), "should contain operator text");
}

#[test]
fn cli_inspect_default_format_emits_json() {
    let output = Command::new(wasm_git_bin())
        .args(["inspect", &fixture_path("old.wasm")])
        .output()
        .expect("failed to execute wasm-git inspect");
    assert!(output.status.success(), "inspect should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(r#""module""#),
        "stdout should contain module key"
    );
    assert!(
        stdout.contains(r#""functions": 1"#),
        "should report 1 function"
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
    let dir = std::env::temp_dir();
    let bad_path = dir.join("wasm-git-test-bad.wasm");
    std::fs::write(&bad_path, b"not wasm binary data").expect("failed to write temp file");

    let output = Command::new(wasm_git_bin())
        .args(["inspect", &bad_path.to_string_lossy()])
        .output()
        .expect("failed to execute wasm-git inspect");
    assert!(!output.status.success(), "should exit with error");
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
    assert!(!output.status.success(), "should exit with error");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("error:"),
        "stderr should contain error prefix"
    );
}

#[test]
fn cli_inspect_missing_args_prints_usage() {
    let output = Command::new(wasm_git_bin())
        .arg("inspect")
        .output()
        .expect("failed to execute wasm-git inspect");
    assert!(!output.status.success(), "should exit with error");
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
    let dir = std::env::temp_dir();
    let bad_path = dir.join("wasm-git-test-diff-bad.wasm");
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
