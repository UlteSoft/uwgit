use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = PathBuf::from("/tmp").join(format!(
            "uwgit-history-{}-{}",
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
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn run(args: &[&str]) -> String {
    let result = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&run(args)).unwrap()
}
fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}
#[test]
fn decentralized_history_can_be_forked_transferred_and_audited() {
    let tmp = Temp::new();
    let original = tmp.path("original");
    let peer = tmp.path("peer");
    let bundle = tmp.path("peer.bundle");
    let checkout = tmp.path("exact.wasm");
    run(&["init", &original]);
    run(&["commit", &original, &fixture("old.wasm"), "-m", "base"]);
    run(&["clone", &original, &peer]);
    run(&["branch", &peer, "work"]);
    run(&["switch", &peer, "work"]);
    run(&["commit", &peer, &fixture("new.wasm"), "-m", "one operator"]);
    run(&["bundle", &peer, &bundle]);
    run(&["unbundle", &original, &bundle, "incoming"]);
    let difference = json(&[
        "diff", "main", "incoming", "--repo", &original, "--format", "json",
    ]);
    assert_eq!(difference["binary_changed"], true);
    assert_eq!(difference["summary"]["functions_changed"], 1);
    assert!(!difference["audit"]["edits"].as_array().unwrap().is_empty());
    run(&["checkout", &original, "incoming", &checkout]);
    assert_eq!(
        std::fs::read(checkout).unwrap(),
        std::fs::read(fixture("new.wasm")).unwrap()
    );
    let inspection = json(&["inspect", "incoming", "--repo", &original]);
    assert_eq!(
        inspection["audit"]["validation"],
        "valid_with_all_known_features"
    );
    let fsck = json(&["fsck", &original]);
    assert_eq!(fsck["commits"], 2);
}

#[test]
fn future_opcode_changes_are_audited_even_when_function_analysis_stops() {
    let tmp = Temp::new();
    let old = tmp.path("old.wasm");
    let new = tmp.path("new.wasm");
    let mut bytes = std::fs::read(fixture("old.wasm")).unwrap();
    // The final instruction is end. 0xff has no instruction layout known here.
    let index = bytes.len() - 2;
    bytes[index] = 0xff;
    std::fs::write(&old, &bytes).unwrap();
    bytes[index] = 0xf5;
    std::fs::write(&new, &bytes).unwrap();
    let difference = json(&["diff", &old, &new, "--format", "json"]);
    assert_eq!(difference["binary_changed"], true);
    assert_eq!(difference["function_analysis"]["available"], false);
    let diagnostics = difference["audit"]["old"]["diagnostics"]
        .as_array()
        .unwrap();
    assert!(diagnostics.iter().any(|d| d["code"] == "unknown_operator"));
    assert!(!difference["audit"]["edits"].as_array().unwrap().is_empty());
}
