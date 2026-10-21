//! Fixed multi-Wasm history replay and publication boundaries; no fuzzing.
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const EMPTY: &[u8] = b"\0asm\x01\0\0\0";
const FUTURE_A: &[u8] = b"\0asm\x01\0\0\0\xff\x01\x42";
const FUTURE_B: &[u8] = b"\0asm\x01\0\0\0\xff\x01\x43";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-tree-history-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn root(&self) -> &str {
        self.0.to_str().unwrap()
    }
    fn path(&self, path: &str) -> PathBuf {
        self.0.join(path)
    }
    fn init(&self) {
        success(&["init", self.root()]);
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        fs::write(self.path(path), bytes).unwrap();
    }
    fn stage(&self, paths: &[&str]) {
        let mut args = vec!["add", self.root()];
        args.extend(paths);
        success(&args);
    }
    fn commit(&self, message: &str) -> String {
        success(&["commit", self.root(), "-m", message]);
        self.tip()
    }
    fn tip(&self) -> String {
        success(&["rev-parse", self.root(), "HEAD"]).trim().into()
    }
    fn switch(&self, branch: &str) {
        success(&["switch", self.root(), branch]);
    }
    fn initial(&self) {
        self.init();
        self.write("main.wasm", &module(0, 0));
        self.write("keep.wasm", EMPTY);
        self.write("delete.wasm", EMPTY);
        self.stage(&["main.wasm", "keep.wasm", "delete.wasm"]);
        self.commit("base");
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn success(args: &[&str]) -> String {
    let output = invoke(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn json(args: &[&str]) -> Value {
    serde_json::from_str(&success(args)).unwrap()
}
fn module(left: i32, right: i32) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (func (result i32) i32.const {left}) (func (result i32) i32.const {right}))"
    ))
    .unwrap()
}
fn snapshot(temp: &Temp) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(base: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(base).unwrap().into();
            if entry.file_type().unwrap().is_dir() {
                result.insert(relative, None);
                visit(base, &path, result);
            } else {
                result.insert(relative, Some(fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(&temp.0, &temp.0, &mut result);
    result
}

#[test]
fn tree_cherry_pick_and_revert_preserve_unrelated_paths_and_exact_module_bytes() {
    let temp = Temp::new();
    temp.initial();
    success(&["branch", temp.root(), "topic"]);
    temp.write("main.wasm", &module(1, 0));
    temp.stage(&["main.wasm"]);
    let ours = temp.commit("ours");
    temp.switch("topic");
    temp.write("main.wasm", &module(0, 2));
    temp.write("added.wasm", FUTURE_A);
    success(&["rm", temp.root(), "delete.wasm"]);
    temp.stage(&["main.wasm", "added.wasm"]);
    let selected = temp.commit("add remove and edit");
    temp.switch("main");
    let picked = json(&["cherry-pick", temp.root(), &selected]);
    assert_eq!(picked["status"], "committed");
    assert_eq!(fs::read(temp.path("main.wasm")).unwrap(), module(1, 2));
    assert_eq!(fs::read(temp.path("keep.wasm")).unwrap(), EMPTY);
    assert_eq!(fs::read(temp.path("added.wasm")).unwrap(), FUTURE_A);
    assert!(!temp.path("delete.wasm").exists());
    assert_eq!(
        json(&["show", temp.root(), "HEAD"])["parents"],
        serde_json::json!([ours])
    );
    let reverted = json(&["revert", temp.root(), &selected]);
    assert_eq!(reverted["status"], "committed");
    assert_eq!(fs::read(temp.path("main.wasm")).unwrap(), module(1, 0));
    assert_eq!(fs::read(temp.path("delete.wasm")).unwrap(), EMPTY);
    assert_eq!(fs::read(temp.path("keep.wasm")).unwrap(), EMPTY);
    assert!(!temp.path("added.wasm").exists());
    success(&["fsck", temp.root()]);
}

#[test]
fn tree_root_commit_is_applied_against_a_real_empty_file_map() {
    let source = Temp::new();
    source.init();
    source.write("root-added.wasm", FUTURE_A);
    source.stage(&["root-added.wasm"]);
    let root_commit = source.commit("tree root");
    let bundle = source.path("root.bundle");
    success(&["bundle", source.root(), bundle.to_str().unwrap()]);
    let temp = Temp::new();
    temp.init();
    temp.write("keep.wasm", FUTURE_B);
    temp.stage(&["keep.wasm"]);
    temp.commit("independent tree");
    success(&[
        "unbundle",
        temp.root(),
        bundle.to_str().unwrap(),
        "selected-root",
    ]);
    assert_eq!(
        json(&["cherry-pick", temp.root(), &root_commit])["status"],
        "committed"
    );
    assert_eq!(fs::read(temp.path("root-added.wasm")).unwrap(), FUTURE_A);
    assert_eq!(fs::read(temp.path("keep.wasm")).unwrap(), FUTURE_B);
    assert_eq!(
        json(&["revert", temp.root(), &root_commit])["status"],
        "committed"
    );
    assert!(!temp.path("root-added.wasm").exists());
    assert_eq!(fs::read(temp.path("keep.wasm")).unwrap(), FUTURE_B);
}

#[test]
fn tree_rebase_combines_all_paths_and_publishes_only_final_replay_tip() {
    let temp = Temp::new();
    temp.initial();
    success(&["branch", temp.root(), "feature"]);
    temp.write("main.wasm", &module(0, 4));
    temp.write("upstream.wasm", FUTURE_A);
    temp.stage(&["main.wasm", "upstream.wasm"]);
    let upstream = temp.commit("upstream");
    temp.switch("feature");
    temp.write("main.wasm", &module(1, 0));
    temp.write("feature.wasm", FUTURE_B);
    temp.stage(&["main.wasm", "feature.wasm"]);
    temp.commit("feature first");
    success(&["rm", temp.root(), "delete.wasm"]);
    temp.write("second.wasm", EMPTY);
    temp.stage(&["second.wasm"]);
    temp.commit("feature second");
    let before: Value = json(&["reflog", temp.root()]);
    let count = before.as_array().unwrap().len();
    let rebased = json(&["rebase", temp.root(), "main"]);
    assert_eq!(rebased["status"], "rebased");
    let commits = rebased["commits"].as_array().unwrap();
    assert_eq!(commits.len(), 2);
    assert_eq!(
        json(&["show", temp.root(), commits[0].as_str().unwrap()])["parents"],
        serde_json::json!([upstream])
    );
    assert_eq!(
        json(&["show", temp.root(), "HEAD"])["parents"],
        serde_json::json!([commits[0]])
    );
    assert_eq!(fs::read(temp.path("main.wasm")).unwrap(), module(1, 4));
    assert_eq!(fs::read(temp.path("upstream.wasm")).unwrap(), FUTURE_A);
    assert_eq!(fs::read(temp.path("feature.wasm")).unwrap(), FUTURE_B);
    assert_eq!(fs::read(temp.path("second.wasm")).unwrap(), EMPTY);
    assert!(!temp.path("delete.wasm").exists());
    let after = json(&["reflog", temp.root()]);
    assert_eq!(after.as_array().unwrap().len(), count + 1);
    success(&["fsck", temp.root()]);
}

#[test]
fn later_tree_rebase_conflict_leaves_objects_refs_index_and_worktree_byte_exact() {
    let temp = Temp::new();
    temp.initial();
    success(&["branch", temp.root(), "feature"]);
    temp.write("main.wasm", &module(0, 9));
    temp.stage(&["main.wasm"]);
    temp.commit("upstream");
    temp.switch("feature");
    temp.write("main.wasm", &module(1, 0));
    temp.write("first.wasm", FUTURE_A);
    temp.stage(&["main.wasm", "first.wasm"]);
    temp.commit("first replay is clean");
    temp.write("main.wasm", &module(1, 2));
    temp.stage(&["main.wasm"]);
    let later = temp.commit("second replay conflicts");
    let before = snapshot(&temp);
    let output = invoke(&["rebase", temp.root(), "main"]);
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "conflict");
    assert_eq!(report["stopped_at"], later);
    assert_eq!(snapshot(&temp), before);
}

#[test]
fn untracked_target_collision_is_rejected_before_any_history_publication() {
    let temp = Temp::new();
    temp.initial();
    success(&["branch", temp.root(), "topic"]);
    temp.switch("topic");
    temp.write("occupied.wasm", FUTURE_A);
    temp.stage(&["occupied.wasm"]);
    let selected = temp.commit("adds occupied path");
    temp.switch("main");
    temp.write("occupied.wasm", FUTURE_B);
    let before = snapshot(&temp);
    for arguments in [
        vec!["cherry-pick", temp.root(), selected.as_str()],
        vec!["rebase", temp.root(), "topic"],
        vec!["merge", temp.root(), "topic", "-m", "must preflight"],
    ] {
        let output = invoke(&arguments);
        assert!(!output.status.success(), "{arguments:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("untracked"));
        assert_eq!(snapshot(&temp), before);
    }
}
