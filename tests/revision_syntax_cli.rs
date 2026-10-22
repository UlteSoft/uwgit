use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "uwgit-revisions-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        ok(&["init", p(&root)]);
        Self(root)
    }
    fn root(&self) -> &str {
        p(&self.0)
    }
    fn commit(&self, value: u8) -> String {
        fs::write(
            self.0.join("a.wasm"),
            [b"\0asm\x01\0\0\0".as_slice(), &[0, 3, 1, b'x', value]].concat(),
        )
        .unwrap();
        ok(&["add", self.root(), "a.wasm"]);
        ok(&["commit", self.root(), "-m", &format!("value {value}")]);
        self.id("HEAD")
    }
    fn id(&self, revision: &str) -> String {
        ok(&["rev-parse", self.root(), revision])
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(args)
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
#[test]
fn ordinals_and_commit_peeling_compose_with_real_parent_edges_and_object_paths() {
    let t = Temp::new();
    let first = t.commit(1);
    let second = t.commit(2);
    let third = t.commit(3);
    for (revision, expected) in [
        ("@", &third),
        ("HEAD@{0}", &third),
        ("@{1}", &second),
        ("main@{2}", &first),
        ("refs/heads/main@{1}~1", &first),
        ("HEAD^{commit}^{}~2", &first),
        ("@{0}^0^{object}", &third),
    ] {
        assert_eq!(t.id(revision), *expected, "{revision}");
    }
    assert_eq!(ok(&["cat-file", t.root(), "-t", "main@{1}:a.wasm"]), "wasm");
    let old: Value = serde_json::from_str(&ok(&["log", t.root(), "@{1}^{commit}"])).unwrap();
    assert_eq!(old.as_array().unwrap().len(), 2);
    assert_eq!(ok(&["rev-list", t.root(), "HEAD^!"]), third);
    assert_eq!(
        ok(&["rev-list", t.root(), "HEAD^@"]),
        format!("{second}\n{first}")
    );
    assert_eq!(ok(&["rev-list", t.root(), "HEAD^-"]), third);
    assert!(!run(&["rev-list", t.root(), "HEAD^-2"]).status.success());
    let tree = ok(&["write-tree", t.root()]);
    let merge = ok(&[
        "commit-tree",
        t.root(),
        &tree,
        "-p",
        &second,
        "-p",
        &first,
        "-m",
        "two real parent edges",
    ]);
    assert_eq!(
        ok(&["rev-list", t.root(), &format!("{merge}^-2")]),
        format!("{merge}\n{second}")
    );
    assert_eq!(ok(&["rev-list", t.root(), &format!("{first}^@")]), "");
    let index = fs::read(t.0.join(".uwgit/index")).unwrap();
    let log = fs::read(t.0.join(".uwgit/reflog")).unwrap();
    for revision in [
        "HEAD@{3}",
        "HEAD@{18446744073709551616}",
        "HEAD@{yesterday}",
        "HEAD^{tree}^{commit}",
        "HEAD^{blob}",
        "HEAD@{-1}",
        "@{-0}",
        "HEAD^-0",
    ] {
        assert!(
            !run(&["rev-parse", t.root(), revision]).status.success(),
            "{revision}"
        );
    }
    assert_eq!(fs::read(t.0.join(".uwgit/index")).unwrap(), index);
    assert_eq!(fs::read(t.0.join(".uwgit/reflog")).unwrap(), log);
}
#[test]
fn ordinal_history_resets_when_a_deleted_branch_name_is_recreated() {
    let t = Temp::new();
    let first = t.commit(1);
    let second = t.commit(2);
    ok(&["branch", t.root(), "topic", &first]);
    ok(&["update-ref", t.root(), "refs/heads/topic", &second, &first]);
    assert_eq!(t.id("topic@{1}"), first);
    ok(&["branch", t.root(), "-D", "topic"]);
    ok(&["branch", t.root(), "topic", &second]);
    assert_eq!(t.id("topic@{0}"), second);
    assert!(!run(&["rev-parse", t.root(), "topic@{1}"]).status.success());
    ok(&["tag", t.root(), "topic", &first]);
    assert!(!run(&["rev-parse", t.root(), "topic@{0}"]).status.success());
    assert_eq!(t.id("refs/heads/topic@{0}"), second);
    assert_eq!(t.id("refs/tags/topic@{0}"), first);
}
#[test]
fn previous_checkout_uses_the_previous_branch_current_tip_and_switch_dash_roundtrips() {
    let t = Temp::new();
    let first = t.commit(1);
    ok(&["switch", t.root(), "-c", "topic"]);
    let topic = t.commit(2);
    ok(&["switch", t.root(), "main"]);
    let main = t.commit(3);
    assert_eq!(t.id("@{-1}"), topic);
    assert_eq!(t.id("@{-2}"), main);
    assert_eq!(t.id("@{-1}~1"), first);
    ok(&["switch", t.root(), "-"]);
    assert_eq!(t.id("HEAD"), topic);
    ok(&["checkout", t.root(), "main"]);
    assert_eq!(t.id("HEAD"), main);
    ok(&["fsck", t.root()]);
}
