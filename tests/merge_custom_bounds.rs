//! Fixed three-way custom-name length boundaries; no generated input search.
//! CLI repositories and checkouts stay in /tmp. No Wasm guest is executed.
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::{audit, merge};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const INVALID: [&str; 3] = [
    "0061736d010000000005ffffffff0f",
    "0061736d010000000005feffffff0f",
    "0061736d010000000005fdffffff0f",
];
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unhex(encoded: &str) -> Vec<u8> {
    let (pairs, rest) = encoded.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unsigned(mut value: usize, bytes: &mut Vec<u8>) {
    loop {
        let byte = value as u8 & 0x7f;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}

fn custom(bytes: &mut Vec<u8>, encoded_name: &[u8], payload: u8) {
    bytes.push(0);
    unsigned(encoded_name.len() + 1, bytes);
    bytes.extend_from_slice(encoded_name);
    bytes.push(payload);
}

fn named_pair(names: &[Vec<u8>; 2], first: u8, second: u8) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    custom(&mut bytes, &names[0], first);
    custom(&mut bytes, &names[1], second);
    bytes
}

fn legal_names(long: bool) -> [Vec<u8>; 2] {
    if long {
        let mut ascii = vec![0xa1, 0x8d, 6]; // 100,001 bytes.
        ascii.extend_from_slice("n".repeat(100_001).as_bytes());
        let mut unicode = vec![0xa4, 0x8d, 6]; // 100,004 bytes of UTF-8 and NUL.
        unicode.extend_from_slice("人\0".repeat(25_001).as_bytes());
        [ascii, unicode]
    } else {
        // Legal padded u32 length and a distinct UTF-8/NUL name.
        [
            vec![0x81, 0x80, 0x80, 0x80, 0, b'x'],
            vec![4, 0xe4, 0xba, 0xba, 0],
        ]
    }
}

fn identity_conflict(base: &[u8], ours: &[u8], theirs: &[u8]) {
    // All inputs differ, so this must reach concurrent section correspondence.
    assert!(base != ours && base != theirs && ours != theirs);
    let report = merge::merge(base, ours, theirs).unwrap();
    assert_eq!(report.status, "conflict");
    assert_eq!(report.validation, "not_synthesized");
    assert!(report.bytes.is_none() && report.framing_fixups.is_empty());
    assert_eq!(report.conflicts.len(), 1);
    let conflict = &report.conflicts[0];
    assert_eq!(conflict.path, "custom[0]");
    assert!(conflict.reason.contains("custom section identity"));
    assert!(conflict.reason.contains("cannot be decoded"));
    for (evidence, bytes) in [
        (&conflict.base, base),
        (&conflict.ours, ours),
        (&conflict.theirs, theirs),
    ] {
        assert_eq!(evidence.span.start, HEADER.len());
        assert_eq!(evidence.span.end, bytes.len());
        assert_eq!(evidence.hex, hex(&bytes[HEADER.len()..]));
    }
}

#[test]
fn max_custom_name_lengths_conflict_in_every_three_way_position_without_panicking() {
    let inputs = INVALID.map(unhex);
    // Three fixed rotations, not a mutation or permutation search.
    for [base, ours, theirs] in [[0, 1, 2], [1, 2, 0], [2, 0, 1]] {
        identity_conflict(&inputs[base], &inputs[ours], &inputs[theirs]);
    }
    for bytes in &inputs {
        let module = audit::inspect(bytes).unwrap();
        assert_eq!(module.sections[0].status, "malformed");
        assert_eq!(
            module.sections[0].standard_support.status,
            "invalid_encoding"
        );
        // An exact whole-file selection remains a byte-preserving operation.
        let report = merge::merge(HEADER, bytes, HEADER).unwrap();
        assert_eq!(report.status, "clean");
        assert_eq!(report.validation, "failed_or_unsupported");
        assert_eq!(report.bytes.unwrap(), *bytes);
    }
}

#[test]
fn unreadable_custom_name_on_either_branch_is_not_a_section_identity() {
    let base = unhex("0061736d010000000003017801");
    let changed = unhex("0061736d010000000003017802");
    for invalid in INVALID.map(unhex).into_iter().chain([
        unhex("0061736d01000000000180"),
        unhex("0061736d01000000000201ff"),
        unhex("0061736d0100000000020261"),
    ]) {
        identity_conflict(&base, &invalid, &changed);
        identity_conflict(&base, &changed, &invalid);
    }
}

#[test]
fn ordinary_and_long_complete_names_still_select_original_sections_atomically() {
    for long in [false, true] {
        let names = legal_names(long);
        let base = named_pair(&names, 1, 2);
        let ours = named_pair(&names, 3, 2);
        let theirs = named_pair(&names, 1, 4);
        let expected = named_pair(&names, 3, 4);
        for (left, right) in [(&ours, &theirs), (&theirs, &ours)] {
            let report = merge::merge(&base, left, right).unwrap();
            assert_eq!(report.status, "clean");
            assert_eq!(report.validation, "valid_with_all_known_features");
            assert!(report.conflicts.is_empty() && report.framing_fixups.is_empty());
            assert_eq!(report.bytes.unwrap(), expected);
        }
        let module = audit::inspect(&expected).unwrap();
        assert_eq!(module.standard.validation, "valid");
        assert_eq!(
            module.standard.validator_input.projections.len(),
            if long { 2 } else { 0 }
        );
        for (section, encoded_name) in module.sections.iter().zip(&names) {
            let start = section.payload_span.start;
            assert_eq!(&expected[start..start + encoded_name.len()], encoded_name);
        }
    }
}

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-merge-custom-bounds-{}-{}",
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

fn commit(repo: &str, input: &str, bytes: &[u8], message: &str) -> String {
    std::fs::write(input, bytes).unwrap();
    success(&["commit", repo, input, "-m", message])
        .split_whitespace()
        .last()
        .unwrap()
        .to_owned()
}

fn store_snapshot(repo: &str) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), result);
            } else {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let root = Path::new(repo).join(".uwgit");
    let mut result = BTreeMap::new();
    visit(&root, &root, &mut result);
    result
}

#[test]
fn cli_merge_reports_custom_length_conflicts_and_preserves_legal_name_bytes() {
    let invalid = INVALID.map(unhex);
    let mut cases = vec![(
        invalid[0].clone(),
        invalid[1].clone(),
        invalid[2].clone(),
        None,
    )];
    for long in [false, true] {
        let names = legal_names(long);
        cases.push((
            named_pair(&names, 1, 2),
            named_pair(&names, 3, 2),
            named_pair(&names, 1, 4),
            Some(named_pair(&names, 3, 4)),
        ));
    }
    for (base, ours, theirs, expected) in cases {
        let temp = Temp::new();
        let repo = temp.path("repo");
        let input = temp.path("input.wasm");
        success(&["init", &repo]);
        let base_id = commit(&repo, &input, &base, "base");
        success(&["branch", &repo, "right", &base_id]);
        let ours_id = commit(&repo, &input, &ours, "ours");
        success(&["switch", &repo, "right"]);
        let theirs_id = commit(&repo, &input, &theirs, "theirs");
        success(&["switch", &repo, "main"]);
        let before = store_snapshot(&repo);
        let output = invoke(&["merge", &repo, &theirs_id, "-m", "combine"]);
        assert_eq!(
            output.status.code(),
            Some(if expected.is_some() { 0 } else { 2 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["old_head"], ours_id);
        assert_eq!(report["target"], theirs_id);
        if let Some(expected) = expected {
            assert_eq!(report["status"], "merged");
            assert_eq!(
                report["report"]["validation"],
                "valid_with_all_known_features"
            );
            let checkout = temp.path("merged.wasm");
            success(&["checkout", &repo, "HEAD", &checkout]);
            assert_eq!(std::fs::read(checkout).unwrap(), expected);
        } else {
            assert_eq!(report["status"], "conflict");
            assert!(report["commit"].is_null());
            assert_eq!(report["report"]["conflicts"].as_array().unwrap().len(), 1);
            let conflict = &report["report"]["conflicts"][0];
            assert_eq!(conflict["path"], "custom[0]");
            assert!(conflict["reason"]
                .as_str()
                .unwrap()
                .contains("cannot be decoded"));
            for (side, bytes) in [("base", &base), ("ours", &ours), ("theirs", &theirs)] {
                assert_eq!(conflict[side]["span"]["start"], HEADER.len());
                assert_eq!(conflict[side]["span"]["end"], bytes.len());
                assert_eq!(conflict[side]["hex"], hex(&bytes[HEADER.len()..]));
            }
            assert_eq!(store_snapshot(&repo), before);
        }
        for (id, bytes, name) in [
            (&base_id, &base, "base.wasm"),
            (&ours_id, &ours, "ours.wasm"),
            (&theirs_id, &theirs, "theirs.wasm"),
        ] {
            let checkout = temp.path(name);
            success(&["checkout", &repo, id, &checkout]);
            assert_eq!(std::fs::read(checkout).unwrap(), *bytes);
        }
    }
}
