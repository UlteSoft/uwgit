//! Deterministic raw-byte mutation properties. These tests never execute Wasm.
//!
//! Every changed byte after the immutable Core encoding header must be reported
//! and survive a serialized patch roundtrip, even if framing/validation breaks.
//! Header mutations are tested separately as explicit out-of-scope rejections.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use wasm_git::audit::{self, AuditModule, Region, Span};
use wasm_git::patch::{self, BytePatch};
use wasm_git::standard::Standard;

const SEED: u64 = 0x7577_6769_742d_7631;
const HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let mut fixtures: Vec<_> = [
        ("mvp", "(module (func (export \"run\") (param i32) (result i32) local.get 0 i32.const 17 i32.add))"),
        ("simd-immediates", "(module (memory 1) (func v128.const i8x16 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 drop i32.const 0 v128.load offset=16 drop))"),
        ("gc-eh", "(module (type $s (struct (field i32))) (tag $e) (func struct.new_default $s drop (block $caught (try_table (catch $e $caught) throw $e)) i32.const 7 drop))"),
        ("imports-data", "(module (import \"arbitrary.host\" \"f\" (func $f)) (memory 1) (data (i32.const 0) \"\\00\\ffname\") (func call $f))"),
    ].into_iter().map(|(name, wat)| (name, wat::parse_str(wat).unwrap())).collect();
    fixtures.push((
        "opaque-custom",
        [
            HEADER.as_slice(),
            &[0, 9, 4, b'n', b'a', b'm', b'e', 1, 2, 0x80, 0],
        ]
        .concat(),
    ));
    fixtures.push((
        "unknown-opcode",
        [
            HEADER.as_slice(),
            &[
                1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 10, 7, 1, 5, 0, 0xff, 0x41, 1, 0x0b,
            ],
        ]
        .concat(),
    ));
    fixtures.push((
        "future-section",
        [HEADER.as_slice(), &[14, 3, 0xff, 0, 0x80, 0, 2, 1, b'x']].concat(),
    ));
    fixtures.push((
        "truncated-section",
        [HEADER.as_slice(), &[1, 0x80, 0x80]].concat(),
    ));
    fixtures.push((
        "noncanonical-leb",
        [HEADER.as_slice(), &[0, 0x82, 0, 1, b'x']].concat(),
    ));
    fixtures
}

fn valid_span(span: Span, len: usize) -> bool {
    span.start <= span.end && span.end <= len
}

fn region_bounds(region: &Region, len: usize) -> bool {
    valid_span(region.span, len)
        && region
            .children
            .iter()
            .all(|child| region_bounds(child, len))
}

fn check_module(module: &AuditModule, bytes: &[u8]) -> Result<(), String> {
    if module.byte_len != bytes.len() {
        return Err("wrong audit byte length".into());
    }
    for section in &module.sections {
        if ![section.span, section.header_span, section.payload_span]
            .into_iter()
            .all(|span| valid_span(span, bytes.len()))
            || !section
                .regions
                .iter()
                .all(|region| region_bounds(region, bytes.len()))
        {
            return Err(format!("out-of-bounds section/region: {}", section.path));
        }
    }
    for diagnostic in &module.diagnostics {
        if diagnostic.offset > bytes.len() {
            return Err(format!("out-of-bounds diagnostic: {diagnostic:?}"));
        }
    }
    for evidence in &module.standard.evidence {
        if !valid_span(evidence.span, bytes.len())
            || evidence.raw_hex != hex(&bytes[evidence.span.start..evidence.span.end])
        {
            return Err(format!("invalid standard evidence: {evidence:?}"));
        }
    }
    Ok(())
}

fn check_case(old: &[u8], new: &[u8]) -> Result<(), String> {
    if old == new || !old.starts_with(HEADER) || !new.starts_with(HEADER) {
        return Err("mutation harness must supply different Core-header byte strings".into());
    }
    let mut physical = None;
    for standard in PROFILES {
        let report = audit::compare_with_standard(old, new, standard)?;
        if !report.changed || report.edits.is_empty() {
            return Err(format!("mutation disappeared under {standard}"));
        }
        check_module(&report.old, old)?;
        check_module(&report.new, new)?;
        let value = serde_json::to_vec(&report.edits).map_err(|error| error.to_string())?;
        if let Some(expected) = &physical {
            if expected != &value {
                return Err(format!("profile changed physical edits under {standard}"));
            }
        } else {
            physical = Some(value);
        }
        let mut rebuilt = Vec::new();
        let mut old_cursor = 0;
        let mut new_cursor = 0;
        for edit in &report.edits {
            if !valid_span(edit.old_span, old.len())
                || !valid_span(edit.new_span, new.len())
                || edit.old_span.start < old_cursor
                || edit.new_span.start < new_cursor
            {
                return Err("out-of-bounds, unsorted or overlapping physical edits".into());
            }
            if old[old_cursor..edit.old_span.start] != new[new_cursor..edit.new_span.start]
                || edit.old_hex != hex(&old[edit.old_span.start..edit.old_span.end])
                || edit.new_hex != hex(&new[edit.new_span.start..edit.new_span.end])
            {
                return Err("physical edit lost byte evidence or an unchanged gap".into());
            }
            for context in &edit.old_context {
                if !valid_span(context.span, old.len()) {
                    return Err("old context out of bounds".into());
                }
            }
            for context in &edit.new_context {
                if !valid_span(context.span, new.len()) {
                    return Err("new context out of bounds".into());
                }
            }
            rebuilt.extend_from_slice(&old[old_cursor..edit.old_span.start]);
            rebuilt.extend_from_slice(&new[edit.new_span.start..edit.new_span.end]);
            old_cursor = edit.old_span.end;
            new_cursor = edit.new_span.end;
        }
        if old[old_cursor..] != new[new_cursor..] {
            return Err("unreported changed tail".into());
        }
        rebuilt.extend_from_slice(&old[old_cursor..]);
        if rebuilt != new {
            return Err("physical edit replay mismatch".into());
        }
    }
    let encoded = patch::create(old, new)?.to_bytes()?;
    let decoded = BytePatch::from_bytes(&encoded)?;
    if decoded.to_bytes()? != encoded || decoded.apply(old)? != new {
        return Err("serialized patch replay mismatch".into());
    }
    // Reversing the raw inputs must also be a replayable, complete edit.
    let reverse = patch::create(new, old)?.to_bytes()?;
    if BytePatch::from_bytes(&reverse)?.apply(new)? != old {
        return Err("reverse patch replay mismatch".into());
    }
    Ok(())
}

fn exercise_mutations(
    mut visit: impl FnMut(&str, &str, &[u8], &[u8]),
    exhaustive_insertions: bool,
) {
    for (label, old) in fixtures() {
        for position in 8..old.len() {
            for bit in 0..8 {
                let mut new = old.clone();
                new[position] ^= 1 << bit;
                visit(label, &format!("bit:{position}:{bit}"), &old, &new);
            }
            let mut new = old.clone();
            new.remove(position);
            visit(label, &format!("delete:{position}"), &old, &new);
        }
        let insertion_values: &[u8] = if exhaustive_insertions {
            &[0, 1, 0x0b, 0x41, 0x7f, 0x80, 0xff]
        } else {
            &[0, 0xff]
        };
        for position in 8..=old.len() {
            for value in insertion_values {
                let mut new = old.clone();
                new.insert(position, *value);
                visit(label, &format!("insert:{position}:{value:02x}"), &old, &new);
            }
        }
    }
}

#[test]
fn every_payload_bit_and_single_byte_insertion_deletion_is_audited_and_replayed() {
    let mut cases = 0usize;
    exercise_mutations(
        |label, mutation, old, new| {
            check_case(old, new).unwrap_or_else(|error| {
                panic!(
                    "{label}/{mutation}: {error}\nold={}\nnew={}",
                    hex(old),
                    hex(new)
                )
            });
            cases += 1;
        },
        false,
    );
    assert!(
        cases > 2_000,
        "fixture breadth unexpectedly shrank: {cases}"
    );
}

#[test]
fn encoding_header_mutations_are_explicit_rejections_not_unchanged_core_modules() {
    let old = &fixtures()[0].1;
    for position in 0..8 {
        for bit in 0..8 {
            let mut new = old.clone();
            new[position] ^= 1 << bit;
            for standard in PROFILES {
                assert!(audit::inspect_with_standard(&new, standard).is_err());
                assert!(audit::compare_with_standard(old, &new, standard).is_err());
            }
            assert!(patch::create(old, &new).is_err());
        }
        let mut deleted = old.clone();
        deleted.remove(position);
        assert!(audit::inspect(&deleted).is_err());
        assert!(patch::create(old, &deleted).is_err());
        let mut inserted = old.clone();
        inserted.insert(position, 0xff);
        assert!(audit::inspect(&inserted).is_err());
        assert!(patch::create(old, &inserted).is_err());
    }
}

struct Random(u64);
impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

#[derive(Serialize)]
struct Receipt<'a> {
    case: usize,
    fixture: &'a str,
    mutation: &'a str,
    seed: String,
    old_sha256: String,
    new_sha256: String,
    old_hex: String,
    new_hex: String,
    status: &'static str,
    error: Option<&'a str>,
}

struct Evidence {
    dir: PathBuf,
    writer: BufWriter<File>,
    cases: usize,
}

impl Evidence {
    fn new() -> Self {
        let dir = std::env::var_os("UWGIT_AUDIT_FUZZ_REPORT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new("/tmp").join(format!("uwgit-audit-fuzz-{}", std::process::id()))
            });
        assert!(
            dir.is_absolute()
                && dir.starts_with("/tmp")
                && !dir
                    .components()
                    .any(|part| matches!(part, Component::ParentDir)),
            "fuzz evidence must remain under /tmp"
        );
        fs::create_dir_all(&dir).unwrap();
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(dir.join("cases.jsonl"))
            .expect("use a fresh evidence directory; retain receipts from previous runs");
        Self {
            dir,
            writer: BufWriter::new(file),
            cases: 0,
        }
    }
    fn case(&mut self, label: &str, mutation: &str, old: &[u8], new: &[u8]) {
        let result = std::panic::catch_unwind(|| check_case(old, new)).unwrap_or_else(|panic| {
            let detail = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            Err(format!("audit/patch panicked: {detail}"))
        });
        let receipt = Receipt {
            case: self.cases,
            fixture: label,
            mutation,
            seed: format!("{SEED:016x}"),
            old_sha256: sha256(old),
            new_sha256: sha256(new),
            old_hex: hex(old),
            new_hex: hex(new),
            status: if result.is_ok() { "PASS" } else { "FAIL" },
            error: result.as_ref().err().map(String::as_str),
        };
        serde_json::to_writer(&mut self.writer, &receipt).unwrap();
        writeln!(self.writer).unwrap();
        self.cases += 1;
        if let Err(error) = result {
            self.writer.flush().unwrap();
            self.summary("FAIL");
            panic!(
                "{label}/{mutation}: {error}; replay receipt in {}",
                self.dir.display()
            );
        }
    }
    fn summary(&mut self, status: &str) {
        self.writer.flush().unwrap();
        let receipts = fs::read(self.dir.join("cases.jsonl")).unwrap();
        let summary = serde_json::json!({"schema_version":1,"status":status,"seed":format!("{SEED:016x}"),"cases":self.cases,"profiles":["core1","core2","core3","all-known"],"receipts":"cases.jsonl","receipts_sha256":sha256(&receipts),"interpretation":"Changed Core-header payload bytes; every profile must report identical physical edits, bounded evidence, and exact forward/reverse serialized patch replay. Header mutations are separately checked as out-of-scope rejections. No Wasm is executed."});
        fs::write(
            self.dir.join("summary.json"),
            serde_json::to_vec_pretty(&summary).unwrap(),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "extended deterministic byte fuzz; run explicitly in the existing SSH Linux cgroup"]
fn deterministic_extended_byte_fuzz_with_replay_receipts() {
    let mut evidence = Evidence::new();
    exercise_mutations(
        |label, mutation, old, new| evidence.case(label, mutation, old, new),
        true,
    );
    let random_cases = std::env::var("UWGIT_AUDIT_FUZZ_CASES")
        .map(|value| {
            value
                .parse::<usize>()
                .expect("UWGIT_AUDIT_FUZZ_CASES must be an integer")
        })
        .unwrap_or(10_000);
    assert!(
        random_cases <= 1_000_000,
        "explicit bounded fuzz run required"
    );
    let seeds = fixtures();
    let mut random = Random(SEED);
    for iteration in 0..random_cases {
        let (label, old) = &seeds[random.below(seeds.len())];
        let mut new = old.clone();
        for _ in 0..1 + random.below(8) {
            let position = 8 + random.below(new.len() - 7);
            match random.below(4) {
                0 if position < new.len() => {
                    new[position] ^= 1 << random.below(8);
                }
                1 if position < new.len() => {
                    new.remove(position);
                }
                2 => {
                    new.insert(position, random.next() as u8);
                }
                _ => {
                    new.extend_from_slice(&random.next().to_le_bytes()[..1 + random.below(8)]);
                }
            }
        }
        if new == *old {
            new.push(0);
        }
        evidence.case(label, &format!("random:{iteration}"), old, &new);
    }
    evidence.summary("PASS");
    eprintln!(
        "fuzz cases={} seed={SEED:016x} evidence={}",
        evidence.cases,
        evidence.dir.display()
    );
}
