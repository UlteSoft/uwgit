//! A reproducible seed producer. It compiles WAT, never executes Wasm.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[derive(Serialize)]
struct Seed {
    name: String,
    file: String,
    bytes: usize,
    sha256: String,
    old_hex: String,
    new_hex: String,
    old_sha256: String,
    new_sha256: String,
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let output = PathBuf::from(args.next().expect("seed directory required"));
    let report = PathBuf::from(args.next().expect("report path required"));
    assert!(args.next().is_none(), "unexpected argument");
    fs::create_dir(&output).expect("seed directory must be new");
    assert!(!report.exists(), "report path must be new");

    let texts = [
        ("empty", "(module)"),
        ("mvp", "(module (func (export \"run\") (param i32) (result i32) local.get 0 i32.const 17 i32.add))"),
        ("multi-value", "(module (func (result i32 i64) i32.const 1 i64.const 2))"),
        ("sign-extension", "(module (func (result i32) i32.const 255 i32.extend8_s))"),
        ("saturating-conversion", "(module (func (result i32) f32.const 1 i32.trunc_sat_f32_s))"),
        ("reference-types", "(module (func (param externref) (result externref) local.get 0))"),
        ("simd-immediates", "(module (memory 1) (func v128.const i8x16 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 drop i32.const 0 v128.load offset=16 drop i32.const 79225 drop))"),
        ("simd-shuffle-lane", "(module (func v128.const i32x4 0 0 0 0 v128.const i32x4 1 1 1 1 i8x16.shuffle 31 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 i8x16.extract_lane_s 15 drop i32.const 79225 drop))"),
        ("bulk-memory", "(module (memory 1) (data $d \"x\") (func i32.const 0 i32.const 0 i32.const 1 memory.init $d))"),
        ("gc-rec-subtypes", "(module (rec (type $p (sub (struct (field i32)))) (type $c (sub $p (struct (field i32) (field i64))))))"),
        ("gc-operators", "(module (type $s (struct (field i32))) (type $a (array (mut i8))) (func struct.new_default $s drop i32.const 0 array.new_default $a drop i32.const 79225 drop))"),
        ("typed-reference", "(module (type $f (func)) (func $f (type $f)) (elem declare func $f) (func ref.func $f call_ref $f))"),
        ("exceptions", "(module (tag $e) (func (block $b (try_table (catch $e $b) throw $e)) i32.const 79225 drop))"),
        ("exception-ref-type", "(module (func (param exnref)))"),
        ("tail-call", "(module (func $f) (func return_call $f i32.const 79225 drop))"),
        ("multi-memory", "(module (memory 1) (memory 1) (func i32.const 0 i32.load 1 drop))"),
        ("memory64", "(module (memory i64 1) (func i64.const 0 i32.load drop))"),
        ("table64", "(module (table i64 1 funcref) (func i64.const 0 table.get drop))"),
        ("extended-const", "(module (global i32 i32.const 1 i32.const 2 i32.add))"),
        ("relaxed-simd", "(module (func (param v128 v128) (result v128) local.get 0 local.get 1 i8x16.relaxed_swizzle))"),
        ("threads-extra", "(module (memory 1 1 shared) (func (result i32) i32.const 0 i32.atomic.load))"),
        ("legacy-eh-extra", "(module (tag $e) (func try throw $e catch $e end))"),
        ("stack-switching-extra", "(module (type $f (func)) (type $c (cont $f)) (func $f (type $f)) (elem declare func $f) (func ref.func $f cont.new $c drop))"),
        ("imports-data", "(module (import \"arbitrary.host\" \"f\" (func $f)) (memory 1) (data (i32.const 0) \"\\00\\ffname\") (func call $f))"),
        ("all-sections", "(module (type $f (func)) (import \"host\" \"f\" (func $host (type $f))) (table 1 funcref) (memory 1) (tag $e (param i32)) (global (mut i32) (i32.const 0)) (func $start (type $f) i32.const 0 i32.const 0 i32.const 0 memory.init $d) (export \"run\" (func $start)) (start $start) (elem (i32.const 0) func $host) (data $d \"x\"))"),
    ];
    let mut modules = Vec::new();
    for (name, text) in texts {
        let bytes = wat::parse_str(text).unwrap_or_else(|error| panic!("{name}: {error}\n{text}"));
        modules.push((name.to_owned(), bytes));
    }
    for (name, bytes) in [
        ("bare-concrete-ref", "0061736d0100000001080260000060010000"),
        (
            "explicit-concrete-ref",
            "0061736d010000000109026000006001630000",
        ),
        (
            "missing-function-end",
            "0061736d01000000010401600000030201000a0401020001",
        ),
        (
            "unknown-opcode",
            "0061736d01000000010401600000030201000a07010500ff41010b",
        ),
        ("truncated-section", "0061736d01000000018080"),
        ("noncanonical-leb", "0061736d010000000082000178"),
        (
            "malformed-name-convention",
            "0061736d010000000009046e616d6501028000",
        ),
        (
            "bad-table-memory64",
            "0061736d0100000001040160000003020100040301700805030104000a0a01080042002802001a0b",
        ),
        ("overflow-count", "0061736d010000000106ffffffff0f00"),
    ] {
        modules.push((name.to_owned(), unhex(bytes)));
    }
    for id in [14, 127, 128, 255] {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(&[id, 3, 0xff, 0, 0x80, 0, 2, 1, b'x']);
        modules.push((format!("unknown-section-{id}"), bytes));
    }

    let mut records = Vec::new();
    let mut emit = |name: String, old: &[u8], new: &[u8]| {
        assert!(old.starts_with(HEADER) && new.starts_with(HEADER));
        let split = u16::try_from(old.len() - 8).unwrap();
        let mut input = split.to_le_bytes().to_vec();
        input.extend_from_slice(&old[8..]);
        input.extend_from_slice(&new[8..]);
        assert!(input.len() <= 4096, "oversized seed: {name}");
        let file = format!("{:03}-{name}", records.len());
        fs::write(output.join(&file), &input).unwrap();
        records.push(Seed {
            name,
            file,
            bytes: input.len(),
            sha256: sha256(&input),
            old_hex: hex(old),
            new_hex: hex(new),
            old_sha256: sha256(old),
            new_sha256: sha256(new),
        });
    };
    for (name, bytes) in &modules {
        emit(format!("{name}-identity"), bytes, bytes);
        let mut changed = bytes.clone();
        changed.extend_from_slice(&[0, 3, 1, b'x', 0xff]);
        emit(format!("{name}-custom-append"), bytes, &changed);
        emit(format!("{name}-insert"), HEADER, bytes);
        emit(format!("{name}-delete"), bytes, HEADER);
    }
    // Neither side is derived from the other; repeated-byte alignments admit
    // several equally minimal scripts. The target checks cost, not alignment.
    emit(
        "independent-payloads".into(),
        &unhex("0061736d010000000003017841017f00"),
        &unhex("0061736d0100000000040178ffff"),
    );
    emit(
        "repeated-byte-alignment".into(),
        &unhex("0061736d01000000000401780000"),
        &unhex("0061736d0100000000050178000000"),
    );

    let document = serde_json::json!({
        "format": 1,
        "input_format": "u16le split followed by old/new payloads; each receives a fixed Core header",
        "max_input": 4096,
        "modules": modules.len(),
        "seeds": records,
    });
    fs::write(report, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    println!(
        "generated {} seeds from {} modules",
        document["seeds"].as_array().unwrap().len(),
        modules.len()
    );
}
