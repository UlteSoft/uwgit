//! One physical decoder, independently checked against three standard profiles.
//!
//! WAT is only an input producer: the profile oracle is wasmparser validation,
//! and instruction offsets are obtained independently from its binary reader.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_git::audit::{self, AuditModule, Region, Span};
use wasm_git::standard::Standard;
use wasmparser::{Operator, Parser, Payload, Validator, WasmFeatures};

const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];
const SENTINEL: i32 = 0x13579;

fn oracle_features(standard: Standard) -> WasmFeatures {
    match standard {
        Standard::Core1 => WasmFeatures::WASM1,
        Standard::Core2 => WasmFeatures::WASM2,
        // wasmparser 0.249's draft WASM3 constant also enables threads. Threads
        // are outside the published Core 3 profile selected by this API.
        Standard::Core3 => WasmFeatures::WASM3.difference(WasmFeatures::THREADS),
        Standard::AllKnown => WasmFeatures::all(),
    }
}

fn compile(source: &str) -> Vec<u8> {
    wat::parse_str(source).unwrap_or_else(|error| panic!("fixture WAT: {error}\n{source}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(region: &'a Region, out: &mut Vec<&'a Region>) {
        out.push(region);
        for child in &region.children {
            visit(child, out);
        }
    }
    let mut out = Vec::new();
    for section in &module.sections {
        for region in &section.regions {
            visit(region, &mut out);
        }
    }
    out
}

fn check_bounds(module: &AuditModule, bytes: &[u8]) {
    assert_eq!(module.byte_len, bytes.len());
    for section in &module.sections {
        for span in [section.span, section.header_span, section.payload_span] {
            assert!(
                span.start <= span.end && span.end <= bytes.len(),
                "{span:?}"
            );
        }
    }
    for region in regions(module) {
        assert!(
            region.span.start <= region.span.end && region.span.end <= bytes.len(),
            "{region:?}"
        );
    }
    for evidence in &module.standard.evidence {
        assert!(evidence.span.start <= evidence.span.end && evidence.span.end <= bytes.len());
        assert_eq!(
            evidence.raw_hex,
            hex(&bytes[evidence.span.start..evidence.span.end])
        );
        assert!(matches!(
            evidence.status.as_str(),
            "supported"
                | "recognized_but_disabled"
                | "unknown"
                | "invalid_encoding"
                | "invalid_semantics"
        ));
    }
    for diagnostic in &module.diagnostics {
        assert!(diagnostic.offset <= bytes.len(), "{diagnostic:?}");
    }
}

fn check_profiles(label: &str, bytes: &[u8], expected: [bool; 4]) {
    for (standard, valid) in PROFILES.into_iter().zip(expected) {
        let oracle = Validator::new_with_features(oracle_features(standard))
            .validate_all(bytes)
            .is_ok();
        assert_eq!(oracle, valid, "{label}: independent profile {standard}");
        assert_eq!(standard.features(), oracle_features(standard), "{standard}");
        let module = audit::inspect_with_standard(bytes, standard).unwrap();
        assert_eq!(
            module.standard.validation,
            if valid { "valid" } else { "invalid" },
            "{label}: {standard}"
        );
        check_bounds(&module, bytes);
        if !valid && expected[3] {
            assert!(
                module
                    .standard
                    .evidence
                    .iter()
                    .any(|item| item.status == "recognized_but_disabled"),
                "{label}: known disabled feature needs physical evidence under {standard}"
            );
        }
    }
}

#[test]
fn same_binary_has_explicit_core1_core2_core3_results() {
    let cases = [
        ("mvp", "(module (func (result i32) i32.const 1))", [true, true, true, true]),
        ("multi-value", "(module (type (func (result i32 i64))) (func (result i32 i64) i32.const 1 i64.const 2))", [false, true, true, true]),
        ("sign-extension", "(module (func (result i32) i32.const 255 i32.extend8_s))", [false, true, true, true]),
        ("saturating-conversion", "(module (func (result i32) f32.const 1 i32.trunc_sat_f32_s))", [false, true, true, true]),
        ("externref", "(module (type (func (param externref) (result externref))) (func (param externref) (result externref) local.get 0))", [false, true, true, true]),
        ("v128-type", "(module (type (func (param v128))) (func (param v128)))", [false, true, true, true]),
        ("bulk-memory", "(module (memory 1) (data $d \"x\") (func i32.const 0 i32.const 0 i32.const 1 memory.init $d))", [false, true, true, true]),
        ("gc-rec-subtypes", "(module (rec (type $parent (sub (struct (field i32)))) (type $child (sub $parent (struct (field i32) (field i64))))))", [false, false, true, true]),
        ("typed-reference", "(module (type $f (func)) (func $f (type $f)) (elem declare func $f) (func ref.func $f call_ref $f))", [false, false, true, true]),
        ("exception-reference-type", "(module (func (param exnref)))", [false, false, true, true]),
        ("tail-call", "(module (func $f) (func return_call $f))", [false, false, true, true]),
        ("multi-memory", "(module (memory 1) (memory 1))", [false, false, true, true]),
        ("memory64", "(module (memory i64 1))", [false, false, true, true]),
        ("extended-const", "(module (global i32 i32.const 1 i32.const 2 i32.add))", [false, false, true, true]),
        ("relaxed-simd", "(module (func (param v128 v128) (result v128) local.get 0 local.get 1 i8x16.relaxed_swizzle))", [false, false, true, true]),
        ("threads-extra", "(module (memory 1 1 shared) (func (result i32) i32.const 0 i32.atomic.load))", [false, false, false, true]),
        ("legacy-eh-extra", "(module (tag $e) (func try throw $e catch $e end))", [false, false, false, true]),
        ("stack-switching-extra", "(module (type $f (func)) (type $c (cont $f)) (func $target (type $f)) (elem declare func $target) (func ref.func $target cont.new $c drop))", [false, false, false, true]),
    ];
    for (label, source, expected) in cases {
        check_profiles(label, &compile(source), expected);
    }
}

#[test]
fn every_standard_section_is_framed_under_every_profile() {
    let mut bytes = compile(
        r#"(module
        (type $f (func))
        (import "host" "f" (func $host (type $f)))
        (table 1 funcref) (memory 1)
        (tag $exception (param i32))
        (global (mut i32) (i32.const 0))
        (func $start (type $f)
            i32.const 0 i32.const 0 i32.const 0 memory.init $bytes)
        (export "run" (func $start)) (start $start)
        (elem (i32.const 0) func $host)
        (data $bytes "x"))"#,
    );
    bytes.extend_from_slice(&[0, 5, 4, b'n', b'a', b'm', b'e']);
    check_profiles("all standard sections", &bytes, [false, false, true, true]);
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&bytes, standard).unwrap();
        let ids: BTreeSet<_> = module.sections.iter().map(|section| section.id).collect();
        assert_eq!(ids, (0..=13).collect(), "{standard}");
        assert!(module
            .sections
            .iter()
            .all(|section| section.status == "decoded"));
    }
}

fn independently_decoded_operators(bytes: &[u8]) -> Vec<(Span, String, bool)> {
    let mut out = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.unwrap() {
            let mut reader = body.get_operators_reader().unwrap();
            while !reader.eof() {
                let start = reader.original_position();
                let operator = reader.read().unwrap();
                let sentinel =
                    matches!(operator, Operator::I32Const { value } if value == SENTINEL);
                out.push((
                    Span {
                        start,
                        end: reader.original_position(),
                    },
                    format!("{operator:?}"),
                    sentinel,
                ));
            }
        }
    }
    out
}

#[test]
fn disabled_simd_immediates_do_not_hide_later_mvp_instructions() {
    let bytes = compile(
        r#"(module (memory 1)
        (func
            v128.const i8x16 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 drop
            v128.const i32x4 0 0 0 0 v128.const i32x4 1 1 1 1
            i8x16.shuffle 31 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 drop
            v128.const i32x4 0 0 0 0 i8x16.extract_lane_s 15 drop
            i32.const 0 v128.load offset=32 align=16 drop
            i32.const 0 v128.const i32x4 0 0 0 0 v128.load8_lane offset=7 15 drop
            i32.const 79225 drop)
        (func i32.const 79225 drop))"#,
    );
    check_profiles("SIMD immediates", &bytes, [false, true, true, true]);
    let module = audit::inspect_with_standard(&bytes, Standard::Core1).unwrap();
    let parsed = independently_decoded_operators(&bytes);
    let all_regions = regions(&module);
    for (span, description, _) in &parsed {
        assert!(
            all_regions
                .iter()
                .any(|item| item.span == *span && item.description == *description),
            "missing complete operator {description} at {span:?}"
        );
        if description.starts_with("V128") || description.starts_with("I8x16") {
            assert!(
                module
                    .standard
                    .evidence
                    .iter()
                    .any(|item| item.span == *span && item.status == "recognized_but_disabled"),
                "missing disabled SIMD evidence {description} at {span:?}"
            );
        }
    }
    assert_eq!(
        parsed.iter().filter(|(_, _, sentinel)| *sentinel).count(),
        2
    );
}

#[test]
fn gc_eh_and_tail_call_keep_exact_following_instruction_boundaries() {
    let cases = [
        (
            "GC",
            r#"(module (type $s (struct (field i32)))
            (func struct.new_default $s drop i32.const 79225 drop)
            (func i32.const 79225 drop))"#,
        ),
        (
            "EH",
            r#"(module (tag $e)
            (func (block $caught
                (try_table (catch $e $caught) throw $e)) i32.const 79225 drop)
            (func i32.const 79225 drop))"#,
        ),
        (
            "return_call",
            r#"(module (func $target)
            (func return_call $target i32.const 79225 drop)
            (func i32.const 79225 drop))"#,
        ),
    ];
    for (label, source) in cases {
        let bytes = compile(source);
        check_profiles(label, &bytes, [false, false, true, true]);
        for standard in [Standard::Core1, Standard::Core2] {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            let all_regions = regions(&module);
            let parsed = independently_decoded_operators(&bytes);
            for (span, description, _) in &parsed {
                assert!(
                    all_regions
                        .iter()
                        .any(|item| item.span == *span && item.description == *description),
                    "{label}/{standard}: {description} at {span:?}"
                );
            }
            assert_eq!(
                parsed.iter().filter(|(_, _, sentinel)| *sentinel).count(),
                2
            );
            assert!(!module
                .diagnostics
                .iter()
                .any(|item| item.code == "unknown_operator"));
        }
    }
}

fn section(id: u8, payload: &[u8], bytes: &mut Vec<u8>) {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    bytes.extend_from_slice(payload);
}

fn raw_bodies(first: &[u8]) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(1, &[1, 0x60, 0, 0], &mut bytes);
    section(3, &[2, 0, 0], &mut bytes);
    let second = [0, 0x41, 42, 0x1a, 0x0b];
    let mut payload = vec![2, first.len() as u8];
    payload.extend_from_slice(first);
    payload.push(second.len() as u8);
    payload.extend_from_slice(&second);
    section(10, &payload, &mut bytes);
    section(0, &[1, b'x', 0xaa], &mut bytes);
    bytes
}

#[test]
fn incomplete_or_overlong_function_expressions_have_local_structure_evidence() {
    for (first, suffix, raw) in [
        (&[0, 0x01][..], "expression_structure", ""),
        (&[0, 0x02, 0x40, 0x0b][..], "expression_structure", ""),
        (&[0, 0x0b, 0x01][..], "trailing_bytes", "01"),
    ] {
        let bytes = raw_bodies(first);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            check_bounds(&module, &bytes);
            assert_eq!(module.standard.validation, "invalid");
            let path = format!("code[0]/function[0]/{suffix}");
            let structure = module
                .standard
                .evidence
                .iter()
                .find(|entry| entry.path == path)
                .unwrap();
            assert_eq!(structure.status, "invalid_encoding");
            assert_eq!(structure.raw_hex, raw);
            assert!(module
                .diagnostics
                .iter()
                .any(|entry| entry.code == "expression_structure"));
            assert!(!module
                .diagnostics
                .iter()
                .any(|entry| entry.code == "unknown_operator"));
            assert!(!regions(&module)
                .iter()
                .any(|region| region.path == "code[0]/function[0]/opaque"));
            let all = regions(&module);
            let later = all
                .iter()
                .find(|region| region.path == "code[0]/function[1]/operator[0]")
                .unwrap();
            assert!(later.description.contains("42"));
            assert_eq!(later.standard_support.display, "instruction");
            assert!(module.sections.iter().any(|section| section.id == 0));
            if first == [0, 0x01] {
                let nop = all
                    .iter()
                    .find(|region| region.path == "code[0]/function[0]/operator[0]")
                    .unwrap();
                assert_eq!(nop.description, "Nop");
                assert_eq!(nop.standard_support.display, "instruction");
                assert_eq!(nop.span.end, structure.span.start);
                assert_eq!(structure.span.start, structure.span.end);
            }
        }
    }
}

#[test]
fn incomplete_constant_expressions_keep_only_their_proven_prefix_and_next_section() {
    for (id, payload, expression_path, expected_op) in [
        (
            6,
            vec![1, 0x7f, 0, 0x41, 0],
            "global[0]/entry[0]/init",
            "I32Const",
        ),
        (
            11,
            vec![1, 0, 0x41, 0],
            "data[0]/entry[0]/offset",
            "I32Const",
        ),
        (
            4,
            vec![1, 0x40, 0, 0x70, 0, 0, 0xd0, 0x70],
            "table[0]/entry[0]/init",
            "RefNull",
        ),
        (
            9,
            vec![1, 5, 0x70, 1, 0xd0, 0x70],
            "element[0]/entry[0]/item[0]",
            "RefNull",
        ),
    ] {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        if id == 11 {
            section(5, &[1, 0, 1], &mut bytes);
        }
        section(id, &payload, &mut bytes);
        let expression_end = bytes.len();
        section(0, &[1, b'x', 0xaa], &mut bytes);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            check_bounds(&module, &bytes);
            assert_eq!(module.standard.validation, "invalid");
            let all = regions(&module);
            let known_path = format!("{expression_path}/operator[0]");
            let known = all.iter().find(|region| region.path == known_path).unwrap();
            assert!(known.description.starts_with(expected_op));
            assert_eq!(known.span.end, expression_end);
            let error_path = format!("{expression_path}/expression_structure");
            let error = module
                .standard
                .evidence
                .iter()
                .find(|entry| entry.path == error_path)
                .unwrap();
            assert_eq!(error.status, "invalid_encoding");
            assert_eq!(
                error.span,
                Span {
                    start: expression_end,
                    end: expression_end
                }
            );
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.status == "unknown"));
            assert!(module
                .sections
                .iter()
                .any(|section| section.id == 0 && section.span.start == expression_end));
        }
    }
}

#[test]
fn completed_constant_expression_does_not_turn_trailing_payload_into_instructions() {
    let mut extra = b"\0asm\x01\0\0\0".to_vec();
    section(6, &[1, 0x7f, 0, 0x41, 0, 0x0b, 0x01], &mut extra);
    let extra_offset = extra.len() - 1;
    section(0, &[1, b'x'], &mut extra);
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&extra, standard).unwrap();
        check_bounds(&module, &extra);
        let error = module
            .standard
            .evidence
            .iter()
            .find(|entry| entry.path == "global[0]/trailing_bytes")
            .unwrap();
        assert_eq!(error.status, "invalid_encoding");
        assert_eq!(error.raw_hex, "01");
        assert_eq!(
            error.span,
            Span {
                start: extra_offset,
                end: extra_offset + 1
            }
        );
        assert!(!regions(&module)
            .iter()
            .any(|region| region.path.contains("/operator[") && region.span.start >= extra_offset));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "unknown"));
    }

    let mut data = b"\0asm\x01\0\0\0".to_vec();
    section(5, &[1, 0, 1], &mut data);
    // Offset expression is complete. The declared byte-vector length exceeds
    // the payload; 01 FF 0B are data, never Nop/unknown/End instructions.
    section(11, &[1, 0, 0x41, 0, 0x0b, 8, 0x01, 0xff, 0x0b], &mut data);
    let data_end = data.len();
    section(0, &[1, b'x'], &mut data);
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&data, standard).unwrap();
        assert_eq!(module.standard.validation, "invalid");
        check_bounds(&module, &data);
        assert!(!regions(&module).iter().any(
            |region| region.path.starts_with("data[0]/") && region.path.contains("/operator[")
        ));
        assert!(!module
            .diagnostics
            .iter()
            .any(|entry| entry.code == "unknown_operator"));
        assert!(module
            .sections
            .iter()
            .any(|section| section.id == 0 && section.span.start == data_end));
    }

    // ConstExpr's first End is the only proved recovery horizon even if an
    // illegal nested control structure left its root expression unclosed.
    let mut nested = b"\0asm\x01\0\0\0".to_vec();
    section(6, &[1, 0x7f, 0, 0x02, 0x40, 0x0b, 0x01, 0x0b], &mut nested);
    let inner_end = nested.len() - 2;
    section(0, &[1, b'x'], &mut nested);
    let module = audit::inspect_with_standard(&nested, Standard::Core3).unwrap();
    check_bounds(&module, &nested);
    assert!(module.standard.evidence.iter().any(|entry| entry.path
        == "global[0]/entry[0]/init/expression_structure"
        && entry.status == "invalid_encoding"
        && entry.span
            == Span {
                start: inner_end,
                end: inner_end
            }));
    assert!(module
        .standard
        .evidence
        .iter()
        .any(|entry| entry.path == "global[0]/entry[0]/undecoded"
            && entry.status == "unknown"
            && entry.raw_hex == "010b"));
    assert!(!regions(&module)
        .iter()
        .any(|region| region.path.contains("/operator[") && region.span.start >= inner_end));
}

fn raw_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn malformed_unrelated_index_spaces_do_not_erase_known_memory_or_table_types() {
    for (encoded, opcode) in [
        (
            "0061736d0100000001040160000003020100040301700805030104000a0a01080042002802001a0b",
            "I32Load",
        ),
        (
            "0061736d010000000104016000000302010005030104000605017f00ff0b0a0a01080042002802001a0b",
            "I32Load",
        ),
        (
            "0061736d0100000001040160000003020100040401700400050201100a08010600fc10001a0b",
            "TableSize",
        ),
        // A bad suffix in the same space must preserve its complete first entry.
        (
            "0061736d01000000010401600000030201000504020400100a0a01080042002802001a0b",
            "I32Load",
        ),
    ] {
        let mut bytes = raw_hex(encoded);
        section(0, &[1, b'x'], &mut bytes);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            check_bounds(&module, &bytes);
            assert_eq!(module.standard.validation, "invalid");
            let all = regions(&module);
            let operator = all
                .iter()
                .find(|region| {
                    region.path.contains("/operator[") && region.description.starts_with(opcode)
                })
                .unwrap();
            assert!(module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.path == operator.path && entry.feature == "memory64"));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.path == operator.path && entry.status == "unknown"));
            assert_eq!(
                operator.standard_support.display,
                if matches!(standard, Standard::Core1 | Standard::Core2) {
                    "binary"
                } else {
                    "instruction"
                }
            );
        }
    }
}

#[test]
fn malformed_import_suffix_preserves_known_prefix_but_later_declarations_get_no_guessed_index() {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(1, &[1, 0x60, 0, 0], &mut bytes);
    section(2, &[2, 1, b'm', 1, b'a', 2, 4, 0, 0xff], &mut bytes);
    section(3, &[2, 0, 0], &mut bytes);
    section(5, &[1, 4, 0], &mut bytes);
    section(
        10,
        &[
            2, 8, 0, 0x42, 0, 0x28, 2, 0, 0x1a, 0x0b, 9, 0, 0x42, 0, 0x28, 0x42, 1, 0, 0x1a, 0x0b,
        ],
        &mut bytes,
    );
    let module = audit::inspect_with_standard(&bytes, Standard::Core3).unwrap();
    check_bounds(&module, &bytes);
    let all = regions(&module);
    let first = all
        .iter()
        .find(|region| region.path == "code[0]/function[0]/operator[1]")
        .unwrap();
    let later = all
        .iter()
        .find(|region| region.path == "code[0]/function[1]/operator[1]")
        .unwrap();
    assert_eq!(first.standard_support.display, "instruction");
    assert!(first
        .standard_support
        .required_features
        .iter()
        .any(|feature| feature == "memory64"));
    assert_eq!(later.standard_support.status, "unknown");
    assert_eq!(later.standard_support.display, "binary");
    assert!(!module
        .diagnostics
        .iter()
        .any(|entry| entry.code == "unknown_operator"));
}

#[test]
fn malformed_global_suffix_keeps_prior_global_role_and_marks_later_indices_unproven() {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(5, &[1, 0, 1], &mut bytes);
    section(6, &[2, 0x7f, 0, 0x41, 0, 0x0b, 0x7a], &mut bytes);
    section(
        11,
        &[2, 0, 0x23, 0, 0x0b, 0, 0, 0x23, 1, 0x0b, 0],
        &mut bytes,
    );
    let module = audit::inspect_with_standard(&bytes, Standard::Core3).unwrap();
    check_bounds(&module, &bytes);
    let all = regions(&module);
    let known = all
        .iter()
        .find(|region| region.path == "data[0]/entry[0]/offset/operator[0]")
        .unwrap();
    assert_eq!(known.description, "GlobalGet { global_index: 0 }");
    assert_eq!(known.standard_support.display, "instruction");
    assert!(known
        .standard_support
        .required_features
        .iter()
        .any(|feature| feature == "gc"));
    let unproven = all
        .iter()
        .find(|region| region.path == "data[0]/entry[1]/offset/operator[0]")
        .unwrap();
    assert_eq!(unproven.description, "GlobalGet { global_index: 1 }");
    assert_eq!(unproven.standard_support.status, "unknown");
    assert_eq!(unproven.standard_support.display, "binary");
    assert!(!module
        .diagnostics
        .iter()
        .any(|entry| entry.code == "unknown_operator"));
}

#[test]
fn unknown_and_truncated_instructions_stop_only_their_own_framed_body() {
    let cases: &[(&str, &[u8], &str)] = &[
        (
            "unknown opcode",
            &[0, 0x01, 0xff, 0x41, 43, 0x1a, 0x0b],
            "unknown",
        ),
        (
            "unknown SIMD subopcode",
            &[0, 0xfd, 0xff, 0x7f, 0x41, 43, 0x1a, 0x0b],
            "unknown",
        ),
        (
            "unknown GC subopcode",
            &[0, 0xfb, 0xff, 0x7f, 0x41, 43, 0x1a, 0x0b],
            "unknown",
        ),
        (
            "truncated v128 immediate",
            &[0, 0xfd, 0x0c, 0, 0, 0x0b],
            "invalid_encoding",
        ),
        (
            "truncated i32 LEB",
            &[0, 0x41, 0x80, 0x80],
            "invalid_encoding",
        ),
        ("truncated call LEB", &[0, 0x10, 0x80], "invalid_encoding"),
    ];
    for (label, first, expected_status) in cases {
        let bytes = raw_bodies(first);
        check_profiles(label, &bytes, [false; 4]);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            let all_regions = regions(&module);
            assert!(
                all_regions
                    .iter()
                    .any(|region| region.path == "code[0]/function[1]/operator[0]"
                        && region.description.contains("42")),
                "{label}/{standard}: later function must still decode"
            );
            assert!(module
                .sections
                .iter()
                .any(|item| item.id == 0 && item.status == "opaque"));
            let opaque = all_regions
                .iter()
                .find(|region| region.path == "code[0]/function[0]/opaque")
                .unwrap_or_else(|| {
                    panic!("{label}/{standard}: unknown instruction tail must be opaque")
                });
            assert!(opaque.span.end - opaque.span.start >= 1);
            assert_eq!(
                opaque.standard_support.status, *expected_status,
                "{label}/{standard}"
            );
            assert!(module.standard.evidence.iter().any(|entry| {
                entry.path == opaque.path
                    && entry.span == opaque.span
                    && entry.status == *expected_status
                    && entry.raw_hex == hex(&bytes[opaque.span.start..opaque.span.end])
            }));
            assert!(
                !all_regions.iter().any(|region| region
                    .path
                    .starts_with("code[0]/function[0]/operator[")
                    && region.span.start >= opaque.span.start),
                "unknown tail cannot invent later boundaries"
            );
            assert!(
                !module.standard.evidence.iter().any(|item| item.status
                    == "recognized_but_disabled"
                    && item.span == opaque.span),
                "unknown/malformed is not a legal disabled instruction"
            );
        }
    }
}

#[test]
fn malformed_locals_do_not_mark_later_simd_body_supported_in_core1() {
    let mut bytes = compile(
        "(module (func (local i32)) (func v128.const i32x4 1 2 3 4 drop i32.const 79225 drop))",
    );
    let mut first_local_type = None;
    let mut second_body = None;
    let mut index = 0;
    for payload in Parser::new(0).parse_all(&bytes) {
        if let Payload::CodeSectionEntry(body) = payload.unwrap() {
            if index == 0 {
                let mut locals = body.get_locals_reader().unwrap();
                assert_eq!(locals.get_count(), 1);
                let start = locals.original_position();
                assert_eq!(locals.read().unwrap(), (1, wasmparser::ValType::I32));
                assert_eq!(locals.original_position(), start + 2);
                first_local_type = Some(start + 1);
            } else {
                second_body = Some(body.range());
            }
            index += 1;
        }
    }
    let second_body = second_body.unwrap();
    let expected: Vec<_> = independently_decoded_operators(&bytes)
        .into_iter()
        .filter(|(span, _, _)| second_body.contains(&span.start))
        .collect();
    let bad_offset = first_local_type.unwrap();
    // 0xff followed by End (0x0b) can be read as a positive s33 heap-type
    // index. The reserved negative abstract type -6 must fail locals decoding.
    bytes[bad_offset] = 0x7a;
    let module = audit::inspect_with_standard(&bytes, Standard::Core1).unwrap();
    assert_eq!(module.standard.validation, "invalid");
    check_bounds(&module, &bytes);
    let all_regions = regions(&module);
    let opaque = all_regions
        .iter()
        .find(|region| region.path == "code[0]/function[0]/opaque")
        .unwrap();
    assert!(opaque.span.start <= bad_offset && bad_offset < opaque.span.end);
    assert_eq!(opaque.standard_support.status, "unknown");
    for (span, description, sentinel) in expected {
        let region = all_regions
            .iter()
            .find(|region| region.span == span && region.description == description)
            .unwrap_or_else(|| panic!("later body lost {description} at {span:?}"));
        if description.starts_with("V128Const") {
            assert_eq!(region.standard_support.status, "recognized_but_disabled");
            assert_eq!(region.standard_support.display, "binary");
            assert!(module.standard.evidence.iter().any(|item| item.span == span
                && item.status == "recognized_but_disabled"
                && item.raw_hex == hex(&bytes[span.start..span.end])));
        } else if sentinel {
            assert_eq!(region.standard_support.status, "supported");
            assert_eq!(region.standard_support.display, "instruction");
        }
    }
}

#[test]
fn unknown_section_and_invalid_type_keep_later_sections_auditable() {
    for (label, first_id, first_payload) in [
        ("future section", 14, vec![0x41, 1, 0x0b]),
        ("unknown type", 1, vec![2, 0x60, 0, 0, 0xff]),
        ("malformed import kind", 2, vec![1, 1, b'm', 1, b'f', 0xff]),
    ] {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(first_id, &first_payload, &mut bytes);
        if first_id != 1 {
            section(1, &[1, 0x60, 0, 0], &mut bytes);
        }
        section(3, &[1, 0], &mut bytes);
        section(10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b], &mut bytes);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(module.standard.validation, "invalid", "{label}");
            check_bounds(&module, &bytes);
            assert!(
                regions(&module)
                    .iter()
                    .any(|item| item.path == "code[0]/function[0]/operator[0]"
                        && item.description.contains("42")),
                "{label}/{standard}: independent frame recovery"
            );
            let first = &module.sections[0];
            assert!(matches!(first.status.as_str(), "opaque" | "malformed"));
            assert_ne!(
                first.kind, "custom",
                "invalid standard sections stay standard sections"
            );
        }
    }
}

#[test]
fn malformed_name_convention_remains_opaque_custom_under_every_profile() {
    let mut bytes = raw_bodies(&[0, 0x0b]);
    section(0, &[4, b'n', b'a', b'm', b'e', 1, 2, 0x80, 0], &mut bytes);
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&bytes, standard).unwrap();
        assert_eq!(module.standard.validation, "valid");
        let custom = module.sections.last().unwrap();
        assert_eq!(custom.id, 0);
        assert_eq!(custom.status, "opaque");
        assert_eq!(custom.kind, "custom:name");
        check_bounds(&module, &bytes);
    }
}

#[test]
fn normalized_values_do_not_erase_newer_wire_encoding_requirements() {
    // These deliberately use long/explicit encodings whose decoded values can
    // equal older shorthand. Acceptance by a normalizing validator alone is
    // insufficient evidence that their original wire form belongs to Core 1.
    type WireCase<'a> = (&'a str, &'a [(u8, &'a [u8])], [bool; 4]);
    let cases: &[WireCase<'_>] = &[
        (
            "explicit data memory index zero",
            &[(5, &[1, 0, 1]), (11, &[1, 2, 0, 0x41, 0, 0x0b, 0])],
            [false, true, true, true],
        ),
        (
            "long nullable funcref table type",
            &[(4, &[1, 0x63, 0x70, 0, 1])],
            [false, false, true, true],
        ),
        (
            "explicit singleton recursion group",
            &[(1, &[1, 0x4e, 1, 0x60, 0, 0])],
            [false, false, true, true],
        ),
        (
            "explicit final subtype",
            &[(1, &[1, 0x4f, 0, 0x60, 0, 0])],
            [false, false, true, true],
        ),
        (
            "explicit nonfinal subtype",
            &[(1, &[1, 0x50, 0, 0x60, 0, 0])],
            [false, false, true, true],
        ),
        (
            "long nullable funcref function parameter",
            &[(1, &[1, 0x60, 1, 0x63, 0x70, 0])],
            [false, false, true, true],
        ),
        (
            "memory32 six-byte minimum zero",
            &[(5, &[1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0])],
            [false, false, true, true],
        ),
        (
            "table32 six-byte minimum zero",
            &[(4, &[1, 0x70, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0])],
            [false, false, true, true],
        ),
        (
            "memory32 six-byte maximum zero",
            &[(5, &[1, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0])],
            [false, false, true, true],
        ),
        (
            "memory32 six-byte memarg offset zero",
            &[
                (1, &[1, 0x60, 0, 0]),
                (3, &[1, 0]),
                (5, &[1, 0, 0]),
                (
                    10,
                    &[
                        1, 13, 0, 0x41, 0, 0x28, 2, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0x1a, 0x0b,
                    ],
                ),
            ],
            [false, false, true, true],
        ),
    ];
    for (label, sections, expected) in cases {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        for (id, payload) in *sections {
            section(*id, payload, &mut bytes);
        }
        Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .unwrap_or_else(|error| panic!("{label}: malformed fixture: {error}"));
        for (standard, valid) in PROFILES.into_iter().zip(*expected) {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(
                module.standard.validation,
                if valid { "valid" } else { "invalid" },
                "{label}/{standard}: wire format must be checked before its distinctions disappear"
            );
            if !valid {
                assert!(
                    module
                        .standard
                        .evidence
                        .iter()
                        .any(|item| item.status == "recognized_but_disabled"),
                    "{label}/{standard}: explicit encoding needs disabled physical evidence"
                );
            }
            check_bounds(&module, &bytes);
        }
    }
}

#[test]
fn overflowing_u64_limit_is_malformed_under_every_profile() {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(
        5,
        &[
            1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ],
        &mut bytes,
    );
    section(0, &[1, b'x', 42], &mut bytes);
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&bytes, standard).unwrap();
        assert_eq!(module.standard.validation, "invalid");
        assert_eq!(module.sections[0].status, "malformed");
        assert_eq!(module.sections[1].id, 0);
        assert_eq!(module.sections[1].status, "opaque");
        check_bounds(&module, &bytes);
    }
}

#[test]
fn element_expression_reference_wire_form_is_not_erased_by_normalization() {
    let mut shorthand = b"\0asm\x01\0\0\0".to_vec();
    section(9, &[1, 5, 0x70, 0], &mut shorthand);
    let mut explicit = b"\0asm\x01\0\0\0".to_vec();
    section(9, &[1, 5, 0x63, 0x70, 0], &mut explicit);
    assert_eq!(
        audit::inspect_with_standard(&shorthand, Standard::Core2)
            .unwrap()
            .standard
            .validation,
        "valid"
    );
    let module = audit::inspect_with_standard(&explicit, Standard::Core2).unwrap();
    assert_eq!(module.standard.validation, "invalid");
    assert!(module.standard.evidence.iter().any(|evidence| {
        evidence.feature == "function_references"
            && evidence.status == "recognized_but_disabled"
            && evidence.span == Span { start: 12, end: 14 }
            && evidence.raw_hex == "6370"
    }));
    assert_eq!(
        audit::inspect_with_standard(&explicit, Standard::Core3)
            .unwrap()
            .standard
            .validation,
        "valid"
    );
}

#[test]
fn tag_results_are_an_explicit_extra_proposal_requirement() {
    let bytes = [
        b"\0asm\x01\0\0\0".as_slice(),
        &[1, 5, 1, 0x60, 0, 1, 0x7f, 13, 3, 1, 0, 0],
    ]
    .concat();
    check_profiles("tag results", &bytes, [false, false, false, true]);
    let module = audit::inspect_with_standard(&bytes, Standard::Core3).unwrap();
    assert!(module.standard.evidence.iter().any(|evidence| {
        evidence.feature == "stack_switching"
            && evidence.status == "recognized_but_disabled"
            && evidence.span == Span { start: 18, end: 20 }
    }));
}

#[test]
fn bare_concrete_reference_is_not_a_core3_value_type_shorthand() {
    let bare = [
        b"\0asm\x01\0\0\0".as_slice(),
        &[1, 8, 2, 0x60, 0, 0, 0x60, 1, 0, 0],
    ]
    .concat();
    let explicit = [
        b"\0asm\x01\0\0\0".as_slice(),
        &[1, 9, 2, 0x60, 0, 0, 0x60, 1, 0x63, 0, 0],
    ]
    .concat();
    // Independent reproduction of this pinned dependency's permissive reader:
    // this is precisely why its successful validation cannot be our wire oracle.
    Validator::new_with_features(oracle_features(Standard::Core3))
        .validate_all(&bare)
        .unwrap();
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&bare, standard).unwrap();
        assert_eq!(module.standard.validation, "invalid");
        assert_eq!(module.validation, "failed_or_unsupported");
        assert!(module.standard.evidence.iter().any(|evidence| {
            evidence.status == "invalid_encoding"
                && evidence.span == Span { start: 16, end: 17 }
                && evidence.raw_hex == "00"
        }));
        assert!(module
            .diagnostics
            .iter()
            .any(|item| item.code == "invalid_encoding"));
        check_bounds(&module, &bare);
    }
    assert_eq!(
        audit::inspect_with_standard(&explicit, Standard::Core3)
            .unwrap()
            .standard
            .validation,
        "valid"
    );
}

#[test]
fn illegal_reference_shorthand_is_checked_in_every_value_type_position() {
    type RawSections<'a> = &'a [(u8, &'a [u8])];
    let cases: &[(&str, RawSections<'_>)] = &[
        ("table", &[(4, &[1, 0, 0, 0])]),
        ("table-import", &[(2, &[1, 1, b'm', 1, b't', 1, 0, 0, 0])]),
        ("global-import", &[(2, &[1, 1, b'm', 1, b'g', 3, 0, 0])]),
        ("global", &[(6, &[1, 0, 0, 0xd0, 0, 0x0b])]),
        ("element", &[(9, &[1, 5, 0, 0])]),
        ("local", &[(3, &[1, 0]), (10, &[1, 4, 1, 1, 0, 0x0b])]),
        (
            "typed-select",
            &[(3, &[1, 0]), (10, &[1, 7, 0, 0, 0x1c, 1, 0, 0x1a, 0x0b])],
        ),
    ];
    for (label, sections) in cases {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(1, &[1, 0x60, 0, 0], &mut bytes);
        for (id, payload) in *sections {
            section(*id, payload, &mut bytes);
        }
        Validator::new_with_features(oracle_features(Standard::Core3))
            .validate_all(&bytes)
            .unwrap_or_else(|error| panic!("permissive dependency oracle {label}: {error}"));
        let module = audit::inspect_with_standard(&bytes, Standard::Core3).unwrap();
        assert_eq!(module.standard.validation, "invalid", "{label}");
        assert_eq!(module.validation, "failed_or_unsupported", "{label}");
        assert!(
            module
                .standard
                .evidence
                .iter()
                .any(|item| item.status == "invalid_encoding"),
            "{label}"
        );
        check_bounds(&module, &bytes);
    }

    // A positive s33 is a legal type index in blocktype position. It must not
    // be rejected by the value-type shorthand rule.
    let mut block = b"\0asm\x01\0\0\0".to_vec();
    section(1, &[1, 0x60, 0, 0], &mut block);
    section(3, &[1, 0], &mut block);
    section(10, &[1, 5, 0, 2, 0, 0x0b, 0x0b], &mut block);
    check_profiles("indexed empty block", &block, [false, true, true, true]);
}

#[test]
fn core1_br_table_typing_is_distinct_from_modern_feature_flags() {
    let bytes = compile(
        "(module (func (result i32)
            (block $outer (result i32)
                (block $inner (result i64)
                    unreachable i32.const 0 br_table $inner $outer)
                drop i32.const 7)))",
    );
    Validator::new_with_features(WasmFeatures::WASM1)
        .validate_all(&bytes)
        .unwrap();
    let span = independently_decoded_operators(&bytes)
        .into_iter()
        .find(|(_, description, _)| description.starts_with("BrTable"))
        .unwrap()
        .0;
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&bytes, standard).unwrap();
        assert_eq!(module.validation, "valid_with_all_known_features");
        assert!(module.standard.validator_valid);
        if standard == Standard::Core1 {
            assert_eq!(module.standard.validation, "invalid");
            assert!(module.standard.evidence.iter().any(|item| {
                item.status == "invalid_semantics"
                    && item.span == span
                    && item.raw_hex == hex(&bytes[span.start..span.end])
            }));
            let branch = regions(&module)
                .into_iter()
                .find(|item| item.span == span)
                .unwrap();
            assert_eq!(branch.standard_support.status, "invalid_semantics");
            assert_eq!(branch.standard_support.display, "binary");
        } else {
            assert_eq!(module.standard.validation, "valid");
        }
        check_bounds(&module, &bytes);
    }
}

#[test]
fn profile_never_changes_physical_edits_or_default_all_known_behavior() {
    let old = compile("(module (func v128.const i32x4 1 2 3 4 drop i32.const 79225 drop))");
    let new = compile("(module (func v128.const i32x4 1 2 3 5 drop i32.const 79226 drop))");
    let default = audit::compare(&old, &new).unwrap();
    let expected = serde_json::to_value(&default.edits).unwrap();
    for standard in PROFILES {
        let report = audit::compare_with_standard(&old, &new, standard).unwrap();
        assert!(report.changed);
        assert_eq!(serde_json::to_value(&report.edits).unwrap(), expected);
        assert_eq!(report.exact_minimal, default.exact_minimal);
        assert_eq!(report.alignment, default.alignment);
    }
    assert_eq!(
        serde_json::to_value(audit::inspect(&new).unwrap()).unwrap(),
        serde_json::to_value(audit::inspect_with_standard(&new, Standard::AllKnown).unwrap())
            .unwrap()
    );
}

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "uwgit-standard-profiles-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cli(arguments: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_wasm-git"))
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn cli_inspect_diff_and_apply_expose_selected_standard_without_losing_bytes() {
    let directory = Directory::new();
    let old = compile("(module (func v128.const i32x4 1 2 3 4 drop i32.const 79225 drop))");
    let new = compile("(module (func v128.const i32x4 1 2 3 5 drop i32.const 79225 drop))");
    let old_path = directory.0.join("old.wasm");
    let new_path = directory.0.join("new.wasm");
    let patch_path = directory.0.join("change.json");
    let output_path = directory.0.join("replayed.wasm");
    std::fs::write(&old_path, &old).unwrap();
    std::fs::write(&new_path, &new).unwrap();
    let old_path = old_path.to_str().unwrap();
    let new_path = new_path.to_str().unwrap();
    let patch_path = patch_path.to_str().unwrap();
    let output_path = output_path.to_str().unwrap();
    let inspect = cli(&["inspect", new_path, "--json", "--standard", "core1"]);
    assert_eq!(inspect["audit"]["standard"]["selected_standard"], "core1");
    assert_eq!(inspect["audit"]["standard"]["validation"], "invalid");
    assert!(inspect["audit"]["standard"]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["status"] == "recognized_but_disabled"));
    let first = cli(&[
        "diff",
        old_path,
        new_path,
        "--format",
        "json",
        "--standard",
        "core1",
    ]);
    let second = cli(&[
        "diff",
        old_path,
        new_path,
        "--format",
        "json",
        "--standard",
        "core2",
    ]);
    assert_eq!(first["audit"]["new"]["standard"]["validation"], "invalid");
    assert_eq!(second["audit"]["new"]["standard"]["validation"], "valid");
    assert_eq!(first["audit"]["edits"], second["audit"]["edits"]);
    cli(&["patch", old_path, new_path, "--output", patch_path]);
    let apply = cli(&[
        "apply",
        old_path,
        patch_path,
        "--output",
        output_path,
        "--standard",
        "core1",
    ]);
    assert_eq!(apply["audit"]["new"]["standard"]["validation"], "invalid");
    assert_eq!(std::fs::read(output_path).unwrap(), new);
}
