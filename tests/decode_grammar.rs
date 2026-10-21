//! Fixed decoder failures distinguish malformed known integers from unknown grammar.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};
use wasmparser::{Validator, WasmFeatures};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];
const TYPES: &[u8] = &[1, 0x60, 1, 0x7f, 0];
const FUNCTIONS: &[u8] = &[2, 0, 0];
const MEMORY: &[u8] = &[1, 0, 1];
const AFTER: &[u8] = &[0x41, 42, 0x1a, 1, 0x0b];
const DROP_AFTER: &[u8] = &[0x1a, 0x41, 42, 0x1a, 1, 0x0b];

fn wire(literal: &str) -> Vec<u8> {
    literal
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> Span {
    assert!(payload.len() < 128);
    let start = bytes.len() + 2;
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    bytes.extend_from_slice(payload);
    Span {
        start,
        end: bytes.len(),
    }
}

fn declarations() -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, TYPES);
    section(&mut bytes, 3, FUNCTIONS);
    section(&mut bytes, 5, MEMORY);
    bytes
}

fn bodies(bytes: &mut Vec<u8>, instruction: &[u8], after: &[u8]) -> (Span, Span) {
    let mut first = vec![0, 0]; // zero locals, unreachable for stack polymorphism
    first.extend_from_slice(instruction);
    first.extend_from_slice(after);
    let second = [0, 0x41, 42, 0x1a, 1, 0x0b];
    let mut code = vec![2, first.len() as u8];
    code.extend_from_slice(&first);
    code.push(second.len() as u8);
    code.extend_from_slice(&second);
    let start = bytes.len();
    let failed_suffix = Span {
        start: start + 6,
        end: start + 4 + first.len(),
    };
    let next_constant = Span {
        start: failed_suffix.end + 2,
        end: failed_suffix.end + 4,
    };
    section(bytes, 10, &code);
    (failed_suffix, next_constant)
}

fn module(instruction: &[u8], after: &[u8]) -> (Vec<u8>, Span, Span) {
    let mut bytes = declarations();
    let (failed, following) = bodies(&mut bytes, instruction, after);
    (bytes, failed, following)
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(entries: &'a [Region], out: &mut Vec<&'a Region>) {
        for entry in entries {
            out.push(entry);
            visit(&entry.children, out);
        }
    }
    let mut result = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut result);
    }
    result
}

fn raw(module: &AuditModule, bytes: &[u8]) {
    for entry in &module.standard.evidence {
        let span = entry.span;
        assert!(span.start <= span.end && span.end <= bytes.len());
        let hex: String = bytes[span.start..span.end]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(entry.raw_hex, hex);
    }
}

fn constant_at(module: &AuditModule, expected: Span) {
    let all = regions(module);
    let constant = all
        .iter()
        .find(|region| region.span == expected && region.path.contains("/operator["))
        .unwrap();
    assert_eq!(constant.description, "I32Const { value: 42 }");
    assert_eq!(constant.standard_support.status, "supported");
}

fn failed_body(bytes: &[u8], expected: Span, next: Span, status: &str) {
    for profile in PROFILES {
        let inspected = audit::inspect_with_standard(bytes, profile).unwrap();
        raw(&inspected, bytes);
        let all = regions(&inspected);
        let suffix = all
            .iter()
            .find(|region| region.path == "code[0]/function[0]/opaque")
            .unwrap();
        assert_eq!(suffix.span, expected, "{profile}");
        assert_eq!(suffix.standard_support.status, status, "{profile}");
        assert!(inspected.standard.evidence.iter().any(|entry| {
            entry.path == suffix.path && entry.span == expected && entry.status == status
        }));
        assert!(!all.iter().any(
            |region| region.path.starts_with("code[0]/function[0]/operator[")
                && region.span.start >= expected.start
        ));
        assert_eq!(inspected.standard.validation, "invalid");
        constant_at(&inspected, next);
    }
}

fn replay(bytes: &[u8]) {
    let mut expected = None;
    for profile in PROFILES {
        let edits = serde_json::to_vec(
            &audit::compare_with_standard(HEADER, bytes, profile)
                .unwrap()
                .edits,
        )
        .unwrap();
        if let Some(previous) = &expected {
            assert_eq!(previous, &edits);
        } else {
            expected = Some(edits);
        }
    }
    for (old, new) in [(HEADER, bytes), (bytes, HEADER)] {
        let patch = wasm_git::patch::create(old, new).unwrap();
        assert_eq!(
            BytePatch::from_bytes(&patch.to_bytes().unwrap())
                .unwrap()
                .apply(old)
                .unwrap(),
            new
        );
    }
}

#[test]
fn known_integer_overflow_excess_width_and_misplaced_control_are_encoding_failures() {
    let cases = [
        ("u32 overflow", "20 80 80 80 80 10"),
        ("u32 too long", "20 80 80 80 80 80 00"),
        ("i32 overflow", "41 80 80 80 80 08"),
        ("i32 too long", "41 80 80 80 80 80 00"),
        ("s33 overflow", "02 80 80 80 80 10"),
        ("s33 too long", "02 80 80 80 80 80 00"),
        ("i64 overflow", "42 80 80 80 80 80 80 80 80 80 01"),
        ("i64 too long", "42 80 80 80 80 80 80 80 80 80 80 00"),
        ("u64 overflow", "28 02 80 80 80 80 80 80 80 80 80 02"),
        ("u64 too long", "28 02 80 80 80 80 80 80 80 80 80 80 00"),
        ("else outside if", "05"),
        ("catch outside try", "07 00"),
        ("catch_all outside try", "19"),
        ("delegate outside try", "18 00"),
    ];
    for (name, literal) in cases {
        let (bytes, failed, next) = module(&wire(literal), AFTER);
        assert!(
            Validator::new_with_features(WasmFeatures::all())
                .validate_all(&bytes)
                .is_err(),
            "{name}"
        );
        failed_body(&bytes, failed, next, "invalid_encoding");
        replay(&bytes);
    }
}

#[test]
fn legal_integer_padding_remains_readable_including_signed_ends_and_u64_offsets() {
    for literal in [
        "20 80 80 80 80 00 1a",
        "41 80 80 80 80 00 1a",
        "41 ff ff ff ff 7f 1a",
        "42 80 80 80 80 80 80 80 80 80 00 1a",
        "42 ff ff ff ff ff ff ff ff ff 7f 1a",
        // Type 0 has one i32 parameter, consumed inside the block.
        "02 80 80 80 80 00 1a 0b",
        "28 02 80 80 80 80 80 80 80 80 80 00 1a",
    ] {
        let (bytes, _, next) = module(&wire(literal), AFTER);
        assert!(
            Validator::new_with_features(WasmFeatures::all())
                .validate_all(&bytes)
                .is_ok(),
            "{literal}"
        );
        for profile in PROFILES {
            let inspected = audit::inspect_with_standard(&bytes, profile).unwrap();
            raw(&inspected, &bytes);
            assert!(!inspected
                .standard
                .evidence
                .iter()
                .any(|entry| matches!(entry.status.as_str(), "invalid_encoding" | "unknown")));
            assert_eq!(inspected.validation, "valid_with_all_known_features");
            constant_at(&inspected, next);
        }
        replay(&bytes);
    }
}

#[test]
fn malformed_secondary_opcode_integers_differ_from_well_encoded_future_opcodes() {
    for prefix in [0xfb, 0xfc, 0xfd, 0xfe] {
        for suffix in ["80 80 80 80 10", "80 80 80 80 80 00"] {
            let mut instruction = vec![prefix];
            instruction.extend(wire(suffix));
            let (bytes, failed, next) = module(&instruction, AFTER);
            failed_body(&bytes, failed, next, "invalid_encoding");
            replay(&bytes);
        }
        let mut future = vec![prefix];
        future.extend(wire("ff ff ff ff 0f")); // Valid u32::MAX, not a known opcode.
        let (bytes, failed, next) = module(&future, AFTER);
        failed_body(&bytes, failed, next, "unknown");
        replay(&bytes);
    }
    // No apparent MVP suffix is available: each known immediate ends at its
    // framed body's EOF, and only the next function supplies a trusted restart.
    for literal in ["20 80", "41 80", "42 80", "02 80", "fd 80", "fd 0c 00 00"] {
        let (bytes, failed, next) = module(&wire(literal), &[]);
        failed_body(&bytes, failed, next, "invalid_encoding");
        replay(&bytes);
    }
}

#[test]
fn future_opcodes_types_and_unclassified_enum_errors_stay_unknown() {
    for literal in [
        "ff",                // Future primary opcode.
        "d0 7a",             // Unknown heap type, not a proven bad integer.
        "02 7a",             // Unknown block/value type.
        "1f 40 01 04 00",    // Catch kind outside the pinned enum: conservative unknown.
        "fb 18 04 00 6e 6e", // Cast flags: outside the deliberately narrow classifier.
        "fe 03 01",          // Fence flags: outside the deliberately narrow classifier.
        "fe 4f 02 00",       // Shared-everything ordering: outside the classifier.
        "28 80 01 00",       // Unknown memarg flag bits: outside the classifier.
    ] {
        let (bytes, failed, next) = module(&wire(literal), AFTER);
        failed_body(&bytes, failed, next, "unknown");
        replay(&bytes);
    }
    let mut bytes = HEADER.to_vec();
    // A complete function type0 precedes an unknown type1; later sections do
    // not depend on guessing that unknown type's shape.
    let payload = section(&mut bytes, 1, &[2, 0x60, 1, 0x7f, 0, 0x7a]);
    section(&mut bytes, 3, FUNCTIONS);
    section(&mut bytes, 5, MEMORY);
    let (_, next) = bodies(&mut bytes, &[1], AFTER);
    for profile in PROFILES {
        let inspected = audit::inspect_with_standard(&bytes, profile).unwrap();
        raw(&inspected, &bytes);
        assert!(inspected.standard.evidence.iter().any(|entry| {
            entry.path == "type[0]/undecoded"
                && entry.span
                    == Span {
                        start: payload.end - 1,
                        end: payload.end,
                    }
                && entry.status == "unknown"
        }));
        assert!(!inspected
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "invalid_encoding"));
        constant_at(&inspected, next);
    }
    replay(&bytes);
}

#[test]
fn decoded_lane_shuffle_select_and_natural_alignment_errors_are_not_encoding_failures() {
    let cases = [
        "fd 15 10", // i8x16.extract_lane_s lane16: the u8 is well formed.
        "fd 0d 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        "1c 00",       // A well-formed empty type vector, invalid select arity.
        "1c 02 7f 7f", // A well-formed two-type vector, invalid select arity.
        "28 03 00",    // Valid memarg flags; alignment exceeds i32.load's natural 2.
    ];
    for literal in cases {
        let instruction = wire(literal);
        if instruction.starts_with(&[0xfd, 0x0d]) {
            assert_eq!(instruction.len(), 18); // Exactly 16 shuffle lanes.
        }
        let (bytes, first, next) = module(&instruction, DROP_AFTER);
        assert!(Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .is_err());
        for profile in PROFILES {
            let inspected = audit::inspect_with_standard(&bytes, profile).unwrap();
            raw(&inspected, &bytes);
            let all = regions(&inspected);
            assert!(all.iter().any(|region| {
                region.path.starts_with("code[0]/function[0]/operator[")
                    && region.span.start == first.start
                    && region.span.end == first.start + instruction.len()
            }));
            assert!(!inspected
                .standard
                .evidence
                .iter()
                .any(|entry| matches!(entry.status.as_str(), "invalid_encoding" | "unknown")));
            constant_at(
                &inspected,
                Span {
                    start: first.start + instruction.len() + 1,
                    end: first.start + instruction.len() + 3,
                },
            );
            constant_at(&inspected, next);
        }
        replay(&bytes);
    }
}

#[test]
fn known_section_integer_and_eof_errors_do_not_hide_following_mvp_sections() {
    let cases: &[(u8, &str, usize)] = &[
        (1, "80 80 80 80 10", 0),       // Entry count overflow.
        (1, "80 80 80 80 80 00", 0),    // Entry count too long.
        (1, "01 60 80 80 80 80 10", 1), // Function parameter count overflow.
        (3, "02 00 80 80 80 80 10", 2), // One known function declaration, then bad typeidx.
        (3, "02 00 80 80 80 80 80 00", 2),
        (7, "", 0),                   // Missing known section entry count.
        (8, "80 80 80 80 10", 0),     // Start function scalar overflow.
        (12, "80 80 80 80 80 00", 0), // Data-count scalar too long.
    ];
    for (id, literal, suffix_offset) in cases {
        let mut bytes = HEADER.to_vec();
        let bad = wire(literal);
        let mut bad_payload = None;
        for (section_id, normal) in [(1, TYPES), (3, FUNCTIONS), (5, MEMORY)] {
            let payload = section(
                &mut bytes,
                section_id,
                if section_id == *id { &bad } else { normal },
            );
            if section_id == *id {
                bad_payload = Some(payload);
            }
        }
        let payload = bad_payload.unwrap_or_else(|| section(&mut bytes, *id, &bad));
        let (_, next) = bodies(&mut bytes, &[1], AFTER);
        for profile in PROFILES {
            let inspected = audit::inspect_with_standard(&bytes, profile).unwrap();
            raw(&inspected, &bytes);
            let section = inspected.sections.iter().find(|s| s.id == *id).unwrap();
            let expected = Span {
                start: payload.start + suffix_offset,
                end: payload.end,
            };
            let undecoded = section
                .regions
                .iter()
                .find(|region| region.path.ends_with("/undecoded"))
                .unwrap();
            assert_eq!(undecoded.span, expected, "section {id}/{profile}");
            assert_eq!(undecoded.standard_support.status, "invalid_encoding");
            assert!(inspected.standard.evidence.iter().any(|entry| {
                entry.path == undecoded.path
                    && entry.span == expected
                    && entry.status == "invalid_encoding"
            }));
            constant_at(&inspected, next);
        }
        replay(&bytes);
    }
}
