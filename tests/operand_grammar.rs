//! Fixed historical wire forms and damaged-prefix references; no fuzz search.
use wasm_git::{
    audit::{self, AuditModule, Region},
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
type BulkCase<'a> = (&'a str, &'a [u8], bool, &'a [(usize, usize)]);
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    bytes.extend_from_slice(payload);
}
fn body(bytes: &mut Vec<u8>, locals: &[u8], operators: &[u8]) {
    let mut code = vec![1, (locals.len() + operators.len()) as u8];
    code.extend_from_slice(locals);
    code.extend_from_slice(operators);
    section(bytes, 10, &code);
}
fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(entries: &'a [Region], all: &mut Vec<&'a Region>) {
        for entry in entries {
            all.push(entry);
            visit(&entry.children, all);
        }
    }
    let mut all = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut all);
    }
    all
}
fn bounds(module: &AuditModule, bytes: &[u8]) {
    for evidence in &module.standard.evidence {
        assert!(evidence.span.start <= evidence.span.end && evidence.span.end <= bytes.len());
        assert_eq!(
            evidence.raw_hex,
            hex(&bytes[evidence.span.start..evidence.span.end])
        );
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

fn bulk_module(instruction: &[u8], init: bool) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[1, 0]);
    section(&mut bytes, 5, &[1, 0, 1]);
    if init {
        section(&mut bytes, 12, &[1]);
    }
    let mut operators = vec![0x41, 0, 0x41, 0, 0x41, 0];
    operators.extend_from_slice(instruction);
    operators.extend_from_slice(&[0x41, 42, 0x1a, 1, 0x0b]);
    body(&mut bytes, &[0], &operators);
    if init {
        section(&mut bytes, 11, &[1, 1, 0]);
    }
    bytes
}

#[test]
fn bulk_memory_reserved_bytes_are_checked_individually_without_losing_following_mvp() {
    // Offsets below are inside the literal instruction, not decoder-derived.
    let cases: &[BulkCase<'_>] = &[
        ("fill", &[0xfc, 11, 0x80, 0], false, &[(2, 4)]),
        (
            "copy destination",
            &[0xfc, 10, 0x80, 0, 0],
            false,
            &[(2, 4)],
        ),
        ("copy source", &[0xfc, 10, 0, 0x80, 0], false, &[(3, 5)]),
        (
            "copy both",
            &[0xfc, 10, 0x80, 0, 0x80, 0],
            false,
            &[(2, 4), (4, 6)],
        ),
        ("init", &[0xfc, 8, 0, 0x80, 0], true, &[(3, 5)]),
        (
            "init padded data",
            &[0xfc, 8, 0x80, 0, 0x80, 0],
            true,
            &[(4, 6)],
        ),
        (
            "fill padded opcode",
            &[0xfc, 0x8b, 0, 0x80, 0],
            false,
            &[(3, 5)],
        ),
    ];
    for (name, instruction, init, indices) in cases {
        let bytes = bulk_module(instruction, *init);
        // The pinned validator normalizes these zero-valued u32s and accepts
        // them under Core2; the historical literal-byte rule is independent.
        assert!(
            Validator::new_with_features(WasmFeatures::WASM2)
                .validate_all(&bytes)
                .is_ok(),
            "{name}"
        );
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            bounds(&module, &bytes);
            assert_eq!(
                module.standard.validation,
                if matches!(profile, Standard::Core3 | Standard::AllKnown) {
                    "valid"
                } else {
                    "invalid"
                },
                "{name}/{profile}"
            );
            let all = regions(&module);
            let op = all
                .iter()
                .find(|r| r.path == "code[0]/function[0]/operator[3]")
                .unwrap();
            assert_eq!(&bytes[op.span.start..op.span.end], *instruction);
            let wire: Vec<_> = module
                .standard
                .evidence
                .iter()
                .filter(|e| {
                    e.path == op.path
                        && e.feature == "multi_memory"
                        && e.reason.contains("Core2 literal")
                })
                .collect();
            assert_eq!(wire.len(), indices.len(), "{name}/{profile}");
            for (entry, (start, end)) in wire.iter().zip(*indices) {
                assert_eq!(entry.span.start, op.span.start + start);
                assert_eq!(entry.span.end, op.span.start + end);
                assert_eq!(entry.raw_hex, hex(&instruction[*start..*end]));
                assert_eq!(
                    entry.status,
                    if matches!(profile, Standard::Core1 | Standard::Core2) {
                        "recognized_but_disabled"
                    } else {
                        "supported"
                    }
                );
            }
            let sentinel = all
                .iter()
                .find(|r| r.path == "code[0]/function[0]/operator[4]")
                .unwrap();
            assert_eq!(sentinel.span.start, op.span.end);
            assert_eq!(sentinel.description, "I32Const { value: 42 }");
            assert_eq!(sentinel.standard_support.status, "supported");
        }
        replay(&bytes);
    }
}

#[test]
fn legal_core2_padding_in_opcode_and_data_index_is_not_a_new_memory_form() {
    for (instruction, init) in [
        (&[0xfc, 11, 0][..], false),
        (&[0xfc, 0x8b, 0, 0], false),
        (&[0xfc, 10, 0, 0][..], false),
        (&[0xfc, 0x8a, 0, 0, 0], false),
        (&[0xfc, 8, 0, 0][..], true),
        (&[0xfc, 8, 0x80, 0, 0], true),
        (&[0xfc, 0x88, 0, 0x80, 0, 0][..], true),
    ] {
        let bytes = bulk_module(instruction, init);
        for profile in [Standard::Core2, Standard::Core3, Standard::AllKnown] {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            assert_eq!(module.standard.validation, "valid");
            assert!(!module.standard.evidence.iter().any(|e| e.path
                == "code[0]/function[0]/operator[3]"
                && e.feature == "multi_memory"));
        }
    }
}

fn partial_types(continuation: bool) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    // Fully known type0 function and type1 array/continuation, then unknown type2.
    let mut types = vec![3, 0x60, 0, 0];
    types.extend_from_slice(if continuation {
        &[0x5d, 0]
    } else {
        &[0x5e, 0x7f, 1]
    });
    types.push(0x7a);
    section(&mut bytes, 1, &types);
    section(&mut bytes, 3, &[1, 0]);
    bytes
}
fn reference_body(continuation: bool, instruction: &[u8]) -> Vec<u8> {
    let mut bytes = partial_types(continuation);
    let mut ops = vec![0];
    ops.extend_from_slice(instruction);
    // array.copy consumes both arrays; all other tested instructions push one value.
    if instruction.first() != Some(&0xfb) || instruction.get(1) != Some(&0x11) {
        ops.push(0x1a);
    }
    ops.extend_from_slice(&[0x41, 42, 0x1a, 1, 0x0b]);
    body(&mut bytes, &[0], &ops);
    bytes
}

#[test]
fn array_copy_checks_destination_and_source_type_contexts_separately() {
    for (dst, src) in [(1, 1), (2, 1), (1, 2), (2, 2)] {
        let bytes = reference_body(false, &[0xfb, 0x11, dst, src]);
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            bounds(&module, &bytes);
            let unknown: Vec<_> = module
                .standard
                .evidence
                .iter()
                .filter(|e| e.path == "code[0]/function[0]/operator[1]" && e.status == "unknown")
                .collect();
            assert_eq!(unknown.len(), usize::from(dst == 2) + usize::from(src == 2));
            assert_eq!(
                unknown
                    .iter()
                    .any(|e| e.reason.contains("destination array type index 2")),
                dst == 2
            );
            assert_eq!(
                unknown
                    .iter()
                    .any(|e| e.reason.contains("source array type index 2")),
                src == 2
            );
            let all = regions(&module);
            let sentinel = all
                .iter()
                .find(|r| r.path == "code[0]/function[0]/operator[2]")
                .unwrap();
            assert_eq!(sentinel.description, "I32Const { value: 42 }");
            assert_eq!(sentinel.standard_support.status, "supported");
        }
        replay(&bytes);
    }
}

#[test]
fn continuation_bind_checks_input_and_result_type_contexts_separately() {
    for (input, result) in [(1, 1), (2, 1), (1, 2), (2, 2)] {
        let bytes = reference_body(true, &[0xe1, input, result]);
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            bounds(&module, &bytes);
            let unknown: Vec<_> = module
                .standard
                .evidence
                .iter()
                .filter(|e| e.path == "code[0]/function[0]/operator[1]" && e.status == "unknown")
                .collect();
            assert_eq!(
                unknown.len(),
                usize::from(input == 2) + usize::from(result == 2)
            );
            assert_eq!(
                unknown
                    .iter()
                    .any(|e| e.reason.contains("continuation input type index 2")),
                input == 2
            );
            assert_eq!(
                unknown
                    .iter()
                    .any(|e| e.reason.contains("continuation result type index 2")),
                result == 2
            );
            assert!(module
                .standard
                .evidence
                .iter()
                .any(|e| e.path == "code[0]/function[0]/operator[1]"
                    && e.feature == "stack_switching"));
        }
        replay(&bytes);
    }
}

#[test]
fn concrete_and_exact_heap_operands_keep_known_prefix_and_mark_unavailable_types() {
    for index in [1, 2] {
        for instruction in [
            vec![0xd0, index],
            vec![0xd0, 0x62, index],
            vec![0xfb, 0x14, index],
            vec![0xfb, 0x16, index],
        ] {
            let bytes = reference_body(false, &instruction);
            for profile in PROFILES {
                let module = audit::inspect_with_standard(&bytes, profile).unwrap();
                bounds(&module, &bytes);
                let unknown: Vec<_> = module
                    .standard
                    .evidence
                    .iter()
                    .filter(|e| {
                        e.path == "code[0]/function[0]/operator[1]" && e.status == "unknown"
                    })
                    .collect();
                assert_eq!(unknown.len(), usize::from(index == 2));
                if let Some(entry) = unknown.first() {
                    assert!(entry.reason.contains("heap type index 2"));
                }
                assert!(!module
                    .standard
                    .evidence
                    .iter()
                    .any(|e| e.status == "invalid_encoding"));
                let all = regions(&module);
                let sentinel = all
                    .iter()
                    .find(|r| r.path == "code[0]/function[0]/operator[3]")
                    .unwrap();
                assert_eq!(sentinel.description, "I32Const { value: 42 }");
                assert_eq!(sentinel.standard_support.status, "supported");
            }
            replay(&bytes);
        }
    }
}

#[test]
fn heap_type_context_is_checked_in_structures_locals_and_typed_select() {
    for index in [1, 2] {
        for place in ["global", "table", "local", "select"] {
            let mut bytes = partial_types(false);
            match place {
                "global" => section(&mut bytes, 6, &[1, 0x63, index, 0, 0xd0, index, 0x0b]),
                "table" => section(&mut bytes, 4, &[1, 0x63, index, 0, 0]),
                _ => {}
            }
            let locals = if place == "local" {
                vec![1, 0, 0x63, index]
            } else {
                vec![0]
            };
            let ops = if place == "select" {
                vec![0, 0x1c, 1, 0x63, index, 0x1a, 0x0b]
            } else {
                vec![0x0b]
            };
            body(&mut bytes, &locals, &ops);
            let path = match place {
                "global" => "global[0]/entry[0]",
                "table" => "table[0]/entry[0]",
                "local" => "code[0]/function[0]/local_group[0]",
                _ => "code[0]/function[0]/operator[1]",
            };
            for profile in PROFILES {
                let module = audit::inspect_with_standard(&bytes, profile).unwrap();
                bounds(&module, &bytes);
                assert_eq!(
                    module
                        .standard
                        .evidence
                        .iter()
                        .any(|e| e.path == path && e.status == "unknown"),
                    index == 2,
                    "{place}/{index}/{profile}"
                );
            }
        }
    }
}
