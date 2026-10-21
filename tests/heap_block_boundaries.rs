//! Fixed s33 index/constructor boundaries in a complete type index space.
//! The repeated declarations build one explicit index127 fixture, not a search.
use wasm_git::{
    audit::{self, AuditModule, Region},
    patch::BytePatch,
    standard::Standard,
};
use wasmparser::Validator;

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

fn unsigned(mut value: u32, bytes: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        bytes.push(byte | if value != 0 { 0x80 } else { 0 });
        if value == 0 {
            break;
        }
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    bytes.push(id);
    unsigned(payload.len() as u32, bytes);
    bytes.extend_from_slice(payload);
}

fn module(first: &[u8]) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    let mut types = vec![0x80, 1]; // Exactly 128 function types, indices0..127.
    for _ in 0..128 {
        types.extend_from_slice(&[0x60, 0, 0]);
    }
    section(&mut bytes, 1, &types);
    section(&mut bytes, 3, &[2, 0, 0]);
    let mut code = vec![2];
    unsigned(first.len() as u32, &mut code);
    code.extend_from_slice(first);
    code.extend_from_slice(&[5, 0, 0x41, 42, 0x1a, 0x0b]);
    section(&mut bytes, 10, &code);
    section(&mut bytes, 0, &[1, b'x', 0xaa]);
    bytes
}

#[test]
fn a_complete_heap_index_space_cannot_validate_an_unknown_value_type_constructor() {
    let mut bytes = HEADER.to_vec();
    let mut types = vec![0x80, 1];
    for _ in 0..128 {
        types.extend_from_slice(&[0x60, 0, 0]);
    }
    section(&mut bytes, 1, &types);
    section(&mut bytes, 3, &[1, 0]);
    // A permissive bare FF00 value type and a legitimate explicit heap index
    // both become nullable concrete127. The latter cannot justify the former.
    section(&mut bytes, 6, &[1, 0xff, 0, 0, 0xd0, 0xff, 0, 0x0b]);
    section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
    assert!(Validator::new_with_features(Standard::AllKnown.features())
        .validate_all(&bytes)
        .is_ok());
    check(&bytes, |standard, module| {
        assert_eq!(module.validation, "failed_or_unsupported");
        assert_eq!(module.standard.validation, "invalid");
        if matches!(standard, Standard::Core3 | Standard::AllKnown) {
            assert!(module.standard.validator_valid);
        }
        assert_eq!(
            region(module, "global[0]/undecoded").feature.as_deref(),
            Some("unknown_declaration_type")
        );
        let constant = region(module, "code[0]/function[0]/operator[0]");
        assert_eq!(constant.description, "I32Const { value: 42 }");
        assert_eq!(constant.standard_support.status, "supported");
    });
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn region<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    regions(module)
        .into_iter()
        .find(|region| region.path == path)
        .unwrap_or_else(|| panic!("missing physical region {path}"))
}

fn check(bytes: &[u8], mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected = None;
    for standard in PROFILES {
        let module = audit::inspect_with_standard(bytes, standard).unwrap();
        for evidence in &module.standard.evidence {
            assert!(evidence.span.start <= evidence.span.end && evidence.span.end <= bytes.len());
            assert_eq!(
                evidence.raw_hex,
                hex(&bytes[evidence.span.start..evidence.span.end])
            );
        }
        inspect(standard, &module);
        let edits = serde_json::to_vec(
            &audit::compare_with_standard(HEADER, bytes, standard)
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

fn later_body(module: &AuditModule, bytes: &[u8]) {
    let later = region(module, "code[0]/function[1]/operator[0]");
    assert_eq!(&bytes[later.span.start..later.span.end], &[0x41, 42]);
    assert_eq!(later.standard_support.status, "supported");
    assert!(module.sections.iter().any(|section| section.id == 0));
}

fn known(module: &AuditModule) {
    assert!(!module.standard.evidence.iter().any(|evidence| matches!(
        evidence.status.as_str(),
        "unknown" | "invalid_encoding" | "invalid_semantics"
    )));
    assert!(regions(module)
        .iter()
        .any(|region| region.path == "type[0]/type[127]"));
}

#[test]
fn positive_and_padded_s33_block_indices_do_not_use_value_type_prefix_rules() {
    for index in [
        &[0xff, 0][..],       // Positive127, shortest signed encoding.
        &[0xff, 0x80, 0][..], // Positive127, permitted signed padding.
        &[0x80, 0][..],       // Positive0, permitted signed padding.
    ] {
        let mut first = vec![0, 0x02];
        first.extend_from_slice(index);
        first.extend_from_slice(&[1, 0x0b, 0x41, 42, 0x1a, 0x0b]);
        let bytes = module(&first);
        assert!(Validator::new_with_features(Standard::Core2.features())
            .validate_all(&bytes)
            .is_ok());
        check(&bytes, |standard, module| {
            known(module);
            assert_eq!(
                module.standard.validation,
                if standard == Standard::Core1 {
                    "invalid"
                } else {
                    "valid"
                }
            );
            let block = region(module, "code[0]/function[0]/operator[0]");
            assert_eq!(
                &bytes[block.span.start..block.span.end],
                &first[1..2 + index.len()]
            );
            assert!(block.description.contains("FuncType"));
            assert!(module.standard.evidence.iter().any(|evidence| {
                evidence.path == block.path && evidence.feature == "multi_value"
            }));
            let constant = region(module, "code[0]/function[0]/operator[3]");
            assert_eq!(&bytes[constant.span.start..constant.span.end], &[0x41, 42]);
            assert_eq!(constant.standard_support.status, "supported");
            later_body(module, &bytes);
        });
    }
}

#[test]
fn positive_and_padded_s33_heap_indices_remain_concrete_heap_references() {
    for index in [&[0xff, 0][..], &[0xff, 0x80, 0][..], &[0x80, 0][..]] {
        let mut first = vec![0, 0xd0];
        first.extend_from_slice(index);
        first.extend_from_slice(&[0x1a, 0x41, 42, 0x1a, 0x0b]);
        let bytes = module(&first);
        assert!(Validator::new_with_features(Standard::Core3.features())
            .validate_all(&bytes)
            .is_ok());
        check(&bytes, |standard, module| {
            known(module);
            assert_eq!(
                module.standard.validation,
                if matches!(standard, Standard::Core3 | Standard::AllKnown) {
                    "valid"
                } else {
                    "invalid"
                }
            );
            let reference = region(module, "code[0]/function[0]/operator[0]");
            assert_eq!(
                &bytes[reference.span.start..reference.span.end],
                &first[1..2 + index.len()]
            );
            assert!(reference.description.contains("Concrete"));
            assert!(module.standard.evidence.iter().any(|evidence| {
                evidence.path == reference.path && evidence.feature == "function_references"
            }));
            let constant = region(module, "code[0]/function[0]/operator[2]");
            assert_eq!(&bytes[constant.span.start..constant.span.end], &[0x41, 42]);
            assert_eq!(constant.standard_support.status, "supported");
            later_body(module, &bytes);
        });
    }
}

#[test]
fn explicit_reference_value_types_accept_index127_in_locals_and_block_results() {
    for index in [&[0xff, 0][..], &[0xff, 0x80, 0][..]] {
        for block in [false, true] {
            let mut first = if block {
                vec![0, 0x02, 0x63]
            } else {
                vec![1, 1, 0x63]
            };
            first.extend_from_slice(index);
            if block {
                // Unreachable supplies the block's nullable reference result.
                first.extend_from_slice(&[0, 0x0b]);
            } else {
                first.extend_from_slice(&[0x20, 0]);
            }
            first.extend_from_slice(&[0x1a, 0x41, 42, 0x1a, 0x0b]);
            let bytes = module(&first);
            assert!(Validator::new_with_features(Standard::Core3.features())
                .validate_all(&bytes)
                .is_ok());
            check(&bytes, |standard, module| {
                known(module);
                assert_eq!(
                    module.standard.validation,
                    if matches!(standard, Standard::Core3 | Standard::AllKnown) {
                        "valid"
                    } else {
                        "invalid"
                    }
                );
                let typed = region(
                    module,
                    if block {
                        "code[0]/function[0]/operator[0]"
                    } else {
                        "code[0]/function[0]/local_group[0]"
                    },
                );
                assert!(module.standard.evidence.iter().any(|evidence| {
                    evidence.path == typed.path && evidence.feature == "function_references"
                }));
                assert!(!module.standard.evidence.iter().any(|evidence| {
                    evidence.path == typed.path && evidence.feature == "reference_type_encoding"
                }));
                let constant = region(
                    module,
                    if block {
                        "code[0]/function[0]/operator[4]"
                    } else {
                        "code[0]/function[0]/operator[2]"
                    },
                );
                assert_eq!(&bytes[constant.span.start..constant.span.end], &[0x41, 42]);
                assert_eq!(constant.standard_support.status, "supported");
                later_body(module, &bytes);
            });
        }
    }
}

#[test]
fn unknown_negative_constructors_differ_from_truncated_known_s33_indices() {
    for (operators, expected) in [
        (vec![0x02, 0x7a, 0x41, 42, 0x1a, 0x0b, 0x0b], "unknown"),
        (vec![0xd0, 0x7a, 0x41, 42, 0x1a, 0x0b], "unknown"),
        (vec![0x02, 0x63, 0x7a, 0x41, 42, 0x0b, 0x0b], "unknown"),
        (vec![0x02, 0xff], "invalid_encoding"),
        (vec![0xd0, 0xff], "invalid_encoding"),
        (vec![0x02, 0x63, 0xff], "invalid_encoding"),
    ] {
        let mut first = vec![0];
        first.extend_from_slice(&operators);
        let bytes = module(&first);
        check(&bytes, |_, module| {
            assert_eq!(module.standard.validation, "invalid");
            let opaque = region(module, "code[0]/function[0]/opaque");
            assert_eq!(
                &bytes[opaque.span.start..opaque.span.end],
                operators.as_slice()
            );
            assert_eq!(opaque.standard_support.status, expected);
            assert!(module
                .standard
                .evidence
                .iter()
                .any(|evidence| { evidence.path == opaque.path && evidence.status == expected }));
            assert!(!regions(module)
                .iter()
                .any(|region| { region.path.starts_with("code[0]/function[0]/operator[") }));
            later_body(module, &bytes);
        });
    }
}
