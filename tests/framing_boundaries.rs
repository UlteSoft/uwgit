//! Literal binary fixtures keep legal padding and malformed encodings intact.
//!
//! These are the 19 manually checked round-9 framing/LEB cases. Validation is
//! checked independently; physical decoding must still respect trusted frames.
//! No Wasm is instantiated or executed.

use wasm_git::audit::{self, AuditModule, Region, Span};
use wasm_git::patch::{self, BytePatch};
use wasm_git::standard::Standard;
use wasmparser::{Validator, WasmFeatures};

const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

#[derive(Clone, Copy)]
enum Failure {
    None,
    SectionSize,
    TypePayload { known_prefix: bool },
    FunctionImmediate,
    DuplicateOrOrder,
    UnknownSection(u8),
}

struct Case {
    name: &'static str,
    wire: &'static str,
    failure: Failure,
    /// Every fixture with readable code ends in this const, drop, end sequence.
    constant: Option<(&'static str, i32)>,
}

const CASES: [Case; 19] = [
    Case {
        name: "canonical",
        wire: "0061736d01000000 010401600000 03020100 0a0701050041011a0b",
        failure: Failure::None,
        constant: Some(("4101", 1)),
    },
    Case {
        name: "padded-section-size-u32",
        wire: "0061736d01000000 01848080800001600000 03020100 0a0701050041011a0b",
        failure: Failure::None,
        constant: Some(("4101", 1)),
    },
    Case {
        name: "padded-entry-count-u32",
        wire: "0061736d01000000 01088180808000600000 03020100 0a0701050041011a0b",
        failure: Failure::None,
        constant: Some(("4101", 1)),
    },
    Case {
        name: "padded-i32-positive",
        wire: "0061736d01000000 010401600000 03020100 0a0b0109004181808080001a0b",
        failure: Failure::None,
        constant: Some(("418180808000", 1)),
    },
    Case {
        name: "padded-i32-negative",
        wire: "0061736d01000000 010401600000 03020100 0a0b01090041ffffffff7f1a0b",
        failure: Failure::None,
        constant: Some(("41ffffffff7f", -1)),
    },
    Case {
        name: "too-wide-section-size",
        wire: "0061736d01000000 0184808080800001600000 03020100 0a0701050041011a0b",
        failure: Failure::SectionSize,
        constant: None,
    },
    Case {
        name: "overflow-section-size",
        wire: "0061736d01000000 01848080801001600000 03020100 0a0701050041011a0b",
        failure: Failure::SectionSize,
        constant: None,
    },
    Case {
        name: "too-wide-entry-count",
        wire: "0061736d01000000 0109818080808000600000 03020100 0a0701050041011a0b",
        failure: Failure::TypePayload {
            known_prefix: false,
        },
        constant: Some(("4101", 1)),
    },
    Case {
        name: "overflow-i32",
        wire: "0061736d01000000 010401600000 03020100 0a0b0109004181808080101a0b",
        failure: Failure::FunctionImmediate,
        constant: None,
    },
    Case {
        name: "too-wide-i32",
        wire: "0061736d01000000 010401600000 03020100 0a0c010a00418180808080001a0b",
        failure: Failure::FunctionImmediate,
        constant: None,
    },
    Case {
        name: "duplicate-type",
        wire: "0061736d01000000 010401600000 010401600000 03020100 0a0701050041011a0b",
        failure: Failure::DuplicateOrOrder,
        constant: Some(("4101", 1)),
    },
    Case {
        name: "out-of-order-function-type",
        wire: "0061736d01000000 03020100 010401600000 0a0701050041011a0b",
        failure: Failure::DuplicateOrOrder,
        constant: Some(("4101", 1)),
    },
    Case {
        name: "unknown-id14",
        wire: "0061736d01000000 0e0341020b 010401600000 03020100 0a0701050041011a0b",
        failure: Failure::UnknownSection(14),
        constant: Some(("4101", 1)),
    },
    Case {
        name: "unknown-high-id128",
        wire: "0061736d01000000 800341020b 010401600000 03020100 0a0701050041011a0b",
        failure: Failure::UnknownSection(128),
        constant: Some(("4101", 1)),
    },
    Case {
        name: "unknown-high-id255",
        wire: "0061736d01000000 ff0341020b 010401600000 03020100 0a0701050041011a0b",
        failure: Failure::UnknownSection(255),
        constant: Some(("4101", 1)),
    },
    Case {
        name: "empty-known-type",
        wire: "0061736d01000000 0100 03020100 0a0701050041011a0b",
        failure: Failure::TypePayload {
            known_prefix: false,
        },
        constant: Some(("4101", 1)),
    },
    Case {
        name: "empty-unknown-id14",
        wire: "0061736d01000000 0e00 010401600000 03020100 0a0701050041011a0b",
        failure: Failure::UnknownSection(14),
        constant: Some(("4101", 1)),
    },
    Case {
        name: "framed-unknown-type-then-mvp",
        wire: "0061736d01000000 010502600000ff 03020100 0a0701050041011a0b",
        failure: Failure::TypePayload { known_prefix: true },
        constant: Some(("4101", 1)),
    },
    Case {
        name: "custom-interleaved-duplicate-name",
        wire: "0061736d01000000 00020178 010401600000 00020178 03020100 0a0701050041011a0b",
        failure: Failure::None,
        constant: Some(("4101", 1)),
    },
];

fn unhex(text: &str) -> Vec<u8> {
    let text: String = text.split_ascii_whitespace().collect();
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn oracle_features(standard: Standard) -> WasmFeatures {
    match standard {
        Standard::Core1 => WasmFeatures::WASM1,
        Standard::Core2 => WasmFeatures::WASM2,
        Standard::Core3 => WasmFeatures::WASM3.difference(WasmFeatures::THREADS),
        Standard::AllKnown => WasmFeatures::all(),
    }
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(region: &'a Region, output: &mut Vec<&'a Region>) {
        output.push(region);
        for child in &region.children {
            visit(child, output);
        }
    }
    let mut output = Vec::new();
    for section in &module.sections {
        for region in &section.regions {
            visit(region, &mut output);
        }
    }
    output
}

fn check_bounds(module: &AuditModule, bytes: &[u8]) {
    let check = |span: Span| {
        assert!(
            span.start <= span.end && span.end <= bytes.len(),
            "{span:?}"
        );
    };
    assert_eq!(module.byte_len, bytes.len());
    for section in &module.sections {
        check(section.span);
        check(section.header_span);
        check(section.payload_span);
    }
    for region in regions(module) {
        check(region.span);
    }
    for evidence in &module.standard.evidence {
        check(evidence.span);
        assert_eq!(
            evidence.raw_hex,
            hex(&bytes[evidence.span.start..evidence.span.end])
        );
    }
    for diagnostic in &module.diagnostics {
        assert!(diagnostic.offset <= bytes.len(), "{diagnostic:?}");
    }
}

fn check_constant_tail(case: &Case, bytes: &[u8], module: &AuditModule) {
    let all_regions = regions(module);
    let operators: Vec<_> = all_regions
        .iter()
        .copied()
        .filter(|region| region.path.contains("/operator["))
        .collect();
    let Some((wire, value)) = case.constant else {
        assert!(
            operators.is_empty(),
            "{}: no resynchronization inside malformed bytes",
            case.name
        );
        return;
    };
    let constant = unhex(wire);
    let start = bytes.len() - constant.len() - 2;
    let expected = [
        (
            Span {
                start,
                end: bytes.len() - 2,
            },
            format!("I32Const {{ value: {value} }}"),
            constant,
        ),
        (
            Span {
                start: bytes.len() - 2,
                end: bytes.len() - 1,
            },
            "Drop".into(),
            vec![0x1a],
        ),
        (
            Span {
                start: bytes.len() - 1,
                end: bytes.len(),
            },
            "End".into(),
            vec![0x0b],
        ),
    ];
    assert_eq!(
        operators.len(),
        expected.len(),
        "{}: opaque payload is not code",
        case.name
    );
    for (index, (span, description, wire)) in expected.iter().enumerate() {
        let region = operators[index];
        assert_eq!(
            region.path,
            format!("code[0]/function[0]/operator[{index}]"),
            "{}",
            case.name
        );
        assert_eq!(region.span, *span, "{}: {description}", case.name);
        assert_eq!(region.description, *description, "{}", case.name);
        assert_eq!(
            &bytes[span.start..span.end],
            wire.as_slice(),
            "{}",
            case.name
        );
        assert_eq!(
            region.standard_support.status, "supported",
            "{}: {description}",
            case.name
        );
        assert!(
            module.standard.evidence.iter().any(|entry| {
                entry.path == region.path
                    && entry.span == *span
                    && entry.status == "supported"
                    && entry.raw_hex == hex(wire)
                    && entry.feature == "mvp"
            }),
            "{}: complete instruction evidence at {span:?}",
            case.name
        );
    }
}

#[test]
fn nineteen_literal_boundaries_match_all_four_profiles() {
    assert_eq!(
        CASES
            .iter()
            .filter(|case| matches!(case.failure, Failure::None))
            .count(),
        6
    );
    for case in &CASES {
        let bytes = unhex(case.wire);
        let valid = matches!(case.failure, Failure::None);
        let all_known = Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .is_ok();
        assert_eq!(
            all_known, valid,
            "{}: independent all-known validator",
            case.name
        );
        for standard in PROFILES {
            let oracle = Validator::new_with_features(oracle_features(standard))
                .validate_all(&bytes)
                .is_ok();
            assert_eq!(
                oracle, valid,
                "{}/{standard}: independent validator",
                case.name
            );
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(
                module.standard.validator_valid, oracle,
                "{}/{standard}",
                case.name
            );
            assert_eq!(
                module.standard.validation,
                if valid { "valid" } else { "invalid" },
                "{}/{standard}",
                case.name
            );
            assert_eq!(
                module.validation,
                if valid {
                    "valid_with_all_known_features"
                } else {
                    "failed_or_unsupported"
                },
                "{}/{standard}",
                case.name
            );
            assert!(
                !module
                    .standard
                    .evidence
                    .iter()
                    .any(|entry| entry.status == "recognized_but_disabled"),
                "{}: malformed/unknown is not a disabled legal proposal",
                case.name
            );
            check_bounds(&module, &bytes);
            check_constant_tail(case, &bytes, &module);
            match case.failure {
                Failure::None => {
                    assert!(
                        module
                            .standard
                            .evidence
                            .iter()
                            .all(|entry| entry.status == "supported"),
                        "{}",
                        case.name
                    );
                }
                Failure::SectionSize => {
                    assert_eq!(
                        module.sections.len(),
                        1,
                        "{}: never scan for a replacement section header",
                        case.name
                    );
                    let section = &module.sections[0];
                    assert_eq!(section.status, "malformed");
                    assert_eq!(
                        section.span,
                        Span {
                            start: 8,
                            end: bytes.len()
                        }
                    );
                    assert_eq!(section.header_span, section.span);
                    assert_eq!(
                        section.payload_span,
                        Span {
                            start: bytes.len(),
                            end: bytes.len()
                        }
                    );
                    assert!(module
                        .diagnostics
                        .iter()
                        .any(|entry| entry.code == "section_framing"));
                    assert_eq!(section.standard_support.status, "invalid_encoding");
                    assert!(module
                        .standard
                        .evidence
                        .iter()
                        .any(|entry| entry.path == section.path
                            && entry.status == "invalid_encoding"));
                }
                Failure::TypePayload { known_prefix } => {
                    assert_eq!(module.sections[0].id, 1);
                    assert_eq!(module.sections[0].status, "malformed");
                    // The completed prefix case ends in an unknown type byte;
                    // the other fixtures have an illegal/missing u32 count.
                    let expected_status = if known_prefix {
                        "unknown"
                    } else {
                        "invalid_encoding"
                    };
                    assert!(module.standard.evidence.iter().any(|entry| {
                        entry.status == expected_status && entry.path == "type[0]/undecoded"
                    }));
                    if known_prefix {
                        let prefix = regions(&module)
                            .into_iter()
                            .find(|region| region.path == "type[0]/type[0]")
                            .unwrap();
                        assert_eq!(hex(&bytes[prefix.span.start..prefix.span.end]), "600000");
                        let opaque = regions(&module)
                            .into_iter()
                            .find(|region| region.path == "type[0]/undecoded")
                            .unwrap();
                        assert_eq!(hex(&bytes[opaque.span.start..opaque.span.end]), "ff");
                    } else {
                        // Invalid count bytes are not a completed declaration
                        // prefix. Later references must not acquire guessed
                        // type indices merely because the suffix is invalid.
                        for path in ["function[0]/entry[0]", "code[0]/function[0]"] {
                            assert!(module
                                .standard
                                .evidence
                                .iter()
                                .any(|entry| { entry.path == path && entry.status == "unknown" }));
                        }
                    }
                }
                Failure::FunctionImmediate => {
                    let opaque = regions(&module)
                        .into_iter()
                        .find(|region| region.path == "code[0]/function[0]/opaque")
                        .unwrap();
                    assert_eq!(
                        opaque.span,
                        Span {
                            start: 23,
                            end: bytes.len()
                        }
                    );
                    assert!(module
                        .standard
                        .evidence
                        .iter()
                        .any(|entry| entry.status == "invalid_encoding"
                            && entry.path == opaque.path
                            && entry.span == opaque.span));
                    assert_eq!(opaque.standard_support.status, "invalid_encoding");
                    assert_eq!(opaque.standard_support.display, "binary");
                }
                Failure::DuplicateOrOrder => {
                    // Individual entries can decode while the module ordering
                    // is invalid. The independent validator owns this result.
                    assert!(module
                        .diagnostics
                        .iter()
                        .any(|entry| entry.code == "validation"));
                }
                Failure::UnknownSection(id) => {
                    let section = &module.sections[0];
                    assert_eq!(section.id, id);
                    assert_eq!(section.kind, "unknown");
                    assert_eq!(section.status, "opaque");
                    assert_eq!(section.standard_support.status, "unknown");
                    assert!(module
                        .standard
                        .evidence
                        .iter()
                        .any(|entry| entry.feature == "unknown"
                            && entry.status == "unknown"
                            && entry.span == section.payload_span));
                }
            }
        }
    }
}

#[test]
fn invalid_memory_count_withdraws_address_type_inference_for_later_code() {
    let bytes =
        unhex("0061736d01000000 010401600000 03020100 05088180808080000400 0a070105003f001a0b");
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&bytes, standard).unwrap();
        check_bounds(&module, &bytes);
        assert_eq!(module.standard.validation, "invalid");
        let all = regions(&module);
        let undecoded = all
            .iter()
            .find(|region| region.path == "memory[0]/undecoded")
            .unwrap();
        assert_eq!(undecoded.standard_support.status, "invalid_encoding");
        assert_eq!(
            &bytes[undecoded.span.start..undecoded.span.end],
            &[0x81, 0x80, 0x80, 0x80, 0x80, 0, 4, 0]
        );
        let size = all
            .iter()
            .find(|region| region.path == "code[0]/function[0]/operator[0]")
            .unwrap();
        assert_eq!(size.description, "MemorySize { mem: 0 }");
        assert_eq!(&bytes[size.span.start..size.span.end], &[0x3f, 0]);
        assert_eq!(size.standard_support.status, "unknown");
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| { entry.path == size.path && entry.feature == "memory64" }));
        let end = all
            .iter()
            .find(|region| region.path == "code[0]/function[0]/operator[2]")
            .unwrap();
        assert_eq!(end.description, "End");
        assert_eq!(end.standard_support.status, "supported");
    }
}

#[test]
fn changed_padding_and_broken_framing_replay_exactly() {
    let canonical = unhex(CASES[0].wire);
    for index in [1, 5] {
        let changed = unhex(CASES[index].wire);
        for standard in PROFILES {
            let report = audit::compare_with_standard(&canonical, &changed, standard).unwrap();
            assert!(report.changed);
            assert!(!report.edits.is_empty());
            let mut replay = Vec::new();
            let mut old_end = 0;
            let mut new_end = 0;
            for edit in &report.edits {
                assert!(
                    old_end <= edit.old_span.start
                        && edit.old_span.start <= edit.old_span.end
                        && edit.old_span.end <= canonical.len()
                );
                assert!(
                    new_end <= edit.new_span.start
                        && edit.new_span.start <= edit.new_span.end
                        && edit.new_span.end <= changed.len()
                );
                assert_eq!(
                    edit.old_hex,
                    hex(&canonical[edit.old_span.start..edit.old_span.end])
                );
                assert_eq!(
                    edit.new_hex,
                    hex(&changed[edit.new_span.start..edit.new_span.end])
                );
                replay.extend_from_slice(&canonical[old_end..edit.old_span.start]);
                replay.extend_from_slice(&unhex(&edit.new_hex));
                old_end = edit.old_span.end;
                new_end = edit.new_span.end;
            }
            replay.extend_from_slice(&canonical[old_end..]);
            assert_eq!(replay, changed, "{}: physical edits", CASES[index].name);
        }
        let serialized = patch::create(&canonical, &changed)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(
            BytePatch::from_bytes(&serialized)
                .unwrap()
                .apply(&canonical)
                .unwrap(),
            changed
        );
        let reverse = patch::create(&changed, &canonical)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(
            BytePatch::from_bytes(&reverse)
                .unwrap()
                .apply(&changed)
                .unwrap(),
            canonical
        );
    }
}
