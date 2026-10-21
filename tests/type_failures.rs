//! Fixed trusted type-field failures and future/resource controls; no fuzzing.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const CARRIER: &str = "type[0]/undecoded";
const TYPE_ERROR: &str = "type[0]/undecoded/type_error";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

struct Case {
    entry: &'static [u8],
    field: &'static str,
    start: usize,
    end: usize,
}

struct Fixture {
    bytes: Vec<u8>,
    failed: Span,
    custom: usize,
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn fixture(entry: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    let mut payload = vec![2, 0x60, 0, 0];
    payload.extend_from_slice(entry);
    let start = section(&mut bytes, 1, &payload);
    let failed = Span {
        start: start + 4,
        end: bytes.len(),
    };
    section(&mut bytes, 3, &[2, 0, 1]);
    section(&mut bytes, 10, &[2, 2, 0, 0x0b, 2, 0, 0x0b]);
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        failed,
        custom,
    }
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(input: &'a [Region], output: &mut Vec<&'a Region>) {
        for region in input {
            output.push(region);
            visit(&region.children, output);
        }
    }
    let mut output = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut output);
    }
    output
}

fn at<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    regions(module)
        .into_iter()
        .find(|region| region.path == path)
        .unwrap_or_else(|| panic!("missing physical region {path}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn check(fixture: &Fixture, mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        assert_eq!(
            at(&module, "type[0]/type[0]").span,
            Span { start: 11, end: 14 }
        );
        for region in regions(&module) {
            assert!(region.span.start <= region.span.end && region.span.end <= fixture.bytes.len());
        }
        for evidence in &module.standard.evidence {
            assert!(
                evidence.span.start <= evidence.span.end
                    && evidence.span.end <= fixture.bytes.len()
            );
            assert_eq!(
                evidence.raw_hex,
                hex(&fixture.bytes[evidence.span.start..evidence.span.end])
            );
        }
        let json = serde_json::to_value(&module).unwrap();
        assert_eq!(
            json["standard"]["selected_standard"],
            serde_json::to_value(profile).unwrap()
        );
        assert_eq!(json["byte_len"], fixture.bytes.len());
        let custom = module
            .sections
            .iter()
            .find(|section| section.id == 0)
            .unwrap();
        assert_eq!(custom.kind, "custom:x");
        assert_eq!(
            custom.span,
            Span {
                start: fixture.custom,
                end: fixture.custom + 5
            }
        );
        assert_eq!(
            at(&module, "code[0]/function[0]/operator[0]").description,
            "End"
        );
        assert_eq!(
            at(&module, "code[0]/function[1]/operator[0]").description,
            "End"
        );
        inspect(profile, &module);
        let diff = audit::compare_with_standard(HEADER, &fixture.bytes, profile).unwrap();
        assert!(diff.changed && diff.exact_minimal);
        let mut replay = Vec::new();
        let mut cursor = 0;
        for edit in &diff.edits {
            assert!(cursor <= edit.old_span.start && edit.old_span.end <= HEADER.len());
            assert!(
                edit.new_span.start <= edit.new_span.end
                    && edit.new_span.end <= fixture.bytes.len()
            );
            assert_eq!(
                edit.old_hex,
                hex(&HEADER[edit.old_span.start..edit.old_span.end])
            );
            assert_eq!(
                edit.new_hex,
                hex(&fixture.bytes[edit.new_span.start..edit.new_span.end])
            );
            replay.extend_from_slice(&HEADER[cursor..edit.old_span.start]);
            replay.extend_from_slice(&fixture.bytes[edit.new_span.start..edit.new_span.end]);
            cursor = edit.old_span.end;
        }
        replay.extend_from_slice(&HEADER[cursor..]);
        assert_eq!(replay, fixture.bytes);
        let edits = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &expected_edits {
            assert_eq!(previous, &edits);
        } else {
            expected_edits = Some(edits);
        }
    }
    for (old, new) in [
        (HEADER, fixture.bytes.as_slice()),
        (fixture.bytes.as_slice(), HEADER),
    ] {
        let patch = wasm_git::patch::create(old, new).unwrap();
        let decoded = BytePatch::from_bytes(&patch.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded.apply(old).unwrap(), new);
    }
}

fn unpublished(module: &AuditModule) {
    assert_ne!(
        at(module, "function[0]/entry[0]").standard_support.status,
        "unknown"
    );
    assert_eq!(
        at(module, "function[0]/entry[1]").standard_support.status,
        "unknown"
    );
    assert!(!regions(module)
        .iter()
        .any(|region| region.path == "type[0]/type[1]"));
}

fn known(case: &Case) {
    let fixture = fixture(case.entry);
    check(&fixture, |_, module| {
        unpublished(module);
        assert!(!module.standard.validator_valid);
        assert_eq!(module.sections[0].status, "malformed");
        let carrier = at(module, CARRIER);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(carrier.standard_support.status, "invalid_encoding");
        let child = at(module, TYPE_ERROR);
        assert_eq!(
            child.span,
            Span {
                start: fixture.failed.start + case.start,
                end: fixture.failed.start + case.end,
            }
        );
        assert_eq!(child.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(child.standard_support.status, "invalid_encoding");
        assert_eq!(child.standard_support.display, "binary");
        assert!(child.description.starts_with(&format!("{}:", case.field)));
        assert!(child.description.contains("only this field is diagnosed"));
        let errors: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|evidence| evidence.path == TYPE_ERROR && evidence.status == "invalid_encoding")
            .collect();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].span, child.span);
        assert_eq!(errors[0].raw_hex, hex(&case.entry[case.start..case.end]));
        assert!(errors[0].reason.contains(case.field));
        assert_eq!(carrier.children.len(), 1);
        assert_eq!(carrier.children[0].path, TYPE_ERROR);
        assert!(!regions(module).iter().any(|region| {
            fixture.failed.start <= region.span.start
                && region.span.start < fixture.failed.end
                && region.path != CARRIER
                && region.path != TYPE_ERROR
        }));
        assert!(!module.standard.evidence.iter().any(|evidence| {
            evidence.path.starts_with(CARRIER) && evidence.status == "unknown"
        }));
        let token = format!(
            "invalid_encoding {TYPE_ERROR} [{}..{}) binary={}",
            child.span.start,
            child.span.end,
            hex(&case.entry[case.start..case.end])
        );
        assert!(module
            .to_text()
            .lines()
            .any(|line| line.starts_with(&token) && line.contains(case.field)));
    });
}

fn unknown(entry: &[u8]) {
    let fixture = fixture(entry);
    check(&fixture, |_, module| {
        unpublished(module);
        assert!(!module.standard.validator_valid);
        let carrier = at(module, CARRIER);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.standard_support.status, "unknown");
        assert!(!regions(module)
            .iter()
            .any(|region| region.path == TYPE_ERROR));
        assert!(!module.standard.evidence.iter().any(|evidence| {
            evidence.span.start >= fixture.failed.start
                && evidence.span.start < fixture.failed.end
                && evidence.status == "invalid_encoding"
        }));
    });
}

#[test]
fn recursive_member_counts_diagnose_only_the_trusted_integer_field() {
    let cases = [
        Case {
            entry: &[0x4e, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "recursive type member count",
            start: 1,
            end: 6,
        },
        // The sixth apparent integer byte and fake later type remain opaque.
        Case {
            entry: &[0x4e, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0x60, 0, 0],
            field: "recursive type member count",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x4e],
            field: "recursive type member count",
            start: 1,
            end: 1,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn explicit_final_and_nonfinal_supertype_counts_have_precise_failures() {
    let cases = [
        Case {
            entry: &[0x4f, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "supertype count",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x50, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0x60, 0, 0],
            field: "supertype count",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x50, 0x80],
            field: "supertype count",
            start: 1,
            end: 2,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn struct_field_counts_are_known_grammar_even_when_disabled_by_a_profile() {
    let cases = [
        Case {
            entry: &[0x5f, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "struct field count",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x5f, 0x80, 0x80, 0x80, 0x80, 0x80],
            field: "struct field count",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x5f],
            field: "struct field count",
            start: 1,
            end: 1,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn function_parameter_and_result_counts_keep_independent_field_ranges() {
    let cases = [
        Case {
            entry: &[0x60, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "function parameter count",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x60, 0x80, 0x80, 0x80, 0x80, 0x80],
            field: "function parameter count",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x60],
            field: "function parameter count",
            start: 1,
            end: 1,
        },
        Case {
            entry: &[0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "function result count",
            start: 2,
            end: 7,
        },
        Case {
            entry: &[0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x80],
            field: "function result count",
            start: 2,
            end: 7,
        },
        Case {
            entry: &[0x60, 0],
            field: "function result count",
            start: 2,
            end: 2,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn type_index_wire_failures_are_not_confused_with_index_context_or_new_features() {
    let cases = [
        Case {
            entry: &[0x50, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "supertype index",
            start: 2,
            end: 7,
        },
        Case {
            entry: &[0x4f, 1],
            field: "supertype index",
            start: 2,
            end: 2,
        },
        Case {
            entry: &[0x4c, 0x80, 0x80, 0x80, 0x80, 0x80],
            field: "described type index",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x4c],
            field: "described type index",
            start: 1,
            end: 1,
        },
        Case {
            entry: &[0x4d, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "descriptor type index",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x4d],
            field: "descriptor type index",
            start: 1,
            end: 1,
        },
        Case {
            entry: &[0x5d, 0x80, 0x80, 0x80, 0x80, 0x80],
            field: "continuation function type index",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0x5d],
            field: "continuation function type index",
            start: 1,
            end: 1,
        },
        // HeapType reads an s33 through a cloned cursor. Failed reads still
        // diagnose the complete reference field, including consumed bytes.
        Case {
            entry: &[0x60, 1, 0x63, 0x80],
            field: "value type",
            start: 2,
            end: 4,
        },
        Case {
            entry: &[0x60, 1, 0x64, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "value type",
            start: 2,
            end: 8,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn nested_wrappers_keep_count_and_eof_failures_at_their_proved_fields() {
    let cases = [
        Case {
            entry: &[0x4e, 1, 0x4f, 0, 0x5f, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "struct field count",
            start: 5,
            end: 10,
        },
        Case {
            entry: &[
                0x65, 0x4c, 0, 0x4d, 0, 0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            field: "function result count",
            start: 7,
            end: 12,
        },
        // The complete first recursive member must not supply a type index.
        Case {
            entry: &[0x4e, 2, 0x5e, 0x78, 0, 0x60, 1],
            field: "value type",
            start: 7,
            end: 7,
        },
        Case {
            entry: &[0x5e, 0x7f],
            field: "field mutability",
            start: 2,
            end: 2,
        },
        Case {
            entry: &[0x4e, 1],
            field: "type constructor",
            start: 2,
            end: 2,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn unknown_forms_and_unsupported_inheritance_cannot_authorize_fake_later_errors() {
    let cases: &[&[u8]] = &[
        &[0x60, 1, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0x5f, 1, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0x4e, 1, 0x61, 0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0x50, 2, 0, 0, 0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0x4e, 2, 0x5d, 0x7f, 0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
    ];
    for entry in cases {
        unknown(entry);
    }
}

#[test]
fn upstream_resource_limits_do_not_turn_later_fake_failures_into_encoding_rules() {
    // These are five selected pinned-reader limits, not large allocations or
    // generated count sweeps. The independent scan cannot override the reader's
    // first resource-limit result with a later EOF/overflow observation.
    let cases: &[&[u8]] = &[
        &[0x60, 0xe9, 7, 0x7f, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10], // 1001 params.
        &[0x60, 0, 0xe9, 7, 0x7f, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10], // 1001 results.
        &[
            0x5f, 0x91, 0x4e, 0x7f, 0, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10,
        ], // 10001 fields.
        &[
            0x4e, 0xc1, 0x84, 0x3d, 0x60, 0, 0, 0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ], // 1000001 members.
        &[
            0x50, 1, 0x80, 0x80, 0x40, 0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ], // PackedIndex 2^20.
    ];
    for entry in cases {
        unknown(entry);
    }
}

#[test]
fn legal_padded_counts_and_explicit_heap_indices_have_no_precise_encoding_error() {
    for entry in [
        &[0x60, 0x80, 0, 0x80, 0][..],
        // FF00 here is a complete positive s33 heap index behind a known
        // reference constructor. Undefined index127 is a separate type check.
        &[0x60, 1, 0x63, 0xff, 0, 0][..],
    ] {
        let fixture = fixture(entry);
        check(&fixture, |_, module| {
            assert_eq!(module.sections[0].status, "decoded");
            assert_eq!(at(module, "type[0]/type[1]").span, fixture.failed);
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == TYPE_ERROR));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|evidence| evidence.status == "invalid_encoding"));
            if entry[1] == 0x80 {
                assert!(module.standard.validator_valid);
                assert_eq!(module.standard.validation, "valid");
            }
        });
    }
}
