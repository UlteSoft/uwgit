//! Fixed import-field failures, unknown forms and resource controls; no fuzzing.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const CARRIER: &str = "import[0]/undecoded";
const IMPORT_ERROR: &str = "import[0]/undecoded/import_error";
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
    sentinel: Span,
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
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    let mut payload = vec![2, 0, 1, b'f', 0, 0];
    payload.extend_from_slice(entry);
    let start = section(&mut bytes, 2, &payload);
    let failed = Span {
        start: start + 6,
        end: bytes.len(),
    };
    section(&mut bytes, 3, &[1, 0]);
    // An incomplete import group cannot prove whether function index1 is a
    // later import or the defined function. Index0 remains a complete import.
    let code = section(
        &mut bytes,
        10,
        &[1, 9, 0, 0x10, 0, 0x10, 1, 0x41, 42, 0x1a, 0x0b],
    );
    let sentinel = Span {
        start: code + 7,
        end: code + 9,
    };
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        failed,
        sentinel,
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
            at(&module, "import[0]/group[0]").span,
            Span { start: 17, end: 22 }
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
        let constant = at(&module, "code[0]/function[0]/operator[2]");
        assert_eq!(constant.span, fixture.sentinel);
        assert_eq!(
            &fixture.bytes[constant.span.start..constant.span.end],
            &[0x41, 42]
        );
        assert_eq!(constant.standard_support.status, "supported");
        assert_eq!(
            at(&module, "code[0]/function[0]/operator[4]").description,
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
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.starts_with("import[0]/group[1]")));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|evidence| evidence.path.starts_with("import[0]/group[1]")));
    assert_ne!(
        at(module, "code[0]/function[0]/operator[0]")
            .standard_support
            .status,
        "unknown"
    );
    assert_eq!(
        at(module, "code[0]/function[0]/operator[1]")
            .standard_support
            .status,
        "unknown"
    );
}

fn known(case: &Case) {
    let fixture = fixture(case.entry);
    check(&fixture, |_, module| {
        unpublished(module);
        assert!(!module.standard.validator_valid);
        let carrier = at(module, CARRIER);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(carrier.standard_support.status, "invalid_encoding");
        assert_eq!(carrier.standard_support.display, "binary");
        let child = at(module, IMPORT_ERROR);
        assert_eq!(
            child.span,
            Span {
                start: fixture.failed.start + case.start,
                end: fixture.failed.start + case.end
            }
        );
        assert_eq!(child.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(child.standard_support.status, "invalid_encoding");
        assert_eq!(child.standard_support.display, "binary");
        assert!(child.children.is_empty());
        assert!(child.description.starts_with(&format!("{}:", case.field)));
        assert!(child.description.contains("only this field is diagnosed"));
        assert_eq!(carrier.children.len(), 1);
        assert_eq!(carrier.children[0].path, IMPORT_ERROR);
        let errors: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|evidence| evidence.path == IMPORT_ERROR)
            .collect();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].span, child.span);
        assert_eq!(errors[0].status, "invalid_encoding");
        assert_eq!(errors[0].raw_hex, hex(&case.entry[case.start..case.end]));
        assert!(errors[0].reason.contains(case.field));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|evidence| evidence.path.starts_with(CARRIER) && evidence.status == "unknown"));
        let token = format!(
            "invalid_encoding {IMPORT_ERROR} [{}..{}) binary={}",
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
        let carrier = at(module, CARRIER);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.standard_support.status, "unknown");
        assert_eq!(carrier.standard_support.display, "opaque");
        assert!(!regions(module)
            .iter()
            .any(|region| region.path == IMPORT_ERROR));
        assert!(!module.standard.evidence.iter().any(|evidence| {
            evidence.path.starts_with(CARRIER) && evidence.status == "invalid_encoding"
        }));
    });
}

#[test]
fn ordinary_name_integer_and_partial_payload_failures_preserve_complete_wire_ranges() {
    let cases = [
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x10],
            field: "module name",
            start: 0,
            end: 5,
        },
        Case {
            entry: &[3, b'a', b'b'],
            field: "module name",
            start: 0,
            end: 3,
        },
        Case {
            entry: &[0, 0x80, 0x80, 0x80, 0x80, 0x80],
            field: "item name",
            start: 1,
            end: 6,
        },
        Case {
            entry: &[0, 3, b'a', b'b'],
            field: "item name",
            start: 1,
            end: 4,
        },
        Case {
            entry: &[],
            field: "module name",
            start: 0,
            end: 0,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn compact_counts_and_member_names_do_not_publish_partial_groups() {
    let cases = [
        Case {
            entry: &[0, 0, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "compact import member count",
            start: 3,
            end: 8,
        },
        Case {
            entry: &[0, 0, 0x7e, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "compact import member count",
            start: 5,
            end: 10,
        },
        Case {
            entry: &[0, 0, 0x7f],
            field: "compact import member count",
            start: 3,
            end: 3,
        },
        Case {
            entry: &[0, 0, 0x7e, 0, 0, 1, 3, b'a', b'b'],
            field: "member name",
            start: 6,
            end: 9,
        },
        // Member a is complete, but the second name is absent at section EOF.
        Case {
            entry: &[0, 0, 0x7f, 2, 1, b'a', 0, 0],
            field: "member name",
            start: 8,
            end: 8,
        },
        // These 32-bit-addressed limits use legal six-byte u64 padding. The
        // later names count, rather than the shared limit, is malformed.
        Case {
            entry: &[
                0, 0, 0x7e, 2, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            field: "compact import member count",
            start: 11,
            end: 16,
        },
        Case {
            entry: &[
                0, 0, 0x7e, 1, 0x70, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80,
                0x10,
            ],
            field: "compact import member count",
            start: 12,
            end: 17,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn function_exact_function_and_tag_indices_have_precise_known_failures() {
    let cases = [
        Case {
            entry: &[0, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x80],
            field: "function type index",
            start: 3,
            end: 8,
        },
        Case {
            entry: &[0, 0, 0x20, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "function type index",
            start: 3,
            end: 8,
        },
        Case {
            entry: &[0, 0, 0],
            field: "function type index",
            start: 3,
            end: 3,
        },
        Case {
            entry: &[0, 0, 4],
            field: "tag attribute",
            start: 3,
            end: 3,
        },
        Case {
            entry: &[0, 0, 4, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "tag type index",
            start: 4,
            end: 9,
        },
        Case {
            entry: &[0, 0, 4, 0],
            field: "tag type index",
            start: 4,
            end: 4,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn table_reference_flags_and_u64_limits_are_checked_at_proved_boundaries() {
    let cases = [
        Case {
            entry: &[0, 0, 1, 0x70],
            field: "table limits flags",
            start: 4,
            end: 4,
        },
        Case {
            entry: &[
                0, 0, 1, 0x70, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2,
            ],
            field: "table minimum",
            start: 5,
            end: 15,
        },
        Case {
            entry: &[
                0, 0, 1, 0x70, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            ],
            field: "table maximum",
            start: 6,
            end: 16,
        },
        Case {
            entry: &[0, 0, 1, 0x63, 0x80],
            field: "table reference type",
            start: 3,
            end: 5,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn memory_limits_use_u64_and_the_page_size_field_uses_u32() {
    let cases = [
        Case {
            entry: &[0, 0, 2],
            field: "memory limits flags",
            start: 3,
            end: 3,
        },
        Case {
            entry: &[
                0, 0, 2, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2,
            ],
            field: "memory minimum",
            start: 4,
            end: 14,
        },
        Case {
            entry: &[0, 0, 2, 1, 0],
            field: "memory maximum",
            start: 5,
            end: 5,
        },
        Case {
            entry: &[0, 0, 2, 8, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "memory page size",
            start: 5,
            end: 10,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn known_global_value_and_flags_eof_do_not_borrow_the_next_section() {
    let cases = [
        Case {
            entry: &[0, 0, 3],
            field: "global value type",
            start: 3,
            end: 3,
        },
        Case {
            entry: &[0, 0, 3, 0x64, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "global value type",
            start: 3,
            end: 9,
        },
        Case {
            entry: &[0, 0, 3, 0x7f],
            field: "global flags",
            start: 4,
            end: 4,
        },
        Case {
            entry: &[0, 0],
            field: "import kind",
            start: 2,
            end: 2,
        },
    ];
    for case in cases {
        known(&case);
    }
}

#[test]
fn unknown_types_and_kinds_cannot_authorize_fake_later_integer_fields() {
    let cases: &[&[u8]] = &[
        &[0, 0, 3, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0, 0, 1, 0xff, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[
            0, 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0xff, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        &[0, 0, 0x7e, 3, 0xff, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0, 0, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10],
    ];
    for entry in cases {
        unknown(entry);
    }
}

#[test]
fn string_resource_caps_and_unrecognized_limits_flags_stop_before_fake_errors() {
    let cases: &[&[u8]] = &[
        // 100001 is a legal name length above the pinned string resource cap.
        &[0xa1, 0x8d, 6, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0, 0, 0x7f, 1, 0xa1, 0x8d, 6, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0, 0, 2, 0x10, 0x80, 0x80, 0x80, 0x80, 0x10],
    ];
    for entry in cases {
        unknown(entry);
    }
}

#[test]
fn old_utf8_diagnostics_and_known_wire_positive_controls_keep_their_meaning() {
    for case in [
        Case {
            entry: &[1, 0xff, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "module_name/utf8",
            start: 1,
            end: 2,
        },
        Case {
            entry: &[0, 0, 0x7f, 1, 1, 0xff],
            field: "item[0]/name/utf8",
            start: 5,
            end: 6,
        },
    ] {
        let fixture = fixture(case.entry);
        check(&fixture, |_, module| {
            unpublished(module);
            let path = format!("{CARRIER}/{}", case.field);
            let child = at(module, &path);
            assert_eq!(
                child.span,
                Span {
                    start: fixture.failed.start + case.start,
                    end: fixture.failed.start + case.end
                }
            );
            assert_eq!(child.standard_support.status, "invalid_encoding");
            assert_eq!(at(module, CARRIER).children.len(), 1);
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == IMPORT_ERROR));
        });
    }
    for entry in [
        &[0x80, 0, 0x80, 0, 0, 0x80, 0][..],
        // The fifth payload bit is legal in a u64 limit. Its memory32 bound
        // is a separate semantic constraint, not malformed integer encoding.
        &[0, 0, 2, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..],
    ] {
        let fixture = fixture(entry);
        check(&fixture, |_, module| {
            assert_eq!(at(module, "import[0]/group[1]").span, fixture.failed);
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == IMPORT_ERROR));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|evidence| evidence.status == "invalid_encoding"));
            if entry[0] == 0x80 {
                assert!(module.standard.validator_valid);
            }
        });
    }
}
