//! Fixed declaration-header failures and conservative future/resource controls.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

struct Case {
    id: u8,
    entry: &'static [u8],
    field: &'static str,
    start: usize,
    end: usize,
}

struct Fixture {
    bytes: Vec<u8>,
    path: &'static str,
    prior: Span,
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

fn fixture(id: u8, entry: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    // Function declarations precede all four declaration sections in Core
    // section order; their independently framed body follows the failed entry.
    section(&mut bytes, 3, &[1, 0]);
    let (path, prior): (&str, &[u8]) = match id {
        4 => ("table[0]", &[0x70, 0, 0]),
        5 => ("memory[0]", &[0, 0]),
        6 => ("global[0]", &[0x7f, 0, 0x41, 0, 0x0b]),
        13 => ("tag[0]", &[0, 0]),
        _ => unreachable!(),
    };
    let mut payload = vec![2];
    payload.extend_from_slice(prior);
    payload.extend_from_slice(entry);
    let start = section(&mut bytes, id, &payload);
    let prior = Span {
        start: start + 1,
        end: start + 1 + prior.len(),
    };
    let failed = Span {
        start: prior.end,
        end: bytes.len(),
    };
    // call0 still has a proved signature: a failed non-function declaration
    // does not make the complete function declaration prefix unknown.
    let code = section(&mut bytes, 10, &[1, 7, 0, 0x10, 0, 0x41, 42, 0x1a, 0x0b]);
    let sentinel = Span {
        start: code + 5,
        end: code + 7,
    };
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        path,
        prior,
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

fn error_path(fixture: &Fixture) -> String {
    format!(
        "{}/undecoded/{}_error",
        fixture.path,
        fixture.path.split('[').next().unwrap()
    )
}

fn check(fixture: &Fixture, mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        let prior = at(&module, &format!("{}/entry[0]", fixture.path));
        assert_eq!(prior.span, fixture.prior);
        assert_ne!(prior.standard_support.status, "unknown");
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
        assert_eq!(json["byte_len"], fixture.bytes.len());
        assert_eq!(
            json["standard"]["selected_standard"],
            serde_json::to_value(profile).unwrap()
        );
        assert_eq!(at(&module, "function[0]/entry[0]").description, "0");
        assert_eq!(
            at(&module, "code[0]/function[0]/operator[0]")
                .standard_support
                .status,
            "supported"
        );
        let constant = at(&module, "code[0]/function[0]/operator[1]");
        assert_eq!(constant.span, fixture.sentinel);
        assert_eq!(constant.standard_support.status, "supported");
        assert_eq!(
            &fixture.bytes[constant.span.start..constant.span.end],
            &[0x41, 42]
        );
        assert_eq!(
            at(&module, "code[0]/function[0]/operator[3]").description,
            "End"
        );
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

fn known(case: &Case) {
    let fixture = fixture(case.id, case.entry);
    check(&fixture, |_, module| {
        let carrier_path = format!("{}/undecoded", fixture.path);
        let carrier = at(module, &carrier_path);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(carrier.standard_support.status, "invalid_encoding");
        assert_eq!(carrier.standard_support.display, "binary");
        let path = error_path(&fixture);
        let child = at(module, &path);
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
        assert_eq!(carrier.children[0].path, path);
        assert!(!regions(module).iter().any(|region| region
            .path
            .starts_with(&format!("{}/entry[1]", fixture.path))));
        let errors: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|evidence| evidence.path == path)
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
            .any(
                |evidence| evidence.path.starts_with(&carrier_path) && evidence.status == "unknown"
            ));
        let token = format!(
            "invalid_encoding {path} [{}..{}) binary={}",
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

fn conservative(id: u8, entry: &[u8]) {
    let fixture = fixture(id, entry);
    check(&fixture, |_, module| {
        let carrier_path = format!("{}/undecoded", fixture.path);
        let carrier = at(module, &carrier_path);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.standard_support.status, "unknown");
        assert_eq!(carrier.standard_support.display, "opaque");
        assert!(!regions(module)
            .iter()
            .any(|region| region.path == error_path(&fixture)));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|evidence| evidence.path.starts_with(&carrier_path)
                && evidence.status == "invalid_encoding"));
        assert!(!regions(module).iter().any(|region| region
            .path
            .starts_with(&format!("{}/entry[1]", fixture.path))));
    });
}

#[test]
fn table_reference_and_flags_failures_include_empty_and_cloned_cursor_eof() {
    for case in [
        Case {
            id: 4,
            entry: &[],
            field: "table reference type",
            start: 0,
            end: 0,
        },
        Case {
            id: 4,
            entry: &[0x63, 0x80],
            field: "table reference type",
            start: 0,
            end: 2,
        },
        Case {
            id: 4,
            entry: &[0x64, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "table reference type",
            start: 0,
            end: 6,
        },
        Case {
            id: 4,
            entry: &[0x70],
            field: "table limits flags",
            start: 1,
            end: 1,
        },
    ] {
        known(&case);
    }
}

#[test]
fn table_u64_minimum_and_maximum_failures_stop_at_the_bad_field() {
    for case in [
        Case {
            id: 4,
            entry: &[0x70, 0],
            field: "table minimum",
            start: 2,
            end: 2,
        },
        Case {
            id: 4,
            entry: &[
                0x70, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2, 0xa5,
            ],
            field: "table minimum",
            start: 2,
            end: 12,
        },
        Case {
            id: 4,
            entry: &[0x70, 1, 0],
            field: "table maximum",
            start: 3,
            end: 3,
        },
        Case {
            id: 4,
            entry: &[
                0x70, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xa5,
            ],
            field: "table maximum",
            start: 3,
            end: 13,
        },
    ] {
        known(&case);
    }
}

#[test]
fn explicit_table_initializer_prefix_keeps_reserved_and_shifted_header_ranges() {
    for case in [
        Case {
            id: 4,
            entry: &[0x40],
            field: "table initializer reserved byte",
            start: 1,
            end: 1,
        },
        Case {
            id: 4,
            entry: &[0x40, 0],
            field: "table reference type",
            start: 2,
            end: 2,
        },
        Case {
            id: 4,
            entry: &[0x40, 0, 0x70, 0],
            field: "table minimum",
            start: 4,
            end: 4,
        },
    ] {
        known(&case);
    }
}

#[test]
fn memory_flags_u64_limits_and_u32_page_size_have_distinct_field_ranges() {
    for case in [
        Case {
            id: 5,
            entry: &[],
            field: "memory limits flags",
            start: 0,
            end: 0,
        },
        Case {
            id: 5,
            entry: &[0],
            field: "memory minimum",
            start: 1,
            end: 1,
        },
        Case {
            id: 5,
            entry: &[
                0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2, 0xa5,
            ],
            field: "memory minimum",
            start: 1,
            end: 11,
        },
        Case {
            id: 5,
            entry: &[1, 0],
            field: "memory maximum",
            start: 2,
            end: 2,
        },
        Case {
            id: 5,
            entry: &[
                1, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xa5,
            ],
            field: "memory maximum",
            start: 2,
            end: 12,
        },
        Case {
            id: 5,
            entry: &[8, 0],
            field: "memory page size",
            start: 2,
            end: 2,
        },
        Case {
            id: 5,
            entry: &[8, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "memory page size",
            start: 2,
            end: 7,
        },
    ] {
        known(&case);
    }
}

#[test]
fn global_value_and_flags_errors_preserve_the_complete_field() {
    for case in [
        Case {
            id: 6,
            entry: &[],
            field: "global value type",
            start: 0,
            end: 0,
        },
        Case {
            id: 6,
            entry: &[0x63, 0x80],
            field: "global value type",
            start: 0,
            end: 2,
        },
        Case {
            id: 6,
            entry: &[0x64, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "global value type",
            start: 0,
            end: 6,
        },
        Case {
            id: 6,
            entry: &[0x7f],
            field: "global flags",
            start: 1,
            end: 1,
        },
    ] {
        known(&case);
    }
}

#[test]
fn tag_attribute_and_type_index_failures_do_not_consume_following_sections() {
    for case in [
        Case {
            id: 13,
            entry: &[],
            field: "tag attribute",
            start: 0,
            end: 0,
        },
        Case {
            id: 13,
            entry: &[0],
            field: "tag type index",
            start: 1,
            end: 1,
        },
        Case {
            id: 13,
            entry: &[0, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "tag type index",
            start: 1,
            end: 6,
        },
        Case {
            id: 13,
            entry: &[0, 0x80, 0x80, 0x80, 0x80, 0x80, 0xa5],
            field: "tag type index",
            start: 1,
            end: 6,
        },
    ] {
        known(&case);
    }
}

#[test]
fn unknown_values_flags_reserved_bytes_and_attributes_stop_before_fake_errors() {
    for (id, entry) in [
        (4, &[0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (4, &[0x40, 0, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (6, &[0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (4, &[0x70, 8, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (4, &[0x40, 1, 0x70, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (5, &[0x10, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (5, &[8, 0, 64, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (6, &[0x7f, 4, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (13, &[1, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
    ] {
        conservative(id, entry);
    }
}

#[test]
fn indexed_reference_implementation_limits_do_not_authorize_later_failures() {
    // The s33 index1048576 is wire-legal but exceeds PackedIndex's pinned cap.
    for (id, entry) in [
        (
            4,
            &[0x63, 0x80, 0x80, 0xc0, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..],
        ),
        (
            6,
            &[0x63, 0x80, 0x80, 0xc0, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..],
        ),
    ] {
        conservative(id, entry);
    }
}

#[test]
fn padded_known_limits_and_indices_are_not_u32_header_errors() {
    for (id, entry) in [
        (4, &[0x70, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0][..]),
        (5, &[0, 0x80, 0x80, 0x80, 0x80, 0x80, 0][..]),
        (
            4,
            &[
                0x70, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
            ][..],
        ),
        (
            5,
            &[
                1, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
            ][..],
        ),
        (13, &[0, 0x80, 0][..]),
        (6, &[0x63, 0x80, 0, 0, 0xd0, 0, 0x0b][..]),
    ] {
        let fixture = fixture(id, entry);
        check(&fixture, |_, module| {
            assert_eq!(
                at(module, &format!("{}/entry[1]", fixture.path)).span,
                fixture.failed
            );
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == error_path(&fixture)));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|evidence| evidence.path.starts_with(fixture.path)
                    && evidence.status == "invalid_encoding"));
        });
    }
}

#[test]
fn unknown_initializer_opcode_or_type_never_becomes_a_later_header_failure() {
    for (id, entry, prefix, opaque) in [
        (
            6,
            &[0x7f, 0, 0x41, 0, 0xff, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10][..],
            2,
            4,
        ),
        (
            6,
            &[
                0x7f, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10,
            ][..],
            2,
            4,
        ),
        (
            4,
            &[
                0x40, 0, 0x70, 0, 0, 0xd0, 0x70, 0xff, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10,
            ][..],
            5,
            7,
        ),
        (
            4,
            &[
                0x40, 0, 0x70, 0, 0, 0xd0, 0x70, 0x1c, 1, 0xff, 0, 0x0b, 0x80, 0x80, 0x80, 0x80,
                0x10,
            ][..],
            5,
            7,
        ),
    ] {
        let fixture = fixture(id, entry);
        check(&fixture, |_, module| {
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == error_path(&fixture)));
            let init = format!("{}/entry[1]/init", fixture.path);
            assert_eq!(
                at(module, &format!("{init}/operator[0]")).span,
                Span {
                    start: fixture.failed.start + prefix,
                    end: fixture.failed.start + opaque
                }
            );
            let unknown = at(module, &format!("{init}/opaque"));
            assert_eq!(
                unknown.span,
                Span {
                    start: fixture.failed.start + opaque,
                    end: fixture.failed.end
                }
            );
            assert_eq!(unknown.standard_support.status, "unknown");
            assert!(!regions(module).iter().any(|region| region
                .path
                .starts_with(&format!("{}/entry[2]", fixture.path))));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|evidence| evidence.path.starts_with(&init)
                    && evidence.status == "invalid_encoding"));
        });
    }
    // A complete header followed immediately by EOF belongs to expression
    // recovery, even though the initializer has no bytes to decode.
    for (id, entry) in [(6, &[0x7f, 0][..]), (4, &[0x40, 0, 0x70, 0, 0][..])] {
        let fixture = fixture(id, entry);
        check(&fixture, |_, module| {
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == error_path(&fixture)));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|evidence| evidence.path == error_path(&fixture)));
            let entry_path = format!("{}/entry[1]", fixture.path);
            let recovered = at(module, &entry_path);
            assert_eq!(recovered.feature.as_deref(), Some("recovered_expression"));
            assert_eq!(recovered.span, fixture.failed);
            assert_eq!(
                at(module, &format!("{entry_path}/header")).span,
                fixture.failed
            );
            assert_eq!(
                at(module, &format!("{entry_path}/init")).span,
                Span {
                    start: fixture.failed.end,
                    end: fixture.failed.end
                }
            );
        });
    }
}
