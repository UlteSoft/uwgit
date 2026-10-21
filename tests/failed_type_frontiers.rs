//! Fixed unknown declaration frontiers even when the permissive entry reader fails.
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

struct Fixture {
    bytes: Vec<u8>,
    path: &'static str,
    prior_path: &'static str,
    prior: Span,
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

fn fixture(id: u8, failed: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    if id == 2 {
        section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    }
    if id == 9 {
        section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    }
    let (path, prior_path, prior): (&str, &str, &[u8]) = match id {
        1 => ("type[0]", "type[0]/group[0]", &[0x60, 0, 0]),
        2 => ("import[0]", "import[0]/group[0]", &[0, 1, b'f', 0, 0]),
        4 => ("table[0]", "table[0]/entry[0]", &[0x70, 0, 1]),
        6 => ("global[0]", "global[0]/entry[0]", &[0x7f, 0, 0x41, 0, 0x0b]),
        9 => ("element[0]", "element[0]/entry[0]", &[0, 0x41, 0, 0x0b, 0]),
        _ => unreachable!(),
    };
    let mut payload = vec![2];
    payload.extend_from_slice(prior);
    payload.extend_from_slice(failed);
    let start = section(&mut bytes, id, &payload);
    let prior = Span {
        start: start + 1,
        end: start + 1 + prior.len(),
    };
    let failed = Span {
        start: prior.end,
        end: bytes.len(),
    };
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        path,
        prior_path,
        prior,
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
        assert_eq!(at(&module, fixture.prior_path).span, fixture.prior);
        for region in regions(&module) {
            assert!(region.span.start <= region.span.end && region.span.end <= fixture.bytes.len());
        }
        for evidence in &module.standard.evidence {
            assert!(evidence.span.start <= evidence.span.end);
            assert!(evidence.span.end <= fixture.bytes.len());
            assert_eq!(
                evidence.raw_hex,
                hex(&fixture.bytes[evidence.span.start..evidence.span.end])
            );
        }
        let custom = module
            .sections
            .iter()
            .find(|section| section.id == 0)
            .unwrap();
        assert_eq!(custom.kind, "custom:x");
        assert_eq!(custom.span.start, fixture.custom);
        assert_eq!(custom.span.end, fixture.custom + 5);
        inspect(profile, &module);
        let diff = audit::compare_with_standard(HEADER, &fixture.bytes, profile).unwrap();
        assert!(diff.changed && diff.exact_minimal);
        let mut replay = Vec::new();
        let mut cursor = 0;
        for edit in &diff.edits {
            assert!(cursor <= edit.old_span.start && edit.old_span.end <= HEADER.len());
            assert!(edit.new_span.start <= edit.new_span.end);
            assert!(edit.new_span.end <= fixture.bytes.len());
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

fn frontier(fixture: &Fixture, module: &AuditModule, offset: usize) {
    let path = format!("{}/undecoded", fixture.path);
    let marker_path = format!("{path}/value_type_start");
    let opaque = at(module, &path);
    assert_eq!(opaque.span, fixture.failed);
    assert_eq!(opaque.feature.as_deref(), Some("unknown_declaration_type"));
    assert_eq!(opaque.standard_support.status, "unknown");
    let marker = at(module, &marker_path);
    assert_eq!(
        marker.span,
        Span {
            start: offset,
            end: offset + 1
        }
    );
    assert_eq!(marker.feature.as_deref(), Some("unknown_value_type"));
    assert_eq!(marker.standard_support.status, "unknown");
    assert!(module.standard.evidence.iter().any(|evidence| {
        evidence.path == marker_path && evidence.span == marker.span && evidence.status == "unknown"
    }));
    assert!(!module.standard.evidence.iter().any(|evidence| {
        evidence.path.starts_with(fixture.path)
            && evidence.span.start >= offset
            && evidence.status == "invalid_encoding"
    }));
    assert!(!regions(module).iter().any(|region| {
        region.path.starts_with(fixture.path)
            && region.path != path
            && region.path != marker_path
            && region.span.start >= fixture.failed.start
    }));
    assert!(!module.standard.validator_valid);
}

#[test]
fn unknown_type_field_stops_before_missing_or_bad_remaining_type_fields() {
    let cases: &[(&[u8], usize)] = &[
        (&[0x60, 1, 0xff, 0], 2), // Missing result count follows the unknown parameter.
        (&[0x60, 1, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10], 2),
        (&[0x5e, 0xff, 0], 1),       // Missing array field mutability.
        (&[0x5f, 1, 0xff, 0, 2], 2), // Invalid-looking mutability cannot be located.
        (&[0x4e, 1, 0x60, 1, 0xff, 0], 4),
        (&[0x50, 0, 0x60, 1, 0xff, 0], 4),
        // A known nonnegative continuation index does not hide the next
        // recursive member's unknown parameter type.
        (&[0x4e, 2, 0x5d, 0, 0x60, 1, 0x7a, 0], 6),
    ];
    for (entry, offset) in cases {
        let fixture = fixture(1, entry);
        check(&fixture, |_, module| {
            frontier(&fixture, module, fixture.failed.start + offset)
        });
    }
}

#[test]
fn unknown_import_type_precedes_truncated_ordinary_and_compact_group_fields() {
    let cases: &[(&[u8], usize)] = &[
        (&[0, 1, b'u', 3, 0xff, 0], 4), // Ordinary global; no mutability.
        (&[0, 1, b'u', 1, 0xff, 0], 4), // Ordinary table; no limits.
        (&[0, 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 3, 0xff, 0], 11),
        (&[0, 0, 0x7e, 1, 0xff, 0], 4), // Shared table type; no limits or names.
    ];
    for (entry, offset) in cases {
        let fixture = fixture(2, entry);
        check(&fixture, |_, module| {
            frontier(&fixture, module, fixture.failed.start + offset)
        });
        // A complete-looking Compact1 member inside the failed group never
        // publishes a separate declaration before the unknown second member.
    }
}

#[test]
fn unknown_table_reference_type_precedes_missing_limits_or_initializer() {
    for (entry, offset) in [(&[0xff, 0][..], 0), (&[0x40, 0, 0xff, 0, 0, 0][..], 2)] {
        let fixture = fixture(4, entry);
        check(&fixture, |_, module| {
            frontier(&fixture, module, fixture.failed.start + offset)
        });
    }
}

#[test]
fn unknown_global_type_precedes_missing_or_invalid_looking_mutability() {
    for entry in [&[0xff, 0][..], &[0xff, 0, 4][..]] {
        let fixture = fixture(6, entry);
        check(&fixture, |_, module| {
            frontier(&fixture, module, fixture.failed.start)
        });
    }
}

#[test]
fn known_element_mode_survives_unknown_reference_type_and_missing_item_count() {
    let cases: &[(&[u8], usize, &[&str])] = &[
        (&[5, 0xff, 0], 1, &["bulk_memory", "reference_types"]),
        (&[7, 0xff, 0], 1, &["bulk_memory", "reference_types"]),
        (&[6, 0, 0x41, 0, 0x0b, 0xff, 0], 5, &["reference_types"]),
        (&[5, 0x7a], 1, &["bulk_memory", "reference_types"]),
    ];
    for (entry, offset, features) in cases {
        let fixture = fixture(9, entry);
        check(&fixture, |profile, module| {
            frontier(&fixture, module, fixture.failed.start + offset);
            let path = format!("{}/undecoded", fixture.path);
            for feature in *features {
                assert!(module.standard.evidence.iter().any(|evidence| {
                    evidence.path == path
                        && evidence.span
                            == Span {
                                start: fixture.failed.start,
                                end: fixture.failed.start + 1,
                            }
                        && evidence.feature == *feature
                        && evidence.status
                            == if profile == Standard::Core1 {
                                "recognized_but_disabled"
                            } else {
                                "supported"
                            }
                }));
            }
        });
    }
}

#[test]
fn missing_bytes_prior_known_errors_and_unproved_offsets_do_not_invent_a_type_frontier() {
    // These fixed negatives stop before the apparent later unknown byte. The
    // last control uses an explicit reference constructor, whose FF00 is a
    // legitimate heap index encoding rather than a value-type constructor.
    let cases: &[(u8, &[u8], bool)] = &[
        (1, &[0x60, 1], true),
        (1, &[0x60, 1, 0x63], true),
        (1, &[0x60, 2, 0, 0xff, 0, 0], true),
        (1, &[0x60, 0x80, 0x80, 0x80, 0x80, 0x10, 0xff, 0], true),
        (2, &[1, 0xff, 1, b'u', 3, 0xff, 0, 0], true),
        (9, &[6, 0, 0x02, 0x40, 0x0b, 0xff, 0, 0], false),
        (9, &[6, 0, 0xff, 0x0b, 0xff, 0, 0], false),
        (1, &[0x4e, 2, 0x5d, 0x7f, 0x60, 1, 0x7a, 0], false),
        (1, &[0x50, 2, 0, 0, 0x60, 1, 0x7a, 0], false),
        (1, &[0x60, 1, 0x63, 0xff, 0, 0], false),
    ];
    for (id, entry, invalid) in cases {
        let fixture = fixture(*id, entry);
        check(&fixture, |_, module| {
            assert!(!regions(module).iter().any(|region| {
                region.path.starts_with(fixture.path)
                    && (region.path.ends_with("/value_type_start")
                        || region.feature.as_deref() == Some("unknown_declaration_type"))
            }));
            if *invalid {
                assert!(module.standard.evidence.iter().any(|evidence| {
                    evidence.path.starts_with(fixture.path)
                        && evidence.span.start >= fixture.failed.start
                        && evidence.status == "invalid_encoding"
                }));
            }
        });
    }
}
