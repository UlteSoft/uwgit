//! Fixed numeric/vector values in reference-only slots; no generated mutations.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const REASON: &str = "known numeric or vector value type is forbidden in a reference-only field";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

struct Case {
    id: u8,
    entry: &'static [u8],
    slot: usize,
}

struct Fixture {
    bytes: Vec<u8>,
    id: u8,
    path: &'static str,
    prior: Span,
    target: Span,
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
    if id != 2 {
        section(&mut bytes, 3, &[1, 0]);
    }
    if id == 9 {
        section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    }
    let (path, prior): (&str, &[u8]) = match id {
        2 => ("import[0]", &[0, 1, b'f', 0, 0]),
        4 => ("table[0]", &[0x70, 0, 0]),
        6 => ("global[0]", &[0x7f, 0, 0x41, 0, 0x0b]),
        9 => ("element[0]", &[0, 0x41, 0, 0x0b, 0]),
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
    let target = Span {
        start: prior.end,
        end: bytes.len(),
    };
    if id == 2 {
        section(&mut bytes, 3, &[1, 0]);
    }
    let code = section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
    let sentinel = Span {
        start: code + 3,
        end: code + 5,
    };
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        id,
        path,
        prior,
        target,
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

fn entry_path(fixture: &Fixture, index: usize) -> String {
    format!(
        "{}/{}[{index}]",
        fixture.path,
        if fixture.id == 2 { "group" } else { "entry" }
    )
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
        let prior = at(&module, &entry_path(fixture, 0));
        assert_eq!(prior.span, fixture.prior);
        assert_ne!(prior.standard_support.status, "unknown");
        for region in regions(&module) {
            assert!(region.span.start <= region.span.end && region.span.end <= fixture.bytes.len());
        }
        for row in &module.standard.evidence {
            assert!(row.span.start <= row.span.end && row.span.end <= fixture.bytes.len());
            assert_eq!(
                row.raw_hex,
                hex(&fixture.bytes[row.span.start..row.span.end])
            );
        }
        let json = serde_json::to_value(&module).unwrap();
        assert_eq!(json["byte_len"], fixture.bytes.len());
        assert_eq!(
            json["standard"]["selected_standard"],
            serde_json::to_value(profile).unwrap()
        );
        let constant = at(&module, "code[0]/function[0]/operator[0]");
        assert_eq!(constant.span, fixture.sentinel);
        assert_eq!(constant.standard_support.status, "supported");
        assert_eq!(
            &fixture.bytes[constant.span.start..constant.span.end],
            &[0x41, 42]
        );
        assert_eq!(
            at(&module, "code[0]/function[0]/operator[2]").description,
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

fn unpublished(fixture: &Fixture, module: &AuditModule) {
    let failed = entry_path(fixture, 1);
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.starts_with(&failed)));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path.starts_with(&failed)));
}

fn known(case: &Case) {
    let fixture = fixture(case.id, case.entry);
    check(&fixture, |_, module| {
        unpublished(&fixture, module);
        let carrier_path = format!("{}/undecoded", fixture.path);
        let carrier = at(module, &carrier_path);
        assert_eq!(carrier.span, fixture.target);
        assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(carrier.standard_support.status, "invalid_encoding");
        assert_eq!(carrier.standard_support.display, "binary");
        let path = error_path(&fixture);
        let child = at(module, &path);
        let span = Span {
            start: fixture.target.start + case.slot,
            end: fixture.target.start + case.slot + 1,
        };
        let field = if case.id == 9 {
            "element reference type"
        } else {
            "table reference type"
        };
        let description = format!(
            "{field}: {REASON}; only this field is diagnosed, remaining bytes stay undecoded"
        );
        assert_eq!(child.span, span);
        assert_eq!(child.description, description);
        assert_eq!(child.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(child.standard_support.status, "invalid_encoding");
        assert_eq!(child.standard_support.display, "binary");
        assert!(child.children.is_empty());
        assert_eq!(carrier.children.len(), 1);
        assert_eq!(carrier.children[0].path, path);
        assert!(matches!(case.entry[case.slot], 0x7b..=0x7f));
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == path)
            .collect();
        assert_eq!(rows.len(), 1);
        let raw = hex(&case.entry[case.slot..case.slot + 1]);
        assert_eq!(
            serde_json::to_value(rows[0]).unwrap(),
            serde_json::json!({
                "path": path, "span": span, "feature": "section_structure", "status": "invalid_encoding",
                "kind": "structure", "reason": description, "raw_hex": raw, "recognized": null
            })
        );
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(&carrier_path)
                && (row.status == "unknown"
                    || (row.span.start >= span.end && row.path != carrier_path))));
        let line = format!("invalid_encoding {path} [{}..{}) binary={raw} feature=section_structure recognized=None: {description}", span.start, span.end);
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|text| text.starts_with(&format!("invalid_encoding {path} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
    });
}

fn no_reference_error(fixture: &Fixture, module: &AuditModule) {
    assert!(!regions(module)
        .iter()
        .any(|region| region.path == error_path(fixture)));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.reason.contains(REASON)));
}

fn unknown(case: &Case, marker: bool) {
    let fixture = fixture(case.id, case.entry);
    check(&fixture, |_, module| {
        unpublished(&fixture, module);
        no_reference_error(&fixture, module);
        let carrier = at(module, &format!("{}/undecoded", fixture.path));
        assert_eq!(carrier.span, fixture.target);
        assert_eq!(carrier.standard_support.status, "unknown");
        assert_eq!(carrier.standard_support.display, "opaque");
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(&carrier.path) && row.status == "invalid_encoding"));
        if marker {
            let frontier = at(module, &format!("{}/value_type_start", carrier.path));
            assert_eq!(
                frontier.span,
                Span {
                    start: fixture.target.start + case.slot,
                    end: fixture.target.start + case.slot + 1
                }
            );
            assert_eq!(carrier.children.len(), 1);
            assert!(frontier.children.is_empty());
            assert!(!module.standard.evidence.iter().any(|row| row
                .path
                .starts_with(&carrier.path)
                && row.status != "unknown"
                && row.span.end > frontier.span.start));
        } else {
            assert!(carrier.children.is_empty());
        }
    });
}

#[test]
fn ordinary_table_reference_slots_reject_all_known_numeric_and_vector_values() {
    for case in [
        Case {
            id: 4,
            entry: &[0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 0,
        },
        Case {
            id: 4,
            entry: &[0x7e, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 0,
        },
        Case {
            id: 4,
            entry: &[0x7d, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 0,
        },
        Case {
            id: 4,
            entry: &[0x7c, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 0,
        },
        Case {
            id: 4,
            entry: &[0x7b, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 0,
        },
    ] {
        known(&case);
    }
}

#[test]
fn initialized_table_slots_start_after_the_complete_initializer_marker() {
    for case in [
        Case {
            id: 4,
            entry: &[0x40, 0, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 2,
        },
        Case {
            id: 4,
            entry: &[0x40, 0, 0x7e, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 2,
        },
        Case {
            id: 4,
            entry: &[0x40, 0, 0x7d, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 2,
        },
        Case {
            id: 4,
            entry: &[0x40, 0, 0x7c, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 2,
        },
        Case {
            id: 4,
            entry: &[0x40, 0, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 2,
        },
    ] {
        known(&case);
    }
}

#[test]
fn ordinary_table_imports_diagnose_the_reference_byte_after_names_and_kind() {
    for case in [
        Case {
            id: 2,
            entry: &[1, b'm', 1, b't', 1, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 1, b't', 1, 0x7e, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 1, b't', 1, 0x7d, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 1, b't', 1, 0x7c, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 1, b't', 1, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
    ] {
        known(&case);
    }
}

#[test]
fn compact1_prior_complete_member_does_not_publish_a_failed_import_group() {
    for case in [
        Case {
            id: 2,
            entry: &[
                1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            slot: 12,
        },
        Case {
            id: 2,
            entry: &[
                1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0x7e, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            slot: 12,
        },
        Case {
            id: 2,
            entry: &[
                1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0x7d, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            slot: 12,
        },
        Case {
            id: 2,
            entry: &[
                1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0x7c, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            slot: 12,
        },
        Case {
            id: 2,
            entry: &[
                1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            slot: 12,
        },
    ] {
        known(&case);
    }
}

#[test]
fn compact2_shared_table_type_stops_before_apparent_names_and_counts() {
    for case in [
        Case {
            id: 2,
            entry: &[1, b'm', 0, 0x7e, 1, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 0, 0x7e, 1, 0x7e, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 0, 0x7e, 1, 0x7d, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 0, 0x7e, 1, 0x7c, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 0, 0x7e, 1, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
    ] {
        known(&case);
    }
}

#[test]
fn passive_expression_elements_require_a_reference_type_before_item_count() {
    for case in [
        Case {
            id: 9,
            entry: &[5, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[5, 0x7e, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[5, 0x7d, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[5, 0x7c, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[5, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
    ] {
        known(&case);
    }
}

#[test]
fn active_expression_elements_reach_the_slot_only_after_the_root_end() {
    for case in [
        Case {
            id: 9,
            entry: &[6, 0, 0x41, 0, 0x0b, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 9,
            entry: &[6, 0, 0x41, 0, 0x0b, 0x7e, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 9,
            entry: &[6, 0, 0x41, 0, 0x0b, 0x7d, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 9,
            entry: &[6, 0, 0x41, 0, 0x0b, 0x7c, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 9,
            entry: &[6, 0, 0x41, 0, 0x0b, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
    ] {
        known(&case);
    }
}

#[test]
fn declarative_expression_elements_reject_the_same_five_single_byte_values() {
    for case in [
        Case {
            id: 9,
            entry: &[7, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[7, 0x7e, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[7, 0x7d, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[7, 0x7c, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[7, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
    ] {
        known(&case);
    }
}

#[test]
fn future_leading_bytes_in_all_eight_slots_stay_unknown_before_fake_errors() {
    for case in [
        Case {
            id: 4,
            entry: &[0x7a, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 0,
        },
        Case {
            id: 4,
            entry: &[0x40, 0, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 2,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 1, b't', 1, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 2,
            entry: &[
                1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0x7a, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            slot: 12,
        },
        Case {
            id: 2,
            entry: &[1, b'm', 0, 0x7e, 1, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 9,
            entry: &[5, 0x7a, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
        Case {
            id: 9,
            entry: &[6, 0, 0x41, 0, 0x0b, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 5,
        },
        Case {
            id: 9,
            entry: &[7, 0x7a, 0x80, 0x80, 0x80, 0x80, 0x10],
            slot: 1,
        },
    ] {
        unknown(&case, true);
    }
}

#[test]
fn constructor_internal_unknown_heap_bytes_and_resource_limits_are_not_slot_values() {
    for (case, marker) in [
        (
            Case {
                id: 4,
                entry: &[0x63, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
                slot: 0,
            },
            false,
        ),
        (
            Case {
                id: 4,
                entry: &[0x40, 0, 0x65, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
                slot: 2,
            },
            true,
        ),
        (
            Case {
                id: 2,
                entry: &[
                    1, b'm', 1, b't', 1, 0x63, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10,
                ],
                slot: 5,
            },
            false,
        ),
        (
            Case {
                id: 2,
                entry: &[
                    1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0x64, 0x7f, 0x80, 0x80, 0x80,
                    0x80, 0x10,
                ],
                slot: 12,
            },
            false,
        ),
        (
            Case {
                id: 2,
                entry: &[
                    1, b'm', 0, 0x7e, 1, 0x65, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10,
                ],
                slot: 5,
            },
            true,
        ),
        (
            Case {
                id: 9,
                entry: &[5, 0x63, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
                slot: 1,
            },
            false,
        ),
        (
            Case {
                id: 9,
                entry: &[
                    6, 0, 0x41, 0, 0x0b, 0x64, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10,
                ],
                slot: 5,
            },
            false,
        ),
        // Positive heap index1048576 has a legal s33 but exceeds PackedIndex's cap.
        (
            Case {
                id: 9,
                entry: &[7, 0x63, 0x80, 0x80, 0xc0, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
                slot: 1,
            },
            false,
        ),
    ] {
        unknown(&case, marker);
    }
}

#[test]
fn earlier_unknown_layouts_expressions_names_and_utf8_keep_their_ownership() {
    for (id, entry) in [
        (4, &[0x40, 1, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (9, &[8, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (
            9,
            &[
                6, 0, 0x41, 0, 0xff, 0x0b, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10,
            ][..],
        ),
        (
            9,
            &[6, 0, 2, 0x40, 0x0b, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10][..],
        ),
        (
            9,
            &[
                5, 0x70, 2, 0xd0, 0x70, 0xff, 0x0b, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10,
            ][..],
        ),
        (2, &[0xa1, 0x8d, 6, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (
            2,
            &[1, 0xff, 1, b't', 1, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10][..],
        ),
        (
            2,
            &[
                1, b'm', 0, 0x7f, 1, 1, 0xff, 1, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10,
            ][..],
        ),
    ] {
        let fixture = fixture(id, entry);
        check(&fixture, |_, module| {
            no_reference_error(&fixture, module);
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path.starts_with(&entry_path(&fixture, 2))));
            if id == 2 && entry[0] == 1 && entry[1] == 0xff {
                let child = at(module, "import[0]/undecoded/module_name/utf8");
                assert_eq!(
                    child.span,
                    Span {
                        start: fixture.target.start + 1,
                        end: fixture.target.start + 2
                    }
                );
                assert_eq!(child.standard_support.status, "invalid_encoding");
            } else if id == 2 && entry.starts_with(&[1, b'm', 0, 0x7f]) {
                let child = at(module, "import[0]/undecoded/item[0]/name/utf8");
                assert_eq!(
                    child.span,
                    Span {
                        start: fixture.target.start + 6,
                        end: fixture.target.start + 7
                    }
                );
                assert_eq!(child.standard_support.status, "invalid_encoding");
            } else if id == 2 && entry.starts_with(&[0xa1, 0x8d, 6]) {
                let carrier = at(module, "import[0]/undecoded");
                assert_eq!(carrier.span, fixture.target);
                assert_eq!(carrier.feature.as_deref(), Some("unknown"));
                assert_eq!(carrier.standard_support.status, "unknown");
                assert_eq!(carrier.standard_support.display, "opaque");
                assert!(carrier.children.is_empty());
            }
        });
    }
}

#[test]
fn the_same_five_values_remain_valid_value_types_in_global_declarations() {
    for entry in [
        &[0x7f, 0, 0x41, 0, 0x0b][..],
        &[0x7e, 0, 0x42, 0, 0x0b][..],
        &[0x7d, 0, 0x43, 0, 0, 0, 0, 0x0b][..],
        &[0x7c, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b][..],
        &[
            0x7b, 0, 0xfd, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b,
        ][..],
    ] {
        let fixture = fixture(6, entry);
        check(&fixture, |_, module| {
            no_reference_error(&fixture, module);
            let target = at(module, "global[0]/entry[1]");
            assert_eq!(target.span, fixture.target);
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == "global[0]/undecoded"));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path.starts_with(&target.path) && row.status == "invalid_encoding"));
        });
    }
}
