//! Fixed segment metadata/body-framing failures; expression owners stay separate.
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
    id: u8,
    path: &'static str,
    prior: Span,
    failed: Span,
    sentinel: Option<Span>,
    custom: usize,
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn complete_code(bytes: &mut Vec<u8>) -> Span {
    let start = section(bytes, 10, &[2, 2, 0, 0x0b, 5, 0, 0x41, 42, 0x1a, 0x0b]);
    Span {
        start: start + 6,
        end: start + 8,
    }
}

fn fixture(id: u8, entry: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[2, 0, 0]);
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 0, 1]);
    let mut sentinel = if id == 11 {
        Some(complete_code(&mut bytes))
    } else {
        None
    };
    let (path, prior): (&str, &[u8]) = match id {
        9 => ("element[0]", &[0, 0x41, 0, 0x0b, 0]),
        10 => ("code[0]", &[2, 0, 0x0b]),
        11 => ("data[0]", &[1, 1, 0xa5]),
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
    if id == 9 {
        sentinel = Some(complete_code(&mut bytes));
    }
    if id == 10 {
        section(&mut bytes, 11, &[0]);
    }
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        id,
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

fn entry_path(fixture: &Fixture, index: usize) -> String {
    format!(
        "{}/{}[{index}]",
        fixture.path,
        if fixture.id == 10 {
            "function"
        } else {
            "entry"
        }
    )
}

fn error_path(fixture: &Fixture) -> String {
    format!(
        "{}/undecoded/{}_error",
        fixture.path,
        match fixture.id {
            9 => "element",
            10 => "code",
            11 => "data",
            _ => unreachable!(),
        }
    )
}

fn no_new_error(fixture: &Fixture, module: &AuditModule) {
    let path = error_path(fixture);
    assert!(!regions(module).iter().any(|region| region.path == path));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|evidence| evidence.path == path));
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
        if let Some(span) = fixture.sentinel {
            let constant = at(&module, "code[0]/function[1]/operator[0]");
            assert_eq!(constant.span, span);
            assert_eq!(&fixture.bytes[span.start..span.end], &[0x41, 42]);
            assert_eq!(constant.standard_support.status, "supported");
        } else {
            assert_eq!(
                at(&module, "code[0]/function[0]/operator[0]").description,
                "End"
            );
            assert!(module
                .sections
                .iter()
                .any(|section| section.id == 11 && section.status == "decoded"));
        }
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
        let mut cursor = 0;
        let mut replay = Vec::new();
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
        let carrier = at(module, &format!("{}/undecoded", fixture.path));
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
        assert_eq!(carrier.children.len(), 1);
        assert_eq!(carrier.children[0].path, path);
        assert!(child.description.starts_with(&format!("{}:", case.field)));
        assert!(child.description.contains("only this field is diagnosed"));
        let unpublished = entry_path(&fixture, 1);
        assert!(!regions(module)
            .iter()
            .any(|region| region.path == unpublished
                || region.path.starts_with(&format!("{unpublished}/"))));
        assert!(
            !module
                .standard
                .evidence
                .iter()
                .any(|row| row.path == unpublished
                    || row.path.starts_with(&format!("{unpublished}/")))
        );
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == path)
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].span, child.span);
        assert_eq!(rows[0].raw_hex, hex(&case.entry[case.start..case.end]));
        assert_eq!(rows[0].recognized, None);
        assert_eq!(rows[0].reason, child.description);
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

#[test]
fn element_flags_and_table_indices_fail_only_at_their_known_fields() {
    for case in [
        Case {
            id: 9,
            entry: &[],
            field: "element flags",
            start: 0,
            end: 0,
        },
        Case {
            id: 9,
            entry: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element flags",
            start: 0,
            end: 5,
        },
        Case {
            id: 9,
            entry: &[2, 0x80],
            field: "element table index",
            start: 1,
            end: 2,
        },
        Case {
            id: 9,
            entry: &[2, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element table index",
            start: 1,
            end: 6,
        },
    ] {
        known(&case);
    }
}

#[test]
fn element_kind_and_reference_type_ranges_include_cloned_heap_type_failures() {
    for case in [
        Case {
            id: 9,
            entry: &[1],
            field: "element kind",
            start: 1,
            end: 1,
        },
        Case {
            id: 9,
            entry: &[5],
            field: "element reference type",
            start: 1,
            end: 1,
        },
        Case {
            id: 9,
            entry: &[5, 0x63, 0x80],
            field: "element reference type",
            start: 1,
            end: 3,
        },
        Case {
            id: 9,
            entry: &[5, 0x64, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element reference type",
            start: 1,
            end: 7,
        },
    ] {
        known(&case);
    }
}

#[test]
fn element_item_counts_require_a_complete_strict_root_offset_before_later_fields() {
    for case in [
        Case {
            id: 9,
            entry: &[1, 0],
            field: "element item count",
            start: 2,
            end: 2,
        },
        Case {
            id: 9,
            entry: &[1, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element item count",
            start: 2,
            end: 7,
        },
        Case {
            id: 9,
            entry: &[0, 0x41, 0, 0x0b],
            field: "element item count",
            start: 4,
            end: 4,
        },
        Case {
            id: 9,
            entry: &[2, 0, 0x41, 0, 0x0b, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element item count",
            start: 6,
            end: 11,
        },
        Case {
            id: 9,
            entry: &[4, 0x41, 0, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element item count",
            start: 4,
            end: 9,
        },
        Case {
            id: 9,
            entry: &[6, 0, 0x41, 0, 0x0b, 0x70],
            field: "element item count",
            start: 6,
            end: 6,
        },
        Case {
            id: 9,
            entry: &[7, 0x70],
            field: "element item count",
            start: 2,
            end: 2,
        },
    ] {
        known(&case);
    }
}

#[test]
fn function_index_element_items_do_not_publish_a_partial_segment() {
    for case in [
        Case {
            id: 9,
            entry: &[1, 0, 1],
            field: "element function index",
            start: 3,
            end: 3,
        },
        Case {
            id: 9,
            entry: &[1, 0, 1, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element function index",
            start: 3,
            end: 8,
        },
        Case {
            id: 9,
            entry: &[0, 0x41, 0, 0x0b, 1, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element function index",
            start: 5,
            end: 10,
        },
        Case {
            id: 9,
            entry: &[3, 0, 2, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "element function index",
            start: 4,
            end: 9,
        },
    ] {
        known(&case);
    }
}

#[test]
fn data_flags_and_explicit_memory_indices_have_distinct_error_fields() {
    for case in [
        Case {
            id: 11,
            entry: &[],
            field: "data flags",
            start: 0,
            end: 0,
        },
        Case {
            id: 11,
            entry: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "data flags",
            start: 0,
            end: 5,
        },
        Case {
            id: 11,
            entry: &[2],
            field: "data memory index",
            start: 1,
            end: 1,
        },
        Case {
            id: 11,
            entry: &[2, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "data memory index",
            start: 1,
            end: 6,
        },
    ] {
        known(&case);
    }
}

#[test]
fn data_length_and_partial_payload_eof_stop_at_the_section_boundary() {
    for case in [
        Case {
            id: 11,
            entry: &[1],
            field: "data byte count",
            start: 1,
            end: 1,
        },
        Case {
            id: 11,
            entry: &[1, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "data byte count",
            start: 1,
            end: 6,
        },
        Case {
            id: 11,
            entry: &[2, 0, 0x41, 0, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "data byte count",
            start: 5,
            end: 10,
        },
        Case {
            id: 11,
            entry: &[1, 3, 0xaa, 0xbb],
            field: "data bytes",
            start: 2,
            end: 4,
        },
        Case {
            id: 11,
            entry: &[0, 0x41, 0, 0x0b, 3, 0xaa],
            field: "data bytes",
            start: 5,
            end: 6,
        },
    ] {
        known(&case);
    }
}

#[test]
fn code_body_size_and_declared_body_bytes_do_not_borrow_following_sections() {
    for case in [
        Case {
            id: 10,
            entry: &[],
            field: "function body size",
            start: 0,
            end: 0,
        },
        Case {
            id: 10,
            entry: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "function body size",
            start: 0,
            end: 5,
        },
        Case {
            id: 10,
            entry: &[0x80, 0x80, 0x80, 0x80, 0x80, 0xa5],
            field: "function body size",
            start: 0,
            end: 5,
        },
        Case {
            id: 10,
            entry: &[4, 0, 0x0b],
            field: "function body bytes",
            start: 1,
            end: 3,
        },
    ] {
        known(&case);
    }
}

#[test]
fn unknown_segment_layouts_types_resources_and_operators_never_authorize_fake_metadata() {
    for (id, entry) in [
        (9, &[8, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (9, &[1, 1, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (9, &[5, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (
            9,
            &[5, 0x63, 0x80, 0x80, 0xc0, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..],
        ),
        (11, &[3, 0x80, 0x80, 0x80, 0x80, 0x10][..]),
        (
            11,
            &[0, 0x41, 0, 0xff, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10][..],
        ),
        (
            9,
            &[
                0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10,
            ][..],
        ),
    ] {
        let fixture = fixture(id, entry);
        check(&fixture, |_, module| {
            no_new_error(&fixture, module);
            assert!(!regions(module)
                .iter()
                .any(|region| region.path.starts_with(&entry_path(&fixture, 2))));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path.starts_with(&entry_path(&fixture, 2))));
        });
    }
}

#[test]
fn incomplete_offsets_items_and_complete_body_internal_failures_keep_their_expression_owners() {
    for (id, entry, owner) in [
        (
            9,
            &[0, 2, 0x40, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10][..],
            "offset",
        ),
        (
            11,
            &[0, 2, 0x40, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10][..],
            "offset",
        ),
        (
            9,
            &[
                5, 0x70, 2, 0xd0, 0x70, 0xff, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x10,
            ][..],
            "item[0]",
        ),
        (9, &[0][..], "offset"),
        (11, &[0][..], "offset"),
    ] {
        let fixture = fixture(id, entry);
        check(&fixture, |_, module| {
            no_new_error(&fixture, module);
            let owner_path = format!("{}/{owner}", entry_path(&fixture, 1));
            at(module, &owner_path);
            assert!(!regions(module)
                .iter()
                .any(|region| region.path.starts_with(&entry_path(&fixture, 2))));
            if owner == "item[0]" {
                assert!(!regions(module).iter().any(|region| region
                    .path
                    .starts_with(&format!("{}/item[1]", entry_path(&fixture, 1)))));
            }
        });
    }
    for (entry, start, feature) in [
        (&[0][..], 1, "invalid_encoding"),
        (&[2, 0x80, 0x80][..], 1, "invalid_encoding"),
        (&[3, 0, 0x41, 0x80][..], 2, "invalid_encoding"),
        (&[3, 0, 0xff, 0x0b][..], 2, "unknown"),
    ] {
        let fixture = fixture(10, entry);
        check(&fixture, |_, module| {
            no_new_error(&fixture, module);
            let path = entry_path(&fixture, 1);
            assert_eq!(at(module, &path).span, fixture.failed);
            assert_eq!(
                at(module, &format!("{path}/body_size")).span,
                Span {
                    start: fixture.failed.start,
                    end: fixture.failed.start + 1
                }
            );
            let opaque = at(module, &format!("{path}/opaque"));
            assert_eq!(
                opaque.span,
                Span {
                    start: fixture.failed.start + start,
                    end: fixture.failed.end
                }
            );
            assert_eq!(opaque.feature.as_deref(), Some(feature));
        });
    }
}

#[test]
fn padded_u32_fields_and_data_payload_fake_opcodes_remain_known_wire() {
    for (id, entry) in [
        (
            9,
            &[1, 0, 0x81, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0][..],
        ),
        (9, &[2, 0x80, 0x80, 0x80, 0x80, 0, 0x41, 0, 0x0b, 0, 0][..]),
        (11, &[1, 0x81, 0x80, 0x80, 0x80, 0, 0xa5][..]),
        (10, &[0x82, 0x80, 0x80, 0x80, 0, 0, 0x0b][..]),
    ] {
        let fixture = fixture(id, entry);
        check(&fixture, |_, module| {
            no_new_error(&fixture, module);
            let path = entry_path(&fixture, 1);
            assert_eq!(at(module, &path).span, fixture.failed);
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path.starts_with(fixture.path) && row.status == "invalid_encoding"));
            if id == 11 {
                assert_eq!(
                    at(module, &format!("{path}/bytes")).span,
                    Span {
                        start: fixture.failed.end - 1,
                        end: fixture.failed.end
                    }
                );
                assert!(!regions(module)
                    .iter()
                    .any(|region| region.path.starts_with(&path)
                        && region.path.contains("operator[")));
            }
            if id == 10 {
                assert_eq!(
                    at(module, &format!("{path}/body_size")).span,
                    Span {
                        start: fixture.failed.start,
                        end: fixture.failed.start + 5
                    }
                );
            }
        });
    }
}

#[test]
fn all_eight_element_modes_keep_complete_zero_item_entries() {
    for entry in [
        &[0, 0x41, 0, 0x0b, 0][..],
        &[1, 0, 0][..],
        &[2, 0, 0x41, 0, 0x0b, 0, 0][..],
        &[3, 0, 0][..],
        &[4, 0x41, 0, 0x0b, 0][..],
        &[5, 0x70, 0][..],
        &[6, 0, 0x41, 0, 0x0b, 0x70, 0][..],
        &[7, 0x70, 0][..],
    ] {
        let fixture = fixture(9, entry);
        check(&fixture, |_, module| {
            no_new_error(&fixture, module);
            assert_eq!(at(module, &entry_path(&fixture, 1)).span, fixture.failed);
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path.starts_with(fixture.path) && row.status == "invalid_encoding"));
        });
    }
}
