//! Handwritten scalar/count failures and wire, semantic and future controls.
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
const VECTORS: [u8; 11] = [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 13];

struct Case {
    entry: &'static [u8],
    field: &'static str,
    start: usize,
    end: usize,
}

struct Fixture {
    bytes: Vec<u8>,
    path: &'static str,
    payload: Span,
    failed: Span,
    prior: Option<Span>,
    later_code: Option<Span>,
    custom: usize,
}

fn name(id: u8) -> &'static str {
    match id {
        1 => "type[0]",
        2 => "import[0]",
        3 => "function[0]",
        4 => "table[0]",
        5 => "memory[0]",
        6 => "global[0]",
        7 => "export[0]",
        8 => "start[0]",
        9 => "element[0]",
        10 => "code[0]",
        11 => "data[0]",
        12 => "data_count[0]",
        13 => "tag[0]",
        42 => "unknown:42[0]",
        _ => unreachable!(),
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn later_code(bytes: &mut Vec<u8>) -> Span {
    let start = section(bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
    Span {
        start: start + 3,
        end: start + 5,
    }
}

fn finish(bytes: &mut Vec<u8>) -> usize {
    let start = bytes.len();
    section(bytes, 0, &[1, b'x', 0xa5]);
    start
}

fn count_fixture(id: u8, payload: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    let start = section(&mut bytes, id, payload);
    let payload = Span {
        start,
        end: bytes.len(),
    };
    // Code/data are already at the end of Core section order. Other cases
    // retain a separately framed later body; its signature need not be known.
    let later_code = if matches!(id, 10 | 11) {
        None
    } else {
        Some(later_code(&mut bytes))
    };
    let custom = finish(&mut bytes);
    Fixture {
        bytes,
        path: name(id),
        payload,
        failed: payload,
        prior: None,
        later_code,
        custom,
    }
}

fn scalar_fixture(id: u8, entry: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    if id != 3 {
        section(&mut bytes, 3, &[1, 0]);
    }
    let (body, prefix): (Vec<u8>, usize) = match id {
        3 => ([&[2, 0][..], entry].concat(), 2),
        7 => ([&[2, 1, b'p', 0, 0][..], entry].concat(), 5),
        8 | 12 => (entry.to_vec(), 0),
        _ => unreachable!(),
    };
    let start = section(&mut bytes, id, &body);
    let payload = Span {
        start,
        end: bytes.len(),
    };
    let failed = Span {
        start: start + prefix,
        end: bytes.len(),
    };
    let prior = if prefix == 0 {
        None
    } else {
        Some(Span {
            start: start + 1,
            end: failed.start,
        })
    };
    let later_code = Some(later_code(&mut bytes));
    if id == 12 {
        section(&mut bytes, 11, &[0]);
    }
    let custom = finish(&mut bytes);
    Fixture {
        bytes,
        path: name(id),
        payload,
        failed,
        prior,
        later_code,
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

fn child_path(fixture: &Fixture, suffix: &str) -> String {
    format!("{}/undecoded/{suffix}", fixture.path)
}

fn no_child(fixture: &Fixture, module: &AuditModule, suffix: &str) {
    let path = child_path(fixture, suffix);
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
        if let Some(prior) = fixture.prior {
            let region = at(&module, &format!("{}/entry[0]", fixture.path));
            assert_eq!(region.span, prior);
            assert_ne!(region.standard_support.status, "unknown");
        }
        if let Some(span) = fixture.later_code {
            let constant = at(&module, "code[0]/function[0]/operator[0]");
            assert_eq!(constant.span, span);
            assert_eq!(&fixture.bytes[span.start..span.end], &[0x41, 42]);
            assert_eq!(constant.standard_support.status, "supported");
            assert_eq!(
                at(&module, "code[0]/function[0]/operator[2]").description,
                "End"
            );
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

fn known(fixture: Fixture, suffix: &str, case: &Case) {
    check(&fixture, |_, module| {
        let carrier = at(module, &format!("{}/undecoded", fixture.path));
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(carrier.standard_support.status, "invalid_encoding");
        assert_eq!(carrier.standard_support.display, "binary");
        let path = child_path(&fixture, suffix);
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
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|evidence| evidence.path == path)
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].span, child.span);
        assert_eq!(rows[0].raw_hex, hex(&case.entry[case.start..case.end]));
        assert_eq!(rows[0].recognized, None);
        assert_eq!(rows[0].reason, child.description);
        if fixture.prior.is_some() {
            let unpublished = format!("{}/entry[1]", fixture.path);
            assert!(!regions(module).iter().any(|region| {
                region.path == unpublished || region.path.starts_with(&format!("{unpublished}/"))
            }));
            assert!(!module.standard.evidence.iter().any(|evidence| {
                evidence.path == unpublished
                    || evidence.path.starts_with(&format!("{unpublished}/"))
            }));
        }
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
fn all_known_vector_sections_locate_outer_count_overflow_before_suffix_bytes() {
    let case = Case {
        entry: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
        field: "section entry count",
        start: 0,
        end: 5,
    };
    for id in VECTORS {
        known(count_fixture(id, case.entry), "count_error", &case);
    }
}

#[test]
fn all_known_vector_sections_keep_empty_count_eof_inside_their_own_section() {
    let case = Case {
        entry: &[],
        field: "section entry count",
        start: 0,
        end: 0,
    };
    for id in VECTORS {
        known(count_fixture(id, case.entry), "count_error", &case);
    }
}

#[test]
fn count_guards_distinguish_integer_failures_missing_entries_padding_and_unknown_sections() {
    for (id, case) in [
        (
            2,
            Case {
                entry: &[0x80, 0x80, 0x80, 0x80, 0x80, 0xa5],
                field: "section entry count",
                start: 0,
                end: 5,
            },
        ),
        (
            10,
            Case {
                entry: &[0x80, 0x80],
                field: "section entry count",
                start: 0,
                end: 2,
            },
        ),
    ] {
        known(count_fixture(id, case.entry), "count_error", &case);
    }
    let unknown = count_fixture(42, &[0x80, 0x80, 0x80, 0x80, 0x10]);
    check(&unknown, |_, module| {
        no_child(&unknown, module, "count_error");
        let section = module
            .sections
            .iter()
            .find(|section| section.id == 42)
            .unwrap();
        assert_eq!(section.status, "opaque");
        assert_eq!(
            at(module, &format!("{}/opaque", unknown.path)).span,
            unknown.payload
        );
    });
    let padded = count_fixture(1, &[0x81, 0x80, 0x80, 0x80, 0, 0x60, 0, 0]);
    check(&padded, |_, module| {
        no_child(&padded, module, "count_error");
        assert_eq!(
            at(module, "type[0]/count").span,
            Span {
                start: padded.payload.start,
                end: padded.payload.start + 5
            }
        );
        assert_eq!(
            at(module, "type[0]/type[0]").span,
            Span {
                start: padded.payload.start + 5,
                end: padded.payload.end
            }
        );
    });
    for id in [1, 2] {
        let missing_entry = count_fixture(id, &[1]);
        check(&missing_entry, |_, module| {
            no_child(&missing_entry, module, "count_error");
            assert_eq!(
                at(module, &format!("{}/count", missing_entry.path)).span,
                missing_entry.payload
            );
        });
    }
    let trailing = count_fixture(1, &[0, 0x80, 0x80, 0x80, 0x80, 0x10]);
    check(&trailing, |_, module| {
        no_child(&trailing, module, "count_error");
        assert_eq!(
            at(module, "type[0]/count").span,
            Span {
                start: trailing.payload.start,
                end: trailing.payload.start + 1
            }
        );
        let suffix = at(module, "type[0]/trailing_bytes");
        assert_eq!(
            suffix.span,
            Span {
                start: trailing.payload.start + 1,
                end: trailing.payload.end
            }
        );
        assert_eq!(suffix.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(suffix.standard_support.status, "invalid_encoding");
        assert!(suffix.children.is_empty());
        for prefix in ["type[0]/entry[", "type[0]/group[", "type[0]/type["] {
            assert!(!regions(module)
                .iter()
                .any(|region| region.path.starts_with(prefix)));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|evidence| evidence.path.starts_with(prefix)));
        }
    });
}

#[test]
fn function_type_indices_have_precise_failures_but_legal_five_byte_padding() {
    for case in [
        Case {
            entry: &[],
            field: "function type index",
            start: 0,
            end: 0,
        },
        Case {
            entry: &[0x80],
            field: "function type index",
            start: 0,
            end: 1,
        },
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "function type index",
            start: 0,
            end: 5,
        },
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x80, 0xa5],
            field: "function type index",
            start: 0,
            end: 5,
        },
    ] {
        known(scalar_fixture(3, case.entry), "function_error", &case);
    }
    let padded = scalar_fixture(3, &[0x80, 0x80, 0x80, 0x80, 0]);
    check(&padded, |_, module| {
        no_child(&padded, module, "function_error");
        assert_eq!(at(module, "function[0]/entry[1]").span, padded.failed);
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(padded.path) && row.status == "invalid_encoding"));
    });
}

#[test]
fn export_name_length_and_partial_payload_errors_cover_the_whole_wire_field() {
    for case in [
        Case {
            entry: &[],
            field: "export name",
            start: 0,
            end: 0,
        },
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "export name",
            start: 0,
            end: 5,
        },
        Case {
            entry: &[3, b'a', b'b'],
            field: "export name",
            start: 0,
            end: 3,
        },
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x80, 0xa5],
            field: "export name",
            start: 0,
            end: 5,
        },
    ] {
        known(scalar_fixture(7, case.entry), "export_error", &case);
    }
}

#[test]
fn export_kind_eof_and_every_known_export_index_have_precise_fields() {
    for case in [
        Case {
            entry: &[0],
            field: "export kind",
            start: 1,
            end: 1,
        },
        Case {
            entry: &[0, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "export function index",
            start: 2,
            end: 7,
        },
        Case {
            entry: &[0, 1, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "export table index",
            start: 2,
            end: 7,
        },
        Case {
            entry: &[0, 2, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "export memory index",
            start: 2,
            end: 7,
        },
        Case {
            entry: &[0, 3, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "export global index",
            start: 2,
            end: 7,
        },
        Case {
            entry: &[0, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "export tag index",
            start: 2,
            end: 7,
        },
    ] {
        known(scalar_fixture(7, case.entry), "export_error", &case);
    }
}

#[test]
fn export_utf8_exact_kind_resource_and_future_controls_keep_their_original_boundaries() {
    for (entry, suffix) in [
        (&[1, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10][..], "name/utf8"),
        (
            &[0, 0x20, 0x80, 0x80, 0x80, 0x80, 0x10][..],
            "external_kind",
        ),
    ] {
        let fixture = scalar_fixture(7, entry);
        check(&fixture, |_, module| {
            no_child(&fixture, module, "export_error");
            let old = at(module, &child_path(&fixture, suffix));
            assert_eq!(
                old.span,
                Span {
                    start: fixture.failed.start + 1,
                    end: fixture.failed.start + 2
                }
            );
            assert_eq!(old.standard_support.status, "invalid_encoding");
            assert_eq!(at(module, "export[0]/undecoded").children.len(), 1);
        });
    }
    for entry in [
        &[0, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10][..],
        &[0xa1, 0x8d, 6, 0x80, 0x80, 0x80, 0x80, 0x10][..],
    ] {
        let fixture = scalar_fixture(7, entry);
        check(&fixture, |_, module| {
            no_child(&fixture, module, "export_error");
            assert_eq!(
                at(module, "export[0]/undecoded").standard_support.status,
                "unknown"
            );
        });
    }
    let padded = scalar_fixture(7, &[0x80, 0, 0, 0x80, 0]);
    check(&padded, |_, module| {
        no_child(&padded, module, "export_error");
        assert_eq!(at(module, "export[0]/entry[1]").span, padded.failed);
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(padded.path) && row.status == "invalid_encoding"));
    });
}

#[test]
fn start_function_index_failures_locate_the_bounded_single_scalar() {
    for case in [
        Case {
            entry: &[],
            field: "start function index",
            start: 0,
            end: 0,
        },
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "start function index",
            start: 0,
            end: 5,
        },
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x80, 0xa5],
            field: "start function index",
            start: 0,
            end: 5,
        },
    ] {
        known(scalar_fixture(8, case.entry), "start_error", &case);
    }
}

#[test]
fn data_count_failures_are_scalar_errors_not_vector_entry_count_errors() {
    for case in [
        Case {
            entry: &[],
            field: "data count",
            start: 0,
            end: 0,
        },
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "data count",
            start: 0,
            end: 5,
        },
        Case {
            entry: &[0x80, 0x80, 0x80, 0x80, 0x80, 0xa5],
            field: "data count",
            start: 0,
            end: 5,
        },
    ] {
        let fixture = scalar_fixture(12, case.entry);
        known(fixture, "data_count_error", &case);
    }
}

#[test]
fn padded_semantically_invalid_and_trailing_scalars_preserve_existing_ownership() {
    for id in [8, 12] {
        let suffix = if id == 8 {
            "start_error"
        } else {
            "data_count_error"
        };
        let padded = scalar_fixture(id, &[0x80, 0x80, 0x80, 0x80, 0]);
        check(&padded, |_, module| {
            no_child(&padded, module, suffix);
            no_child(&padded, module, "count_error");
            assert_eq!(
                at(module, &format!("{}/value", padded.path)).span,
                padded.payload
            );
        });
        let semantics = scalar_fixture(id, &[1]);
        check(&semantics, |profile, module| {
            no_child(&semantics, module, suffix);
            no_child(&semantics, module, "count_error");
            assert_eq!(
                at(module, &format!("{}/value", semantics.path)).description,
                "1"
            );
            if profile == Standard::AllKnown {
                assert!(!module.standard.validator_valid);
            }
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(
                    |row| row.path.starts_with(semantics.path) && row.status == "invalid_encoding"
                ));
        });
        let trailing = scalar_fixture(id, &[0, 0x80, 0x80, 0x80, 0x80, 0x10]);
        check(&trailing, |_, module| {
            no_child(&trailing, module, suffix);
            no_child(&trailing, module, "count_error");
            assert_eq!(
                at(module, &format!("{}/value", trailing.path)).span,
                Span {
                    start: trailing.payload.start,
                    end: trailing.payload.start + 1
                }
            );
            let carrier = at(module, &format!("{}/undecoded", trailing.path));
            assert_eq!(
                carrier.span,
                Span {
                    start: trailing.payload.start + 1,
                    end: trailing.payload.end
                }
            );
            assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
            assert!(carrier.children.is_empty());
            assert_eq!(carrier.description, "trailing bytes after scalar payload");
        });
    }
}
