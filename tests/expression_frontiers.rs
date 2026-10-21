//! Hand-written unframed expression boundaries; no mutation search or fuzzing.
use wasm_git::{
    audit::{self, AuditDiff, AuditModule, Region, Span},
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
    section_end: usize,
}

fn fixture(id: u8, payload: &[u8]) -> Fixture {
    assert!(payload.len() < 128);
    let mut bytes = HEADER.to_vec();
    match id {
        9 => bytes.extend_from_slice(&[4, 4, 1, 0x70, 0, 1]),
        11 => bytes.extend_from_slice(&[5, 3, 1, 0, 1]),
        _ => unreachable!(),
    }
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    bytes.extend_from_slice(payload);
    let section_end = bytes.len();
    bytes.extend_from_slice(&[0, 3, 1, b'x', 0xa5]);
    Fixture { bytes, section_end }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
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

fn physical(module: &AuditModule, bytes: &[u8], path: &str, start: usize, end: usize) {
    let region = at(module, path);
    assert_eq!(region.span, Span { start, end }, "{path}");
    for evidence in module
        .standard
        .evidence
        .iter()
        .filter(|entry| entry.path == path)
    {
        assert_eq!(
            evidence.raw_hex,
            hex(&bytes[evidence.span.start..evidence.span.end])
        );
    }
}

fn known_const(module: &AuditModule, fixture: &Fixture, path: &str, start: usize) {
    physical(module, &fixture.bytes, path, start, start + 2);
    let region = at(module, path);
    assert_eq!(&fixture.bytes[start..start + 2], &[0x41, 0]);
    assert_eq!(region.standard_support.status, "supported");
}

fn unknown(module: &AuditModule, fixture: &Fixture, path: &str, start: usize) {
    physical(module, &fixture.bytes, path, start, fixture.section_end);
    let region = at(module, path);
    assert!(matches!(
        region.feature.as_deref(),
        Some("unknown" | "unknown_value_type")
    ));
    assert_eq!(region.standard_support.status, "unknown");
    assert!(module.standard.evidence.iter().any(|entry| {
        entry.path == path
            && entry.span == region.span
            && entry.status == "unknown"
            && entry.raw_hex == hex(&fixture.bytes[start..fixture.section_end])
    }));
    // An apparent End after the unknown prefix proves no payload, next entry,
    // later instruction, or encoding error within the same unframed section.
    assert!(!regions(module).iter().any(|entry| {
        start <= entry.span.start && entry.span.start < fixture.section_end && entry.path != path
    }));
    assert!(!module.standard.evidence.iter().any(|entry| {
        start <= entry.span.start
            && entry.span.start < fixture.section_end
            && (entry.status != "unknown" || entry.path != path)
    }));
}

fn invalid(module: &AuditModule, fixture: &Fixture, path: &str, start: usize) {
    physical(module, &fixture.bytes, path, start, fixture.section_end);
    assert_eq!(at(module, path).standard_support.status, "invalid_encoding");
    assert!(module.standard.evidence.iter().any(|entry| {
        entry.path == path
            && entry.status == "invalid_encoding"
            && entry.span
                == Span {
                    start,
                    end: fixture.section_end,
                }
    }));
}

fn edit_replay(diff: &AuditDiff, old: &[u8], new: &[u8]) {
    let (mut old_cursor, mut new_cursor) = (0, 0);
    let mut replay = Vec::new();
    for edit in &diff.edits {
        assert!(old_cursor <= edit.old_span.start && edit.old_span.end <= old.len());
        assert!(new_cursor <= edit.new_span.start && edit.new_span.end <= new.len());
        assert_eq!(
            &old[old_cursor..edit.old_span.start],
            &new[new_cursor..edit.new_span.start]
        );
        assert_eq!(
            unhex(&edit.old_hex),
            old[edit.old_span.start..edit.old_span.end]
        );
        assert_eq!(
            unhex(&edit.new_hex),
            new[edit.new_span.start..edit.new_span.end]
        );
        replay.extend_from_slice(&old[old_cursor..edit.old_span.start]);
        replay.extend_from_slice(&unhex(&edit.new_hex));
        old_cursor = edit.old_span.end;
        new_cursor = edit.new_span.end;
    }
    assert_eq!(&old[old_cursor..], &new[new_cursor..]);
    replay.extend_from_slice(&old[old_cursor..]);
    assert_eq!(replay, new);
}

fn check(fixture: &Fixture, mut inspect: impl FnMut(Standard, &AuditModule)) {
    // A fixed valid module gives byte comparison both shared and changed gaps.
    let old = self::fixture(11, &[1, 0, 0x41, 0, 0x0b, 2, 0xaa, 0xbb]).bytes;
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        for region in regions(&module) {
            assert!(region.span.start <= region.span.end);
            assert!(region.span.end <= fixture.bytes.len());
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
        assert_eq!(
            custom.span,
            Span {
                start: fixture.section_end,
                end: fixture.section_end + 5,
            }
        );
        physical(
            &module,
            &fixture.bytes,
            "custom[0]/payload/opaque",
            fixture.section_end + 4,
            fixture.section_end + 5,
        );
        inspect(profile, &module);
        let diff = audit::compare_with_standard(&old, &fixture.bytes, profile).unwrap();
        edit_replay(&diff, &old, &fixture.bytes);
        let raw_edits: Vec<_> = diff
            .edits
            .iter()
            .map(|edit| {
                (
                    edit.old_span,
                    edit.new_span,
                    edit.old_hex.clone(),
                    edit.new_hex.clone(),
                )
            })
            .collect();
        if let Some(previous) = &expected_edits {
            assert_eq!(previous, &raw_edits);
        } else {
            expected_edits = Some(raw_edits);
        }
    }
    for (before, after) in [
        (old.as_slice(), fixture.bytes.as_slice()),
        (fixture.bytes.as_slice(), old.as_slice()),
    ] {
        let patch = wasm_git::patch::create(before, after).unwrap();
        let decoded = BytePatch::from_bytes(&patch.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded.apply(before).unwrap(), after);
    }
}

#[test]
fn data_unknown_select_precedes_apparent_length_truncation_overflow_or_short_payload() {
    for payload in [
        &[2, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x80][..],
        &[
            2, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ][..],
        &[2, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 3, 0xa5][..],
        &[2, 0, 0x41, 0, 0x1c, 1, 0x7a, 0x0b, 0x80][..],
    ] {
        let fixture = fixture(11, payload);
        check(&fixture, |_, module| {
            known_const(module, &fixture, "data[0]/entry[0]/offset/operator[0]", 17);
            unknown(module, &fixture, "data[0]/entry[0]/offset/opaque", 19);
            assert!(!regions(module)
                .iter()
                .any(|entry| entry.path == "data[0]/entry[0]/bytes"));
        });
    }
}

#[test]
fn explicit_memory_index_does_not_frame_data_after_an_unknown_offset_type() {
    let fixture = fixture(11, &[2, 2, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x80]);
    check(&fixture, |_, module| {
        physical(module, &fixture.bytes, "data[0]/entry[0]/header", 16, 18);
        assert!(at(module, "data[0]/entry[0]")
            .description
            .contains("active memory=0"));
        known_const(module, &fixture, "data[0]/entry[0]/offset/operator[0]", 18);
        unknown(module, &fixture, "data[0]/entry[0]/offset/opaque", 20);
    });
}

#[test]
fn completed_data_entry_remains_readable_before_the_unknown_expression_frontier() {
    let fixture = fixture(
        11,
        &[
            3, 1, 2, 0x41, 0x42, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x80,
        ],
    );
    check(&fixture, |_, module| {
        physical(module, &fixture.bytes, "data[0]/entry[0]", 16, 20);
        physical(module, &fixture.bytes, "data[0]/entry[0]/bytes", 18, 20);
        assert_eq!(&fixture.bytes[18..20], &[0x41, 0x42]);
        physical(module, &fixture.bytes, "data[0]/entry[1]/header", 20, 21);
        known_const(module, &fixture, "data[0]/entry[1]/offset/operator[0]", 21);
        unknown(module, &fixture, "data[0]/entry[1]/offset/opaque", 23);
        assert!(!regions(module)
            .iter()
            .any(|entry| entry.path.starts_with("data[0]/entry[2]")));
    });
}

#[test]
fn apparent_successful_end_and_data_length_cannot_authorize_a_later_entry() {
    for payload in [
        &[2, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0, 1, 1, 0xa5][..],
        &[2, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0, 0][..],
    ] {
        let fixture = fixture(11, payload);
        check(&fixture, |_, module| {
            known_const(module, &fixture, "data[0]/entry[0]/offset/operator[0]", 17);
            unknown(module, &fixture, "data[0]/entry[0]/offset/opaque", 19);
            assert!(!regions(module).iter().any(|entry| {
                entry.path == "data[0]/entry[0]/bytes" || entry.path.starts_with("data[0]/entry[1]")
            }));
        });
    }
}

#[test]
fn element_offset_unknown_type_precedes_apparent_item_count_and_reference_type() {
    // The table prefix is one byte longer than the memory prefix: this
    // element section has payload origin16, rather than the data origin15.
    for (payload, constant_start) in [
        (&[1, 4, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x80][..], 18),
        (&[1, 6, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x63, 0][..], 19),
    ] {
        let fixture = fixture(9, payload);
        check(&fixture, |_, module| {
            known_const(
                module,
                &fixture,
                "element[0]/entry[0]/offset/operator[0]",
                constant_start,
            );
            unknown(
                module,
                &fixture,
                "element[0]/entry[0]/offset/opaque",
                constant_start + 2,
            );
            assert!(!at(module, "element[0]/entry[0]")
                .description
                .contains("element_type"));
            assert!(!regions(module)
                .iter()
                .any(|entry| entry.path.starts_with("element[0]/entry[0]/item[")));
        });
    }
}

#[test]
fn unknown_opcode_and_unaccepted_type_do_not_resynchronize_at_apparent_end_bytes() {
    for payload in [
        &[2, 0, 0x41, 0, 0xff, 0x0b, 0, 1, 1, 0xa5][..],
        &[2, 0, 0x41, 0, 0x1c, 1, 0x7a, 0x0b, 0, 1, 1, 0xa5][..],
    ] {
        let fixture = fixture(11, payload);
        check(&fixture, |_, module| {
            known_const(module, &fixture, "data[0]/entry[0]/offset/operator[0]", 17);
            unknown(module, &fixture, "data[0]/entry[0]/offset/opaque", 19);
        });
    }
}

#[test]
fn known_expression_and_trusted_active_or_passive_data_length_failures_remain_invalid() {
    let fixture = fixture(11, &[1, 0, 0x41, 0, 0x41, 0x80]);
    check(&fixture, |_, module| {
        known_const(module, &fixture, "data[0]/entry[0]/offset/operator[0]", 17);
        invalid(module, &fixture, "data[0]/entry[0]/offset/opaque", 19);
    });
    for payload in [
        &[1, 0, 0x41, 0, 0x0b, 0x80][..],
        &[1, 1, 0x80][..],
        &[1, 0, 0x41, 0, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x80, 0][..],
    ] {
        let fixture = self::fixture(11, payload);
        check(&fixture, |_, module| {
            invalid(module, &fixture, "data[0]/undecoded", 16);
            assert!(!regions(module).iter().any(|entry| {
                entry.path.starts_with("data[0]") && entry.path.contains("/operator[")
            }));
        });
    }
}

#[test]
fn valid_data_bytes_with_opcode_patterns_are_never_scanned_as_expressions() {
    for (payload, data_start, active) in [
        (
            &[
                1, 0, 0x41, 0, 0x0b, 8, 0x1c, 1, 0xff, 0, 0x0b, 0x80, 0xff, 0x0b,
            ][..],
            21,
            true,
        ),
        (
            &[1, 1, 8, 0x1c, 1, 0xff, 0, 0x0b, 0x80, 0xff, 0x0b][..],
            18,
            false,
        ),
    ] {
        let fixture = fixture(11, payload);
        check(&fixture, |profile, module| {
            physical(
                module,
                &fixture.bytes,
                "data[0]/entry[0]/bytes",
                data_start,
                data_start + 8,
            );
            assert_eq!(fixture.section_end, data_start + 8);
            assert_eq!(module.validation, "valid_with_all_known_features");
            if active || profile != Standard::Core1 {
                assert_eq!(module.standard.validation, "valid");
            }
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|entry| { matches!(entry.status.as_str(), "unknown" | "invalid_encoding") }));
            assert!(!module.diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.code.as_str(),
                    "unknown_operator" | "operator_decode"
                )
            }));
            if active {
                known_const(module, &fixture, "data[0]/entry[0]/offset/operator[0]", 17);
                physical(
                    module,
                    &fixture.bytes,
                    "data[0]/entry[0]/offset/operator[1]",
                    19,
                    20,
                );
            } else {
                assert!(!regions(module)
                    .iter()
                    .any(|entry| entry.path.starts_with("data[0]/entry[0]/offset")));
            }
            assert!(!regions(module).iter().any(|entry| {
                data_start <= entry.span.start
                    && entry.span.start < fixture.section_end
                    && entry.path != "data[0]/entry[0]/bytes"
            }));
        });
    }
}
