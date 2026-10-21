//! Fixed HeapType operand slots and guarded dual-heap prefixes; no fuzzing.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const REASON: &str = "known numeric or vector value type is forbidden in a heap-type operand";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];
const LATER: &[u8] = &[
    0, 0xfd, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a, 0x41, 0, 0xfb, 0x1c, 0x1a,
    0x1f, 0x40, 0, 0x0b, 0x41, 42, 0x1a, 0x0b,
];

struct Fixture {
    bytes: Vec<u8>,
    expression: &'static str,
    opcode: usize,
    end: usize,
    later: Span,
    prior_function: Span,
    prior_entry: Option<(&'static str, Span)>,
    custom: usize,
}

struct GuardCase {
    instruction: &'static [u8],
    status: &'static str,
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn code(bytes: &mut Vec<u8>, body: &[u8]) -> (Span, Span) {
    assert_eq!(LATER.len(), 33);
    let mut payload = vec![3, 2, 0, 0x0b, body.len() as u8];
    payload.extend_from_slice(body);
    payload.push(LATER.len() as u8);
    payload.extend_from_slice(LATER);
    let start = section(bytes, 10, &payload);
    (
        Span {
            start: start + 1,
            end: start + 4,
        },
        Span {
            start: start + 6 + body.len(),
            end: bytes.len(),
        },
    )
}

fn fixture(instruction: &[u8], tail: bool) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[3, 0, 0, 0]);
    let mut body = vec![0];
    body.extend_from_slice(instruction);
    if tail {
        body.extend_from_slice(&[0x41, 42, 0x1a, 0x0b]);
    }
    let (prior_function, later) = code(&mut bytes, &body);
    let end = 27 + body.len();
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        expression: "code[0]/function[1]",
        opcode: 28,
        end,
        later,
        prior_function,
        prior_entry: None,
        custom,
    }
}

fn constant_fixture(id: u8, instruction: &[u8], end_expression: bool) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[3, 0, 0, 0]);
    if id == 9 {
        section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    }
    let (expression, prior_path, prior, header): (&str, &str, &[u8], &[u8]) = match id {
        4 => (
            "table[0]/entry[1]/init",
            "table[0]/entry[0]",
            &[0x70, 0, 0],
            &[0x40, 0, 0x70, 0, 0],
        ),
        6 => (
            "global[0]/entry[1]/init",
            "global[0]/entry[0]",
            &[0x7f, 0, 0x41, 0, 0x0b],
            &[0x6f, 0],
        ),
        9 => (
            "element[0]/entry[1]/item[0]",
            "element[0]/entry[0]",
            &[0, 0x41, 0, 0x0b, 0],
            &[5, 0x70, 1],
        ),
        _ => unreachable!(),
    };
    let mut payload = vec![2];
    payload.extend_from_slice(prior);
    payload.extend_from_slice(header);
    payload.extend_from_slice(instruction);
    if end_expression {
        payload.push(0x0b);
    }
    let start = section(&mut bytes, id, &payload);
    let prior_span = Span {
        start: start + 1,
        end: start + 1 + prior.len(),
    };
    let opcode = prior_span.end + header.len();
    let end = bytes.len();
    let (prior_function, later) = code(&mut bytes, &[0, 0x0b]);
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        expression,
        opcode,
        end,
        later,
        prior_function,
        prior_entry: Some((prior_path, prior_span)),
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
            at(&module, "code[0]/function[0]").span,
            fixture.prior_function
        );
        assert_eq!(
            at(&module, "code[0]/function[0]/operator[0]").description,
            "End"
        );
        if let Some((path, span)) = fixture.prior_entry {
            assert_eq!(at(&module, path).span, span);
        }
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
        assert_eq!(fixture.later.end - fixture.later.start, 33);
        assert_eq!(
            at(&module, "code[0]/function[2]").span,
            Span {
                start: fixture.later.start - 1,
                end: fixture.later.end
            }
        );
        for (index, start, end, feature) in [
            (0, 1, 19, "simd"),
            (3, 22, 24, "gc"),
            (5, 25, 28, "exceptions"),
        ] {
            let path = format!("code[0]/function[2]/operator[{index}]");
            let region = at(&module, &path);
            assert_eq!(
                region.span,
                Span {
                    start: fixture.later.start + start,
                    end: fixture.later.start + end
                }
            );
            let supported = if feature == "simd" {
                profile != Standard::Core1
            } else {
                matches!(profile, Standard::Core3 | Standard::AllKnown)
            };
            let status = if supported {
                "supported"
            } else {
                "recognized_but_disabled"
            };
            assert_eq!(region.standard_support.status, status);
            assert_eq!(
                region.standard_support.display,
                if supported { "instruction" } else { "binary" }
            );
            assert!(module.standard.evidence.iter().any(|row| row.path == path
                && row.feature == feature
                && row.status == status
                && row.span == region.span));
        }
        let sentinel = at(&module, "code[0]/function[2]/operator[7]");
        assert_eq!(
            sentinel.span,
            Span {
                start: fixture.later.start + 29,
                end: fixture.later.start + 31
            }
        );
        assert_eq!(sentinel.standard_support.status, "supported");
        assert_eq!(
            &fixture.bytes[sentinel.span.start..sentinel.span.end],
            &[0x41, 42]
        );
        assert_eq!(
            at(&module, "code[0]/function[2]/operator[9]").description,
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

fn no_heap_error(module: &AuditModule) {
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.ends_with("/heap_type_error")));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.reason.contains(REASON)));
}

fn precise(fixture: &Fixture, slot: usize) {
    precise_field(fixture, slot, "heap type operand");
}

fn precise_field(fixture: &Fixture, slot: usize, field: &str) {
    let description =
        format!("{field}: {REASON}; only this field is diagnosed, remaining bytes stay undecoded");
    check(fixture, |_, module| {
        let opaque_path = format!("{}/opaque", fixture.expression);
        let error_path = format!("{opaque_path}/heap_type_error");
        let opaque = at(module, &opaque_path);
        assert_eq!(
            opaque.span,
            Span {
                start: fixture.opcode,
                end: fixture.end
            }
        );
        assert_eq!(opaque.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(opaque.standard_support.status, "invalid_encoding");
        assert_eq!(opaque.standard_support.display, "binary");
        assert_eq!(opaque.children.len(), 1);
        assert_eq!(opaque.children[0].path, error_path);
        let child = at(module, &error_path);
        let span = Span {
            start: fixture.opcode + slot,
            end: fixture.opcode + slot + 1,
        };
        assert!(matches!(fixture.bytes[span.start], 0x7b..=0x7f));
        assert_eq!(child.span, span);
        assert_eq!(child.description, description);
        assert_eq!(child.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(child.standard_support.status, "invalid_encoding");
        assert_eq!(child.standard_support.display, "binary");
        assert!(child.children.is_empty());
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == error_path)
            .collect();
        assert_eq!(rows.len(), 1);
        let raw = hex(&fixture.bytes[span.start..span.end]);
        assert_eq!(
            serde_json::to_value(rows[0]).unwrap(),
            serde_json::json!({
                "path": error_path, "span": span, "feature": "section_structure", "status": "invalid_encoding",
                "kind": "structure", "reason": description, "raw_hex": raw, "recognized": null
            })
        );
        let line = format!("invalid_encoding {error_path} [{}..{}) binary={raw} feature=section_structure recognized=None: {description}", span.start, span.end);
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|text| text.starts_with(&format!("invalid_encoding {error_path} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
        assert!(!regions(module).iter().any(|region| region
            .path
            .starts_with(&format!("{}/operator[", fixture.expression))));
        assert!(!module.standard.evidence.iter().any(|row| row
            .path
            .starts_with(&format!("{}/operator[", fixture.expression))));
        assert!(!regions(module)
            .iter()
            .any(|region| region.path.ends_with("/locals_error")));
    });
}

fn known(instruction: &[u8], slot: usize) {
    precise(&fixture(instruction, true), slot);
}

fn control(instruction: &[u8], tail: bool, status: &str) {
    let fixture = fixture(instruction, tail);
    check(&fixture, |_, module| {
        no_heap_error(module);
        let opaque = at(module, "code[0]/function[1]/opaque");
        assert_eq!(
            opaque.span,
            Span {
                start: fixture.opcode,
                end: fixture.end
            }
        );
        assert_eq!(
            opaque.feature.as_deref(),
            Some(if status == "unknown" {
                "unknown"
            } else {
                "invalid_encoding"
            })
        );
        assert_eq!(opaque.standard_support.status, status);
        assert_eq!(
            opaque.standard_support.display,
            if status == "unknown" {
                "opaque"
            } else {
                "binary"
            }
        );
        assert!(opaque.children.is_empty());
        assert!(!regions(module)
            .iter()
            .any(|region| region.path.starts_with("code[0]/function[1]/operator[")));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with("code[0]/function[1]/operator[")));
    });
}

fn decoded(instruction: &[u8], expected_name: Option<&str>) {
    let fixture = fixture(instruction, true);
    check(&fixture, |_, module| {
        no_heap_error(module);
        let first = at(module, "code[0]/function[1]/operator[0]");
        assert_eq!(
            first.span,
            Span {
                start: fixture.opcode,
                end: fixture.opcode + instruction.len()
            }
        );
        if let Some(name) = expected_name {
            assert!(first.description.starts_with(name));
        }
        assert!(!regions(module)
            .iter()
            .any(|region| region.path == "code[0]/function[1]/opaque"));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path == first.path && row.status == "invalid_encoding"));
        let following = at(module, "code[0]/function[1]/operator[1]");
        assert_eq!(
            following.span,
            Span {
                start: first.span.end,
                end: first.span.end + 2
            }
        );
        assert_eq!(following.standard_support.status, "supported");
        assert_eq!(
            &fixture.bytes[following.span.start..following.span.end],
            &[0x41, 42]
        );
        assert_eq!(
            at(module, "code[0]/function[1]/operator[3]").description,
            "End"
        );
    });
}

#[test]
fn ref_null_heap_slot_rejects_five_complete_numeric_and_vector_tokens() {
    known(&[0xd0, 0x7f], 1);
    known(&[0xd0, 0x7e], 1);
    known(&[0xd0, 0x7d], 1);
    known(&[0xd0, 0x7c], 1);
    known(&[0xd0, 0x7b], 1);
}

#[test]
fn ref_test_non_null_has_one_heap_slot_after_known_subopcode14() {
    known(&[0xfb, 0x14, 0x7f], 2);
    known(&[0xfb, 0x14, 0x7e], 2);
    known(&[0xfb, 0x14, 0x7d], 2);
    known(&[0xfb, 0x14, 0x7c], 2);
    known(&[0xfb, 0x14, 0x7b], 2);
}

#[test]
fn ref_test_nullable_has_one_heap_slot_after_known_subopcode15() {
    known(&[0xfb, 0x15, 0x7f], 2);
    known(&[0xfb, 0x15, 0x7e], 2);
    known(&[0xfb, 0x15, 0x7d], 2);
    known(&[0xfb, 0x15, 0x7c], 2);
    known(&[0xfb, 0x15, 0x7b], 2);
}

#[test]
fn ref_cast_non_null_has_one_heap_slot_after_known_subopcode16() {
    known(&[0xfb, 0x16, 0x7f], 2);
    known(&[0xfb, 0x16, 0x7e], 2);
    known(&[0xfb, 0x16, 0x7d], 2);
    known(&[0xfb, 0x16, 0x7c], 2);
    known(&[0xfb, 0x16, 0x7b], 2);
}

#[test]
fn ref_cast_nullable_has_one_heap_slot_after_known_subopcode17() {
    known(&[0xfb, 0x17, 0x7f], 2);
    known(&[0xfb, 0x17, 0x7e], 2);
    known(&[0xfb, 0x17, 0x7d], 2);
    known(&[0xfb, 0x17, 0x7c], 2);
    known(&[0xfb, 0x17, 0x7b], 2);
}

#[test]
fn ref_get_desc_u32_indices_are_not_heap_type_tokens() {
    decoded(&[0xfb, 0x22, 0x7f], Some("RefGetDesc"));
    decoded(&[0xfb, 0x22, 0x7e], Some("RefGetDesc"));
    decoded(&[0xfb, 0x22, 0x7d], Some("RefGetDesc"));
    decoded(&[0xfb, 0x22, 0x7c], Some("RefGetDesc"));
    decoded(&[0xfb, 0x22, 0x7b], Some("RefGetDesc"));
    decoded(&[0xfb, 0xa2, 0, 0x7b], Some("RefGetDesc"));
}

#[test]
fn ref_cast_desc_eq_non_null_has_one_heap_slot_after_known_subopcode23() {
    known(&[0xfb, 0x23, 0x7f], 2);
    known(&[0xfb, 0x23, 0x7e], 2);
    known(&[0xfb, 0x23, 0x7d], 2);
    known(&[0xfb, 0x23, 0x7c], 2);
    known(&[0xfb, 0x23, 0x7b], 2);
}

#[test]
fn ref_cast_desc_eq_nullable_has_one_heap_slot_after_known_subopcode24() {
    known(&[0xfb, 0x24, 0x7f], 2);
    known(&[0xfb, 0x24, 0x7e], 2);
    known(&[0xfb, 0x24, 0x7d], 2);
    known(&[0xfb, 0x24, 0x7c], 2);
    known(&[0xfb, 0x24, 0x7b], 2);
}

#[test]
fn complete_padded_gc_subopcodes_keep_the_actual_shifted_heap_slot() {
    known(&[0xfb, 0x94, 0, 0x7f], 3);
    known(&[0xfb, 0x95, 0, 0x7e], 3);
    known(&[0xfb, 0x96, 0, 0x7d], 3);
    known(&[0xfb, 0x97, 0, 0x7c], 3);
    known(&[0xfb, 0xa3, 0, 0x7f], 3);
    known(&[0xfb, 0xa4, 0x80, 0x80, 0x80, 0, 0x7e], 6);
}

#[test]
fn unknown_future_nested_heap_forms_and_resource_caps_do_not_gain_a_numeric_leaf() {
    control(&[0xd0, 0x7a, 0x80, 0x80, 0x80, 0x80, 0x10], true, "unknown");
    control(&[0xfb, 0x14, 0x7a, 0x7f], true, "unknown");
    control(&[0xfb, 0x15, 0xff, 0x7f, 0x7b], true, "unknown");
    control(&[0xfb, 0x16, 0x65, 0x7f], true, "unknown");
    control(&[0xfb, 0x17, 0x65, 0x7b], true, "unknown");
    control(&[0xfb, 0x23, 0xff, 0x7f, 0x7f], true, "unknown");
    control(&[0xfb, 0x24, 0x65, 0x7f], true, "unknown");
    control(&[0xd0, 0x63, 0x7f], true, "unknown");
    control(&[0xd0, 0x64, 0x7b], true, "unknown");
    control(&[0xd0, 0x80, 0x80, 0xc0, 0], true, "unknown");
    control(&[0xfb, 0x14, 0x80, 0x80, 0xc0, 0], true, "unknown");
    control(&[0xfb, 0x7f, 0x7b], true, "unknown");
}

#[test]
fn every_dual_heap_form_stops_at_unknown_flags_before_depth_errors() {
    for case in [
        GuardCase {
            instruction: &[0xfb, 0x18, 4],
            status: "unknown",
        },
        GuardCase {
            instruction: &[0xfb, 0x18, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
            status: "unknown",
        },
        GuardCase {
            instruction: &[0xfb, 0x19, 4],
            status: "unknown",
        },
        GuardCase {
            instruction: &[0xfb, 0x19, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
            status: "unknown",
        },
        GuardCase {
            instruction: &[0xfb, 0x25, 4],
            status: "unknown",
        },
        GuardCase {
            instruction: &[0xfb, 0x25, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
            status: "unknown",
        },
        GuardCase {
            instruction: &[0xfb, 0x26, 4],
            status: "unknown",
        },
        GuardCase {
            instruction: &[0xfb, 0x26, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
            status: "unknown",
        },
        GuardCase {
            instruction: &[0xfb, 0x18, 0],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x19, 0],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x25, 0],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x26, 0],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x18, 3, 0x80, 0x80, 0x80, 0x80, 0x10],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x19, 3, 0x80, 0x80, 0x80, 0x80, 0x10],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x25, 3, 0x80, 0x80, 0x80, 0x80, 0x10],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x26, 3, 0x80, 0x80, 0x80, 0x80, 0x10],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x18],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x19],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x25],
            status: "invalid_encoding",
        },
        GuardCase {
            instruction: &[0xfb, 0x26],
            status: "invalid_encoding",
        },
    ] {
        control(case.instruction, false, case.status);
    }
    precise_field(
        &fixture(&[0xfb, 0x18, 0, 0, 0x7f], false),
        4,
        "source heap type operand",
    );
    precise_field(
        &fixture(&[0xfb, 0x19, 0, 0, 0x7f], false),
        4,
        "source heap type operand",
    );
    precise_field(
        &fixture(&[0xfb, 0x25, 0, 0, 0x7f], false),
        4,
        "source heap type operand",
    );
    precise_field(
        &fixture(&[0xfb, 0x26, 0, 0, 0x7f], false),
        4,
        "source heap type operand",
    );
}

#[test]
fn known_heap_prefix_eof_and_integer_failures_keep_their_old_operator_ownership() {
    control(&[0xd0], false, "invalid_encoding");
    control(&[0xd0, 0x80], false, "invalid_encoding");
    control(
        &[0xd0, 0x80, 0x80, 0x80, 0x80, 0x10],
        false,
        "invalid_encoding",
    );
    control(&[0xfb, 0x14], false, "invalid_encoding");
    control(
        &[0xfb, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
        false,
        "invalid_encoding",
    );
    control(&[0xd0, 0x62], false, "invalid_encoding");
    control(&[0xd0, 0x65], false, "invalid_encoding");
}

#[test]
fn legal_indices_abstract_heaps_and_non_heap_value_types_keep_decoded_boundaries() {
    for instruction in [
        &[0xd0, 0x70][..],
        &[0xd0, 0xff, 0][..],
        &[0xd0, 0][..],
        &[0xd0, 0x80, 0][..],
        &[0xd0, 0x65, 0x70][..],
        &[0xd0, 0x62, 0][..],
        &[0xfb, 0x14, 0x6e][..],
        &[0x1c, 1, 0x7f][..],
    ] {
        decoded(instruction, None);
    }
}

#[test]
fn constant_expression_owners_use_the_same_numeric_proof_and_cast_flag_frontier() {
    precise(&constant_fixture(6, &[0xd0, 0x7f], true), 1);
    precise(&constant_fixture(4, &[0xd0, 0x7b], true), 1);
    precise(&constant_fixture(9, &[0xd0, 0x7e], true), 1);
    let fixture = constant_fixture(6, &[0xfb, 0x18, 4], false);
    check(&fixture, |_, module| {
        no_heap_error(module);
        let opaque = at(module, "global[0]/entry[1]/init/opaque");
        assert_eq!(
            opaque.span,
            Span {
                start: fixture.opcode,
                end: fixture.end
            }
        );
        assert_eq!(opaque.feature.as_deref(), Some("unknown"));
        assert_eq!(opaque.standard_support.status, "unknown");
        assert_eq!(opaque.standard_support.display, "opaque");
        assert!(opaque.children.is_empty());
        assert!(!regions(module)
            .iter()
            .any(|region| region.path == "global[0]/undecoded/global_error"));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with("global[0]/entry[1]/init/")
                && row.status == "invalid_encoding"));
    });
}
