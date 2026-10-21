//! Fixed source/target HeapType slots in four dual-heap casts; no fuzzing.
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

fn known(instruction: &[u8], slot: usize, field: &str) {
    precise_field(&fixture(instruction, true), slot, field);
}

fn control(instruction: &[u8], tail: bool, status: &str) {
    control_fixture(&fixture(instruction, tail), status);
}

fn control_fixture(fixture: &Fixture, status: &str) {
    check(fixture, |_, module| {
        no_heap_error(module);
        let opaque = at(module, &format!("{}/opaque", fixture.expression));
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
        assert!(!regions(module).iter().any(|region| region
            .path
            .starts_with(&format!("{}/operator[", fixture.expression))));
        assert!(!module.standard.evidence.iter().any(|row| row
            .path
            .starts_with(&format!("{}/operator[", fixture.expression))));
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
fn br_on_cast_source_and_target_each_reject_five_numeric_tokens() {
    known(
        &[0xfb, 0x18, 0, 0, 0x7f, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x18, 0, 0, 0x7e, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x18, 0, 0, 0x7d, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x18, 0, 0, 0x7c, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x18, 0, 0, 0x7b, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x18, 3, 0, 0x70, 0x7f],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x18, 3, 0, 0x70, 0x7e],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x18, 3, 0, 0x70, 0x7d],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x18, 3, 0, 0x70, 0x7c],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x18, 3, 0, 0x70, 0x7b],
        5,
        "target heap type operand",
    );
}

#[test]
fn br_on_cast_fail_source_and_target_each_reject_five_numeric_tokens() {
    known(
        &[0xfb, 0x19, 0, 0, 0x7f, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x19, 0, 0, 0x7e, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x19, 0, 0, 0x7d, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x19, 0, 0, 0x7c, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x19, 0, 0, 0x7b, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x19, 3, 0, 0x70, 0x7f],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x19, 3, 0, 0x70, 0x7e],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x19, 3, 0, 0x70, 0x7d],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x19, 3, 0, 0x70, 0x7c],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x19, 3, 0, 0x70, 0x7b],
        5,
        "target heap type operand",
    );
}

#[test]
fn descriptor_cast_source_and_target_each_reject_five_numeric_tokens() {
    known(
        &[0xfb, 0x25, 0, 0, 0x7f, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x25, 0, 0, 0x7e, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x25, 0, 0, 0x7d, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x25, 0, 0, 0x7c, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x25, 0, 0, 0x7b, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x25, 3, 0, 0x70, 0x7f],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x25, 3, 0, 0x70, 0x7e],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x25, 3, 0, 0x70, 0x7d],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x25, 3, 0, 0x70, 0x7c],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x25, 3, 0, 0x70, 0x7b],
        5,
        "target heap type operand",
    );
}

#[test]
fn descriptor_cast_fail_source_and_target_each_reject_five_numeric_tokens() {
    known(
        &[0xfb, 0x26, 0, 0, 0x7f, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x26, 0, 0, 0x7e, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x26, 0, 0, 0x7d, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x26, 0, 0, 0x7c, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x26, 0, 0, 0x7b, 0x7b],
        4,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x26, 3, 0, 0x70, 0x7f],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x26, 3, 0, 0x70, 0x7e],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x26, 3, 0, 0x70, 0x7d],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x26, 3, 0, 0x70, 0x7c],
        5,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x26, 3, 0, 0x70, 0x7b],
        5,
        "target heap type operand",
    );
}

#[test]
fn padding_and_complete_source_types_prove_the_shifted_target_slot() {
    known(
        &[0xfb, 0x98, 0, 0, 0, 0x7f, 0x70],
        5,
        "source heap type operand",
    );
    known(
        &[0xfb, 0x99, 0, 0, 0x80, 0, 0x70, 0x7e],
        7,
        "target heap type operand",
    );
    known(
        &[0xfb, 0xa5, 0, 3, 0x80, 0x80, 0x80, 0x80, 0, 0x7d, 0x70],
        9,
        "source heap type operand",
    );
    known(
        &[
            0xfb, 0xa6, 0x80, 0x80, 0x80, 0, 2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x70, 0x7c,
        ],
        13,
        "target heap type operand",
    );
    known(&[0xfb, 0x18, 0, 0, 0, 0x7f], 5, "target heap type operand");
    known(
        &[0xfb, 0x19, 1, 0, 0xff, 0, 0x7e],
        6,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x25, 2, 0, 0x65, 0x70, 0x7d],
        6,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x26, 3, 0, 0x62, 0, 0x7c],
        6,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x18, 0, 0, 0xff, 0xff, 0x3f, 0x7b],
        7,
        "target heap type operand",
    );
    known(
        &[0xfb, 0x19, 0, 0, 0x62, 0xff, 0xff, 0x3f, 0x7f],
        8,
        "target heap type operand",
    );
}

#[test]
fn unknown_flags_block_all_later_numeric_or_integer_proofs() {
    control(&[0xfb, 0x18, 4], false, "unknown");
    control(&[0xfb, 0x19, 4], false, "unknown");
    control(&[0xfb, 0x25, 4], false, "unknown");
    control(&[0xfb, 0x26, 4], false, "unknown");
    control(
        &[0xfb, 0x18, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f, 0x7b],
        true,
        "unknown",
    );
    control(
        &[0xfb, 0x19, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f, 0x7b],
        true,
        "unknown",
    );
    control(
        &[0xfb, 0x25, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f, 0x7b],
        true,
        "unknown",
    );
    control(
        &[0xfb, 0x26, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f, 0x7b],
        true,
        "unknown",
    );
    control(&[0xfb, 0x18, 0x80, 0, 0x7f, 0x7b], true, "unknown");
    control(&[0xfb, 0x26, 0xff, 0, 0x7f, 0x7b], true, "unknown");
}

#[test]
fn known_prefix_eof_and_integer_errors_keep_their_existing_operator_ownership() {
    control(&[0xfb, 0x18], false, "invalid_encoding");
    control(&[0xfb, 0x19, 0], false, "invalid_encoding");
    control(
        &[0xfb, 0x25, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        false,
        "invalid_encoding",
    );
    control(
        &[0xfb, 0x26, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        false,
        "invalid_encoding",
    );
    control(&[0xfb, 0x18, 0, 0], false, "invalid_encoding");
    control(
        &[0xfb, 0x19, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        false,
        "invalid_encoding",
    );
    control(&[0xfb, 0x25, 0, 0, 0x70], false, "invalid_encoding");
    control(
        &[0xfb, 0x26, 0, 0, 0x70, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        false,
        "invalid_encoding",
    );
}

#[test]
fn unknown_source_heap_blocks_any_apparent_numeric_target_or_following_error() {
    control(&[0xfb, 0x18, 0, 0, 0x7a, 0x7f], true, "unknown");
    control(&[0xfb, 0x19, 0, 0, 0xff, 0x7f, 0x7b], true, "unknown");
    control(&[0xfb, 0x25, 0, 0, 0x65, 0x7f, 0x7b], true, "unknown");
    control(&[0xfb, 0x26, 0, 0, 0x63, 0x7f, 0x7b], true, "unknown");
    control(&[0xfb, 0x18, 0, 0, 0x64, 0x7b, 0x7f], true, "unknown");
    control(&[0xfb, 0x19, 0, 0, 0x65, 0x62, 0x7f], true, "unknown");
    control(
        &[0xfb, 0x25, 0, 0, 0x7a, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
        true,
        "unknown",
    );
    control(
        &[
            0xfb, 0x26, 0, 0, 0xff, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f,
        ],
        true,
        "unknown",
    );
    control(&[0xfb, 0x18, 0, 0, 0x76, 0x7f], true, "unknown");
    control(&[0xfb, 0x19, 0, 0, 0x65, 0xff, 0x7f, 0x7f], true, "unknown");
}

#[test]
fn unknown_target_heap_preserves_its_prefix_without_searching_for_numeric_bytes() {
    control(&[0xfb, 0x18, 0, 0, 0x70, 0x7a, 0x7f], true, "unknown");
    control(&[0xfb, 0x19, 0, 0, 0x70, 0xff, 0x7f, 0x7b], true, "unknown");
    control(&[0xfb, 0x25, 0, 0, 0x70, 0x65, 0x7f, 0x7b], true, "unknown");
    control(&[0xfb, 0x26, 0, 0, 0x70, 0x63, 0x7f], true, "unknown");
    control(&[0xfb, 0x18, 0, 0, 0x70, 0x64, 0x7b], true, "unknown");
    control(&[0xfb, 0x19, 0, 0, 0x70, 0x76, 0x7f], true, "unknown");
}

#[test]
fn packed_index_and_ref_type_conversion_limits_stop_before_later_tokens() {
    control(
        &[0xfb, 0x18, 0, 0, 0x80, 0x80, 0xc0, 0, 0x7f],
        true,
        "unknown",
    );
    control(
        &[
            0xfb, 0x19, 0, 0, 0x80, 0x80, 0xc0, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        true,
        "unknown",
    );
    control(
        &[0xfb, 0x25, 0, 0, 0x62, 0x80, 0x80, 0x40, 0x7b],
        true,
        "unknown",
    );
    control(
        &[0xfb, 0x26, 0, 0, 0x62, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f],
        true,
        "unknown",
    );
    control(
        &[0xfb, 0x18, 0, 0, 0x70, 0x80, 0x80, 0xc0, 0, 0x7f],
        true,
        "unknown",
    );
    control(
        &[0xfb, 0x19, 0, 0, 0x70, 0x62, 0x80, 0x80, 0x40, 0x7b],
        true,
        "unknown",
    );
    control(
        &[
            0xfb, 0x25, 0, 0, 0x70, 0x62, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f,
        ],
        true,
        "unknown",
    );
    control(
        &[
            0xfb, 0x26, 0, 0, 0x70, 0x80, 0x80, 0xc0, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        true,
        "unknown",
    );
}

#[test]
fn legal_depth_and_heap_index_encodings_remain_decoded_despite_semantic_limits() {
    decoded(&[0xfb, 0x18, 0, 0, 0x70, 0x70], Some("BrOnCast"));
    decoded(&[0xfb, 0x19, 1, 0, 0x6e, 0x6d], Some("BrOnCastFail"));
    decoded(
        &[0xfb, 0x25, 2, 0, 0x65, 0x70, 0x65, 0x70],
        Some("BrOnCastDescEq"),
    );
    decoded(
        &[0xfb, 0x26, 3, 0, 0x62, 0, 0x62, 0],
        Some("BrOnCastDescEqFail"),
    );
    decoded(&[0xfb, 0x18, 0, 0x7f, 0, 0], Some("BrOnCast"));
    decoded(&[0xfb, 0x19, 0, 0, 0xff, 0, 0], Some("BrOnCastFail"));
    decoded(&[0xfb, 0x25, 0, 0, 0x70, 0xff, 0], Some("BrOnCastDescEq"));
    decoded(
        &[0xfb, 0x26, 0, 0, 0x62, 0x7f, 0x62, 0x7b],
        Some("BrOnCastDescEqFail"),
    );
}

#[test]
fn recovered_constant_expressions_keep_source_target_and_header_ownership() {
    precise_field(
        &constant_fixture(6, &[0xfb, 0x18, 0, 0, 0x7f, 0x70], true),
        4,
        "source heap type operand",
    );
    precise_field(
        &constant_fixture(4, &[0xfb, 0x19, 1, 0, 0x70, 0x7b], true),
        5,
        "target heap type operand",
    );
    precise_field(
        &constant_fixture(9, &[0xfb, 0x25, 2, 0, 0x62, 0, 0x7e], true),
        6,
        "target heap type operand",
    );
    control_fixture(
        &constant_fixture(6, &[0xfb, 0x18, 0, 0, 0x7a, 0x7f], true),
        "unknown",
    );
    control_fixture(
        &constant_fixture(
            4,
            &[0xfb, 0x19, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
            true,
        ),
        "unknown",
    );
    control_fixture(
        &constant_fixture(9, &[0xfb, 0x25, 0, 0, 0x62, 0x80, 0x80, 0x40, 0x7f], true),
        "unknown",
    );
}
