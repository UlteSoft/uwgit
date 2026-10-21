//! Fixed bounded br_table vector fields and ownership controls; no fuzzing.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const EOF_REASON: &str = "known encoding is truncated at its trusted input boundary";
const WIDTH_REASON: &str = "integer encoding exceeds its required width or length";
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

fn no_branch_error(module: &AuditModule) {
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.ends_with("/br_table_error")));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path.ends_with("/br_table_error")));
}

fn precise_field(fixture: &Fixture, start: usize, end: usize, field: &str, reason: &str) {
    let description =
        format!("{field}: {reason}; only this field is diagnosed, remaining bytes stay undecoded");
    check(fixture, |_, module| {
        let opaque_path = format!("{}/opaque", fixture.expression);
        let error_path = format!("{opaque_path}/br_table_error");
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
            start: fixture.opcode + start,
            end: fixture.opcode + end,
        };
        assert!(span.start <= span.end && span.end <= fixture.end);
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

fn eof(instruction: &[u8], start: usize, field: &str) {
    precise_field(
        &fixture(instruction, false),
        start,
        instruction.len(),
        field,
        EOF_REASON,
    );
}

fn width(instruction: &[u8], start: usize, end: usize, field: &str) {
    precise_field(&fixture(instruction, true), start, end, field, WIDTH_REASON);
}

fn control(instruction: &[u8], tail: bool, status: &str) {
    control_fixture(&fixture(instruction, tail), status);
}

fn control_fixture(fixture: &Fixture, status: &str) {
    check(fixture, |_, module| {
        no_branch_error(module);
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
        no_branch_error(module);
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
fn count_eof_width_and_length_failures_are_bounded_before_any_target() {
    eof(&[0x0e], 1, "branch table target count");
    eof(&[0x0e, 0x80], 1, "branch table target count");
    eof(&[0x0e, 0x80, 0x80], 1, "branch table target count");
    eof(
        &[0x0e, 0x80, 0x80, 0x80, 0x80],
        1,
        "branch table target count",
    );
    width(
        &[0x0e, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "branch table target count",
    );
    width(
        &[0x0e, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "branch table target count",
    );
}

#[test]
fn first_target_depth_errors_never_become_default_or_count_errors() {
    eof(&[0x0e, 1], 2, "branch table target[0] depth");
    eof(&[0x0e, 1, 0x80], 2, "branch table target[0] depth");
    eof(&[0x0e, 1, 0x80, 0x80], 2, "branch table target[0] depth");
    width(
        &[0x0e, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "branch table target[0] depth",
    );
    width(
        &[0x0e, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "branch table target[0] depth",
    );
    width(
        &[0x0e, 0x81, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "branch table target[0] depth",
    );
}

#[test]
fn second_target_depth_requires_the_complete_prior_depth_not_semantic_label_validity() {
    eof(&[0x0e, 2, 0], 3, "branch table target[1] depth");
    eof(&[0x0e, 2, 0, 0x80], 3, "branch table target[1] depth");
    width(
        &[0x0e, 2, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        4,
        9,
        "branch table target[1] depth",
    );
    width(
        &[
            0x0e, 2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ],
        7,
        12,
        "branch table target[1] depth",
    );
    width(
        &[0x0e, 0x82, 0, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        4,
        9,
        "branch table target[1] depth",
    );
    width(
        &[0x0e, 2, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "branch table target[1] depth",
    );
}

#[test]
fn default_depth_has_a_separate_role_after_zero_or_complete_targets() {
    eof(&[0x0e, 0], 2, "branch table default depth");
    eof(&[0x0e, 0, 0x80], 2, "branch table default depth");
    width(
        &[0x0e, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "branch table default depth",
    );
    width(
        &[0x0e, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "branch table default depth",
    );
    eof(&[0x0e, 1, 0], 3, "branch table default depth");
    width(
        &[0x0e, 2, 0x80, 0, 0x81, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        6,
        11,
        "branch table default depth",
    );
}

#[test]
fn padding_and_the_accepted_count_limit_keep_the_actual_next_field_boundary() {
    eof(&[0x0e, 0x80, 0], 3, "branch table default depth");
    eof(&[0x0e, 0x81, 0, 0x80, 0], 5, "branch table default depth");
    width(
        &[
            0x0e, 0x81, 0x80, 0x80, 0x80, 0, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        8,
        13,
        "branch table default depth",
    );
    eof(
        &[0x0e, 2, 0x80, 0x80, 0x80, 0x80, 0, 0x81, 0, 0x80],
        9,
        "branch table default depth",
    );
    eof(
        &[0x0e, 0xb1, 0x97, 0xd3, 3],
        5,
        "branch table target[0] depth",
    );
}

#[test]
fn implementation_count_limits_do_not_borrow_later_integer_failures() {
    control(
        &[0x0e, 0xb2, 0x97, 0xd3, 3, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
    );
    control(
        &[
            0x0e, 0xff, 0xff, 0xff, 0xff, 0x0f, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        true,
        "unknown",
    );
    control(&[0x0e, 0xb2, 0x97, 0xd3, 3], false, "unknown");
    control(
        &[
            0x0e, 0xb2, 0x97, 0xd3, 0x83, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        true,
        "unknown",
    );
}

#[test]
fn valid_padding_and_undefined_depths_remain_complete_wire_instructions() {
    decoded(&[0x0e, 0, 0], Some("BrTable"));
    decoded(&[0x0e, 0, 0x0b], Some("BrTable"));
    decoded(&[0x0e, 0x80, 0, 0x80, 0], Some("BrTable"));
    decoded(&[0x0e, 0x81, 0, 0x80, 0, 0x80, 0], Some("BrTable"));
    decoded(&[0x0e, 2, 0x80, 0, 0x81, 0, 0x82, 0], Some("BrTable"));
    decoded(&[0x0e, 0, 0xff, 0xff, 0xff, 0xff, 0x0f], Some("BrTable"));
    decoded(&[0x0e, 1, 0x7f, 0], Some("BrTable"));
    decoded(&[0x0e, 0, 0x80, 0x80, 0x80, 0x80, 0], Some("BrTable"));
    decoded(
        &[
            0x0e, 0x81, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0,
        ],
        Some("BrTable"),
    );
}

struct OwnerCase {
    instruction: &'static [u8],
    tail: bool,
    owner: &'static str,
    start: usize,
    feature: &'static str,
    status: &'static str,
    diagnostic: &'static str,
    severity: &'static str,
    prior_branch: bool,
}

#[test]
fn complete_tables_and_earlier_unknowns_keep_operator_and_frame_ownership() {
    for case in [
        OwnerCase {
            instruction: &[0x0e, 0, 0, 0xff],
            tail: true,
            owner: "opaque",
            start: 3,
            feature: "unknown",
            status: "unknown",
            diagnostic: "unknown_operator",
            severity: "warning",
            prior_branch: true,
        },
        OwnerCase {
            instruction: &[0x0e, 0, 0, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10],
            tail: true,
            owner: "opaque",
            start: 3,
            feature: "invalid_encoding",
            status: "invalid_encoding",
            diagnostic: "operator_decode",
            severity: "error",
            prior_branch: true,
        },
        OwnerCase {
            instruction: &[0x0e, 0, 0, 0x1c, 1, 0x7a],
            tail: true,
            owner: "opaque",
            start: 3,
            feature: "unknown_value_type",
            status: "unknown",
            diagnostic: "unknown_operator",
            severity: "warning",
            prior_branch: true,
        },
        OwnerCase {
            instruction: &[0x0e, 0, 0],
            tail: false,
            owner: "expression_structure",
            start: 3,
            feature: "invalid_encoding",
            status: "invalid_encoding",
            diagnostic: "expression_structure",
            severity: "error",
            prior_branch: true,
        },
        OwnerCase {
            instruction: &[0xff, 0x0e, 0x80, 0x80, 0x80, 0x80, 0x10],
            tail: true,
            owner: "opaque",
            start: 0,
            feature: "unknown",
            status: "unknown",
            diagnostic: "unknown_operator",
            severity: "warning",
            prior_branch: false,
        },
        OwnerCase {
            instruction: &[0x1f, 0x40, 1, 4, 0x0e, 0x80, 0x80, 0x80, 0x80, 0x10],
            tail: true,
            owner: "opaque",
            start: 0,
            feature: "unknown",
            status: "unknown",
            diagnostic: "operator_decode",
            severity: "error",
            prior_branch: false,
        },
    ] {
        let fixture = fixture(case.instruction, case.tail);
        check(&fixture, |_, module| {
            no_branch_error(module);
            let owner_path = format!("{}/{}", fixture.expression, case.owner);
            let owner = at(module, &owner_path);
            assert_eq!(
                owner.span,
                Span {
                    start: fixture.opcode + case.start,
                    end: fixture.end
                }
            );
            assert_eq!(owner.feature.as_deref(), Some(case.feature));
            assert_eq!(owner.standard_support.status, case.status);
            assert_eq!(
                owner.standard_support.display,
                if case.status == "unknown" {
                    "opaque"
                } else {
                    "binary"
                }
            );
            assert!(owner.children.is_empty());
            assert!(module.diagnostics.iter().any(|d| d.code == case.diagnostic
                && d.severity == case.severity
                && d.offset == owner.span.start));
            if case.prior_branch {
                let first = at(module, "code[0]/function[1]/operator[0]");
                assert_eq!(
                    first.span,
                    Span {
                        start: fixture.opcode,
                        end: fixture.opcode + 3
                    }
                );
                assert!(first.description.starts_with("BrTable"));
                assert!(!regions(module)
                    .iter()
                    .any(|r| r.path == "code[0]/function[1]/operator[1]"));
            } else {
                assert!(!regions(module)
                    .iter()
                    .any(|r| r.path.starts_with("code[0]/function[1]/operator[")));
            }
            if case.owner == "expression_structure" {
                assert!(!regions(module)
                    .iter()
                    .any(|r| r.path == "code[0]/function[1]/opaque"));
            }
        });
    }
}

#[test]
fn failed_constant_expressions_keep_global_table_and_element_ownership() {
    precise_field(
        &constant_fixture(6, &[0x0e, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        1,
        6,
        "branch table target count",
        WIDTH_REASON,
    );
    precise_field(
        &constant_fixture(4, &[0x0e, 1], false),
        2,
        2,
        "branch table target[0] depth",
        EOF_REASON,
    );
    precise_field(
        &constant_fixture(9, &[0x0e, 0, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        2,
        7,
        "branch table default depth",
        WIDTH_REASON,
    );
}
