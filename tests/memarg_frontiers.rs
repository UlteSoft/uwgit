//! Fixed unknown memarg frontiers and known-layout controls; no fuzzing.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const EOF_REASON: &str = "known encoding is truncated at its trusted input boundary";
const WIDTH_REASON: &str = "integer encoding exceeds its required width or length";
type ExpectedMemarg = (usize, usize, &'static str, &'static str);
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

fn opaque(instruction: &[u8], tail: bool, status: &str, message: &str) {
    opaque_fixture(
        &fixture(instruction, tail),
        status,
        "operator_decode",
        "error",
        message,
    );
}

fn unknown_opcode(instruction: &[u8], message: &str) {
    opaque_fixture(
        &fixture(instruction, true),
        "unknown",
        "unknown_operator",
        "warning",
        message,
    );
}

fn opaque_memarg(instruction: &[u8], tail: bool, message: &str, expected: ExpectedMemarg) {
    opaque_fixture_expected(
        &fixture(instruction, tail),
        "invalid_encoding",
        "operator_decode",
        "error",
        message,
        Some(expected),
    );
}

fn opaque_fixture(
    fixture: &Fixture,
    status: &str,
    diagnostic: &str,
    severity: &str,
    message: &str,
) {
    opaque_fixture_expected(fixture, status, diagnostic, severity, message, None);
}

fn opaque_simd(instruction: &[u8], start: usize, end: usize, field: &'static str) {
    opaque_fixture_named(
        &fixture(instruction, false),
        "invalid_encoding",
        "operator_decode",
        "error",
        "unexpected end-of-file",
        Some((start, end, field, EOF_REASON)),
        "simd_immediate_error",
    );
}

fn opaque_fixture_expected(
    fixture: &Fixture,
    status: &str,
    diagnostic: &str,
    severity: &str,
    message: &str,
    expected: Option<ExpectedMemarg>,
) {
    opaque_fixture_named(
        fixture,
        status,
        diagnostic,
        severity,
        message,
        expected,
        "memarg_error",
    );
}

fn opaque_fixture_named(
    fixture: &Fixture,
    status: &str,
    diagnostic: &str,
    severity: &str,
    message: &str,
    expected: Option<ExpectedMemarg>,
    leaf: &str,
) {
    check(fixture, |_, module| {
        if leaf != "memarg_error" {
            assert!(!regions(module)
                .iter()
                .any(|region| region.path.ends_with("/memarg_error")));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path.ends_with("/memarg_error")));
        }
        let path = format!("{}/opaque", fixture.expression);
        let region = at(module, &path);
        assert_eq!(
            region.span,
            Span {
                start: fixture.opcode,
                end: fixture.end
            }
        );
        assert_eq!(
            region.feature.as_deref(),
            Some(if status == "unknown" {
                "unknown"
            } else {
                "invalid_encoding"
            })
        );
        assert_eq!(region.standard_support.status, status);
        assert_eq!(
            region.standard_support.display,
            if status == "unknown" {
                "opaque"
            } else {
                "binary"
            }
        );
        assert!(region.description.contains(message));
        if expected.is_none() {
            assert!(region.children.is_empty());
            assert!(!regions(module)
                .iter()
                .any(|r| r.path.starts_with(&format!("{path}/"))));
        }
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|r| r.path == path || r.path.starts_with(&format!("{path}/")))
            .collect();
        assert_eq!(rows.len(), if expected.is_some() { 2 } else { 1 });
        if let Some((start, end, field, reason)) = expected {
            let child_path = format!("{path}/{leaf}");
            let span = Span {
                start: fixture.opcode + start,
                end: fixture.opcode + end,
            };
            let description = format!(
                "{field}: {reason}; only this field is diagnosed, remaining bytes stay undecoded"
            );
            assert!(span.start <= span.end && span.end <= fixture.end);
            assert_eq!(region.children.len(), 1);
            assert_eq!(region.children[0].path, child_path);
            let child = at(module, &child_path);
            assert_eq!(child.span, span);
            assert_eq!(child.description, description);
            assert_eq!(child.feature.as_deref(), Some("invalid_encoding"));
            assert_eq!(child.standard_support.status, "invalid_encoding");
            assert_eq!(child.standard_support.display, "binary");
            assert!(child.children.is_empty());
            let descendants: Vec<_> = regions(module)
                .into_iter()
                .filter(|r| r.path.starts_with(&format!("{path}/")))
                .map(|r| r.path.as_str())
                .collect();
            assert_eq!(descendants, vec![child_path.as_str()]);
            let raw = hex(&fixture.bytes[span.start..span.end]);
            assert_eq!(
                serde_json::to_value(rows[1]).unwrap(),
                serde_json::json!({
                    "path": child_path, "span": span, "feature": "section_structure", "status": "invalid_encoding",
                    "kind": "structure", "reason": description, "raw_hex": raw, "recognized": null
                })
            );
            let line = format!("invalid_encoding {child_path} [{}..{}) binary={raw} feature=section_structure recognized=None: {description}", span.start, span.end);
            assert_eq!(
                module
                    .to_text()
                    .lines()
                    .filter(|l| l.starts_with(&format!("invalid_encoding {child_path} ")))
                    .collect::<Vec<_>>(),
                vec![line.as_str()]
            );
            let derived: Vec<_> = module
                .diagnostics
                .iter()
                .filter(|d| d.code == "invalid_encoding" && d.message == description)
                .collect();
            assert_eq!(derived.len(), 1);
            assert_eq!(
                serde_json::to_value(derived[0]).unwrap(),
                serde_json::json!({
                    "severity": "error", "code": "invalid_encoding", "offset": span.start, "message": description
                })
            );
            if leaf == "simd_immediate_error" {
                let original = module
                    .diagnostics
                    .iter()
                    .position(|diagnostic| {
                        diagnostic.code == "operator_decode"
                            && diagnostic.offset == fixture.opcode
                            && diagnostic.message.contains("unexpected end-of-file")
                    })
                    .unwrap();
                let parent = module
                    .diagnostics
                    .iter()
                    .position(|diagnostic| {
                        diagnostic.code == "invalid_encoding"
                            && diagnostic.offset == fixture.opcode
                            && diagnostic.message == rows[0].reason
                    })
                    .unwrap();
                let child = module
                    .diagnostics
                    .iter()
                    .position(|diagnostic| {
                        diagnostic.code == "invalid_encoding"
                            && diagnostic.offset == span.start
                            && diagnostic.message == description
                    })
                    .unwrap();
                assert!(original < parent && parent < child);
            }
        }
        let row = rows[0];
        assert_eq!(row.path, path);
        assert_eq!(row.span, region.span);
        assert_eq!(row.status, status);
        assert_eq!(row.kind, "opaque");
        assert_eq!(
            row.feature,
            if status == "unknown" {
                "unknown"
            } else {
                "expression_structure"
            }
        );
        assert_eq!(row.recognized, None);
        assert_eq!(
            row.raw_hex,
            hex(&fixture.bytes[fixture.opcode..fixture.end])
        );
        assert!(row.reason.contains(message));
        if status == "unknown" {
            assert!(row
                .reason
                .starts_with("unrecognized or unclassified instruction grammar: "));
        }
        let line = format!(
            "{status} {path} [{}..{}) binary={} feature={} recognized=None: {}",
            row.span.start, row.span.end, row.raw_hex, row.feature, row.reason
        );
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|l| l.starts_with(&format!("{status} {path} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
        assert!(module.diagnostics.iter().any(|d| d.code == diagnostic
            && d.severity == severity
            && d.offset == fixture.opcode
            && d.message.contains(message)));
        let derived: Vec<_> = module
            .diagnostics
            .iter()
            .filter(|d| d.code == "invalid_encoding" && d.offset == fixture.opcode)
            .collect();
        if status == "unknown" {
            assert!(derived.is_empty());
        } else {
            assert!(derived.iter().any(|d| d.message == row.reason));
        }
        assert!(!regions(module).iter().any(|r| r
            .path
            .starts_with(&format!("{}/operator[", fixture.expression))));
        assert!(!module.standard.evidence.iter().any(|r| r
            .path
            .starts_with(&format!("{}/operator[", fixture.expression))));
    });
}

fn decoded(instruction: &[u8], name: &str) {
    let fixture = fixture(instruction, true);
    check(&fixture, |_, module| {
        let first = at(module, "code[0]/function[1]/operator[0]");
        assert_eq!(
            first.span,
            Span {
                start: fixture.opcode,
                end: fixture.opcode + instruction.len()
            }
        );
        assert!(first.description.starts_with(name));
        assert!(!regions(module)
            .iter()
            .any(|r| r.path == "code[0]/function[1]/opaque"));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|r| r.path == first.path && r.status == "invalid_encoding"));
        let next = at(module, "code[0]/function[1]/operator[1]");
        assert_eq!(
            next.span,
            Span {
                start: first.span.end,
                end: first.span.end + 2
            }
        );
        assert_eq!(&fixture.bytes[next.span.start..next.span.end], &[0x41, 42]);
        assert_eq!(next.standard_support.status, "supported");
        assert_eq!(
            at(module, "code[0]/function[1]/operator[3]").description,
            "End"
        );
    });
}

#[test]
fn primary_memargs_stop_at_unknown_flags_before_missing_memory_index() {
    opaque(&[0x28, 0xc0, 1], false, "unknown", "unexpected end-of-file");
    opaque(&[0x29, 0xc0, 1], false, "unknown", "unexpected end-of-file");
    opaque(&[0x2c, 0xc0, 1], false, "unknown", "unexpected end-of-file");
    opaque(&[0x35, 0xc0, 1], false, "unknown", "unexpected end-of-file");
    opaque(&[0x36, 0xc0, 1], false, "unknown", "unexpected end-of-file");
    opaque(&[0x3a, 0xc0, 1], false, "unknown", "unexpected end-of-file");
    opaque(&[0x3d, 0xc0, 1], false, "unknown", "unexpected end-of-file");
    opaque(&[0x3e, 0xc0, 1], false, "unknown", "unexpected end-of-file");
}

#[test]
fn unknown_flags_block_later_memory_index_width_errors_in_all_three_families() {
    opaque(
        &[0x28, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
        "invalid var_u32",
    );
    opaque(
        &[0x3e, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
        "invalid var_u32",
    );
    opaque(
        &[0xfd, 0, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
        "invalid var_u32",
    );
    opaque(
        &[0xfd, 0x54, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
        "invalid var_u32",
    );
    opaque(
        &[0xfe, 0, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
        "invalid var_u32",
    );
    opaque(
        &[0xfe, 0x4e, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
        "invalid var_u32",
    );
}

#[test]
fn simd_memarg_ranges_and_lane_forms_share_the_guard_after_padded_subopcodes() {
    opaque(
        &[0xfd, 0, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfd, 0x0b, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfd, 0x54, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfd, 0x5b, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfd, 0x5c, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfd, 0x5d, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfd, 0x80, 0, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfd, 0xd4, 0, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
}

#[test]
fn atomic_memarg_range_boundaries_stop_before_unknown_flag_suffixes() {
    opaque(
        &[0xfe, 0, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfe, 2, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfe, 0x10, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfe, 0x17, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfe, 0x4d, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfe, 0x4e, 0xc0, 1],
        false,
        "unknown",
        "unexpected end-of-file",
    );
}

#[test]
fn complete_unknown_flag_values_padding_and_known_aligned_stops_remain_opaque() {
    opaque(
        &[0x28, 0x80, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
        "malformed memop alignment",
    );
    opaque(
        &[0x28, 0xff, 0xff, 0xff, 0xff, 0x0f],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfd, 0, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x80],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[0xfe, 0x10, 0xc0, 0x81, 0],
        false,
        "unknown",
        "unexpected end-of-file",
    );
    opaque(
        &[
            0x3e, 0xc0, 0x81, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ],
        true,
        "unknown",
        "invalid var_u32",
    );
    opaque(
        &[0x28, 0xc0, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "unknown",
        "malformed memop alignment",
    );
}

#[test]
fn incomplete_flags_and_known_low_bits_preserve_real_integer_and_lane_eof_errors() {
    opaque_memarg(
        &[0x28],
        false,
        "unexpected end-of-file",
        (1, 1, "memarg flags", EOF_REASON),
    );
    opaque_memarg(
        &[0x28, 0xc0],
        false,
        "unexpected end-of-file",
        (1, 2, "memarg flags", EOF_REASON),
    );
    opaque_memarg(
        &[0x28, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "invalid var_u32",
        (1, 6, "memarg flags", WIDTH_REASON),
    );
    opaque_memarg(
        &[0x28, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        true,
        "invalid var_u32",
        (1, 6, "memarg flags", WIDTH_REASON),
    );
    opaque_memarg(
        &[0x28, 0x40],
        false,
        "unexpected end-of-file",
        (2, 2, "memarg memory index", EOF_REASON),
    );
    opaque_memarg(
        &[0x28, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "invalid var_u32",
        (2, 7, "memarg memory index", WIDTH_REASON),
    );
    opaque_simd(&[0xfd, 0x54, 0, 0], 4, 4, "v128.load8_lane lane index");
    opaque_memarg(
        &[0xfe, 0x10, 0],
        false,
        "unexpected end-of-file",
        (3, 3, "memarg offset", EOF_REASON),
    );
}

#[test]
fn non_memarg_secondary_grammars_do_not_borrow_the_flag_rule() {
    opaque_simd(&[0xfd, 0x0c, 0xc0, 1], 2, 4, "v128.const value bytes");
    decoded(&[0xfd, 0x15, 0xc0], "I8x16ExtractLaneS");
    opaque(
        &[0xfe, 3, 1],
        true,
        "unknown",
        "nonzero byte after `atomic.fence`",
    );
    opaque(
        &[0xfe, 0x4f, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "invalid_encoding",
        "invalid var_u32",
    );
    opaque(&[0xfd], false, "invalid_encoding", "unexpected end-of-file");
    opaque(
        &[0xfd, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
        "invalid_encoding",
        "invalid var_u32",
    );
    unknown_opcode(
        &[0xfd, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xc0, 1, 0x80],
        "unknown 0xfd subopcode",
    );
    unknown_opcode(&[0xfe, 4, 0xc0, 1, 0x80], "unknown 0xfe subopcode");
}

#[test]
fn known_alignment_fields_and_u64_offsets_keep_complete_decoded_boundaries() {
    decoded(&[0x28, 3, 0], "I32Load");
    decoded(&[0x28, 0x7f, 0, 0], "I32Load");
    decoded(&[0x28, 2, 0x80, 0x80, 0x80, 0x80, 0x10], "I32Load");
    decoded(&[0x28, 2, 0x80, 0x80, 0x80, 0x80, 0x80, 0], "I32Load");
    decoded(
        &[
            0x28, 2, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ],
        "I32Load",
    );
    decoded(&[0x28, 0x40, 0x80, 0, 0], "I32Load");
    decoded(&[0xfd, 0x80, 0, 0, 0], "V128Load");
    decoded(&[0xfe, 0x10, 0, 0], "I32AtomicLoad");
}

#[test]
fn complete_memarg_and_earlier_unknown_opcode_keep_their_own_failure_positions() {
    let fixture = fixture(&[0x28, 2, 0, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10], true);
    check(&fixture, |_, module| {
        let first = at(module, "code[0]/function[1]/operator[0]");
        assert_eq!(
            first.span,
            Span {
                start: fixture.opcode,
                end: fixture.opcode + 3
            }
        );
        assert!(first.description.starts_with("I32Load"));
        let owner = at(module, "code[0]/function[1]/opaque");
        assert_eq!(
            owner.span,
            Span {
                start: fixture.opcode + 3,
                end: fixture.end
            }
        );
        assert_eq!(owner.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(owner.standard_support.status, "invalid_encoding");
        assert!(owner.children.is_empty());
        assert!(!regions(module)
            .iter()
            .any(|r| r.path == "code[0]/function[1]/operator[1]"));
        assert!(module
            .diagnostics
            .iter()
            .any(|d| d.code == "operator_decode"
                && d.severity == "error"
                && d.offset == owner.span.start
                && d.message.contains("invalid var_i32")));
    });
    unknown_opcode(
        &[0xff, 0x28, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10],
        "illegal opcode",
    );
}

#[test]
fn recovered_constant_owners_share_the_unknown_flag_frontier() {
    opaque_fixture(
        &constant_fixture(6, &[0x28, 0xc0, 1], false),
        "unknown",
        "operator_decode",
        "error",
        "unexpected end-of-file",
    );
    opaque_fixture(
        &constant_fixture(4, &[0x28, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        "unknown",
        "operator_decode",
        "error",
        "invalid var_u32",
    );
    opaque_fixture(
        &constant_fixture(9, &[0x28, 0xc0, 1, 0x80], false),
        "unknown",
        "operator_decode",
        "error",
        "unexpected end-of-file",
    );
}
