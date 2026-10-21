//! Fixed typed-select reader resource frontiers and bounded controls; no fuzzing.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const EOF_REASON: &str = "known encoding is truncated at its trusted input boundary";
const WIDTH_REASON: &str = "integer encoding exceeds its required width or length";
const RESOURCE_REASON: &str = "select types size is out of bounds";
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

fn check_validator_locations(fixture: &Fixture, module: &AuditModule) {
    fn add(output: &mut Vec<serde_json::Value>, path: &str, span: Span, offset: usize) {
        let relation = if span.start == offset && span.end == offset {
            Some("empty_at_offset")
        } else if span.start <= offset && offset < span.end {
            Some("contains_offset")
        } else if span.start < offset && span.end == offset {
            Some("ends_at_offset")
        } else {
            None
        };
        if let Some(relation) = relation {
            output.push(serde_json::json!({"path": path, "span": span, "relation": relation}));
        }
    }
    fn visit(output: &mut Vec<serde_json::Value>, entries: &[Region], offset: usize) {
        for region in entries {
            add(output, &region.path, region.span, offset);
            visit(output, &region.children, offset);
        }
    }
    if let Some(error) = &module.standard.validator_error {
        let mut expected = Vec::new();
        for section in &module.sections {
            add(&mut expected, &section.path, section.span, error.offset);
            visit(&mut expected, &section.regions, error.offset);
        }
        assert_eq!(
            serde_json::to_value(&error.locations).unwrap(),
            serde_json::Value::Array(expected)
        );
        let context = &error.byte_context;
        let cursor = error.offset.min(fixture.bytes.len());
        assert_eq!(
            context.span,
            Span {
                start: cursor.saturating_sub(8),
                end: cursor.saturating_add(8).min(fixture.bytes.len())
            }
        );
        assert_eq!(
            context.raw_hex,
            hex(&fixture.bytes[context.span.start..context.span.end])
        );
        assert_eq!(
            context.offset_in_module,
            error.offset <= fixture.bytes.len()
        );
        assert_eq!(context.offset_is_eof, error.offset == fixture.bytes.len());
    }
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
        check_validator_locations(fixture, &module);
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

fn no_suffix_metadata(module: &AuditModule, fixture: &Fixture, path: &str) {
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.starts_with(&format!("{path}/"))));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path.starts_with(&format!("{path}/"))));
    assert!(!regions(module).iter().any(|region| region
        .path
        .starts_with(&format!("{}/operator[", fixture.expression))));
    assert!(!module.standard.evidence.iter().any(|row| row
        .path
        .starts_with(&format!("{}/operator[", fixture.expression))));
}

fn resource(fixture: &Fixture) {
    check(fixture, |_, module| {
        let path = format!("{}/opaque", fixture.expression);
        let opaque = at(module, &path);
        let span = Span {
            start: fixture.opcode,
            end: fixture.end,
        };
        assert_eq!(opaque.span, span);
        assert_eq!(opaque.feature.as_deref(), Some("unknown"));
        assert_eq!(opaque.standard_support.status, "unknown");
        assert_eq!(opaque.standard_support.display, "opaque");
        assert_eq!(opaque.standard_support.required_features, vec!["unknown"]);
        assert!(opaque.children.is_empty());
        no_suffix_metadata(module, fixture, &path);
        // read_size records the start of the count, before reading its u32.
        let reader_error = format!("{RESOURCE_REASON} (at offset 0x{:x})", fixture.opcode + 1);
        assert_eq!(opaque.description, format!("unrecognized or unclassified instruction grammar: {reader_error}; failed instruction and remaining expression are not decoded; no later instruction boundaries inferred"));
        let reason = format!("unrecognized or unclassified instruction grammar: {reader_error}; failed instruction and remaining expression are not decoded; no resynchronization");
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == path)
            .collect();
        assert_eq!(rows.len(), 1);
        let raw = hex(&fixture.bytes[span.start..span.end]);
        assert_eq!(
            serde_json::to_value(rows[0]).unwrap(),
            serde_json::json!({
                "path": path, "span": span, "feature": "unknown", "status": "unknown", "kind": "opaque",
                "reason": reason, "raw_hex": raw, "recognized": null
            })
        );
        let diagnostic_message = format!("{reader_error}; remaining expression opaque from byte {}, no resynchronization attempted", fixture.opcode);
        let actual: Vec<_> = module
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == "operator_decode" && diagnostic.offset == fixture.opcode
            })
            .collect();
        assert_eq!(actual.len(), 1);
        assert_eq!(
            serde_json::to_value(actual[0]).unwrap(),
            serde_json::json!({
                "severity": "error", "code": "operator_decode", "offset": fixture.opcode, "message": diagnostic_message
            })
        );
        assert!(!module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.offset == fixture.opcode
                && (diagnostic.code == "unknown_operator"
                    || diagnostic.code == "invalid_encoding")));
        assert!(!module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.offset == fixture.opcode
                && diagnostic
                    .message
                    .contains("untrusted typed-select value prefix")));
        let line = format!(
            "unknown {path} [{}..{}) binary={raw} feature=unknown recognized=None: {reason}",
            span.start, span.end
        );
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|text| text.starts_with(&format!("unknown {path} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
    });
}

fn decoded(instruction: &[u8], name: &str) {
    let fixture = fixture(instruction, true);
    check(&fixture, |profile, module| {
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
            .any(|region| region.path == "code[0]/function[1]/opaque"));
        let supported = profile != Standard::Core1;
        let reason = if supported {
            "recognized opcode grammar".to_owned()
        } else {
            format!("recognized opcode grammar; known reference_types grammar is outside {profile}")
        };
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == first.path)
            .map(|row| serde_json::to_value(row).unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![serde_json::json!({
                "path": first.path, "span": first.span, "feature": "reference_types", "status": if supported { "supported" } else { "recognized_but_disabled" },
                "kind": "instruction", "reason": reason, "raw_hex": hex(instruction), "recognized": name
            })]
        );
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

#[derive(Clone, Copy)]
struct Owner {
    start: usize,
    feature: &'static str,
    status: &'static str,
    standard_feature: &'static str,
    diagnostic: &'static str,
    severity: &'static str,
    diagnostic_message: Option<&'static str>,
    evidence_message: Option<&'static str>,
    prior_instruction: Option<(&'static str, usize)>,
}
const UNKNOWN_OWNER: Owner = Owner {
    start: 0,
    feature: "unknown",
    status: "unknown",
    standard_feature: "unknown",
    diagnostic: "unknown_operator",
    severity: "warning",
    diagnostic_message: None,
    evidence_message: None,
    prior_instruction: None,
};
const INVALID_OWNER: Owner = Owner {
    feature: "invalid_encoding",
    status: "invalid_encoding",
    standard_feature: "expression_structure",
    diagnostic: "operator_decode",
    severity: "error",
    ..UNKNOWN_OWNER
};
const EOF_OWNER: Owner = Owner {
    diagnostic_message: Some("unexpected end-of-file"),
    evidence_message: Some(EOF_REASON),
    ..INVALID_OWNER
};
const WIDTH_OWNER: Owner = Owner {
    diagnostic_message: Some("invalid var_u32"),
    evidence_message: Some(WIDTH_REASON),
    ..INVALID_OWNER
};
const UNKNOWN_TYPE: Owner = Owner {
    feature: "unknown_value_type",
    diagnostic_message: Some("untrusted typed-select value prefix"),
    evidence_message: Some("unknown typed-select value-type prefix"),
    ..UNKNOWN_OWNER
};
const BARE_TYPE: Owner = Owner {
    standard_feature: "reference_type_encoding",
    diagnostic_message: Some("untrusted typed-select value prefix"),
    evidence_message: Some("a bare positive type index is not a value-type shorthand"),
    ..INVALID_OWNER
};
fn owned(fixture: &Fixture, expected: Owner) {
    check(fixture, |_, module| {
        let path = format!("{}/opaque", fixture.expression);
        let owner = at(module, &path);
        assert_eq!(
            owner.span,
            Span {
                start: fixture.opcode + expected.start,
                end: fixture.end
            }
        );
        assert_eq!(owner.feature.as_deref(), Some(expected.feature));
        assert_eq!(owner.standard_support.status, expected.status);
        assert_eq!(
            owner.standard_support.display,
            if expected.status == "unknown" {
                "opaque"
            } else {
                "binary"
            }
        );
        assert!(owner.children.is_empty());
        assert!(!regions(module)
            .iter()
            .any(|region| region.path.starts_with(&format!("{path}/"))));
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == path || row.path.starts_with(&format!("{path}/")))
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, path);
        assert_eq!(rows[0].span, owner.span);
        assert_eq!(rows[0].feature, expected.standard_feature);
        assert_eq!(rows[0].status, expected.status);
        assert_eq!(rows[0].kind, "opaque");
        assert_eq!(rows[0].recognized, None);
        assert_eq!(
            rows[0].raw_hex,
            hex(&fixture.bytes[owner.span.start..owner.span.end])
        );
        assert!(!rows[0].reason.contains(RESOURCE_REASON));
        assert!(module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == expected.diagnostic
                && diagnostic.severity == expected.severity
                && diagnostic.offset == owner.span.start
                && expected
                    .diagnostic_message
                    .is_none_or(|message| diagnostic.message.contains(message))));
        if let Some(message) = expected.evidence_message {
            assert!(rows[0].reason.contains(message));
        }
        if let Some((name, length)) = expected.prior_instruction {
            let first = at(module, &format!("{}/operator[0]", fixture.expression));
            assert_eq!(
                first.span,
                Span {
                    start: fixture.opcode,
                    end: fixture.opcode + length
                }
            );
            assert!(first.description.starts_with(name));
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == format!("{}/operator[1]", fixture.expression)));
        } else {
            no_suffix_metadata(module, fixture, &path);
        }
        assert!(!module.standard.evidence.iter().any(|row| row
            .path
            .starts_with(&format!("{}/operator[", fixture.expression))
            && row.span.start >= owner.span.start));
    });
}
#[test]
fn count_eleven_stops_before_every_apparent_value_or_operator_suffix() {
    resource(&fixture(&[0x1c, 0x0b], false));
    resource(&fixture(&[0x1c, 0x0b, 0], true));
    resource(&fixture(&[0x1c, 0x0b, 0x7a], true));
    resource(&fixture(&[0x1c, 0x0b, 0xff], true));
    resource(&fixture(&[0x1c, 0x0b, 0x7f], true));
    resource(&fixture(
        &[0x1c, 0x0b, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
    ));
    resource(&fixture(
        &[0x1c, 0x0b, 0x0b, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10],
        true,
    ));
    resource(&fixture(&[0x1c, 0x0b, 0x65, 0x7f], true));
}

#[test]
fn padded_eleven_and_full_u32_max_have_the_same_reader_resource_frontier() {
    resource(&fixture(&[0x1c, 0x8b, 0], false));
    resource(&fixture(&[0x1c, 0x8b, 0, 0], true));
    resource(&fixture(&[0x1c, 0x8b, 0, 0x7a], true));
    resource(&fixture(&[0x1c, 0xff, 0xff, 0xff, 0xff, 0x0f], false));
    resource(&fixture(&[0x1c, 0xff, 0xff, 0xff, 0xff, 0x0f, 0], true));
    resource(&fixture(
        &[0x1c, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x63, 0x80],
        false,
    ));
}

#[test]
fn count_ten_is_admitted_before_complete_unknown_or_missing_value_types() {
    decoded(
        &[
            0x1c, 0x8a, 0, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        ],
        "TypedSelectMulti",
    );
    owned(&fixture(&[0x1c, 10], false), EOF_OWNER);
    owned(&fixture(&[0x1c, 10, 0x7f], false), EOF_OWNER);
    owned(&fixture(&[0x1c, 10, 0x7a], true), UNKNOWN_TYPE);
}

#[test]
fn zero_and_one_with_legal_count_padding_remain_complete_wire_grammars() {
    decoded(&[0x1c, 0], "TypedSelectMulti");
    decoded(&[0x1c, 0x80, 0], "TypedSelectMulti");
    decoded(&[0x1c, 1, 0x7f], "TypedSelect");
    decoded(&[0x1c, 0x81, 0, 0x7f], "TypedSelect");
}

#[test]
fn admitted_value_prefixes_preserve_bare_future_heap_eof_and_invalid_heap_owners() {
    owned(&fixture(&[0x1c, 1, 0], true), BARE_TYPE);
    owned(&fixture(&[0x1c, 1, 0x7a], true), UNKNOWN_TYPE);
    owned(&fixture(&[0x1c, 1, 0xff, 0], true), UNKNOWN_TYPE);
    owned(&fixture(&[0x1c, 1, 0x63, 0x80], false), EOF_OWNER);
    owned(
        &fixture(&[0x1c, 1, 0x63, 0x80, 0x80, 0x40], false),
        Owner {
            diagnostic: "operator_decode",
            severity: "error",
            diagnostic_message: Some("invalid value type"),
            evidence_message: Some("invalid value type"),
            ..UNKNOWN_OWNER
        },
    );
    owned(&fixture(&[0x1c, 1, 0x65, 0x7f], true), UNKNOWN_TYPE);
}

#[test]
fn count_eof_and_integer_failures_are_encoding_errors_before_resource_admission() {
    owned(&fixture(&[0x1c], false), EOF_OWNER);
    owned(&fixture(&[0x1c, 0x80], false), EOF_OWNER);
    owned(
        &fixture(&[0x1c, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        WIDTH_OWNER,
    );
    owned(
        &fixture(&[0x1c, 0x80, 0x80, 0x80, 0x80, 0x80, 0], true),
        WIDTH_OWNER,
    );
}

#[test]
fn incomplete_or_overwide_counts_do_not_use_low_bits_as_an_early_resource_count() {
    owned(
        &fixture(&[0x1c, 0xff, 0xff, 0xff, 0xff, 0x1f, 0], true),
        WIDTH_OWNER,
    );
    owned(&fixture(&[0x1c, 0x8b, 0x80], false), EOF_OWNER);
}

#[test]
fn completed_selects_and_earlier_unknowns_preserve_later_error_ownership() {
    owned(
        &fixture(&[0x1c, 0, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            start: 2,
            diagnostic_message: Some("invalid var_i32"),
            prior_instruction: Some(("TypedSelectMulti", 2)),
            ..WIDTH_OWNER
        },
    );
    owned(
        &fixture(&[0x1c, 1, 0x7f, 0xff], true),
        Owner {
            start: 3,
            prior_instruction: Some(("TypedSelect", 3)),
            ..UNKNOWN_OWNER
        },
    );
    owned(&fixture(&[0xff, 0x1c, 0x0b, 0], true), UNKNOWN_OWNER);
    owned(
        &fixture(&[0x1c, 1, 0x7a, 0x1c, 0x0b, 0], true),
        UNKNOWN_TYPE,
    );
}

#[test]
fn resource_opaque_constants_do_not_lend_suffixes_to_later_headers_or_code() {
    let global = constant_fixture(6, &[0x1c, 0x0b, 0], false);
    assert_eq!(global.opcode, 30);
    resource(&global);
    let table = constant_fixture(4, &[0x1c, 0x8b, 0, 0x7a], false);
    assert_eq!(table.opcode, 31);
    resource(&table);
    let element = constant_fixture(9, &[0x1c, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x63, 0x80], false);
    assert_eq!(element.opcode, 37);
    resource(&element);
    owned(&constant_fixture(6, &[0x1c, 1, 0x7a], false), UNKNOWN_TYPE);
}
