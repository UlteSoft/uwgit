//! Fixed cumulative locals-reader frontiers; no generated inputs or fuzzing.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const FUNCTION: &str = "code[0]/function[1]";
const OPAQUE: &str = "code[0]/function[1]/opaque";
const ERROR: &str = "code[0]/function[1]/opaque/locals_error";
const EOF: &str = "known encoding is truncated at its trusted input boundary";
const INTEGER: &str = "integer encoding exceeds its required width or length";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

struct Case {
    body: &'static [u8],
    field: &'static str,
    start: usize,
    end: usize,
    opaque: usize,
    prior_group: Option<(usize, usize)>,
    reason: &'static str,
}

struct Fixture {
    bytes: Vec<u8>,
    frame: Span,
    body: Span,
    later: Span,
    custom: usize,
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

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn fixture(body: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[3, 0, 0, 0]);
    let mut code = vec![3, 2, 0, 0x0b, body.len() as u8];
    code.extend_from_slice(body);
    // One complete, independent body after the target. Its modern grammar is
    // decoded in every profile before compatibility is evaluated.
    code.extend_from_slice(&[
        33, 0, 0xfd, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a, 0x41, 0, 0xfb,
        0x1c, 0x1a, 0x1f, 0x40, 0, 0x0b, 0x41, 42, 0x1a, 0x0b,
    ]);
    let start = section(&mut bytes, 10, &code);
    let frame = Span {
        start: start + 4,
        end: start + 5 + body.len(),
    };
    let body = Span {
        start: frame.start + 1,
        end: frame.end,
    };
    let later = Span {
        start: frame.end + 1,
        end: bytes.len(),
    };
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        frame,
        body,
        later,
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

fn relative(fixture: &Fixture, start: usize, end: usize) -> Span {
    Span {
        start: fixture.body.start + start,
        end: fixture.body.start + end,
    }
}

fn check(fixture: &Fixture, mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        assert_eq!(
            at(&module, "code[0]/function[0]").span,
            Span { start: 23, end: 26 }
        );
        assert_eq!(
            at(&module, "code[0]/function[0]/operator[0]").span,
            Span { start: 25, end: 26 }
        );
        assert_eq!(at(&module, FUNCTION).span, fixture.frame);
        assert_eq!(
            at(&module, &format!("{FUNCTION}/body_size")).span,
            Span {
                start: fixture.frame.start,
                end: fixture.body.start
            }
        );
        assert_eq!(
            at(&module, "code[0]/function[2]").span,
            Span {
                start: fixture.later.start - 1,
                end: fixture.later.end
            }
        );
        assert_eq!(fixture.later.end - fixture.later.start, 33);
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
        assert!(!regions(&module)
            .iter()
            .any(|region| region.path == "code[0]/undecoded/code_error"));
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

fn no_local_error(module: &AuditModule) {
    assert!(!regions(module).iter().any(|region| region.path == ERROR));
    assert!(!module.standard.evidence.iter().any(|row| row.path == ERROR));
}

fn known(case: &Case) {
    let fixture = fixture(case.body);
    check(&fixture, |_, module| {
        let carrier = at(module, OPAQUE);
        assert_eq!(
            carrier.span,
            relative(&fixture, case.opaque, case.body.len())
        );
        assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(carrier.standard_support.status, "invalid_encoding");
        assert_eq!(carrier.standard_support.display, "binary");
        let child = at(module, ERROR);
        let span = relative(&fixture, case.start, case.end);
        let description = format!(
            "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
            case.field, case.reason
        );
        assert_eq!(child.span, span);
        assert_eq!(child.description, description);
        assert_eq!(child.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(child.standard_support.status, "invalid_encoding");
        assert_eq!(child.standard_support.display, "binary");
        assert!(child.children.is_empty());
        assert_eq!(carrier.children.len(), 1);
        assert_eq!(carrier.children[0].path, ERROR);
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == ERROR)
            .collect();
        assert_eq!(rows.len(), 1);
        let raw = hex(&case.body[case.start..case.end]);
        assert_eq!(
            serde_json::to_value(rows[0]).unwrap(),
            serde_json::json!({
                "path": ERROR, "span": span, "feature": "section_structure", "status": "invalid_encoding",
                "kind": "structure", "reason": description, "raw_hex": raw, "recognized": null
            })
        );
        let line = format!("invalid_encoding {ERROR} [{}..{}) binary={raw} feature=section_structure recognized=None: {description}", span.start, span.end);
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|text| text.starts_with(&format!("invalid_encoding {ERROR} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
        assert!(!regions(module)
            .iter()
            .any(|region| region.path.starts_with(&format!("{FUNCTION}/operator["))));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(&format!("{FUNCTION}/operator["))));
        if let Some((start, end)) = case.prior_group {
            assert_eq!(
                at(module, &format!("{FUNCTION}/local_group[0]")).span,
                relative(&fixture, start, end)
            );
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == format!("{FUNCTION}/local_group[1]")));
        } else {
            assert!(!regions(module)
                .iter()
                .any(|region| region.path.starts_with(&format!("{FUNCTION}/local_group["))));
        }
    });
}

fn prior_groups(module: &AuditModule, fixture: &Fixture, groups: &[(usize, usize)]) {
    for (index, &(start, end)) in groups.iter().enumerate() {
        assert_eq!(
            at(module, &format!("{FUNCTION}/local_group[{index}]")).span,
            relative(fixture, start, end)
        );
    }
    assert!(!regions(module)
        .iter()
        .any(|region| region.path == format!("{FUNCTION}/local_group[{}]", groups.len())));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path == format!("{FUNCTION}/local_group[{}]", groups.len())));
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.starts_with(&format!("{FUNCTION}/operator["))));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path.starts_with(&format!("{FUNCTION}/operator["))));
}

fn resource(body: &[u8], start: usize, count_end: usize, groups: &[(usize, usize)]) {
    let fixture = fixture(body);
    check(&fixture, |_, module| {
        no_local_error(module);
        assert_eq!(
            module
                .sections
                .iter()
                .find(|section| section.id == 10)
                .unwrap()
                .status,
            "malformed"
        );
        let carrier = at(module, OPAQUE);
        let span = relative(&fixture, start, body.len());
        let offset = fixture.body.start + count_end;
        let reader_error = format!("too many locals (at offset 0x{offset:x})");
        assert_eq!(carrier.span, span);
        assert_eq!(carrier.feature.as_deref(), Some("unknown"));
        assert_eq!(carrier.standard_support.status, "unknown");
        assert_eq!(carrier.standard_support.display, "opaque");
        assert_eq!(carrier.standard_support.required_features, vec!["unknown"]);
        assert!(carrier.children.is_empty());
        assert_eq!(carrier.description, format!("unrecognized or unclassified locals grammar: {reader_error}; undecoded locals and remaining instructions"));
        let reason = format!("unrecognized or unclassified locals grammar: {reader_error}; locals and remaining body are not decoded; the framed next body remains independently readable");
        let raw = hex(&body[start..]);
        let own: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == OPAQUE || row.path.starts_with(&format!("{OPAQUE}/")))
            .map(|row| serde_json::to_value(row).unwrap())
            .collect();
        assert_eq!(
            own,
            vec![serde_json::json!({
                "path": OPAQUE, "span": span, "feature": "unknown", "status": "unknown", "kind": "opaque",
                "reason": reason, "raw_hex": raw, "recognized": null
            })]
        );
        assert!(!regions(module)
            .iter()
            .any(|region| region.path.starts_with(&format!("{OPAQUE}/"))));
        prior_groups(module, &fixture, groups);
        let diagnostics: Vec<_> = module
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "locals_decode")
            .map(|diagnostic| serde_json::to_value(diagnostic).unwrap())
            .collect();
        assert_eq!(
            diagnostics,
            vec![
                serde_json::json!({"severity": "error", "code": "locals_decode", "offset": offset, "message": reader_error})
            ]
        );
        assert!(!module.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("untrusted local value-type prefix")));
        let line = format!(
            "unknown {OPAQUE} [{}..{}) binary={raw} feature=unknown recognized=None: {reason}",
            span.start, span.end
        );
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|text| text.starts_with(&format!("unknown {OPAQUE} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
    });
}

fn unknown(
    body: &[u8],
    start: usize,
    type_offset: usize,
    invalid: bool,
    groups: &[(usize, usize)],
) {
    let fixture = fixture(body);
    check(&fixture, |_, module| {
        no_local_error(module);
        let carrier = at(module, OPAQUE);
        let span = relative(&fixture, start, body.len());
        let reason = if invalid {
            "a bare positive type index is not a value-type shorthand; remaining locals and body are not decoded"
        } else {
            "unknown local value-type prefix; remaining locals and body are not decoded"
        };
        let status = if invalid {
            "invalid_encoding"
        } else {
            "unknown"
        };
        let feature = if invalid {
            "reference_type_encoding"
        } else {
            "unknown"
        };
        assert_eq!(carrier.span, span);
        assert_eq!(
            carrier.feature.as_deref(),
            Some(if invalid {
                "invalid_encoding"
            } else {
                "unknown"
            })
        );
        assert_eq!(carrier.standard_support.status, status);
        assert_eq!(
            carrier.standard_support.display,
            if invalid { "binary" } else { "opaque" }
        );
        assert!(carrier.children.is_empty());
        assert_eq!(carrier.description, reason);
        let raw = hex(&body[start..]);
        let own: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == OPAQUE || row.path.starts_with(&format!("{OPAQUE}/")))
            .map(|row| serde_json::to_value(row).unwrap())
            .collect();
        assert_eq!(
            own,
            vec![
                serde_json::json!({"path": OPAQUE, "span": span, "feature": feature, "status": status, "kind": "opaque", "reason": reason, "raw_hex": raw, "recognized": null})
            ]
        );
        prior_groups(module, &fixture, groups);
        let diagnostics: Vec<_> = module
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "locals_decode")
            .map(|diagnostic| serde_json::to_value(diagnostic).unwrap())
            .collect();
        assert_eq!(
            diagnostics,
            vec![
                serde_json::json!({"severity": if invalid { "error" } else { "warning" }, "code": "locals_decode", "offset": fixture.body.start + type_offset, "message": "untrusted local value-type prefix; no later group or instruction boundaries inferred"})
            ]
        );
        assert!(!own[0]["reason"]
            .as_str()
            .unwrap()
            .contains("too many locals"));
        let line = format!(
            "{status} {OPAQUE} [{}..{}) binary={raw} feature={feature} recognized=None: {reason}",
            span.start, span.end
        );
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|text| text.starts_with(&format!("{status} {OPAQUE} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
    });
}

fn decoded(body: &[u8], groups: &[(usize, usize)], end: usize) {
    let fixture = fixture(body);
    check(&fixture, |_, module| {
        no_local_error(module);
        assert!(!regions(module).iter().any(|region| region.path == OPAQUE));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path == OPAQUE || row.reason.contains("too many locals")));
        for (index, &(start, finish)) in groups.iter().enumerate() {
            let region = at(module, &format!("{FUNCTION}/local_group[{index}]"));
            assert_eq!(region.span, relative(&fixture, start, finish));
            assert_eq!(region.standard_support.status, "supported");
        }
        let operator = at(module, &format!("{FUNCTION}/operator[0]"));
        assert_eq!(operator.span, relative(&fixture, end, end + 1));
        assert_eq!(operator.description, "End");
        assert_eq!(operator.standard_support.status, "supported");
        assert!(!module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "locals_decode"));
        // The separate validator rejects its own maximum before these huge
        // counts become executable locals. The wire reader does not allocate
        // them and must still preserve their known field/operator boundaries.
        assert!(!module.standard.validator_valid);
    });
}

#[test]
fn overflowing_repetition_precedes_every_unread_future_or_bare_type() {
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7a],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x76],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[
            2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 1],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x3f],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x65, 0x7f],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[
            2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7a, 1, 0x7f, 0x41, 42, 0x1a, 0x0b,
        ],
        7,
        8,
        &[(1, 7)],
    );
}

#[test]
fn known_type_eof_and_bad_heap_suffixes_preserve_the_same_resource_error() {
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7f],
        7,
        8,
        &[(1, 7)],
    );
    resource(&[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1], 7, 8, &[(1, 7)]);
    resource(
        &[
            2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7b],
        7,
        8,
        &[(1, 7)],
    );
}

#[test]
fn padded_counts_and_multiple_prior_groups_share_checked_u32_accumulation() {
    resource(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0x81, 0, 0x7a],
        7,
        9,
        &[(1, 7)],
    );
    resource(
        &[0x82, 0, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0],
        8,
        9,
        &[(2, 8)],
    );
    resource(
        &[2, 0xfe, 0xff, 0xff, 0xff, 0x0f, 0x7f, 2, 0x7a],
        7,
        8,
        &[(1, 7)],
    );
    resource(
        &[3, 0xfe, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7e, 1, 0x7a],
        9,
        10,
        &[(1, 7), (7, 9)],
    );
    resource(
        &[
            2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7a,
        ],
        7,
        12,
        &[(1, 7)],
    );
    resource(
        &[3, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0, 0x7f, 1, 0x7a],
        9,
        10,
        &[(1, 7), (7, 9)],
    );
}

#[test]
fn admitted_sum_and_zero_repetition_reach_the_actual_type_frontier() {
    unknown(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0, 0x7a],
        7,
        8,
        false,
        &[(1, 7)],
    );
    unknown(
        &[2, 0xfe, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7a],
        7,
        8,
        false,
        &[(1, 7)],
    );
    unknown(
        &[2, 0xfe, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0],
        7,
        8,
        true,
        &[(1, 7)],
    );
    unknown(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7a, 1, 0, 0x41, 42, 0x0b],
        1,
        6,
        false,
        &[],
    );
}

#[test]
fn admitted_full_u32_total_keeps_known_groups_and_the_end_operator() {
    decoded(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0, 0x7f, 0x0b],
        &[(1, 7), (7, 9)],
        9,
    );
    decoded(
        &[2, 0xfe, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7e, 0x0b],
        &[(1, 7), (7, 9)],
        9,
    );
    decoded(
        &[
            3, 0xfe, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7e, 0, 0x7f, 0x0b,
        ],
        &[(1, 7), (7, 9), (9, 11)],
        11,
    );
}

#[test]
fn malformed_repetition_leb_fails_before_the_cumulative_count_check() {
    for case in [
        Case {
            body: &[
                2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7a,
            ],
            field: "local repetition count",
            start: 7,
            end: 12,
            opaque: 7,
            prior_group: Some((1, 7)),
            reason: INTEGER,
        },
        Case {
            body: &[
                2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0x7a,
            ],
            field: "local repetition count",
            start: 7,
            end: 12,
            opaque: 7,
            prior_group: Some((1, 7)),
            reason: INTEGER,
        },
        Case {
            body: &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0x80],
            field: "local repetition count",
            start: 7,
            end: 8,
            opaque: 7,
            prior_group: Some((1, 7)),
            reason: EOF,
        },
    ] {
        known(&case);
    }
}

#[test]
fn an_earlier_unknown_or_bare_type_blocks_later_cumulative_claims() {
    unknown(
        &[2, 1, 0x7a, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0],
        1,
        2,
        false,
        &[],
    );
    unknown(
        &[2, 1, 0, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x7a],
        1,
        2,
        true,
        &[],
    );
}
