//! Fixed locals-field failures and independently framed later-body boundaries.
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

struct OperatorCase {
    body: &'static [u8],
    owner: &'static str,
    start: usize,
    end: usize,
    feature: &'static str,
    status: &'static str,
    display: &'static str,
    diagnostic: &'static str,
    severity: &'static str,
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

fn opaque_control(
    body: &[u8],
    start: usize,
    invalid_bare: bool,
    prior_group: Option<(usize, usize)>,
) {
    let fixture = fixture(body);
    check(&fixture, |_, module| {
        no_local_error(module);
        let carrier = at(module, OPAQUE);
        assert_eq!(carrier.span, relative(&fixture, start, body.len()));
        assert_eq!(
            carrier.standard_support.status,
            if invalid_bare {
                "invalid_encoding"
            } else {
                "unknown"
            }
        );
        assert_eq!(
            carrier.standard_support.display,
            if invalid_bare { "binary" } else { "opaque" }
        );
        assert!(carrier.children.is_empty());
        assert!(!regions(module)
            .iter()
            .any(|region| region.path.starts_with(&format!("{FUNCTION}/operator["))));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(&format!("{FUNCTION}/operator["))));
        if let Some((a, b)) = prior_group {
            assert_eq!(
                at(module, &format!("{FUNCTION}/local_group[0]")).span,
                relative(&fixture, a, b)
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

#[test]
fn local_declaration_count_diagnoses_only_its_eof_width_or_long_field() {
    for case in [
        Case {
            body: &[],
            field: "local declaration count",
            start: 0,
            end: 0,
            opaque: 0,
            prior_group: None,
            reason: EOF,
        },
        Case {
            body: &[0x80],
            field: "local declaration count",
            start: 0,
            end: 1,
            opaque: 0,
            prior_group: None,
            reason: EOF,
        },
        Case {
            body: &[0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "local declaration count",
            start: 0,
            end: 5,
            opaque: 0,
            prior_group: None,
            reason: INTEGER,
        },
        Case {
            body: &[0x80, 0x80, 0x80, 0x80, 0x80, 0],
            field: "local declaration count",
            start: 0,
            end: 5,
            opaque: 0,
            prior_group: None,
            reason: INTEGER,
        },
    ] {
        known(&case);
    }
}

#[test]
fn local_repetition_count_is_separate_from_the_complete_declaration_count() {
    for case in [
        Case {
            body: &[1],
            field: "local repetition count",
            start: 1,
            end: 1,
            opaque: 1,
            prior_group: None,
            reason: EOF,
        },
        Case {
            body: &[1, 0x80],
            field: "local repetition count",
            start: 1,
            end: 2,
            opaque: 1,
            prior_group: None,
            reason: EOF,
        },
        Case {
            body: &[1, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
            field: "local repetition count",
            start: 1,
            end: 6,
            opaque: 1,
            prior_group: None,
            reason: INTEGER,
        },
        Case {
            body: &[1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f],
            field: "local repetition count",
            start: 1,
            end: 6,
            opaque: 1,
            prior_group: None,
            reason: INTEGER,
        },
        Case {
            body: &[2, 1, 0x7f, 0x80],
            field: "local repetition count",
            start: 3,
            end: 4,
            opaque: 3,
            prior_group: Some((1, 3)),
            reason: EOF,
        },
        Case {
            body: &[0xff, 0xff, 0xff, 0xff, 0x0f],
            field: "local repetition count",
            start: 5,
            end: 5,
            opaque: 5,
            prior_group: None,
            reason: EOF,
        },
    ] {
        known(&case);
    }
}

#[test]
fn local_value_type_eof_includes_its_complete_known_constructor_prefix() {
    for case in [
        Case {
            body: &[1, 1],
            field: "local value type",
            start: 2,
            end: 2,
            opaque: 1,
            prior_group: None,
            reason: EOF,
        },
        Case {
            body: &[1, 1, 0x63],
            field: "local value type",
            start: 2,
            end: 3,
            opaque: 1,
            prior_group: None,
            reason: EOF,
        },
        Case {
            body: &[1, 1, 0x64],
            field: "local value type",
            start: 2,
            end: 3,
            opaque: 1,
            prior_group: None,
            reason: EOF,
        },
        Case {
            body: &[1, 1, 0x65],
            field: "local value type",
            start: 2,
            end: 3,
            opaque: 1,
            prior_group: None,
            reason: EOF,
        },
    ] {
        known(&case);
    }
}

#[test]
fn local_heap_type_clone_cursor_errors_keep_the_full_value_field_span() {
    for case in [
        Case {
            body: &[1, 1, 0x63, 0x80],
            field: "local value type",
            start: 2,
            end: 4,
            opaque: 1,
            prior_group: None,
            reason: EOF,
        },
        Case {
            body: &[1, 1, 0x64, 0x80, 0x80, 0x80, 0x80, 0x10, 0xa5],
            field: "local value type",
            start: 2,
            end: 8,
            opaque: 1,
            prior_group: None,
            reason: INTEGER,
        },
        Case {
            body: &[1, 1, 0x63, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
            field: "local value type",
            start: 2,
            end: 8,
            opaque: 1,
            prior_group: None,
            reason: INTEGER,
        },
        Case {
            body: &[2, 1, 0x7f, 1, 0x64, 0x80],
            field: "local value type",
            start: 4,
            end: 6,
            opaque: 3,
            prior_group: Some((1, 3)),
            reason: EOF,
        },
    ] {
        known(&case);
    }
}

#[test]
fn a_later_incomplete_group_keeps_the_prior_complete_local_group() {
    for case in [
        Case {
            body: &[2, 1, 0x7f, 1],
            field: "local value type",
            start: 4,
            end: 4,
            opaque: 3,
            prior_group: Some((1, 3)),
            reason: EOF,
        },
        Case {
            body: &[2, 1, 0x7f, 1, 0x65],
            field: "local value type",
            start: 4,
            end: 5,
            opaque: 3,
            prior_group: Some((1, 3)),
            reason: EOF,
        },
    ] {
        known(&case);
    }
}

#[test]
fn future_value_forms_and_bare_indices_do_not_gain_new_locals_diagnostics() {
    opaque_control(&[1, 1, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10], 1, false, None);
    opaque_control(&[2, 0, 0x7a, 1, 0x7f, 0x0b], 1, false, None);
    opaque_control(
        &[2, 1, 0x7f, 1, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        false,
        Some((1, 3)),
    );
    opaque_control(
        &[1, 1, 0x65, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        false,
        None,
    );
    opaque_control(
        &[1, 1, 0x63, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        false,
        None,
    );
    opaque_control(
        &[1, 1, 0x64, 0x7b, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        false,
        None,
    );
    opaque_control(&[1, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x10], 1, true, None);
}

#[test]
fn implementation_and_cumulative_local_limits_stop_before_a_fake_type_error() {
    opaque_control(
        &[
            1, 1, 0x63, 0x80, 0x80, 0xc0, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        1,
        false,
        None,
    );
    // Group0 has u32::MAX locals. The next repetition count1 overflows the
    // pinned cumulative counter before its missing/bad type can be read.
    opaque_control(
        &[2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1],
        7,
        false,
        Some((1, 7)),
    );
    opaque_control(
        &[
            2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        7,
        false,
        Some((1, 7)),
    );
    opaque_control(
        &[
            2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 1, 0xff, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        7,
        false,
        Some((1, 7)),
    );
    // 50001 is wire-legal: the validator's separate maximum does not turn
    // this successfully decoded local group into an integer encoding failure.
    let fixture = fixture(&[1, 0xd1, 0x86, 3, 0x7f, 0x0b]);
    check(&fixture, |_, module| {
        no_local_error(module);
        assert_eq!(
            at(module, &format!("{FUNCTION}/local_group[0]")).span,
            relative(&fixture, 1, 5)
        );
        assert_eq!(
            at(module, &format!("{FUNCTION}/operator[0]")).span,
            relative(&fixture, 5, 6)
        );
        assert!(!regions(module).iter().any(|region| region.path == OPAQUE));
    });
}

#[test]
fn canonical_and_padded_local_fields_preserve_their_original_wire_spans() {
    for (body, count_end, group, operator) in [
        (&[0x80, 0x80, 0x80, 0x80, 0, 0x0b][..], 5, None, 5),
        (
            &[0x81, 0x80, 0x80, 0x80, 0, 0, 0x7f, 0x0b][..],
            5,
            Some((5, 7)),
            7,
        ),
        (
            &[1, 0x80, 0x80, 0x80, 0x80, 0, 0x7f, 0x0b][..],
            1,
            Some((1, 7)),
            7,
        ),
        (
            &[1, 0x81, 0x80, 0x80, 0x80, 0, 0x7f, 0x0b][..],
            1,
            Some((1, 7)),
            7,
        ),
        (&[1, 0, 0x63, 0x80, 0, 0x0b][..], 1, Some((1, 5)), 5),
        (
            &[1, 0, 0x64, 0x80, 0x80, 0x80, 0x80, 0, 0x0b][..],
            1,
            Some((1, 8)),
            8,
        ),
    ] {
        let fixture = fixture(body);
        check(&fixture, |_, module| {
            no_local_error(module);
            assert_eq!(
                at(module, &format!("{FUNCTION}/locals_count")).span,
                relative(&fixture, 0, count_end)
            );
            if let Some((start, end)) = group {
                assert_eq!(
                    at(module, &format!("{FUNCTION}/local_group[0]")).span,
                    relative(&fixture, start, end)
                );
            }
            assert_eq!(
                at(module, &format!("{FUNCTION}/operator[0]")).span,
                relative(&fixture, operator, operator + 1)
            );
            assert!(!regions(module).iter().any(|region| region.path == OPAQUE));
        });
    }
}

#[test]
fn complete_locals_leave_invalid_or_unknown_operators_with_the_operator_decoder() {
    for case in [
        OperatorCase {
            body: &[0, 0xff, 0x0b],
            owner: "opaque",
            start: 1,
            end: 3,
            feature: "unknown",
            status: "unknown",
            display: "opaque",
            diagnostic: "unknown_operator",
            severity: "warning",
        },
        OperatorCase {
            body: &[0, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10],
            owner: "opaque",
            start: 1,
            end: 7,
            feature: "invalid_encoding",
            status: "invalid_encoding",
            display: "binary",
            diagnostic: "operator_decode",
            severity: "error",
        },
        OperatorCase {
            body: &[1, 1, 0x7f, 0xff, 0x0b],
            owner: "opaque",
            start: 3,
            end: 5,
            feature: "unknown",
            status: "unknown",
            display: "opaque",
            diagnostic: "unknown_operator",
            severity: "warning",
        },
        OperatorCase {
            body: &[1, 1, 0x7f, 0x1c, 1, 0xff, 0x0b],
            owner: "opaque",
            start: 3,
            end: 7,
            feature: "unknown_value_type",
            status: "unknown",
            display: "opaque",
            diagnostic: "unknown_operator",
            severity: "warning",
        },
        OperatorCase {
            body: &[1, 1, 0x7f],
            owner: "expression_structure",
            start: 3,
            end: 3,
            feature: "invalid_encoding",
            status: "invalid_encoding",
            display: "binary",
            diagnostic: "expression_structure",
            severity: "error",
        },
        OperatorCase {
            body: &[0, 0x05, 0x0b],
            owner: "opaque",
            start: 1,
            end: 3,
            feature: "invalid_encoding",
            status: "invalid_encoding",
            display: "binary",
            diagnostic: "operator_decode",
            severity: "error",
        },
    ] {
        let fixture = fixture(case.body);
        check(&fixture, |_, module| {
            no_local_error(module);
            let owner_path = format!("{FUNCTION}/{}", case.owner);
            let owner = at(module, &owner_path);
            assert_eq!(owner.span, relative(&fixture, case.start, case.end));
            assert_eq!(owner.feature.as_deref(), Some(case.feature));
            assert_eq!(owner.standard_support.status, case.status);
            assert_eq!(owner.standard_support.display, case.display);
            assert!(owner.children.is_empty());
            assert!(module
                .standard
                .evidence
                .iter()
                .any(|row| row.path == owner_path
                    && row.span == owner.span
                    && row.status == case.status));
            assert!(module.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == case.diagnostic
                    && diagnostic.severity == case.severity
                    && diagnostic.offset == fixture.body.start + case.start
            }));
            if case.owner == "expression_structure" {
                assert!(!regions(module).iter().any(|region| region.path == OPAQUE));
            }
            assert!(!module
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "locals_decode"));
            at(module, &format!("{FUNCTION}/locals_count"));
            if case.body[0] == 1 {
                assert_eq!(
                    at(module, &format!("{FUNCTION}/local_group[0]")).span,
                    relative(&fixture, 1, 3)
                );
            }
        });
    }
}

#[test]
fn all_five_numeric_and_vector_types_are_still_legal_local_value_types() {
    for body in [
        &[1, 1, 0x7f, 0x0b][..],
        &[1, 1, 0x7e, 0x0b][..],
        &[1, 1, 0x7d, 0x0b][..],
        &[1, 1, 0x7c, 0x0b][..],
        &[1, 1, 0x7b, 0x0b][..],
    ] {
        let fixture = fixture(body);
        check(&fixture, |_, module| {
            no_local_error(module);
            assert_eq!(
                at(module, &format!("{FUNCTION}/local_group[0]")).span,
                relative(&fixture, 1, 3)
            );
            assert_eq!(
                at(module, &format!("{FUNCTION}/operator[0]")).span,
                relative(&fixture, 3, 4)
            );
            assert!(!regions(module).iter().any(|region| region.path == OPAQUE));
        });
    }
}
