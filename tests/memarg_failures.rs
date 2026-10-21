//! Fixed memarg flags/index/offset fields and preserved lane ownership; no fuzzing.
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

fn no_memarg_error(module: &AuditModule) {
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.ends_with("/memarg_error")));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path.ends_with("/memarg_error")));
}

fn precise_field(fixture: &Fixture, start: usize, end: usize, field: &str, reason: &str) {
    precise_named(fixture, start, end, field, reason, "memarg_error");
}

fn precise_named(
    fixture: &Fixture,
    start: usize,
    end: usize,
    field: &str,
    reason: &str,
    leaf: &str,
) {
    let description =
        format!("{field}: {reason}; only this field is diagnosed, remaining bytes stay undecoded");
    check(fixture, |_, module| {
        let opaque_path = format!("{}/opaque", fixture.expression);
        let error_path = format!("{opaque_path}/{leaf}");
        if leaf != "memarg_error" {
            no_memarg_error(module);
        }
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
        assert!(opaque
            .standard_support
            .required_features
            .iter()
            .any(|feature| feature == "section_structure"));
        let physical_descendants: Vec<_> = regions(module)
            .into_iter()
            .filter(|region| region.path.starts_with(&format!("{opaque_path}/")))
            .map(|region| region.path.as_str())
            .collect();
        assert_eq!(physical_descendants, vec![error_path.as_str()]);
        let evidence_descendants: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path.starts_with(&format!("{opaque_path}/")))
            .map(|row| row.path.as_str())
            .collect();
        assert_eq!(evidence_descendants, vec![error_path.as_str()]);
        let parents: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == opaque_path)
            .collect();
        assert_eq!(parents.len(), 1);
        let parent = parents[0];
        assert_eq!(parent.span, opaque.span);
        assert_eq!(parent.feature, "expression_structure");
        assert_eq!(parent.status, "invalid_encoding");
        assert_eq!(parent.kind, "opaque");
        assert_eq!(parent.recognized, None);
        assert_eq!(
            parent.raw_hex,
            hex(&fixture.bytes[fixture.opcode..fixture.end])
        );
        assert!(parent.reason.starts_with(reason));
        let actual_diagnostic = module
            .diagnostics
            .iter()
            .position(|diagnostic| {
                diagnostic.code == "operator_decode"
                    && diagnostic.severity == "error"
                    && diagnostic.offset == fixture.opcode
                    && diagnostic.message.contains(if reason == EOF_REASON {
                        "unexpected end-of-file"
                    } else if field == "memarg offset" {
                        "invalid var_u64"
                    } else {
                        "invalid var_u32"
                    })
            })
            .unwrap();
        let parent_diagnostic = module
            .diagnostics
            .iter()
            .position(|diagnostic| {
                diagnostic.code == "invalid_encoding"
                    && diagnostic.severity == "error"
                    && diagnostic.offset == fixture.opcode
                    && diagnostic.message == parent.reason
            })
            .unwrap();
        let derived: Vec<_> = module
            .diagnostics
            .iter()
            .enumerate()
            .filter(|(_, diagnostic)| {
                diagnostic.code == "invalid_encoding" && diagnostic.message == description
            })
            .collect();
        assert_eq!(derived.len(), 1);
        assert_eq!(
            serde_json::to_value(derived[0].1).unwrap(),
            serde_json::json!({
                "severity": "error", "code": "invalid_encoding", "offset": span.start, "message": description
            })
        );
        assert!(actual_diagnostic < parent_diagnostic && parent_diagnostic < derived[0].0);
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

fn decoded(instruction: &[u8], expected_name: Option<&str>) {
    let fixture = fixture(instruction, true);
    check(&fixture, |_, module| {
        no_memarg_error(module);
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
fn scalar_memarg_flags_have_their_own_eof_width_and_length_field() {
    eof(&[0x28], 1, "memarg flags");
    eof(&[0x28, 0xc0], 1, "memarg flags");
    width(&[0x28, 0x80, 0x80, 0x80, 0x80, 0x10], 1, 6, "memarg flags");
    width(
        &[0x3e, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "memarg flags",
    );
}

#[test]
fn simd_memarg_boundaries_and_padded_subopcodes_locate_failed_flags() {
    eof(&[0xfd, 0], 2, "memarg flags");
    eof(&[0xfd, 0x54, 0x80], 2, "memarg flags");
    width(
        &[0xfd, 0x5d, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "memarg flags",
    );
    width(
        &[0xfd, 0x0b, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "memarg flags",
    );
    eof(&[0xfd, 0x80, 0], 3, "memarg flags");
}

#[test]
fn atomic_memarg_boundaries_and_padded_subopcodes_locate_failed_flags() {
    eof(&[0xfe, 0], 2, "memarg flags");
    eof(&[0xfe, 2, 0x80], 2, "memarg flags");
    width(
        &[0xfe, 0x4e, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "memarg flags",
    );
    width(
        &[0xfe, 0x10, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "memarg flags",
    );
    eof(&[0xfe, 0x90, 0], 3, "memarg flags");
}

#[test]
fn explicit_memory_indices_follow_only_complete_known_flags() {
    eof(&[0x28, 0x40], 2, "memarg memory index");
    eof(&[0xfd, 0, 0x40], 3, "memarg memory index");
    eof(&[0xfe, 0x10, 0x40], 3, "memarg memory index");
    eof(&[0x28, 0x7f, 0x80], 2, "memarg memory index");
    width(
        &[0xfd, 0x54, 0x40, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "memarg memory index",
    );
    width(
        &[0xfe, 0x4e, 0x40, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "memarg memory index",
    );
    eof(&[0x28, 0xc0, 0], 3, "memarg memory index");
    width(
        &[0xfd, 0xd4, 0, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10],
        4,
        9,
        "memarg memory index",
    );
}

#[test]
fn offsets_are_u64_fields_with_empty_or_partial_eof_in_all_three_families() {
    eof(&[0x28, 0], 2, "memarg offset");
    eof(&[0x28, 0, 0x80], 2, "memarg offset");
    eof(&[0xfd, 0, 0], 3, "memarg offset");
    eof(&[0xfd, 0, 0, 0x80], 3, "memarg offset");
    eof(&[0xfe, 0x10, 0], 3, "memarg offset");
    eof(&[0xfe, 0x10, 0, 0x80], 3, "memarg offset");
}

#[test]
fn offset_width_length_and_shifted_prefixes_preserve_the_full_u64_field() {
    width(
        &[
            0x28, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2,
        ],
        2,
        12,
        "memarg offset",
    );
    width(
        &[
            0xfd, 0x5c, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ],
        3,
        13,
        "memarg offset",
    );
    eof(
        &[0xfe, 0x10, 0x40, 0xff, 0xff, 0xff, 0xff, 0x0f],
        8,
        "memarg offset",
    );
    width(
        &[
            0xfd, 0x80, 0, 0xc0, 0, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            2,
        ],
        7,
        17,
        "memarg offset",
    );
}

#[derive(Clone, Copy)]
struct Owner {
    suffix: &'static str,
    start: usize,
    feature: &'static str,
    status: &'static str,
    diagnostic: &'static str,
    severity: &'static str,
    prior_instruction: Option<(&'static str, usize)>,
    root_end: bool,
}

const UNKNOWN_OWNER: Owner = Owner {
    suffix: "opaque",
    start: 0,
    feature: "unknown",
    status: "unknown",
    diagnostic: "unknown_operator",
    severity: "warning",
    prior_instruction: None,
    root_end: false,
};
const UNKNOWN_READER: Owner = Owner {
    diagnostic: "operator_decode",
    severity: "error",
    ..UNKNOWN_OWNER
};
const INVALID_OWNER: Owner = Owner {
    feature: "invalid_encoding",
    status: "invalid_encoding",
    ..UNKNOWN_READER
};

fn owned(fixture: &Fixture, expected: Owner) {
    check(fixture, |_, module| {
        no_memarg_error(module);
        let path = format!("{}/{}", fixture.expression, expected.suffix);
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
        assert_eq!(rows[0].status, expected.status);
        assert_eq!(rows[0].recognized, None);
        assert_eq!(
            rows[0].raw_hex,
            hex(&fixture.bytes[owner.span.start..owner.span.end])
        );
        if expected.suffix == "opaque" {
            assert_eq!(rows[0].kind, "opaque");
            assert_eq!(
                rows[0].feature,
                if expected.status == "unknown" {
                    "unknown"
                } else {
                    "expression_structure"
                }
            );
        }
        assert!(module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == expected.diagnostic
                && diagnostic.severity == expected.severity
                && diagnostic.offset == owner.span.start));
        if let Some((name, length)) = expected.prior_instruction {
            let first = at(module, "code[0]/function[1]/operator[0]");
            assert_eq!(
                first.span,
                Span {
                    start: fixture.opcode,
                    end: fixture.opcode + length
                }
            );
            assert!(first.description.starts_with(name));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path == first.path && row.status == "invalid_encoding"));
            if expected.root_end {
                let end = at(module, "code[0]/function[1]/operator[1]");
                assert_eq!(end.description, "End");
                assert_eq!(
                    end.span,
                    Span {
                        start: first.span.end,
                        end: first.span.end + 1
                    }
                );
                assert!(!regions(module)
                    .iter()
                    .any(|region| region.path == "code[0]/function[1]/operator[2]"));
            } else {
                assert!(!regions(module)
                    .iter()
                    .any(|region| region.path == "code[0]/function[1]/operator[1]"));
            }
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path.starts_with("code[0]/function[1]/operator[")
                    && row.span.start >= owner.span.start));
        } else {
            assert!(!regions(module).iter().any(|region| region
                .path
                .starts_with(&format!("{}/operator[", fixture.expression))));
            assert!(!module.standard.evidence.iter().any(|row| row
                .path
                .starts_with(&format!("{}/operator[", fixture.expression))));
        }
        if expected.suffix != "opaque" {
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == format!("{}/opaque", fixture.expression)));
        }
    });
}

#[test]
fn lane_eof_after_each_complete_simd_memarg_stays_owned_by_the_original_operator() {
    precise_named(
        &fixture(&[0xfd, 0x54, 0, 0], false),
        4,
        4,
        "v128.load8_lane lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
    precise_named(
        &fixture(&[0xfd, 0x55, 0, 0], false),
        4,
        4,
        "v128.load16_lane lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
    precise_named(
        &fixture(&[0xfd, 0x56, 0, 0], false),
        4,
        4,
        "v128.load32_lane lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
    precise_named(
        &fixture(&[0xfd, 0x57, 0, 0], false),
        4,
        4,
        "v128.load64_lane lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
    precise_named(
        &fixture(&[0xfd, 0x58, 0, 0], false),
        4,
        4,
        "v128.store8_lane lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
    precise_named(
        &fixture(&[0xfd, 0x59, 0, 0], false),
        4,
        4,
        "v128.store16_lane lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
    precise_named(
        &fixture(&[0xfd, 0x5a, 0, 0], false),
        4,
        4,
        "v128.store32_lane lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
    precise_named(
        &fixture(&[0xfd, 0x5b, 0, 0], false),
        4,
        4,
        "v128.store64_lane lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
}

#[test]
fn completed_unknown_flags_block_every_later_index_offset_and_lane_claim() {
    owned(
        &fixture(&[0x28, 0x80, 1, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_READER,
    );
    owned(&fixture(&[0x28, 0xc0, 1], false), UNKNOWN_READER);
    owned(
        &fixture(&[0xfd, 0, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_READER,
    );
    owned(
        &fixture(
            &[0xfe, 0x10, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
            true,
        ),
        UNKNOWN_READER,
    );
    owned(
        &fixture(&[0x28, 0xff, 0xff, 0xff, 0xff, 0x0f], false),
        UNKNOWN_READER,
    );
    owned(
        &fixture(&[0xfe, 0x4e, 0xc0, 0x81, 0, 0x80], false),
        UNKNOWN_READER,
    );
    owned(
        &fixture(
            &[0xfd, 0x54, 0xc0, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            true,
        ),
        UNKNOWN_READER,
    );
    owned(
        &fixture(
            &[
                0x28, 0xc0, 0x81, 0x80, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            true,
        ),
        UNKNOWN_READER,
    );
}

#[test]
fn full_alignment_u32_indices_and_u64_offsets_do_not_gain_semantic_encoding_caps() {
    decoded(&[0x28, 0x3f, 0], Some("I32Load"));
    decoded(&[0x28, 0x7f, 0, 0], Some("I32Load"));
    decoded(&[0x28, 2, 0x80, 0x80, 0x80, 0x80, 0x10], Some("I32Load"));
    decoded(&[0x28, 2, 0x80, 0x80, 0x80, 0x80, 0x80, 0], Some("I32Load"));
    decoded(
        &[
            0x28, 2, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ],
        Some("I32Load"),
    );
    decoded(
        &[
            0x28, 2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
        ],
        Some("I32Load"),
    );
    decoded(&[0x28, 0x80, 0, 0x0b], Some("I32Load"));
    decoded(
        &[0xfe, 0x10, 0x40, 0xff, 0xff, 0xff, 0xff, 0x0f, 0],
        Some("I32AtomicLoad"),
    );
    decoded(&[0xfd, 0xd4, 0, 0, 0, 0xff], Some("V128Load8Lane"));
    decoded(&[0xfd, 0x5d, 0, 0], Some("V128Load64Zero"));
}

#[test]
fn adjacent_grammars_and_failed_or_future_subopcodes_have_no_memarg_leaf() {
    precise_named(
        &fixture(&[0xfd, 0x0c, 0xc0, 1], false),
        2,
        4,
        "v128.const value bytes",
        EOF_REASON,
        "simd_immediate_error",
    );
    precise_named(
        &fixture(&[0xfd, 0x15], false),
        2,
        2,
        "i8x16.extract_lane_s lane index",
        EOF_REASON,
        "simd_immediate_error",
    );
    owned(&fixture(&[0xfe, 3, 1], true), UNKNOWN_READER);
    owned(
        &fixture(&[0xfe, 0x4f, 0, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        INVALID_OWNER,
    );
    owned(&fixture(&[0xfd], false), INVALID_OWNER);
    owned(
        &fixture(&[0xfe, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        INVALID_OWNER,
    );
    owned(
        &fixture(&[0xfd, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xc0, 1, 0x80], true),
        UNKNOWN_OWNER,
    );
    owned(&fixture(&[0xfe, 4, 0xc0, 1, 0x80], true), UNKNOWN_OWNER);
}

#[test]
fn completed_memargs_root_end_and_earlier_frontiers_keep_their_original_owners() {
    owned(
        &fixture(&[0x28, 0, 0, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            start: 3,
            prior_instruction: Some(("I32Load", 3)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0xfd, 0x54, 0, 0, 0, 0xff], true),
        Owner {
            start: 5,
            prior_instruction: Some(("V128Load8Lane", 5)),
            ..UNKNOWN_OWNER
        },
    );
    owned(
        &fixture(&[0xfe, 0x10, 0, 0], false),
        Owner {
            suffix: "expression_structure",
            start: 4,
            diagnostic: "expression_structure",
            prior_instruction: Some(("I32AtomicLoad", 4)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(
            &[0x28, 0, 0, 0x0b, 0x28, 0x80, 0x80, 0x80, 0x80, 0x10],
            true,
        ),
        Owner {
            suffix: "trailing_bytes",
            start: 4,
            diagnostic: "expression_structure",
            root_end: true,
            prior_instruction: Some(("I32Load", 3)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0xff, 0x28, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_OWNER,
    );
    owned(
        &fixture(
            &[0x1c, 1, 0x7a, 0xfd, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            true,
        ),
        Owner {
            feature: "unknown_value_type",
            ..UNKNOWN_OWNER
        },
    );
}

#[test]
fn recovered_constants_keep_memarg_fields_and_unknown_flags_within_their_owners() {
    let global = constant_fixture(6, &[0x28, 0x80, 0x80, 0x80, 0x80, 0x10], true);
    assert_eq!(global.opcode, 30);
    precise_field(&global, 1, 6, "memarg flags", WIDTH_REASON);
    let table = constant_fixture(4, &[0xfd, 0, 0x40], false);
    assert_eq!(table.opcode, 31);
    precise_field(&table, 3, 3, "memarg memory index", EOF_REASON);
    let element = constant_fixture(
        9,
        &[
            0xfe, 0x10, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2,
        ],
        true,
    );
    assert_eq!(element.opcode, 37);
    precise_field(&element, 3, 13, "memarg offset", WIDTH_REASON);
    owned(
        &constant_fixture(6, &[0x28, 0xc0, 1, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_READER,
    );
}
