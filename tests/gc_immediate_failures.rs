//! Fixed Core3 GC unsigned immediate fields and ownership; no fuzzing.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const EOF_REASON: &str = "known encoding is truncated at its trusted input boundary";
const WIDTH_REASON: &str = "integer encoding exceeds its required width or length";
const HEAP_REASON: &str = "known numeric or vector value type is forbidden in a heap-type operand";
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

fn no_gc_immediate_error(module: &AuditModule) {
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.ends_with("/gc_immediate_error")));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path.ends_with("/gc_immediate_error")));
}

fn precise_field(fixture: &Fixture, start: usize, end: usize, field: &str, reason: &str) {
    precise_named(fixture, start, end, field, reason, "gc_immediate_error");
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
        if leaf != "gc_immediate_error" {
            no_gc_immediate_error(module);
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
                    } else if reason == HEAP_REASON {
                        "invalid heap type"
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
    check(&fixture, |profile, module| {
        no_gc_immediate_error(module);
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
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == first.path && row.feature == "gc")
            .collect();
        assert_eq!(rows.len(), 1);
        let supported = matches!(profile, Standard::Core3 | Standard::AllKnown);
        let reason = if supported {
            "recognized opcode grammar".to_owned()
        } else {
            format!("recognized opcode grammar; known gc grammar is outside {profile}")
        };
        assert_eq!(
            serde_json::to_value(rows[0]).unwrap(),
            serde_json::json!({
                "path": first.path, "span": first.span, "feature": "gc",
                "status": if supported { "supported" } else { "recognized_but_disabled" },
                "kind": "instruction", "reason": reason, "raw_hex": hex(instruction),
                "recognized": expected_name
            })
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
const INVALID_OWNER: Owner = Owner {
    feature: "invalid_encoding",
    status: "invalid_encoding",
    diagnostic: "operator_decode",
    severity: "error",
    ..UNKNOWN_OWNER
};

fn owned(fixture: &Fixture, expected: Owner) {
    check(fixture, |_, module| {
        no_gc_immediate_error(module);
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
            let first = at(module, &format!("{}/operator[0]", fixture.expression));
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
                let end = at(module, &format!("{}/operator[1]", fixture.expression));
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
                    .any(|region| region.path == format!("{}/operator[2]", fixture.expression)));
            } else {
                assert!(!regions(module)
                    .iter()
                    .any(|region| region.path == format!("{}/operator[1]", fixture.expression)));
            }
        } else {
            assert!(!regions(module).iter().any(|region| region
                .path
                .starts_with(&format!("{}/operator[", fixture.expression))));
        }
        assert!(!module.standard.evidence.iter().any(|row| row
            .path
            .starts_with(&format!("{}/operator[", fixture.expression))
            && row.span.start >= owner.span.start));
        if expected.suffix != "opaque" {
            assert!(!regions(module)
                .iter()
                .any(|region| region.path == format!("{}/opaque", fixture.expression)));
        }
    });
}

#[test]
fn struct_new_type_index_has_exact_eof_width_and_length_boundaries() {
    eof(&[0xfb, 0], 2, "struct.new type index");
    width(
        &[0xfb, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
        2,
        7,
        "struct.new type index",
    );
    width(
        &[0xfb, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "struct.new type index",
    );
}

#[test]
fn struct_new_default_keeps_its_padded_secondary_outside_the_type_field() {
    eof(&[0xfb, 0x81, 0, 0x80], 3, "struct.new_default type index");
    width(
        &[0xfb, 0x81, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "struct.new_default type index",
    );
    width(
        &[0xfb, 0x81, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "struct.new_default type index",
    );
}

#[test]
fn struct_get_distinguishes_type_from_field_after_a_full_u32_type_index() {
    eof(&[0xfb, 2], 2, "struct.get type index");
    width(
        &[0xfb, 2, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "struct.get type index",
    );
    width(
        &[0xfb, 2, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "struct.get type index",
    );
    eof(
        &[0xfb, 2, 0xff, 0xff, 0xff, 0xff, 0x0f],
        7,
        "struct.get field index",
    );
    width(
        &[0xfb, 2, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "struct.get field index",
    );
    width(
        &[0xfb, 2, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "struct.get field index",
    );
}

#[test]
fn struct_get_s_reaches_the_field_only_after_complete_type_padding() {
    eof(&[0xfb, 3, 0x80], 2, "struct.get_s type index");
    width(
        &[0xfb, 3, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "struct.get_s type index",
    );
    width(
        &[0xfb, 3, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "struct.get_s type index",
    );
    eof(&[0xfb, 3, 0x80, 0], 4, "struct.get_s field index");
    width(
        &[0xfb, 3, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "struct.get_s field index",
    );
    width(
        &[0xfb, 3, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "struct.get_s field index",
    );
}

#[test]
fn struct_get_u_does_not_apply_a_heap_type_cap_to_the_prior_type_index() {
    eof(&[0xfb, 4], 2, "struct.get_u type index");
    width(
        &[0xfb, 4, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "struct.get_u type index",
    );
    width(
        &[0xfb, 4, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "struct.get_u type index",
    );
    eof(&[0xfb, 4, 0x80, 0x80, 0x40], 5, "struct.get_u field index");
    width(
        &[0xfb, 4, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "struct.get_u field index",
    );
    width(
        &[0xfb, 4, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "struct.get_u field index",
    );
}

#[test]
fn struct_set_keeps_destination_type_and_field_roles_separate() {
    eof(&[0xfb, 5], 2, "struct.set type index");
    width(
        &[0xfb, 5, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "struct.set type index",
    );
    width(
        &[0xfb, 5, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "struct.set type index",
    );
    eof(
        &[0xfb, 0x85, 0, 0xff, 0xff, 0xff, 0xff, 0x0f],
        8,
        "struct.set field index",
    );
    width(
        &[0xfb, 5, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "struct.set field index",
    );
    width(
        &[0xfb, 5, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "struct.set field index",
    );
}

#[test]
fn array_new_diagnoses_only_its_unsigned_type_index() {
    eof(&[0xfb, 6, 0x80], 2, "array.new type index");
    width(
        &[0xfb, 6, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.new type index",
    );
    width(
        &[0xfb, 6, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.new type index",
    );
}

#[test]
fn array_new_default_keeps_the_first_failed_type_index_field() {
    eof(&[0xfb, 7], 2, "array.new_default type index");
    width(
        &[0xfb, 7, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.new_default type index",
    );
    width(
        &[0xfb, 7, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.new_default type index",
    );
}

#[test]
fn array_new_fixed_distinguishes_type_index_from_element_count() {
    eof(&[0xfb, 8], 2, "array.new_fixed type index");
    width(
        &[0xfb, 8, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.new_fixed type index",
    );
    width(
        &[0xfb, 8, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.new_fixed type index",
    );
    eof(
        &[0xfb, 8, 0xff, 0xff, 0xff, 0xff, 0x0f],
        7,
        "array.new_fixed element count",
    );
    width(
        &[0xfb, 8, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "array.new_fixed element count",
    );
    width(
        &[0xfb, 0x88, 0, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        5,
        10,
        "array.new_fixed element count",
    );
}

#[test]
fn array_new_data_keeps_type_and_data_index_order() {
    eof(&[0xfb, 9], 2, "array.new_data type index");
    width(
        &[0xfb, 9, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.new_data type index",
    );
    width(
        &[0xfb, 9, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.new_data type index",
    );
    eof(&[0xfb, 9, 0x80, 0x80, 0x40], 5, "array.new_data data index");
    width(
        &[0xfb, 9, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "array.new_data data index",
    );
    width(
        &[0xfb, 9, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "array.new_data data index",
    );
}

#[test]
fn array_new_elem_keeps_type_and_element_index_order() {
    eof(&[0xfb, 10], 2, "array.new_elem type index");
    width(
        &[0xfb, 10, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.new_elem type index",
    );
    width(
        &[0xfb, 10, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.new_elem type index",
    );
    eof(&[0xfb, 10, 0x7f], 3, "array.new_elem element index");
    width(
        &[0xfb, 10, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "array.new_elem element index",
    );
    width(
        &[0xfb, 10, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "array.new_elem element index",
    );
}

#[test]
fn array_get_locates_only_the_unsigned_type_index() {
    eof(&[0xfb, 11, 0x80], 2, "array.get type index");
    width(
        &[0xfb, 11, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.get type index",
    );
    width(
        &[0xfb, 11, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.get type index",
    );
}

#[test]
fn array_get_s_retains_empty_eof_and_integer_width_boundaries() {
    eof(&[0xfb, 12], 2, "array.get_s type index");
    width(
        &[0xfb, 12, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.get_s type index",
    );
    width(
        &[0xfb, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.get_s type index",
    );
}

#[test]
fn array_get_u_retains_partial_eof_and_integer_width_boundaries() {
    eof(&[0xfb, 13, 0x80], 2, "array.get_u type index");
    width(
        &[0xfb, 13, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.get_u type index",
    );
    width(
        &[0xfb, 13, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.get_u type index",
    );
}

#[test]
fn array_set_has_one_trusted_unsigned_type_field() {
    eof(&[0xfb, 14], 2, "array.set type index");
    width(
        &[0xfb, 14, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.set type index",
    );
    width(
        &[0xfb, 14, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.set type index",
    );
}

#[test]
fn array_fill_partial_type_eof_does_not_borrow_the_next_frame() {
    eof(&[0xfb, 16, 0x80, 0x80], 2, "array.fill type index");
    width(
        &[0xfb, 16, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.fill type index",
    );
    width(
        &[0xfb, 16, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.fill type index",
    );
}

#[test]
fn array_copy_distinguishes_destination_and_source_type_indices() {
    eof(&[0xfb, 17], 2, "array.copy destination type index");
    width(
        &[0xfb, 17, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.copy destination type index",
    );
    width(
        &[0xfb, 17, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.copy destination type index",
    );
    eof(&[0xfb, 0x91, 0, 0x80, 0], 5, "array.copy source type index");
    width(
        &[0xfb, 17, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "array.copy source type index",
    );
    width(
        &[0xfb, 17, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "array.copy source type index",
    );
}

#[test]
fn array_init_data_distinguishes_array_type_from_data_segment_index() {
    eof(&[0xfb, 18, 0x80], 2, "array.init_data type index");
    width(
        &[0xfb, 18, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.init_data type index",
    );
    width(
        &[0xfb, 18, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.init_data type index",
    );
    eof(
        &[0xfb, 18, 0xff, 0xff, 0xff, 0xff, 0x0f],
        7,
        "array.init_data data index",
    );
    width(
        &[0xfb, 18, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "array.init_data data index",
    );
    width(
        &[0xfb, 18, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "array.init_data data index",
    );
}

#[test]
fn array_init_elem_distinguishes_array_type_from_element_segment_index() {
    eof(&[0xfb, 19], 2, "array.init_elem type index");
    width(
        &[0xfb, 19, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "array.init_elem type index",
    );
    width(
        &[0xfb, 19, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "array.init_elem type index",
    );
    eof(
        &[0xfb, 19, 0x80, 0x80, 0x40],
        5,
        "array.init_elem element index",
    );
    width(
        &[0xfb, 19, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "array.init_elem element index",
    );
    width(
        &[0xfb, 19, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "array.init_elem element index",
    );
}

#[test]
fn complete_type_field_segment_and_count_values_use_full_u32_grammar() {
    decoded(&[0xfb, 0, 0x80, 0x80, 0x40], Some("StructNew"));
    decoded(&[0xfb, 0x81, 0, 0x80, 0], Some("StructNewDefault"));
    decoded(
        &[
            0xfb, 2, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0xff, 0x0f,
        ],
        Some("StructGet"),
    );
    decoded(&[0xfb, 3, 0x7a, 0x7f], Some("StructGetS"));
    decoded(
        &[0xfb, 8, 0x80, 0x80, 0x40, 0xff, 0xff, 0xff, 0xff, 0x0f],
        Some("ArrayNewFixed"),
    );
    decoded(
        &[0xfb, 9, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f],
        Some("ArrayNewData"),
    );
    decoded(
        &[0xfb, 10, 0x7f, 0xff, 0xff, 0xff, 0xff, 0x0f],
        Some("ArrayNewElem"),
    );
    decoded(
        &[
            0xfb, 0x91, 0, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x80, 0x80, 0x40,
        ],
        Some("ArrayCopy"),
    );
    decoded(&[0xfb, 18, 0, 0x80, 0], Some("ArrayInitData"));
    decoded(&[0xfb, 19, 0x7f, 0x0b], Some("ArrayInitElem"));
}

#[test]
fn complete_gc_immediates_and_earlier_unknown_grammar_keep_their_owners() {
    owned(
        &fixture(&[0xfb, 1, 0, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            start: 3,
            prior_instruction: Some(("StructNewDefault", 3)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0xfb, 15, 0xff], true),
        Owner {
            start: 2,
            prior_instruction: Some(("ArrayLen", 2)),
            ..UNKNOWN_OWNER
        },
    );
    owned(
        &fixture(&[0xfb, 11, 0x0b], false),
        Owner {
            suffix: "expression_structure",
            start: 3,
            diagnostic: "expression_structure",
            prior_instruction: Some(("ArrayGet", 3)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(
            &[0xfb, 16, 0, 0x0b, 0xfb, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            true,
        ),
        Owner {
            suffix: "trailing_bytes",
            start: 4,
            diagnostic: "expression_structure",
            prior_instruction: Some(("ArrayFill", 3)),
            root_end: true,
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0xff, 0xfb, 2, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_OWNER,
    );
    owned(
        &fixture(
            &[0x1c, 1, 0x7a, 0xfb, 8, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            true,
        ),
        Owner {
            feature: "unknown_value_type",
            ..UNKNOWN_OWNER
        },
    );
}

#[test]
fn excluded_prefixes_heap_casts_descriptors_and_other_integer_leaves_keep_ownership() {
    owned(&fixture(&[0xfb], false), INVALID_OWNER);
    owned(
        &fixture(&[0xfb, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        INVALID_OWNER,
    );
    owned(
        &fixture(&[0xfb, 0x80, 0x80, 0x80, 0x80, 0x80, 0], true),
        INVALID_OWNER,
    );
    owned(
        &fixture(&[0xfb, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xfb, 0, 0x80], true),
        UNKNOWN_OWNER,
    );
    decoded(&[0xfb, 0x0f], Some("ArrayLen"));
    owned(
        &fixture(&[0xfb, 0x20, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        INVALID_OWNER,
    );
    owned(
        &fixture(&[0xfb, 0x22, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        INVALID_OWNER,
    );
    precise_named(
        &fixture(&[0xfb, 0x14, 0x7f], true),
        2,
        3,
        "heap type operand",
        HEAP_REASON,
        "heap_type_error",
    );
    owned(
        &fixture(&[0xfb, 0x18, 4, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f], true),
        Owner {
            diagnostic: "operator_decode",
            severity: "error",
            ..UNKNOWN_OWNER
        },
    );
    precise_named(
        &fixture(&[0xfc, 9, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        2,
        7,
        "data.drop data index",
        WIDTH_REASON,
        "bulk_index_error",
    );
    precise_named(
        &fixture(&[0x3f], false),
        1,
        1,
        "memory.size memory index",
        EOF_REASON,
        "memory_index_error",
    );
    precise_named(
        &fixture(&[0xfd, 8], false),
        2,
        2,
        "memarg flags",
        EOF_REASON,
        "memarg_error",
    );
    precise_named(
        &fixture(&[0xfe, 0x10], false),
        2,
        2,
        "memarg flags",
        EOF_REASON,
        "memarg_error",
    );
}

#[test]
fn recovered_global_table_and_element_gc_fields_stop_at_their_original_boundaries() {
    let global = constant_fixture(6, &[0xfb, 2, 0, 0x80, 0x80, 0x80, 0x80, 0x10], true);
    assert_eq!(global.opcode, 30);
    precise_field(&global, 3, 8, "struct.get field index", WIDTH_REASON);
    let table = constant_fixture(4, &[0xfb, 8, 0], false);
    assert_eq!(table.opcode, 31);
    precise_field(&table, 3, 3, "array.new_fixed element count", EOF_REASON);
    let element = constant_fixture(9, &[0xfb, 19, 0, 0x80], false);
    assert_eq!(element.opcode, 37);
    precise_field(&element, 3, 4, "array.init_elem element index", EOF_REASON);
    owned(
        &constant_fixture(6, &[0xff, 0xfb, 17, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_OWNER,
    );
}
