//! Fixed primary single-u32 immediate fields and ownership; no fuzzing.
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

fn no_primary_index_error(module: &AuditModule) {
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.ends_with("/primary_index_error")));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path.ends_with("/primary_index_error")));
}

fn precise_field(fixture: &Fixture, start: usize, end: usize, field: &str, reason: &str) {
    precise_named(fixture, start, end, field, reason, "primary_index_error");
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
        if leaf != "primary_index_error" {
            no_primary_index_error(module);
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

fn decoded(instruction: &[u8], name: &str, feature: &str, nonzero_table: bool) {
    let fixture = fixture(instruction, true);
    check(&fixture, |profile, module| {
        no_primary_index_error(module);
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
        let supported = match feature {
            "mvp" => true,
            "reference_types" => profile != Standard::Core1,
            "exceptions" | "tail_call" | "function_references" => {
                matches!(profile, Standard::Core3 | Standard::AllKnown)
            }
            _ => panic!("unexpected fixed feature {feature}"),
        };
        let status = if supported {
            "supported"
        } else {
            "recognized_but_disabled"
        };
        let reason = if supported {
            "recognized opcode grammar".to_owned()
        } else {
            format!("recognized opcode grammar; known {feature} grammar is outside {profile}")
        };
        let mut expected = vec![serde_json::json!({
            "path": first.path, "span": first.span, "feature": feature, "status": status,
            "kind": "instruction", "reason": reason, "raw_hex": hex(instruction), "recognized": name
        })];
        if nonzero_table {
            assert_eq!(feature, "reference_types");
            let reason = if supported {
                "nonzero table index".to_owned()
            } else {
                format!("nonzero table index; known reference_types grammar is outside {profile}")
            };
            expected.push(serde_json::json!({
                "path": first.path, "span": first.span, "feature": "reference_types", "status": status,
                "kind": "instruction", "reason": reason, "raw_hex": hex(instruction), "recognized": null
            }));
        }
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == first.path)
            .map(|row| serde_json::to_value(row).unwrap())
            .collect();
        assert_eq!(rows, expected);
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
    message: Option<&'static str>,
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
    message: None,
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
        no_primary_index_error(module);
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
        if let Some(message) = expected.message {
            assert!(module
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == expected.diagnostic
                    && diagnostic.offset == owner.span.start
                    && diagnostic.message.contains(message)));
            assert!(rows[0]
                .reason
                .starts_with("known control delimiter is outside its required frame"));
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
fn throw_tag_index_has_exact_eof_width_and_length_boundaries() {
    eof(&[0x08], 1, "throw tag index");
    width(
        &[0x08, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "throw tag index",
    );
    width(
        &[0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "throw tag index",
    );
}

#[test]
fn br_label_depth_keeps_the_partial_integer_in_its_field() {
    eof(&[0x0c, 0x80], 1, "br label depth");
    width(
        &[0x0c, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "br label depth",
    );
    width(
        &[0x0c, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "br label depth",
    );
}

#[test]
fn br_if_label_depth_does_not_include_a_sixth_integer_byte() {
    eof(&[0x0d], 1, "br_if label depth");
    width(
        &[0x0d, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "br_if label depth",
    );
    width(
        &[0x0d, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "br_if label depth",
    );
}

#[test]
fn call_function_index_has_no_signature_namespace_dependency() {
    eof(&[0x10, 0x80], 1, "call function index");
    width(
        &[0x10, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "call function index",
    );
    width(
        &[0x10, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "call function index",
    );
}

#[test]
fn return_call_function_index_is_a_single_unsigned_field() {
    eof(&[0x12], 1, "return_call function index");
    width(
        &[0x12, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "return_call function index",
    );
    width(
        &[0x12, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "return_call function index",
    );
}

#[test]
fn call_ref_type_index_uses_u32_width_without_a_heap_type_cap() {
    eof(&[0x14, 0x80, 0x80, 0x80, 0x80], 1, "call_ref type index");
    width(
        &[0x14, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "call_ref type index",
    );
    width(
        &[0x14, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "call_ref type index",
    );
}

#[test]
fn return_call_ref_type_index_is_not_a_heap_type_operand() {
    eof(&[0x15], 1, "return_call_ref type index");
    width(
        &[0x15, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "return_call_ref type index",
    );
    width(
        &[0x15, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "return_call_ref type index",
    );
}

#[test]
fn local_get_local_index_is_bounded_by_the_function_body() {
    eof(&[0x20, 0x80], 1, "local.get local index");
    width(
        &[0x20, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "local.get local index",
    );
    width(
        &[0x20, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "local.get local index",
    );
}

#[test]
fn local_set_local_index_keeps_width_and_length_errors_precise() {
    eof(&[0x21], 1, "local.set local index");
    width(
        &[0x21, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "local.set local index",
    );
    width(
        &[0x21, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "local.set local index",
    );
}

#[test]
fn local_tee_local_index_includes_only_the_available_partial_bytes() {
    eof(&[0x22, 0x80, 0x80], 1, "local.tee local index");
    width(
        &[0x22, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "local.tee local index",
    );
    width(
        &[0x22, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "local.tee local index",
    );
}

#[test]
fn global_get_global_index_can_be_diagnosed_without_a_declared_global() {
    eof(&[0x23], 1, "global.get global index");
    width(
        &[0x23, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "global.get global index",
    );
    width(
        &[0x23, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "global.get global index",
    );
}

#[test]
fn global_set_global_index_keeps_the_first_failed_unsigned_field() {
    eof(&[0x24, 0x80], 1, "global.set global index");
    width(
        &[0x24, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "global.set global index",
    );
    width(
        &[0x24, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "global.set global index",
    );
}

#[test]
fn table_get_table_index_has_no_reference_constructor_grammar() {
    eof(&[0x25], 1, "table.get table index");
    width(
        &[0x25, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "table.get table index",
    );
    width(
        &[0x25, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "table.get table index",
    );
}

#[test]
fn table_set_table_index_does_not_consume_the_following_mvp_tail() {
    eof(&[0x26, 0x80], 1, "table.set table index");
    width(
        &[0x26, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "table.set table index",
    );
    width(
        &[0x26, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "table.set table index",
    );
}

#[test]
fn ref_func_function_index_is_unsigned_in_all_selected_profiles() {
    eof(&[0xd2], 1, "ref.func function index");
    width(
        &[0xd2, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "ref.func function index",
    );
    width(
        &[0xd2, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "ref.func function index",
    );
}

#[test]
fn br_on_null_label_depth_keeps_partial_eof_and_integer_errors_distinct() {
    eof(&[0xd5, 0x80], 1, "br_on_null label depth");
    width(
        &[0xd5, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "br_on_null label depth",
    );
    width(
        &[0xd5, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "br_on_null label depth",
    );
}

#[test]
fn br_on_non_null_label_depth_has_a_single_bytecode_field() {
    eof(&[0xd6], 1, "br_on_non_null label depth");
    width(
        &[0xd6, 0x80, 0x80, 0x80, 0x80, 0x10],
        1,
        6,
        "br_on_non_null label depth",
    );
    width(
        &[0xd6, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        1,
        6,
        "br_on_non_null label depth",
    );
}

#[test]
fn complete_full_u32_and_padding_remain_wire_valid_with_existing_proposal_rows() {
    decoded(&[0x08, 0x7f], "Throw", "exceptions", false);
    decoded(&[0x0c, 0x0b], "Br", "mvp", false);
    decoded(&[0x0d, 0xff, 0xff, 0xff, 0xff, 0x0f], "BrIf", "mvp", false);
    decoded(&[0x10, 0x80, 0], "Call", "mvp", false);
    decoded(&[0x12, 0x80, 0x80, 0x40], "ReturnCall", "tail_call", false);
    decoded(&[0x14, 0x7a], "CallRef", "function_references", false);
    decoded(
        &[0x15, 0xff, 0xff, 0xff, 0xff, 0x0f],
        "ReturnCallRef",
        "function_references",
        false,
    );
    decoded(
        &[0x20, 0xff, 0xff, 0xff, 0xff, 0x0f],
        "LocalGet",
        "mvp",
        false,
    );
    decoded(&[0x21, 0x80, 0x80, 0x80, 0x80, 0], "LocalSet", "mvp", false);
    decoded(&[0x22, 0x7b], "LocalTee", "mvp", false);
    decoded(&[0x23, 0x7c], "GlobalGet", "mvp", false);
    decoded(&[0x24, 0x7d], "GlobalSet", "mvp", false);
    decoded(
        &[0x25, 0xff, 0xff, 0xff, 0xff, 0x0f],
        "TableGet",
        "reference_types",
        true,
    );
    decoded(&[0x26, 0x7e], "TableSet", "reference_types", true);
    decoded(&[0xd2, 0x80, 0], "RefFunc", "reference_types", false);
    decoded(&[0xd5, 0x7f], "BrOnNull", "function_references", false);
    decoded(
        &[0xd6, 0x80, 0x80, 0x40],
        "BrOnNonNull",
        "function_references",
        false,
    );
}

#[test]
fn complete_operands_and_earlier_unknown_grammars_keep_their_original_owners() {
    owned(
        &fixture(&[0x20, 0, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            start: 2,
            prior_instruction: Some(("LocalGet", 2)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0x23, 0, 0xff], true),
        Owner {
            start: 2,
            prior_instruction: Some(("GlobalGet", 2)),
            ..UNKNOWN_OWNER
        },
    );
    owned(
        &fixture(&[0x10, 0x0b], false),
        Owner {
            suffix: "expression_structure",
            start: 2,
            diagnostic: "expression_structure",
            prior_instruction: Some(("Call", 2)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0x0d, 0, 0x0b, 0x20, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            suffix: "trailing_bytes",
            start: 3,
            diagnostic: "expression_structure",
            prior_instruction: Some(("BrIf", 2)),
            root_end: true,
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0xff, 0x10, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_OWNER,
    );
    owned(
        &fixture(&[0x1c, 1, 0x7a, 0x14, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            feature: "unknown_value_type",
            ..UNKNOWN_OWNER
        },
    );
}

#[test]
fn frame_prechecks_and_secondary_neighbors_never_get_a_primary_index_leaf() {
    owned(
        &fixture(&[0x07, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            message: Some("`catch` found outside `LegacyTry` block"),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0x18, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            message: Some("`delegate` found outside `LegacyTry` block"),
            ..INVALID_OWNER
        },
    );
    owned(&fixture(&[0x09], false), INVALID_OWNER);
    owned(&fixture(&[0xe0], false), INVALID_OWNER);
    owned(
        &fixture(&[0xe2, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        INVALID_OWNER,
    );
    precise_named(
        &fixture(&[0x11], false),
        1,
        1,
        "call_indirect type index",
        EOF_REASON,
        "call_indirect_error",
    );
    precise_named(
        &fixture(&[0xfb, 0], false),
        2,
        2,
        "struct.new type index",
        EOF_REASON,
        "gc_immediate_error",
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
    owned(
        &fixture(
            &[0x1f, 0x40, 1, 4, 0, 0x20, 0x80, 0x80, 0x80, 0x80, 0x10],
            true,
        ),
        Owner {
            diagnostic: "operator_decode",
            severity: "error",
            ..UNKNOWN_OWNER
        },
    );
}

#[test]
fn constant_recovery_keeps_exact_fields_and_following_independent_sections() {
    let global = constant_fixture(6, &[0x23, 0x80, 0x80, 0x80, 0x80, 0x10], true);
    assert_eq!(global.opcode, 30);
    precise_field(&global, 1, 6, "global.get global index", WIDTH_REASON);
    let table = constant_fixture(4, &[0xd2], false);
    assert_eq!(table.opcode, 31);
    precise_field(&table, 1, 1, "ref.func function index", EOF_REASON);
    let element = constant_fixture(9, &[0x08, 0x80], false);
    assert_eq!(element.opcode, 37);
    precise_field(&element, 1, 2, "throw tag index", EOF_REASON);
    owned(
        &constant_fixture(6, &[0xff, 0x20, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_OWNER,
    );
}
