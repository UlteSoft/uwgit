//! Fixed bulk-memory/table u32 fields and expression ownership; no fuzzing.
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

fn no_bulk_index_error(module: &AuditModule) {
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.ends_with("/bulk_index_error")));
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|row| row.path.ends_with("/bulk_index_error")));
}

fn precise_field(fixture: &Fixture, start: usize, end: usize, field: &str, reason: &str) {
    precise_named(fixture, start, end, field, reason, "bulk_index_error");
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
        if leaf != "bulk_index_error" {
            no_bulk_index_error(module);
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

struct Requirement {
    start: usize,
    end: usize,
    feature: &'static str,
    reason: &'static str,
}

fn decoded(instruction: &[u8], expected_name: Option<&str>, expected_requirements: &[Requirement]) {
    let fixture = fixture(instruction, true);
    check(&fixture, |profile, module| {
        no_bulk_index_error(module);
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
        let requirements: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| {
                row.path == first.path
                    && matches!(row.feature.as_str(), "multi_memory" | "reference_types")
            })
            .collect();
        assert_eq!(requirements.len(), expected_requirements.len());
        for (row, expected) in requirements.iter().zip(expected_requirements) {
            let supported = if expected.feature == "multi_memory" {
                matches!(profile, Standard::Core3 | Standard::AllKnown)
            } else {
                profile != Standard::Core1
            };
            let span = Span {
                start: fixture.opcode + expected.start,
                end: fixture.opcode + expected.end,
            };
            let reason = if supported {
                expected.reason.to_owned()
            } else {
                format!(
                    "{}; known {} grammar is outside {profile}",
                    expected.reason, expected.feature
                )
            };
            assert_eq!(
                serde_json::to_value(row).unwrap(),
                serde_json::json!({
                    "path": first.path, "span": span, "feature": expected.feature,
                    "status": if supported { "supported" } else { "recognized_but_disabled" },
                    "kind": "instruction", "reason": reason,
                    "raw_hex": hex(&fixture.bytes[span.start..span.end]), "recognized": null
                })
            );
        }
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
        no_bulk_index_error(module);
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
fn memory_init_stops_at_its_first_failed_data_or_memory_index() {
    eof(&[0xfc, 8], 2, "memory.init data index");
    width(
        &[0xfc, 8, 0x80, 0x80, 0x80, 0x80, 0x10, 0x7f],
        2,
        7,
        "memory.init data index",
    );
    width(
        &[0xfc, 8, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "memory.init data index",
    );
    eof(
        &[0xfc, 8, 0xff, 0xff, 0xff, 0xff, 0x0f],
        7,
        "memory.init memory index",
    );
    width(
        &[0xfc, 8, 0x7a, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "memory.init memory index",
    );
    width(
        &[0xfc, 0x88, 0, 0x80, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        5,
        10,
        "memory.init memory index",
    );
}

#[test]
fn data_drop_locates_only_its_unsigned_data_index() {
    eof(&[0xfc, 9, 0x80], 2, "data.drop data index");
    width(
        &[0xfc, 9, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "data.drop data index",
    );
    width(
        &[0xfc, 9, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "data.drop data index",
    );
}

#[test]
fn memory_copy_distinguishes_destination_from_source_after_complete_padding() {
    eof(&[0xfc, 10], 2, "memory.copy destination memory index");
    width(
        &[0xfc, 10, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "memory.copy destination memory index",
    );
    width(
        &[0xfc, 10, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "memory.copy destination memory index",
    );
    eof(&[0xfc, 10, 0x80, 0], 4, "memory.copy source memory index");
    width(
        &[0xfc, 10, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "memory.copy source memory index",
    );
    width(
        &[0xfc, 10, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "memory.copy source memory index",
    );
}

#[test]
fn memory_fill_retains_partial_eof_width_and_length_boundaries() {
    eof(&[0xfc, 11, 0x80, 0x80], 2, "memory.fill memory index");
    width(
        &[0xfc, 11, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "memory.fill memory index",
    );
    width(
        &[0xfc, 11, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "memory.fill memory index",
    );
}

#[test]
fn table_init_allows_a_full_element_index_before_the_table_field() {
    eof(&[0xfc, 12], 2, "table.init element index");
    width(
        &[0xfc, 12, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "table.init element index",
    );
    width(
        &[0xfc, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "table.init element index",
    );
    eof(&[0xfc, 12, 0x80, 0x80, 0x40], 5, "table.init table index");
    width(
        &[0xfc, 12, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "table.init table index",
    );
    width(
        &[0xfc, 12, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "table.init table index",
    );
}

#[test]
fn elem_drop_has_a_single_element_index_field() {
    eof(&[0xfc, 13], 2, "elem.drop element index");
    width(
        &[0xfc, 13, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "elem.drop element index",
    );
    width(
        &[0xfc, 13, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "elem.drop element index",
    );
}

#[test]
fn table_copy_keeps_both_roles_after_padded_subopcode_and_full_u32() {
    eof(&[0xfc, 14], 2, "table.copy destination table index");
    width(
        &[0xfc, 14, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "table.copy destination table index",
    );
    width(
        &[0xfc, 14, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "table.copy destination table index",
    );
    eof(
        &[0xfc, 0x8e, 0, 0xff, 0xff, 0xff, 0xff, 0x0f],
        8,
        "table.copy source table index",
    );
    width(
        &[0xfc, 14, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        3,
        8,
        "table.copy source table index",
    );
    width(
        &[0xfc, 14, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        3,
        8,
        "table.copy source table index",
    );
}

#[test]
fn table_grow_locates_partial_eof_and_integer_failure_in_its_table_index() {
    eof(&[0xfc, 15, 0x80], 2, "table.grow table index");
    width(
        &[0xfc, 15, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "table.grow table index",
    );
    width(
        &[0xfc, 15, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "table.grow table index",
    );
}

#[test]
fn table_size_has_no_other_integer_or_reserved_byte_interpretation() {
    eof(&[0xfc, 16], 2, "table.size table index");
    width(
        &[0xfc, 16, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "table.size table index",
    );
    width(
        &[0xfc, 16, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "table.size table index",
    );
}

#[test]
fn table_fill_preserves_partial_eof_and_the_first_five_integer_bytes() {
    eof(&[0xfc, 17, 0x80], 2, "table.fill table index");
    width(
        &[0xfc, 17, 0x80, 0x80, 0x80, 0x80, 0x10],
        2,
        7,
        "table.fill table index",
    );
    width(
        &[0xfc, 17, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
        2,
        7,
        "table.fill table index",
    );
}

#[test]
fn complete_indices_and_all_eight_no_immediate_saturating_forms_keep_wire_evidence() {
    decoded(&[0xfc, 0], Some("I32TruncSatF32S"), &[]);
    decoded(&[0xfc, 1], Some("I32TruncSatF32U"), &[]);
    decoded(&[0xfc, 2], Some("I32TruncSatF64S"), &[]);
    decoded(&[0xfc, 3], Some("I32TruncSatF64U"), &[]);
    decoded(&[0xfc, 4], Some("I64TruncSatF32S"), &[]);
    decoded(&[0xfc, 5], Some("I64TruncSatF32U"), &[]);
    decoded(&[0xfc, 6], Some("I64TruncSatF64S"), &[]);
    decoded(&[0xfc, 7], Some("I64TruncSatF64U"), &[]);
    decoded(
        &[0xfc, 0x88, 0, 0x80, 0, 0xff, 0xff, 0xff, 0xff, 0x0f],
        Some("MemoryInit"),
        &[
            Requirement { start: 0, end: 10, feature: "multi_memory", reason: "nonzero memory index" },
            Requirement { start: 5, end: 10, feature: "multi_memory", reason: "memory.init memory index 4294967295 is not the Core2 literal reserved zero byte; this uses the newer memory-index wire grammar" },
        ],
    );
    decoded(
        &[0xfc, 10, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x80, 0x80, 0x40],
        Some("MemoryCopy"),
        &[
            Requirement { start: 0, end: 10, feature: "multi_memory", reason: "nonzero memory index" },
            Requirement { start: 0, end: 10, feature: "multi_memory", reason: "nonzero memory index" },
            Requirement { start: 2, end: 7, feature: "multi_memory", reason: "memory.copy destination memory index 4294967295 is not the Core2 literal reserved zero byte; this uses the newer memory-index wire grammar" },
            Requirement { start: 7, end: 10, feature: "multi_memory", reason: "memory.copy source memory index 1048576 is not the Core2 literal reserved zero byte; this uses the newer memory-index wire grammar" },
        ],
    );
    decoded(
        &[0xfc, 11, 0x7f],
        Some("MemoryFill"),
        &[
            Requirement { start: 0, end: 3, feature: "multi_memory", reason: "nonzero memory index" },
            Requirement { start: 2, end: 3, feature: "multi_memory", reason: "memory.fill memory index 127 is not the Core2 literal reserved zero byte; this uses the newer memory-index wire grammar" },
        ],
    );
    decoded(
        &[0xfc, 12, 0x7a, 0x7f],
        Some("TableInit"),
        &[Requirement {
            start: 0,
            end: 4,
            feature: "reference_types",
            reason: "nonzero table index",
        }],
    );
    decoded(
        &[
            0xfc, 0x8e, 0, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x80, 0x80, 0x40,
        ],
        Some("TableCopy"),
        &[
            Requirement {
                start: 0,
                end: 11,
                feature: "reference_types",
                reason: "nonzero table index",
            },
            Requirement {
                start: 0,
                end: 11,
                feature: "reference_types",
                reason: "nonzero table index",
            },
        ],
    );
}

#[test]
fn completed_bulk_indices_and_earlier_unknown_grammar_keep_their_owners() {
    owned(
        &fixture(&[0xfc, 11, 0, 0x41, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        Owner {
            start: 3,
            prior_instruction: Some(("MemoryFill", 3)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0xfc, 16, 0, 0xff], true),
        Owner {
            start: 3,
            prior_instruction: Some(("TableSize", 3)),
            ..UNKNOWN_OWNER
        },
    );
    owned(
        &fixture(&[0xfc, 13, 0x0b], false),
        Owner {
            suffix: "expression_structure",
            start: 3,
            diagnostic: "expression_structure",
            prior_instruction: Some(("ElemDrop", 3)),
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(
            &[0xfc, 9, 0, 0x0b, 0xfc, 8, 0x80, 0x80, 0x80, 0x80, 0x10],
            true,
        ),
        Owner {
            suffix: "trailing_bytes",
            start: 4,
            diagnostic: "expression_structure",
            prior_instruction: Some(("DataDrop", 3)),
            root_end: true,
            ..INVALID_OWNER
        },
    );
    owned(
        &fixture(&[0xff, 0xfc, 8, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_OWNER,
    );
    owned(
        &fixture(
            &[0x1c, 1, 0x7a, 0xfc, 14, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            true,
        ),
        Owner {
            feature: "unknown_value_type",
            ..UNKNOWN_OWNER
        },
    );
}

#[test]
fn failed_or_unknown_subopcodes_and_other_prefixes_never_gain_bulk_operand_leaves() {
    owned(&fixture(&[0xfc], false), INVALID_OWNER);
    owned(
        &fixture(&[0xfc, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        INVALID_OWNER,
    );
    owned(
        &fixture(&[0xfc, 0x80, 0x80, 0x80, 0x80, 0x80, 0], true),
        INVALID_OWNER,
    );
    owned(
        &fixture(&[0xfc, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xfc, 8, 0x80], true),
        UNKNOWN_OWNER,
    );
    owned(
        &fixture(&[0xfc, 18, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        INVALID_OWNER,
    );
    decoded(&[0xfb, 0x1c], Some("RefI31"), &[]);
    decoded(&[0xfd, 0x40], Some("I32x4GeU"), &[]);
    decoded(&[0xfe, 0x40, 0, 0], Some("I64AtomicRmw32XorU"), &[]);
    precise_named(
        &fixture(&[0x3f, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        1,
        6,
        "memory.size memory index",
        WIDTH_REASON,
        "memory_index_error",
    );
    precise_named(
        &fixture(&[0x40], false),
        1,
        1,
        "memory.grow memory index",
        EOF_REASON,
        "memory_index_error",
    );
}

#[test]
fn recovered_global_table_and_element_expressions_keep_bulk_fields_bounded() {
    let global = constant_fixture(6, &[0xfc, 8, 0, 0x80, 0x80, 0x80, 0x80, 0x10], true);
    assert_eq!(global.opcode, 30);
    precise_field(&global, 3, 8, "memory.init memory index", WIDTH_REASON);
    let table = constant_fixture(4, &[0xfc, 14], false);
    assert_eq!(table.opcode, 31);
    precise_field(
        &table,
        2,
        2,
        "table.copy destination table index",
        EOF_REASON,
    );
    let element = constant_fixture(9, &[0xfc, 17, 0x80], false);
    assert_eq!(element.opcode, 37);
    precise_field(&element, 2, 3, "table.fill table index", EOF_REASON);
    owned(
        &constant_fixture(6, &[0xff, 0xfc, 10, 0x80, 0x80, 0x80, 0x80, 0x10], true),
        UNKNOWN_OWNER,
    );
}
