//! Fixed pinned type-reader resource frontiers; limits are not Core wire rules.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const CARRIER: &str = "type[0]/undecoded";
const TYPE_ERROR: &str = "type[0]/undecoded/type_error";
const EOF_REASON: &str = "known encoding is truncated at its trusted input boundary";
const WIDTH_REASON: &str = "integer encoding exceeds its required width or length";
const PACKED_REASON: &str = "type index greater than implementation limits";
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
    failed: Span,
    later: Span,
    custom: usize,
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn fixture(entry: &[u8], fake_later_type: bool) -> Fixture {
    let mut bytes = HEADER.to_vec();
    let mut payload = vec![if fake_later_type { 3 } else { 2 }, 0x60, 0, 0];
    payload.extend_from_slice(entry);
    if fake_later_type {
        // These bytes look like a complete third type. The failed second
        // entry/group supplies neither its own nor a later type boundary.
        payload.extend_from_slice(&[0x60, 0, 0]);
    }
    let start = section(&mut bytes, 1, &payload);
    let failed = Span {
        start: start + 4,
        end: bytes.len(),
    };
    section(&mut bytes, 3, &[3, 0, 1, 0]);
    assert_eq!(LATER.len(), 33);
    let mut code = vec![3, 2, 0, 0x0b, 2, 0, 0x0b, 33];
    code.extend_from_slice(LATER);
    let start = section(&mut bytes, 10, &code);
    let later = Span {
        start: start + 8,
        end: bytes.len(),
    };
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        failed,
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
        start: fixture.failed.start + start,
        end: fixture.failed.start + end,
    }
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
        assert_eq!(fixture.failed.start, 14);
        assert_eq!(
            at(&module, "type[0]/count").span,
            Span { start: 10, end: 11 }
        );
        assert_eq!(
            at(&module, "type[0]/type[0]").span,
            Span { start: 11, end: 14 }
        );
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
        // Only the complete first type may supply a signature. No fake type1
        // or type2, group1 or group2, is published into either physical or
        // standard evidence after the resource/unknown boundary.
        for path in [
            "type[0]/type[1]",
            "type[0]/type[2]",
            "type[0]/group[1]",
            "type[0]/group[2]",
        ] {
            assert!(!regions(&module)
                .iter()
                .any(|region| region.path == path || region.path.starts_with(&format!("{path}/"))));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|row| row.path == path || row.path.starts_with(&format!("{path}/"))));
        }
        assert_ne!(
            at(&module, "function[0]/entry[0]").standard_support.status,
            "unknown"
        );
        assert_eq!(
            at(&module, "function[0]/entry[1]").standard_support.status,
            "unknown"
        );
        assert_ne!(
            at(&module, "function[0]/entry[2]").standard_support.status,
            "unknown"
        );
        assert_eq!(
            at(&module, "code[0]/function[0]/operator[0]").description,
            "End"
        );
        assert_eq!(
            at(&module, "code[0]/function[1]/operator[0]").description,
            "End"
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
                && row.span == region.span
                && row.feature == feature
                && row.status == status));
        }
        let sentinel = at(&module, "code[0]/function[2]/operator[7]");
        assert_eq!(
            sentinel.span,
            Span {
                start: fixture.later.start + 29,
                end: fixture.later.start + 31
            }
        );
        assert_eq!(
            &fixture.bytes[sentinel.span.start..sentinel.span.end],
            &[0x41, 42]
        );
        assert_eq!(sentinel.standard_support.status, "supported");
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

fn resource(entry: &[u8], message: &str, error_offset: usize) {
    let fixture = fixture(entry, true);
    check(&fixture, |_, module| {
        assert_eq!(module.sections[0].status, "malformed");
        let carrier = at(module, CARRIER);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.feature.as_deref(), Some("unknown"));
        assert_eq!(carrier.standard_support.status, "unknown");
        assert_eq!(carrier.standard_support.display, "opaque");
        assert_eq!(carrier.standard_support.required_features, vec!["unknown"]);
        assert!(carrier.children.is_empty());
        let error_offset = fixture.failed.start + error_offset;
        let reader_error = format!("{message} (at offset 0x{error_offset:x})");
        assert_eq!(carrier.description, format!("unrecognized or unclassified grammar: {reader_error}; undecoded payload includes the failed entry and remaining bytes, without inferred later entry boundaries"));
        let reason = format!("unrecognized or unclassified section grammar: {reader_error}; failed entry and remaining payload are not decoded; no later entry boundaries inferred");
        let raw = hex(&fixture.bytes[fixture.failed.start..fixture.failed.end]);
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == CARRIER || row.path.starts_with(&format!("{CARRIER}/")))
            .map(|row| serde_json::to_value(row).unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![serde_json::json!({
                "path": CARRIER, "span": fixture.failed, "feature": "unknown", "status": "unknown", "kind": "opaque",
                "reason": reason, "raw_hex": raw, "recognized": null
            })]
        );
        assert!(!regions(module)
            .iter()
            .any(|region| fixture.failed.start <= region.span.start
                && region.span.start < fixture.failed.end
                && region.path != CARRIER));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| fixture.failed.start <= row.span.start
                && row.span.start < fixture.failed.end
                && row.path != CARRIER));
        let actual: Vec<_> = module
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "core_decode")
            .map(|diagnostic| serde_json::to_value(diagnostic).unwrap())
            .collect();
        assert_eq!(
            actual,
            vec![
                serde_json::json!({"severity": "error", "code": "core_decode", "offset": error_offset, "message": reader_error})
            ]
        );
        assert!(!module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "unknown_declaration_type"));
        let line = format!(
            "unknown {CARRIER} [{}..{}) binary={raw} feature=unknown recognized=None: {reason}",
            fixture.failed.start, fixture.failed.end
        );
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|text| text.starts_with(&format!("unknown {CARRIER} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
    });
}

fn future(entry: &[u8], offset: usize) {
    let fixture = fixture(entry, true);
    check(&fixture, |_, module| {
        assert_eq!(module.sections[0].status, "partially_decoded");
        let carrier = at(module, CARRIER);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.feature.as_deref(), Some("unknown_declaration_type"));
        assert_eq!(carrier.standard_support.status, "unknown");
        assert_eq!(carrier.standard_support.display, "opaque");
        assert_eq!(carrier.children.len(), 1);
        let marker_path = format!("{CARRIER}/value_type_start");
        let marker = at(module, &marker_path);
        assert_eq!(marker.span, relative(&fixture, offset, offset + 1));
        assert_eq!(marker.feature.as_deref(), Some("unknown_value_type"));
        assert_eq!(marker.standard_support.status, "unknown");
        assert!(marker.children.is_empty());
        assert_eq!(carrier.children[0].path, marker_path);
        assert!(!regions(module)
            .iter()
            .any(|region| fixture.failed.start <= region.span.start
                && region.span.start < fixture.failed.end
                && region.path != CARRIER
                && region.path != marker_path));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(CARRIER) && row.status == "invalid_encoding"));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(CARRIER)
                && row.status != "unknown"
                && row.span.end > marker.span.start));
        assert!(!module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "core_decode"));
        assert!(module
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "unknown_declaration_type"
                && diagnostic.offset == marker.span.start));
    });
}

struct Known {
    entry: &'static [u8],
    field: &'static str,
    start: usize,
    end: usize,
    reason: &'static str,
}

fn known(case: Known) {
    let fixture = fixture(case.entry, false);
    check(&fixture, |_, module| {
        assert_eq!(module.sections[0].status, "malformed");
        let carrier = at(module, CARRIER);
        assert_eq!(carrier.span, fixture.failed);
        assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(carrier.standard_support.status, "invalid_encoding");
        assert_eq!(carrier.standard_support.display, "binary");
        assert_eq!(carrier.children.len(), 1);
        assert_eq!(carrier.children[0].path, TYPE_ERROR);
        let child = at(module, TYPE_ERROR);
        let span = relative(&fixture, case.start, case.end);
        let description = format!(
            "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
            case.field, case.reason
        );
        assert_eq!(child.span, span);
        assert_eq!(child.feature.as_deref(), Some("invalid_encoding"));
        assert_eq!(child.standard_support.status, "invalid_encoding");
        assert_eq!(child.standard_support.display, "binary");
        assert_eq!(child.description, description);
        assert!(child.children.is_empty());
        let raw = hex(&fixture.bytes[span.start..span.end]);
        let rows: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|row| row.path == TYPE_ERROR)
            .map(|row| serde_json::to_value(row).unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![
                serde_json::json!({"path": TYPE_ERROR, "span": span, "feature": "section_structure", "status": "invalid_encoding", "kind": "structure", "reason": description, "raw_hex": raw, "recognized": null})
            ]
        );
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|row| row.path.starts_with(CARRIER) && row.status == "unknown"));
        let line = format!("invalid_encoding {TYPE_ERROR} [{}..{}) binary={raw} feature=section_structure recognized=None: {description}", span.start, span.end);
        assert_eq!(
            module
                .to_text()
                .lines()
                .filter(|text| text.starts_with(&format!("invalid_encoding {TYPE_ERROR} ")))
                .collect::<Vec<_>>(),
            vec![line.as_str()]
        );
    });
}

#[test]
fn parameter_limit_stops_before_every_apparent_value_and_fake_type() {
    resource(
        &[0x60, 0xe9, 0x07, 0x7a],
        "function params size is out of bounds",
        1,
    );
    resource(
        &[0x60, 0xe9, 0x07, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        "function params size is out of bounds",
        1,
    );
    resource(
        &[0x60, 0xe9, 0x07, 0x7f, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10],
        "function params size is out of bounds",
        1,
    );
    resource(
        &[0x60, 0xe9, 0x07, 0x65, 0x7f, 0x60, 0, 0],
        "function params size is out of bounds",
        1,
    );
    resource(
        &[0x60, 0xe9, 0x87, 0, 0x7b, 0x7a],
        "function params size is out of bounds",
        1,
    );
    resource(
        &[0x60, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7a],
        "function params size is out of bounds",
        1,
    );
}

#[test]
fn result_limit_is_checked_before_any_result_value_prefix() {
    resource(
        &[0x60, 0, 0xe9, 0x07, 0x7a],
        "function returns size is out of bounds",
        2,
    );
    resource(
        &[0x60, 0, 0xe9, 0x07, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        "function returns size is out of bounds",
        2,
    );
    resource(
        &[
            0x60, 0, 0xe9, 0x07, 0x7f, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        "function returns size is out of bounds",
        2,
    );
    resource(
        &[0x60, 0, 0xe9, 0x07, 0x65, 0x7f, 0x60, 0, 0],
        "function returns size is out of bounds",
        2,
    );
    resource(
        &[0x60, 0, 0xe9, 0x87, 0, 0x7b, 0x7a],
        "function returns size is out of bounds",
        2,
    );
    resource(
        &[0x60, 0, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7a],
        "function returns size is out of bounds",
        2,
    );
}

#[test]
fn struct_field_limit_precedes_storage_type_and_mutability() {
    resource(
        &[0x5f, 0x91, 0x4e, 0x7a, 0],
        "struct fields size is out of bounds",
        1,
    );
    resource(
        &[0x5f, 0x91, 0x4e, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
        "struct fields size is out of bounds",
        1,
    );
    resource(
        &[
            0x5f, 0x91, 0x4e, 0x7f, 0, 0x63, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        "struct fields size is out of bounds",
        1,
    );
    resource(
        &[0x5f, 0x91, 0x4e, 0x78, 1, 0xff, 0],
        "struct fields size is out of bounds",
        1,
    );
    resource(
        &[0x5f, 0x91, 0xce, 0, 0x78, 0, 0x7a, 0],
        "struct fields size is out of bounds",
        1,
    );
    resource(
        &[0x5f, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7a, 0],
        "struct fields size is out of bounds",
        1,
    );
}

#[test]
fn recursive_group_limit_precedes_the_first_member_constructor() {
    resource(
        &[0x4e, 0xc1, 0x84, 0x3d, 0x60, 1, 0x7a],
        "rec group types size is out of bounds",
        1,
    );
    resource(
        &[
            0x4e, 0xc1, 0x84, 0x3d, 0x60, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        "rec group types size is out of bounds",
        1,
    );
    resource(
        &[0x4e, 0xc1, 0x84, 0x3d, 0x60, 1, 0x7f, 0, 0x60, 1, 0x7a],
        "rec group types size is out of bounds",
        1,
    );
    resource(
        &[0x4e, 0xc1, 0x84, 0x3d, 0x60, 1, 0x65, 0x7f],
        "rec group types size is out of bounds",
        1,
    );
    resource(
        &[0x4e, 0xc1, 0x84, 0xbd, 0, 0x60, 1, 0x7a],
        "rec group types size is out of bounds",
        1,
    );
    resource(
        &[0x4e, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x60, 1, 0x7a],
        "rec group types size is out of bounds",
        1,
    );
}

#[test]
fn packed_supertype_limit_stops_before_the_composite_constructor() {
    resource(
        &[0x4f, 1, 0x80, 0x80, 0x40, 0x60, 1, 0x7a],
        PACKED_REASON,
        5,
    );
    resource(
        &[0x50, 1, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x60, 1, 0x7a],
        PACKED_REASON,
        7,
    );
}

#[test]
fn packed_describes_limit_stops_before_the_next_composite_opcode() {
    resource(&[0x4c, 0x80, 0x80, 0x40, 0x60, 1, 0x7a], PACKED_REASON, 4);
    resource(
        &[0x4c, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x60, 1, 0x7a],
        PACKED_REASON,
        6,
    );
}

#[test]
fn packed_descriptor_limit_stops_before_the_next_composite_opcode() {
    resource(&[0x4d, 0x80, 0x80, 0x40, 0x60, 1, 0x7a], PACKED_REASON, 4);
    resource(
        &[0x4d, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x60, 1, 0x7a],
        PACKED_REASON,
        6,
    );
}

#[test]
fn inclusive_count_and_packed_limits_still_reach_unknown_values() {
    // These are short wire prefixes, not count-sized vectors. Unlike the
    // unsigned indices above, a HeapType operand would use signed LEB rules.
    future(&[0x60, 0xe8, 0x07, 0x7a], 3);
    future(&[0x60, 0, 0xe8, 0x07, 0x7a], 4);
    future(&[0x5f, 0x90, 0x4e, 0x7a, 0], 3);
    future(&[0x4e, 0xc0, 0x84, 0x3d, 0x60, 1, 0x7a], 6);
    future(&[0x50, 1, 0xff, 0xff, 0x3f, 0x60, 1, 0x7a], 7);
    future(&[0x4c, 0xff, 0xff, 0x3f, 0x60, 1, 0x7a], 6);
    future(&[0x4d, 0xff, 0xff, 0x3f, 0x60, 1, 0x7a], 6);
}

#[test]
fn count_eof_and_integer_width_errors_keep_existing_precise_type_leaves() {
    for case in [
        Known {
            entry: &[0x60],
            field: "function parameter count",
            start: 1,
            end: 1,
            reason: EOF_REASON,
        },
        Known {
            entry: &[0x60, 0],
            field: "function result count",
            start: 2,
            end: 2,
            reason: EOF_REASON,
        },
        Known {
            entry: &[0x5f],
            field: "struct field count",
            start: 1,
            end: 1,
            reason: EOF_REASON,
        },
        Known {
            entry: &[0x4e],
            field: "recursive type member count",
            start: 1,
            end: 1,
            reason: EOF_REASON,
        },
        Known {
            entry: &[0x60, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "function parameter count",
            start: 1,
            end: 6,
            reason: WIDTH_REASON,
        },
        Known {
            entry: &[0x60, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "function result count",
            start: 2,
            end: 7,
            reason: WIDTH_REASON,
        },
        Known {
            entry: &[0x5f, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "struct field count",
            start: 1,
            end: 6,
            reason: WIDTH_REASON,
        },
        Known {
            entry: &[0x4e, 0x80, 0x80, 0x80, 0x80, 0x10],
            field: "recursive type member count",
            start: 1,
            end: 6,
            reason: WIDTH_REASON,
        },
    ] {
        known(case);
    }
}

#[test]
fn partial_and_too_long_counts_do_not_become_resource_limits() {
    for case in [
        Known {
            entry: &[0x60, 0x80],
            field: "function parameter count",
            start: 1,
            end: 2,
            reason: EOF_REASON,
        },
        Known {
            entry: &[0x4e, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
            field: "recursive type member count",
            start: 1,
            end: 6,
            reason: WIDTH_REASON,
        },
    ] {
        known(case);
    }
}

#[test]
fn an_earlier_unknown_value_cannot_expose_a_later_resource_or_error() {
    future(
        &[
            0x60, 1, 0x7a, 0x60, 0xe9, 0x07, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
        ],
        2,
    );
    future(&[0x5f, 1, 0x7a, 0, 0x60, 0xe9, 0x07, 0x7f], 2);
    future(&[0x4e, 2, 0x60, 1, 0x7a, 0x60, 0xe9, 0x07, 0x7f], 4);
}
