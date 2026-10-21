//! Fixed known type fields before an unknown constructor; no mutation search.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const CARRIER: &str = "type[0]/undecoded";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

struct Fixture {
    bytes: Vec<u8>,
    failed: Span,
    custom: usize,
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn fixture(entry: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    let mut payload = vec![2, 0x60, 0, 0];
    payload.extend_from_slice(entry);
    let start = section(&mut bytes, 1, &payload);
    let failed = Span {
        start: start + 4,
        end: bytes.len(),
    };
    // Only the independently complete first type can supply a signature. A
    // complete-looking member of the failed second group supplies no type1.
    section(&mut bytes, 3, &[2, 0, 1]);
    section(&mut bytes, 10, &[2, 2, 0, 0x0b, 2, 0, 0x0b]);
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        failed,
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

fn span(fixture: &Fixture, start: usize, end: usize) -> Span {
    Span {
        start: fixture.failed.start + start,
        end: fixture.failed.start + end,
    }
}

fn expected_status(profile: Standard, feature: &str) -> &'static str {
    let supported = match feature {
        "core1" => true,
        "simd" | "reference_types" | "multi_value" => profile != Standard::Core1,
        "gc" | "function_references" => {
            matches!(profile, Standard::Core3 | Standard::AllKnown)
        }
        "shared_everything_threads" | "custom_descriptors" | "stack_switching" => {
            profile == Standard::AllKnown
        }
        _ => panic!("unexpected test feature {feature}"),
    };
    if supported {
        "supported"
    } else {
        "recognized_but_disabled"
    }
}

fn fact(
    profile: Standard,
    module: &AuditModule,
    fixture: &Fixture,
    start: usize,
    end: usize,
    feature: &str,
    role: &str,
) {
    let span = span(fixture, start, end);
    let status = expected_status(profile, feature);
    assert!(
        module.standard.evidence.iter().any(|evidence| {
            evidence.path == CARRIER
                && evidence.span == span
                && evidence.feature == feature
                && evidence.status == status
                && evidence.kind == "structure"
                && evidence.reason.contains(role)
        }),
        "{profile}: missing {feature} at {span:?}, role={role}"
    );
    let token = format!(
        "{status} {CARRIER} [{}..{}) binary={} feature={feature}",
        span.start,
        span.end,
        hex(&fixture.bytes[span.start..span.end])
    );
    assert!(
        module
            .to_text()
            .lines()
            .any(|line| { line.starts_with(&token) && line.contains(role) }),
        "{profile}: known prefix field absent from text: {token}"
    );
}

fn frontier(module: &AuditModule, fixture: &Fixture, offset: usize) {
    let opaque = at(module, CARRIER);
    assert_eq!(opaque.span, fixture.failed);
    assert_eq!(opaque.feature.as_deref(), Some("unknown_declaration_type"));
    assert_eq!(opaque.standard_support.status, "unknown");
    let marker_path = format!("{CARRIER}/value_type_start");
    let marker = at(module, &marker_path);
    assert_eq!(marker.span, span(fixture, offset, offset + 1));
    assert_eq!(marker.feature.as_deref(), Some("unknown_value_type"));
    assert_eq!(marker.standard_support.status, "unknown");
    assert!(!regions(module).iter().any(|region| {
        fixture.failed.start <= region.span.start
            && region.span.start < fixture.failed.end
            && region.path != CARRIER
            && region.path != marker_path
    }));
    for evidence in module
        .standard
        .evidence
        .iter()
        .filter(|evidence| evidence.path == CARRIER && evidence.status != "unknown")
    {
        assert!(fixture.failed.start <= evidence.span.start);
        assert!(evidence.span.start < evidence.span.end);
        assert!(evidence.span.end <= marker.span.start);
        assert!(!matches!(
            evidence.status.as_str(),
            "invalid_encoding" | "invalid_semantics"
        ));
    }
    // Indexed wire fields in a failed group do not leave pending dependencies
    // or turn the recognized prefix into a partially published type namespace.
    assert!(!module.standard.evidence.iter().any(|evidence| {
        evidence.path == CARRIER && evidence.status == "unknown" && evidence.span != fixture.failed
    }));
    assert!(!module.standard.evidence.iter().any(|evidence| {
        evidence.path.starts_with(CARRIER)
            && marker.span.start <= evidence.span.start
            && evidence.status != "unknown"
    }));
    assert_ne!(
        at(module, "function[0]/entry[0]").standard_support.status,
        "unknown"
    );
    assert_eq!(
        at(module, "function[0]/entry[1]").standard_support.status,
        "unknown"
    );
    assert_eq!(
        at(module, "code[0]/function[0]/operator[0]").description,
        "End"
    );
    assert_eq!(
        at(module, "code[0]/function[1]/operator[0]").description,
        "End"
    );
}

fn check(fixture: &Fixture, mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        assert_eq!(
            at(&module, "type[0]/type[0]").span,
            Span { start: 11, end: 14 }
        );
        for region in regions(&module) {
            assert!(region.span.start <= region.span.end && region.span.end <= fixture.bytes.len());
        }
        for evidence in &module.standard.evidence {
            assert!(
                evidence.span.start <= evidence.span.end
                    && evidence.span.end <= fixture.bytes.len()
            );
            assert_eq!(
                evidence.raw_hex,
                hex(&fixture.bytes[evidence.span.start..evidence.span.end])
            );
        }
        let json = serde_json::to_value(&module).unwrap();
        assert_eq!(
            json["standard"]["selected_standard"],
            serde_json::to_value(profile).unwrap()
        );
        assert_eq!(json["byte_len"], fixture.bytes.len());
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
        assert!(!module.standard.validator_valid);
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

#[test]
fn known_function_parameter_types_survive_a_later_unknown_parameter() {
    type Case<'a> = (&'a [u8], usize, usize, usize, usize, &'a str);
    let cases: &[Case<'_>] = &[
        (&[0x60, 2, 0x7b, 0xff, 0], 3, 2, 2, 3, "simd"),
        (&[0x60, 2, 0x6f, 0xff, 0], 3, 2, 2, 3, "reference_types"),
        (
            &[0x60, 2, 0x63, 1, 0xff, 0],
            4,
            2,
            2,
            4,
            "function_references",
        ),
        // Both a padded count and a concrete positive heap-index encoding
        // have complete, independent wire ranges before the unknown byte.
        (
            &[0x60, 0x82, 0, 0x63, 0xff, 0, 0xff, 0],
            6,
            3,
            3,
            6,
            "function_references",
        ),
    ];
    for (entry, unknown, count_end, value_start, value_end, feature) in cases {
        let fixture = fixture(entry);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, *unknown);
            fact(
                profile,
                module,
                &fixture,
                0,
                1,
                "core1",
                "function type marker",
            );
            fact(
                profile,
                module,
                &fixture,
                1,
                *count_end,
                "core1",
                "function parameter count",
            );
            fact(
                profile,
                module,
                &fixture,
                *value_start,
                *value_end,
                feature,
                "",
            );
            fact(
                profile,
                module,
                &fixture,
                *value_start,
                *value_end,
                "core1",
                "known value-type field boundary",
            );
        });
    }
}

#[test]
fn a_known_result_count_proves_multi_value_without_completing_the_result_types() {
    for (entry, count_end, value_start, unknown) in [
        (&[0x60, 0, 2, 0x7f, 0xff, 0][..], 3, 3, 4),
        (&[0x60, 0, 0x82, 0, 0x7f, 0xff, 0][..], 4, 4, 5),
    ] {
        let fixture = fixture(entry);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, unknown);
            fact(
                profile,
                module,
                &fixture,
                1,
                2,
                "core1",
                "function parameter count",
            );
            fact(
                profile,
                module,
                &fixture,
                2,
                count_end,
                "core1",
                "function result count",
            );
            fact(
                profile,
                module,
                &fixture,
                2,
                count_end,
                "multi_value",
                "function result count",
            );
            fact(
                profile,
                module,
                &fixture,
                value_start,
                value_start + 1,
                "core1",
                "known value-type field boundary",
            );
        });
    }
}

#[test]
fn recursive_subtype_and_supertype_wire_fields_do_not_publish_the_failed_group() {
    let cases: &[(&[u8], usize)] = &[
        (&[0x4e, 1, 0x60, 1, 0xff, 0], 4),
        (&[0x50, 0, 0x60, 1, 0xff, 0], 4),
        (&[0x4f, 1, 0, 0x60, 1, 0xff, 0], 5),
        (&[0x4e, 2, 0x60, 0, 0, 0x60, 1, 0xff, 0], 7),
    ];
    for (entry, unknown) in cases {
        let fixture = fixture(entry);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, *unknown);
            fact(profile, module, &fixture, 0, 1, "gc", "");
            fact(profile, module, &fixture, 1, 2, "gc", "count");
            if entry[0] == 0x4f {
                fact(profile, module, &fixture, 2, 3, "gc", "supertype index");
            }
            if entry[0] == 0x4e && entry[1] == 2 {
                fact(
                    profile,
                    module,
                    &fixture,
                    2,
                    3,
                    "core1",
                    "function type marker",
                );
                fact(
                    profile,
                    module,
                    &fixture,
                    4,
                    5,
                    "core1",
                    "function result count",
                );
            }
        });
    }
}

#[test]
fn shared_and_descriptor_modifiers_keep_their_exact_marker_and_index_spans() {
    let cases: &[(&[u8], usize)] = &[
        (&[0x65, 0x60, 1, 0xff, 0], 3),
        (&[0x4c, 0, 0x60, 1, 0xff, 0], 4),
        (&[0x4d, 0, 0x60, 1, 0xff, 0], 4),
        (&[0x65, 0x4c, 0, 0x4d, 0, 0x60, 1, 0xff, 0], 7),
    ];
    for (entry, unknown) in cases {
        let fixture = fixture(entry);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, *unknown);
            let mut offset = 0;
            if entry[offset] == 0x65 {
                fact(
                    profile,
                    module,
                    &fixture,
                    offset,
                    offset + 1,
                    "shared_everything_threads",
                    "shared composite type marker",
                );
                offset += 1;
            }
            for (marker, clause, index) in [
                (0x4c, "describes clause marker", "described type index"),
                (0x4d, "descriptor clause marker", "descriptor type index"),
            ] {
                if entry[offset] == marker {
                    fact(
                        profile,
                        module,
                        &fixture,
                        offset,
                        offset + 1,
                        "custom_descriptors",
                        clause,
                    );
                    fact(
                        profile,
                        module,
                        &fixture,
                        offset + 1,
                        offset + 2,
                        "custom_descriptors",
                        index,
                    );
                    offset += 2;
                }
            }
            fact(
                profile,
                module,
                &fixture,
                offset,
                offset + 1,
                "core1",
                "function type marker",
            );
        });
    }
}

#[test]
fn struct_storage_and_mutability_fields_remain_located_before_unknown_storage() {
    for (entry, unknown) in [
        (&[0x5f, 3, 0x78, 0, 0x77, 1, 0xff, 0][..], 6),
        (&[0x5f, 2, 0x7b, 1, 0xff, 0][..], 4),
    ] {
        let fixture = fixture(entry);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, unknown);
            fact(profile, module, &fixture, 0, 1, "gc", "struct type marker");
            fact(profile, module, &fixture, 1, 2, "gc", "struct field count");
            fact(profile, module, &fixture, 3, 4, "gc", "field mutability");
            if entry[2] == 0x78 {
                fact(
                    profile,
                    module,
                    &fixture,
                    2,
                    3,
                    "gc",
                    "packed field storage type",
                );
                fact(
                    profile,
                    module,
                    &fixture,
                    4,
                    5,
                    "gc",
                    "packed field storage type",
                );
                fact(profile, module, &fixture, 5, 6, "gc", "field mutability");
            } else {
                fact(profile, module, &fixture, 2, 3, "simd", "");
            }
        });
    }
}

#[test]
fn array_markers_and_complete_packed_array_members_remain_wire_facts_only() {
    for (entry, unknown) in [
        (&[0x5e, 0xff, 0][..], 1),
        (&[0x4e, 2, 0x5e, 0x78, 1, 0x60, 1, 0xff, 0][..], 7),
    ] {
        let fixture = fixture(entry);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, unknown);
            let offset = if entry[0] == 0x4e { 2 } else { 0 };
            fact(
                profile,
                module,
                &fixture,
                offset,
                offset + 1,
                "gc",
                "array type marker",
            );
            if offset == 2 {
                fact(
                    profile,
                    module,
                    &fixture,
                    3,
                    4,
                    "gc",
                    "packed field storage type",
                );
                fact(profile, module, &fixture, 4, 5, "gc", "field mutability");
            }
        });
    }
}

#[test]
fn complete_continuation_wire_fields_do_not_declare_a_type_in_the_failed_group() {
    for (entry, index_end, unknown) in [
        (&[0x4e, 2, 0x5d, 0, 0x60, 1, 0xff, 0][..], 4, 6),
        (&[0x4e, 2, 0x5d, 0x80, 0, 0x60, 1, 0xff, 0][..], 5, 7),
    ] {
        let fixture = fixture(entry);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, unknown);
            fact(
                profile,
                module,
                &fixture,
                2,
                3,
                "stack_switching",
                "continuation type marker",
            );
            fact(
                profile,
                module,
                &fixture,
                3,
                index_end,
                "stack_switching",
                "continuation function type index",
            );
        });
    }
}

#[test]
fn complete_indexed_storage_type_withdraws_its_pending_type_dependency() {
    let fixture = fixture(&[0x5f, 2, 0x63, 2, 0, 0xff, 0]);
    check(&fixture, |profile, module| {
        frontier(module, &fixture, 5);
        fact(profile, module, &fixture, 2, 4, "function_references", "");
        fact(
            profile,
            module,
            &fixture,
            2,
            4,
            "core1",
            "known value-type field boundary",
        );
        fact(profile, module, &fixture, 4, 5, "gc", "field mutability");
        assert!(!module.standard.evidence.iter().any(|evidence| {
            evidence.path == CARRIER
                && evidence
                    .reason
                    .contains("lies beyond the complete type declaration prefix")
        }));
    });
}

#[test]
fn prior_errors_and_future_composite_forms_do_not_authorize_later_type_fields() {
    let cases: &[&[u8]] = &[
        &[0x60, 2, 0, 0xff, 0, 0],
        &[0x5f, 2, 0x78, 2, 0xff, 0],
        &[0x50, 2, 0, 0, 0x60, 1, 0xff, 0],
        &[0x4e, 0x80, 0x80, 0x80, 0x80, 0x10, 0x60, 1, 0xff, 0],
        &[0x50, 0x80, 0x80, 0x80, 0x80, 0x10, 0x60, 1, 0xff, 0],
        &[0x4e, 2, 0x5d, 0x7f, 0x60, 1, 0xff, 0],
        &[0x4e, 1, 0x61, 0x60, 1, 0xff, 0],
        &[0x4e, 1],
    ];
    for entry in cases {
        let fixture = fixture(entry);
        check(&fixture, |_, module| {
            assert!(!regions(module).iter().any(|region| {
                region.feature.as_deref() == Some("unknown_declaration_type")
                    || region.path.ends_with("/value_type_start")
            }));
            assert!(!module.standard.evidence.iter().any(|evidence| {
                evidence.path == CARRIER
                    && matches!(
                        evidence.status.as_str(),
                        "supported" | "recognized_but_disabled"
                    )
            }));
            // An unknown future composite constructor is not a known invalid
            // value type, and cannot lend boundaries to the following bytes.
            if entry.starts_with(&[0x4e, 1, 0x61]) {
                assert!(module.standard.evidence.iter().any(|evidence| {
                    evidence.path == CARRIER
                        && evidence.status == "unknown"
                        && evidence.span == fixture.failed
                }));
                assert!(!module.standard.evidence.iter().any(|evidence| {
                    evidence.path == CARRIER && evidence.status == "invalid_encoding"
                }));
            }
        });
    }
}
