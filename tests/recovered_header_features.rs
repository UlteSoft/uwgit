//! Fixed feature evidence before failed expressions; no mutation search.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

struct Fixture {
    bytes: Vec<u8>,
    entry: Span,
    custom: usize,
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn finish(mut bytes: Vec<u8>, entry: Span) -> Fixture {
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        entry,
        custom,
    }
}

fn element(entry: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    // A complete MVP segment remains readable before the failing segment.
    let mut payload = vec![2, 0, 0x41, 0, 0x0b, 0];
    let offset = payload.len();
    payload.extend_from_slice(entry);
    let start = section(&mut bytes, 9, &payload) + offset;
    let end = bytes.len();
    finish(bytes, Span { start, end })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn feature(profile: Standard, module: &AuditModule, path: &str, span: Span, name: &str) {
    let expected = if profile == Standard::Core1 {
        "recognized_but_disabled"
    } else {
        "supported"
    };
    assert!(
        module.standard.evidence.iter().any(|evidence| {
            evidence.path == path
                && evidence.span == span
                && evidence.feature == name
                && evidence.status == expected
                && evidence.kind == "structure"
        }),
        "{profile}: missing {name} at {path} {span:?}"
    );
}

fn no_feature(module: &AuditModule, path: &str, name: &str) {
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|evidence| evidence.path == path && evidence.feature == name));
}

fn opaque(module: &AuditModule, fixture: &Fixture, path: &str, start: usize, status: &str) {
    let region = at(module, path);
    assert_eq!(
        region.span,
        Span {
            start,
            end: fixture.entry.end
        }
    );
    assert_eq!(region.standard_support.status, status);
    assert!(module.standard.evidence.iter().any(|evidence| {
        evidence.path == path
            && evidence.span == region.span
            && evidence.status == status
            && evidence.raw_hex == hex(&fixture.bytes[start..fixture.entry.end])
    }));
    let parent = path.strip_suffix("/opaque");
    assert!(!regions(module).iter().any(|region| {
        start <= region.span.start
            && region.span.start < fixture.entry.end
            && region.path != path
            && Some(region.path.as_str()) != parent
    }));
}

fn check(fixture: &Fixture, mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        for region in regions(&module) {
            assert!(region.span.start <= region.span.end && region.span.end <= fixture.bytes.len());
        }
        for evidence in &module.standard.evidence {
            assert!(evidence.span.start <= evidence.span.end);
            assert!(evidence.span.end <= fixture.bytes.len());
            assert_eq!(
                evidence.raw_hex,
                hex(&fixture.bytes[evidence.span.start..evidence.span.end])
            );
        }
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
        assert_eq!(
            at(&module, "custom[0]/payload/opaque").span,
            Span {
                start: fixture.custom + 4,
                end: fixture.custom + 5
            }
        );
        inspect(profile, &module);
        let diff = audit::compare_with_standard(HEADER, &fixture.bytes, profile).unwrap();
        // Reconstruct from the actual physical byte edits, independently of
        // BytePatch's representation and the selected standard evidence.
        let mut replay = Vec::new();
        let mut cursor = 0;
        for edit in &diff.edits {
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

fn element_prefix(module: &AuditModule) {
    let prefix = at(module, "element[0]/entry[0]");
    assert_eq!(prefix.span, Span { start: 17, end: 22 });
    assert_eq!(prefix.standard_support.status, "supported");
    assert_eq!(
        at(module, "element[0]/entry[0]/offset/operator[0]").description,
        "I32Const { value: 0 }"
    );
    assert!(!regions(module)
        .iter()
        .any(|region| region.path.starts_with("element[0]/entry[2]")));
}

#[test]
fn passive_and_declarative_expression_headers_keep_bulk_memory_before_unknown_items() {
    // These are two specified segment encodings, not generated mutations.
    for flags in [5, 7] {
        let fixture = element(&[flags, 0x70, 1, 0xd0, 0x70, 0xff, 0x0b, 1, 0x70, 0]);
        check(&fixture, |profile, module| {
            element_prefix(module);
            let flag_span = Span {
                start: fixture.entry.start,
                end: fixture.entry.start + 1,
            };
            feature(
                profile,
                module,
                "element[0]/entry[1]",
                flag_span,
                "bulk_memory",
            );
            assert!(module.standard.evidence.iter().any(|evidence| {
                evidence.path == "element[0]/entry[1]"
                    && evidence.feature == "reference_types"
                    && evidence.status
                        == if profile == Standard::Core1 {
                            "recognized_but_disabled"
                        } else {
                            "supported"
                        }
            }));
            let known = at(module, "element[0]/entry[1]/item[0]/operator[0]");
            assert_eq!(
                &fixture.bytes[known.span.start..known.span.end],
                &[0xd0, 0x70]
            );
            assert_eq!(known.span.start, fixture.entry.start + 3);
            opaque(
                module,
                &fixture,
                "element[0]/entry[1]/item[0]/opaque",
                fixture.entry.start + 5,
                "unknown",
            );
            assert!(!regions(module)
                .iter()
                .any(|region| region.path.starts_with("element[0]/entry[1]/item[1]")));
        });
    }
}

#[test]
fn passive_and_declarative_expression_headers_survive_a_truncated_known_item() {
    for flags in [5, 7] {
        let fixture = element(&[flags, 0x70, 1, 0xd0, 0x70, 0xd0]);
        check(&fixture, |profile, module| {
            element_prefix(module);
            feature(
                profile,
                module,
                "element[0]/entry[1]",
                Span {
                    start: fixture.entry.start,
                    end: fixture.entry.start + 1,
                },
                "bulk_memory",
            );
            opaque(
                module,
                &fixture,
                "element[0]/entry[1]/item[0]/opaque",
                fixture.entry.start + 5,
                "invalid_encoding",
            );
            assert_eq!(
                at(module, "element[0]/entry[1]/item[0]/operator[0]")
                    .span
                    .start,
                fixture.entry.start + 3
            );
        });
    }
}

#[test]
fn passive_and_declarative_index_forms_keep_their_known_and_truncated_boundaries() {
    for flags in [1, 3] {
        let fixture = element(&[flags, 0, 0]);
        check(&fixture, |profile, module| {
            element_prefix(module);
            feature(
                profile,
                module,
                "element[0]/entry[1]",
                Span {
                    start: fixture.entry.start,
                    end: fixture.entry.start + 1,
                },
                "bulk_memory",
            );
            assert_eq!(at(module, "element[0]/entry[1]").span, fixture.entry);
            no_feature(module, "element[0]/entry[1]", "reference_types");
        });
        // Index items have no expression start. Preserve the complete failed
        // entry and expose only the proved u32 error, without item regions.
        let fixture = element(&[flags, 0, 1, 0x80]);
        check(&fixture, |_, module| {
            element_prefix(module);
            let path = "element[0]/undecoded";
            let carrier = at(module, path);
            assert_eq!(carrier.span, fixture.entry);
            assert_eq!(carrier.feature.as_deref(), Some("invalid_encoding"));
            assert_eq!(carrier.standard_support.status, "invalid_encoding");
            assert_eq!(carrier.standard_support.display, "binary");
            assert!(module.standard.evidence.iter().any(|evidence| {
                evidence.path == path
                    && evidence.span == fixture.entry
                    && evidence.status == "invalid_encoding"
                    && evidence.raw_hex
                        == hex(&fixture.bytes[fixture.entry.start..fixture.entry.end])
            }));
            let error_path = "element[0]/undecoded/element_error";
            assert_eq!(carrier.children.len(), 1);
            assert_eq!(carrier.children[0].path, error_path);
            let error = at(module, error_path);
            assert_eq!(error.span, Span { start: 25, end: 26 });
            assert_eq!(error.feature.as_deref(), Some("invalid_encoding"));
            assert_eq!(error.standard_support.status, "invalid_encoding");
            assert_eq!(error.standard_support.display, "binary");
            assert!(error.children.is_empty());
            assert_eq!(error.description, "element function index: known encoding is truncated at its trusted input boundary; only this field is diagnosed, remaining bytes stay undecoded");
            let errors: Vec<_> = module
                .standard
                .evidence
                .iter()
                .filter(|evidence| evidence.path == error_path)
                .collect();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].span, error.span);
            assert_eq!(errors[0].status, "invalid_encoding");
            assert_eq!(errors[0].kind, "structure");
            assert_eq!(errors[0].raw_hex, "80");
            assert_eq!(errors[0].recognized, None);
            assert_eq!(errors[0].reason, error.description);
            assert!(!regions(module).iter().any(|region| {
                fixture.entry.start <= region.span.start
                    && region.span.start < fixture.entry.end
                    && region.path != path
                    && region.path != error_path
            }));
            assert!(!regions(module)
                .iter()
                .any(|region| region.path.starts_with("element[0]/entry[1]")));
        });
    }
}

#[test]
fn active_element_headers_do_not_gain_passive_or_declarative_bulk_memory() {
    for flags in [0, 2, 4, 6] {
        let mut entry = vec![flags];
        if flags & 2 != 0 {
            entry.push(0); // Explicit table zero, before the offset expression.
        }
        entry.extend_from_slice(&[0x41, 0, 0xff, 0x0b, 0, 1, 0x70, 0]);
        let fixture = element(&entry);
        check(&fixture, |profile, module| {
            element_prefix(module);
            no_feature(module, "element[0]/entry[1]", "bulk_memory");
            if flags == 0 {
                no_feature(module, "element[0]/entry[1]", "reference_types");
            } else {
                feature(
                    profile,
                    module,
                    "element[0]/entry[1]",
                    Span {
                        start: fixture.entry.start,
                        end: fixture.entry.start + 1,
                    },
                    "reference_types",
                );
            }
            let constant = at(module, "element[0]/entry[1]/offset/operator[0]");
            assert_eq!(
                &fixture.bytes[constant.span.start..constant.span.end],
                &[0x41, 0]
            );
            assert_eq!(constant.standard_support.status, "supported");
            opaque(
                module,
                &fixture,
                "element[0]/entry[1]/offset/opaque",
                constant.span.end,
                "unknown",
            );
            assert!(!regions(module)
                .iter()
                .any(|region| region.path.starts_with("element[0]/entry[1]/item[")));
        });
    }
}

fn table(prior: &str, code: bool) -> Fixture {
    let mut bytes = HEADER.to_vec();
    if code {
        section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    }
    if prior == "imported" {
        section(&mut bytes, 2, &[1, 1, b'm', 1, b't', 1, 0x70, 0, 1]);
    }
    if code {
        section(&mut bytes, 3, &[1, 0]);
    }
    let mut payload = if prior == "defined" {
        vec![2, 0x70, 0, 1]
    } else {
        vec![1]
    };
    let offset = payload.len();
    payload.extend_from_slice(&[0x40, 0, 0x70, 0, 1, 0xff, 0x0b]);
    let start = section(&mut bytes, 4, &payload) + offset;
    let end = bytes.len();
    if code {
        // The failed table must never enter the declaration map. Index1 is
        // beyond every complete prefix, including the no-prior-table control.
        section(&mut bytes, 10, &[1, 6, 0, 0xfc, 0x10, 1, 0x1a, 0x0b]);
    }
    finish(bytes, Span { start, end })
}

#[test]
fn recovered_table_header_preserves_additional_table_feature_without_a_declaration() {
    for prior in ["defined", "imported", "none"] {
        let fixture = table(prior, false);
        check(&fixture, |profile, module| {
            let path = if prior == "defined" {
                "table[0]/entry[1]"
            } else {
                "table[0]/entry[0]"
            };
            let span = Span {
                start: fixture.entry.start,
                end: fixture.entry.start + 5,
            };
            assert_eq!(at(module, &format!("{path}/header")).span, span);
            assert!(module.standard.evidence.iter().any(|evidence| {
                evidence.path == path
                    && evidence.span == span
                    && evidence.feature == "function_references"
                    && evidence.status
                        == if matches!(profile, Standard::Core3 | Standard::AllKnown) {
                            "supported"
                        } else {
                            "recognized_but_disabled"
                        }
            }));
            if prior == "none" {
                no_feature(module, path, "reference_types");
            } else {
                feature(profile, module, path, span, "reference_types");
                assert!(module.standard.evidence.iter().any(|evidence| {
                    evidence.path == path
                        && evidence.feature == "reference_types"
                        && evidence.reason.contains("additional table")
                }));
            }
            opaque(
                module,
                &fixture,
                &format!("{path}/init/opaque"),
                fixture.entry.start + 5,
                "unknown",
            );
            if prior == "defined" {
                assert_eq!(
                    at(module, "table[0]/entry[0]").span,
                    Span { start: 11, end: 14 }
                );
                assert_eq!(fixture.entry, Span { start: 14, end: 21 });
                assert_eq!(fixture.custom, 21);
            }
        });
    }
}

#[test]
fn header_feature_evidence_does_not_publish_a_failed_table_for_later_operands() {
    for prior in ["defined", "imported", "none"] {
        let fixture = table(prior, true);
        check(&fixture, |_, module| {
            let operand = at(module, "code[0]/function[0]/operator[0]");
            assert_eq!(operand.description, "TableSize { table: 1 }");
            assert_eq!(
                &fixture.bytes[operand.span.start..operand.span.end],
                &[0xfc, 0x10, 1]
            );
            assert_eq!(operand.standard_support.status, "unknown");
            assert!(module.standard.evidence.iter().any(|evidence| {
                evidence.path == operand.path
                    && evidence.status == "unknown"
                    && evidence.reason.contains(
                        "table index 1 lies beyond the complete table/import declaration prefix",
                    )
            }));
            assert_eq!(
                at(module, "code[0]/function[0]/operator[1]").description,
                "Drop"
            );
            assert_eq!(
                at(module, "code[0]/function[0]/operator[2]").description,
                "End"
            );
        });
    }
}

#[test]
fn known_element_flags_survive_an_unknown_declaration_type_without_interpreting_its_suffix() {
    for flags in [5, 7] {
        let mut bytes = HEADER.to_vec();
        let start = section(&mut bytes, 9, &[1, flags, 0xff, 0, 0]) + 1;
        let end = bytes.len();
        let fixture = finish(bytes, Span { start, end });
        check(&fixture, |profile, module| {
            assert_eq!(fixture.entry, Span { start: 11, end: 15 });
            let path = "element[0]/undecoded";
            let carrier = at(module, path);
            assert_eq!(carrier.span, fixture.entry);
            assert_eq!(carrier.standard_support.status, "unknown");
            assert_eq!(carrier.feature.as_deref(), Some("unknown_declaration_type"));
            let flag_span = Span { start: 11, end: 12 };
            feature(profile, module, path, flag_span, "bulk_memory");
            feature(profile, module, path, flag_span, "reference_types");
            let unknown_type = at(module, "element[0]/undecoded/value_type_start");
            assert_eq!(unknown_type.span, Span { start: 12, end: 13 });
            assert_eq!(unknown_type.standard_support.status, "unknown");
            assert_eq!(&fixture.bytes[12..15], &[0xff, 0, 0]);
            assert!(!regions(module).iter().any(|region| {
                region.path.starts_with("element[0]/entry[")
                    || (region.path.starts_with("element[0]/undecoded/")
                        && region.path != unknown_type.path)
            }));
            assert!(!module.standard.evidence.iter().any(|evidence| {
                evidence.span.start >= 12
                    && evidence.span.start < 15
                    && evidence.status != "unknown"
            }));
        });
    }
    // Bit patterns have no authority until the complete discriminator is one
    // of the known 0..=7 forms. This one deliberately has every low bit set.
    let mut bytes = HEADER.to_vec();
    let start = section(&mut bytes, 9, &[1, 0x0f, 0xff, 0, 0]) + 1;
    let end = bytes.len();
    let fixture = finish(bytes, Span { start, end });
    check(&fixture, |_, module| {
        let path = "element[0]/undecoded";
        opaque(module, &fixture, path, 11, "unknown");
        no_feature(module, path, "bulk_memory");
        no_feature(module, path, "reference_types");
        assert!(!regions(module).iter().any(|region| {
            region.path.starts_with("element[0]/entry[")
                || region.path == "element[0]/undecoded/value_type_start"
        }));
    });
}
