//! Fixed tag namespace and catch/handler operands; no generated mutation search.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};
use wasmparser::{Validator, WasmFeatures};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];
const FUNCTION_TYPE: &[u8] = &[1, 0x60, 0, 0];
const FUNCTION_AND_CONT: &[u8] = &[2, 0x60, 0, 0, 0x5d, 0];
const PARTIAL_TYPES: &[u8] = &[2, 0x60, 0, 0, 0x7a];
const TAG_IMPORT: &[u8] = &[1, 1, b'm', 1, b't', 4, 0, 0];
const PARTIAL_IMPORTS: &[u8] = &[2, 1, b'm', 1, b't', 4, 0, 0, 1, b'm', 1, b'u', 4, 1, 0];
// Tag0 is complete; the second tag's attribute 1 is not recognized.
const PARTIAL_TAGS: &[u8] = &[2, 0, 0, 1, 0];
const SENTINEL: &[u8] = &[0x41, 42, 0x1a, 1];

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    bytes.extend_from_slice(payload);
}

fn declarations(types: &[u8], imports: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, types);
    if let Some(imports) = imports {
        section(&mut bytes, 2, imports);
    }
    section(&mut bytes, 3, &[1, 0]);
    bytes
}

fn target_body(
    bytes: &mut Vec<u8>,
    prefix: &[u8],
    instruction: &[u8],
    close_frames: &[u8],
) -> (Span, Span) {
    let mut operators = prefix.to_vec();
    operators.extend_from_slice(instruction);
    operators.extend_from_slice(close_frames);
    operators.extend_from_slice(SENTINEL);
    operators.push(0x0b);
    let mut payload = vec![1, (operators.len() + 1) as u8, 0];
    payload.extend_from_slice(&operators);
    // Section id/size, body count/size, and locals count are all one byte.
    let target_start = bytes.len() + 5 + prefix.len();
    let sentinel_start = target_start + instruction.len() + close_frames.len();
    section(bytes, 10, &payload);
    (
        Span {
            start: target_start,
            end: target_start + instruction.len(),
        },
        Span {
            start: sentinel_start,
            end: sentinel_start + 2,
        },
    )
}

fn region_at(module: &AuditModule, span: Span) -> &Region {
    fn find(regions: &[Region], span: Span) -> Option<&Region> {
        for region in regions {
            if region.span == span && region.path.contains("/operator[") {
                return Some(region);
            }
            if let Some(found) = find(&region.children, span) {
                return Some(found);
            }
        }
        None
    }
    module
        .sections
        .iter()
        .find_map(|section| find(&section.regions, span))
        .unwrap()
}

fn assert_raw(module: &AuditModule, bytes: &[u8]) {
    for evidence in &module.standard.evidence {
        let span = evidence.span;
        assert!(span.start <= span.end && span.end <= bytes.len());
        let hex: String = bytes[span.start..span.end]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(evidence.raw_hex, hex);
    }
}

fn check_target(bytes: &[u8], target: Span, sentinel: Span, reasons: &[&str]) {
    for profile in PROFILES {
        let module = audit::inspect_with_standard(bytes, profile).unwrap();
        assert_raw(&module, bytes);
        let target_region = region_at(&module, target);
        let unknown: Vec<_> = module
            .standard
            .evidence
            .iter()
            .filter(|entry| entry.path == target_region.path && entry.status == "unknown")
            .collect();
        assert_eq!(unknown.len(), reasons.len(), "{profile}: {unknown:?}");
        for reason in reasons {
            assert!(
                unknown.iter().any(|entry| entry.reason.contains(reason)),
                "{profile}: missing {reason:?} in {unknown:?}"
            );
        }
        let following = region_at(&module, sentinel);
        assert_eq!(following.description, "I32Const { value: 42 }");
        assert_eq!(following.standard_support.status, "supported");
        assert_eq!(
            &bytes[following.span.start..following.span.end],
            &[0x41, 42]
        );
    }
}

fn replay(bytes: &[u8]) {
    let mut expected = None;
    for profile in PROFILES {
        let edits = serde_json::to_vec(
            &audit::compare_with_standard(HEADER, bytes, profile)
                .unwrap()
                .edits,
        )
        .unwrap();
        if let Some(previous) = &expected {
            assert_eq!(previous, &edits);
        } else {
            expected = Some(edits);
        }
    }
    for (old, new) in [(HEADER, bytes), (bytes, HEADER)] {
        let patch = wasm_git::patch::create(old, new).unwrap();
        assert_eq!(
            BytePatch::from_bytes(&patch.to_bytes().unwrap())
                .unwrap()
                .apply(old)
                .unwrap(),
            new
        );
    }
}

#[test]
fn partial_tag_and_import_prefixes_preserve_known_throw_suspend_and_catch_operands() {
    for imported in [false, true] {
        for index in [0, 1] {
            for operation in ["throw", "suspend", "legacy catch"] {
                let mut bytes = declarations(FUNCTION_TYPE, imported.then_some(PARTIAL_IMPORTS));
                if !imported {
                    section(&mut bytes, 13, PARTIAL_TAGS);
                }
                let (prefix, instruction, close): (&[u8], Vec<u8>, &[u8]) = match operation {
                    "throw" => (&[0], vec![0x08, index], &[]),
                    "suspend" => (&[0], vec![0xe2, index], &[]),
                    _ => (&[0x06, 0x40, 0], vec![0x07, index], &[0x0b]),
                };
                let (target, sentinel) = target_body(&mut bytes, prefix, &instruction, close);
                let reasons: &[&str] = if index == 1 {
                    &["tag index 1 lies beyond the complete tag/import declaration prefix"]
                } else {
                    &[]
                };
                check_target(&bytes, target, sentinel, reasons);
                replay(&bytes);
            }
        }
    }
}

#[test]
fn try_table_tag_operands_are_distinct_from_all_four_catch_label_operands() {
    for kind in [0, 1, 2, 3] {
        for tag in [0, 1] {
            let mut bytes = declarations(FUNCTION_TYPE, None);
            section(&mut bytes, 13, PARTIAL_TAGS);
            let mut instruction = vec![0x1f, 0x40, 1, kind];
            if kind <= 1 {
                instruction.push(tag);
            }
            // Label 1 is not a tag index. The outer block and implicit
            // function provide two label depths; catch_ref typing is left to
            // the module validator, separate from namespace availability.
            instruction.push(1);
            let (target, sentinel) =
                target_body(&mut bytes, &[0x02, 0x40, 0], &instruction, &[0x0b, 0x0b]);
            let reasons: &[&str] = if kind <= 1 && tag == 1 {
                &["try_table catch[0] tag index 1 lies beyond"]
            } else {
                &[]
            };
            check_target(&bytes, target, sentinel, reasons);
            replay(&bytes);
        }
    }
}

#[test]
fn resume_handlers_and_direct_resume_throw_switch_tags_keep_separate_dependencies() {
    for index in [0, 1] {
        let cases: &[(&[u8], &[&str])] = &[
            (
                &[0xe3, 1, 1, 0, index, 42],
                if index == 1 {
                    &["resume handler[0] tag index 1 lies beyond"]
                } else {
                    &[]
                },
            ),
            (
                &[0xe3, 1, 1, 1, index],
                if index == 1 {
                    &["resume handler[0] tag index 1 lies beyond"]
                } else {
                    &[]
                },
            ),
            (
                &[0xe4, 1, index, 1, 0, index, 42],
                if index == 1 {
                    &[
                        "tag index 1 lies beyond",
                        "resume handler[0] tag index 1 lies beyond",
                    ]
                } else {
                    &[]
                },
            ),
            (
                &[0xe5, 1, 1, 1, index],
                if index == 1 {
                    &["resume handler[0] tag index 1 lies beyond"]
                } else {
                    &[]
                },
            ),
            (
                &[0xe6, 1, index],
                if index == 1 {
                    &["tag index 1 lies beyond"]
                } else {
                    &[]
                },
            ),
        ];
        for (instruction, reasons) in cases {
            let mut bytes = declarations(FUNCTION_AND_CONT, None);
            section(&mut bytes, 13, PARTIAL_TAGS);
            let (target, sentinel) = target_body(&mut bytes, &[0], instruction, &[]);
            check_target(&bytes, target, sentinel, reasons);
            replay(&bytes);
        }
    }
}

#[test]
fn a_known_tag_still_checks_an_unavailable_signature_type_at_uses_and_exports() {
    let mut bytes = declarations(PARTIAL_TYPES, None);
    section(&mut bytes, 13, &[1, 0, 1]);
    section(&mut bytes, 7, &[1, 1, b't', 4, 0]);
    let (target, sentinel) = target_body(&mut bytes, &[0], &[0x08, 0], &[]);
    check_target(
        &bytes,
        target,
        sentinel,
        &["tag index 0 signature type index 1 lies beyond"],
    );
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&bytes, profile).unwrap();
        assert!(module.standard.evidence.iter().any(|entry| {
            entry.path == "export[0]/entry[0]"
                && entry.status == "unknown"
                && entry
                    .reason
                    .contains("exported tag index 0 signature type index 1 lies beyond")
        }));
    }
    replay(&bytes);
}

#[test]
fn repeated_or_late_tag_and_import_sections_withdraw_prior_tag_index_inference() {
    for layout in [
        "duplicate tags",
        "late tags",
        "late import",
        "duplicate imports",
    ] {
        let mut bytes = declarations(
            FUNCTION_TYPE,
            (layout == "duplicate imports").then_some(TAG_IMPORT),
        );
        if layout != "late tags" {
            section(&mut bytes, 13, &[1, 0, 0]);
        }
        if layout == "duplicate tags" {
            section(&mut bytes, 13, &[1, 0, 0]);
        }
        if layout == "duplicate imports" {
            section(&mut bytes, 2, TAG_IMPORT);
        }
        let (target, sentinel) = target_body(&mut bytes, &[0], &[0x08, 0], &[]);
        if layout == "late import" {
            section(&mut bytes, 2, TAG_IMPORT);
        }
        if layout == "late tags" {
            section(&mut bytes, 13, &[1, 0, 0]);
        }
        check_target(
            &bytes,
            target,
            sentinel,
            &["tag index 0 lies beyond the complete tag/import declaration prefix"],
        );
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            assert_eq!(module.standard.validation, "invalid");
            assert!(module
                .diagnostics
                .iter()
                .any(|entry| matches!(entry.code.as_str(), "section_duplicate" | "section_order")));
        }
        replay(&bytes);
    }
}

#[test]
fn a_complete_combined_tag_namespace_leaves_out_of_range_indices_to_the_validator() {
    for index in [0, 1, 2] {
        let mut bytes = declarations(FUNCTION_TYPE, Some(TAG_IMPORT));
        section(&mut bytes, 13, &[1, 0, 0]);
        let (target, sentinel) = target_body(&mut bytes, &[0], &[0x08, index], &[]);
        check_target(&bytes, target, sentinel, &[]);
        assert_eq!(
            Validator::new_with_features(WasmFeatures::all())
                .validate_all(&bytes)
                .is_ok(),
            index < 2
        );
        for profile in [Standard::Core3, Standard::AllKnown] {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            assert_eq!(
                module.standard.validation,
                if index < 2 { "valid" } else { "invalid" }
            );
        }
        replay(&bytes);
    }
}
