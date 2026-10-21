//! Fixed declaration dependencies and incomplete prefixes; no generated search.
use wasm_git::{
    audit::{self, AuditModule, Region},
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

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    bytes.extend_from_slice(payload);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unknown(module: &AuditModule, path: &str) -> bool {
    module
        .standard
        .evidence
        .iter()
        .any(|entry| entry.path == path && entry.status == "unknown")
}

fn region<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    fn find<'a>(regions: &'a [Region], path: &str) -> Option<&'a Region> {
        for region in regions {
            if region.path == path {
                return Some(region);
            }
            if let Some(found) = find(&region.children, path) {
                return Some(found);
            }
        }
        None
    }
    module
        .sections
        .iter()
        .find_map(|section| find(&section.regions, path))
        .unwrap_or_else(|| panic!("missing physical region {path}"))
}

fn check(bytes: &[u8], mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(bytes, profile).unwrap();
        for evidence in &module.standard.evidence {
            assert!(evidence.span.start <= evidence.span.end && evidence.span.end <= bytes.len());
            assert_eq!(
                evidence.raw_hex,
                hex(&bytes[evidence.span.start..evidence.span.end])
            );
        }
        inspect(profile, &module);
        let edits = serde_json::to_vec(
            &audit::compare_with_standard(HEADER, bytes, profile)
                .unwrap()
                .edits,
        )
        .unwrap();
        if let Some(previous) = &expected_edits {
            assert_eq!(previous, &edits);
        } else {
            expected_edits = Some(edits);
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

fn code(bytes: &mut Vec<u8>, count: u8) {
    let mut payload = vec![count];
    for _ in 0..count {
        // locals=0; i32.const 42; drop; nop; end.
        payload.extend_from_slice(&[6, 0, 0x41, 42, 0x1a, 1, 0x0b]);
    }
    section(bytes, 10, &payload);
}

fn assert_mvp_tail(module: &AuditModule, bytes: &[u8], function: usize) {
    let constant = region(module, &format!("code[0]/function[{function}]/operator[0]"));
    assert_eq!(&bytes[constant.span.start..constant.span.end], &[0x41, 42]);
    assert_eq!(constant.standard_support.status, "supported");
    let nop = region(module, &format!("code[0]/function[{function}]/operator[2]"));
    assert_eq!(&bytes[nop.span.start..nop.span.end], &[1]);
    assert_eq!(nop.standard_support.status, "supported");
}

fn export(payload: &mut Vec<u8>, name: u8, kind: u8, index: u8) {
    payload.extend_from_slice(&[1, name, kind, index]);
}

#[test]
fn damaged_type_suffix_is_visible_in_declarations_start_exports_and_element_items() {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[2, 0x60, 0, 0, 0x7a]);
    section(&mut bytes, 3, &[2, 0, 1]);
    section(&mut bytes, 4, &[1, 0x70, 0, 2]);
    let mut exports = vec![2];
    export(&mut exports, b'a', 0, 0);
    export(&mut exports, b'b', 0, 1);
    section(&mut bytes, 7, &exports);
    section(&mut bytes, 8, &[1]);
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 2, 0, 1]);
    code(&mut bytes, 2);
    check(&bytes, |_, module| {
        for path in [
            "function[0]/entry[0]",
            "export[0]/entry[0]",
            "element[0]/entry[0]/item[0]",
            "code[0]/function[0]",
        ] {
            assert!(!unknown(module, path), "{path}");
        }
        for path in [
            "function[0]/entry[1]",
            "export[0]/entry[1]",
            "start[0]/value",
            "element[0]/entry[0]/item[1]",
            "code[0]/function[1]",
        ] {
            assert!(unknown(module, path), "{path}");
        }
        assert_mvp_tail(module, &bytes, 0);
        assert_mvp_tail(module, &bytes, 1);
    });
}

#[test]
fn damaged_import_suffix_preserves_each_known_index_space_and_marks_later_exports() {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    let imports = [
        5, // Five entries, only the first four have known grammar.
        0, 1, b'f', 0, 0, // function0, type0
        0, 1, b't', 1, 0x70, 0, 1, // table0
        0, 1, b'm', 2, 0, 1, // memory0
        0, 1, b'e', 4, 0, 0, // tag0, attribute0, type0
        0, 0, 0xff, // Unknown import kind, with known empty strings.
    ];
    section(&mut bytes, 2, &imports);
    let mut exports = vec![8];
    for (pair, kind) in [0, 1, 2, 4].into_iter().enumerate() {
        export(&mut exports, b'a' + pair as u8 * 2, kind, 0);
        export(&mut exports, b'b' + pair as u8 * 2, kind, 1);
    }
    section(&mut bytes, 7, &exports);
    check(&bytes, |_, module| {
        for pair in 0..4 {
            assert!(!unknown(module, &format!("export[0]/entry[{}]", pair * 2)));
            assert!(unknown(
                module,
                &format!("export[0]/entry[{}]", pair * 2 + 1)
            ));
        }
    });
}

#[test]
fn damaged_defined_function_suffix_keeps_imported_and_defined_prefixes_distinct() {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 2, &[1, 0, 1, b'f', 0, 0]);
    // One complete declaration, then a truncated type-index LEB.
    section(&mut bytes, 3, &[2, 0, 0x80]);
    let mut exports = vec![3];
    for index in 0..3 {
        export(&mut exports, b'a' + index, 0, index);
    }
    section(&mut bytes, 7, &exports);
    section(&mut bytes, 8, &[2]);
    code(&mut bytes, 2);
    check(&bytes, |_, module| {
        assert!(!unknown(module, "export[0]/entry[0]"));
        assert!(!unknown(module, "export[0]/entry[1]"));
        assert!(unknown(module, "export[0]/entry[2]"));
        assert!(unknown(module, "start[0]/value"));
        assert!(!unknown(module, "code[0]/function[0]"));
        assert!(unknown(module, "code[0]/function[1]"));
        assert_mvp_tail(module, &bytes, 1);
    });
}

#[test]
fn complete_out_of_bounds_indices_are_validator_errors_without_invented_unknown_grammar() {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[1, 9]);
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 0, 1]);
    section(&mut bytes, 13, &[1, 0, 0]);
    section(&mut bytes, 6, &[1, 0x7f, 0, 0x41, 0, 0x0b]);
    let mut exports = vec![5];
    for (name, kind) in [(b'f', 0), (b't', 1), (b'm', 2), (b'g', 3), (b'e', 4)] {
        export(&mut exports, name, kind, 9);
    }
    section(&mut bytes, 7, &exports);
    section(&mut bytes, 8, &[9]);
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 9]);
    code(&mut bytes, 1);
    assert!(Validator::new_with_features(WasmFeatures::all())
        .validate_all(&bytes)
        .is_err());
    check(&bytes, |_, module| {
        assert_eq!(module.standard.validation, "invalid");
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "unknown"));
        assert_mvp_tail(module, &bytes, 0);
    });
}

#[test]
fn constant_expression_global_use_is_rechecked_after_a_later_damaged_global() {
    for index in [0, 1] {
        let mut bytes = HEADER.to_vec();
        // global0 is complete even though its initializer is semantically
        // invalid; global1 has no recognized type or initializer boundary.
        section(&mut bytes, 6, &[2, 0x7f, 0, 0x23, index, 0x0b, 0x7a]);
        check(&bytes, |_, module| {
            let path = "global[0]/entry[0]/init/operator[0]";
            assert_eq!(unknown(module, path), index == 1);
            let op = region(module, path);
            assert_eq!(&bytes[op.span.start..op.span.end], &[0x23, index]);
        });
    }
}

fn partial_type_reference(definition: &[u8]) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    let mut types = vec![3, 0x60, 0, 0];
    types.extend_from_slice(definition);
    types.push(0x7a);
    section(&mut bytes, 1, &types);
    bytes
}

#[test]
fn forward_heap_references_in_function_array_and_struct_types_use_the_final_prefix() {
    for index in [0, 2] {
        for definition in [
            vec![0x60, 1, 0x63, index, 0], // function parameter
            vec![0x60, 0, 1, 0x63, index], // function result
            vec![0x5e, 0x63, index, 0],    // array field
            vec![0x5f, 1, 0x63, index, 0], // struct field
        ] {
            let bytes = partial_type_reference(&definition);
            check(&bytes, |_, module| {
                assert_eq!(unknown(module, "type[0]/type[1]"), index == 2);
                assert!(
                    module.standard.evidence.iter().any(|entry| {
                        entry.path == "type[0]/type[1]"
                            && entry.status == "unknown"
                            && entry.reason.contains("heap type index 2")
                    }) == (index == 2)
                );
            });
        }
    }
}

#[test]
fn subtype_descriptor_and_continuation_references_use_the_final_type_prefix() {
    for index in [0, 2] {
        for (definition, role) in [
            (vec![0x50, 1, index, 0x60, 0, 0], "supertype index"),
            (vec![0x4c, index, 0x5f, 0], "described type index"),
            (vec![0x4d, index, 0x5f, 0], "descriptor type index"),
            (vec![0x5d, index], "continuation function type index"),
        ] {
            let bytes = partial_type_reference(&definition);
            check(&bytes, |_, module| {
                assert_eq!(unknown(module, "type[0]/type[1]"), index == 2);
                assert_eq!(
                    module.standard.evidence.iter().any(|entry| {
                        entry.path == "type[0]/type[1]"
                            && entry.status == "unknown"
                            && entry.reason.contains(&format!("{role} 2"))
                    }),
                    index == 2,
                    "{role}"
                );
            });
        }
    }
}

#[test]
fn valid_recursive_forward_type_reference_is_never_reported_as_unknown() {
    let mut bytes = HEADER.to_vec();
    // One rec group: type0=(struct (field (ref null 1))), type1=(struct).
    section(&mut bytes, 1, &[1, 0x4e, 2, 0x5f, 1, 0x63, 1, 0, 0x5f, 0]);
    assert!(Validator::new_with_features(Standard::Core3.features())
        .validate_all(&bytes)
        .is_ok());
    check(&bytes, |profile, module| {
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "unknown"));
        assert_eq!(
            module.standard.validation,
            if matches!(profile, Standard::Core3 | Standard::AllKnown) {
                "valid"
            } else {
                "invalid"
            }
        );
    });
}
