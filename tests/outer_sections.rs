//! Fixed wire counterexamples; no generated mutations or Wasm execution.
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(raw: &str) -> Vec<u8> {
    let (pairs, rest) = raw.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    bytes.extend_from_slice(payload);
}
fn tail(bytes: &mut Vec<u8>, operators: &[u8]) {
    let mut body = vec![1, (operators.len() + 1) as u8, 0];
    body.extend_from_slice(operators);
    section(bytes, 10, &body);
}
fn declarations(bytes: &mut Vec<u8>) {
    section(bytes, 1, &[1, 0x60, 0, 0]);
    section(bytes, 3, &[1, 0]);
}
fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(entries: &'a [Region], all: &mut Vec<&'a Region>) {
        for entry in entries {
            all.push(entry);
            visit(&entry.children, all);
        }
    }
    let mut all = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut all);
    }
    all
}
fn check_raw(module: &AuditModule, bytes: &[u8]) {
    for entry in &module.standard.evidence {
        assert!(entry.span.start <= entry.span.end && entry.span.end <= bytes.len());
        assert_eq!(entry.raw_hex, hex(&bytes[entry.span.start..entry.span.end]));
    }
}
fn check_edits(bytes: &[u8]) {
    let mut expected = None;
    for profile in PROFILES {
        let diff = audit::compare_with_standard(HEADER, bytes, profile).unwrap();
        assert!(diff.changed && !diff.edits.is_empty());
        let actual = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &expected {
            assert_eq!(&actual, previous);
        } else {
            expected = Some(actual);
        }
    }
    for (old, new) in [(HEADER, bytes), (bytes, HEADER)] {
        let patch = wasm_git::patch::create(old, new).unwrap();
        let decoded = BytePatch::from_bytes(&patch.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded.apply(old).unwrap(), new);
    }
}

#[test]
fn invalid_section_lengths_are_binary_under_every_profile_and_id() {
    for id in [0, 1, 5, 10, 13, 14, 255] {
        for bad_size in [
            &[0x80][..],
            &[0x80, 0x80, 0x80, 0x80, 0x10],
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 4, 1, 0x60, 0, 0],
        ] {
            let bytes = [HEADER, &[id], bad_size].concat();
            assert!(Validator::new_with_features(WasmFeatures::all())
                .validate_all(&bytes)
                .is_err());
            for profile in PROFILES {
                let module = audit::inspect_with_standard(&bytes, profile).unwrap();
                check_raw(&module, &bytes);
                assert_eq!(module.sections.len(), 1);
                let first = &module.sections[0];
                assert_eq!(first.status, "malformed");
                assert_eq!(first.standard_support.status, "invalid_encoding");
                assert_eq!(first.standard_support.display, "binary");
                assert!(module
                    .standard
                    .evidence
                    .iter()
                    .any(|entry| entry.path == first.path && entry.status == "invalid_encoding"));
                assert!(!regions(&module).iter().any(
                    |entry| entry.path.contains("/operator[") || entry.path.contains("/type[")
                ));
            }
            check_edits(&bytes);
        }
    }
}

#[test]
fn truncated_outer_frame_never_supplies_a_complete_looking_payload_to_the_classifier() {
    for (id, payload) in [
        (1, &[1, 0x60, 0, 0][..]),
        (0, &[0][..]),
        (14, &[0x41, 0, 0x0b][..]),
    ] {
        let bytes = [HEADER, &[id, (payload.len() + 1) as u8], payload].concat();
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            check_raw(&module, &bytes);
            assert_eq!(module.standard.validation, "invalid");
            assert_eq!(
                module.sections[0].standard_support.status,
                "invalid_encoding"
            );
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.feature == "function_references"));
            assert!(!regions(&module)
                .iter()
                .any(|entry| entry.path.ends_with("/name")
                    || entry.path.contains("/type[")
                    || entry.path.contains("/operator[")));
        }
        check_edits(&bytes);
    }
}

#[test]
fn invalid_outer_custom_names_keep_next_framed_mvp_body_readable() {
    for payload in [
        &[][..],
        &[0x80],
        &[1, 0xff],
        &[5, b'a'],
        &[0x80, 0x80, 0x80, 0x80, 0x80, 0],
    ] {
        let mut bytes = HEADER.to_vec();
        section(&mut bytes, 0, payload);
        declarations(&mut bytes);
        tail(&mut bytes, &[0x41, 1, 0x1a, 0x0b]);
        assert!(Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .is_err());
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            check_raw(&module, &bytes);
            assert_eq!(
                module.sections[0].standard_support.status,
                "invalid_encoding"
            );
            let outer = regions(&module)
                .into_iter()
                .find(|region| region.path == "custom[0]/outer_name")
                .unwrap();
            assert_eq!(outer.standard_support.status, "invalid_encoding");
            assert_eq!(&bytes[outer.span.start..outer.span.end], payload);
            let all = regions(&module);
            let constant = all
                .iter()
                .find(|region| region.path == "code[0]/function[0]/operator[0]")
                .unwrap();
            assert_eq!(constant.description, "I32Const { value: 1 }");
            assert_eq!(constant.standard_support.status, "supported");
        }
        check_edits(&bytes);
    }
}

#[test]
fn legal_outer_names_and_noncanonical_conventions_remain_core_valid() {
    for payload in [
        &[0][..],
        &[0x80, 0x80, 0x80, 0x80, 0, 0xaa],
        &[4, b'n', b'a', b'm', b'e', 0xff],
        &[8, b'o', b'r', b'd', b'e', b'r', b'i', b'n', b'g', 0xff],
    ] {
        let mut bytes = HEADER.to_vec();
        section(&mut bytes, 0, payload);
        declarations(&mut bytes);
        tail(&mut bytes, &[0x41, 1, 0x1a, 0x0b]);
        assert!(Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .is_ok());
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            assert_eq!(module.standard.validation, "valid");
            assert_eq!(module.sections[0].status, "opaque");
            assert!(module
                .standard
                .evidence
                .iter()
                .all(|entry| entry.status == "supported"));
        }
    }
}

#[test]
fn late_imports_withdraw_combined_index_inference_but_preserve_operator_boundaries() {
    let cases: &[(&[u8], &[u8], &[u8])] = &[
        (
            &[5, 3, 1, 0, 1],
            &[1, 1, b'm', 1, b'x', 2, 4, 1],
            &[0x3f, 0, 0x1a, 0x0b],
        ),
        (
            &[4, 4, 1, 0x70, 0, 1],
            &[1, 1, b'm', 1, b'x', 1, 0x70, 4, 1],
            &[0xfc, 0x10, 0, 0x1a, 0x0b],
        ),
        (
            &[6, 6, 1, 0x7f, 0, 0x41, 0, 0x0b],
            &[1, 1, b'm', 1, b'x', 3, 0x7e, 0],
            &[0x23, 0, 0x1a, 0x0b],
        ),
        (&[], &[1, 1, b'm', 1, b'x', 0, 0], &[0x10, 0, 0x0b]),
    ];
    for (defined, import, operators) in cases {
        let mut bytes = HEADER.to_vec();
        declarations(&mut bytes);
        bytes.extend_from_slice(defined);
        section(&mut bytes, 2, import);
        tail(&mut bytes, operators);
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            check_raw(&module, &bytes);
            assert_eq!(module.standard.validation, "invalid");
            assert!(module
                .diagnostics
                .iter()
                .any(|entry| entry.code == "section_order"));
            assert!(module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.path == "code[0]/function[0]/operator[0]"
                    && entry.status == "unknown"));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.path == "code[0]/function[0]/operator[0]"
                    && entry.feature == "memory64"));
            let all = regions(&module);
            let body = all
                .iter()
                .find(|entry| entry.path == "code[0]/function[0]")
                .unwrap();
            assert!(body.description.contains("function_index=unknown"));
            let end = all
                .iter()
                .find(|entry| {
                    entry.path.ends_with(&format!(
                        "/operator[{}]",
                        if operators[0] == 0x10 { 1 } else { 2 }
                    ))
                })
                .unwrap();
            assert_eq!(end.description, "End");
            assert_eq!(end.standard_support.status, "supported");
        }
        check_edits(&bytes);
    }
}

#[test]
fn import_after_code_retracts_earlier_combined_function_index() {
    let mut bytes = HEADER.to_vec();
    declarations(&mut bytes);
    tail(&mut bytes, &[0x10, 0, 0x0b]);
    section(&mut bytes, 2, &[1, 1, b'm', 1, b'x', 0, 0]);
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&bytes, profile).unwrap();
        let all = regions(&module);
        let body = all
            .iter()
            .find(|entry| entry.path == "code[0]/function[0]")
            .unwrap();
        assert!(body.description.contains("function_index=unknown"));
        assert!(module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.path == "code[0]/function[0]/operator[0]"
                && entry.status == "unknown"));
    }
}

#[test]
fn global_export_does_not_infer_mutability_from_an_untrusted_combined_map() {
    let invalid = unhex("0061736d010000000606017f0041000b020801016d0178037f0107050101670300");
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&invalid, profile).unwrap();
        assert!(module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.path == "export[0]/entry[0]"
                && entry.status == "unknown"
                && entry.kind == "structure"));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.path == "export[0]/entry[0]" && entry.feature == "mutable_global"));
    }
    // The same declarations in valid order still prove mutable global export.
    let valid = unhex("0061736d01000000020801016d0178037f010606017f0041000b07050101670300");
    assert!(Validator::new_with_features(WasmFeatures::all())
        .validate_all(&valid)
        .is_ok());
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&valid, profile).unwrap();
        assert_eq!(module.standard.validation, "valid");
        assert!(module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.path == "export[0]/entry[0]"
                && entry.feature == "mutable_global"
                && entry.status == "supported"));
    }
}

#[test]
fn unreadable_late_import_still_retracts_prior_index_assumptions() {
    for suffix in [&[2, 0x80][..], &[2, 2, 1][..]] {
        let mut bytes = HEADER.to_vec();
        declarations(&mut bytes);
        tail(&mut bytes, &[0x10, 0, 0x0b]);
        bytes.extend_from_slice(suffix);
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            check_raw(&module, &bytes);
            assert!(module
                .diagnostics
                .iter()
                .any(|entry| entry.code == "section_order"));
            assert!(module
                .diagnostics
                .iter()
                .any(|entry| entry.code == "section_framing"));
            assert_eq!(
                module.sections.last().unwrap().standard_support.status,
                "invalid_encoding"
            );
            let all = regions(&module);
            let body = all
                .iter()
                .find(|entry| entry.path == "code[0]/function[0]")
                .unwrap();
            assert!(body.description.contains("function_index=unknown"));
            assert!(module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.path == "code[0]/function[0]/operator[0]"
                    && entry.status == "unknown"));
        }
        check_edits(&bytes);
    }
}

#[test]
fn duplicates_invalidate_index_maps_and_normative_tag_data_count_order_is_accepted() {
    for repeated in [1, 2, 3, 4, 5, 6, 10] {
        let mut bytes = HEADER.to_vec();
        if repeated == 1 {
            section(&mut bytes, 1, &[1, 0x60, 0, 0]);
        }
        declarations(&mut bytes);
        if repeated == 2 {
            section(&mut bytes, 2, &[0]);
        }
        if repeated != 1 && repeated != 10 {
            section(
                &mut bytes,
                repeated,
                if repeated == 3 { &[1, 0] } else { &[0] },
            );
        }
        tail(&mut bytes, &[0x10, 0, 0x0b]);
        if repeated == 10 {
            tail(&mut bytes, &[0x10, 0, 0x0b]);
        }
        // A duplicate after code is both repeated and outside its allowed rank.
        if matches!(repeated, 4..=6) {
            section(&mut bytes, repeated, &[0]);
        }
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            assert!(module
                .diagnostics
                .iter()
                .any(|entry| entry.code == "section_duplicate"));
            if matches!(repeated, 2 | 3 | 10) {
                for body in regions(&module)
                    .into_iter()
                    .filter(|region| region.description.starts_with("function_index="))
                {
                    assert!(body.description.starts_with("function_index=unknown "));
                }
            }
            assert!(module.sections.iter().any(|section| section
                .regions
                .iter()
                .any(|entry| entry.path.ends_with("/ordering"))
                && section.standard_support.status == "invalid_encoding"));
        }
    }
    let mut bytes = HEADER.to_vec();
    for id in [1, 2, 3, 4, 5, 13, 6, 7, 9, 12, 10, 11] {
        section(&mut bytes, 0, &[0]);
        section(&mut bytes, id, &[0]);
    }
    assert!(Validator::new_with_features(WasmFeatures::all())
        .validate_all(&bytes)
        .is_ok());
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&bytes, profile).unwrap();
        assert!(!module
            .diagnostics
            .iter()
            .any(|entry| matches!(entry.code.as_str(), "section_order" | "section_duplicate")));
        if matches!(profile, Standard::Core3 | Standard::AllKnown) {
            assert_eq!(module.standard.validation, "valid");
        }
    }
    // The independent literal late-import counterexample is kept verbatim.
    let bytes = unhex(
        "0061736d01000000010401600000030201000503010001020801016d01780204010a070105003f001a0b",
    );
    let module = audit::inspect_with_standard(&bytes, Standard::Core3).unwrap();
    assert!(module
        .standard
        .evidence
        .iter()
        .any(|e| e.path == "code[0]/function[0]/operator[0]"
            && e.status == "unknown"
            && e.raw_hex == "3f00"));
    assert!(module
        .to_text()
        .contains("binary (unknown requirements or index context"));
    assert!(!module.to_text().contains("recognized grammar is disabled"));
    // A controlled memory index change must retain the same honest explanation
    // in diff's per-edit contexts, rather than calling Core3 grammar disabled.
    let mut index_one = bytes.clone();
    index_one[39] = 1;
    let diff = audit::compare_with_standard(&bytes, &index_one, Standard::Core3).unwrap();
    assert_eq!(diff.edits.len(), 1);
    assert!(diff
        .to_text()
        .contains("binary (unknown requirements or index context"));
    assert!(!diff.to_text().contains("recognized grammar is disabled"));
}
