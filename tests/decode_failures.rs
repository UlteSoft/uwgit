//! Fixed malformed encodings and unknown-grammar controls; no mutation search.
use wasm_git::{
    audit::{self, AuditModule, Region},
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

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    bytes.extend_from_slice(payload);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn module(first: &[u8]) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[2, 0, 0]);
    let mut code = vec![2, first.len() as u8];
    code.extend_from_slice(first);
    code.extend_from_slice(&[5, 0, 0x41, 42, 0x1a, 0x0b]);
    section(&mut bytes, 10, &code);
    section(&mut bytes, 0, &[1, b'x', 0xaa]);
    bytes
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(entries: &'a [Region], output: &mut Vec<&'a Region>) {
        for entry in entries {
            output.push(entry);
            visit(&entry.children, output);
        }
    }
    let mut all = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut all);
    }
    all
}

fn check(bytes: &[u8], mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected = None;
    for standard in PROFILES {
        let module = audit::inspect_with_standard(bytes, standard).unwrap();
        assert_eq!(module.standard.validation, "invalid");
        for entry in &module.standard.evidence {
            assert!(entry.span.start <= entry.span.end && entry.span.end <= bytes.len());
            assert_eq!(entry.raw_hex, hex(&bytes[entry.span.start..entry.span.end]));
        }
        inspect(standard, &module);
        let edits = serde_json::to_vec(
            &audit::compare_with_standard(HEADER, bytes, standard)
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

fn later_body(module: &AuditModule, bytes: &[u8], index: usize) {
    let path = format!("code[0]/function[{index}]/operator[0]");
    let all = regions(module);
    let sentinel = all.iter().find(|entry| entry.path == path).unwrap();
    assert_eq!(&bytes[sentinel.span.start..sentinel.span.end], &[0x41, 42]);
    assert_eq!(sentinel.standard_support.status, "supported");
    assert!(module.sections.iter().any(|entry| entry.id == 0));
}

fn failure_suffix(module: &AuditModule, path: &str, raw: &[u8], status: &str) {
    let entry = module
        .standard
        .evidence
        .iter()
        .find(|entry| entry.path == path && entry.status == status)
        .unwrap_or_else(|| panic!("missing failure evidence {path}"));
    assert_eq!(entry.status, status);
    assert_eq!(entry.raw_hex, hex(raw));
    let all = regions(module);
    let physical = all.iter().find(|region| region.path == path).unwrap();
    assert_eq!(physical.span, entry.span);
    assert_eq!(physical.standard_support.status, status);
    assert!(!all.iter().any(|region| {
        region.path.starts_with(path.rsplit_once('/').unwrap().0)
            && region.path.contains("/operator[")
            && region.span.start >= entry.span.start
    }));
}

#[test]
fn control_delimiters_outside_their_known_frames_are_invalid_not_future_opcodes() {
    for operators in [
        vec![0x05, 0x41, 42, 0x1a, 0x0b],    // else outside if
        vec![0x07, 0, 0x41, 42, 0x1a, 0x0b], // catch outside legacy try
        vec![0x19, 0x41, 42, 0x1a, 0x0b],    // catch_all outside legacy try
        vec![0x18, 0, 0x41, 42, 0x1a, 0x0b], // delegate outside legacy try
    ] {
        let mut first = vec![0];
        first.extend_from_slice(&operators);
        let bytes = module(&first);
        check(&bytes, |_, module| {
            failure_suffix(
                module,
                "code[0]/function[0]/opaque",
                &operators,
                "invalid_encoding",
            );
            assert!(!module.standard.evidence.iter().any(|entry| entry.path
                == "code[0]/function[0]/opaque"
                && entry.status == "unknown"));
            later_body(module, &bytes, 1);
        });
    }
}

#[test]
fn duplicate_else_retains_the_known_control_prefix_and_an_opaque_invalid_suffix() {
    let first = [
        0, 0x41, 0, 0x04, 0x40, 0x05, 0x05, 0x41, 42, 0x1a, 0x0b, 0x0b,
    ];
    let bytes = module(&first);
    check(&bytes, |_, module| {
        failure_suffix(
            module,
            "code[0]/function[0]/opaque",
            &first[6..],
            "invalid_encoding",
        );
        let all = regions(module);
        let valid_else = all
            .iter()
            .find(|entry| entry.path == "code[0]/function[0]/operator[2]")
            .unwrap();
        assert_eq!(&bytes[valid_else.span.start..valid_else.span.end], &[0x05]);
        assert_eq!(valid_else.standard_support.status, "supported");
        later_body(module, &bytes, 1);
    });
}

#[test]
fn truncated_known_immediates_and_overflowing_leb_encodings_are_invalid() {
    for operators in [
        vec![0x41, 0x80],                         // i32.const
        vec![0x42, 0x80],                         // i64.const
        vec![0x43, 1, 2, 3],                      // f32.const, only three payload bytes
        vec![0x44, 1, 2, 3, 4, 5, 6, 7],          // f64.const
        vec![0xfd, 0x0c, 0, 0, 0],                // v128.const, only three payload bytes
        vec![0x10, 0x80],                         // call function index
        vec![0x41, 0x80, 0x80, 0x80, 0x80, 0x80], // i32 LEB too long
        vec![
            0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        ], // i64 LEB too long
        vec![0x02, 0x80, 0x80, 0x80, 0x80, 0x80], // s33 block type too long
        vec![
            0x28, 0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        ], // u64 memarg offset too long
        vec![0x20, 0xff, 0xff, 0xff, 0xff, 0x1f], // u32 index too large
        vec![0xfd, 0x80, 0x80, 0x80, 0x80, 0x80], // subopcode LEB too long
    ] {
        let mut first = vec![0];
        first.extend_from_slice(&operators);
        let bytes = module(&first);
        check(&bytes, |_, module| {
            failure_suffix(
                module,
                "code[0]/function[0]/opaque",
                &operators,
                "invalid_encoding",
            );
            later_body(module, &bytes, 1);
        });
    }
    // Unknown opcodes and unknown value-type grammar must retain that status;
    // a decoder error alone does not prove an intrinsically malformed encoding.
    for operators in [
        vec![0xff, 0x41, 42, 0x0b],
        vec![0xfd, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x41, 42, 0x0b],
        vec![0x1c, 1, 0x7a, 0x41, 42, 0x0b],
    ] {
        let mut first = vec![0];
        first.extend_from_slice(&operators);
        let bytes = module(&first);
        check(&bytes, |_, module| {
            failure_suffix(module, "code[0]/function[0]/opaque", &operators, "unknown");
            later_body(module, &bytes, 1);
        });
    }
}

#[test]
fn truncated_locals_counts_do_not_erase_the_next_body_frame() {
    for (first, suffix) in [
        (&[][..], &[][..]),
        (&[0x80][..], &[0x80][..]),
        (&[1, 0x80][..], &[0x80][..]),
        (&[1, 1][..], &[1][..]),
        (
            &[0x80, 0x80, 0x80, 0x80, 0x80][..],
            &[0x80, 0x80, 0x80, 0x80, 0x80][..],
        ),
    ] {
        let bytes = module(first);
        check(&bytes, |_, module| {
            failure_suffix(
                module,
                "code[0]/function[0]/opaque",
                suffix,
                "invalid_encoding",
            );
            later_body(module, &bytes, 1);
        });
    }
    // Here no complete body range exists. The next section is independently
    // framed, but no body or operator boundary may be invented inside code.
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[1, 0]);
    section(&mut bytes, 10, &[1, 2, 0]);
    section(&mut bytes, 0, &[1, b'x', 0xaa]);
    check(&bytes, |_, module| {
        failure_suffix(module, "code[0]/undecoded", &[2, 0], "invalid_encoding");
        assert!(!regions(module)
            .iter()
            .any(|region| region.path.contains("/operator[")));
        assert!(module.sections.iter().any(|section| section.id == 0));
    });
}

#[test]
fn missing_and_extra_end_keep_existing_exact_structure_boundaries() {
    for (first, suffix, raw) in [
        (&[0, 1][..], "expression_structure", &[][..]),
        (&[0, 0x02, 0x40, 0x0b][..], "expression_structure", &[][..]),
        (&[0, 0x0b, 0x0b][..], "trailing_bytes", &[0x0b][..]),
    ] {
        let bytes = module(first);
        check(&bytes, |_, module| {
            let path = format!("code[0]/function[0]/{suffix}");
            failure_suffix(module, &path, raw, "invalid_encoding");
            later_body(module, &bytes, 1);
        });
    }
}

#[test]
fn recovered_constant_expression_prefixes_classify_known_truncation_in_each_context() {
    for (id, payload, path, prefix) in [
        (
            6,
            vec![1, 0x7f, 0, 0x41, 0, 0x41, 0x80],
            "global[0]/entry[0]/init",
            vec![0x41, 0],
        ),
        (
            4,
            vec![1, 0x40, 0, 0x70, 0, 1, 0xd0, 0x70, 0x41, 0x80],
            "table[0]/entry[0]/init",
            vec![0xd0, 0x70],
        ),
        (
            9,
            vec![1, 0, 0x41, 0, 0x41, 0x80],
            "element[0]/entry[0]/offset",
            vec![0x41, 0],
        ),
        (
            11,
            vec![1, 0, 0x41, 0, 0x41, 0x80],
            "data[0]/entry[0]/offset",
            vec![0x41, 0],
        ),
    ] {
        let mut bytes = HEADER.to_vec();
        section(&mut bytes, 1, &[1, 0x60, 0, 0]);
        section(&mut bytes, 3, &[1, 0]);
        if id == 9 {
            section(&mut bytes, 4, &[1, 0x70, 0, 1]);
        }
        if id == 11 {
            section(&mut bytes, 5, &[1, 0, 1]);
            section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
        }
        section(&mut bytes, id, &payload);
        if id != 11 {
            section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
        }
        section(&mut bytes, 0, &[1, b'x', 0xaa]);
        check(&bytes, |_, module| {
            let error = format!("{path}/opaque");
            failure_suffix(module, &error, &[0x41, 0x80], "invalid_encoding");
            let first = format!("{path}/operator[0]");
            let all = regions(module);
            let recognized = all.iter().find(|region| region.path == first).unwrap();
            assert_eq!(
                &bytes[recognized.span.start..recognized.span.end],
                prefix.as_slice()
            );
            assert_ne!(recognized.standard_support.status, "unknown");
            assert_ne!(recognized.standard_support.status, "invalid_encoding");
            later_body(module, &bytes, 0);
        });
    }
}

#[test]
fn unknown_value_type_prefixes_never_authorize_later_field_or_expression_boundaries() {
    fn unknown_suffix(module: &AuditModule, path: &str, raw: &[u8]) {
        failure_suffix(module, path, raw, "unknown");
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| { entry.path == path && entry.status == "invalid_encoding" }));
    }

    // FF is an unknown value-type constructor. The permissive pinned reader
    // may consume FF 00 as a concrete heap index, but that cannot prove the
    // following bytes are another count or type field.
    for (first, opaque_start) in [
        (vec![1, 1, 0xff], 1),
        (vec![2, 1, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10], 1),
        (
            vec![3, 1, 0x7f, 1, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
            3,
        ),
    ] {
        let bytes = module(&first);
        check(&bytes, |_, module| {
            unknown_suffix(module, "code[0]/function[0]/opaque", &first[opaque_start..]);
            if opaque_start == 3 {
                let all = regions(module);
                let known = all
                    .iter()
                    .find(|region| region.path == "code[0]/function[0]/local_group[0]")
                    .unwrap();
                assert_eq!(&bytes[known.span.start..known.span.end], &[1, 0x7f]);
                assert_eq!(known.standard_support.status, "supported");
            }
            later_body(module, &bytes, 1);
        });
    }

    for operators in [
        vec![0x1c, 1, 0xff],
        vec![0x1c, 2, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10],
    ] {
        let mut first = vec![0];
        first.extend_from_slice(&operators);
        let bytes = module(&first);
        check(&bytes, |_, module| {
            unknown_suffix(module, "code[0]/function[0]/opaque", &operators);
            later_body(module, &bytes, 1);
        });
    }

    for (types, failed_start) in [
        (vec![1, 0x60, 1, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10], 1),
        (
            vec![
                2, 0x60, 0, 0, 0x60, 1, 0xff, 0, 0x80, 0x80, 0x80, 0x80, 0x10,
            ],
            4,
        ),
    ] {
        let mut bytes = HEADER.to_vec();
        section(&mut bytes, 1, &types);
        section(&mut bytes, 3, &[1, 0]);
        section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
        section(&mut bytes, 0, &[1, b'x', 0xaa]);
        check(&bytes, |_, module| {
            unknown_suffix(module, "type[0]/undecoded", &types[failed_start..]);
            if failed_start == 4 {
                assert!(regions(module)
                    .iter()
                    .any(|region| region.path == "type[0]/type[0]"));
            }
            later_body(module, &bytes, 0);
        });
    }

    for (id, known, unknown, type_prefix_len, path, prefix_operator) in [
        (
            6,
            vec![0x7f, 0, 0x41, 0, 0x0b],
            vec![0xff, 0, 0, 0x41, 42, 0x41, 0x80],
            1,
            "global[0]",
            Some("global[0]/entry[0]/init/operator[0]"),
        ),
        (
            4,
            vec![0x70, 0, 1],
            vec![0x40, 0, 0xff, 0, 0, 1, 0x41, 42, 0x41, 0x80],
            3,
            "table[0]",
            None,
        ),
        (
            9,
            vec![0, 0x41, 0, 0x0b, 0],
            vec![5, 0xff, 0, 1, 0x41, 42, 0x41, 0x80],
            2,
            "element[0]",
            Some("element[0]/entry[0]/offset/operator[0]"),
        ),
    ] {
        for unknown in [&unknown[..type_prefix_len], unknown.as_slice()] {
            let mut bytes = HEADER.to_vec();
            section(&mut bytes, 1, &[1, 0x60, 0, 0]);
            section(&mut bytes, 3, &[1, 0]);
            if id == 9 {
                section(&mut bytes, 4, &[1, 0x70, 0, 1]);
            }
            let mut payload = vec![2];
            payload.extend_from_slice(&known);
            payload.extend_from_slice(unknown);
            section(&mut bytes, id, &payload);
            section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
            section(&mut bytes, 0, &[1, b'x', 0xaa]);
            check(&bytes, |_, module| {
                unknown_suffix(module, &format!("{path}/undecoded"), unknown);
                let all = regions(module);
                assert!(all
                    .iter()
                    .any(|region| region.path == format!("{path}/entry[0]")));
                assert!(!all.iter().any(|region| {
                    region.path.starts_with(&format!("{path}/entry[1]"))
                        && region.path.contains("/operator[")
                }));
                if let Some(prefix) = prefix_operator {
                    let known = all.iter().find(|region| region.path == prefix).unwrap();
                    assert_eq!(&bytes[known.span.start..known.span.end], &[0x41, 0]);
                    assert_eq!(known.standard_support.status, "supported");
                }
                later_body(module, &bytes, 0);
            });
        }
    }

    // The pinned reader can normalize FF 00 and then accept the next End.
    // That apparent boundary cannot prove a second global or element item:
    // both must be withdrawn when the strict expression reader rejects FF.
    for (id, payload, expression, withdrawn, suffix) in [
        (
            6,
            vec![
                2, 0x7f, 0, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x7f, 0, 0x41, 0, 0x0b,
            ],
            "global[0]/entry[0]/init",
            "global[0]/entry[1]",
            vec![0x1c, 1, 0xff, 0, 0x0b, 0x7f, 0, 0x41, 0, 0x0b],
        ),
        (
            9,
            vec![1, 5, 0x70, 2, 0, 0x1c, 1, 0xff, 0, 0x0b, 0xd0, 0x70, 0x0b],
            "element[0]/entry[0]/item[0]",
            "element[0]/entry[0]/item[1]",
            vec![0x1c, 1, 0xff, 0, 0x0b, 0xd0, 0x70, 0x0b],
        ),
    ] {
        let mut bytes = HEADER.to_vec();
        section(&mut bytes, 1, &[1, 0x60, 0, 0]);
        section(&mut bytes, 3, &[1, 0]);
        section(&mut bytes, id, &payload);
        let section_end = bytes.len();
        section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
        section(&mut bytes, 0, &[1, b'x', 0xaa]);
        check(&bytes, |_, module| {
            let path = format!("{expression}/opaque");
            unknown_suffix(module, &path, &suffix);
            let all = regions(module);
            let opaque = all.iter().find(|region| region.path == path).unwrap();
            assert_eq!(opaque.span.end, section_end);
            assert!(!all.iter().any(|region| region.path.starts_with(withdrawn)));
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.path.starts_with(withdrawn)));
            let prefix = format!("{expression}/operator[0]");
            let unreachable = all.iter().find(|region| region.path == prefix).unwrap();
            assert_eq!(&bytes[unreachable.span.start..unreachable.span.end], &[0]);
            assert_eq!(unreachable.standard_support.status, "supported");
            later_body(module, &bytes, 0);
        });
    }

    // In flags6 the explicit reference type follows the offset expression.
    // An End seen only after normalizing its unknown typed-select prefix does
    // not authorize interpreting the apparent 63 00 as that reference type.
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 3, &[1, 0]);
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(
        &mut bytes,
        9,
        &[1, 6, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x63, 0, 0],
    );
    let element_end = bytes.len();
    let fake_type_start = element_end - 3;
    section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
    section(&mut bytes, 0, &[1, b'x', 0xaa]);
    check(&bytes, |_, module| {
        let path = "element[0]/entry[0]/offset/opaque";
        unknown_suffix(module, path, &[0x1c, 1, 0xff, 0, 0x0b, 0x63, 0, 0]);
        let all = regions(module);
        let opaque = all.iter().find(|region| region.path == path).unwrap();
        assert_eq!(opaque.span.end, element_end);
        let entry = all
            .iter()
            .find(|region| region.path == "element[0]/entry[0]")
            .unwrap();
        assert!(!entry.description.contains("element_type"));
        assert!(!all
            .iter()
            .any(|region| region.path.starts_with("element[0]/entry[0]/item[")));
        assert!(!module.standard.evidence.iter().any(|entry| {
            entry.path.starts_with("element[0]/entry[0]")
                && (entry.feature == "function_references"
                    || entry.reason.contains("heap type")
                    || (fake_type_start <= entry.span.start
                        && entry.span.start < fake_type_start + 2
                        && entry.kind != "opaque"))
        }));
        assert!(module.standard.evidence.iter().any(|entry| {
            entry.path == "element[0]/entry[0]" && entry.feature == "reference_types"
        }));
        let constant = all
            .iter()
            .find(|region| region.path == "element[0]/entry[0]/offset/operator[0]")
            .unwrap();
        assert_eq!(&bytes[constant.span.start..constant.span.end], &[0x41, 0]);
        assert_eq!(constant.standard_support.status, "supported");
        later_body(module, &bytes, 0);
    });

    // Withdrawal must also precede classifying a later entry's decode error,
    // and must run after a failed expression was recovered into an entry.
    for (id, payload, section_path, expression, withdrawn, suffix, prefix) in [
        (
            6,
            vec![2, 0x7f, 0, 0x41, 0, 0x1c, 1, 0xff, 0, 0x0b, 0x7f],
            "global[0]",
            "global[0]/entry[0]/init",
            "global[0]/entry[1]",
            vec![0x1c, 1, 0xff, 0, 0x0b, 0x7f],
            Some("global[0]/entry[0]/init/operator[0]"),
        ),
        (
            9,
            vec![1, 5, 0x70, 2, 0x1c, 1, 0xff, 0, 0x0b, 0x41, 0x80],
            "element[0]",
            "element[0]/entry[0]/item[0]",
            "element[0]/entry[0]/item[1]",
            vec![0x1c, 1, 0xff, 0, 0x0b, 0x41, 0x80],
            None,
        ),
    ] {
        let mut bytes = HEADER.to_vec();
        section(&mut bytes, 1, &[1, 0x60, 0, 0]);
        section(&mut bytes, 3, &[1, 0]);
        section(&mut bytes, id, &payload);
        let section_end = bytes.len();
        section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
        section(&mut bytes, 0, &[1, b'x', 0xaa]);
        check(&bytes, |_, module| {
            let path = format!("{expression}/opaque");
            unknown_suffix(module, &path, &suffix);
            let all = regions(module);
            let opaque = all.iter().find(|region| region.path == path).unwrap();
            assert_eq!(opaque.span.end, section_end);
            assert!(!all.iter().any(|region| {
                region.path.starts_with(withdrawn)
                    || (region.path.starts_with(section_path)
                        && region.path.ends_with("/undecoded"))
            }));
            assert!(!module.standard.evidence.iter().any(|entry| {
                entry.path.starts_with(withdrawn)
                    || (entry.path.starts_with(section_path)
                        && entry.span.start >= opaque.span.start
                        && entry.status == "invalid_encoding")
            }));
            // Independent validator errors may still mention EOF. These
            // primary decoding errors would instead claim an unproved entry.
            assert!(!module.diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.code.as_str(),
                    "core_decode" | "operator_decode" | "expression_structure" | "invalid_encoding"
                ) && opaque.span.start <= diagnostic.offset
                    && diagnostic.offset <= section_end
            }));
            if let Some(prefix) = prefix {
                let known = all.iter().find(|region| region.path == prefix).unwrap();
                assert_eq!(&bytes[known.span.start..known.span.end], &[0x41, 0]);
                assert_eq!(known.standard_support.status, "supported");
            } else {
                assert!(module.standard.evidence.iter().any(|entry| {
                    entry.path == "element[0]/entry[0]" && entry.feature == "bulk_memory"
                }));
            }
            later_body(module, &bytes, 0);
        });
    }
}
