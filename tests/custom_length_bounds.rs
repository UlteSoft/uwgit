//! Fixed custom-name lengths, including values that overflow a 32-bit reader.
//! No search, generated mutations, or WebAssembly execution.
use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
// One MVP function followed by a separate custom section named "x".
const TAIL: &[u8] = &[
    1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 10, 7, 1, 5, 0, 0x41, 42, 0x1a, 0x0b, 0, 3, 1, b'x', 0xa5,
];
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

struct InvalidName {
    payload: &'static [u8],
    error_position: usize,
    message: &'static str,
}

const INVALID: &[InvalidName] = &[
    InvalidName {
        payload: &[0xff, 0xff, 0xff, 0xff, 0x0f],
        error_position: 5,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[0xfe, 0xff, 0xff, 0xff, 0x0f, b'x'],
        error_position: 5,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[0xfb, 0xff, 0xff, 0xff, 0x0f],
        error_position: 5,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[0xff, 0x80, 0x80, 0x80, 0],
        error_position: 5,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[0x81, 0x80, 0x80, 0x80, 0],
        error_position: 5,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[2, b'a'],
        error_position: 1,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[],
        error_position: 0,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[0x80],
        error_position: 1,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[0x80, 0x80, 0x80, 0x80],
        error_position: 4,
        message: "unexpected end-of-file",
    },
    InvalidName {
        payload: &[0x80, 0x80, 0x80, 0x80, 0x10],
        error_position: 4,
        message: "invalid var_u32: integer too large",
    },
    InvalidName {
        payload: &[0x80, 0x80, 0x80, 0x80, 0x80, 0],
        error_position: 4,
        message: "invalid var_u32: integer representation too long",
    },
    InvalidName {
        payload: &[1, 0xff],
        error_position: 1,
        message: "malformed UTF-8 encoding",
    },
];

fn unsigned(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let byte = value as u8 & 0x7f;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}

fn fixture(payload: &[u8]) -> (Vec<u8>, Span, usize) {
    let mut bytes = HEADER.to_vec();
    bytes.push(0);
    unsigned(payload.len(), &mut bytes);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    let tail = bytes.len();
    bytes.extend_from_slice(TAIL);
    (bytes, Span { start, end: tail }, tail)
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(entries: &'a [Region], result: &mut Vec<&'a Region>) {
        for entry in entries {
            result.push(entry);
            visit(&entry.children, result);
        }
    }
    let mut result = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut result);
    }
    result
}

fn region<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    regions(module)
        .into_iter()
        .find(|entry| entry.path == path)
        .unwrap_or_else(|| panic!("missing physical region {path}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn raw_spans(module: &AuditModule, bytes: &[u8]) {
    assert_eq!(module.byte_len, bytes.len());
    let mut cursor = HEADER.len();
    for section in &module.sections {
        assert_eq!(section.span.start, cursor);
        assert_eq!(section.header_span.start, cursor);
        assert_eq!(section.header_span.end, section.payload_span.start);
        assert_eq!(section.payload_span.end, section.span.end);
        assert!(section.span.end <= bytes.len());
        cursor = section.span.end;
    }
    assert_eq!(cursor, bytes.len());
    for entry in regions(module) {
        assert!(entry.span.start <= entry.span.end && entry.span.end <= bytes.len());
    }
    for entry in &module.standard.evidence {
        assert!(entry.span.start <= entry.span.end && entry.span.end <= bytes.len());
        assert_eq!(entry.raw_hex, hex(&bytes[entry.span.start..entry.span.end]));
    }
}

fn independent_tail(module: &AuditModule, tail: usize) {
    assert_eq!(module.sections.len(), 5);
    for (index, id) in [(1, 1), (2, 3), (3, 10), (4, 0)] {
        assert_eq!(module.sections[index].id, id);
    }
    for (index, start, end, description) in [
        (0, 15, 17, "I32Const { value: 42 }"),
        (1, 17, 18, "Drop"),
        (2, 18, 19, "End"),
    ] {
        let entry = region(module, &format!("code[0]/function[0]/operator[{index}]"));
        assert_eq!(
            entry.span,
            Span {
                start: tail + start,
                end: tail + end
            }
        );
        assert_eq!(entry.description, description);
        assert_eq!(entry.standard_support.status, "supported");
    }
    let name = region(module, "custom[1]/name");
    assert_eq!(
        name.span,
        Span {
            start: tail + 21,
            end: tail + 23
        }
    );
    assert_eq!(name.description, "x");
    let opaque = region(module, "custom[1]/payload/opaque");
    assert_eq!(
        opaque.span,
        Span {
            start: tail + 23,
            end: tail + 24
        }
    );
    assert_eq!(module.sections[4].status, "opaque");
}

fn exact_edits_and_patches(bytes: &[u8], tail: usize) {
    // Only the independently framed function's constant changes: 42 -> 43.
    let immediate = tail + 16;
    let mut changed = bytes.to_vec();
    changed[immediate] = 43;
    let expected = Span {
        start: immediate,
        end: immediate + 1,
    };
    let mut encoded = None;
    for standard in PROFILES {
        let diff = audit::compare_with_standard(bytes, &changed, standard).unwrap();
        assert!(diff.changed && diff.exact_minimal);
        assert_eq!(diff.edits.len(), 1);
        let edit = &diff.edits[0];
        assert_eq!(edit.old_span, expected);
        assert_eq!(edit.new_span, expected);
        assert_eq!(edit.old_hex, "2a");
        assert_eq!(edit.new_hex, "2b");
        assert_eq!(&bytes[..immediate], &changed[..immediate]);
        assert_eq!(&bytes[immediate + 1..], &changed[immediate + 1..]);
        raw_spans(&diff.old, bytes);
        raw_spans(&diff.new, &changed);
        let actual = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &encoded {
            assert_eq!(previous, &actual);
        } else {
            encoded = Some(actual);
        }
    }
    for (old, new) in [(bytes, changed.as_slice()), (changed.as_slice(), bytes)] {
        let patch = wasm_git::patch::create(old, new).unwrap();
        let decoded = BytePatch::from_bytes(&patch.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded.apply(old).unwrap(), new);
    }
}

#[test]
fn forged_custom_name_lengths_fail_without_host_arithmetic_or_later_section_borrowing() {
    for case in INVALID {
        let (bytes, payload, tail) = fixture(case.payload);
        assert_eq!(&*audit::core_reader_bytes(&bytes), bytes);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(module.validation, "failed_or_unsupported");
            assert_eq!(module.standard.validation, "invalid");
            assert!(!module.standard.validator_valid);
            assert_eq!(module.standard.validator_input.kind, "original_bytes");
            assert!(module.standard.validator_input.projections.is_empty());
            assert_eq!(module.sections[0].status, "malformed");
            assert_eq!(module.sections[0].payload_span, payload);
            assert_eq!(
                module.sections[0].standard_support.status,
                "invalid_encoding"
            );
            let outer = region(&module, "custom[0]/outer_name");
            assert_eq!(outer.span, payload);
            assert_eq!(outer.standard_support.status, "invalid_encoding");
            assert_eq!(&bytes[outer.span.start..outer.span.end], case.payload);
            assert!(!regions(&module)
                .iter()
                .any(|entry| entry.path == "custom[0]/name"));
            let errors: Vec<_> = module
                .diagnostics
                .iter()
                .filter(|entry| entry.code == "core_decode")
                .collect();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].offset, payload.start + case.error_position);
            assert!(errors[0].message.starts_with(case.message));
            raw_spans(&module, &bytes);
            independent_tail(&module, tail);
        }
        exact_edits_and_patches(&bytes, tail);
    }
}

#[test]
fn complete_padded_empty_nul_and_unicode_custom_names_keep_original_rules() {
    for (payload, display) in [
        (&[0, 0xa5][..], ""),
        (&[0x80, 0x80, 0x80, 0x80, 0, 0xa5][..], ""),
        (&[0x81, 0x80, 0x80, 0x80, 0, b'x', 0xa5][..], "x"),
        (&[1, 0, 0xa5][..], "\0"),
        (&[4, 0xe4, 0xba, 0xba, 0, 0xa5][..], "人\0"),
    ] {
        let (bytes, payload_span, tail) = fixture(payload);
        assert_eq!(&*audit::core_reader_bytes(&bytes), bytes);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(module.validation, "valid_with_all_known_features");
            assert_eq!(module.standard.validation, "valid");
            assert!(module.standard.validator_valid);
            assert_eq!(module.standard.validator_input.kind, "original_bytes");
            assert!(module.standard.validator_input.projections.is_empty());
            let name = region(&module, "custom[0]/name");
            assert_eq!(
                name.span,
                Span {
                    start: payload_span.start,
                    end: tail - 1
                }
            );
            assert_eq!(name.description, display);
            let opaque = region(&module, "custom[0]/payload/opaque");
            assert_eq!(
                opaque.span,
                Span {
                    start: tail - 1,
                    end: tail
                }
            );
            assert_eq!(&bytes[opaque.span.start..opaque.span.end], &[0xa5]);
            assert!(!module
                .diagnostics
                .iter()
                .any(|entry| entry.code == "core_decode"));
            raw_spans(&module, &bytes);
            independent_tail(&module, tail);
        }
        exact_edits_and_patches(&bytes, tail);
    }
}

#[test]
fn legal_long_custom_names_still_use_only_the_disclosed_reader_projection() {
    for (length, display) in [
        (&[0xa1, 0x8d, 6][..], "n".repeat(100_001)),
        (&[0xa4, 0x8d, 6][..], "人\0".repeat(25_001)),
    ] {
        let mut payload = length.to_vec();
        payload.extend_from_slice(display.as_bytes());
        payload.push(0xa5);
        let (bytes, payload_span, tail) = fixture(&payload);
        let mut expected_view = bytes.clone();
        expected_view[payload_span.start] = 0;
        assert_eq!(&*audit::core_reader_bytes(&bytes), expected_view);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(module.validation, "valid_with_all_known_features");
            assert_eq!(module.standard.validation, "valid");
            assert!(module.standard.validator_valid);
            assert_eq!(
                module.standard.validator_input.kind,
                "custom_name_projection"
            );
            let projections = &module.standard.validator_input.projections;
            assert_eq!(projections.len(), 1);
            assert_eq!(projections[0].path, "custom[0]/name");
            assert_eq!(
                projections[0].name_span,
                Span {
                    start: payload_span.start,
                    end: tail - 1
                }
            );
            assert_eq!(
                projections[0].byte_span,
                Span {
                    start: payload_span.start,
                    end: payload_span.start + 1
                }
            );
            assert_eq!(projections[0].original_hex, hex(&length[..1]));
            assert_eq!(projections[0].projected_hex, "00");
            let name = region(&module, "custom[0]/name");
            assert_eq!(name.span, projections[0].name_span);
            assert_eq!(name.description, display);
            let opaque = region(&module, "custom[0]/payload/opaque");
            assert_eq!(
                opaque.span,
                Span {
                    start: tail - 1,
                    end: tail
                }
            );
            assert_eq!(&bytes[opaque.span.start..opaque.span.end], &[0xa5]);
            raw_spans(&module, &bytes);
            independent_tail(&module, tail);
        }
        exact_edits_and_patches(&bytes, tail);
    }
}
