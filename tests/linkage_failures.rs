//! Fixed Core linkage-name failures and unknown-frontier controls; no search.
use std::ops::Range;
use wasm_git::{
    audit::{self, AuditModule, ByteEdit, Region, Span},
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
    section: &'static str,
    failure: Span,
    prefix: Span,
    blame: Option<Span>,
    immediate: usize,
}

fn unsigned(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let byte = value as u8 & 0x7f;
        value >>= 7;
        out.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}

fn name(raw: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    unsigned(raw.len(), &mut result);
    result.extend_from_slice(raw);
    result
}

fn padded_name(raw: &[u8]) -> Vec<u8> {
    assert!(raw.len() < 128);
    let mut result = vec![raw.len() as u8 | 0x80, 0x80, 0x80, 0x80, 0];
    result.extend_from_slice(raw);
    result
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> Span {
    bytes.push(id);
    unsigned(payload.len(), bytes);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    Span {
        start,
        end: bytes.len(),
    }
}

fn linked(id: u8, payload: &[u8]) -> (Vec<u8>, Span, usize) {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    let mut target = None;
    if id == 2 {
        target = Some(section(&mut bytes, id, payload));
    }
    section(&mut bytes, 3, &[1, 0]);
    if id == 7 {
        target = Some(section(&mut bytes, id, payload));
    }
    let code = section(&mut bytes, 10, &[1, 5, 0, 0x41, 42, 0x1a, 0x0b]);
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    (bytes, target.unwrap(), code.start + 4)
}

fn fixture(id: u8, failed: &[u8], blame: Option<Range<usize>>) -> Fixture {
    let (prefix, next, section_name): (&[u8], &[u8], &str) = if id == 2 {
        (&[0, 1, b'k', 0, 0], &[0, 1, b'z', 0, 0], "import[0]")
    } else {
        (&[1, b'k', 0, 0], &[1, b'z', 0, 0], "export[0]")
    };
    let mut payload = vec![3];
    payload.extend_from_slice(prefix);
    let failed_start = payload.len();
    payload.extend_from_slice(failed);
    payload.extend_from_slice(next);
    let (bytes, target, immediate) = linked(id, &payload);
    Fixture {
        bytes,
        section: section_name,
        prefix: Span {
            start: target.start + 1,
            end: target.start + failed_start,
        },
        failure: Span {
            start: target.start + failed_start,
            end: target.end,
        },
        blame: blame.map(|span| Span {
            start: target.start + failed_start + span.start,
            end: target.start + failed_start + span.end,
        }),
        immediate,
    }
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn walk<'a>(entries: &'a [Region], out: &mut Vec<&'a Region>) {
        for entry in entries {
            out.push(entry);
            walk(&entry.children, out);
        }
    }
    let mut out = Vec::new();
    for section in &module.sections {
        walk(&section.regions, &mut out);
    }
    out
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

fn unhex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn raw_spans(bytes: &[u8], module: &AuditModule) {
    for entry in regions(module) {
        assert!(entry.span.start <= entry.span.end && entry.span.end <= bytes.len());
    }
    for entry in &module.standard.evidence {
        assert!(entry.span.start <= entry.span.end && entry.span.end <= bytes.len());
        assert_eq!(entry.raw_hex, hex(&bytes[entry.span.start..entry.span.end]));
    }
}

fn replay(old: &[u8], new: &[u8], edits: &[ByteEdit]) {
    let (mut a, mut b) = (0, 0);
    let mut output = Vec::new();
    for edit in edits {
        assert!(a <= edit.old_span.start && edit.old_span.start <= edit.old_span.end);
        assert!(b <= edit.new_span.start && edit.new_span.start <= edit.new_span.end);
        assert!(edit.old_span.end <= old.len() && edit.new_span.end <= new.len());
        assert_eq!(&old[a..edit.old_span.start], &new[b..edit.new_span.start]);
        assert_eq!(
            edit.old_hex,
            hex(&old[edit.old_span.start..edit.old_span.end])
        );
        assert_eq!(
            edit.new_hex,
            hex(&new[edit.new_span.start..edit.new_span.end])
        );
        output.extend_from_slice(&old[a..edit.old_span.start]);
        output.extend_from_slice(&unhex(&edit.new_hex));
        a = edit.old_span.end;
        b = edit.new_span.end;
    }
    assert_eq!(&old[a..], &new[b..]);
    output.extend_from_slice(&old[a..]);
    assert_eq!(output, new);
}

fn physical_pair(old: &[u8], new: &[u8]) {
    let mut previous = None;
    for standard in PROFILES {
        let diff = audit::compare_with_standard(old, new, standard).unwrap();
        assert!(diff.changed && !diff.edits.is_empty());
        raw_spans(old, &diff.old);
        raw_spans(new, &diff.new);
        replay(old, new, &diff.edits);
        let encoded = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(expected) = &previous {
            assert_eq!(expected, &encoded);
        }
        previous = Some(encoded);
    }
    for (before, after) in [(old, new), (new, old)] {
        let patch = wasm_git::patch::create(before, after).unwrap();
        assert_eq!(
            BytePatch::from_bytes(&patch.to_bytes().unwrap())
                .unwrap()
                .apply(before)
                .unwrap(),
            after
        );
    }
}

fn preserved(input: &Fixture, module: &AuditModule) {
    let prefix = if input.section == "import[0]" {
        "import[0]/group[0]"
    } else {
        "export[0]/entry[0]"
    };
    assert_eq!(region(module, prefix).span, input.prefix);
    assert_eq!(region(module, prefix).standard_support.status, "supported");
    for index in [1, 2] {
        let unpublished = if input.section == "import[0]" {
            format!("import[0]/group[{index}]")
        } else {
            format!("export[0]/entry[{index}]")
        };
        assert!(!regions(module)
            .iter()
            .any(|entry| entry.path == unpublished
                || entry.path.starts_with(&format!("{unpublished}/"))));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.path == unpublished
                || entry.path.starts_with(&format!("{unpublished}/"))));
    }
    let constant = region(module, "code[0]/function[0]/operator[0]");
    assert_eq!(
        constant.span,
        Span {
            start: input.immediate - 1,
            end: input.immediate + 1
        }
    );
    assert_eq!(
        &input.bytes[constant.span.start..constant.span.end],
        &[0x41, 42]
    );
    assert_eq!(constant.standard_support.status, "supported");
    assert!(module.sections.iter().any(|section| section.id == 0));
    raw_spans(&input.bytes, module);
}

fn check_invalid(input: &Fixture, field: &str) {
    let parent = format!("{}/undecoded", input.section);
    let child = format!("{parent}/{field}");
    let blame = input.blame.unwrap();
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&input.bytes, standard).unwrap();
        assert_eq!(module.validation, "failed_or_unsupported");
        assert_eq!(module.standard.validation, "invalid");
        assert_eq!(region(&module, &parent).span, input.failure);
        assert_eq!(
            region(&module, &parent).standard_support.status,
            "invalid_encoding"
        );
        assert_eq!(region(&module, &child).span, blame);
        assert_eq!(
            region(&module, &child).standard_support.status,
            "invalid_encoding"
        );
        for (path, span) in [(&parent, input.failure), (&child, blame)] {
            let evidence: Vec<_> = module
                .standard
                .evidence
                .iter()
                .filter(|entry| entry.path == *path)
                .collect();
            assert!(!evidence.is_empty(), "missing invalid evidence {path}");
            assert!(evidence
                .iter()
                .all(|entry| entry.status == "invalid_encoding"
                    && entry.span == span
                    && entry.raw_hex == hex(&input.bytes[span.start..span.end])));
        }
        preserved(input, &module);
    }
    let mut changed = input.bytes.clone();
    changed[input.immediate] = 43;
    physical_pair(&input.bytes, &changed);
}

fn check_unknown(input: &Fixture, require_unknown_parent: bool) {
    let parent = format!("{}/undecoded", input.section);
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&input.bytes, standard).unwrap();
        assert_eq!(module.validation, "failed_or_unsupported");
        assert_eq!(module.standard.validation, "invalid");
        assert_eq!(region(&module, &parent).span, input.failure);
        if require_unknown_parent {
            assert_eq!(region(&module, &parent).standard_support.status, "unknown");
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.status == "invalid_encoding"
                    && (entry.path == parent || entry.path.starts_with(&format!("{parent}/")))));
        }
        assert!(!regions(&module)
            .iter()
            .any(|entry| entry.path.starts_with(&format!("{parent}/"))
                && (entry.path.ends_with("/utf8") || entry.path.ends_with("/external_kind"))));
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.path.starts_with(&format!("{parent}/"))
                && entry.path.ends_with("/utf8")));
        preserved(input, &module);
    }
    let mut changed = input.bytes.clone();
    changed[input.immediate] = 43;
    physical_pair(&input.bytes, &changed);
}

#[test]
fn ordinary_import_names_locate_the_first_bad_utf8_sequence_after_valid_prefixes() {
    // Explicit malformed sequences, not generated byte mutations or searches.
    let cases: &[(&[u8], usize, usize)] = &[
        (&[0xff], 0, 1),
        (&[b'a', b'b', 0xff], 2, 1),
        (&[0xe4, 0xb8, 0xad, 0xff], 3, 1),
        (&[0xc0, 0xaf], 0, 1),
        (&[0xed, 0xa0, 0x80], 0, 1),
        (&[0xf4, 0x90, 0x80, 0x80], 0, 1),
        (&[0xc3, 0xa9, 0xe2, 0x82], 2, 2),
        (&[0xe2, 0x28, 0xa1], 0, 1),
    ];
    for &(raw, valid, length) in cases {
        let error = std::str::from_utf8(raw).unwrap_err();
        assert_eq!(error.valid_up_to(), valid);
        assert_eq!(error.error_len().unwrap_or(raw.len() - valid), length);
        let mut bad_module = name(raw);
        bad_module.extend_from_slice(&[0, 0, 0]);
        let prefix = name(raw).len() - raw.len();
        check_invalid(
            &fixture(
                2,
                &bad_module,
                Some(prefix + valid..prefix + valid + length),
            ),
            "module_name/utf8",
        );
        let mut bad_item = vec![0];
        bad_item.extend_from_slice(&name(raw));
        bad_item.extend_from_slice(&[0, 0]);
        check_invalid(
            &fixture(
                2,
                &bad_item,
                Some(1 + prefix + valid..1 + prefix + valid + length),
            ),
            "item_name/utf8",
        );
    }
}

#[test]
fn bad_export_names_precede_normal_or_exact_kinds_without_inventing_later_entries() {
    for kind in [0, 0x20] {
        let failed = [3, b'o', b'k', 0xff, kind, 0];
        let input = fixture(7, &failed, Some(3..4));
        check_invalid(&input, "name/utf8");
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&input.bytes, standard).unwrap();
            assert!(!regions(&module)
                .iter()
                .any(|entry| entry.path == "export[0]/undecoded/external_kind"));
        }
    }
}

#[test]
fn exact_function_export_is_a_wire_failure_while_exact_function_import_remains_a_proposal() {
    for index in [0, 1] {
        check_invalid(
            &fixture(7, &[1, b'x', 0x20, index], Some(2..3)),
            "external_kind",
        );
    }
    let (normal_export, _, _) = linked(7, &[1, 1, b'x', 0, 0]);
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&normal_export, standard).unwrap();
        assert_eq!(module.validation, "valid_with_all_known_features");
        assert_eq!(module.standard.validation, "valid");
    }
    let (exact_import, _, _) = linked(2, &[1, 0, 1, b'x', 0x20, 0]);
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&exact_import, standard).unwrap();
        assert_eq!(module.validation, "valid_with_all_known_features");
        assert_eq!(
            module.standard.validation,
            if standard == Standard::AllKnown {
                "valid"
            } else {
                "invalid"
            }
        );
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "invalid_encoding"));
        assert!(module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.feature == "custom_descriptors"));
    }
}

#[test]
fn compact1_bad_names_withdraw_the_group_even_before_a_later_unknown_kind() {
    let second = [0, 0, 0x7f, 2, 1, b'a', 0, 0, 1, 0xff, 0, 0];
    check_invalid(&fixture(2, &second, Some(9..10)), "item[1]/name/utf8");
    // The eager pinned group reader may fail at the kind first. The raw name
    // prefix independently proves the earlier UTF-8 error nonetheless.
    let first_then_unknown = [0, 0, 0x7f, 1, 1, 0xff, 0xff];
    check_invalid(
        &fixture(2, &first_then_unknown, Some(5..6)),
        "item[0]/name/utf8",
    );
    let bad_module = [1, 0xff, 0, 0x7f, 0];
    check_invalid(&fixture(2, &bad_module, Some(1..2)), "module_name/utf8");
}

#[test]
fn compact2_bad_names_do_not_publish_shared_type_or_partial_name_instances() {
    let second = [0, 0, 0x7e, 2, 4, 0, 2, 1, b'a', 1, 0xff];
    check_invalid(&fixture(2, &second, Some(10..11)), "item[1]/name/utf8");
    let first = [0, 0, 0x7e, 0, 0, 1, 1, 0xff];
    check_invalid(&fixture(2, &first, Some(7..8)), "item[0]/name/utf8");
    let bad_module = [1, 0xff, 0, 0x7e, 0, 0, 0];
    check_invalid(&fixture(2, &bad_module, Some(1..2)), "module_name/utf8");
}

#[test]
fn unknown_kinds_or_value_prefixes_cannot_authorize_fake_later_utf8_fields() {
    let cases: &[(u8, &[u8])] = &[
        (2, &[0, 0, 0xff, 1, 0xff]),
        (2, &[0, 1, b'x', 0x7f, 1, 1, 0xff]), // Nonempty item name is not a compact marker.
        (2, &[0, 0, 0x7f, 2, 0, 0xff, 1, 0xff, 0, 0]),
        (2, &[0, 0, 0x7f, 2, 0, 3, 0xff, 0, 0, 1, 0xff, 0, 0]),
        (2, &[0, 0, 0x7e, 0xff, 1, 1, 0xff]),
        (2, &[0, 0, 0x7e, 3, 0xff, 0, 0, 1, 1, 0xff]),
        (7, &[1, b'x', 0xff, 1, 0xff, 0, 0]),
    ];
    for &(id, failed) in cases {
        check_unknown(&fixture(id, failed, None), true);
    }
    // A bare positive value-type fallback is not a proved layout for finding
    // later name strings. Do not demand that its separate wire diagnosis vanish.
    check_unknown(&fixture(2, &[0, 0, 0x7e, 3, 0, 0, 1, 1, 0xff], None), false);
}

#[test]
fn known_reference_constructors_allow_a_later_bad_name_to_be_proved() {
    for ty in [
        &[1, 0x70, 0, 0][..],
        &[3, 0x63, 0xff, 0, 0][..], // Explicit constructor and legitimate heap index127.
    ] {
        let mut failed = vec![0, 0, 0x7f, 2, 0];
        failed.extend_from_slice(ty);
        failed.push(1);
        let invalid = failed.len();
        failed.extend_from_slice(&[0xff, 0, 0]);
        check_invalid(
            &fixture(2, &failed, Some(invalid..invalid + 1)),
            "item[1]/name/utf8",
        );
    }
}

#[test]
fn legal_names_beyond_the_reader_resource_limit_are_not_invalid_encodings() {
    // One fixed legal length, no limit search or generated mutations.
    let long_name = name(&vec![b'n'; 100_001]);
    let mut module_name = long_name.clone();
    module_name.extend_from_slice(&[0, 0, 0]);
    let mut item_name = vec![0];
    item_name.extend_from_slice(&long_name);
    item_name.extend_from_slice(&[0, 0]);
    let mut compact1 = vec![0, 0, 0x7f, 1];
    compact1.extend_from_slice(&long_name);
    compact1.extend_from_slice(&[0, 0]);
    let mut compact2 = vec![0, 0, 0x7e, 0, 0, 1];
    compact2.extend_from_slice(&long_name);
    let mut export = long_name;
    export.extend_from_slice(&[0, 0]);
    for (id, failed) in [
        (2, module_name),
        (2, item_name),
        (2, compact1),
        (2, compact2),
        (7, export),
    ] {
        check_unknown(&fixture(id, &failed, None), true);
    }
}

#[test]
fn valid_unicode_nul_and_padded_core_name_lengths_keep_their_meaning() {
    let module_name = padded_name("m\0中".as_bytes());
    let item_name = padded_name("n\0é".as_bytes());
    let mut single = module_name.clone();
    single.extend_from_slice(&item_name);
    single.extend_from_slice(&[0, 0]);
    let mut compact1 = module_name.clone();
    compact1.extend_from_slice(&padded_name(b""));
    compact1.extend_from_slice(&[0x7f, 1]);
    compact1.extend_from_slice(&item_name);
    compact1.extend_from_slice(&[0, 0]);
    let mut compact2 = module_name;
    compact2.extend_from_slice(&padded_name(b""));
    compact2.extend_from_slice(&[0x7e, 0, 0, 1]);
    compact2.extend_from_slice(&item_name);
    let mut export = padded_name("e\0中".as_bytes());
    export.extend_from_slice(&[0, 0]);
    for (id, entry, compact) in [
        (2, single, false),
        (2, compact1, true),
        (2, compact2, true),
        (7, export, false),
    ] {
        let mut payload = vec![1];
        payload.extend_from_slice(&entry);
        let (bytes, _, immediate) = linked(id, &payload);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(module.validation, "valid_with_all_known_features");
            assert_eq!(
                module.standard.validation,
                if !compact || standard == Standard::AllKnown {
                    "valid"
                } else {
                    "invalid"
                }
            );
            assert!(!module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.status == "invalid_encoding"));
            let constant = region(&module, "code[0]/function[0]/operator[0]");
            assert_eq!(&bytes[constant.span.start..constant.span.end], &[0x41, 42]);
            raw_spans(&bytes, &module);
        }
        let mut changed = bytes.clone();
        changed[immediate] = 43;
        physical_pair(&bytes, &changed);
    }
}
