//! Fixed unknown declaration constructors and trusted vector prefixes; no search.
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
const UNKNOWN_TYPES: [&[u8]; 3] = [&[0xff, 0], &[0xff, 0x7f], &[0x7a]];

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> Span {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    Span {
        start,
        end: bytes.len(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(raw: &str) -> Vec<u8> {
    assert_eq!(raw.len() % 2, 0);
    raw.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn replay(old: &[u8], new: &[u8], edits: &[ByteEdit]) {
    let mut restored = Vec::new();
    let mut cursor = 0;
    for edit in edits {
        assert!(cursor <= edit.old_span.start && edit.old_span.end <= old.len());
        assert!(edit.new_span.start <= edit.new_span.end && edit.new_span.end <= new.len());
        assert_eq!(
            edit.old_hex,
            hex(&old[edit.old_span.start..edit.old_span.end])
        );
        assert_eq!(
            edit.new_hex,
            hex(&new[edit.new_span.start..edit.new_span.end])
        );
        restored.extend_from_slice(&old[cursor..edit.old_span.start]);
        restored.extend_from_slice(&unhex(&edit.new_hex));
        cursor = edit.old_span.end;
    }
    restored.extend_from_slice(&old[cursor..]);
    assert_eq!(restored, new);
}

fn patch_pair(old: &[u8], new: &[u8]) {
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

fn all_regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(regions: &'a [Region], found: &mut Vec<&'a Region>) {
        for region in regions {
            found.push(region);
            visit(&region.children, found);
        }
    }
    let mut found = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut found);
    }
    found
}

fn region<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    all_regions(module)
        .into_iter()
        .find(|region| region.path == path)
        .unwrap_or_else(|| panic!("missing physical region {path}"))
}

fn unknown(module: &AuditModule, path: &str) -> bool {
    module
        .standard
        .evidence
        .iter()
        .any(|entry| entry.path == path && entry.status == "unknown")
}

fn check(bytes: &[u8], mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(bytes, profile).unwrap();
        for entry in &module.standard.evidence {
            assert!(entry.span.start <= entry.span.end && entry.span.end <= bytes.len());
            assert_eq!(entry.raw_hex, hex(&bytes[entry.span.start..entry.span.end]));
        }
        inspect(profile, &module);
        let diff = audit::compare_with_standard(HEADER, bytes, profile).unwrap();
        assert!(diff.changed);
        replay(HEADER, bytes, &diff.edits);
        let edits = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &expected_edits {
            assert_eq!(previous, &edits);
        } else {
            expected_edits = Some(edits);
        }
    }
    patch_pair(HEADER, bytes);
}

fn types(bytes: &mut Vec<u8>) {
    section(bytes, 1, &[1, 0x60, 0, 0]);
}

fn functions(bytes: &mut Vec<u8>, count: u8) {
    let mut payload = vec![count];
    payload.resize(usize::from(count) + 1, 0);
    section(bytes, 3, &payload);
}

fn exports(bytes: &mut Vec<u8>, kind: u8) {
    section(bytes, 7, &[2, 1, b'a', kind, 0, 1, b'b', kind, 1]);
}

fn code(bytes: &mut Vec<u8>, count: u8, prefix: &[u8]) {
    let mut payload = vec![count];
    for _ in 0..count {
        payload.push((prefix.len() + 6) as u8);
        payload.push(0); // The framed body has no local declaration groups.
        payload.extend_from_slice(prefix);
        payload.extend_from_slice(&[0x41, 42, 0x1a, 1, 0x0b]);
    }
    section(bytes, 10, &payload);
    section(bytes, 0, &[1, b'x', 0xa5]);
}

fn mvp_tail(module: &AuditModule, bytes: &[u8], function: usize) {
    let prefix = format!("code[0]/function[{function}]/operator[");
    let all = all_regions(module);
    let sentinel = all
        .iter()
        .find(|entry| {
            entry.path.starts_with(&prefix) && entry.description == "I32Const { value: 42 }"
        })
        .unwrap();
    assert_eq!(&bytes[sentinel.span.start..sentinel.span.end], &[0x41, 42]);
    assert_eq!(sentinel.standard_support.status, "supported");
    assert!(all.iter().any(|entry| {
        entry.path.starts_with(&prefix)
            && entry.description == "Nop"
            && entry.standard_support.status == "supported"
    }));
    assert!(module.sections.iter().any(|section| section.id == 0));
}

fn frontier(
    module: &AuditModule,
    bytes: &[u8],
    section_path: &str,
    span: Span,
    value_start: usize,
) {
    let path = format!("{section_path}/undecoded");
    let value_path = format!("{path}/value_type_start");
    let opaque = region(module, &path);
    assert_eq!(opaque.span, span);
    assert_eq!(opaque.feature.as_deref(), Some("unknown_declaration_type"));
    assert_eq!(opaque.standard_support.status, "unknown");
    let evidence: Vec<_> = module
        .standard
        .evidence
        .iter()
        .filter(|entry| entry.path == path)
        .collect();
    assert!(!evidence.is_empty());
    assert!(evidence.iter().all(|entry| {
        if entry.status == "unknown" {
            entry.span == span && entry.raw_hex == hex(&bytes[span.start..span.end])
        } else {
            // Only independently proved wire fields before the unknown byte
            // survive; they do not authorize a type or a later entry.
            entry.span.start >= span.start
                && entry.span.start < entry.span.end
                && entry.span.end <= value_start
                && entry.raw_hex == hex(&bytes[entry.span.start..entry.span.end])
                && entry.kind == "structure"
                && matches!(
                    entry.status.as_str(),
                    "supported" | "recognized_but_disabled"
                )
                && match section_path {
                    "element[0]" => {
                        entry.span
                            == (Span {
                                start: span.start,
                                end: span.start + 1,
                            })
                            && matches!(
                                (bytes[span.start], entry.feature.as_str()),
                                (5 | 7, "bulk_memory" | "reference_types") | (6, "reference_types")
                            )
                    }
                    "table[0]" => {
                        entry.span
                            == (Span {
                                start: span.start,
                                end: span.start + 2,
                            })
                            && bytes[span.start..entry.span.end] == [0x40, 0]
                            && entry.feature == "function_references"
                    }
                    "import[0]" => matches!(entry.feature.as_str(), "core1" | "compact_imports"),
                    "type[0]" => matches!(
                        entry.feature.as_str(),
                        "core1"
                            | "gc"
                            | "multi_value"
                            | "simd"
                            | "reference_types"
                            | "function_references"
                            | "exceptions"
                            | "stack_switching"
                            | "shared_everything_threads"
                            | "custom_descriptors"
                    ),
                    _ => false,
                }
        }
    }));
    {
        let prefix = region(module, &value_path);
        assert_eq!(
            prefix.span,
            Span {
                start: value_start,
                end: value_start + 1
            }
        );
        assert_eq!(prefix.feature.as_deref(), Some("unknown_value_type"));
        assert_eq!(prefix.standard_support.status, "unknown");
        assert!(unknown(module, &value_path));
    }
    // No interpretation of an unknown constructor may create another entry,
    // type-field evidence, or an initializer after the committed prefix.
    assert!(!all_regions(module).iter().any(|entry| {
        entry.path.starts_with(section_path)
            && entry.path != path
            && entry.path != value_path
            && entry.span.start >= span.start
    }));
    assert!(!module.standard.evidence.iter().any(|entry| {
        entry.path.starts_with(section_path)
            && entry.path != path
            && entry.path != value_path
            && entry.kind != "section"
            && entry.span.start >= span.start
    }));
}

fn opaque_change_is_lossless(bytes: &[u8], span: Span) {
    assert!(span.start < span.end);
    let mut changed = bytes.to_vec();
    changed[span.end - 1] ^= 1;
    let mut expected_edits = None;
    for profile in PROFILES {
        let diff = audit::compare_with_standard(bytes, &changed, profile).unwrap();
        assert!(diff.changed && diff.exact_minimal);
        assert!(!diff.edits.is_empty());
        replay(bytes, &changed, &diff.edits);
        let edits = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &expected_edits {
            assert_eq!(previous, &edits);
        } else {
            expected_edits = Some(edits);
        }
    }
    patch_pair(bytes, &changed);
}

#[test]
fn unknown_function_array_struct_and_recursive_type_fields_stop_the_group_vector() {
    for unknown_type in UNKNOWN_TYPES {
        for form in ["parameter", "result", "array", "struct", "rec", "subtype"] {
            let mut failed = match form {
                "parameter" => vec![0x60, 1],
                "result" => vec![0x60, 0, 1],
                "array" => vec![0x5e],
                "struct" => vec![0x5f, 1],
                "rec" => vec![0x4e, 1, 0x60, 1],
                "subtype" => vec![0x50, 0, 0x60, 1],
                _ => unreachable!(),
            };
            failed.extend_from_slice(unknown_type);
            if form != "result" {
                failed.push(0); // Fake result count or field mutability.
            }
            let mut payload = vec![3, 0x60, 0, 0];
            payload.extend_from_slice(&failed);
            payload.extend_from_slice(&[0x60, 0, 0]); // An unframed fake third group.
            let mut bytes = HEADER.to_vec();
            let target = section(&mut bytes, 1, &payload);
            section(&mut bytes, 3, &[2, 0, 1]);
            exports(&mut bytes, 0);
            code(&mut bytes, 2, &[0x10, 0, 0x10, 1]);
            let suffix = Span {
                start: target.start + 4,
                end: target.end,
            };
            check(&bytes, |_, module| {
                let value_offset = match form {
                    "parameter" | "struct" => 2,
                    "result" => 3,
                    "array" => 1,
                    "rec" | "subtype" => 4,
                    _ => unreachable!(),
                };
                frontier(
                    module,
                    &bytes,
                    "type[0]",
                    suffix,
                    suffix.start + value_offset,
                );
                let known = region(module, "type[0]/type[0]");
                assert_eq!(&bytes[known.span.start..known.span.end], &[0x60, 0, 0]);
                assert!(!unknown(module, "function[0]/entry[0]"));
                assert!(unknown(module, "function[0]/entry[1]"));
                assert!(!unknown(module, "export[0]/entry[0]"));
                assert!(unknown(module, "export[0]/entry[1]"));
                assert!(!unknown(module, "code[0]/function[0]/operator[0]"));
                assert!(unknown(module, "code[0]/function[0]/operator[1]"));
                mvp_tail(module, &bytes, 0);
                mvp_tail(module, &bytes, 1);
            });
            opaque_change_is_lossless(&bytes, suffix);
        }
    }
}

#[test]
fn unknown_table_types_cannot_publish_limits_initializers_or_later_tables() {
    for unknown_type in UNKNOWN_TYPES {
        for explicit_init in [false, true] {
            let mut failed = if explicit_init { vec![0x40, 0] } else { vec![] };
            failed.extend_from_slice(unknown_type);
            failed.extend_from_slice(&[4, 0]); // Fake table64 flag and minimum.
            if explicit_init {
                failed.extend_from_slice(&[0xd0, 0, 0x0b]);
            }
            let mut payload = vec![3, 0x70, 0, 1];
            payload.extend_from_slice(&failed);
            payload.extend_from_slice(&[0x70, 4, 0]);
            let mut bytes = HEADER.to_vec();
            types(&mut bytes);
            functions(&mut bytes, 1);
            let target = section(&mut bytes, 4, &payload);
            exports(&mut bytes, 1);
            code(&mut bytes, 1, &[0xfc, 0x10, 0, 0x1a, 0xfc, 0x10, 1, 0x1a]);
            let suffix = Span {
                start: target.start + 4,
                end: target.end,
            };
            check(&bytes, |_, module| {
                frontier(
                    module,
                    &bytes,
                    "table[0]",
                    suffix,
                    suffix.start + if explicit_init { 2 } else { 0 },
                );
                assert_eq!(region(module, "table[0]/entry[0]").span.end, suffix.start);
                assert!(!unknown(module, "export[0]/entry[0]"));
                assert!(unknown(module, "export[0]/entry[1]"));
                assert!(!unknown(module, "code[0]/function[0]/operator[0]"));
                assert!(unknown(module, "code[0]/function[0]/operator[2]"));
                assert!(!module.standard.evidence.iter().any(|entry| {
                    entry.path == "code[0]/function[0]/operator[2]" && entry.feature == "memory64"
                }));
                mvp_tail(module, &bytes, 0);
            });
            opaque_change_is_lossless(&bytes, suffix);
        }
    }
}

#[test]
fn unknown_global_types_cannot_authorize_an_initializer_or_later_global() {
    for unknown_type in UNKNOWN_TYPES {
        let mut payload = vec![3, 0x7f, 0, 0x41, 0, 0x0b];
        payload.extend_from_slice(unknown_type);
        payload.extend_from_slice(&[0, 0xd0, 0, 0x0b]);
        payload.extend_from_slice(&[0x7f, 0, 0x41, 0, 0x0b]);
        let mut bytes = HEADER.to_vec();
        types(&mut bytes);
        functions(&mut bytes, 1);
        let target = section(&mut bytes, 6, &payload);
        exports(&mut bytes, 3);
        code(&mut bytes, 1, &[0x23, 0, 0x1a, 0x23, 1, 0x1a]);
        let suffix = Span {
            start: target.start + 6,
            end: target.end,
        };
        check(&bytes, |_, module| {
            frontier(module, &bytes, "global[0]", suffix, suffix.start);
            let known = region(module, "global[0]/entry[0]/init/operator[0]");
            assert_eq!(&bytes[known.span.start..known.span.end], &[0x41, 0]);
            assert_eq!(known.standard_support.status, "supported");
            assert!(!unknown(module, "export[0]/entry[0]"));
            assert!(unknown(module, "export[0]/entry[1]"));
            assert!(!unknown(module, "code[0]/function[0]/operator[0]"));
            assert!(unknown(module, "code[0]/function[0]/operator[2]"));
            mvp_tail(module, &bytes, 0);
        });
        opaque_change_is_lossless(&bytes, suffix);
    }
}

fn import_module(failed: &[u8]) -> (Vec<u8>, Span) {
    let mut bytes = HEADER.to_vec();
    types(&mut bytes);
    // group0 is a complete function import. Neither a fake import after the
    // unknown type nor a complete-looking member inside its group is trusted.
    let mut payload = vec![3, 0, 1, b'f', 0, 0];
    payload.extend_from_slice(failed);
    payload.extend_from_slice(&[0, 1, b'z', 0, 0]);
    let target = section(&mut bytes, 2, &payload);
    functions(&mut bytes, 1);
    exports(&mut bytes, 0);
    code(&mut bytes, 1, &[0x10, 0, 0x10, 1]);
    (
        bytes,
        Span {
            start: target.start + 6,
            end: target.end,
        },
    )
}

fn check_import_frontier(bytes: &[u8], suffix: Span, value_offset: usize) {
    check(bytes, |_, module| {
        frontier(
            module,
            bytes,
            "import[0]",
            suffix,
            suffix.start + value_offset,
        );
        assert_eq!(region(module, "import[0]/group[0]").span.end, suffix.start);
        assert!(!unknown(module, "export[0]/entry[0]"));
        assert!(unknown(module, "export[0]/entry[1]"));
        assert!(!unknown(module, "code[0]/function[0]/operator[0]"));
        assert!(unknown(module, "code[0]/function[0]/operator[1]"));
        assert!(region(module, "code[0]/function[0]")
            .description
            .contains("function_index=unknown"));
        mvp_tail(module, bytes, 0);
    });
    opaque_change_is_lossless(bytes, suffix);
}

#[test]
fn ordinary_import_unknown_table_and_global_types_withdraw_following_imports() {
    for unknown_type in UNKNOWN_TYPES {
        for kind in [1, 3] {
            let mut failed = vec![0, 1, b'u', kind];
            failed.extend_from_slice(unknown_type);
            failed.push(0); // Fake table limits flag or global mutability.
            if kind == 1 {
                failed.push(1); // Fake table minimum.
            }
            let (bytes, suffix) = import_module(&failed);
            check_import_frontier(&bytes, suffix, 4);
        }
    }
}

#[test]
fn compact1_unknown_member_withdraws_the_whole_group_including_its_first_member() {
    for unknown_type in UNKNOWN_TYPES {
        for kind in [1, 3] {
            let mut failed = vec![
                0, 0, 0x7f, 3, // module, empty name, Compact1, three members
                1, b'a', 0, 0, // a complete-looking func import inside this group
                1, b'b', kind,
            ];
            failed.extend_from_slice(unknown_type);
            failed.push(0);
            if kind == 1 {
                failed.push(1);
            }
            failed.extend_from_slice(&[1, b'c', 0, 0]);
            let (bytes, suffix) = import_module(&failed);
            check_import_frontier(&bytes, suffix, 11);
        }
    }
}

#[test]
fn compact2_unknown_shared_type_cannot_authorize_names_or_the_following_group() {
    for unknown_type in UNKNOWN_TYPES {
        for kind in [1, 3] {
            let mut failed = vec![0, 0, 0x7e, kind];
            failed.extend_from_slice(unknown_type);
            failed.push(0);
            if kind == 1 {
                failed.push(1);
            }
            failed.extend_from_slice(&[2, 1, b'a', 1, b'b']);
            let (bytes, suffix) = import_module(&failed);
            check_import_frontier(&bytes, suffix, 4);
        }
    }
}

#[test]
fn element_flags5_flags6_and_flags7_do_not_frame_items_after_an_unknown_reference_type() {
    for unknown_type in UNKNOWN_TYPES {
        for flags in [5, 6, 7] {
            let mut payload = vec![3, 5, 0x70, 0, flags];
            if flags == 6 {
                payload.extend_from_slice(&[0, 0x41, 0, 0x0b]);
            }
            payload.extend_from_slice(unknown_type);
            payload.push(0); // Fake expression count.
            payload.extend_from_slice(&[5, 0x70, 0]); // Fake next segment.
            let mut bytes = HEADER.to_vec();
            types(&mut bytes);
            functions(&mut bytes, 1);
            section(&mut bytes, 4, &[1, 0x70, 0, 1]);
            let target = section(&mut bytes, 9, &payload);
            code(&mut bytes, 1, &[]);
            let suffix = Span {
                start: target.start + 4,
                end: target.end,
            };
            check(&bytes, |_, module| {
                frontier(
                    module,
                    &bytes,
                    "element[0]",
                    suffix,
                    suffix.start + if flags == 6 { 5 } else { 1 },
                );
                assert_eq!(region(module, "element[0]/entry[0]").span.end, suffix.start);
                mvp_tail(module, &bytes, 0);
            });
            opaque_change_is_lossless(&bytes, suffix);
        }
    }
}

#[test]
fn explicit_reference_constructor_is_known_even_when_its_heap_index_is_out_of_bounds() {
    // 63 FF 00 is a known nullable reference to heap type127, not the unknown
    // leading FF used above. A complete type namespace makes index127 a
    // validator error, without making the declaration's wire grammar unknown.
    for (id, payload, completed, section_path) in [
        (
            1,
            vec![3, 0x60, 0, 0, 0x60, 1, 0x63, 0xff, 0, 0, 0x60, 0, 0],
            "type[0]/type[2]",
            "type[0]",
        ),
        (
            4,
            vec![3, 0x70, 0, 1, 0x63, 0xff, 0, 0, 1, 0x70, 0, 1],
            "table[0]/entry[2]",
            "table[0]",
        ),
        (
            6,
            vec![
                3, 0x7f, 0, 0x41, 0, 0x0b, 0x63, 0xff, 0, 0, 0xd0, 0, 0x0b, 0x7f, 0, 0x41, 0, 0x0b,
            ],
            "global[0]/entry[2]",
            "global[0]",
        ),
        (
            2,
            vec![
                3, 0, 1, b'f', 0, 0, 0, 1, b'u', 3, 0x63, 0xff, 0, 0, 0, 1, b'z', 0, 0,
            ],
            "import[0]/group[2]/import[0]",
            "import[0]",
        ),
        (
            2,
            vec![
                3, 0, 1, b'f', 0, 0, 0, 0, 0x7f, 3, 1, b'a', 0, 0, 1, b'b', 3, 0x63, 0xff, 0, 0, 1,
                b'c', 0, 0, 0, 1, b'z', 0, 0,
            ],
            "import[0]/group[2]/import[0]",
            "import[0]",
        ),
        (
            2,
            vec![
                3, 0, 1, b'f', 0, 0, 0, 0, 0x7e, 3, 0x63, 0xff, 0, 0, 2, 1, b'a', 1, b'b', 0, 1,
                b'z', 0, 0,
            ],
            "import[0]/group[2]/import[0]",
            "import[0]",
        ),
        (
            9,
            vec![3, 5, 0x70, 0, 5, 0x63, 0xff, 0, 0, 5, 0x70, 0],
            "element[0]/entry[2]",
            "element[0]",
        ),
    ] {
        let mut bytes = HEADER.to_vec();
        if id == 1 {
            section(&mut bytes, id, &payload);
        } else {
            types(&mut bytes);
        }
        if id == 2 {
            section(&mut bytes, id, &payload);
        }
        functions(&mut bytes, 1);
        if id > 2 {
            section(&mut bytes, id, &payload);
        }
        code(&mut bytes, 1, &[]);
        check(&bytes, |_, module| {
            assert_eq!(module.standard.validation, "invalid");
            region(module, completed);
            assert!(!all_regions(module).iter().any(|entry| {
                entry.path.starts_with(section_path)
                    && entry.feature.as_deref() == Some("unknown_declaration_type")
            }));
            assert!(!module.standard.evidence.iter().any(|entry| {
                entry.path.starts_with(section_path)
                    && matches!(entry.status.as_str(), "unknown" | "invalid_encoding")
            }));
            mvp_tail(module, &bytes, 0);
        });
    }
}
