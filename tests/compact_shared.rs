//! Fixed Compact2 shared wire types versus actual import instances; no search.
use wasm_git::{
    audit::{self, AuditModule, ByteEdit, Region, Span},
    patch::BytePatch,
    standard::Standard,
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const TYPES: &[u8] = &[1, 0x60, 0, 0];
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

#[derive(Clone)]
struct Group {
    bytes: Vec<u8>,
    shared: Option<Span>,
    names: Vec<Span>,
}

struct Fixture {
    bytes: Vec<u8>,
    shared: Vec<Option<Span>>,
    names: Vec<Vec<Span>>,
}

fn unsigned(mut value: usize, bytes: &mut Vec<u8>) {
    loop {
        let byte = value as u8 & 0x7f;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    bytes.push(id);
    unsigned(payload.len(), bytes);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn compact2(ty: &[u8], count: u8) -> Group {
    let mut bytes = vec![1, b'm', 0, 0x7e];
    let start = bytes.len();
    bytes.extend_from_slice(ty);
    let shared = Some(Span {
        start,
        end: bytes.len(),
    });
    bytes.push(count);
    let mut names = Vec::new();
    for index in 0..count {
        let start = bytes.len();
        bytes.extend_from_slice(&[1, b'a' + index]);
        names.push(Span {
            start,
            end: bytes.len(),
        });
    }
    Group {
        bytes,
        shared,
        names,
    }
}

fn single(ty: &[u8], name: u8) -> Group {
    let mut bytes = vec![1, b'm', 1, name];
    bytes.extend_from_slice(ty);
    Group {
        bytes,
        shared: None,
        names: Vec::new(),
    }
}

fn compact1(ty: &[u8]) -> Group {
    let mut bytes = vec![1, b'm', 0, 0x7f, 2];
    for name in *b"ab" {
        bytes.extend_from_slice(&[1, name]);
        bytes.extend_from_slice(ty);
    }
    Group {
        bytes,
        shared: None,
        names: Vec::new(),
    }
}

fn fixture(types: &[u8], groups: &[Group], declarations: &[(u8, &[u8])], prefix: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, types);
    let mut imports = Vec::new();
    unsigned(groups.len(), &mut imports);
    let mut starts = Vec::new();
    for group in groups {
        starts.push(imports.len());
        imports.extend_from_slice(&group.bytes);
    }
    let payload_start = section(&mut bytes, 2, &imports);
    let shared = groups
        .iter()
        .zip(&starts)
        .map(|(group, start)| {
            group.shared.map(|span| Span {
                start: payload_start + start + span.start,
                end: payload_start + start + span.end,
            })
        })
        .collect();
    let names = groups
        .iter()
        .zip(starts)
        .map(|(group, start)| {
            group
                .names
                .iter()
                .map(|span| Span {
                    start: payload_start + start + span.start,
                    end: payload_start + start + span.end,
                })
                .collect()
        })
        .collect();
    section(&mut bytes, 3, &[1, 0]);
    for (id, payload) in declarations {
        section(&mut bytes, *id, payload);
    }
    let mut body = vec![0];
    body.extend_from_slice(prefix);
    body.extend_from_slice(&[0x41, 42, 0x1a, 1, 0x0b]);
    let mut code = vec![1];
    unsigned(body.len(), &mut code);
    code.extend_from_slice(&body);
    section(&mut bytes, 10, &code);
    Fixture {
        bytes,
        shared,
        names,
    }
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(entries: &'a [Region], output: &mut Vec<&'a Region>) {
        for entry in entries {
            output.push(entry);
            visit(&entry.children, output);
        }
    }
    let mut output = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut output);
    }
    output
}

fn region<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    regions(module)
        .into_iter()
        .find(|entry| entry.path == path)
        .unwrap_or_else(|| panic!("missing region {path}"))
}

fn unknown(module: &AuditModule, path: &str) -> bool {
    module
        .standard
        .evidence
        .iter()
        .any(|entry| entry.path == path && entry.status == "unknown")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn check(fixture: &Fixture, mut inspect: impl FnMut(Standard, &AuditModule)) {
    for standard in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, standard).unwrap();
        for entry in &module.standard.evidence {
            assert!(entry.span.start <= entry.span.end && entry.span.end <= fixture.bytes.len());
            assert_eq!(
                entry.raw_hex,
                hex(&fixture.bytes[entry.span.start..entry.span.end])
            );
        }
        let constant = regions(&module)
            .into_iter()
            .find(|entry| {
                entry.path.starts_with("code[0]/function[0]/operator[")
                    && entry.description == "I32Const { value: 42 }"
            })
            .unwrap();
        assert_eq!(
            &fixture.bytes[constant.span.start..constant.span.end],
            &[0x41, 42]
        );
        assert_eq!(constant.standard_support.status, "supported");
        inspect(standard, &module);
    }
}

fn shared_region<'a>(
    module: &'a AuditModule,
    fixture: &Fixture,
    index: usize,
    ty: &[u8],
) -> &'a Region {
    let shared = region(module, &format!("import[0]/group[{index}]/shared_type"));
    assert_eq!(shared.span, fixture.shared[index].unwrap());
    assert_eq!(&fixture.bytes[shared.span.start..shared.span.end], ty);
    assert!(shared.description.contains("shared_type="));
    for name in &fixture.names[index] {
        assert!(shared.span.end <= name.start);
    }
    shared
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

fn replay(old: &[u8], new: &[u8], edits: &[ByteEdit]) {
    let (mut old_cursor, mut new_cursor) = (0, 0);
    let mut output = Vec::new();
    for edit in edits {
        assert!(
            old_cursor <= edit.old_span.start
                && edit.old_span.start <= edit.old_span.end
                && edit.old_span.end <= old.len()
        );
        assert!(
            new_cursor <= edit.new_span.start
                && edit.new_span.start <= edit.new_span.end
                && edit.new_span.end <= new.len()
        );
        assert_eq!(
            &old[old_cursor..edit.old_span.start],
            &new[new_cursor..edit.new_span.start]
        );
        assert_eq!(
            edit.old_hex,
            hex(&old[edit.old_span.start..edit.old_span.end])
        );
        assert_eq!(
            edit.new_hex,
            hex(&new[edit.new_span.start..edit.new_span.end])
        );
        output.extend_from_slice(&old[old_cursor..edit.old_span.start]);
        output.extend_from_slice(&unhex(&edit.new_hex));
        old_cursor = edit.old_span.end;
        new_cursor = edit.new_span.end;
    }
    assert_eq!(&old[old_cursor..], &new[new_cursor..]);
    output.extend_from_slice(&old[old_cursor..]);
    assert_eq!(output, new);
}

fn physical_pair(old: &[u8], new: &[u8]) {
    let mut expected = None;
    for standard in PROFILES {
        let diff = audit::compare_with_standard(old, new, standard).unwrap();
        assert!(diff.changed);
        replay(old, new, &diff.edits);
        let edits = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &expected {
            assert_eq!(previous, &edits);
        } else {
            expected = Some(edits);
        }
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

#[test]
fn every_fixed_shared_wire_type_is_located_once_before_zero_one_or_two_names() {
    let cases: &[(&str, &[u8], &str)] = &[
        ("memory64", &[2, 4, 0], "memory64"),
        ("table64", &[1, 0x70, 4, 0], "memory64"),
        ("shared-memory", &[2, 3, 0, 1], "threads"),
        ("custom-page", &[2, 8, 0, 0], "custom_page_sizes"),
        ("global-v128", &[3, 0x7b, 0], "simd"),
        ("global-exnref", &[3, 0x69, 0], "exceptions"),
        ("shared-global", &[3, 0x7f, 3], "shared_everything_threads"),
        ("exact-function", &[0x20, 0], "custom_descriptors"),
        ("tag", &[4, 0, 0], "exceptions"),
    ];
    for &(label, ty, feature) in cases {
        for count in [0, 1, 2] {
            let input = fixture(TYPES, &[compact2(ty, count)], &[], &[]);
            check(&input, |_, module| {
                let shared = shared_region(module, &input, 0, ty);
                let requirements: Vec<_> = module
                    .standard
                    .evidence
                    .iter()
                    .filter(|entry| {
                        entry.feature == feature && entry.path.starts_with("import[0]/group[0]/")
                    })
                    .collect();
                assert!(
                    !requirements.is_empty(),
                    "missing {label} wire feature for count{count}"
                );
                for requirement in requirements {
                    assert!(
                        requirement.path == shared.path
                            || requirement.path.starts_with(&format!("{}/", shared.path)),
                        "{label}: {}",
                        requirement.path
                    );
                    assert!(
                        shared.span.start <= requirement.span.start
                            && requirement.span.end <= shared.span.end,
                        "{label}"
                    );
                }
                let group = region(module, "import[0]/group[0]");
                assert_eq!(group.children.len(), usize::from(count) + 1);
                for (index, expected) in input.names[0].iter().enumerate() {
                    let import = region(module, &format!("import[0]/group[0]/import[{index}]"));
                    assert_eq!(import.span, *expected);
                    assert_eq!(
                        &input.bytes[import.span.start..import.span.end],
                        &[1, b'a' + index as u8]
                    );
                }
            });
        }
    }
}

#[test]
fn empty_shared_groups_have_no_entities_signature_uses_or_instance_features() {
    let types = [2, 0x60, 0, 0, 0x60, 0, 1, 0x7f];
    let groups = [
        compact2(&[0, 99], 0),
        compact2(&[4, 0, 99], 0),
        compact2(&[4, 0, 1], 0),
        compact2(&[2, 0, 0], 0),
        compact2(&[1, 0x70, 0, 0], 0),
        compact2(&[3, 0x7f, 1], 0),
    ];
    let declarations: &[(u8, &[u8])] = &[
        (4, &[1, 0x70, 0, 1]),
        (5, &[1, 0, 1]),
        (13, &[1, 0, 0]),
        (6, &[1, 0x7f, 0, 0x41, 0, 0x0b]),
        (
            7,
            &[
                5, 1, b'f', 0, 0, 1, b't', 1, 0, 1, b'm', 2, 0, 1, b'g', 3, 0, 1, b'e', 4, 0,
            ],
        ),
    ];
    let input = fixture(
        &types,
        &groups,
        declarations,
        &[0x3f, 0, 0x1a, 0xfc, 0x10, 0, 0x1a, 0x23, 0, 0x1a],
    );
    check(&input, |standard, module| {
        assert_eq!(module.validation, "valid_with_all_known_features");
        if standard == Standard::AllKnown {
            assert_eq!(module.standard.validation, "valid");
        }
        assert!(region(module, "code[0]/function[0]")
            .description
            .starts_with("function_index=0 "));
        for index in 0..groups.len() {
            let group = region(module, &format!("import[0]/group[{index}]"));
            assert_eq!(group.children.len(), 1);
            assert_eq!(
                group.children[0].path,
                format!("import[0]/group[{index}]/shared_type")
            );
        }
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.feature == "multi_memory"
                || entry.feature == "mutable_global"
                || entry.feature == "stack_switching"
                || entry.reason.contains("additional table")
                || entry.status == "unknown"));
        for index in 0..5 {
            assert!(!unknown(module, &format!("export[0]/entry[{index}]")));
        }
        let size = region(module, "code[0]/function[0]/operator[0]");
        assert_eq!(&input.bytes[size.span.start..size.span.end], &[0x3f, 0]);
        assert_eq!(size.standard_support.status, "supported");
    });
}

#[test]
fn actual_names_advance_combined_indices_and_type_dependencies_stay_on_shared_bytes() {
    let groups = [
        compact2(&[2, 0, 0], 2),
        compact2(&[1, 0x70, 0, 0], 2),
        compact2(&[3, 0x7f, 0], 2),
        compact2(&[4, 0, 0], 2),
        compact2(&[0, 0], 2),
    ];
    let declarations: &[(u8, &[u8])] = &[
        (4, &[1, 0x70, 0, 1]),
        (5, &[1, 0, 1]),
        (13, &[1, 0, 0]),
        (6, &[1, 0x7f, 0, 0x41, 0, 0x0b]),
        (
            7,
            &[
                5, 1, b'f', 0, 2, 1, b't', 1, 2, 1, b'm', 2, 2, 1, b'g', 3, 2, 1, b'e', 4, 2,
            ],
        ),
    ];
    let input = fixture(
        TYPES,
        &groups,
        declarations,
        &[0x3f, 2, 0x1a, 0xfc, 0x10, 2, 0x1a, 0x23, 2, 0x1a],
    );
    check(&input, |_, module| {
        assert!(region(module, "code[0]/function[0]")
            .description
            .starts_with("function_index=2 "));
        for (path, feature, reason) in [
            (
                "import[0]/group[0]/import[1]",
                "multi_memory",
                "additional memory",
            ),
            (
                "import[0]/group[1]/import[1]",
                "reference_types",
                "additional table",
            ),
        ] {
            let expected = region(module, path).span;
            assert!(module
                .standard
                .evidence
                .iter()
                .any(|entry| entry.path == path
                    && entry.feature == feature
                    && entry.reason.contains(reason)
                    && entry.span == expected));
        }
        assert!(!module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "unknown"));
        for index in 0..5 {
            assert!(!unknown(module, &format!("export[0]/entry[{index}]")));
        }
        let size = region(module, "code[0]/function[0]/operator[0]");
        assert_eq!(&input.bytes[size.span.start..size.span.end], &[0x3f, 2]);
    });
    let incomplete_types = [2, 0x60, 0, 0, 0x7a];
    for ty in [
        &[0, 1][..],
        &[0x20, 1],
        &[4, 0, 1],
        &[3, 0x63, 1, 0],
        &[1, 0x63, 1, 0, 0],
    ] {
        for count in [0, 1, 2] {
            let input = fixture(&incomplete_types, &[compact2(ty, count)], &[], &[]);
            check(&input, |_, module| {
                let shared = shared_region(module, &input, 0, ty);
                assert_eq!(unknown(module, &shared.path), count != 0);
                for entry in module.standard.evidence.iter().filter(|entry| {
                    entry.status == "unknown" && entry.path.starts_with("import[0]/group[0]/")
                }) {
                    assert_eq!(entry.path, shared.path);
                    assert!(
                        shared.span.start <= entry.span.start && entry.span.end <= shared.span.end
                    );
                }
            });
        }
    }
}

#[test]
fn unknown_or_failed_groups_are_atomic_but_trusted_illegal_value_bytes_keep_their_location() {
    let first = compact2(&[2, 0, 0], 1);
    let unknown_group = compact2(&[3, 0xff, 0, 0], 1);
    let last = compact2(&[2, 4, 0], 1);
    let input = fixture(
        TYPES,
        &[first.clone(), unknown_group.clone(), last.clone()],
        &[],
        &[0x3f, 0, 0x1a, 0x3f, 1, 0x1a],
    );
    check(&input, |_, module| {
        shared_region(module, &input, 0, &[2, 0, 0]);
        assert!(!regions(module)
            .iter()
            .any(|entry| entry.path.starts_with("import[0]/group[1]")
                || entry.path.starts_with("import[0]/group[2]")));
        assert!(
            region(module, "import[0]/undecoded").feature.as_deref()
                == Some("unknown_declaration_type")
        );
        assert!(!unknown(module, "code[0]/function[0]/operator[0]"));
        assert!(unknown(module, "code[0]/function[0]/operator[2]"));
    });
    let illegal = fixture(TYPES, &[compact2(&[3, 0, 0], 1)], &[], &[]);
    check(&illegal, |_, module| {
        let shared = shared_region(module, &illegal, 0, &[3, 0, 0]);
        assert!(module
            .standard
            .evidence
            .iter()
            .any(|entry| entry.path == shared.path
                && entry.status == "invalid_encoding"
                && entry.span
                    == (Span {
                        start: shared.span.start + 1,
                        end: shared.span.start + 2
                    })
                && entry.raw_hex == "00"));
        assert!(regions(module)
            .iter()
            .any(|entry| entry.path == "import[0]/group[0]/import[0]"));
    });
    let mut bad_utf8 = compact2(&[2, 4, 0], 2);
    *bad_utf8.bytes.last_mut().unwrap() = 0xff;
    let mut bad_name_length = compact2(&[2, 4, 0], 1);
    bad_name_length
        .bytes
        .truncate(bad_name_length.bytes.len() - 2);
    bad_name_length
        .bytes
        .extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x10]);
    let failed_type = compact2(&[1, 0x7f, 0, 0], 1);
    for bad in [bad_utf8, bad_name_length, failed_type] {
        let input = fixture(TYPES, &[first.clone(), bad, last.clone()], &[], &[]);
        check(&input, |_, module| {
            shared_region(module, &input, 0, &[2, 0, 0]);
            assert!(!regions(module)
                .iter()
                .any(|entry| entry.path.starts_with("import[0]/group[1]")
                    || entry.path.starts_with("import[0]/group[2]")));
            assert!(!module.standard.evidence.iter().any(|entry| entry
                .path
                .starts_with("import[0]/group[1]/shared_type")
                || entry.path.starts_with("import[0]/group[2]/shared_type")));
            assert!(regions(module)
                .iter()
                .any(|entry| entry.path == "import[0]/undecoded"));
        });
    }
    physical_pair(&input.bytes, &illegal.bytes);
}

#[test]
fn ordinary_and_compact1_imports_keep_existing_locations_and_all_profiles_replay_original_bytes() {
    for groups in [
        vec![single(&[2, 4, 0], b'a'), single(&[2, 4, 0], b'b')],
        vec![compact1(&[2, 4, 0])],
    ] {
        let input = fixture(TYPES, &groups, &[], &[]);
        check(&input, |_, module| {
            assert!(!regions(module)
                .iter()
                .any(|entry| entry.path.ends_with("/shared_type")));
            let expected = if groups.len() == 2 {
                [
                    "import[0]/group[0]/import[0]",
                    "import[0]/group[1]/import[0]",
                ]
            } else {
                [
                    "import[0]/group[0]/import[0]",
                    "import[0]/group[0]/import[1]",
                ]
            };
            for path in expected {
                assert!(module
                    .standard
                    .evidence
                    .iter()
                    .any(|entry| entry.path == path && entry.feature == "memory64"));
                region(module, path);
            }
        });
    }
    let old = fixture(TYPES, &[compact2(&[2, 4, 0], 2)], &[], &[]);
    let new = fixture(TYPES, &[compact2(&[2, 4, 1], 2)], &[], &[]);
    physical_pair(&old.bytes, &new.bytes);
    let old = fixture(TYPES, &[compact2(&[3, 0xff, 0, 0], 1)], &[], &[]);
    let new = fixture(TYPES, &[compact2(&[3, 0xff, 0, 0], 2)], &[], &[]);
    physical_pair(&old.bytes, &new.bytes);
}
