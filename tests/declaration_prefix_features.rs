//! Fixed declaration prefixes before unknown types; no generated mutations.
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
    carrier: &'static str,
    prior_path: &'static str,
    prior: Span,
    custom: usize,
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn fixture(id: u8, entry: &[u8], operators: &[u8]) -> Fixture {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    let (carrier, prior_path, prior): (&str, &str, &[u8]) = match id {
        2 => (
            "import[0]/undecoded",
            "import[0]/group[0]",
            &[0, 1, b'f', 0, 0],
        ),
        4 => ("table[0]/undecoded", "table[0]/entry[0]", &[0x70, 0, 1]),
        6 => (
            "global[0]/undecoded",
            "global[0]/entry[0]",
            &[0x7f, 0, 0x41, 0, 0x0b],
        ),
        _ => unreachable!(),
    };
    if id != 2 {
        section(&mut bytes, 3, &[1, 0]);
    }
    let mut payload = vec![2];
    payload.extend_from_slice(prior);
    payload.extend_from_slice(entry);
    let start = section(&mut bytes, id, &payload);
    let prior = Span {
        start: start + 1,
        end: start + 1 + prior.len(),
    };
    let entry = Span {
        start: prior.end,
        end: bytes.len(),
    };
    if id == 2 {
        section(&mut bytes, 3, &[1, 0]);
    }
    let mut code = vec![1, (operators.len() + 2) as u8, 0];
    code.extend_from_slice(operators);
    code.push(0x0b);
    section(&mut bytes, 10, &code);
    let custom = bytes.len();
    section(&mut bytes, 0, &[1, b'x', 0xa5]);
    Fixture {
        bytes,
        entry,
        carrier,
        prior_path,
        prior,
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

fn check(fixture: &Fixture, mut inspect: impl FnMut(Standard, &AuditModule)) {
    let mut expected_edits = None;
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        assert_eq!(at(&module, fixture.prior_path).span, fixture.prior);
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

fn relative(fixture: &Fixture, start: usize, end: usize) -> Span {
    Span {
        start: fixture.entry.start + start,
        end: fixture.entry.start + end,
    }
}

fn status(profile: Standard, feature: &str) -> &'static str {
    let allowed = match feature {
        "core1" => true,
        "simd" => profile != Standard::Core1,
        "function_references" | "memory64" => {
            matches!(profile, Standard::Core3 | Standard::AllKnown)
        }
        "compact_imports" => profile == Standard::AllKnown,
        _ => panic!("unexpected test feature {feature}"),
    };
    if allowed {
        "supported"
    } else {
        "recognized_but_disabled"
    }
}

fn fact(
    profile: Standard,
    module: &AuditModule,
    fixture: &Fixture,
    span: Span,
    feature: &str,
    reason: &str,
) {
    assert!(
        module.standard.evidence.iter().any(|evidence| {
            evidence.path == fixture.carrier
                && evidence.span == span
                && evidence.feature == feature
                && evidence.status == status(profile, feature)
                && evidence.kind == "structure"
                && evidence.reason.contains(reason)
        }),
        "{profile}: missing {feature} {span:?} ({reason})"
    );
}

fn frontier(module: &AuditModule, fixture: &Fixture, offset: usize) {
    let carrier = at(module, fixture.carrier);
    assert_eq!(carrier.span, fixture.entry);
    assert_eq!(carrier.feature.as_deref(), Some("unknown_declaration_type"));
    assert_eq!(carrier.standard_support.status, "unknown");
    let marker_path = format!("{}/value_type_start", fixture.carrier);
    let marker = at(module, &marker_path);
    assert_eq!(marker.span, relative(fixture, offset, offset + 1));
    assert_eq!(marker.feature.as_deref(), Some("unknown_value_type"));
    assert_eq!(marker.standard_support.status, "unknown");
    // Prefix facts add no physical children or declaration-looking regions.
    assert!(!regions(module).iter().any(|region| {
        region.span.start >= fixture.entry.start
            && region.span.start < fixture.entry.end
            && region.path != fixture.carrier
            && region.path != marker_path
    }));
    for evidence in module
        .standard
        .evidence
        .iter()
        .filter(|evidence| evidence.path == fixture.carrier && evidence.status != "unknown")
    {
        assert!(
            fixture.entry.start <= evidence.span.start && evidence.span.end <= marker.span.start
        );
        assert!(!matches!(
            evidence.status.as_str(),
            "invalid_encoding" | "invalid_semantics"
        ));
        assert!(!evidence.reason.contains("additional table"));
        assert!(!evidence.reason.contains("additional memory"));
        assert!(!evidence.reason.contains("mutable global import"));
    }
    assert!(!module.standard.evidence.iter().any(|evidence| {
        evidence.path.starts_with(fixture.carrier)
            && evidence.span.start >= marker.span.start
            && evidence.status != "unknown"
    }));
}

fn unknown_operand(module: &AuditModule, index: usize, raw: &[u8], reason: &str) {
    let path = format!("code[0]/function[0]/operator[{index}]");
    let operand = at(module, &path);
    assert_eq!(operand.standard_support.status, "unknown");
    assert!(module.standard.evidence.iter().any(|evidence| {
        evidence.path == path
            && evidence.status == "unknown"
            && evidence.reason.contains(reason)
            && evidence.raw_hex == hex(raw)
    }));
}

#[test]
fn ordinary_import_names_and_kind_remain_visible_before_an_unknown_type() {
    for kind in [1, 3] {
        let fixture = fixture(2, &[1, b'm', 1, b'u', kind, 0xff, 0], &[]);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, 5);
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 0, 2),
                "core1",
                "module",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 2, 4),
                "core1",
                "name",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 4, 5),
                "core1",
                "kind",
            );
            assert!(!module.standard.evidence.iter().any(|evidence| {
                evidence.path == fixture.carrier && evidence.feature == "compact_imports"
            }));
            let text = module.to_text();
            assert!(text.contains("known import module name"));
            assert!(text.contains("known import item name"));
        });
    }
    // Legal padding is part of each original name field, not a normalized
    // one-byte length or a shortened evidence span.
    let fixture = fixture(2, &[0x81, 0, b'm', 0x81, 0, b'u', 3, 0xff, 0], &[]);
    check(&fixture, |profile, module| {
        frontier(module, &fixture, 7);
        fact(
            profile,
            module,
            &fixture,
            relative(&fixture, 0, 3),
            "core1",
            "module",
        );
        fact(
            profile,
            module,
            &fixture,
            relative(&fixture, 3, 6),
            "core1",
            "name",
        );
        fact(
            profile,
            module,
            &fixture,
            relative(&fixture, 6, 7),
            "core1",
            "kind",
        );
    });
}

#[test]
fn table_initializer_marker_survives_without_publishing_the_unknown_table() {
    for suffix in [&[0xff, 0][..], &[0xff, 0, 4, 0x7b, 1, 0x0b][..]] {
        let mut entry = vec![0x40, 0];
        entry.extend_from_slice(suffix);
        let fixture = fixture(4, &entry, &[0xfc, 0x10, 0, 0x1a, 0xfc, 0x10, 1, 0x1a]);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, 2);
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 0, 2),
                "function_references",
                "initializer",
            );
            assert_ne!(
                at(module, "code[0]/function[0]/operator[0]")
                    .standard_support
                    .status,
                "unknown"
            );
            unknown_operand(module, 2, &[0xfc, 0x10, 1], "table index 1");
            assert_eq!(
                at(module, "code[0]/function[0]/operator[3]").description,
                "Drop"
            );
        });
    }
}

#[test]
fn compact1_keeps_complete_prior_wire_types_without_instantiating_them() {
    // Complete member a precedes the unknown global type of member b. Neither
    // member is an import until the entire compact group has been proved.
    for (prior_type, feature, type_start, type_end) in [
        (&[2, 4, 0][..], "memory64", 7, 10),
        (&[3, 0x7b, 1][..], "simd", 8, 9),
    ] {
        let mut entry = vec![1, b'm', 0, 0x7f, 2, 1, b'a'];
        entry.extend_from_slice(prior_type);
        entry.extend_from_slice(&[1, b'b', 3, 0xff, 0]);
        let fixture = fixture(2, &entry, &[0x3f, 0, 0x1a, 0x23, 0, 0x1a]);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, 13);
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 0, 2),
                "core1",
                "module",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 2, 3),
                "core1",
                "name",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 3, 4),
                "compact_imports",
                "compact",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 4, 5),
                "core1",
                "count",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 5, 7),
                "core1",
                "name",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 10, 12),
                "core1",
                "name",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 12, 13),
                "core1",
                "kind",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, type_start, type_end),
                feature,
                "",
            );
            unknown_operand(module, 0, &[0x3f, 0], "memory index 0");
            unknown_operand(module, 2, &[0x23, 0], "global index 0");
        });
    }
}

#[test]
fn compact1_complete_function_member_does_not_publish_a_phantom_import() {
    let fixture = fixture(
        2,
        &[1, b'm', 0, 0x7f, 2, 1, b'a', 0, 0, 1, b'b', 1, 0xff, 0],
        &[0x10, 0, 0x10, 1],
    );
    check(&fixture, |profile, module| {
        frontier(module, &fixture, 12);
        fact(
            profile,
            module,
            &fixture,
            relative(&fixture, 3, 4),
            "compact_imports",
            "compact",
        );
        fact(
            profile,
            module,
            &fixture,
            relative(&fixture, 7, 8),
            "core1",
            "kind",
        );
        assert_ne!(
            at(module, "code[0]/function[0]/operator[0]")
                .standard_support
                .status,
            "unknown"
        );
        unknown_operand(module, 1, &[0x10, 1], "function index 1");
        assert_eq!(
            at(module, "code[0]/function[0]/operator[2]").description,
            "End"
        );
    });
    // The earlier indexed reference is a wire fact in an uncommitted group.
    // Even with an incomplete type namespace, it must not queue a dependency.
    let mut pending = self::fixture(
        2,
        &[
            1, b'm', 0, 0x7f, 2, 1, b'a', 3, 0x63, 1, 0, 1, b'b', 3, 0xff, 0,
        ],
        &[],
    );
    assert_eq!(&pending.bytes[8..14], &[1, 4, 1, 0x60, 0, 0]);
    pending.bytes[13] = 1; // Missing result type; no complete type declaration.
    check(&pending, |profile, module| {
        frontier(module, &pending, 14);
        fact(
            profile,
            module,
            &pending,
            relative(&pending, 8, 10),
            "function_references",
            "",
        );
        for evidence in module
            .standard
            .evidence
            .iter()
            .filter(|evidence| evidence.path == pending.carrier && evidence.status == "unknown")
        {
            assert_eq!(evidence.span, pending.entry);
            assert_eq!(evidence.kind, "opaque");
            assert!(!evidence.reason.contains("type declaration prefix"));
        }
    });
}

#[test]
fn compact2_unknown_shared_type_cannot_authorize_a_names_vector() {
    for suffix in [
        &[0xff, 0][..],
        &[0xff, 0, 2, 1, b'a', 1, b'b', 3, 0x7b, 1][..],
    ] {
        let mut entry = vec![1, b'm', 0, 0x7e, 1];
        entry.extend_from_slice(suffix);
        let fixture = fixture(2, &entry, &[0xfc, 0x10, 0, 0x1a]);
        check(&fixture, |profile, module| {
            frontier(module, &fixture, 5);
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 0, 2),
                "core1",
                "module",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 2, 3),
                "core1",
                "name",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 3, 4),
                "compact_imports",
                "compact",
            );
            fact(
                profile,
                module,
                &fixture,
                relative(&fixture, 4, 5),
                "core1",
                "kind",
            );
            assert!(!module.standard.evidence.iter().any(|evidence| {
                evidence.path == fixture.carrier && evidence.reason.contains("count")
            }));
            unknown_operand(module, 0, &[0xfc, 0x10, 0], "table index 0");
        });
    }
}

#[test]
fn unknown_global_value_type_does_not_authorize_mutability_or_shared_flags() {
    for entry in [&[0xff, 0, 3][..], &[0xff, 0, 0x7b, 1, 0x41, 0, 0x0b][..]] {
        let fixture = fixture(6, entry, &[0x23, 0, 0x1a, 0x23, 1, 0x1a]);
        check(&fixture, |_, module| {
            frontier(module, &fixture, 0);
            assert!(!module.standard.evidence.iter().any(|evidence| {
                evidence.path == fixture.carrier && evidence.status != "unknown"
            }));
            assert_ne!(
                at(module, "code[0]/function[0]/operator[0]")
                    .standard_support
                    .status,
                "unknown"
            );
            unknown_operand(module, 2, &[0x23, 1], "global index 1");
            assert_eq!(
                at(module, "code[0]/function[0]/operator[3]").description,
                "Drop"
            );
        });
    }
}

#[test]
fn prior_reserved_name_and_count_errors_do_not_reach_apparent_unknown_types() {
    let cases: &[(u8, &[u8])] = &[
        (4, &[0x40, 1, 0xff, 0]),
        (4, &[0x40]),
        (2, &[1, 0xff, 0, 0x7e, 1, 0xff, 0]),
        (
            2,
            &[
                1, b'm', 0, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10, 1, b'a', 3, 0xff, 0,
            ],
        ),
        (2, &[1, b'm', 0, 0x7f, 1, 1, 0xff, 3, 0xff, 0]),
        (2, &[1, b'm', 0, 0x7e, 9, 0xff, 0]),
        (2, &[1, b'm', 1, b'u', 0x7e, 3, 0xff, 0]),
    ];
    for (id, entry) in cases {
        let fixture = fixture(*id, entry, &[]);
        check(&fixture, |_, module| {
            assert!(!regions(module).iter().any(|region| {
                region.feature.as_deref() == Some("unknown_declaration_type")
                    || region.path.ends_with("/value_type_start")
            }));
            assert!(!module.standard.evidence.iter().any(|evidence| {
                evidence.path == fixture.carrier
                    && matches!(
                        evidence.feature.as_str(),
                        "compact_imports" | "function_references"
                    )
            }));
        });
    }
}
