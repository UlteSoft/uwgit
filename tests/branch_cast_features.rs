//! Finite handwritten wire fixtures for the semantic extension of ordinary
//! br_on_cast/fail. Core3 requires target <: source; custom descriptors relaxes
//! that to equal heap hierarchies. The pinned implementation additionally only
//! permits continuation targets on the custom-descriptors path. No generated
//! corpus, WAT translation, guest execution or fuzz search is involved.

use std::collections::BTreeSet;

use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};
use wasmparser::{Validator, WasmFeatures};

const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];
const ANY: &str = "0061736d010000000105016000016e03020100";
const FUNC: &str = "0061736d010000000105016000017003020100";
const SHARED: &str = "0061736d01000000010601600001656e03020100";
const CONT: &str = "0061736d010000000105016000016803020100";
// Original type indices: 0=func, 1=open struct, 2=final subtype of 1.
const NOMINAL: &str = "0061736d01000000010e036000016e50005f004f01015f0003020100";
// The same hierarchy in one explicit recursive group; field type refers to 1.
const RECURSIVE: &str = "0061736d010000000116026000016e4e0250005f016301004f01015f0163010003020100";
// Two module indices for structurally equal final types canonicalize equally.
const EQUIVALENT: &str = "0061736d010000000109036000016e5f005f0003020100";

struct Case {
    name: &'static str,
    prefix: &'static str,
    cast: &'static str,
    extension: bool,
    core3_valid: bool,
    all_valid: bool,
    extra_features: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        name: "ordinary upcast",
        prefix: ANY,
        cast: "fb1803006d6e",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &[],
    },
    Case {
        name: "ordinary failed upcast",
        prefix: ANY,
        cast: "fb1903006d6e",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &[],
    },
    Case {
        name: "ordinary downcast",
        prefix: ANY,
        cast: "fb1803006e6d",
        extension: false,
        core3_valid: true,
        all_valid: true,
        extra_features: &[],
    },
    Case {
        name: "ordinary failed downcast",
        prefix: ANY,
        cast: "fb1903006e6d",
        extension: false,
        core3_valid: true,
        all_valid: true,
        extra_features: &[],
    },
    Case {
        name: "sibling heap types",
        prefix: ANY,
        cast: "fb1803006b6a",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &[],
    },
    Case {
        name: "nullable target widens source",
        prefix: ANY,
        cast: "fb1802006e6e",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &["function_references"],
    },
    Case {
        name: "nonnull target narrows source",
        prefix: ANY,
        cast: "fb1801006e6e",
        extension: false,
        core3_valid: true,
        all_valid: true,
        extra_features: &["function_references"],
    },
    Case {
        name: "different hierarchies remain invalid",
        prefix: ANY,
        cast: "fb1803006e6f",
        extension: false,
        core3_valid: false,
        all_valid: false,
        extra_features: &[],
    },
    Case {
        name: "bad label does not hide known extension",
        prefix: ANY,
        cast: "fb1803016d6e",
        extension: true,
        core3_valid: false,
        all_valid: false,
        extra_features: &[],
    },
    Case {
        name: "shared hierarchy upcast",
        prefix: SHARED,
        cast: "fb180300656d656e",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &["shared_everything_threads"],
    },
    Case {
        name: "shared and unshared remain separate",
        prefix: ANY,
        cast: "fb180300656d6e",
        extension: false,
        core3_valid: false,
        all_valid: false,
        extra_features: &["shared_everything_threads"],
    },
    Case {
        name: "nominal function upcast",
        prefix: FUNC,
        cast: "fb1803000070",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &["function_references"],
    },
    Case {
        name: "continuation target needs relaxed cast rule",
        prefix: CONT,
        cast: "fb1803006868",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &["stack_switching"],
    },
    Case {
        name: "nominal struct upcast",
        prefix: NOMINAL,
        cast: "fb1803000201",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &["function_references"],
    },
    Case {
        name: "nominal struct downcast",
        prefix: NOMINAL,
        cast: "fb1803000102",
        extension: false,
        core3_valid: true,
        all_valid: true,
        extra_features: &["function_references"],
    },
    Case {
        name: "recursive nominal upcast",
        prefix: RECURSIVE,
        cast: "fb1903000201",
        extension: true,
        core3_valid: false,
        all_valid: true,
        extra_features: &["function_references"],
    },
    Case {
        name: "canonical aliases are not a new extension",
        prefix: EQUIVALENT,
        cast: "fb1803000102",
        extension: false,
        core3_valid: true,
        all_valid: true,
        extra_features: &["function_references"],
    },
];

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A fixed function: no locals; unreachable; selected cast; nop; i32.const 7;
/// drop; end. Every case has the same independently readable MVP suffix.
fn fixture(prefix: &str, cast: &str) -> (Vec<u8>, Span) {
    let mut bytes = unhex(prefix);
    let cast = unhex(cast);
    let payload_len = u8::try_from(cast.len() + 9).unwrap();
    let body_len = u8::try_from(cast.len() + 7).unwrap();
    assert!(payload_len < 128 && body_len < 128);
    bytes.extend_from_slice(&[10, payload_len, 1, body_len, 0, 0]);
    let start = bytes.len();
    bytes.extend_from_slice(&cast);
    let span = Span {
        start,
        end: bytes.len(),
    };
    bytes.extend_from_slice(&[1, 0x41, 7, 0x1a, 0x0b]);
    (bytes, span)
}

fn region<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    fn find<'a>(entries: &'a [Region], path: &str) -> Option<&'a Region> {
        entries.iter().find_map(|entry| {
            if entry.path == path {
                Some(entry)
            } else {
                find(&entry.children, path)
            }
        })
    }
    module
        .sections
        .iter()
        .find_map(|section| find(&section.regions, path))
        .unwrap()
}

fn physical_evidence(module: &AuditModule, bytes: &[u8], cast: Span) {
    for evidence in &module.standard.evidence {
        assert!(evidence.span.start <= evidence.span.end);
        assert!(evidence.span.end <= bytes.len());
        assert_eq!(
            evidence.raw_hex,
            hex(&bytes[evidence.span.start..evidence.span.end])
        );
    }
    for (ordinal, delta, raw, description) in [
        (2, (0, 1), &[1][..], "Nop"),
        (3, (1, 3), &[0x41, 7][..], "I32Const { value: 7 }"),
        (4, (3, 4), &[0x1a][..], "Drop"),
        (5, (4, 5), &[0x0b][..], "End"),
    ] {
        let path = format!("code[0]/function[0]/operator[{ordinal}]");
        let entry = region(module, &path);
        assert_eq!(
            entry.span,
            Span {
                start: cast.end + delta.0,
                end: cast.end + delta.1
            }
        );
        assert_eq!(&bytes[entry.span.start..entry.span.end], raw);
        assert_eq!(entry.description, description);
        assert_eq!(entry.standard_support.status, "supported");
        assert_eq!(entry.standard_support.display, "instruction");
        assert_eq!(entry.standard_support.required_features, ["mvp"]);
    }
}

fn exact_change_and_patch(bytes: &[u8], cast: Span) {
    let immediate = cast.end + 2;
    let mut changed = bytes.to_vec();
    assert_eq!(changed[immediate], 7);
    changed[immediate] = 8;
    for profile in PROFILES {
        let diff = audit::compare_with_standard(bytes, &changed, profile).unwrap();
        assert!(diff.changed && diff.exact_minimal);
        assert_eq!(diff.edits.len(), 1);
        let expected = Span {
            start: immediate,
            end: immediate + 1,
        };
        assert_eq!(diff.edits[0].old_span, expected);
        assert_eq!(diff.edits[0].new_span, expected);
        assert_eq!(diff.edits[0].old_hex, "07");
        assert_eq!(diff.edits[0].new_hex, "08");
    }
    for (old, new) in [(bytes, changed.as_slice()), (changed.as_slice(), bytes)] {
        let patch = wasm_git::patch::create(old, new).unwrap();
        let encoded = patch.to_bytes().unwrap();
        let decoded = BytePatch::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.apply(old).unwrap(), new);
    }
}

#[test]
fn ordinary_branch_cast_requirements_use_nominal_and_abstract_relations() {
    for case in CASES {
        let (bytes, span) = fixture(case.prefix, case.cast);
        let without_descriptors = WasmFeatures::all().difference(WasmFeatures::CUSTOM_DESCRIPTORS);
        assert_eq!(
            Validator::new_with_features(without_descriptors)
                .validate_all(&bytes)
                .is_ok(),
            case.all_valid && !case.extension,
            "{} without descriptors",
            case.name
        );
        for (profile_index, profile) in PROFILES.into_iter().enumerate() {
            let expected_valid = match profile {
                Standard::Core1 | Standard::Core2 => false,
                Standard::Core3 => case.core3_valid,
                Standard::AllKnown => case.all_valid,
            };
            assert_eq!(
                Validator::new_with_features(profile.features())
                    .validate_all(&bytes)
                    .is_ok(),
                expected_valid,
                "{}/{profile}",
                case.name
            );
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            assert_eq!(
                module.standard.validator_valid, expected_valid,
                "{}/{profile}",
                case.name
            );
            assert_eq!(
                module.standard.validation,
                if expected_valid { "valid" } else { "invalid" },
                "{}/{profile}",
                case.name
            );
            assert_eq!(module.standard.validator_input.kind, "original_bytes");
            let path = "code[0]/function[0]/operator[1]";
            let operator = region(&module, path);
            assert_eq!(operator.span, span);
            assert_eq!(hex(&bytes[span.start..span.end]), case.cast);
            let mut features = BTreeSet::from(["gc", "reference_types"]);
            features.extend(case.extra_features.iter().copied());
            if case.extension {
                features.insert("custom_descriptors");
            }
            let actual: BTreeSet<_> = operator
                .standard_support
                .required_features
                .iter()
                .map(String::as_str)
                .collect();
            assert_eq!(actual, features, "{}/{profile}", case.name);
            let supported = profile_index == 3
                || (profile_index == 2
                    && !case.extension
                    && !case.extra_features.contains(&"shared_everything_threads")
                    && !case.extra_features.contains(&"stack_switching"));
            assert_eq!(
                operator.standard_support.status,
                if supported {
                    "supported"
                } else {
                    "recognized_but_disabled"
                },
                "{}/{profile}",
                case.name
            );
            assert_eq!(
                operator.standard_support.display,
                if supported { "instruction" } else { "binary" }
            );
            let extensions: Vec<_> = module
                .standard
                .evidence
                .iter()
                .filter(|entry| entry.path == path && entry.feature == "custom_descriptors")
                .collect();
            assert_eq!(extensions.len(), usize::from(case.extension));
            for evidence in extensions {
                assert_eq!(evidence.span, span);
                assert_eq!(evidence.raw_hex, case.cast);
                assert_eq!(evidence.kind, "instruction");
                assert_eq!(
                    evidence.status,
                    if profile == Standard::AllKnown {
                        "supported"
                    } else {
                        "recognized_but_disabled"
                    }
                );
            }
            physical_evidence(&module, &bytes, span);
        }
        exact_change_and_patch(&bytes, span);
    }
}

#[test]
fn unavailable_original_types_never_authorize_a_nominal_cast_relation() {
    for (name, prefix) in [
        (
            "forbidden bare value index normalized by validator",
            "0061736d01000000010902600001706001000003020100",
        ),
        (
            "unknown value constructor",
            "0061736d01000000010902600001706001660003020100",
        ),
        (
            "invalid supertype index",
            "0061736d01000000010a02600001704f01095f0003020100",
        ),
        (
            "duplicate type sections",
            "0061736d01000000010501600001700103015f0003020100",
        ),
        (
            "type section has no function",
            "0061736d010000000103015f0003020100",
        ),
    ] {
        let (bytes, span) = fixture(prefix, "fb1803000070");
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            let path = "code[0]/function[0]/operator[1]";
            let operator = region(&module, path);
            assert_eq!(operator.span, span, "{name}/{profile}");
            assert_eq!(
                operator.standard_support.status, "unknown",
                "{name}/{profile}"
            );
            assert!(
                module
                    .standard
                    .evidence
                    .iter()
                    .any(|entry| entry.path == path
                        && entry.feature == "unknown"
                        && entry.reason.contains("type relation is unproven")),
                "{name}/{profile}"
            );
            assert!(
                !module
                    .standard
                    .evidence
                    .iter()
                    .any(|entry| entry.path == path && entry.feature == "custom_descriptors"),
                "{name}/{profile}"
            );
            assert_eq!(module.standard.validation, "invalid");
            physical_evidence(&module, &bytes, span);
        }
        exact_change_and_patch(&bytes, span);
    }
}

#[test]
fn unrelated_invalid_sections_do_not_hide_independently_proven_cast_requirements() {
    for (prefix, cast) in [
        // Correct nominal types followed by an invalid global.get initializer.
        (
            "0061736d01000000010e036000016e50005f004f01015f00030201000606017f0023050b",
            "fb1803000201",
        ),
        // An independently framed unknown section cannot erase the type proof.
        (
            "0061736d01000000010501600001700e01ff03020100",
            "fb1803000070",
        ),
        // Abstract types need no original nominal-type context at all.
        (
            "0061736d010000000109026000016e6001660003020100",
            "fb1803006d6e",
        ),
    ] {
        let (bytes, span) = fixture(prefix, cast);
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            assert_eq!(module.standard.validation, "invalid");
            assert!(!module.standard.validator_valid);
            let entry = module
                .standard
                .evidence
                .iter()
                .find(|entry| {
                    entry.path == "code[0]/function[0]/operator[1]"
                        && entry.feature == "custom_descriptors"
                })
                .unwrap();
            assert_eq!(entry.span, span);
            assert_eq!(entry.raw_hex, cast);
            physical_evidence(&module, &bytes, span);
        }
        exact_change_and_patch(&bytes, span);
    }
}
