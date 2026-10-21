//! Fixed literal modules distinguish GC constant global reads from extended-const arithmetic.
//!
//! Source oracle: wasmparser 0.249.0, src/validator/core.rs. add_global
//! validates the initializer before inserting the current global (lines 61-70).
//! validate_global checks GC for module-defined globals and independently
//! rejects mutable globals (lines 278-294). Only the six integer arithmetic
//! operators below use validate_extended_const (lines 369-393).
//! No WAT generation, resynchronization, or fuzz search is involved.

use std::collections::BTreeSet;

use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    standard::Standard,
};
use wasmparser::{Validator, WasmFeatures};

const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];
const ALL: [bool; 4] = [true; 4];
const NONE: [bool; 4] = [false; 4];
const CORE3: [bool; 4] = [false, false, true, true];
// Independent flag columns are WASM2, WASM2+GC, WASM2+EXTENDED_CONST, both.
const GC_GATE: [bool; 4] = [false, true, false, true];
const EXTENDED_CONST_GATE: [bool; 4] = [false, false, true, true];

struct Case {
    name: &'static str,
    module_hex: &'static str,
    path: &'static str,
    span: (usize, usize),
    raw_hex: &'static str,
    description: &'static str,
    features: &'static [&'static str],
    compatible: [bool; 4],
    valid: [bool; 4],
    independent_flags_valid: [bool; 4],
}

const CASES: &[Case] = &[
    Case {
        // (global $a i32 (i32.const 0)) (global i32 (global.get $a))
        name: "preceding local immutable global",
        module_hex: "0061736d01000000060b027f0041000b7f0023000b",
        path: "global[0]/entry[1]/init/operator[0]",
        span: (18, 20),
        raw_hex: "2300",
        description: "GlobalGet { global_index: 0 }",
        features: &["gc", "mvp"],
        compatible: CORE3,
        valid: CORE3,
        independent_flags_valid: GC_GATE,
    },
    Case {
        // (import "m" "g" (global i32)) (global i32 (global.get 0))
        name: "imported immutable global",
        module_hex: "0061736d01000000020801016d0167037f000606017f0023000b",
        path: "global[0]/entry[0]/init/operator[0]",
        span: (23, 25),
        raw_hex: "2300",
        description: "GlobalGet { global_index: 0 }",
        features: &["mvp"],
        compatible: ALL,
        valid: ALL,
        independent_flags_valid: ALL,
    },
    Case {
        // (global i32 (i32.const 0)) (func global.get 0 drop)
        name: "local global read in a function",
        module_hex: "0061736d01000000010401600000030201000606017f0041000b0a0701050023001a0b",
        path: "code[0]/function[0]/operator[0]",
        span: (31, 33),
        raw_hex: "2300",
        description: "GlobalGet { global_index: 0 }",
        features: &["mvp"],
        compatible: ALL,
        valid: ALL,
        independent_flags_valid: ALL,
    },
    Case {
        // (global $a (mut i32) (i32.const 0)) (global i32 (global.get $a))
        name: "preceding local mutable global",
        module_hex: "0061736d01000000060b027f0141000b7f0023000b",
        path: "global[0]/entry[1]/init/operator[0]",
        span: (18, 20),
        raw_hex: "2300",
        description: "GlobalGet { global_index: 0 }",
        features: &["gc", "mvp"],
        compatible: CORE3,
        valid: NONE,
        independent_flags_valid: NONE,
    },
    Case {
        // (import "m" "g" (global (mut i32))) (global i32 (global.get 0))
        name: "imported mutable global",
        module_hex: "0061736d01000000020801016d0167037f010606017f0023000b",
        path: "global[0]/entry[0]/init/operator[0]",
        span: (23, 25),
        raw_hex: "2300",
        description: "GlobalGet { global_index: 0 }",
        features: &["mvp"],
        compatible: ALL,
        valid: NONE,
        independent_flags_valid: NONE,
    },
    Case {
        // (global i32 (global.get 1)) (global i32 (i32.const 0))
        name: "forward local global read",
        module_hex: "0061736d01000000060b027f0023010b7f0041000b",
        path: "global[0]/entry[0]/init/operator[0]",
        span: (13, 15),
        raw_hex: "2301",
        description: "GlobalGet { global_index: 1 }",
        features: &["mvp"],
        compatible: ALL,
        valid: NONE,
        independent_flags_valid: NONE,
    },
    Case {
        // (global i32 (global.get 0))
        name: "self global read",
        module_hex: "0061736d010000000606017f0023000b",
        path: "global[0]/entry[0]/init/operator[0]",
        span: (13, 15),
        raw_hex: "2300",
        description: "GlobalGet { global_index: 0 }",
        features: &["mvp"],
        compatible: ALL,
        valid: NONE,
        independent_flags_valid: NONE,
    },
    Case {
        // (global i32 (global.get 7))
        name: "out of range global read",
        module_hex: "0061736d010000000606017f0023070b",
        path: "global[0]/entry[0]/init/operator[0]",
        span: (13, 15),
        raw_hex: "2307",
        description: "GlobalGet { global_index: 7 }",
        features: &["mvp"],
        compatible: ALL,
        valid: NONE,
        independent_flags_valid: NONE,
    },
    Case {
        // (global i32 (i32.add (i32.const 3) (i32.const 2)))
        name: "constant i32.add",
        module_hex: "0061736d010000000609017f00410341026a0b",
        path: "global[0]/entry[0]/init/operator[2]",
        span: (17, 18),
        raw_hex: "6a",
        description: "I32Add",
        features: &["extended_const", "mvp"],
        compatible: CORE3,
        valid: CORE3,
        independent_flags_valid: EXTENDED_CONST_GATE,
    },
    Case {
        // (global i32 (i32.sub (i32.const 3) (i32.const 2)))
        name: "constant i32.sub",
        module_hex: "0061736d010000000609017f00410341026b0b",
        path: "global[0]/entry[0]/init/operator[2]",
        span: (17, 18),
        raw_hex: "6b",
        description: "I32Sub",
        features: &["extended_const", "mvp"],
        compatible: CORE3,
        valid: CORE3,
        independent_flags_valid: EXTENDED_CONST_GATE,
    },
    Case {
        // (global i32 (i32.mul (i32.const 3) (i32.const 2)))
        name: "constant i32.mul",
        module_hex: "0061736d010000000609017f00410341026c0b",
        path: "global[0]/entry[0]/init/operator[2]",
        span: (17, 18),
        raw_hex: "6c",
        description: "I32Mul",
        features: &["extended_const", "mvp"],
        compatible: CORE3,
        valid: CORE3,
        independent_flags_valid: EXTENDED_CONST_GATE,
    },
    Case {
        // (global i64 (i64.add (i64.const 3) (i64.const 2)))
        name: "constant i64.add",
        module_hex: "0061736d010000000609017e00420342027c0b",
        path: "global[0]/entry[0]/init/operator[2]",
        span: (17, 18),
        raw_hex: "7c",
        description: "I64Add",
        features: &["extended_const", "mvp"],
        compatible: CORE3,
        valid: CORE3,
        independent_flags_valid: EXTENDED_CONST_GATE,
    },
    Case {
        // (global i64 (i64.sub (i64.const 3) (i64.const 2)))
        name: "constant i64.sub",
        module_hex: "0061736d010000000609017e00420342027d0b",
        path: "global[0]/entry[0]/init/operator[2]",
        span: (17, 18),
        raw_hex: "7d",
        description: "I64Sub",
        features: &["extended_const", "mvp"],
        compatible: CORE3,
        valid: CORE3,
        independent_flags_valid: EXTENDED_CONST_GATE,
    },
    Case {
        // (global i64 (i64.mul (i64.const 3) (i64.const 2)))
        name: "constant i64.mul",
        module_hex: "0061736d010000000609017e00420342027e0b",
        path: "global[0]/entry[0]/init/operator[2]",
        span: (17, 18),
        raw_hex: "7e",
        description: "I64Mul",
        features: &["extended_const", "mvp"],
        compatible: CORE3,
        valid: CORE3,
        independent_flags_valid: EXTENDED_CONST_GATE,
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

fn region<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    fn find<'a>(entries: &'a [Region], path: &str) -> Option<&'a Region> {
        for entry in entries {
            if entry.path == path {
                return Some(entry);
            }
            if let Some(found) = find(&entry.children, path) {
                return Some(found);
            }
        }
        None
    }
    module
        .sections
        .iter()
        .find_map(|section| find(&section.regions, path))
        .unwrap_or_else(|| panic!("missing literal operator path {path}"))
}

#[test]
fn literal_global_contexts_and_const_arithmetic_have_exact_profile_evidence() {
    for case in CASES {
        let bytes = unhex(case.module_hex);
        let span = Span {
            start: case.span.0,
            end: case.span.1,
        };
        assert_eq!(
            hex(&bytes[span.start..span.end]),
            case.raw_hex,
            "{}",
            case.name
        );
        for (index, profile) in PROFILES.into_iter().enumerate() {
            let valid = Validator::new_with_features(profile.features())
                .validate_all(&bytes)
                .is_ok();
            assert_eq!(valid, case.valid[index], "{}/{profile}", case.name);
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            assert_eq!(module.byte_len, bytes.len());
            assert_eq!(
                module.standard.validator_valid, valid,
                "{}/{profile}",
                case.name
            );
            assert_eq!(module.standard.validator_error.is_some(), !valid);
            assert_eq!(
                module.standard.validation,
                if case.valid[index] {
                    "valid"
                } else {
                    "invalid"
                },
                "{}/{profile}",
                case.name
            );
            assert_eq!(
                module.validation,
                if case.valid[3] {
                    "valid_with_all_known_features"
                } else {
                    "failed_or_unsupported"
                },
                "{}/{profile}",
                case.name
            );
            for evidence in &module.standard.evidence {
                assert!(evidence.span.start <= evidence.span.end);
                assert!(evidence.span.end <= bytes.len());
                assert_eq!(
                    evidence.raw_hex,
                    hex(&bytes[evidence.span.start..evidence.span.end]),
                    "{}/{profile}/{}",
                    case.name,
                    evidence.path
                );
            }

            let operator = region(&module, case.path);
            assert_eq!(operator.span, span, "{}/{profile}", case.name);
            assert_eq!(
                operator.description, case.description,
                "{}/{profile}",
                case.name
            );
            let required: Vec<_> = operator
                .standard_support
                .required_features
                .iter()
                .map(String::as_str)
                .collect();
            assert_eq!(
                required.as_slice(),
                case.features,
                "{}/{profile}",
                case.name
            );
            assert_eq!(
                operator.standard_support.status,
                if case.compatible[index] {
                    "supported"
                } else {
                    "recognized_but_disabled"
                },
                "{}/{profile}",
                case.name
            );
            assert_eq!(
                operator.standard_support.display,
                if case.compatible[index] {
                    "instruction"
                } else {
                    "binary"
                },
                "{}/{profile}",
                case.name
            );

            let evidence: Vec<_> = module
                .standard
                .evidence
                .iter()
                .filter(|entry| entry.path == case.path)
                .collect();
            assert_eq!(
                evidence.len(),
                case.features.len(),
                "{}/{profile}",
                case.name
            );
            let features: BTreeSet<_> = evidence
                .iter()
                .map(|entry| entry.feature.as_str())
                .collect();
            let expected: BTreeSet<_> = case.features.iter().copied().collect();
            assert_eq!(features, expected, "{}/{profile}", case.name);
            for entry in evidence {
                assert_eq!(entry.span, span, "{}/{profile}", case.name);
                assert_eq!(entry.raw_hex, case.raw_hex, "{}/{profile}", case.name);
                assert_eq!(entry.kind, "instruction");
                assert_eq!(
                    entry.status,
                    if entry.feature == "mvp" || case.compatible[index] {
                        "supported"
                    } else {
                        "recognized_but_disabled"
                    },
                    "{}/{profile}/{}",
                    case.name,
                    entry.feature
                );
            }
        }
    }
}

#[test]
fn gc_and_extended_const_flags_independently_gate_the_literal_modules() {
    let variants = [
        ("WASM2", WasmFeatures::WASM2),
        ("WASM2+GC", WasmFeatures::WASM2.union(WasmFeatures::GC)),
        (
            "WASM2+EXTENDED_CONST",
            WasmFeatures::WASM2.union(WasmFeatures::EXTENDED_CONST),
        ),
        (
            "WASM2+GC+EXTENDED_CONST",
            WasmFeatures::WASM2
                .union(WasmFeatures::GC)
                .union(WasmFeatures::EXTENDED_CONST),
        ),
    ];
    for case in CASES {
        let bytes = unhex(case.module_hex);
        for (index, (name, features)) in variants.into_iter().enumerate() {
            let valid = Validator::new_with_features(features)
                .validate_all(&bytes)
                .is_ok();
            assert_eq!(
                valid, case.independent_flags_valid[index],
                "{}/{name}",
                case.name
            );
        }
    }
}
