use wasm_git::{audit, standard::Standard};
use wasmparser::Validator;

#[test]
fn validator_cursor_has_bounded_original_bytes_and_physical_locations() {
    // The encoder emits this body; it does not type-check the missing operands.
    let bytes = wat::parse_str("(module (func i32.add drop))").unwrap();
    for profile in [
        Standard::Core1,
        Standard::Core2,
        Standard::Core3,
        Standard::AllKnown,
    ] {
        let independent = Validator::new_with_features(profile.features())
            .validate_all(&bytes)
            .err()
            .expect("missing operands must fail validation");
        let module = audit::inspect_with_standard(&bytes, profile).unwrap();
        let error = module.standard.validator_error.as_ref().unwrap();
        assert_eq!(error.offset, independent.offset());
        assert!(error.byte_context.offset_in_module);
        let span = error.byte_context.span;
        assert!(span.end <= bytes.len() && span.end - span.start <= 16);
        assert_eq!(
            error.byte_context.raw_hex,
            bytes[span.start..span.end]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert!(error
            .locations
            .iter()
            .any(|location| location.path.contains("/operator[")));
        for location in &error.locations {
            assert!(location.span.start <= location.span.end && location.span.end <= bytes.len());
            assert!(location.span.start <= error.offset && error.offset <= location.span.end);
        }
        let text = module.to_text();
        assert!(text.contains("validator raw context"));
        assert!(text.contains("not causal attribution"));
    }
}

#[test]
fn disabled_grammar_and_truncated_framing_keep_context_without_changing_edits() {
    let simd = wat::parse_str("(module (func v128.const i32x4 0 0 0 0 drop))").unwrap();
    let core1 = audit::inspect_with_standard(&simd, Standard::Core1).unwrap();
    assert!(core1.standard.validator_error.is_some());
    assert!(audit::inspect_with_standard(&simd, Standard::Core3)
        .unwrap()
        .standard
        .validator_error
        .is_none());
    let truncated = [b"\0asm\x01\0\0\0".as_slice(), &[1, 4, 1]].concat();
    let mut edits = None;
    for profile in [
        Standard::Core1,
        Standard::Core2,
        Standard::Core3,
        Standard::AllKnown,
    ] {
        let module = audit::inspect_with_standard(&truncated, profile).unwrap();
        let error = module.standard.validator_error.as_ref().unwrap();
        assert!(error.byte_context.span.end <= truncated.len());
        assert_eq!(
            error.byte_context.offset_is_eof,
            error.offset == truncated.len()
        );
        let diff = audit::compare_with_standard(&simd, &truncated, profile).unwrap();
        let serialized = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(expected) = &edits {
            assert_eq!(expected, &serialized);
        } else {
            edits = Some(serialized);
        }
    }
}
