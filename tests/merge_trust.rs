//! Fixed final-output trust checks for synthesized merges; no input search.
use wasm_git::{
    audit::{self, AuditModule, ByteEdit, Span},
    merge::{self, MergeReport},
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

fn unsigned(mut value: u32, bytes: &mut Vec<u8>) {
    loop {
        let byte = value as u8 & 0x7f;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    bytes.push(id);
    unsigned(payload.len() as u32, bytes);
    bytes.extend_from_slice(payload);
}

fn function_types(count: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    unsigned(count, &mut payload);
    // The count128 call constructs the explicit index127 fixture, not a search.
    for _ in 0..count {
        payload.extend_from_slice(&[0x60, 0, 0]);
    }
    payload
}

fn global(index: &[u8], explicit: bool) -> Vec<u8> {
    let mut payload = vec![1];
    if explicit {
        payload.push(0x63);
    }
    payload.extend_from_slice(index);
    payload.extend_from_slice(&[0, 0xd0]); // Immutable; a legitimate heap index.
    payload.extend_from_slice(index);
    payload.push(0x0b);
    payload
}

fn constants(first: u8, second: u8) -> Vec<u8> {
    vec![0, 0x41, first, 0x1a, 0x41, second, 0x1a, 0x0b]
}

fn indexed_constants(first: u8, second: u8) -> Vec<u8> {
    let mut body = vec![
        0, 0x02, 0xff, 0x80, 0, // Block type127 with legal signed padding.
        1, 0x0b, 0xd0, 0xff, 0, 0x1a, // A legitimate heap type127.
    ];
    body.extend_from_slice(&[0x41, first, 0x1a, 0x41, second, 0x1a, 0x0b]);
    body
}

fn module(types: &[u8], global: Option<&[u8]>, body: &[u8], custom: [u8; 2]) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    section(&mut bytes, 1, types);
    section(&mut bytes, 3, &[1, 0]);
    if let Some(global) = global {
        section(&mut bytes, 6, global);
    }
    let mut code = vec![1];
    unsigned(body.len() as u32, &mut code);
    code.extend_from_slice(body);
    section(&mut bytes, 10, &code);
    // Unique, well-framed names with deliberately opaque payload conventions.
    section(&mut bytes, 0, &[1, b'x', custom[0]]);
    section(&mut bytes, 0, &[1, b'y', custom[1]]);
    bytes
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

fn replay(old: &[u8], new: &[u8], edits: &[ByteEdit]) {
    let mut output = Vec::new();
    let (mut old_cursor, mut new_cursor) = (0, 0);
    for edit in edits {
        assert!(old_cursor <= edit.old_span.start && edit.old_span.end <= old.len());
        assert!(new_cursor <= edit.new_span.start && edit.new_span.end <= new.len());
        assert!(edit.old_span.start <= edit.old_span.end);
        assert!(edit.new_span.start <= edit.new_span.end);
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
        assert_eq!(diff.changed, old != new);
        replay(old, new, &diff.edits);
        for (bytes, module) in [(old, &diff.old), (new, &diff.new)] {
            for evidence in &module.standard.evidence {
                assert!(evidence.span.start <= evidence.span.end);
                assert!(evidence.span.end <= bytes.len());
                assert_eq!(
                    evidence.raw_hex,
                    hex(&bytes[evidence.span.start..evidence.span.end])
                );
            }
        }
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

fn permissive_but_untrusted(bytes: &[u8]) -> AuditModule {
    assert!(Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .is_ok());
    let module = audit::inspect(bytes).unwrap();
    assert!(module.standard.validator_valid);
    assert_eq!(module.validation, "failed_or_unsupported");
    assert_eq!(module.standard.validation, "invalid");
    module
}

fn synthesis_conflict(base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeReport {
    let report = merge::merge(base, ours, theirs).unwrap();
    assert_eq!(report.status, "conflict", "{report:?}");
    assert_eq!(report.validation, "failed_or_unsupported");
    assert!(report.bytes.is_none());
    assert!(report.framing_fixups.is_empty());
    assert_eq!(report.conflicts.len(), 1, "{report:?}");
    let conflict = &report.conflicts[0];
    assert_eq!(conflict.path, "module/validation");
    for (bytes, evidence) in
        [base, ours, theirs]
            .into_iter()
            .zip([&conflict.base, &conflict.ours, &conflict.theirs])
    {
        assert_eq!(
            evidence.span,
            Span {
                start: 0,
                end: bytes.len()
            }
        );
        assert_eq!(
            evidence.hex,
            hex(&bytes[evidence.span.start..evidence.span.end])
        );
    }
    report
}

fn clean(base: &[u8], ours: &[u8], theirs: &[u8], expected: &[u8]) -> MergeReport {
    let report = merge::merge(base, ours, theirs).unwrap();
    assert_eq!(report.status, "clean", "{report:?}");
    assert_eq!(report.validation, "valid_with_all_known_features");
    assert!(report.conflicts.is_empty());
    assert_eq!(report.bytes.as_deref(), Some(expected));
    for fixup in &report.framing_fixups {
        assert!(fixup.output_span.start <= fixup.output_span.end);
        assert!(fixup.output_span.end <= expected.len());
        assert_eq!(
            fixup.hex,
            hex(&expected[fixup.output_span.start..fixup.output_span.end])
        );
    }
    assert_eq!(
        audit::inspect(expected).unwrap().validation,
        "valid_with_all_known_features"
    );
    report
}

#[test]
fn decoded_bare_global_type_cannot_survive_concurrent_instruction_synthesis() {
    let types = function_types(1);
    let global = global(&[0], false);
    let fixture = |a, b| module(&types, Some(&global), &constants(a, b), [0x10, 0x20]);
    let (base, ours, theirs, combined) =
        (fixture(1, 2), fixture(3, 2), fixture(1, 4), fixture(3, 4));
    for bytes in [&base, &ours, &theirs, &combined] {
        let audited = permissive_but_untrusted(bytes);
        assert_eq!(
            audited
                .sections
                .iter()
                .find(|section| section.id == 6)
                .unwrap()
                .status,
            "decoded"
        );
        assert!(audited.standard.evidence.iter().any(|evidence| {
            evidence.path == "global[0]/entry[0]" && evidence.status == "invalid_encoding"
        }));
    }
    for (left, right) in [(&ours, &theirs), (&theirs, &ours)] {
        let report = synthesis_conflict(&base, left, right);
        assert!(report
            .decisions
            .iter()
            .any(|decision| decision.path.ends_with("/operator[0]")));
        assert!(report
            .decisions
            .iter()
            .any(|decision| decision.path.ends_with("/operator[2]")));
    }
    physical_pair(&base, &combined);
}

#[test]
fn unchanged_untrusted_type_also_blocks_atomic_custom_section_synthesis() {
    // Type0 is complete. Unused type1 has a bare positive0 with signed padding.
    let types = [2, 0x60, 0, 0, 0x60, 1, 0x80, 0, 0];
    let fixture = |custom| module(&types, None, &constants(1, 2), custom);
    let (base, ours, theirs, combined) = (
        fixture([0x10, 0x20]),
        fixture([0x30, 0x20]),
        fixture([0x10, 0x40]),
        fixture([0x30, 0x40]),
    );
    for bytes in [&base, &ours, &theirs, &combined] {
        let audited = permissive_but_untrusted(bytes);
        assert_eq!(audited.sections[0].status, "partially_decoded");
        assert!(audited.sections[0].regions.iter().any(|region| {
            region.path == "type[0]/undecoded"
                && region.feature.as_deref() == Some("unknown_declaration_type")
        }));
    }
    for (left, right) in [(&ours, &theirs), (&theirs, &ours)] {
        let report = synthesis_conflict(&base, left, right);
        assert_eq!(report.decisions.len(), 2);
        assert!(report
            .decisions
            .iter()
            .all(|decision| decision.path.starts_with("custom[")));
    }
    physical_pair(&base, &combined);
}

#[test]
fn complete_heap_index127_does_not_prove_an_unknown_global_constructor() {
    let types = function_types(128);
    let global = global(&[0xff, 0], false);
    let fixture = |a, b| module(&types, Some(&global), &constants(a, b), [0x10, 0x20]);
    let (base, ours, theirs, combined) =
        (fixture(1, 2), fixture(3, 2), fixture(1, 4), fixture(3, 4));
    for bytes in [&base, &ours, &theirs, &combined] {
        let audited = permissive_but_untrusted(bytes);
        let global = audited
            .sections
            .iter()
            .find(|section| section.id == 6)
            .unwrap();
        assert_eq!(global.status, "partially_decoded");
        let frontier = global
            .regions
            .iter()
            .find(|region| region.path == "global[0]/undecoded")
            .unwrap();
        assert_eq!(
            frontier.feature.as_deref(),
            Some("unknown_declaration_type")
        );
        assert_eq!(
            &bytes[frontier.children[0].span.start..frontier.children[0].span.end],
            &[0xff]
        );
        assert!(audited
            .standard
            .evidence
            .iter()
            .any(|evidence| { evidence.path == frontier.path && evidence.status == "unknown" }));
    }
    synthesis_conflict(&base, &ours, &theirs);
    synthesis_conflict(&base, &theirs, &ours);
    physical_pair(&base, &combined);
}

#[test]
fn whole_module_equality_choices_keep_every_invalid_or_unknown_input_byte() {
    let types0 = function_types(1);
    let types127 = function_types(128);
    let padded_type = [2, 0x60, 0, 0, 0x60, 1, 0x80, 0, 0];
    let bare0 = global(&[0], false);
    let bare127 = global(&[0xff, 0], false);
    let fixtures = [
        (
            module(&types0, Some(&bare0), &constants(1, 2), [0x10, 0x20]),
            module(&types0, Some(&bare0), &constants(3, 4), [0x30, 0x40]),
        ),
        (
            module(&padded_type, None, &constants(1, 2), [0x10, 0x20]),
            module(&padded_type, None, &constants(3, 4), [0x30, 0x40]),
        ),
        (
            module(&types127, Some(&bare127), &constants(1, 2), [0x10, 0x20]),
            module(&types127, Some(&bare127), &constants(3, 4), [0x30, 0x40]),
        ),
    ];
    for (a, b) in &fixtures {
        permissive_but_untrusted(a);
        permissive_but_untrusted(b);
        let (a, b) = (a.as_slice(), b.as_slice());
        // All eight fixed equality layouts; each expected source is explicit.
        for (base, ours, theirs, expected) in [
            (a, a, a, a),
            (a, a, b, b),
            (a, b, a, b),
            (a, b, b, b),
            (b, a, a, a),
            (b, a, b, a),
            (b, b, a, a),
            (b, b, b, b),
        ] {
            let report = merge::merge(base, ours, theirs).unwrap();
            assert_eq!(report.status, "clean", "{report:?}");
            assert_eq!(report.validation, "failed_or_unsupported");
            assert_eq!(report.bytes.as_deref(), Some(expected));
            assert!(report.conflicts.is_empty());
            assert!(report.framing_fixups.is_empty());
            assert_eq!(report.decisions.len(), 1);
            assert_eq!(report.decisions[0].path, "module");
        }
    }
}

#[test]
fn trusted_synthesis_preserves_explicit_indices_opaque_custom_and_a_repaired_body() {
    let types = function_types(128);
    let explicit = global(&[0xff, 0], true);
    let fixture = |a, b| {
        module(
            &types,
            Some(&explicit),
            &indexed_constants(a, b),
            [0x10, 0x20],
        )
    };
    let (base, ours, theirs, expected) =
        (fixture(1, 2), fixture(3, 2), fixture(1, 4), fixture(3, 4));
    for bytes in [&base, &ours, &theirs, &expected] {
        assert!(Validator::new_with_features(WasmFeatures::all())
            .validate_all(bytes)
            .is_ok());
        let audited = audit::inspect(bytes).unwrap();
        assert!(audited
            .sections
            .iter()
            .filter(|section| section.id != 0)
            .all(|section| section.status == "decoded"));
        assert!(!audited
            .standard
            .evidence
            .iter()
            .any(|evidence| matches!(evidence.status.as_str(), "unknown" | "invalid_encoding")));
    }
    let report = clean(&base, &ours, &theirs, &expected);
    assert_eq!(report.framing_fixups.len(), 2);
    clean(&base, &theirs, &ours, &expected);
    physical_pair(&base, &expected);

    let types = function_types(1);
    let body = constants(1, 2);
    let fixture = |custom| module(&types, None, &body, custom);
    let (base, ours, theirs, expected) = (
        fixture([0x10, 0x20]),
        fixture([0x30, 0x20]),
        fixture([0x10, 0x40]),
        fixture([0x30, 0x40]),
    );
    let report = clean(&base, &ours, &theirs, &expected);
    assert!(report.framing_fixups.is_empty());
    assert_eq!(report.decisions.len(), 2);
    assert!(audit::inspect(&expected)
        .unwrap()
        .sections
        .iter()
        .filter(|section| section.id == 0)
        .all(|section| section.status == "opaque"));
    physical_pair(&base, &expected);

    let mut unknown_body = body.clone();
    unknown_body[1] = 0xff; // Preserve the body frame, but remove a known opcode.
    let base = module(&types, None, &unknown_body, [0x10, 0x20]);
    let ours = module(&types, None, &body, [0x10, 0x20]);
    let theirs = module(&types, None, &unknown_body, [0x30, 0x20]);
    let expected = module(&types, None, &body, [0x30, 0x20]);
    for bytes in [&base, &theirs] {
        let audited = audit::inspect(bytes).unwrap();
        assert_eq!(audited.validation, "failed_or_unsupported");
        assert!(audited
            .sections
            .iter()
            .any(|section| section.id == 10 && section.status != "decoded"));
    }
    let report = clean(&base, &ours, &theirs, &expected);
    assert!(report.framing_fixups.is_empty());
    assert!(report
        .decisions
        .iter()
        .any(|decision| decision.path == "code[0]" && decision.source == "ours"));
    assert!(report
        .decisions
        .iter()
        .any(|decision| decision.path == "custom[0]" && decision.source == "theirs"));
    clean(&base, &theirs, &ours, &expected);
    physical_pair(&base, &expected);
}
