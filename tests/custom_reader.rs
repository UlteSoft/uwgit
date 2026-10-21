//! Fixed reader views for legal custom names beyond the pinned string limit.
//! All byte edits, names, offsets and merge results refer to original bytes.
use wasm_git::{
    audit::{self, AuditModule, ByteEdit, Region, Span},
    merge,
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

struct CustomFrame {
    index: usize,
    name: Span,
    data: Span,
    display: String,
}

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

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    bytes.push(id);
    unsigned(payload.len(), bytes);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn custom(bytes: &mut Vec<u8>, index: usize, name: &str, data: &[u8]) -> CustomFrame {
    let mut payload = Vec::new();
    unsigned(name.len(), &mut payload);
    payload.extend_from_slice(name.as_bytes());
    let name_len = payload.len();
    payload.extend_from_slice(data);
    let start = section(bytes, 0, &payload);
    CustomFrame {
        index,
        name: Span {
            start,
            end: start + name_len,
        },
        data: Span {
            start: start + name_len,
            end: bytes.len(),
        },
        display: name.into(),
    }
}

fn core(bytes: &mut Vec<u8>, value: u8) -> usize {
    section(bytes, 1, &[1, 0x60, 0, 0]);
    section(bytes, 3, &[1, 0]);
    let start = section(bytes, 10, &[1, 5, 0, 0x41, value, 0x1a, 0x0b]);
    start + 4
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
    assert_eq!(module.byte_len, bytes.len());
    for entry in regions(module) {
        assert!(entry.span.start <= entry.span.end && entry.span.end <= bytes.len());
    }
    for evidence in &module.standard.evidence {
        assert!(evidence.span.start <= evidence.span.end && evidence.span.end <= bytes.len());
        assert_eq!(
            evidence.raw_hex,
            hex(&bytes[evidence.span.start..evidence.span.end])
        );
    }
}

fn replay(old: &[u8], new: &[u8], edits: &[ByteEdit]) {
    let (mut old_cursor, mut new_cursor) = (0, 0);
    let mut output = Vec::new();
    for edit in edits {
        assert!(old_cursor <= edit.old_span.start && edit.old_span.start <= edit.old_span.end);
        assert!(new_cursor <= edit.new_span.start && edit.new_span.start <= edit.new_span.end);
        assert!(edit.old_span.end <= old.len() && edit.new_span.end <= new.len());
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
        assert!(diff.changed && !diff.edits.is_empty());
        replay(old, new, &diff.edits);
        raw_spans(old, &diff.old);
        raw_spans(new, &diff.new);
        let encoded = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &expected {
            assert_eq!(previous, &encoded);
        } else {
            expected = Some(encoded);
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

fn projection(bytes: &[u8], module: &AuditModule, frames: &[CustomFrame]) {
    let projected = audit::core_reader_bytes(bytes);
    assert_eq!(projected.len(), bytes.len());
    let expected: Vec<_> = frames
        .iter()
        .filter(|frame| frame.display.len() > 100_000)
        .collect();
    let report = &module.standard.validator_input;
    assert_eq!(
        report.kind,
        if expected.is_empty() {
            "original_bytes"
        } else {
            "custom_name_projection"
        }
    );
    assert_eq!(report.projections.len(), expected.len());
    let changed: Vec<_> = bytes
        .iter()
        .zip(projected.iter())
        .enumerate()
        .filter_map(|(index, (old, new))| (old != new).then_some(index))
        .collect();
    assert_eq!(
        changed,
        expected
            .iter()
            .map(|frame| frame.name.start)
            .collect::<Vec<_>>()
    );
    for (entry, frame) in report.projections.iter().zip(expected) {
        assert_eq!(entry.path, format!("custom[{}]/name", frame.index));
        assert_eq!(entry.name_span, frame.name);
        assert_eq!(
            entry.byte_span,
            Span {
                start: frame.name.start,
                end: frame.name.start + 1,
            }
        );
        assert_eq!(
            entry.original_hex,
            hex(&bytes[frame.name.start..frame.name.start + 1])
        );
        assert_eq!(entry.projected_hex, "00");
        assert_eq!(projected[frame.name.start], 0);
    }
    for frame in frames {
        let outer = region(module, &format!("custom[{}]/name", frame.index));
        assert_eq!(outer.span, frame.name);
        assert_eq!(outer.description, frame.display);
        assert_eq!(
            region(module, &format!("custom[{}]/payload/opaque", frame.index)).span,
            frame.data
        );
    }
    raw_spans(bytes, module);
}

fn valid_with_projection(bytes: &[u8], frames: &[CustomFrame]) {
    for standard in PROFILES {
        let module = audit::inspect_with_standard(bytes, standard).unwrap();
        assert_eq!(module.validation, "valid_with_all_known_features");
        assert_eq!(module.standard.validation, "valid");
        assert!(module.standard.validator_valid && module.standard.validator_error.is_none());
        assert!(module
            .standard
            .evidence
            .iter()
            .all(|entry| entry.status == "supported"));
        projection(bytes, &module, frames);
    }
}

#[test]
fn complete_long_outer_names_use_one_byte_views_without_changing_physical_audit() {
    // Two fixed lengths, not a search around the implementation limit.
    for length in [100_001, 131_073] {
        let mut bytes = HEADER.to_vec();
        let frame = custom(&mut bytes, 0, &"n".repeat(length), &[0x31]);
        core(&mut bytes, 42);
        assert!(Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .is_err());
        valid_with_projection(&bytes, &[frame]);
        let mut changed = bytes.clone();
        changed[bytes.len() - 3] = 43;
        physical_pair(&bytes, &changed);
    }
    let mut bytes = HEADER.to_vec();
    let first = custom(&mut bytes, 0, &"a".repeat(131_073), &[1]);
    let short = custom(&mut bytes, 1, "short", &[2]);
    core(&mut bytes, 42);
    let last = custom(&mut bytes, 2, &"b".repeat(100_001), &[3]);
    let empty = custom(&mut bytes, 3, "", &[4]);
    valid_with_projection(&bytes, &[first, short, last, empty]);
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() = 5;
    physical_pair(&bytes, &changed);
}

#[test]
fn names_at_the_limit_and_legal_padded_name_lengths_keep_original_reader_bytes() {
    let mut bytes = HEADER.to_vec();
    let frame = custom(&mut bytes, 0, &"n".repeat(100_000), &[0x31]);
    core(&mut bytes, 42);
    valid_with_projection(&bytes, &[frame]);
    assert_eq!(&*audit::core_reader_bytes(&bytes), bytes);
    for payload in [
        vec![0x81, 0x80, 0x80, 0x80, 0, b'x', 0x31],
        vec![0x80, 0x80, 0x80, 0x80, 0, 0x31],
    ] {
        let mut bytes = HEADER.to_vec();
        let start = section(&mut bytes, 0, &payload);
        let name_end = start + 5 + usize::from(payload[0] == 0x81);
        core(&mut bytes, 42);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(module.validation, "valid_with_all_known_features");
            assert_eq!(module.standard.validation, "valid");
            assert_eq!(module.standard.validator_input.kind, "original_bytes");
            assert!(module.standard.validator_input.projections.is_empty());
            assert_eq!(
                region(&module, "custom[0]/name").span,
                Span {
                    start,
                    end: name_end
                }
            );
            raw_spans(&bytes, &module);
        }
        assert_eq!(&*audit::core_reader_bytes(&bytes), bytes);
        let mut changed = bytes.clone();
        changed[name_end] = 0x32;
        physical_pair(&bytes, &changed);
    }
}

#[test]
fn malformed_outer_names_unknown_sections_and_components_are_never_repaired() {
    let malformed = [
        vec![0, 2, 2, b'a'], // A bounded name cannot borrow the following type-section id.
        vec![0, 2, 1, 0xff],
        vec![0, 5, 0x80, 0x80, 0x80, 0x80, 0x10],
        vec![0, 6, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
    ];
    for suffix in malformed {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(&suffix);
        let immediate = core(&mut bytes, 42);
        assert_eq!(&*audit::core_reader_bytes(&bytes), bytes);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(module.validation, "failed_or_unsupported");
            assert_eq!(module.standard.validation, "invalid");
            assert!(!module.standard.validator_valid);
            assert_eq!(module.standard.validator_input.kind, "original_bytes");
            assert!(module.standard.validator_input.projections.is_empty());
            assert!(module.standard.evidence.iter().any(|entry| {
                entry.path == "custom[0]/outer_name" && entry.status == "invalid_encoding"
            }));
            assert!(module.standard.evidence.iter().any(|entry| {
                entry.recognized.as_deref() == Some("I32Const") && entry.raw_hex == "412a"
            }));
            raw_spans(&bytes, &module);
        }
        let mut changed = bytes.clone();
        changed[immediate] = 43;
        physical_pair(&bytes, &changed);
    }
    let mut truncated = HEADER.to_vec();
    truncated.extend_from_slice(&[0, 5, 1, b'a']);
    let mut unknown = HEADER.to_vec();
    unknown.extend_from_slice(&[14, 1, 0]);
    core(&mut unknown, 42);
    for bytes in [&truncated, &unknown] {
        assert_eq!(&*audit::core_reader_bytes(bytes), bytes.as_slice());
        for standard in PROFILES {
            let module = audit::inspect_with_standard(bytes, standard).unwrap();
            assert_eq!(module.validation, "failed_or_unsupported");
            assert_eq!(module.standard.validation, "invalid");
            assert!(!module.standard.validator_valid);
            assert_eq!(module.standard.validator_input.kind, "original_bytes");
            raw_spans(bytes, &module);
        }
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        physical_pair(bytes, &changed);
    }
    let mut component = b"\0asm\x0d\0\x01\0".to_vec();
    custom(&mut component, 0, &"c".repeat(100_001), &[1]);
    assert_eq!(&*audit::core_reader_bytes(&component), component);
    for standard in PROFILES {
        assert!(audit::inspect_with_standard(&component, standard).is_err());
    }
}

#[test]
fn core_errors_and_other_invalid_outer_names_keep_original_offsets_and_context() {
    let mut core_only = HEADER.to_vec();
    section(&mut core_only, 1, &[1, 0x60, 0, 0]);
    section(&mut core_only, 3, &[1, 0]);
    section(&mut core_only, 10, &[1, 3, 0, 0x6a, 0x0b]); // Known i32.add, missing operands.
    let mut bytes = HEADER.to_vec();
    let frame = custom(&mut bytes, 0, &"n".repeat(100_001), &[0x31]);
    let shift = bytes.len() - HEADER.len();
    bytes.extend_from_slice(&core_only[HEADER.len()..]);
    for standard in PROFILES {
        let Err(original_error) =
            Validator::new_with_features(standard.features()).validate_all(&core_only)
        else {
            panic!("fixed Core operand error must fail validation");
        };
        let projected = audit::core_reader_bytes(&bytes);
        let Err(projected_error) =
            Validator::new_with_features(standard.features()).validate_all(&projected)
        else {
            panic!("custom reader view must preserve the Core operand error");
        };
        let module = audit::inspect_with_standard(&bytes, standard).unwrap();
        assert_eq!(module.validation, "failed_or_unsupported");
        assert_eq!(module.standard.validation, "invalid");
        assert!(!module.standard.validator_valid);
        let error = module.standard.validator_error.as_ref().unwrap();
        assert_eq!(error.offset, original_error.offset() + shift);
        assert_eq!(error.offset, projected_error.offset());
        assert_eq!(error.message, projected_error.to_string());
        assert_eq!(
            error.byte_context.raw_hex,
            hex(&bytes[error.byte_context.span.start..error.byte_context.span.end])
        );
        assert!(error
            .locations
            .iter()
            .any(|location| location.path.starts_with("code[0]")));
        projection(&bytes, &module, std::slice::from_ref(&frame));
    }
    for invalid_first in [true, false] {
        let mut bytes = HEADER.to_vec();
        if invalid_first {
            section(&mut bytes, 0, &[1, 0xff]);
        }
        let frame = custom(
            &mut bytes,
            usize::from(invalid_first),
            &"n".repeat(131_073),
            &[0x31],
        );
        if !invalid_first {
            section(&mut bytes, 0, &[1, 0xff]);
        }
        let immediate = core(&mut bytes, 42);
        for standard in PROFILES {
            let module = audit::inspect_with_standard(&bytes, standard).unwrap();
            assert_eq!(module.validation, "failed_or_unsupported");
            assert_eq!(module.standard.validation, "invalid");
            assert!(!module.standard.validator_valid);
            let bad_index = usize::from(!invalid_first);
            assert!(module.standard.evidence.iter().any(|entry| {
                entry.path == format!("custom[{bad_index}]/outer_name")
                    && entry.status == "invalid_encoding"
            }));
            projection(&bytes, &module, std::slice::from_ref(&frame));
        }
        let mut changed = bytes.clone();
        changed[immediate] = 43;
        physical_pair(&bytes, &changed);
    }
}

fn named_module(name: &str, payload: u8, value: u8, duplicate: bool) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    custom(&mut bytes, 0, name, &[payload]);
    if duplicate {
        custom(&mut bytes, 1, name, &[0x51]);
    }
    core(&mut bytes, value);
    bytes
}

#[test]
fn synthesis_preserves_full_long_name_identity_instead_of_projected_empty_names() {
    let name = "n".repeat(100_001);
    let base = named_module(&name, 1, 1, false);
    let ours = named_module(&name, 2, 1, false);
    let theirs = named_module(&name, 1, 2, false);
    let expected = named_module(&name, 2, 2, false);
    for (left, right) in [(&ours, &theirs), (&theirs, &ours)] {
        let report = merge::merge(&base, left, right).unwrap();
        assert_eq!(report.status, "clean");
        assert_eq!(report.validation, "valid_with_all_known_features");
        assert!(report.conflicts.is_empty());
        let result = report.bytes.unwrap();
        assert_eq!(result, expected);
        let module = audit::inspect(&result).unwrap();
        assert_eq!(region(&module, "custom[0]/name").description, name);
        assert_eq!(module.standard.validation, "valid");
        assert_eq!(
            module.standard.validator_input.kind,
            "custom_name_projection"
        );
    }
    physical_pair(&base, &expected);
    // These legal names share their first 100,000 bytes and differ only at the end.
    let mut renamed = name.clone();
    renamed.replace_range(100_000.., "m");
    let renamed_ours = named_module(&renamed, 2, 1, false);
    let duplicate_base = named_module(&name, 1, 1, true);
    let duplicate_ours = named_module(&name, 2, 1, true);
    let duplicate_theirs = named_module(&name, 1, 2, true);
    for (ancestor, left, right) in [
        (&base, &renamed_ours, &theirs),
        (&duplicate_base, &duplicate_ours, &duplicate_theirs),
    ] {
        for (left, right) in [(left, right), (right, left)] {
            let report = merge::merge(ancestor, left, right).unwrap();
            assert_eq!(report.status, "conflict");
            assert!(report.bytes.is_none() && report.framing_fixups.is_empty());
            assert!(report.conflicts.iter().any(|conflict| {
                conflict.path == "custom[0]" && conflict.reason.contains("custom section identity")
            }));
        }
    }
}
