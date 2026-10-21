//! Finite literal length requests for the vendored wasmparser 0.249.0 reader.
//! No large buffer is allocated, no panic is caught, and no Wasm is executed.
//!
//! Source oracle: BinaryReader::read_bytes checks ensure_has_bytes before moving
//! its cursor; read_reader and read_unlimited_string first consume a u32 length.
//! FunctionBody and Data both use read_reader. Data validation happens only
//! after a complete item is read, so a prior valid passive item can make Core1
//! validation stop before the later forged length. Physical audit still reaches
//! that later bounded field independently.

use wasm_git::{
    audit::{self, AuditModule, Region, Span},
    patch::BytePatch,
    standard::Standard,
};
use wasmparser::{BinaryReader, BinaryReaderError, Validator};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const CUSTOM: &[u8] = &[0, 3, 1, b'x', 0xa5];
const MAX: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0x0f];
const MAX_MINUS_ONE: &[u8] = &[0xfe, 0xff, 0xff, 0xff, 0x0f];
const PADDED_ONE: &[u8] = &[0x81, 0x80, 0x80, 0x80, 0];
const EOF_REASON: &str = "known encoding is truncated at its trusted input boundary";
const PASSIVE_ERROR: &str = "passive data segments require the bulk-memory proposal";
const ALL: [bool; 4] = [true; 4];
const CORE2: [bool; 4] = [false, true, true, true];
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Area {
    Code,
    Data,
}

impl Area {
    fn section(self) -> &'static str {
        match self {
            Self::Code => "code[0]",
            Self::Data => "data[0]",
        }
    }

    fn field(self) -> &'static str {
        match self {
            Self::Code => "function body bytes",
            Self::Data => "data bytes",
        }
    }

    fn error_path(self) -> &'static str {
        match self {
            Self::Code => "code[0]/undecoded/code_error",
            Self::Data => "data[0]/undecoded/data_error",
        }
    }

    fn entry_path(self, index: usize) -> String {
        match self {
            Self::Code => format!("code[0]/function[{index}]"),
            Self::Data => format!("data[0]/entry[{index}]"),
        }
    }
}

#[derive(Clone, Copy)]
enum DataForm {
    Passive,
    Active,
    ExplicitMemoryZero,
}

impl DataForm {
    fn prefix(self) -> &'static [u8] {
        match self {
            Self::Passive => &[1],
            Self::Active => &[0, 0x41, 0, 0x0b],
            Self::ExplicitMemoryZero => &[2, 0, 0x41, 0, 0x0b],
        }
    }
}

struct Failure {
    area: Area,
    target_index: usize,
    entry: Span,
    contents: Span,
    prior_passive: Option<usize>,
}

struct Fixture {
    bytes: Vec<u8>,
    failure: Failure,
    size: Span,
    prior: Option<Span>,
    function: Span,
    constant: Span,
    custom: Span,
}

fn unhex(value: &str) -> Vec<u8> {
    let (pairs, rest) = value.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) -> usize {
    assert!(payload.len() < 128);
    bytes.extend_from_slice(&[id, payload.len() as u8]);
    let start = bytes.len();
    bytes.extend_from_slice(payload);
    start
}

fn custom(bytes: &mut Vec<u8>) -> Span {
    let start = bytes.len();
    bytes.extend_from_slice(CUSTOM);
    Span {
        start,
        end: bytes.len(),
    }
}

fn code_fixture(size: &[u8], contents: &[u8]) -> Fixture {
    // One empty function type and two defined functions. The first complete
    // body is fixed: no locals; i32.const 42; drop; end.
    let mut bytes = unhex("0061736d010000000104016000000303020000");
    let mut payload = vec![2, 5, 0, 0x41, 42, 0x1a, 0x0b];
    payload.extend_from_slice(size);
    payload.extend_from_slice(contents);
    let start = section(&mut bytes, 10, &payload);
    let entry = Span {
        start: start + 7,
        end: bytes.len(),
    };
    let size = Span {
        start: entry.start,
        end: entry.start + size.len(),
    };
    let contents = Span {
        start: size.end,
        end: entry.end,
    };
    let custom = custom(&mut bytes);
    let function = Span {
        start: start + 1,
        end: start + 7,
    };
    Fixture {
        bytes,
        failure: Failure {
            area: Area::Code,
            target_index: 1,
            entry,
            contents,
            prior_passive: None,
        },
        size,
        prior: Some(function),
        function,
        constant: Span {
            start: start + 3,
            end: start + 5,
        },
        custom,
    }
}

fn data_fixture(form: DataForm, size: &[u8], contents: &[u8], prior_passive: bool) -> Fixture {
    // One MVP memory and one independently framed, complete MVP function.
    let mut bytes = unhex("0061736d010000000104016000000302010005030100010a07010500412a1a0b");
    let mut payload = if prior_passive {
        vec![2, 1, 1, 0xa5]
    } else {
        vec![1]
    };
    let relative_entry = payload.len();
    payload.extend_from_slice(form.prefix());
    let relative_size = payload.len();
    payload.extend_from_slice(size);
    let relative_contents = payload.len();
    payload.extend_from_slice(contents);
    let start = section(&mut bytes, 11, &payload);
    let entry = Span {
        start: start + relative_entry,
        end: bytes.len(),
    };
    let size = Span {
        start: start + relative_size,
        end: start + relative_contents,
    };
    let contents = Span {
        start: size.end,
        end: entry.end,
    };
    let custom = custom(&mut bytes);
    Fixture {
        bytes,
        failure: Failure {
            area: Area::Data,
            target_index: usize::from(prior_passive),
            entry,
            contents,
            prior_passive: prior_passive.then_some(start + 1),
        },
        size,
        prior: prior_passive.then_some(Span {
            start: start + 1,
            end: start + 4,
        }),
        function: Span { start: 26, end: 32 },
        constant: Span { start: 28, end: 30 },
        custom,
    }
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

fn at<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    regions(module)
        .into_iter()
        .find(|entry| entry.path == path)
        .unwrap_or_else(|| panic!("missing physical region {path}"))
}

fn raw_bounds(module: &AuditModule, bytes: &[u8]) {
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
    if let Some(error) = &module.standard.validator_error {
        let context = &error.byte_context;
        assert!(context.span.start <= context.span.end && context.span.end <= bytes.len());
        assert_eq!(
            context.raw_hex,
            hex(&bytes[context.span.start..context.span.end])
        );
    }
}

fn framing_survives(fixture: &Fixture, module: &AuditModule) {
    raw_bounds(module, &fixture.bytes);
    let function = at(module, "code[0]/function[0]");
    assert_eq!(function.span, fixture.function);
    let constant = at(module, "code[0]/function[0]/operator[0]");
    assert_eq!(constant.span, fixture.constant);
    assert_eq!(constant.description, "I32Const { value: 42 }");
    assert_eq!(constant.standard_support.status, "supported");
    assert_eq!(
        &fixture.bytes[constant.span.start..constant.span.end],
        &[0x41, 42]
    );
    if let Some(span) = fixture.prior {
        assert_eq!(at(module, &fixture.failure.area.entry_path(0)).span, span);
    }
    let custom = module.sections.last().unwrap();
    assert_eq!(custom.id, 0);
    assert_eq!(custom.kind, "custom:x");
    assert_eq!(custom.status, "opaque");
    assert_eq!(custom.span, fixture.custom);
    assert_eq!(
        at(module, "custom[0]/name").span,
        Span {
            start: fixture.custom.start + 2,
            end: fixture.custom.start + 4,
        }
    );
    let data = at(module, "custom[0]/payload/opaque");
    assert_eq!(
        data.span,
        Span {
            start: fixture.custom.start + 4,
            end: fixture.custom.end,
        }
    );
    assert_eq!(&fixture.bytes[data.span.start..data.span.end], &[0xa5]);
}

fn eof(error: &BinaryReaderError, offset: usize) {
    assert_eq!(error.message(), "unexpected end-of-file");
    assert_eq!(error.offset(), offset);
}

fn failed_length(bytes: &[u8], failure: &Failure, profile: Standard, module: &AuditModule) {
    raw_bounds(module, bytes);
    assert_eq!(module.validation, "failed_or_unsupported");
    assert_eq!(module.standard.validation, "invalid");
    assert!(!module.standard.validator_valid);
    let carrier_path = format!("{}/undecoded", failure.area.section());
    let carrier = at(module, &carrier_path);
    assert_eq!(carrier.span, failure.entry);
    assert_eq!(carrier.standard_support.status, "invalid_encoding");
    assert_eq!(carrier.children.len(), 1);
    let field = at(module, failure.area.error_path());
    assert_eq!(field.span, failure.contents);
    assert_eq!(field.feature.as_deref(), Some("invalid_encoding"));
    assert_eq!(field.standard_support.status, "invalid_encoding");
    assert_eq!(field.standard_support.display, "binary");
    assert!(field.children.is_empty());
    assert_eq!(
        field.description,
        format!(
            "{}: {EOF_REASON}; only this field is diagnosed, remaining bytes stay undecoded",
            failure.area.field()
        )
    );
    let evidence: Vec<_> = module
        .standard
        .evidence
        .iter()
        .filter(|entry| entry.path == field.path)
        .collect();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status, "invalid_encoding");
    assert_eq!(evidence[0].recognized, None);
    assert_eq!(evidence[0].span, failure.contents);
    assert_eq!(
        evidence[0].raw_hex,
        hex(&bytes[failure.contents.start..failure.contents.end])
    );
    assert_eq!(evidence[0].reason, field.description);
    let unpublished = failure.area.entry_path(failure.target_index);
    assert!(!regions(module).iter().any(|entry| {
        entry.path == unpublished || entry.path.starts_with(&format!("{unpublished}/"))
    }));
    let diagnostic: Vec<_> = module
        .diagnostics
        .iter()
        .filter(|entry| entry.code == "core_decode")
        .collect();
    assert_eq!(diagnostic.len(), 1);
    assert_eq!(diagnostic[0].offset, failure.contents.start);
    assert_eq!(
        diagnostic[0].message,
        format!(
            "unexpected end-of-file (at offset 0x{:x})",
            failure.contents.start
        )
    );
    let actual = Validator::new_with_features(profile.features())
        .validate_all(bytes)
        .err()
        .expect("forged bounded byte request must not validate");
    let selected = module.standard.validator_error.as_ref().unwrap();
    if let Some(offset) = failure.prior_passive.filter(|_| profile == Standard::Core1) {
        // The earlier valid passive segment is rejected before the validator
        // reads the forged item. The audit's local EOF is still independently
        // located above; do not invent an EOF as this validator's first error.
        assert_eq!(actual.message(), PASSIVE_ERROR);
        assert_eq!(actual.offset(), offset);
    } else {
        eof(&actual, failure.contents.start);
    }
    assert_eq!(selected.offset, actual.offset());
    assert_eq!(selected.message, actual.to_string());
}

fn patch_pair(old: &[u8], new: &[u8]) {
    for (before, after) in [(old, new), (new, old)] {
        let patch = wasm_git::patch::create(before, after).unwrap();
        let decoded = BytePatch::from_bytes(&patch.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded.apply(before).unwrap(), after);
    }
}

fn small_edit(fixture: &Fixture) {
    let immediate = fixture.constant.start + 1;
    assert_eq!(fixture.bytes[immediate], 42);
    let mut changed = fixture.bytes.clone();
    changed[immediate] = 43;
    let span = Span {
        start: immediate,
        end: immediate + 1,
    };
    let mut prior_edits = None;
    for profile in PROFILES {
        let diff = audit::compare_with_standard(&fixture.bytes, &changed, profile).unwrap();
        assert!(diff.changed && diff.exact_minimal);
        assert_eq!(diff.edits.len(), 1);
        assert_eq!(diff.edits[0].old_span, span);
        assert_eq!(diff.edits[0].new_span, span);
        assert_eq!(diff.edits[0].old_hex, "2a");
        assert_eq!(diff.edits[0].new_hex, "2b");
        raw_bounds(&diff.old, &fixture.bytes);
        raw_bounds(&diff.new, &changed);
        let edits = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &prior_edits {
            assert_eq!(&edits, previous);
        } else {
            prior_edits = Some(edits);
        }
    }
    patch_pair(&fixture.bytes, &changed);
}

#[test]
fn exact_minimal_code_and_data_maximum_lengths_return_eof() {
    // The MAX cases are the retained i686 panic reproducers, unchanged.
    for (wire, area, entry, offset) in [
        (
            "0061736d01000000010401600000030201000a0601ffffffff0f",
            Area::Code,
            Span { start: 21, end: 26 },
            26,
        ),
        (
            "0061736d01000000010401600000030201000a0601feffffff0f",
            Area::Code,
            Span { start: 21, end: 26 },
            26,
        ),
        (
            "0061736d010000000b070101ffffffff0f",
            Area::Data,
            Span { start: 11, end: 17 },
            17,
        ),
        (
            "0061736d010000000b070101feffffff0f",
            Area::Data,
            Span { start: 11, end: 17 },
            17,
        ),
    ] {
        let bytes = unhex(wire);
        assert_eq!(bytes.len(), offset);
        let failure = Failure {
            area,
            target_index: 0,
            entry,
            contents: Span {
                start: offset,
                end: offset,
            },
            prior_passive: None,
        };
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&bytes, profile).unwrap();
            failed_length(&bytes, &failure, profile, &module);
        }
        patch_pair(HEADER, &bytes);
    }
}

#[test]
fn oversized_code_and_all_three_data_forms_keep_complete_prefixes_and_custom_tail() {
    for size in [MAX, MAX_MINUS_ONE] {
        let code = code_fixture(size, &[0xa5]);
        assert_eq!(&code.bytes[code.size.start..code.size.end], size);
        for profile in PROFILES {
            let module = audit::inspect_with_standard(&code.bytes, profile).unwrap();
            framing_survives(&code, &module);
            failed_length(&code.bytes, &code.failure, profile, &module);
        }
        small_edit(&code);
        for form in [
            DataForm::Passive,
            DataForm::Active,
            DataForm::ExplicitMemoryZero,
        ] {
            let data = data_fixture(form, size, &[0xa5], true);
            assert_eq!(&data.bytes[data.size.start..data.size.end], size);
            for profile in PROFILES {
                let module = audit::inspect_with_standard(&data.bytes, profile).unwrap();
                framing_survives(&data, &module);
                failed_length(&data.bytes, &data.failure, profile, &module);
            }
            small_edit(&data);
        }
    }
}

fn complete(fixture: &Fixture, validator: [bool; 4], compatibility: [bool; 4]) {
    for (index, profile) in PROFILES.into_iter().enumerate() {
        let actual = Validator::new_with_features(profile.features()).validate_all(&fixture.bytes);
        assert_eq!(actual.is_ok(), validator[index]);
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        framing_survives(fixture, &module);
        assert_eq!(module.validation, "valid_with_all_known_features");
        assert_eq!(module.standard.validator_valid, validator[index]);
        assert_eq!(
            module.standard.validation,
            if compatibility[index] {
                "valid"
            } else {
                "invalid"
            }
        );
        if let Some(error) = actual.err() {
            assert_eq!(error.message(), PASSIVE_ERROR);
            assert_eq!(error.offset(), fixture.failure.entry.start);
        }
        let path = fixture
            .failure
            .area
            .entry_path(fixture.failure.target_index);
        let entry = at(&module, &path);
        assert_eq!(entry.span, fixture.failure.entry);
        assert!(!regions(&module).iter().any(|entry| {
            entry.path == fixture.failure.area.error_path() || entry.path.ends_with("/locals_error")
        }));
        match fixture.failure.area {
            Area::Code => {
                let target = "code[0]/function[1]";
                assert_eq!(
                    at(&module, &format!("{target}/body_size")).span,
                    fixture.size
                );
                assert_eq!(
                    at(&module, &format!("{target}/operator[0]")).span,
                    Span {
                        start: fixture.failure.contents.start + 1,
                        end: fixture.failure.contents.end,
                    }
                );
            }
            Area::Data => {
                let path = format!("{}/bytes", fixture.failure.area.entry_path(0));
                assert_eq!(at(&module, &path).span, fixture.failure.contents);
                assert_eq!(
                    at(&module, &path).description,
                    format!(
                        "data bytes={}",
                        fixture.failure.contents.end - fixture.failure.contents.start
                    )
                );
            }
        }
    }
    small_edit(fixture);
}

#[test]
fn complete_short_and_padded_sizes_preserve_zero_data_and_wire_compatibility() {
    complete(&code_fixture(&[2], &[0, 0x0b]), ALL, ALL);
    complete(
        &code_fixture(&[0x82, 0x80, 0x80, 0x80, 0], &[0, 0x0b]),
        ALL,
        ALL,
    );
    for (form, validator, compatibility) in [
        (DataForm::Passive, CORE2, CORE2),
        (DataForm::Active, ALL, ALL),
        // The validator normalizes explicit memory zero to the same active
        // segment as flags=0. Historical Core1 wire compatibility still fails.
        (DataForm::ExplicitMemoryZero, ALL, CORE2),
    ] {
        for (size, contents) in [
            (&[0][..], &[][..]),
            (&[1][..], &[0xa5][..]),
            (PADDED_ONE, &[0xa5][..]),
        ] {
            complete(
                &data_fixture(form, size, contents, false),
                validator,
                compatibility,
            );
        }
    }
}

#[test]
fn zero_code_count_is_valid_but_zero_body_size_only_proves_an_empty_frame() {
    let bytes = unhex("0061736d010000000a010000030178a5");
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&bytes, profile).unwrap();
        raw_bounds(&module, &bytes);
        assert!(Validator::new_with_features(profile.features())
            .validate_all(&bytes)
            .is_ok());
        assert_eq!(module.standard.validation, "valid");
        assert!(module.standard.validator_valid);
        assert_eq!(at(&module, "code[0]/count").description, "0");
        assert!(!regions(&module)
            .iter()
            .any(|entry| entry.path.contains("/function[")));
        assert_eq!(module.sections.last().unwrap().kind, "custom:x");
    }
    patch_pair(HEADER, &bytes);

    let fixture = code_fixture(&[0], &[]);
    for profile in PROFILES {
        let module = audit::inspect_with_standard(&fixture.bytes, profile).unwrap();
        framing_survives(&fixture, &module);
        assert_eq!(module.standard.validation, "invalid");
        assert!(!module.standard.validator_valid);
        let frame = at(&module, "code[0]/function[1]");
        assert_eq!(frame.span, fixture.failure.entry);
        assert_eq!(
            at(&module, "code[0]/function[1]/body_size").span,
            fixture.size
        );
        let failure = at(&module, "code[0]/function[1]/opaque/locals_error");
        assert_eq!(failure.span, fixture.failure.contents);
        assert!(failure.description.starts_with("local declaration count:"));
        assert!(!regions(&module)
            .iter()
            .any(|entry| entry.path == Area::Code.error_path()));
        let error = Validator::new_with_features(profile.features())
            .validate_all(&fixture.bytes)
            .err()
            .expect("zero-byte function has no locals count or End");
        eof(&error, fixture.failure.contents.start);
    }
    small_edit(&fixture);
}

#[test]
fn direct_byte_and_length_prefixed_readers_reject_maximum_requests_at_the_cursor() {
    for size in [u32::MAX as usize, u32::MAX as usize - 1, usize::MAX] {
        let mut reader = BinaryReader::new(&[0xaa, 0xbb, 0xcc], 64);
        assert_eq!(reader.read_u8().unwrap(), 0xaa);
        eof(&reader.read_bytes(size).unwrap_err(), 65);
        assert_eq!(reader.original_position(), 65);
        assert_eq!(reader.bytes_remaining(), 2);
        assert_eq!(reader.read_bytes(2).unwrap(), &[0xbb, 0xcc]);
    }
    for length in [MAX, MAX_MINUS_ONE] {
        let mut bytes = vec![0xaa];
        bytes.extend_from_slice(length);
        bytes.push(b'x');
        let mut reader = BinaryReader::new(&bytes, 64);
        reader.read_u8().unwrap();
        eof(&reader.read_reader().unwrap_err(), 70);
        assert_eq!(reader.original_position(), 70);
        assert_eq!(reader.read_u8().unwrap(), b'x');

        let mut reader = BinaryReader::new(&bytes, 64);
        reader.read_u8().unwrap();
        eof(&reader.read_unlimited_string().unwrap_err(), 70);
        assert_eq!(reader.original_position(), 70);
        assert_eq!(reader.read_u8().unwrap(), b'x');
    }
}

#[test]
fn direct_zero_short_and_padded_lengths_remain_readable() {
    let bytes = &[0, 1, b'x', 0x81, 0x80, 0x80, 0x80, 0, b'y'];
    let mut reader = BinaryReader::new(bytes, 64);
    assert_eq!(reader.read_bytes(0).unwrap(), &[] as &[u8]);
    assert_eq!(reader.original_position(), 64);
    for (start, end, contents) in [(65, 65, &[][..]), (66, 67, &b"x"[..]), (72, 73, &b"y"[..])] {
        let mut child = reader.read_reader().unwrap();
        assert_eq!(child.range(), start..end);
        assert_eq!(child.read_bytes(contents.len()).unwrap(), contents);
        assert!(child.eof());
    }
    assert!(reader.eof());
    let mut reader = BinaryReader::new(bytes, 64);
    for expected in ["", "x", "y"] {
        assert_eq!(reader.read_unlimited_string().unwrap(), expected);
    }
    assert!(reader.eof());
}
