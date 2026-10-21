#![no_main]

//! Coverage-guided lossless audit properties; no Wasm is executed.
//!
//! Envelope: u16 little-endian split selector, followed by two concatenated
//! arbitrary payloads. The selector modulo (payload length + 1) divides them.
//! Each side receives a fixed eight-byte Core header. Inputs shorter than two
//! bytes describe two empty payloads. The header is an API domain boundary,
//! not a requirement that any payload, section or instruction must validate.

use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasm_git::audit::{self, AuditDiff, AuditModule, Region, Span};
use wasm_git::patch::{self, BytePatch, PatchEdit, PatchSpan};
use wasm_git::standard::Standard;

const HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";
const MAX_INPUT: usize = 4096;
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

fn span_in(span: Span, len: usize) {
    assert!(span.start <= span.end && span.end <= len);
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn unhex(encoded: &str) -> Vec<u8> {
    assert!(encoded.len().is_multiple_of(2));
    fn digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("audit hex must be canonical lowercase hex"),
        }
    }
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
        .collect()
}

fn region(region: &Region, len: usize, parent: Span) {
    span_in(region.span, len);
    assert!(parent.start <= region.span.start && region.span.end <= parent.end);
    for child in &region.children {
        self::region(child, len, region.span);
    }
}

fn module(module: &AuditModule, bytes: &[u8], standard: Standard) {
    assert_eq!(module.byte_len, bytes.len());
    assert_eq!(module.standard.selected_standard, standard);
    // Frames must cover every original payload byte, including a malformed
    // terminal frame. Region gaps are allowed; guessed regions are not needed.
    let mut cursor = HEADER.len();
    for (ordinal, section) in module.sections.iter().enumerate() {
        assert_eq!(section.ordinal, ordinal);
        for span in [section.span, section.header_span, section.payload_span] {
            span_in(span, bytes.len());
        }
        assert_eq!(section.span.start, cursor);
        assert!(section.span.start < section.span.end);
        assert_eq!(section.id, bytes[section.span.start]);
        assert_eq!(section.span.start, section.header_span.start);
        assert_eq!(section.header_span.end, section.payload_span.start);
        assert_eq!(section.payload_span.end, section.span.end);
        for child in &section.regions {
            region(child, bytes.len(), section.payload_span);
        }
        cursor = section.span.end;
    }
    assert_eq!(cursor, bytes.len());
    for diagnostic in &module.diagnostics {
        assert!(diagnostic.offset <= bytes.len());
    }
    if let Some(error) = &module.standard.validator_error {
        assert!(error.offset <= bytes.len());
    }
    for evidence in &module.standard.evidence {
        span_in(evidence.span, bytes.len());
        assert_eq!(
            unhex(&evidence.raw_hex),
            bytes[evidence.span.start..evidence.span.end]
        );
    }
}

fn topology(module: &AuditModule) -> Value {
    fn entry(region: &Region) -> Value {
        json!([
            region.path,
            region.span,
            region.description,
            region.feature,
            region.children.iter().map(entry).collect::<Vec<_>>()
        ])
    }
    Value::Array(
        module
            .sections
            .iter()
            .map(|section| {
                json!([
                    section.ordinal,
                    section.id,
                    section.kind,
                    section.path,
                    section.span,
                    section.header_span,
                    section.payload_span,
                    section.status,
                    section.regions.iter().map(entry).collect::<Vec<_>>()
                ])
            })
            .collect(),
    )
}

/// Read raw evidence independently of patch::create/apply and the diff engine.
fn replay(report: &AuditDiff, old: &[u8], new: &[u8]) -> usize {
    assert_eq!(report.changed, old != new);
    assert_eq!(report.edits.is_empty(), old == new);
    let (mut old_cursor, mut new_cursor) = (0, 0);
    let mut rebuilt = Vec::new();
    let mut cost = 0;
    for edit in &report.edits {
        span_in(edit.old_span, old.len());
        span_in(edit.new_span, new.len());
        assert!(old_cursor <= edit.old_span.start && new_cursor <= edit.new_span.start);
        assert!(
            edit.old_span.start != edit.old_span.end || edit.new_span.start != edit.new_span.end
        );
        let before = &old[old_cursor..edit.old_span.start];
        assert_eq!(before, &new[new_cursor..edit.new_span.start]);
        let removed = unhex(&edit.old_hex);
        let inserted = unhex(&edit.new_hex);
        assert_eq!(removed, old[edit.old_span.start..edit.old_span.end]);
        assert_eq!(inserted, new[edit.new_span.start..edit.new_span.end]);
        assert_ne!(removed, inserted);
        for context in &edit.old_context {
            span_in(context.span, old.len());
        }
        for context in &edit.new_context {
            span_in(context.span, new.len());
        }
        rebuilt.extend_from_slice(before);
        rebuilt.extend_from_slice(&inserted);
        old_cursor = edit.old_span.end;
        new_cursor = edit.new_span.end;
        cost += removed.len() + inserted.len();
    }
    assert_eq!(&old[old_cursor..], &new[new_cursor..]);
    rebuilt.extend_from_slice(&old[old_cursor..]);
    assert_eq!(rebuilt, new);
    cost
}

/// Independent quadratic insertion/deletion distance, with O(new.len()) space.
/// Substitution costs two; equal-cost alignments need not choose the same spans.
fn distance(old: &[u8], new: &[u8]) -> usize {
    let mut row: Vec<usize> = (0..=new.len()).collect();
    for (i, a) in old.iter().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, b) in new.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = if a == b {
                diagonal
            } else {
                (row[j] + 1).min(above + 1)
            };
            diagonal = above;
        }
    }
    row[new.len()]
}

fn patches(old: &[u8], new: &[u8]) {
    for (base, target) in [(old, new), (new, old)] {
        let created = patch::create(base, target).expect("Core-header raw bytes remain patchable");
        let encoded = created.to_bytes().unwrap();
        let parsed = BytePatch::from_bytes(&encoded).unwrap();
        assert_eq!(parsed.to_bytes().unwrap(), encoded);
        assert_eq!(parsed.apply(base).unwrap(), target);

        // A second producer bypasses create and its shared diff implementation.
        // A whole-file replacement is a valid nonminimal physical patch.
        let manual = BytePatch {
            format: "uwgit-byte-patch-v1".into(),
            old_sha256: format!("{:x}", Sha256::digest(base)),
            new_sha256: format!("{:x}", Sha256::digest(target)),
            old_len: base.len() as u64,
            new_len: target.len() as u64,
            edits: if base == target {
                Vec::new()
            } else {
                vec![PatchEdit {
                    old_span: PatchSpan {
                        start: 0,
                        end: base.len() as u64,
                    },
                    new_span: PatchSpan {
                        start: 0,
                        end: target.len() as u64,
                    },
                    old_hex: hex(base),
                    new_hex: hex(target),
                }]
            },
        };
        let encoded = manual.to_bytes().unwrap();
        assert_eq!(
            BytePatch::from_bytes(&encoded)
                .unwrap()
                .apply(base)
                .unwrap(),
            target
        );
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_INPUT {
        return;
    }
    let payload = input.get(2..).unwrap_or_default();
    let selector = match input.get(..2) {
        Some(bytes) => usize::from(u16::from_le_bytes([bytes[0], bytes[1]])),
        None => 0,
    };
    let split = selector % (payload.len() + 1);
    let old = [HEADER.as_slice(), &payload[..split]].concat();
    let new = [HEADER.as_slice(), &payload[split..]].concat();
    let shortest = (old.len() + new.len() <= 128).then(|| distance(&old, &new));
    let mut physical = None;
    let mut shapes = None;
    for standard in PROFILES {
        // A framed Core header is sufficient for lossless auditing. Unknown or
        // malformed grammar must remain evidence, not become a typing oracle.
        let report = audit::compare_with_standard(&old, &new, standard)
            .expect("lossless audit must preserve unknown/malformed Core payloads");
        module(&report.old, &old, standard);
        module(&report.new, &new, standard);
        let cost = replay(&report, &old, &new);
        if report.exact_minimal {
            if let Some(shortest) = shortest {
                assert_eq!(cost, shortest);
            }
        }
        let edits = serde_json::to_vec(&report.edits).unwrap();
        let shape = (topology(&report.old), topology(&report.new));
        if let Some(expected) = &physical {
            assert_eq!(&edits, expected);
        } else {
            physical = Some(edits);
        }
        if let Some(expected) = &shapes {
            assert_eq!(&shape, expected);
        } else {
            shapes = Some(shape);
        }
    }
    patches(&old, &new);
});
