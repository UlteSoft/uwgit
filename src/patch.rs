//! Verifiable offline patches for original core WebAssembly bytes.
//!
//! The wire format contains only physical edits and raw-file integrity hashes.
//! It makes no claims about instruction decoding, feature support, validation,
//! semantic equivalence, or edit minimality. Unknown or malformed payload bytes
//! are preserved exactly. Applying a patch never executes WebAssembly.

use crate::audit;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FORMAT: &str = "uwgit-byte-patch-v1";
const CORE_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";

/// Physical half-open offsets into one original file, independent of host size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchSpan {
    pub start: u64,
    pub end: u64,
}

/// An entire replacement, insertion, or deletion. Hex is lowercase and exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchEdit {
    pub old_span: PatchSpan,
    pub new_span: PatchSpan,
    pub old_hex: String,
    pub new_hex: String,
}

/// Field order is part of the version-one canonical JSON encoding.
/// SHA-256 fields hash the raw files, not repository object envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytePatch {
    pub format: String,
    pub old_sha256: String,
    pub new_sha256: String,
    pub old_len: u64,
    pub new_len: u64,
    pub edits: Vec<PatchEdit>,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        result.push(char::from(DIGITS[(byte >> 4) as usize]));
        result.push(char::from(DIGITS[(byte & 15) as usize]));
    }
    result
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn header(bytes: &[u8], which: &str) -> Result<(), String> {
    if !bytes.starts_with(CORE_HEADER) {
        return Err(format!(
            "{which}: expected original core WebAssembly version-1 bytes; Component Model is outside this patch format"
        ));
    }
    Ok(())
}

fn offset(value: u64, which: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{which} does not fit this host's address space"))
}

fn valid_hex(value: &str) -> bool {
    value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("hex characters are validated before decoding"),
    }
}

fn matches_hex(bytes: &[u8], encoded: &str) -> bool {
    bytes.len() == encoded.len() / 2
        && bytes
            .iter()
            .zip(encoded.as_bytes().as_chunks::<2>().0)
            .all(|(byte, pair)| *byte == (nibble(pair[0]) << 4 | nibble(pair[1])))
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    output
        .len()
        .checked_add(bytes.len())
        .ok_or("patch output length overflow")?;
    output
        .try_reserve(bytes.len())
        .map_err(|error| format!("cannot grow patch output: {error}"))?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn append_hex(output: &mut Vec<u8>, encoded: &str) -> Result<(), String> {
    let count = encoded.len() / 2;
    output
        .len()
        .checked_add(count)
        .ok_or("patch output length overflow")?;
    // Capacity comes only from actual, validated hex bytes, never new_len.
    output
        .try_reserve(count)
        .map_err(|error| format!("cannot grow patch output: {error}"))?;
    for pair in encoded.as_bytes().as_chunks::<2>().0 {
        output.push(nibble(pair[0]) << 4 | nibble(pair[1]));
    }
    Ok(())
}

/// Create a patch from the complete physical edit script produced by audit.
pub fn create(old: &[u8], new: &[u8]) -> Result<BytePatch, String> {
    let changes = audit::compare(old, new)?.edits;
    let mut edits: Vec<PatchEdit> = Vec::with_capacity(changes.len());
    for change in changes {
        let edit = PatchEdit {
            old_span: PatchSpan {
                start: u64::try_from(change.old_span.start)
                    .map_err(|_| "old offset exceeds u64")?,
                end: u64::try_from(change.old_span.end).map_err(|_| "old offset exceeds u64")?,
            },
            new_span: PatchSpan {
                start: u64::try_from(change.new_span.start)
                    .map_err(|_| "new offset exceeds u64")?,
                end: u64::try_from(change.new_span.end).map_err(|_| "new offset exceeds u64")?,
            },
            old_hex: change.old_hex,
            new_hex: change.new_hex,
        };
        if let Some(previous) = edits.last_mut() {
            if previous.old_span.end == edit.old_span.start
                && previous.new_span.end == edit.new_span.start
            {
                // A touching deletion/insertion pair has one unambiguous
                // replacement representation, including empty-side anchors.
                previous.old_span.end = edit.old_span.end;
                previous.new_span.end = edit.new_span.end;
                previous.old_hex.push_str(&edit.old_hex);
                previous.new_hex.push_str(&edit.new_hex);
                continue;
            }
        }
        edits.push(edit);
    }
    let patch = BytePatch {
        format: FORMAT.into(),
        old_sha256: sha256(old),
        new_sha256: sha256(new),
        old_len: u64::try_from(old.len()).map_err(|_| "old byte length exceeds u64")?,
        new_len: u64::try_from(new.len()).map_err(|_| "new byte length exceeds u64")?,
        edits,
    };
    patch.validate_structure()?;
    Ok(patch)
}

impl BytePatch {
    /// Decode the exact canonical JSON encoding. Unknown or duplicate fields,
    /// reordered fields, alternate escapes, whitespace, and trailing bytes fail.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let patch: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid patch JSON: {error}"))?;
        patch.validate_structure()?;
        let canonical = serde_json::to_vec(&patch)
            .map_err(|error| format!("cannot encode patch JSON: {error}"))?;
        if canonical != bytes {
            return Err("patch JSON is not the canonical uwgit-byte-patch-v1 encoding".into());
        }
        Ok(patch)
    }

    /// Encode a structurally valid patch without a trailing newline.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_structure()?;
        serde_json::to_vec(self).map_err(|error| format!("cannot encode patch JSON: {error}"))
    }

    fn validate_structure(&self) -> Result<(), String> {
        if self.format != FORMAT {
            return Err("unsupported byte patch format".into());
        }
        for (which, digest) in [
            ("old_sha256", &self.old_sha256),
            ("new_sha256", &self.new_sha256),
        ] {
            if digest.len() != 64 || !valid_hex(digest) {
                return Err(format!(
                    "{which} must be 64 lowercase hexadecimal characters"
                ));
            }
        }
        offset(self.old_len, "old_len")?;
        offset(self.new_len, "new_len")?;
        if self.old_len < CORE_HEADER.len() as u64 || self.new_len < CORE_HEADER.len() as u64 {
            return Err("patch file lengths cannot be shorter than the core header".into());
        }
        let mut old_cursor = 0u64;
        let mut new_cursor = 0u64;
        let mut previous_starts = None;
        for (index, edit) in self.edits.iter().enumerate() {
            let old = &edit.old_span;
            let new = &edit.new_span;
            for (which, range, len, encoded) in [
                ("old", old, self.old_len, &edit.old_hex),
                ("new", new, self.new_len, &edit.new_hex),
            ] {
                if range.start > range.end || range.end > len {
                    return Err(format!(
                        "edit[{index}] {which} span is reversed or outside the file"
                    ));
                }
                offset(range.start, "span start")?;
                offset(range.end, "span end")?;
                if !valid_hex(encoded) {
                    return Err(format!(
                        "edit[{index}] {which}_hex must be even-length lowercase hexadecimal"
                    ));
                }
                let hex_len =
                    u64::try_from(encoded.len() / 2).map_err(|_| "hex length exceeds u64")?;
                if range.end - range.start != hex_len {
                    return Err(format!("edit[{index}] {which} span and hex lengths differ"));
                }
            }
            if old.start == old.end && new.start == new.end {
                return Err(format!("edit[{index}] is empty on both sides"));
            }
            if edit.old_hex == edit.new_hex {
                return Err(format!("edit[{index}] is a no-op replacement"));
            }
            if previous_starts.is_some_and(|(previous_old, previous_new)| {
                old.start <= previous_old || new.start <= previous_new
            }) {
                return Err(format!(
                    "edit[{index}] spans are not strictly sorted on both sides"
                ));
            }
            let old_gap = old
                .start
                .checked_sub(old_cursor)
                .ok_or_else(|| format!("edit[{index}] old spans overlap"))?;
            let new_gap = new
                .start
                .checked_sub(new_cursor)
                .ok_or_else(|| format!("edit[{index}] new spans overlap"))?;
            if old_gap != new_gap {
                return Err(format!("edit[{index}] unchanged gap lengths differ"));
            }
            previous_starts = Some((old.start, new.start));
            old_cursor = old.end;
            new_cursor = new.end;
        }
        let old_tail = self
            .old_len
            .checked_sub(old_cursor)
            .ok_or("old tail underflow")?;
        let new_tail = self
            .new_len
            .checked_sub(new_cursor)
            .ok_or("new tail underflow")?;
        if old_tail != new_tail {
            return Err("unchanged tail gap lengths differ".into());
        }
        Ok(())
    }

    /// Verify and replay every edit. All integrity checks run before returning
    /// bytes, and output allocation is driven only by actual input/payload data.
    pub fn apply(&self, old: &[u8]) -> Result<Vec<u8>, String> {
        self.validate_structure()?;
        header(old, "base")?;
        if old.len() != offset(self.old_len, "old_len")? {
            return Err("base byte length does not match old_len".into());
        }
        if sha256(old) != self.old_sha256 {
            return Err("base raw-file SHA-256 does not match old_sha256".into());
        }
        // Verify every old payload before building any target bytes.
        for (index, edit) in self.edits.iter().enumerate() {
            let start = offset(edit.old_span.start, "old span start")?;
            let end = offset(edit.old_span.end, "old span end")?;
            if !matches_hex(&old[start..end], &edit.old_hex) {
                return Err(format!(
                    "edit[{index}] old_hex does not match the original base bytes"
                ));
            }
        }
        let mut output = Vec::new();
        let mut old_cursor = 0usize;
        for (index, edit) in self.edits.iter().enumerate() {
            let start = offset(edit.old_span.start, "old span start")?;
            append(&mut output, &old[old_cursor..start])?;
            if output.len() != offset(edit.new_span.start, "new span start")? {
                return Err(format!(
                    "edit[{index}] target start does not match replay position"
                ));
            }
            append_hex(&mut output, &edit.new_hex)?;
            if output.len() != offset(edit.new_span.end, "new span end")? {
                return Err(format!(
                    "edit[{index}] target end does not match replay position"
                ));
            }
            old_cursor = offset(edit.old_span.end, "old span end")?;
        }
        append(&mut output, &old[old_cursor..])?;
        if output.len() != offset(self.new_len, "new_len")? {
            return Err("replayed target byte length does not match new_len".into());
        }
        header(&output, "target")?;
        if sha256(&output) != self.new_sha256 {
            return Err("replayed target raw-file SHA-256 does not match new_sha256".into());
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(mut value: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = value as u8 & 127;
            value >>= 7;
            bytes.push(byte | if value == 0 { 0 } else { 128 });
            if value == 0 {
                return bytes;
            }
        }
    }

    fn custom(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut data = leb(name.len());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(payload);
        let mut bytes = CORE_HEADER.to_vec();
        bytes.push(0);
        bytes.extend(leb(data.len()));
        bytes.extend(data);
        bytes
    }

    fn roundtrip(old: &[u8], new: &[u8]) -> BytePatch {
        let patch = create(old, new).unwrap();
        assert_eq!(patch.old_sha256, sha256(old));
        assert_eq!(patch.new_sha256, sha256(new));
        let encoded = patch.to_bytes().unwrap();
        assert!(!encoded.ends_with(b"\n"));
        let decoded = BytePatch::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, patch);
        assert_eq!(decoded.apply(old).unwrap(), new);
        patch
    }

    fn replacement() -> (Vec<u8>, Vec<u8>, BytePatch) {
        let old = custom("opaque", b"abcdef");
        let new = custom("opaque", b"axcdyf");
        let patch = create(&old, &new).unwrap();
        assert_eq!(patch.edits.len(), 2);
        (old, new, patch)
    }

    #[test]
    fn exact_replace_insert_delete_and_identity_replay() {
        let original = custom("opaque", b"abcdef");
        for changed in [
            custom("opaque", b"axcdyf"),
            custom("opaque", b"ab123456cdef"),
            custom("opaque", b"abef"),
            CORE_HEADER.to_vec(),
            original.clone(),
        ] {
            let patch = roundtrip(&original, &changed);
            assert_eq!(patch.edits.is_empty(), original == changed);
            roundtrip(&changed, &original);
        }
    }

    #[test]
    fn unknown_and_invalid_bodies_and_custom_conventions_are_replayable() {
        let mut old = wat::parse_str("(module (func i32.const 1 drop))").unwrap();
        let module = audit::inspect(&old).unwrap();
        let code = module
            .sections
            .iter()
            .find(|section| section.id == 10)
            .unwrap();
        let first = code.regions[1]
            .children
            .iter()
            .find(|region| region.path.ends_with("/operator[0]"))
            .unwrap()
            .span
            .start;
        old[first] = 0xff;
        let mut new = old.clone();
        new[first + 1] = 0xfe;
        old.extend_from_slice(&custom("name", &[1, 0x80])[8..]);
        new.extend_from_slice(&custom("name", &[1, 0x81])[8..]);
        assert_eq!(
            audit::inspect(&old).unwrap().validation,
            "failed_or_unsupported"
        );
        roundtrip(&old, &new);
        // Even truncated section framing remains a physical Core-file snapshot.
        let mut truncated = CORE_HEADER.to_vec();
        truncated.extend_from_slice(&[0, 0x80]);
        roundtrip(&old, &truncated);
    }

    #[test]
    fn raw_hashes_are_independent_of_repository_object_envelopes() {
        let patch = roundtrip(CORE_HEADER, CORE_HEADER);
        assert_eq!(
            patch.old_sha256,
            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476"
        );
        assert!(patch.edits.is_empty());
    }

    #[test]
    fn different_or_wrong_base_bytes_are_rejected() {
        let (old, _, patch) = replacement();
        assert!(patch.apply(&custom("opaque", b"abcdefg")).is_err());
        assert!(patch.apply(&custom("opaque", b"ABCDEF")).is_err());
        let mut corrupted = old;
        corrupted[0] = 1;
        assert!(patch.apply(&corrupted).is_err());
    }

    #[test]
    fn hash_and_old_byte_evidence_tampering_are_rejected() {
        let (old, _, original) = replacement();
        for old_hash in [true, false] {
            let mut patch = original.clone();
            if old_hash {
                patch.old_sha256 = "0".repeat(64);
            } else {
                patch.new_sha256 = "0".repeat(64);
            }
            assert!(patch.apply(&old).is_err());
        }
        let mut patch = original.clone();
        patch.edits[0].old_hex = "ff".repeat(patch.edits[0].old_hex.len() / 2);
        assert!(patch.apply(&old).unwrap_err().contains("old_hex"));
        let mut patch = original;
        patch.edits[0].new_hex = "00".repeat(patch.edits[0].new_hex.len() / 2);
        assert!(patch.apply(&old).unwrap_err().contains("new_sha256"));
    }

    #[test]
    fn spans_must_be_strictly_sorted_and_nonoverlapping_on_both_sides() {
        let (old, new, original) = replacement();
        let mut patch = original.clone();
        patch.edits.swap(0, 1);
        assert!(patch.apply(&old).is_err());
        for old_side in [true, false] {
            let mut patch = original.clone();
            let first = if old_side {
                patch.edits[0].old_span.clone()
            } else {
                patch.edits[0].new_span.clone()
            };
            if old_side {
                patch.edits[1].old_span = first;
            } else {
                patch.edits[1].new_span = first;
            }
            assert!(patch.apply(&old).is_err());
        }
        for old_side in [true, false] {
            let mut patch = original.clone();
            if old_side {
                patch.edits[0].old_span.end = patch.edits[1].old_span.start + 1;
                patch.edits[0].old_hex = hex(&old
                    [patch.edits[0].old_span.start as usize..patch.edits[0].old_span.end as usize]);
            } else {
                patch.edits[0].new_span.end = patch.edits[1].new_span.start + 1;
                patch.edits[0].new_hex = hex(&new
                    [patch.edits[0].new_span.start as usize..patch.edits[0].new_span.end as usize]);
            }
            assert!(patch.apply(&old).unwrap_err().contains("overlap"));
        }
    }

    #[test]
    fn range_reversal_out_of_bounds_and_huge_declarations_are_rejected() {
        let (old, _, original) = replacement();
        let mut patch = original.clone();
        patch.edits[0].old_span.start = patch.edits[0].old_span.end + 1;
        assert!(patch.apply(&old).is_err());
        let mut patch = original.clone();
        patch.edits[0].new_span.end = u64::MAX;
        assert!(patch.apply(&old).is_err());
        let mut patch = original.clone();
        patch.new_len = u64::MAX;
        assert!(patch.apply(&old).is_err());
        let mut patch = original;
        patch.old_len = u64::MAX;
        patch.new_len = u64::MAX;
        assert!(patch.apply(&old).is_err());
    }

    #[test]
    fn unchanged_gaps_and_tail_must_agree_exactly() {
        let (old, _, original) = replacement();
        let mut patch = original.clone();
        patch.edits[1].new_span.start += 1;
        patch.edits[1].new_span.end += 1;
        patch.new_len += 1;
        assert!(patch.apply(&old).unwrap_err().contains("gap"));
        let mut patch = original;
        patch.new_len += 1;
        assert!(patch.apply(&old).unwrap_err().contains("tail"));
    }

    #[test]
    fn empty_and_noop_edits_are_rejected() {
        let mut patch = create(CORE_HEADER, CORE_HEADER).unwrap();
        patch.edits.push(PatchEdit {
            old_span: PatchSpan { start: 8, end: 8 },
            new_span: PatchSpan { start: 8, end: 8 },
            old_hex: String::new(),
            new_hex: String::new(),
        });
        assert!(patch.apply(CORE_HEADER).unwrap_err().contains("empty"));
        patch.edits[0] = PatchEdit {
            old_span: PatchSpan { start: 0, end: 1 },
            new_span: PatchSpan { start: 0, end: 1 },
            old_hex: "00".into(),
            new_hex: "00".into(),
        };
        assert!(patch.apply(CORE_HEADER).unwrap_err().contains("no-op"));
    }

    #[test]
    fn hex_must_be_lowercase_even_and_match_both_span_lengths() {
        let (old, _, original) = replacement();
        for bad in ["Ff", "a", "gg", "0000", "é"] {
            for old_side in [true, false] {
                let mut patch = original.clone();
                if old_side {
                    patch.edits[0].old_hex = bad.into();
                } else {
                    patch.edits[0].new_hex = bad.into();
                }
                assert!(patch.apply(&old).is_err());
            }
        }
        for bad in ["A".repeat(64), "f".repeat(63), "x".repeat(64)] {
            let mut patch = original.clone();
            patch.new_sha256 = bad;
            assert!(patch.to_bytes().is_err());
        }
    }

    #[test]
    fn input_and_target_core_headers_are_checked_without_validating_bodies() {
        assert!(create(b"not wasm", CORE_HEADER).is_err());
        let mut component = CORE_HEADER.to_vec();
        component[4] = 0x0d;
        assert!(create(CORE_HEADER, &component).is_err());
        let mut patch = create(CORE_HEADER, CORE_HEADER).unwrap();
        let mut target = CORE_HEADER.to_vec();
        target[4] = 2;
        patch.new_sha256 = sha256(&target);
        patch.edits.push(PatchEdit {
            old_span: PatchSpan { start: 4, end: 5 },
            new_span: PatchSpan { start: 4, end: 5 },
            old_hex: "01".into(),
            new_hex: "02".into(),
        });
        assert!(patch.apply(CORE_HEADER).unwrap_err().contains("target"));
    }

    #[test]
    fn json_unknown_duplicate_and_noncanonical_forms_are_rejected() {
        let (_, _, patch) = replacement();
        let canonical = patch.to_bytes().unwrap();
        let text = String::from_utf8(canonical.clone()).unwrap();
        let unknown = format!("{},\"unexpected\":0}}", &text[..text.len() - 1]);
        assert!(BytePatch::from_bytes(unknown.as_bytes()).is_err());
        let duplicate = format!("{{\"format\":\"{FORMAT}\",{}", &text[1..]);
        assert!(BytePatch::from_bytes(duplicate.as_bytes()).is_err());
        let mut trailing = canonical.clone();
        trailing.push(b'\n');
        assert!(BytePatch::from_bytes(&trailing).is_err());
        assert!(BytePatch::from_bytes(&serde_json::to_vec_pretty(&patch).unwrap()).is_err());
        let escaped = text.replacen("uwgit", "\\u0075wgit", 1);
        assert!(BytePatch::from_bytes(escaped.as_bytes()).is_err());
        let value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        assert!(BytePatch::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        for path in ["edit", "span"] {
            let mut value = serde_json::to_value(&patch).unwrap();
            let target = if path == "edit" {
                &mut value["edits"][0]
            } else {
                &mut value["edits"][0]["old_span"]
            };
            target["unexpected"] = serde_json::json!(0);
            assert!(BytePatch::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn json_integer_overflow_and_wrong_format_are_rejected() {
        let patch = create(CORE_HEADER, CORE_HEADER).unwrap();
        let text = String::from_utf8(patch.to_bytes().unwrap()).unwrap();
        let overflow = text.replace("\"old_len\":8", "\"old_len\":18446744073709551616");
        assert!(BytePatch::from_bytes(overflow.as_bytes()).is_err());
        let negative = text.replace("\"old_len\":8", "\"old_len\":-1");
        assert!(BytePatch::from_bytes(negative.as_bytes()).is_err());
        let wrong = text.replace(FORMAT, "uwgit-byte-patch-v2");
        assert!(BytePatch::from_bytes(wrong.as_bytes()).is_err());
    }

    #[test]
    fn large_fallback_difference_remains_an_exact_replay() {
        let old = custom("opaque", &vec![0x41; 4096]);
        let new = custom("opaque", &vec![0x42; 6144]);
        assert!(!audit::compare(&old, &new).unwrap().exact_minimal);
        let patch = roundtrip(&old, &new);
        let json: serde_json::Value = serde_json::from_slice(&patch.to_bytes().unwrap()).unwrap();
        assert!(json.get("exact_minimal").is_none());
        assert!(json.get("feature").is_none());
        assert!(json.get("context").is_none());
    }
}
