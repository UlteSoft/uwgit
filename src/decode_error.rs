//! Conservative recognition of definite failures in the pinned reader.
//!
//! Error kinds are private in wasmparser 0.249.0. Match only its explicit
//! integer, truncation, and frame errors, never every non-"unknown" message:
//! unknown type constructors and implementation limits also fail decoding.
//! Linkage names/kinds additionally require an independent guarded field walk.

use wasmparser::{
    BinaryReader, BinaryReaderError, ExternalKind, FrameStack, Operator, OperatorsReader, TypeRef,
    ValType,
};

pub(crate) struct LinkageFailure {
    pub field: String,
    pub span: std::ops::Range<usize>,
    pub reason: &'static str,
}

type LinkageScan<T = ()> = Result<T, Option<LinkageFailure>>;

fn linkage_checked<T>(result: wasmparser::Result<T>) -> LinkageScan<T> {
    result.map_err(|_| None)
}

fn linkage_name(reader: &mut BinaryReader<'_>, field: &str) -> LinkageScan<bool> {
    let mut source = reader.clone();
    match reader.read_string() {
        Ok(name) => Ok(name.is_empty()),
        Err(error) if error.message() == "malformed UTF-8 encoding" => {
            // Re-read only this proven, completely bounded name. The pinned
            // error offset points at its last byte, not the invalid sequence.
            let size = linkage_checked(source.read_var_u32())? as usize;
            let start = source.original_position();
            let bytes = linkage_checked(source.read_bytes(size))?;
            let error = std::str::from_utf8(bytes).err().ok_or(None)?;
            let invalid = start + error.valid_up_to();
            Err(Some(LinkageFailure {
                field: format!("{field}/utf8"),
                span: invalid..invalid + error.error_len().unwrap_or(size - error.valid_up_to()),
                reason: "name at a proven field boundary contains an invalid UTF-8 sequence",
            }))
        }
        // In particular, an implementation string-size limit is not a Core
        // encoding rule and gives no authority to interpret following bytes.
        Err(_) => Err(None),
    }
}

fn linkage_type(reader: &mut BinaryReader<'_>) -> LinkageScan {
    let mut prefix = reader.clone();
    let kind = linkage_checked(prefix.read::<ExternalKind>())?;
    if matches!(kind, ExternalKind::Table | ExternalKind::Global) && !value_prefix_known(&prefix) {
        // TypeRef's value reader can accept future leading bytes as indices.
        // Never use that fallback to locate a subsequent compact name.
        return Err(None);
    }
    linkage_checked(reader.read::<TypeRef>())?;
    Ok(())
}

/// Diagnose only a known name/kind error reached from a trusted failed entry
/// start. No error-offset resynchronization and no skipping unknown types.
pub(crate) fn linkage_failure(id: u8, mut reader: BinaryReader<'_>) -> Option<LinkageFailure> {
    let scan = (|| -> LinkageScan {
        match id {
            2 => {
                linkage_name(&mut reader, "module_name")?;
                let empty = linkage_name(&mut reader, "item_name")?;
                let discriminator = linkage_checked(reader.clone().read_u8())?;
                if empty && matches!(discriminator, 0x7e | 0x7f) {
                    linkage_checked(reader.read_u8())?;
                    if discriminator == 0x7e {
                        linkage_type(&mut reader)?;
                    }
                    let count = linkage_checked(reader.read_var_u32())?;
                    for index in 0..count {
                        linkage_name(&mut reader, &format!("item[{index}]/name"))?;
                        if discriminator == 0x7f {
                            linkage_type(&mut reader)?;
                        }
                    }
                } else {
                    linkage_type(&mut reader)?;
                }
            }
            7 => {
                linkage_name(&mut reader, "name")?;
                let start = reader.original_position();
                if linkage_checked(reader.read::<ExternalKind>())? == ExternalKind::FuncExact {
                    return Err(Some(LinkageFailure {
                        field: "external_kind".into(),
                        span: start..reader.original_position(),
                        reason: "known exact-function kind is forbidden in an export descriptor by the pinned grammar",
                    }));
                }
            }
            _ => {}
        }
        Ok(())
    })();
    scan.err().flatten()
}

pub(crate) fn invalid_encoding(error: &BinaryReaderError) -> Option<&'static str> {
    let message = error.message();
    if message == "unexpected end-of-file" {
        return Some("known encoding is truncated at its trusted input boundary");
    }
    if let Some((integer, reason)) = message
        .strip_prefix("invalid var_")
        .and_then(|message| message.split_once(": "))
    {
        if matches!(integer, "u32" | "u64" | "i32" | "i64" | "s33")
            && matches!(
                reason,
                "integer representation too long" | "integer too large"
            )
        {
            return Some("integer encoding exceeds its required width or length");
        }
    }
    if matches!(
        message,
        "`else` found outside `If` block"
            | "`catch` found outside `LegacyTry` block"
            | "`catch_all` found outside `LegacyTry` block"
            | "`delegate` found outside `LegacyTry` block"
    ) {
        return Some("known control delimiter is outside its required frame");
    }
    None
}

/// The pinned value-type reader falls back to `s33` heap indices for any
/// unrecognized leading byte. Do not let that permissive fallback consume a
/// future constructor and lend credibility to an error in following bytes.
/// An absent byte still proves truncation at the caller's trusted boundary.
pub(crate) fn value_prefix_known(reader: &BinaryReader<'_>) -> bool {
    let mut reader = reader.clone();
    match reader.read_u8() {
        Err(_) => true,
        Ok(0x7b..=0x7f | 0x68..=0x75 | 0x63 | 0x64) => true,
        Ok(0x65) => matches!(reader.read_u8(), Err(_) | Ok(0x68..=0x75)),
        Ok(_) => false,
    }
}

/// An already terminated, single-byte positive index is a forbidden bare
/// value-type shorthand in the selected Core releases and pinned grammar.
/// Other unrecognized leading bytes stay unknown; never consume their suffix.
pub(crate) fn forbidden_bare_index(reader: &BinaryReader<'_>) -> bool {
    matches!(reader.clone().read_u8(), Ok(0..=0x3f))
}

/// Return the classification of the first untrusted value-type prefix in a
/// typed select: true is a forbidden bare index, false is unknown grammar.
pub(crate) fn select_value_prefix(mut reader: BinaryReader<'_>) -> Option<bool> {
    if reader.read_u8().ok()? != 0x1c {
        return None;
    }
    // Match the pinned operator reader's resource admission before looking at
    // any value bytes. Ten is its implementation limit, not a Core wire limit.
    let count = reader.read_size(10, "select types").ok()?;
    for _ in 0..count {
        if !value_prefix_known(&reader) {
            return Some(forbidden_bare_index(&reader));
        }
        reader.read::<ValType>().ok()?;
    }
    None
}

enum PrefixFailure {
    Known,
    Unknown,
}

fn failure(error: BinaryReaderError) -> PrefixFailure {
    if invalid_encoding(&error).is_some() {
        PrefixFailure::Known
    } else {
        PrefixFailure::Unknown
    }
}

fn value(reader: &mut BinaryReader<'_>) -> Result<(), PrefixFailure> {
    if !value_prefix_known(reader) {
        return Err(PrefixFailure::Unknown);
    }
    reader.read::<ValType>().map(|_| ()).map_err(failure)
}

fn value_vector(reader: &mut BinaryReader<'_>) -> Result<(), PrefixFailure> {
    let count = reader.read_var_u32().map_err(failure)?;
    for _ in 0..count {
        value(reader)?;
    }
    Ok(())
}

/// Prove the first constant-expression boundary without accepting a permissive
/// value-type fallback or crossing an unknown instruction to find an End.
fn constant_expression(reader: &mut BinaryReader<'_>) -> Result<(), PrefixFailure> {
    let mut operators = OperatorsReader::new(reader.clone());
    while !operators.eof() {
        if let Some(invalid) = select_value_prefix(operators.get_binary_reader()) {
            return Err(if invalid {
                PrefixFailure::Known
            } else {
                PrefixFailure::Unknown
            });
        }
        let raw = operators.get_binary_reader();
        let operator = operators.read().map_err(|error| {
            if operator_failure(&error, raw).is_some() {
                PrefixFailure::Known
            } else {
                PrefixFailure::Unknown
            }
        })?;
        if matches!(operator, Operator::End) {
            // ConstExpr ends at the first End, which must close its root.
            if operators.current_frame().is_some() {
                return Err(PrefixFailure::Known);
            }
            *reader = operators.get_binary_reader();
            return Ok(());
        }
    }
    Err(PrefixFailure::Known)
}

/// A failed entry must recover from its expression's original start even if
/// the upstream ConstExpr reader could skip an untrusted value-type prefix.
pub(crate) fn expression_needs_recovery(mut reader: BinaryReader<'_>) -> bool {
    constant_expression(&mut reader).is_err()
}

fn proved(scan: Result<(), PrefixFailure>, reason: &'static str) -> Option<&'static str> {
    match scan {
        Ok(()) | Err(PrefixFailure::Known) => Some(reason),
        Err(PrefixFailure::Unknown) => None,
    }
}

/// The pinned cast reader reads the depth before rejecting reserved flags.
/// A later integer/EOF error cannot prove a failure beyond unknown flags.
fn cast_flags_known(mut reader: BinaryReader<'_>) -> bool {
    if reader.read_u8().ok() != Some(0xfb)
        || !matches!(reader.read_var_u32(), Ok(0x18 | 0x19 | 0x25 | 0x26))
    {
        return true;
    }
    matches!(reader.read_u8(), Err(_) | Ok(0..=3))
}

/// The pinned memarg reader reads an explicit memory index before rejecting
/// unknown flag bits. Only these typed layouts start with a memarg; adjacent
/// SIMD constants, fences and ordering operands must retain their own grammar.
fn memarg_flags_known(mut reader: BinaryReader<'_>) -> bool {
    let memarg = match reader.read_u8() {
        Ok(0x28..=0x3e) => true,
        Ok(0xfd) => matches!(reader.read_var_u32(), Ok(0x00..=0x0b | 0x54..=0x5d)),
        Ok(0xfe) => matches!(reader.read_var_u32(), Ok(0x00..=0x02 | 0x10..=0x4e)),
        _ => false,
    };
    if !memarg {
        return true;
    }
    // Audit readers decode all known grammar before profile validation: low
    // six bits are alignment, bit6 is the explicit memory-index flag. This
    // does not impose the instruction's semantic natural-alignment limit.
    match reader.read_var_u32() {
        Ok(flags) => flags < 128,
        Err(_) => true, // The flags field's own EOF/integer failure is known.
    }
}

/// `reader` starts at the failed instruction, before any of its bytes have
/// been consumed. Guard unknown immediate prefixes before trusting a later
/// error; field-specific failures require an independent opcode/operand proof.
pub(crate) fn operator_failure(
    error: &BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<&'static str> {
    if !cast_flags_known(reader.clone()) || !memarg_flags_known(reader.clone()) {
        return None;
    }
    if let Some(failure) = crate::value_guard::heap_operand_failure(error, reader.clone()) {
        return Some(failure.reason);
    }
    let reason = invalid_encoding(error)?;
    if reader.read_u8().ok() == Some(0x1c) {
        proved(value_vector(&mut reader), reason)
    } else {
        Some(reason)
    }
}

/// A group reader starts at its local repetition count, whereas a non-group
/// reader starts at the function's locals-vector count itself.
pub(crate) fn locals_failure(
    error: &BinaryReaderError,
    mut reader: BinaryReader<'_>,
    group: bool,
) -> Option<&'static str> {
    let reason = invalid_encoding(error)?;
    if !group {
        return Some(reason);
    }
    let scan = (|| {
        reader.read_var_u32().map_err(failure)?;
        value(&mut reader)
    })();
    proved(scan, reason)
}

/// Guard known section fields at a proved payload or entry start. Linkage
/// errors retain their own walk; scalar, declaration and segment fields use
/// strict independent scans. A later error cannot condemn an unknown prefix.
pub(crate) fn section_failure(
    error: &BinaryReaderError,
    id: u8,
    mut reader: BinaryReader<'_>,
    at_payload_start: bool,
) -> Option<&'static str> {
    if !at_payload_start {
        if let Some(failure) = linkage_failure(id, reader.clone()) {
            return Some(failure.reason);
        }
        if let Some(failure) = crate::value_guard::reference_slot_failure(id, error, reader.clone())
        {
            return Some(failure.reason);
        }
    }
    let reason = invalid_encoding(error)?;
    if at_payload_start {
        return if matches!(id, 8 | 12) {
            crate::value_guard::scalar_failure(id, error, reader)
        } else {
            crate::value_guard::count_failure(id, error, reader)
        }
        .map(|failure| failure.reason);
    }
    if let Some(failure) = crate::value_guard::segment_failure(id, error, reader.clone()) {
        return Some(failure.reason);
    }
    match id {
        1 => crate::value_guard::type_failure(error, reader).map(|failure| failure.reason),
        2 => crate::value_guard::import_failure(error, reader).map(|failure| failure.reason),
        3 | 7 => {
            crate::value_guard::scalar_failure(id, error, reader).map(|failure| failure.reason)
        }
        8 | 12 => None,
        4 | 5 | 6 | 13 => {
            crate::value_guard::header_failure(id, error, reader).map(|failure| failure.reason)
        }
        9 => {
            let scan = (|| {
                let flags = reader.read_var_u32().map_err(failure)?;
                if flags > 7 {
                    return Err(PrefixFailure::Unknown);
                }
                if flags & 1 == 0 {
                    if flags & 2 != 0 {
                        reader.read_var_u32().map_err(failure)?;
                    }
                    // Active offsets require an independently guarded
                    // expression; do not skip it and trust a later field.
                    return Err(PrefixFailure::Unknown);
                }
                if flags & 4 != 0 {
                    value(&mut reader)?;
                } else if reader.read_u8().map_err(failure)? != 0 {
                    return Err(PrefixFailure::Unknown);
                }
                let count = reader.read_var_u32().map_err(failure)?;
                if flags & 4 != 0 {
                    // Expression items are handled only at their independently
                    // established starts by the expression recovery path.
                    return Err(PrefixFailure::Unknown);
                }
                for _ in 0..count {
                    reader.read_var_u32().map_err(failure)?;
                }
                Ok(())
            })();
            proved(scan, reason)
        }
        11 => {
            let scan = (|| {
                match reader.read_var_u32().map_err(failure)? {
                    0 => constant_expression(&mut reader)?,
                    1 => {}
                    2 => {
                        reader.read_var_u32().map_err(failure)?;
                        constant_expression(&mut reader)?;
                    }
                    _ => return Err(PrefixFailure::Unknown),
                }
                let count = reader.read_var_u32().map_err(failure)?;
                reader.read_bytes(count as usize).map_err(failure)?;
                Ok(())
            })();
            proved(scan, reason)
        }
        _ => Some(reason),
    }
}
