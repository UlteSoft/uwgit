//! Prove value-type frontiers from the known entry prefix, independently of
//! a permissive reader's success or failure in bytes after the unknown type.

use wasmparser::{
    BinaryReader, ExternalKind, FrameStack, GlobalType, HeapType, MemoryType, Operator,
    OperatorsReader, RefType, TableType, TagType, TypeRef, ValType,
};

enum Stop {
    Unknown(usize),
    Known(FieldFailure),
    Unproved,
}

type Scan<T = ()> = Result<T, Stop>;

const NUMERIC_REFERENCE: &str =
    "known numeric or vector value type is forbidden in a reference-only field";

pub(crate) enum PrefixKind {
    Name(&'static str),
    CompactImports,
    MemberCount,
    ImportKind,
    CompleteImportType,
    TableInitializer,
    TypeSyntax {
        feature: &'static str,
        description: &'static str,
    },
    TypeCount {
        feature: &'static str,
        role: &'static str,
    },
    TypeValue,
}

pub(crate) struct PrefixFact {
    pub span: std::ops::Range<usize>,
    pub kind: PrefixKind,
}

pub(crate) struct UnknownPrefix {
    pub offset: usize,
    pub facts: Vec<PrefixFact>,
}

pub(crate) struct FieldFailure {
    pub span: std::ops::Range<usize>,
    pub field: &'static str,
    pub reason: &'static str,
}

pub(crate) struct BrTableFailure {
    pub failure: FieldFailure,
    pub target: Option<u32>,
}

pub(crate) struct TryTableFailure {
    pub failure: FieldFailure,
    pub catch: Option<u32>,
}

pub(crate) struct SimdImmediateFailure {
    pub failure: FieldFailure,
    pub lane: Option<u8>,
}

/// SIMD byte fields can fail only at EOF. A present lane byte is complete
/// regardless of its semantic range. Never reach a memory lane through an
/// unknown flag or a failed memarg field, or borrow another frame's bytes.
pub(crate) fn simd_immediate_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<SimdImmediateFailure> {
    if error.message() != "unexpected end-of-file" || reader.read_u8().ok()? != 0xfd {
        return None;
    }
    let opcode = reader.read_var_u32().ok()?;
    let mut lane = None;
    let scan = (|| -> Scan {
        let field = match opcode {
            0x0c => {
                field_checked(&mut reader, "v128.const value bytes", |reader| {
                    reader.read_bytes(16)
                })?;
                return Ok(());
            }
            0x0d => {
                for index in 0u8..16 {
                    lane = Some(index);
                    field_checked(
                        &mut reader,
                        "i8x16.shuffle lane index",
                        BinaryReader::read_u8,
                    )?;
                }
                return Ok(());
            }
            0x15 => "i8x16.extract_lane_s lane index",
            0x16 => "i8x16.extract_lane_u lane index",
            0x17 => "i8x16.replace_lane lane index",
            0x18 => "i16x8.extract_lane_s lane index",
            0x19 => "i16x8.extract_lane_u lane index",
            0x1a => "i16x8.replace_lane lane index",
            0x1b => "i32x4.extract_lane lane index",
            0x1c => "i32x4.replace_lane lane index",
            0x1d => "i64x2.extract_lane lane index",
            0x1e => "i64x2.replace_lane lane index",
            0x1f => "f32x4.extract_lane lane index",
            0x20 => "f32x4.replace_lane lane index",
            0x21 => "f64x2.extract_lane lane index",
            0x22 => "f64x2.replace_lane lane index",
            0x54..=0x5b => {
                let flags = checked(reader.read_var_u32())?;
                if flags >= 128 {
                    return Err(Stop::Unproved);
                }
                if flags & 64 != 0 {
                    checked(reader.read_var_u32())?;
                }
                // All-known grammar uses u64 even for a 32-bit memory.
                checked(reader.read_var_u64())?;
                match opcode {
                    0x54 => "v128.load8_lane lane index",
                    0x55 => "v128.load16_lane lane index",
                    0x56 => "v128.load32_lane lane index",
                    0x57 => "v128.load64_lane lane index",
                    0x58 => "v128.store8_lane lane index",
                    0x59 => "v128.store16_lane lane index",
                    0x5a => "v128.store32_lane lane index",
                    _ => "v128.store64_lane lane index",
                }
            }
            _ => return Err(Stop::Unproved),
        };
        field_checked(&mut reader, field, BinaryReader::read_u8)?;
        Ok(())
    })();
    match scan {
        Err(Stop::Known(failure)) => Some(SimdImmediateFailure { failure, lane }),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// These Core instructions read one full u32 without an earlier control-frame
/// precheck. Legacy catch/delegate and instructions with other operands must
/// keep their own grammar; complete indices prove nothing about later bytes.
pub(crate) fn primary_index_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    let field = match reader.read_u8().ok()? {
        0x08 => "throw tag index",
        0x0c => "br label depth",
        0x0d => "br_if label depth",
        0x10 => "call function index",
        0x12 => "return_call function index",
        0x14 => "call_ref type index",
        0x15 => "return_call_ref type index",
        0x20 => "local.get local index",
        0x21 => "local.set local index",
        0x22 => "local.tee local index",
        0x23 => "global.get global index",
        0x24 => "global.set global index",
        0x25 => "table.get table index",
        0x26 => "table.set table index",
        0xd2 => "ref.func function index",
        0xd5 => "br_on_null label depth",
        0xd6 => "br_on_non_null label depth",
        _ => return None,
    };
    match field_checked(&mut reader, field, BinaryReader::read_var_u32) {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(_) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// Locate only unsigned operands of Core GC struct/array instructions. A
/// complete known secondary opcode is required before any field is trusted;
/// heap types, cast flags and future GC instructions have different grammar.
pub(crate) fn gc_immediate_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    if reader.read_u8().ok()? != 0xfb {
        return None;
    }
    let fields: &[&'static str] = match reader.read_var_u32().ok()? {
        0 => &["struct.new type index"],
        1 => &["struct.new_default type index"],
        2 => &["struct.get type index", "struct.get field index"],
        3 => &["struct.get_s type index", "struct.get_s field index"],
        4 => &["struct.get_u type index", "struct.get_u field index"],
        5 => &["struct.set type index", "struct.set field index"],
        6 => &["array.new type index"],
        7 => &["array.new_default type index"],
        8 => &[
            "array.new_fixed type index",
            "array.new_fixed element count",
        ],
        9 => &["array.new_data type index", "array.new_data data index"],
        10 => &["array.new_elem type index", "array.new_elem element index"],
        11 => &["array.get type index"],
        12 => &["array.get_s type index"],
        13 => &["array.get_u type index"],
        14 => &["array.set type index"],
        16 => &["array.fill type index"],
        17 => &[
            "array.copy destination type index",
            "array.copy source type index",
        ],
        18 => &["array.init_data type index", "array.init_data data index"],
        19 => &[
            "array.init_elem type index",
            "array.init_elem element index",
        ],
        _ => return None,
    };
    let scan = (|| -> Scan {
        for &field in fields {
            // Type indices here are full u32, not packed HeapType indices.
            field_checked(&mut reader, field, BinaryReader::read_var_u32)?;
        }
        Ok(())
    })();
    match scan {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// Prove the secondary opcode before locating a bulk-memory/table operand.
/// Every selected operand is a full u32 in the all-known grammar. Stop at the
/// first failure; complete operands prove nothing about a later instruction.
pub(crate) fn bulk_index_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    if reader.read_u8().ok()? != 0xfc {
        return None;
    }
    let fields: &[&'static str] = match reader.read_var_u32().ok()? {
        8 => &["memory.init data index", "memory.init memory index"],
        9 => &["data.drop data index"],
        10 => &[
            "memory.copy destination memory index",
            "memory.copy source memory index",
        ],
        11 => &["memory.fill memory index"],
        12 => &["table.init element index", "table.init table index"],
        13 => &["elem.drop element index"],
        14 => &[
            "table.copy destination table index",
            "table.copy source table index",
        ],
        15 => &["table.grow table index"],
        16 => &["table.size table index"],
        17 => &["table.fill table index"],
        _ => return None,
    };
    let scan = (|| -> Scan {
        for &field in fields {
            field_checked(&mut reader, field, BinaryReader::read_var_u32)?;
        }
        Ok(())
    })();
    match scan {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// These primary opcodes have one full u32 memory index in the all-known
/// grammar. Historical reserved-zero wire rules and namespace validity belong
/// to validation; a complete index proves no failure in a later instruction.
pub(crate) fn memory_index_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    let field = match reader.read_u8().ok()? {
        0x3f => "memory.size memory index",
        0x40 => "memory.grow memory index",
        _ => return None,
    };
    match field_checked(&mut reader, field, BinaryReader::read_var_u32) {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(_) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// Locate a first failed memarg integer in the all-known audit grammar. The
/// exact layouts mirror the classifier's allowlist; adjacent SIMD constants,
/// atomic fences and ordering operands are not memargs. A complete memarg
/// proves no failure in the SIMD lane byte or any following instruction.
pub(crate) fn memarg_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    let selected = match reader.read_u8().ok()? {
        0x28..=0x3e => true,
        0xfd => matches!(reader.read_var_u32().ok()?, 0x00..=0x0b | 0x54..=0x5d),
        0xfe => matches!(reader.read_var_u32().ok()?, 0x00..=0x02 | 0x10..=0x4e),
        _ => false,
    };
    if !selected {
        return None;
    }
    let scan = (|| -> Scan {
        let flags = field_checked(&mut reader, "memarg flags", BinaryReader::read_var_u32)?;
        if flags >= 128 {
            // The pinned reader may fail in an apparent memory index before
            // checking unknown flags. Never use that suffix as known grammar.
            return Err(Stop::Unproved);
        }
        if flags & 64 != 0 {
            field_checked(
                &mut reader,
                "memarg memory index",
                BinaryReader::read_var_u32,
            )?;
        }
        // All-known readers use u64 even when the selected profile is Core1
        // or the referenced memory is 32-bit. Alignment bounds are semantic.
        field_checked(&mut reader, "memarg offset", BinaryReader::read_var_u64)?;
        Ok(())
    })();
    match scan {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// All-known grammar gives these two opcodes a type index followed by a table
/// index. Prove only the first failed u32; namespace limits and Core1's literal
/// reserved table byte belong to later validation, not physical field parsing.
pub(crate) fn call_indirect_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    let (type_field, table_field) = match reader.read_u8().ok()? {
        0x11 => ("call_indirect type index", "call_indirect table index"),
        0x13 => (
            "return_call_indirect type index",
            "return_call_indirect table index",
        ),
        _ => return None,
    };
    let scan = (|| -> Scan {
        field_checked(&mut reader, type_field, BinaryReader::read_var_u32)?;
        field_checked(&mut reader, table_field, BinaryReader::read_var_u32)?;
        Ok(())
    })();
    match scan {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// Mirror the pinned private BlockType dispatch, only to prove success before
/// the catch vector. Block-type failures must not become catch-field errors.
fn try_table_block_prefix(reader: &mut BinaryReader<'_>) -> Option<()> {
    let first = reader.clone().read_u8().ok()?;
    if first == 0x40 {
        reader.read_u8().ok()?;
    } else if first & 0xc0 == 0x40 {
        if !crate::decode_error::value_prefix_known(reader) {
            return None;
        }
        reader.read::<ValType>().ok()?;
    } else {
        // This is a function type index, not a HeapType/PackedIndex. Preserve
        // the full nonnegative s33/u32 range and reject negative aliases.
        u32::try_from(reader.read_var_s33().ok()?).ok()?;
    }
    Some(())
}

/// Locate only the first failed catch-vector field after a proved block type.
/// Unknown kinds and the pinned count limit stop the walk before later bytes.
pub(crate) fn try_table_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<TryTableFailure> {
    crate::decode_error::invalid_encoding(error)?;
    if reader.read_u8().ok()? != 0x1f {
        return None;
    }
    try_table_block_prefix(&mut reader)?;
    let mut catch = None;
    let scan = (|| -> Scan {
        let count = field_checked(&mut reader, "try table catch count", |reader| {
            reader.read_size(10_000, "catches")
        })?;
        for index in 0..count {
            catch = Some(index as u32);
            let kind = field_checked(&mut reader, "kind", BinaryReader::read_u8)?;
            match kind {
                0 | 1 => {
                    field_checked(&mut reader, "tag index", BinaryReader::read_var_u32)?;
                }
                2 | 3 => {}
                _ => return Err(Stop::Unproved),
            }
            field_checked(&mut reader, "label depth", BinaryReader::read_var_u32)?;
        }
        Ok(())
    })();
    match scan {
        Err(Stop::Known(failure)) => Some(TryTableFailure { failure, catch }),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// Diagnose only a failed integer reached from the actual br_table opcode.
/// The count limit mirrors the pinned reader's implementation limit, not a
/// Core encoding rule. Never continue beyond it to diagnose a later target.
pub(crate) fn br_table_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<BrTableFailure> {
    crate::decode_error::invalid_encoding(error)?;
    if reader.read_u8().ok()? != 0x0e {
        return None;
    }
    let mut target = None;
    let scan = (|| -> Scan {
        let count = field_checked(&mut reader, "branch table target count", |reader| {
            reader.read_size(7_654_321, "br_table")
        })?;
        for index in 0..count {
            target = Some(index as u32);
            field_checked(
                &mut reader,
                "branch table target depth",
                BinaryReader::read_var_u32,
            )?;
        }
        target = None;
        field_checked(
            &mut reader,
            "branch table default depth",
            BinaryReader::read_var_u32,
        )?;
        Ok(())
    })();
    match scan {
        Err(Stop::Known(failure)) => Some(BrTableFailure { failure, target }),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// Match the actual failure, then independently reach a known heap operand.
/// A dual-heap cast may reach its target only after a complete source heap and
/// the same reference-type construction that precedes it in the reader.
pub(crate) fn heap_operand_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    if error.message() != "invalid heap type" {
        return None;
    }
    let field = match reader.read_u8().ok()? {
        0xd0 => "heap type operand",
        0xfb => match reader.read_var_u32().ok()? {
            0x14..=0x17 | 0x23..=0x24 => "heap type operand",
            0x18 | 0x19 | 0x25 | 0x26 => {
                let flags = reader.read_u8().ok()?;
                if flags > 3 {
                    return None;
                }
                reader.read_var_u32().ok()?;
                if matches!(reader.clone().read_u8(), Ok(0x7b..=0x7f)) {
                    return numeric_heap_operand(&mut reader, "source heap type operand");
                }
                // HeapType's positive s33 branch is genuine heap grammar,
                // unlike the permissive bare-index fallback in ValType.
                // Never normalize or continue after a failed source read.
                let source = reader.read::<HeapType>().ok()?;
                RefType::new(flags & 1 != 0, source)?;
                "target heap type operand"
            }
            _ => return None,
        },
        _ => return None,
    };
    numeric_heap_operand(&mut reader, field)
}

fn numeric_heap_operand(
    reader: &mut BinaryReader<'_>,
    field: &'static str,
) -> Option<FieldFailure> {
    let start = reader.original_position();
    if !matches!(reader.read_u8().ok()?, 0x7b..=0x7f) {
        return None;
    }
    Some(FieldFailure {
        span: start..reader.original_position(),
        field,
        reason: "known numeric or vector value type is forbidden in a heap-type operand",
    })
}

fn emit(
    start: usize,
    reader: &BinaryReader<'_>,
    kind: PrefixKind,
    facts: &mut impl FnMut(PrefixFact),
) {
    facts(PrefixFact {
        span: start..reader.original_position(),
        kind,
    });
}

fn checked<T>(result: wasmparser::Result<T>) -> Scan<T> {
    result.map_err(|_| Stop::Unproved)
}

fn field_checked<'a, T>(
    reader: &mut BinaryReader<'a>,
    field: &'static str,
    read: impl FnOnce(&mut BinaryReader<'a>) -> wasmparser::Result<T>,
) -> Scan<T> {
    let start = reader.original_position();
    read(reader).map_err(|error| {
        crate::decode_error::invalid_encoding(&error).map_or(Stop::Unproved, |reason| {
            // HeapType may probe with a cloned cursor. A truncated string's
            // bulk read may instead fail before consuming its available data.
            // EOF uses this field's bounded reader end; integer errors cover
            // the last failing byte without extending into following fields.
            let error_end = if error.message() == "unexpected end-of-file" {
                reader.range().end
            } else {
                error.offset().saturating_add(1)
            };
            let end = reader
                .original_position()
                .max(error_end)
                .min(reader.range().end);
            if end < start {
                return Stop::Unproved;
            }
            Stop::Known(FieldFailure {
                span: start..end,
                field,
                reason,
            })
        })
    })
}

fn type_opcode(reader: &mut BinaryReader<'_>) -> Scan<u8> {
    field_checked(reader, "type constructor", BinaryReader::read_u8)
}

fn value(reader: &mut BinaryReader<'_>, reference: bool) -> Scan {
    value_field(
        reader,
        reference,
        if reference {
            "reference type"
        } else {
            "value type"
        },
    )
}

fn value_field(reader: &mut BinaryReader<'_>, reference: bool, field: &'static str) -> Scan {
    if reference && matches!(reader.clone().read_u8(), Ok(0x7b..=0x7f)) {
        // These are complete known value types, but none is a reference type.
        // Diagnose only this token at the proved slot; never read its suffix.
        let start = reader.original_position();
        checked(reader.read_u8())?;
        return Err(Stop::Known(FieldFailure {
            span: start..reader.original_position(),
            field,
            reason: NUMERIC_REFERENCE,
        }));
    }
    // Bare one-byte positive indices keep their existing definite-illegal
    // classification. Never apply this value-prefix check to a heap type or
    // an indexed block type: their positive s33 encodings are legitimate.
    if crate::decode_error::forbidden_bare_index(reader) {
        return Err(Stop::Unproved);
    }
    if !crate::decode_error::value_prefix_known(reader) {
        return Err(Stop::Unknown(reader.original_position()));
    }
    if reference {
        field_checked(reader, field, |reader| reader.read::<RefType>())?;
    } else {
        field_checked(reader, field, |reader| reader.read::<ValType>())?;
    }
    Ok(())
}

fn type_syntax(
    start: usize,
    reader: &BinaryReader<'_>,
    feature: &'static str,
    description: &'static str,
    facts: &mut impl FnMut(PrefixFact),
) {
    emit(
        start,
        reader,
        PrefixKind::TypeSyntax {
            feature,
            description,
        },
        facts,
    );
}

fn type_count(
    reader: &mut BinaryReader<'_>,
    feature: &'static str,
    role: &'static str,
    limit: usize,
    limit_name: &'static str,
    facts: &mut impl FnMut(PrefixFact),
) -> Scan<usize> {
    let start = reader.original_position();
    // Match the pinned type reader's resource admission before visiting any
    // member. These implementation limits do not narrow the Core wire format.
    let count = field_checked(reader, role, |reader| reader.read_size(limit, limit_name))?;
    emit(
        start,
        reader,
        PrefixKind::TypeCount { feature, role },
        facts,
    );
    Ok(count)
}

fn type_value(reader: &mut BinaryReader<'_>, facts: &mut impl FnMut(PrefixFact)) -> Scan {
    let start = reader.original_position();
    value_field(reader, false, "value type")?;
    emit(start, reader, PrefixKind::TypeValue, facts);
    Ok(())
}

fn values(
    reader: &mut BinaryReader<'_>,
    role: &'static str,
    limit_name: &'static str,
    facts: &mut impl FnMut(PrefixFact),
) -> Scan {
    let count = type_count(reader, "core1", role, 1000, limit_name, facts)?;
    for _ in 0..count {
        type_value(reader, facts)?;
    }
    Ok(())
}

fn field(reader: &mut BinaryReader<'_>, facts: &mut impl FnMut(PrefixFact)) -> Scan {
    let start = reader.original_position();
    if matches!(reader.clone().read_u8(), Ok(0x77 | 0x78)) {
        checked(reader.read_u8())?;
        type_syntax(start, reader, "gc", "packed field storage type", facts);
    } else {
        type_value(reader, facts)?;
    }
    let start = reader.original_position();
    if field_checked(reader, "field mutability", BinaryReader::read_u8)? > 1 {
        return Err(Stop::Unproved);
    }
    type_syntax(start, reader, "gc", "field mutability", facts);
    Ok(())
}

fn subtype(reader: &mut BinaryReader<'_>, facts: &mut impl FnMut(PrefixFact)) -> Scan {
    let mut start = reader.original_position();
    let mut opcode = type_opcode(reader)?;
    if matches!(opcode, 0x4f | 0x50) {
        type_syntax(
            start,
            reader,
            "gc",
            "explicit subtyping/finality wire form",
            facts,
        );
        let count = type_count(reader, "gc", "supertype count", 1, "supertype idxs", facts)?;
        for _ in 0..count {
            let start = reader.original_position();
            let index = field_checked(reader, "supertype index", BinaryReader::read_var_u32)?;
            wasmparser::PackedIndex::from_module_index(index).ok_or(Stop::Unproved)?;
            type_syntax(start, reader, "gc", "supertype index wire field", facts);
        }
        start = reader.original_position();
        opcode = type_opcode(reader)?;
    }
    if opcode == 0x65 {
        type_syntax(
            start,
            reader,
            "shared_everything_threads",
            "shared composite type marker",
            facts,
        );
        start = reader.original_position();
        opcode = type_opcode(reader)?;
    }
    if opcode == 0x4c {
        type_syntax(
            start,
            reader,
            "custom_descriptors",
            "describes clause marker",
            facts,
        );
        start = reader.original_position();
        let index = field_checked(reader, "described type index", BinaryReader::read_var_u32)?;
        wasmparser::PackedIndex::from_module_index(index).ok_or(Stop::Unproved)?;
        type_syntax(
            start,
            reader,
            "custom_descriptors",
            "described type index wire field",
            facts,
        );
        start = reader.original_position();
        opcode = type_opcode(reader)?;
    }
    if opcode == 0x4d {
        type_syntax(
            start,
            reader,
            "custom_descriptors",
            "descriptor clause marker",
            facts,
        );
        start = reader.original_position();
        let index = field_checked(reader, "descriptor type index", BinaryReader::read_var_u32)?;
        wasmparser::PackedIndex::from_module_index(index).ok_or(Stop::Unproved)?;
        type_syntax(
            start,
            reader,
            "custom_descriptors",
            "descriptor type index wire field",
            facts,
        );
        start = reader.original_position();
        opcode = type_opcode(reader)?;
    }
    match opcode {
        0x60 => {
            type_syntax(start, reader, "core1", "function type marker", facts);
            values(reader, "function parameter count", "function params", facts)?;
            values(reader, "function result count", "function returns", facts)
        }
        0x5e => {
            type_syntax(start, reader, "gc", "array type marker", facts);
            field(reader, facts)
        }
        0x5f => {
            type_syntax(start, reader, "gc", "struct type marker", facts);
            let count = type_count(
                reader,
                "gc",
                "struct field count",
                10_000,
                "struct fields",
                facts,
            )?;
            for _ in 0..count {
                field(reader, facts)?;
            }
            Ok(())
        }
        0x5d => {
            type_syntax(
                start,
                reader,
                "stack_switching",
                "continuation type marker",
                facts,
            );
            // A continuation refers to a function type with a positive s33,
            // not a value-type encoding.
            let start = reader.original_position();
            field_checked(reader, "continuation function type index", |reader| {
                reader.read::<wasmparser::ContType>()
            })?;
            type_syntax(
                start,
                reader,
                "stack_switching",
                "continuation function type index wire field",
                facts,
            );
            Ok(())
        }
        _ => Err(Stop::Unproved),
    }
}

fn group(reader: &mut BinaryReader<'_>, facts: &mut impl FnMut(PrefixFact)) -> Scan {
    if reader.clone().read_u8().ok() == Some(0x4e) {
        let start = reader.original_position();
        checked(reader.read_u8())?;
        type_syntax(
            start,
            reader,
            "gc",
            "explicit recursive type group marker",
            facts,
        );
        let count = type_count(
            reader,
            "gc",
            "recursive type member count",
            1_000_000,
            "rec group types",
            facts,
        )?;
        for _ in 0..count {
            subtype(reader, facts)?;
        }
        Ok(())
    } else {
        subtype(reader, facts)
    }
}

fn table_type(reader: &mut BinaryReader<'_>) -> Scan {
    let mut original = reader.clone();
    value_field(reader, true, "table reference type")?;
    let flags = field_checked(reader, "table limits flags", BinaryReader::read_u8)?;
    if flags & !0b111 != 0 {
        return Err(Stop::Unproved);
    }
    field_checked(reader, "table minimum", BinaryReader::read_var_u64)?;
    if flags & 1 != 0 {
        field_checked(reader, "table maximum", BinaryReader::read_var_u64)?;
    }
    checked(original.read::<TableType>())?;
    Ok(())
}

fn memory_type(reader: &mut BinaryReader<'_>) -> Scan {
    let mut original = reader.clone();
    let flags = field_checked(reader, "memory limits flags", BinaryReader::read_u8)?;
    if flags & !0b1111 != 0 {
        return Err(Stop::Unproved);
    }
    // All-known decoding enables memory64 grammar for both address modes.
    // The address-width flag does not narrow these limit LEBs.
    field_checked(reader, "memory minimum", BinaryReader::read_var_u64)?;
    if flags & 1 != 0 {
        field_checked(reader, "memory maximum", BinaryReader::read_var_u64)?;
    }
    if flags & 8 != 0
        && field_checked(reader, "memory page size", BinaryReader::read_var_u32)? >= 64
    {
        return Err(Stop::Unproved);
    }
    checked(original.read::<MemoryType>())?;
    Ok(())
}

fn global_type(reader: &mut BinaryReader<'_>) -> Scan {
    let mut original = reader.clone();
    value_field(reader, false, "global value type")?;
    if field_checked(reader, "global flags", BinaryReader::read_u8)? > 3 {
        return Err(Stop::Unproved);
    }
    checked(original.read::<GlobalType>())?;
    Ok(())
}

fn tag_type(reader: &mut BinaryReader<'_>) -> Scan {
    let mut original = reader.clone();
    if field_checked(reader, "tag attribute", BinaryReader::read_u8)? != 0 {
        return Err(Stop::Unproved);
    }
    field_checked(reader, "tag type index", BinaryReader::read_var_u32)?;
    checked(original.read::<TagType>())?;
    Ok(())
}

fn import_type(reader: &mut BinaryReader<'_>, facts: &mut impl FnMut(PrefixFact)) -> Scan {
    let start = reader.original_position();
    let mut original = reader.clone();
    let kind = field_checked(reader, "import kind", |reader| {
        reader.read::<ExternalKind>()
    })?;
    emit(start, reader, PrefixKind::ImportKind, facts);
    match kind {
        ExternalKind::Func | ExternalKind::FuncExact => {
            field_checked(reader, "function type index", BinaryReader::read_var_u32)?;
        }
        ExternalKind::Table => table_type(reader)?,
        ExternalKind::Memory => memory_type(reader)?,
        ExternalKind::Global => global_type(reader)?,
        ExternalKind::Tag => tag_type(reader)?,
    }
    // Completed wire fields must still agree with the pinned TypeRef reader
    // before a later unknown member may retain them as prefix evidence.
    checked(original.read::<TypeRef>())?;
    emit(start, reader, PrefixKind::CompleteImportType, facts);
    Ok(())
}

fn name(
    reader: &mut BinaryReader<'_>,
    role: &'static str,
    facts: &mut impl FnMut(PrefixFact),
) -> Scan<bool> {
    let start = reader.original_position();
    let empty = field_checked(reader, role, BinaryReader::read_string)?.is_empty();
    emit(start, reader, PrefixKind::Name(role), facts);
    Ok(empty)
}

fn imports(reader: &mut BinaryReader<'_>, facts: &mut impl FnMut(PrefixFact)) -> Scan {
    name(reader, "module name", facts)?;
    let name_is_empty = name(reader, "item name", facts)?;
    let discriminator = reader.clone().read_u8().ok();
    if name_is_empty && discriminator == Some(0x7f) {
        let start = reader.original_position();
        checked(reader.read_u8())?;
        emit(start, reader, PrefixKind::CompactImports, facts);
        let start = reader.original_position();
        let count = field_checked(
            reader,
            "compact import member count",
            BinaryReader::read_var_u32,
        )?;
        emit(start, reader, PrefixKind::MemberCount, facts);
        for _ in 0..count {
            name(reader, "member name", facts)?;
            import_type(reader, facts)?;
        }
        Ok(())
    } else if name_is_empty && discriminator == Some(0x7e) {
        let start = reader.original_position();
        checked(reader.read_u8())?;
        emit(start, reader, PrefixKind::CompactImports, facts);
        import_type(reader, facts)?;
        let start = reader.original_position();
        let count = field_checked(
            reader,
            "compact import member count",
            BinaryReader::read_var_u32,
        )?;
        emit(start, reader, PrefixKind::MemberCount, facts);
        for _ in 0..count {
            name(reader, "member name", facts)?;
        }
        Ok(())
    } else {
        import_type(reader, facts)
    }
}

/// Never skip over an unknown instruction or permissive typed-select value
/// fallback merely to reach a later element type. The expression decoder owns
/// recovery and withdrawal from such an unproved frontier.
fn expression(reader: &mut BinaryReader<'_>) -> Scan {
    let mut operators = OperatorsReader::new(reader.clone());
    while !operators.eof() {
        if operators.current_frame().is_none()
            || crate::decode_error::select_value_prefix(operators.get_binary_reader()).is_some()
        {
            return Err(Stop::Unproved);
        }
        let operator = checked(operators.read())?;
        if matches!(operator, Operator::End) {
            // ConstExpr ends at its first End. A nested End cannot prove
            // the following bytes to be element metadata.
            if operators.current_frame().is_some() {
                return Err(Stop::Unproved);
            }
            *reader = operators.get_binary_reader();
            return Ok(());
        }
    }
    Err(Stop::Unproved)
}

fn table_header(reader: &mut BinaryReader<'_>, facts: &mut impl FnMut(PrefixFact)) -> Scan<bool> {
    let initialized = reader.clone().read_u8().ok() == Some(0x40);
    if initialized {
        let start = reader.original_position();
        checked(reader.read_u8())?;
        if field_checked(
            reader,
            "table initializer reserved byte",
            BinaryReader::read_u8,
        )? != 0
        {
            return Err(Stop::Unproved);
        }
        emit(start, reader, PrefixKind::TableInitializer, facts);
    }
    table_type(reader)?;
    Ok(initialized)
}

fn table(reader: &mut BinaryReader<'_>, facts: &mut impl FnMut(PrefixFact)) -> Scan {
    if table_header(reader, facts)? {
        expression(reader)?;
    }
    Ok(())
}

fn element(reader: &mut BinaryReader<'_>) -> Scan {
    let flags = checked(reader.read_var_u32())?;
    if flags > 7 {
        return Err(Stop::Unproved);
    }
    if flags & 1 == 0 {
        if flags & 2 != 0 {
            checked(reader.read_var_u32())?;
        }
        expression(reader)?;
    }
    if flags & 3 != 0 {
        if flags & 4 != 0 {
            value(reader, true)?;
        } else if checked(reader.read::<ExternalKind>())? != ExternalKind::Func {
            return Err(Stop::Unproved);
        }
    }
    // No later non-expression value type occurs in this entry. Item expression
    // prefixes are checked by the existing strict expression decoder itself.
    Ok(())
}

/// Return the first unknown value-type prefix reached through known grammar.
/// `reader` starts at a proved entry boundary and is bounded by its section.
/// Never read beyond the first unknown prefix to decide whether it exists;
/// unknown bytes cannot authorize the remainder of this entry or later ones.
fn scan_entry(
    section: u8,
    mut reader: BinaryReader<'_>,
    facts: &mut impl FnMut(PrefixFact),
) -> Scan {
    match section {
        1 => group(&mut reader, facts),
        2 => imports(&mut reader, facts),
        4 => table(&mut reader, facts),
        5 => memory_type(&mut reader),
        6 => global_type(&mut reader),
        13 => tag_type(&mut reader),
        9 => element(&mut reader),
        _ => Err(Stop::Unproved),
    }
}

pub(crate) fn unknown_entry_value(section: u8, reader: BinaryReader<'_>) -> Option<usize> {
    match scan_entry(section, reader, &mut |_| {}) {
        Err(Stop::Unknown(offset)) => Some(offset),
        Ok(()) | Err(Stop::Known(_) | Stop::Unproved) => None,
    }
}

/// Reuse the same strict scan to retain only physical facts preceding the
/// unknown type. Any earlier failure discards the entire candidate batch.
pub(crate) fn unknown_entry_prefix(section: u8, reader: BinaryReader<'_>) -> Option<UnknownPrefix> {
    let mut facts = Vec::new();
    match scan_entry(section, reader, &mut |fact| facts.push(fact)) {
        Err(Stop::Unknown(offset)) => Some(UnknownPrefix { offset, facts }),
        Ok(()) | Err(Stop::Known(_) | Stop::Unproved) => None,
    }
}

/// Both the original reader and the strict walk must prove a definite error.
/// In particular, an upstream implementation limit cannot authorize a later
/// integer/EOF diagnosis reached only by walking beyond that limit.
pub(crate) fn type_failure(
    error: &wasmparser::BinaryReaderError,
    reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    declaration_failure(1, error, reader)
}

pub(crate) fn import_failure(
    error: &wasmparser::BinaryReaderError,
    reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    reference_slot_failure(2, error, reader.clone())
        .or_else(|| declaration_failure(2, error, reader))
}

/// Only declaration headers are diagnosed here. Complete table/global headers
/// do not authorize a field diagnosis inside their separate initializer.
pub(crate) fn header_failure(
    section: u8,
    error: &wasmparser::BinaryReaderError,
    reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    if !matches!(section, 4 | 5 | 6 | 13) {
        return None;
    }
    reference_slot_failure(section, error, reader.clone())
        .or_else(|| declaration_failure(section, error, reader))
}

/// The caller proves this is a known vector section's payload start. Unknown
/// sections and the scalar start/data-count payloads have no vector grammar.
pub(crate) fn count_failure(
    section: u8,
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    if !matches!(section, 1 | 2 | 3 | 4 | 5 | 6 | 7 | 9 | 10 | 11 | 13) {
        return None;
    }
    crate::decode_error::invalid_encoding(error)?;
    match field_checked(
        &mut reader,
        "section entry count",
        BinaryReader::read_var_u32,
    ) {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(_) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

fn export(reader: &mut BinaryReader<'_>) -> Scan {
    field_checked(reader, "export name", BinaryReader::read_string)?;
    let kind = field_checked(reader, "export kind", |reader| {
        reader.read::<ExternalKind>()
    })?;
    let field = match kind {
        ExternalKind::Func => "export function index",
        ExternalKind::Table => "export table index",
        ExternalKind::Memory => "export memory index",
        ExternalKind::Global => "export global index",
        ExternalKind::Tag => "export tag index",
        // This known kind is forbidden by the export grammar. Its existing
        // linkage diagnostic has priority; it never authorizes reading an index.
        ExternalKind::FuncExact => return Err(Stop::Unproved),
    };
    field_checked(reader, field, BinaryReader::read_var_u32)?;
    Ok(())
}

/// Read only the scalar payload or export fields reached through proven known
/// grammar. No successful scalar or unknown kind can authorize a later error.
pub(crate) fn scalar_failure(
    section: u8,
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    let scan = match section {
        3 => field_checked(
            &mut reader,
            "function type index",
            BinaryReader::read_var_u32,
        )
        .map(|_| ()),
        7 => export(&mut reader),
        8 => field_checked(
            &mut reader,
            "start function index",
            BinaryReader::read_var_u32,
        )
        .map(|_| ()),
        12 => field_checked(&mut reader, "data count", BinaryReader::read_var_u32).map(|_| ()),
        _ => return None,
    };
    match scan {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// The caller supplies the actual failed locals-reader operation and a reader
/// bounded by that function body. In particular, cumulative-count and resource
/// errors cannot authorize a fresh walk into a later value type or operator.
pub(crate) fn locals_field_failure(
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
    group: bool,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    let scan = (|| -> Scan {
        field_checked(
            &mut reader,
            if group {
                "local repetition count"
            } else {
                "local declaration count"
            },
            BinaryReader::read_var_u32,
        )?;
        if group {
            value_field(&mut reader, false, "local value type")?;
        }
        Ok(())
    })();
    match scan {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

fn element_fields(reader: &mut BinaryReader<'_>) -> Scan {
    let flags = field_checked(reader, "element flags", BinaryReader::read_var_u32)?;
    if flags > 7 {
        return Err(Stop::Unproved);
    }
    if flags & 1 == 0 {
        if flags & 2 != 0 {
            field_checked(reader, "element table index", BinaryReader::read_var_u32)?;
        }
        expression(reader)?;
    }
    if flags & 3 != 0 {
        if flags & 4 != 0 {
            value_field(reader, true, "element reference type")?;
        } else if field_checked(reader, "element kind", BinaryReader::read_u8)? != 0 {
            return Err(Stop::Unproved);
        }
    }
    let count = field_checked(reader, "element item count", BinaryReader::read_var_u32)?;
    if flags & 4 != 0 {
        // The count is a known field, but item expressions have their own
        // recovery. Never skip an unknown item to find a later field or item.
        return Err(Stop::Unproved);
    }
    for _ in 0..count {
        field_checked(reader, "element function index", BinaryReader::read_var_u32)?;
    }
    Ok(())
}

fn data_fields(reader: &mut BinaryReader<'_>) -> Scan {
    match field_checked(reader, "data flags", BinaryReader::read_var_u32)? {
        0 => expression(reader)?,
        1 => {}
        2 => {
            field_checked(reader, "data memory index", BinaryReader::read_var_u32)?;
            expression(reader)?;
        }
        _ => return Err(Stop::Unproved),
    }
    let size = field_checked(reader, "data byte count", BinaryReader::read_var_u32)?;
    field_checked(reader, "data bytes", |reader| {
        reader.read_bytes(size as usize)
    })?;
    Ok(())
}

fn code_frame(reader: &mut BinaryReader<'_>) -> Scan {
    let size = field_checked(reader, "function body size", BinaryReader::read_var_u32)?;
    field_checked(reader, "function body bytes", |reader| {
        reader.read_bytes(size as usize)
    })?;
    // A complete frame proves only its size and byte range. Locals and
    // operators remain owned by the existing, separately bounded body decoder.
    Ok(())
}

/// Diagnose segment metadata and code frames only through independently known
/// field boundaries. Unknown expressions never authorize later metadata reads.
pub(crate) fn segment_failure(
    section: u8,
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    if let Some(failure) = reference_slot_failure(section, error, reader.clone()) {
        return Some(failure);
    }
    crate::decode_error::invalid_encoding(error)?;
    let scan = match section {
        9 => element_fields(&mut reader),
        10 => code_frame(&mut reader),
        11 => data_fields(&mut reader),
        _ => return None,
    };
    match scan {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}

/// The reader also uses this error for unknown reference constructors. Only
/// a strict walk reaching a complete numeric/vector token in a reference-only
/// slot proves this particular failure; never widen the general error whitelist.
pub(crate) fn reference_slot_failure(
    section: u8,
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    if error.message() != "malformed reference type" {
        return None;
    }
    let scan = match section {
        2 => imports(&mut reader, &mut |_| {}),
        4 => table_header(&mut reader, &mut |_| {}).map(|_| ()),
        9 => element_fields(&mut reader),
        _ => return None,
    };
    match scan {
        Err(Stop::Known(failure)) if failure.reason == NUMERIC_REFERENCE => Some(failure),
        _ => None,
    }
}

fn declaration_failure(
    section: u8,
    error: &wasmparser::BinaryReaderError,
    mut reader: BinaryReader<'_>,
) -> Option<FieldFailure> {
    crate::decode_error::invalid_encoding(error)?;
    let scan = if section == 4 {
        table_header(&mut reader, &mut |_| {}).map(|_| ())
    } else {
        scan_entry(section, reader, &mut |_| {})
    };
    match scan {
        Err(Stop::Known(failure)) => Some(failure),
        Ok(()) | Err(Stop::Unknown(_) | Stop::Unproved) => None,
    }
}
