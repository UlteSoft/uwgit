//! Internal representations of a Wasm module.
//!
//! Transition state: this file currently holds MVP IR types (ModuleIr,
//! FunctionIr, etc.) that will evolve into the three-layer Parsed/Resolved/
//! Normalized IR described in doc/wasm-git-ir-design.md.
//!
//! Layer mapping for Phase 2/3:
//!   ParsedModule     = parser output; keeps raw indices/operators only
//!   ResolvedModule   = central hub; adds stable refs/IDs for downstream users
//!   NormalizedModule = diff/fingerprint branch derived from ResolvedModule
//!   AnalysisModule   = CFG/CallGraph/Security branch derived from ResolvedModule
//!
//! `ModuleIr` and `FunctionIr` remain the transitional payload carried by the
//! layer wrappers while the block tree and richer section types are migrated in.

use serde::Serialize;
use std::ops::Deref;

use crate::fingerprint::FuncFingerprint;

// ---------------------------------------------------------------------------
// Phase 1: typed operator layer
// ---------------------------------------------------------------------------

/// Typed opcode for every WebAssembly instruction.
///
/// Explicit variants cover commonly used opcodes. Unrecognized opcodes
/// are stored via `Unrecognized(String)` which preserves the wasmparser
/// `Debug` name for display and hashing, without enabling pattern-matching
/// on the string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Opcode {
    // ── Control ──
    Unreachable,
    Nop,
    Block,
    Loop,
    If,
    Else,
    End,
    Br,
    BrIf,
    BrTable,
    Return,
    // ── Call ──
    Call,
    CallIndirect,
    ReturnCall,
    ReturnCallIndirect,
    CallRef,
    ReturnCallRef,
    // ── Parametric ──
    Drop,
    Select,
    // ── Variable ──
    LocalGet,
    LocalSet,
    LocalTee,
    GlobalGet,
    GlobalSet,
    // ── Table ──
    TableGet,
    TableSet,
    TableSize,
    TableGrow,
    TableFill,
    TableCopy,
    TableInit,
    ElemDrop,
    // ── Memory load ──
    I32Load,
    I64Load,
    F32Load,
    F64Load,
    I32Load8S,
    I32Load8U,
    I32Load16S,
    I32Load16U,
    I64Load8S,
    I64Load8U,
    I64Load16S,
    I64Load16U,
    I64Load32S,
    I64Load32U,
    // ── Memory store ──
    I32Store,
    I64Store,
    F32Store,
    F64Store,
    I32Store8,
    I32Store16,
    I64Store8,
    I64Store16,
    I64Store32,
    // ── Memory misc ──
    MemorySize,
    MemoryGrow,
    MemoryInit,
    DataDrop,
    MemoryCopy,
    MemoryFill,
    // ── Constants ──
    I32Const,
    I64Const,
    F32Const,
    F64Const,
    // ── Reference ──
    RefNull,
    RefIsNull,
    RefFunc,
    RefEq,
    RefAsNonNull,
    BrOnNull,
    BrOnNonNull,
    // ── i32 test ──
    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    // ── i64 test ──
    I64Eqz,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,
    // ── f32 test ──
    F32Eq,
    F32Ne,
    F32Lt,
    F32Gt,
    F32Le,
    F32Ge,
    // ── f64 test ──
    F64Eq,
    F64Ne,
    F64Lt,
    F64Gt,
    F64Le,
    F64Ge,
    // ── i32 unary ──
    I32Clz,
    I32Ctz,
    I32Popcnt,
    I32Extend8S,
    I32Extend16S,
    // ── i64 unary ──
    I64Clz,
    I64Ctz,
    I64Popcnt,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    // ── f32 unary ──
    F32Abs,
    F32Neg,
    F32Ceil,
    F32Floor,
    F32Trunc,
    F32Nearest,
    F32Sqrt,
    // ── f64 unary ──
    F64Abs,
    F64Neg,
    F64Ceil,
    F64Floor,
    F64Trunc,
    F64Nearest,
    F64Sqrt,
    // ── i32 binary ──
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,
    // ── i64 binary ──
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,
    // ── f32 binary ──
    F32Add,
    F32Sub,
    F32Mul,
    F32Div,
    F32Min,
    F32Max,
    F32Copysign,
    // ── f64 binary ──
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    F64Min,
    F64Max,
    F64Copysign,
    // ── Conversions ──
    I32WrapI64,
    I32TruncF32S,
    I32TruncF32U,
    I32TruncF64S,
    I32TruncF64U,
    I64ExtendI32S,
    I64ExtendI32U,
    I64TruncF32S,
    I64TruncF32U,
    I64TruncF64S,
    I64TruncF64U,
    F32ConvertI32S,
    F32ConvertI32U,
    F32ConvertI64S,
    F32ConvertI64U,
    F32DemoteF64,
    F64ConvertI32S,
    F64ConvertI32U,
    F64ConvertI64S,
    F64ConvertI64U,
    F64PromoteF32,
    I32ReinterpretF32,
    I64ReinterpretF64,
    F32ReinterpretI32,
    F64ReinterpretI64,
    I32TruncSatF32S,
    I32TruncSatF32U,
    I32TruncSatF64S,
    I32TruncSatF64U,
    I64TruncSatF32S,
    I64TruncSatF32U,
    I64TruncSatF64S,
    I64TruncSatF64U,
    // ── SIMD ──
    V128Load,
    V128Load8x8S,
    V128Load8x8U,
    V128Load16x4S,
    V128Load16x4U,
    V128Load32x2S,
    V128Load32x2U,
    V128Load8Splat,
    V128Load16Splat,
    V128Load32Splat,
    V128Load64Splat,
    V128Load32Zero,
    V128Load64Zero,
    V128Store,
    V128Const,
    V128Load8Lane,
    V128Load16Lane,
    V128Load32Lane,
    V128Load64Lane,
    V128Store8Lane,
    V128Store16Lane,
    V128Store32Lane,
    V128Store64Lane,
    I8x16Shuffle,
    I8x16Swizzle,
    I8x16Splat,
    I16x8Splat,
    I32x4Splat,
    I64x2Splat,
    F32x4Splat,
    F64x2Splat,
    I8x16ExtractLaneS,
    I8x16ExtractLaneU,
    I8x16ReplaceLane,
    I16x8ExtractLaneS,
    I16x8ExtractLaneU,
    I16x8ReplaceLane,
    I32x4ExtractLane,
    I32x4ReplaceLane,
    I64x2ExtractLane,
    I64x2ReplaceLane,
    F32x4ExtractLane,
    F32x4ReplaceLane,
    F64x2ExtractLane,
    F64x2ReplaceLane,
    I8x16Eq,
    I8x16Ne,
    I8x16LtS,
    I8x16LtU,
    I8x16GtS,
    I8x16GtU,
    I8x16LeS,
    I8x16LeU,
    I8x16GeS,
    I8x16GeU,
    I16x8Eq,
    I16x8Ne,
    I16x8LtS,
    I16x8LtU,
    I16x8GtS,
    I16x8GtU,
    I16x8LeS,
    I16x8LeU,
    I16x8GeS,
    I16x8GeU,
    I32x4Eq,
    I32x4Ne,
    I32x4LtS,
    I32x4LtU,
    I32x4GtS,
    I32x4GtU,
    I32x4LeS,
    I32x4LeU,
    I32x4GeS,
    I32x4GeU,
    I64x2Eq,
    I64x2Ne,
    I64x2LtS,
    I64x2GtS,
    I64x2LeS,
    I64x2GeS,
    F32x4Eq,
    F32x4Ne,
    F32x4Lt,
    F32x4Gt,
    F32x4Le,
    F32x4Ge,
    F64x2Eq,
    F64x2Ne,
    F64x2Lt,
    F64x2Gt,
    F64x2Le,
    F64x2Ge,
    I8x16Neg,
    I8x16Popcnt,
    I16x8Neg,
    I32x4Neg,
    I64x2Neg,
    F32x4Neg,
    F64x2Neg,
    I8x16Abs,
    I16x8Abs,
    I32x4Abs,
    I64x2Abs,
    F32x4Abs,
    F64x2Abs,
    F32x4Sqrt,
    F64x2Sqrt,
    I8x16Add,
    I16x8Add,
    I32x4Add,
    I64x2Add,
    F32x4Add,
    F64x2Add,
    I8x16AddSatS,
    I8x16AddSatU,
    I16x8AddSatS,
    I16x8AddSatU,
    I8x16Sub,
    I16x8Sub,
    I32x4Sub,
    I64x2Sub,
    F32x4Sub,
    F64x2Sub,
    I8x16SubSatS,
    I8x16SubSatU,
    I16x8SubSatS,
    I16x8SubSatU,
    I8x16MinS,
    I8x16MinU,
    I16x8MinS,
    I16x8MinU,
    I32x4MinS,
    I32x4MinU,
    I64x2MinS,
    I64x2MinU,
    F32x4Min,
    F64x2Min,
    I8x16MaxS,
    I8x16MaxU,
    I16x8MaxS,
    I16x8MaxU,
    I32x4MaxS,
    I32x4MaxU,
    I64x2MaxS,
    I64x2MaxU,
    F32x4Max,
    F64x2Max,
    I8x16AvgrU,
    I16x8AvgrU,
    I8x16RoundingAverageU,
    I16x8RoundingAverageU,
    I8x16Mul,
    I16x8Mul,
    I32x4Mul,
    I64x2Mul,
    F32x4Mul,
    F64x2Mul,
    I16x8Q15MulrSatS,
    I16x8ExtMulLowI8x16S,
    I16x8ExtMulHighI8x16S,
    I16x8ExtMulLowI8x16U,
    I16x8ExtMulHighI8x16U,
    I32x4ExtMulLowI16x8S,
    I32x4ExtMulHighI16x8S,
    I32x4ExtMulLowI16x8U,
    I32x4ExtMulHighI16x8U,
    I64x2ExtMulLowI32x4S,
    I64x2ExtMulHighI32x4S,
    I64x2ExtMulLowI32x4U,
    I64x2ExtMulHighI32x4U,
    I8x16Shl,
    I16x8Shl,
    I32x4Shl,
    I64x2Shl,
    I8x16ShrS,
    I8x16ShrU,
    I16x8ShrS,
    I16x8ShrU,
    I32x4ShrS,
    I32x4ShrU,
    I64x2ShrS,
    I64x2ShrU,
    I8x16AllTrue,
    I16x8AllTrue,
    I32x4AllTrue,
    I64x2AllTrue,
    I8x16Bitmask,
    I16x8Bitmask,
    I32x4Bitmask,
    I64x2Bitmask,
    I8x16NarrowI16x8S,
    I8x16NarrowI16x8U,
    I16x8NarrowI32x4S,
    I16x8NarrowI32x4U,
    I16x8ExtendLowI8x16S,
    I16x8ExtendHighI8x16S,
    I16x8ExtendLowI8x16U,
    I16x8ExtendHighI8x16U,
    I32x4ExtendLowI16x8S,
    I32x4ExtendHighI16x8S,
    I32x4ExtendLowI16x8U,
    I32x4ExtendHighI16x8U,
    I64x2ExtendLowI32x4S,
    I64x2ExtendHighI32x4S,
    I64x2ExtendLowI32x4U,
    I64x2ExtendHighI32x4U,
    I32x4TruncSatF32x4S,
    I32x4TruncSatF32x4U,
    I32x4TruncSatF64x2SZero,
    I32x4TruncSatF64x2UZero,
    F32x4ConvertI32x4S,
    F32x4ConvertI32x4U,
    F64x2ConvertLowI32x4S,
    F64x2ConvertLowI32x4U,
    F32x4DemoteF64x2Zero,
    F64x2PromoteLowF32x4,
    F32x4Ceil,
    F32x4Floor,
    F32x4Trunc,
    F32x4Nearest,
    F64x2Ceil,
    F64x2Floor,
    F64x2Trunc,
    F64x2Nearest,
    I32x4DotI16x8S,
    I16x8ExtAddPairwiseI8x16S,
    I16x8ExtAddPairwiseI8x16U,
    I32x4ExtAddPairwiseI16x8S,
    I32x4ExtAddPairwiseI16x8U,
    V128AnyTrue,
    V128And,
    V128AndNot,
    V128Or,
    V128Xor,
    V128Not,
    V128Bitselect,
    F32x4Div,
    F32x4PMin,
    F32x4PMax,
    F64x2Div,
    F64x2PMin,
    F64x2PMax,
    I8x16RelaxedSwizzle,
    I32x4RelaxedTruncF32x4S,
    I32x4RelaxedTruncF32x4U,
    I32x4RelaxedTruncF64x2SZero,
    I32x4RelaxedTruncF64x2UZero,
    F32x4RelaxedMadd,
    F32x4RelaxedNmadd,
    F64x2RelaxedMadd,
    F64x2RelaxedNmadd,
    I8x16RelaxedLaneselect,
    I16x8RelaxedLaneselect,
    I32x4RelaxedLaneselect,
    I64x2RelaxedLaneselect,
    F32x4RelaxedMin,
    F32x4RelaxedMax,
    F64x2RelaxedMin,
    F64x2RelaxedMax,
    I16x8RelaxedQ15mulrS,
    I16x8RelaxedDotI8x16I7x16S,
    I32x4RelaxedDotI8x16I7x16AddS,
    // ── Atomic ──
    MemoryAtomicNotify,
    MemoryAtomicWait32,
    MemoryAtomicWait64,
    AtomicFence,
    I32AtomicLoad,
    I64AtomicLoad,
    I32AtomicLoad8U,
    I32AtomicLoad16U,
    I64AtomicLoad8U,
    I64AtomicLoad16U,
    I64AtomicLoad32U,
    I32AtomicStore,
    I64AtomicStore,
    I32AtomicStore8,
    I32AtomicStore16,
    I64AtomicStore8,
    I64AtomicStore16,
    I64AtomicStore32,
    I32AtomicRmwAdd,
    I64AtomicRmwAdd,
    I32AtomicRmw8AddU,
    I32AtomicRmw16AddU,
    I64AtomicRmw8AddU,
    I64AtomicRmw16AddU,
    I64AtomicRmw32AddU,
    I32AtomicRmwSub,
    I64AtomicRmwSub,
    I32AtomicRmw8SubU,
    I32AtomicRmw16SubU,
    I64AtomicRmw8SubU,
    I64AtomicRmw16SubU,
    I64AtomicRmw32SubU,
    I32AtomicRmwAnd,
    I64AtomicRmwAnd,
    I32AtomicRmw8AndU,
    I32AtomicRmw16AndU,
    I64AtomicRmw8AndU,
    I64AtomicRmw16AndU,
    I64AtomicRmw32AndU,
    I32AtomicRmwOr,
    I64AtomicRmwOr,
    I32AtomicRmw8OrU,
    I32AtomicRmw16OrU,
    I64AtomicRmw8OrU,
    I64AtomicRmw16OrU,
    I64AtomicRmw32OrU,
    I32AtomicRmwXor,
    I64AtomicRmwXor,
    I32AtomicRmw8XorU,
    I32AtomicRmw16XorU,
    I64AtomicRmw8XorU,
    I64AtomicRmw16XorU,
    I64AtomicRmw32XorU,
    I32AtomicRmwXchg,
    I64AtomicRmwXchg,
    I32AtomicRmw8XchgU,
    I32AtomicRmw16XchgU,
    I64AtomicRmw8XchgU,
    I64AtomicRmw16XchgU,
    I64AtomicRmw32XchgU,
    I32AtomicRmwCmpxchg,
    I64AtomicRmwCmpxchg,
    I32AtomicRmw8CmpxchgU,
    I32AtomicRmw16CmpxchgU,
    I64AtomicRmw8CmpxchgU,
    I64AtomicRmw16CmpxchgU,
    I64AtomicRmw32CmpxchgU,
    // ── GC ──
    StructNew,
    StructNewDefault,
    StructGet,
    StructGetS,
    StructGetU,
    StructSet,
    ArrayNew,
    ArrayNewDefault,
    ArrayNewFixed,
    ArrayNewData,
    ArrayNewElem,
    ArrayGet,
    ArrayGetS,
    ArrayGetU,
    ArraySet,
    ArrayLen,
    ArrayFill,
    ArrayCopy,
    ArrayInitData,
    ArrayInitElem,
    RefTestRef,
    RefTestNonNullRef,
    RefCastRef,
    RefCastNonNullRef,
    BrOnCast,
    BrOnCastFail,
    AnyConvertExtern,
    ExternConvertAny,
    RefI31,
    I31GetS,
    I31GetU,
    // ── Exception handling ──
    TryTable,
    Throw,
    ThrowRef,
    Rethrow,
    Catch,
    CatchAll,
    Delegate,
    // ── Tail call ──
    // (ReturnCall and ReturnCallIndirect already covered above)
    // ── Catch-all for opcodes not yet individually enumerated ──
    #[serde(serialize_with = "serialize_unrecognized")]
    Unrecognized(String),
}

impl Opcode {
    /// Return the opcode name suitable for display and hashing.
    /// For explicitly-named variants this is the variant name, for
    /// Unrecognized this is the stored string.
    pub fn as_str(&self) -> &str {
        match self {
            Opcode::Unrecognized(s) => s.as_str(),
            _ => self.variant_name(),
        }
    }

    pub fn is_structural_marker(&self) -> bool {
        matches!(
            self,
            Opcode::Block
                | Opcode::Loop
                | Opcode::Else
                | Opcode::End
                | Opcode::Catch
                | Opcode::CatchAll
        )
    }

    pub fn is_conditional_branch(&self) -> bool {
        matches!(
            self,
            Opcode::If
                | Opcode::BrIf
                | Opcode::BrOnNull
                | Opcode::BrOnNonNull
                | Opcode::BrOnCast
                | Opcode::BrOnCastFail
        )
    }

    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            Opcode::Br
                | Opcode::BrTable
                | Opcode::Return
                | Opcode::Unreachable
                | Opcode::ReturnCall
                | Opcode::ReturnCallIndirect
                | Opcode::ReturnCallRef
                | Opcode::Throw
                | Opcode::ThrowRef
                | Opcode::Rethrow
                | Opcode::Delegate
                | Opcode::TryTable
        )
    }

    fn variant_name(&self) -> &'static str {
        match self {
            // Control
            Opcode::Unreachable => "Unreachable",
            Opcode::Nop => "Nop",
            Opcode::Block => "Block",
            Opcode::Loop => "Loop",
            Opcode::If => "If",
            Opcode::Else => "Else",
            Opcode::End => "End",
            Opcode::Br => "Br",
            Opcode::BrIf => "BrIf",
            Opcode::BrTable => "BrTable",
            Opcode::Return => "Return",
            // Call
            Opcode::Call => "Call",
            Opcode::CallIndirect => "CallIndirect",
            Opcode::ReturnCall => "ReturnCall",
            Opcode::ReturnCallIndirect => "ReturnCallIndirect",
            Opcode::CallRef => "CallRef",
            Opcode::ReturnCallRef => "ReturnCallRef",
            // Parametric
            Opcode::Drop => "Drop",
            Opcode::Select => "Select",
            // Variable
            Opcode::LocalGet => "LocalGet",
            Opcode::LocalSet => "LocalSet",
            Opcode::LocalTee => "LocalTee",
            Opcode::GlobalGet => "GlobalGet",
            Opcode::GlobalSet => "GlobalSet",
            // Table
            Opcode::TableGet => "TableGet",
            Opcode::TableSet => "TableSet",
            Opcode::TableSize => "TableSize",
            Opcode::TableGrow => "TableGrow",
            Opcode::TableFill => "TableFill",
            Opcode::TableCopy => "TableCopy",
            Opcode::TableInit => "TableInit",
            Opcode::ElemDrop => "ElemDrop",
            // Memory load
            Opcode::I32Load => "I32Load",
            Opcode::I64Load => "I64Load",
            Opcode::F32Load => "F32Load",
            Opcode::F64Load => "F64Load",
            Opcode::I32Load8S => "I32Load8S",
            Opcode::I32Load8U => "I32Load8U",
            Opcode::I32Load16S => "I32Load16S",
            Opcode::I32Load16U => "I32Load16U",
            Opcode::I64Load8S => "I64Load8S",
            Opcode::I64Load8U => "I64Load8U",
            Opcode::I64Load16S => "I64Load16S",
            Opcode::I64Load16U => "I64Load16U",
            Opcode::I64Load32S => "I64Load32S",
            Opcode::I64Load32U => "I64Load32U",
            // Memory store
            Opcode::I32Store => "I32Store",
            Opcode::I64Store => "I64Store",
            Opcode::F32Store => "F32Store",
            Opcode::F64Store => "F64Store",
            Opcode::I32Store8 => "I32Store8",
            Opcode::I32Store16 => "I32Store16",
            Opcode::I64Store8 => "I64Store8",
            Opcode::I64Store16 => "I64Store16",
            Opcode::I64Store32 => "I64Store32",
            // Memory misc
            Opcode::MemorySize => "MemorySize",
            Opcode::MemoryGrow => "MemoryGrow",
            Opcode::MemoryInit => "MemoryInit",
            Opcode::DataDrop => "DataDrop",
            Opcode::MemoryCopy => "MemoryCopy",
            Opcode::MemoryFill => "MemoryFill",
            // Constants
            Opcode::I32Const => "I32Const",
            Opcode::I64Const => "I64Const",
            Opcode::F32Const => "F32Const",
            Opcode::F64Const => "F64Const",
            // Reference
            Opcode::RefNull => "RefNull",
            Opcode::RefIsNull => "RefIsNull",
            Opcode::RefFunc => "RefFunc",
            Opcode::RefEq => "RefEq",
            Opcode::RefAsNonNull => "RefAsNonNull",
            Opcode::BrOnNull => "BrOnNull",
            Opcode::BrOnNonNull => "BrOnNonNull",
            // i32 test
            Opcode::I32Eqz => "I32Eqz",
            Opcode::I32Eq => "I32Eq",
            Opcode::I32Ne => "I32Ne",
            Opcode::I32LtS => "I32LtS",
            Opcode::I32LtU => "I32LtU",
            Opcode::I32GtS => "I32GtS",
            Opcode::I32GtU => "I32GtU",
            Opcode::I32LeS => "I32LeS",
            Opcode::I32LeU => "I32LeU",
            Opcode::I32GeS => "I32GeS",
            Opcode::I32GeU => "I32GeU",
            // i64 test
            Opcode::I64Eqz => "I64Eqz",
            Opcode::I64Eq => "I64Eq",
            Opcode::I64Ne => "I64Ne",
            Opcode::I64LtS => "I64LtS",
            Opcode::I64LtU => "I64LtU",
            Opcode::I64GtS => "I64GtS",
            Opcode::I64GtU => "I64GtU",
            Opcode::I64LeS => "I64LeS",
            Opcode::I64LeU => "I64LeU",
            Opcode::I64GeS => "I64GeS",
            Opcode::I64GeU => "I64GeU",
            // f32 test
            Opcode::F32Eq => "F32Eq",
            Opcode::F32Ne => "F32Ne",
            Opcode::F32Lt => "F32Lt",
            Opcode::F32Gt => "F32Gt",
            Opcode::F32Le => "F32Le",
            Opcode::F32Ge => "F32Ge",
            // f64 test
            Opcode::F64Eq => "F64Eq",
            Opcode::F64Ne => "F64Ne",
            Opcode::F64Lt => "F64Lt",
            Opcode::F64Gt => "F64Gt",
            Opcode::F64Le => "F64Le",
            Opcode::F64Ge => "F64Ge",
            // i32 unary
            Opcode::I32Clz => "I32Clz",
            Opcode::I32Ctz => "I32Ctz",
            Opcode::I32Popcnt => "I32Popcnt",
            Opcode::I32Extend8S => "I32Extend8S",
            Opcode::I32Extend16S => "I32Extend16S",
            // i64 unary
            Opcode::I64Clz => "I64Clz",
            Opcode::I64Ctz => "I64Ctz",
            Opcode::I64Popcnt => "I64Popcnt",
            Opcode::I64Extend8S => "I64Extend8S",
            Opcode::I64Extend16S => "I64Extend16S",
            Opcode::I64Extend32S => "I64Extend32S",
            // f32 unary
            Opcode::F32Abs => "F32Abs",
            Opcode::F32Neg => "F32Neg",
            Opcode::F32Ceil => "F32Ceil",
            Opcode::F32Floor => "F32Floor",
            Opcode::F32Trunc => "F32Trunc",
            Opcode::F32Nearest => "F32Nearest",
            Opcode::F32Sqrt => "F32Sqrt",
            // f64 unary
            Opcode::F64Abs => "F64Abs",
            Opcode::F64Neg => "F64Neg",
            Opcode::F64Ceil => "F64Ceil",
            Opcode::F64Floor => "F64Floor",
            Opcode::F64Trunc => "F64Trunc",
            Opcode::F64Nearest => "F64Nearest",
            Opcode::F64Sqrt => "F64Sqrt",
            // i32 binary
            Opcode::I32Add => "I32Add",
            Opcode::I32Sub => "I32Sub",
            Opcode::I32Mul => "I32Mul",
            Opcode::I32DivS => "I32DivS",
            Opcode::I32DivU => "I32DivU",
            Opcode::I32RemS => "I32RemS",
            Opcode::I32RemU => "I32RemU",
            Opcode::I32And => "I32And",
            Opcode::I32Or => "I32Or",
            Opcode::I32Xor => "I32Xor",
            Opcode::I32Shl => "I32Shl",
            Opcode::I32ShrS => "I32ShrS",
            Opcode::I32ShrU => "I32ShrU",
            Opcode::I32Rotl => "I32Rotl",
            Opcode::I32Rotr => "I32Rotr",
            // i64 binary
            Opcode::I64Add => "I64Add",
            Opcode::I64Sub => "I64Sub",
            Opcode::I64Mul => "I64Mul",
            Opcode::I64DivS => "I64DivS",
            Opcode::I64DivU => "I64DivU",
            Opcode::I64RemS => "I64RemS",
            Opcode::I64RemU => "I64RemU",
            Opcode::I64And => "I64And",
            Opcode::I64Or => "I64Or",
            Opcode::I64Xor => "I64Xor",
            Opcode::I64Shl => "I64Shl",
            Opcode::I64ShrS => "I64ShrS",
            Opcode::I64ShrU => "I64ShrU",
            Opcode::I64Rotl => "I64Rotl",
            Opcode::I64Rotr => "I64Rotr",
            // f32 binary
            Opcode::F32Add => "F32Add",
            Opcode::F32Sub => "F32Sub",
            Opcode::F32Mul => "F32Mul",
            Opcode::F32Div => "F32Div",
            Opcode::F32Min => "F32Min",
            Opcode::F32Max => "F32Max",
            Opcode::F32Copysign => "F32Copysign",
            // f64 binary
            Opcode::F64Add => "F64Add",
            Opcode::F64Sub => "F64Sub",
            Opcode::F64Mul => "F64Mul",
            Opcode::F64Div => "F64Div",
            Opcode::F64Min => "F64Min",
            Opcode::F64Max => "F64Max",
            Opcode::F64Copysign => "F64Copysign",
            // Conversions
            Opcode::I32WrapI64 => "I32WrapI64",
            Opcode::I32TruncF32S => "I32TruncF32S",
            Opcode::I32TruncF32U => "I32TruncF32U",
            Opcode::I32TruncF64S => "I32TruncF64S",
            Opcode::I32TruncF64U => "I32TruncF64U",
            Opcode::I64ExtendI32S => "I64ExtendI32S",
            Opcode::I64ExtendI32U => "I64ExtendI32U",
            Opcode::I64TruncF32S => "I64TruncF32S",
            Opcode::I64TruncF32U => "I64TruncF32U",
            Opcode::I64TruncF64S => "I64TruncF64S",
            Opcode::I64TruncF64U => "I64TruncF64U",
            Opcode::F32ConvertI32S => "F32ConvertI32S",
            Opcode::F32ConvertI32U => "F32ConvertI32U",
            Opcode::F32ConvertI64S => "F32ConvertI64S",
            Opcode::F32ConvertI64U => "F32ConvertI64U",
            Opcode::F32DemoteF64 => "F32DemoteF64",
            Opcode::F64ConvertI32S => "F64ConvertI32S",
            Opcode::F64ConvertI32U => "F64ConvertI32U",
            Opcode::F64ConvertI64S => "F64ConvertI64S",
            Opcode::F64ConvertI64U => "F64ConvertI64U",
            Opcode::F64PromoteF32 => "F64PromoteF32",
            Opcode::I32ReinterpretF32 => "I32ReinterpretF32",
            Opcode::I64ReinterpretF64 => "I64ReinterpretF64",
            Opcode::F32ReinterpretI32 => "F32ReinterpretI32",
            Opcode::F64ReinterpretI64 => "F64ReinterpretI64",
            Opcode::I32TruncSatF32S => "I32TruncSatF32S",
            Opcode::I32TruncSatF32U => "I32TruncSatF32U",
            Opcode::I32TruncSatF64S => "I32TruncSatF64S",
            Opcode::I32TruncSatF64U => "I32TruncSatF64U",
            Opcode::I64TruncSatF32S => "I64TruncSatF32S",
            Opcode::I64TruncSatF32U => "I64TruncSatF32U",
            Opcode::I64TruncSatF64S => "I64TruncSatF64S",
            Opcode::I64TruncSatF64U => "I64TruncSatF64U",
            // SIMD
            Opcode::V128Load => "V128Load",
            Opcode::V128Load8x8S => "V128Load8x8S",
            Opcode::V128Load8x8U => "V128Load8x8U",
            Opcode::V128Load16x4S => "V128Load16x4S",
            Opcode::V128Load16x4U => "V128Load16x4U",
            Opcode::V128Load32x2S => "V128Load32x2S",
            Opcode::V128Load32x2U => "V128Load32x2U",
            Opcode::V128Load8Splat => "V128Load8Splat",
            Opcode::V128Load16Splat => "V128Load16Splat",
            Opcode::V128Load32Splat => "V128Load32Splat",
            Opcode::V128Load64Splat => "V128Load64Splat",
            Opcode::V128Load32Zero => "V128Load32Zero",
            Opcode::V128Load64Zero => "V128Load64Zero",
            Opcode::V128Store => "V128Store",
            Opcode::V128Const => "V128Const",
            Opcode::V128Load8Lane => "V128Load8Lane",
            Opcode::V128Load16Lane => "V128Load16Lane",
            Opcode::V128Load32Lane => "V128Load32Lane",
            Opcode::V128Load64Lane => "V128Load64Lane",
            Opcode::V128Store8Lane => "V128Store8Lane",
            Opcode::V128Store16Lane => "V128Store16Lane",
            Opcode::V128Store32Lane => "V128Store32Lane",
            Opcode::V128Store64Lane => "V128Store64Lane",
            Opcode::I8x16Shuffle => "I8x16Shuffle",
            Opcode::I8x16Swizzle => "I8x16Swizzle",
            Opcode::I8x16Splat => "I8x16Splat",
            Opcode::I16x8Splat => "I16x8Splat",
            Opcode::I32x4Splat => "I32x4Splat",
            Opcode::I64x2Splat => "I64x2Splat",
            Opcode::F32x4Splat => "F32x4Splat",
            Opcode::F64x2Splat => "F64x2Splat",
            Opcode::I8x16ExtractLaneS => "I8x16ExtractLaneS",
            Opcode::I8x16ExtractLaneU => "I8x16ExtractLaneU",
            Opcode::I8x16ReplaceLane => "I8x16ReplaceLane",
            Opcode::I16x8ExtractLaneS => "I16x8ExtractLaneS",
            Opcode::I16x8ExtractLaneU => "I16x8ExtractLaneU",
            Opcode::I16x8ReplaceLane => "I16x8ReplaceLane",
            Opcode::I32x4ExtractLane => "I32x4ExtractLane",
            Opcode::I32x4ReplaceLane => "I32x4ReplaceLane",
            Opcode::I64x2ExtractLane => "I64x2ExtractLane",
            Opcode::I64x2ReplaceLane => "I64x2ReplaceLane",
            Opcode::F32x4ExtractLane => "F32x4ExtractLane",
            Opcode::F32x4ReplaceLane => "F32x4ReplaceLane",
            Opcode::F64x2ExtractLane => "F64x2ExtractLane",
            Opcode::F64x2ReplaceLane => "F64x2ReplaceLane",
            Opcode::I8x16Eq => "I8x16Eq",
            Opcode::I8x16Ne => "I8x16Ne",
            Opcode::I8x16LtS => "I8x16LtS",
            Opcode::I8x16LtU => "I8x16LtU",
            Opcode::I8x16GtS => "I8x16GtS",
            Opcode::I8x16GtU => "I8x16GtU",
            Opcode::I8x16LeS => "I8x16LeS",
            Opcode::I8x16LeU => "I8x16LeU",
            Opcode::I8x16GeS => "I8x16GeS",
            Opcode::I8x16GeU => "I8x16GeU",
            Opcode::I16x8Eq => "I16x8Eq",
            Opcode::I16x8Ne => "I16x8Ne",
            Opcode::I16x8LtS => "I16x8LtS",
            Opcode::I16x8LtU => "I16x8LtU",
            Opcode::I16x8GtS => "I16x8GtS",
            Opcode::I16x8GtU => "I16x8GtU",
            Opcode::I16x8LeS => "I16x8LeS",
            Opcode::I16x8LeU => "I16x8LeU",
            Opcode::I16x8GeS => "I16x8GeS",
            Opcode::I16x8GeU => "I16x8GeU",
            Opcode::I32x4Eq => "I32x4Eq",
            Opcode::I32x4Ne => "I32x4Ne",
            Opcode::I32x4LtS => "I32x4LtS",
            Opcode::I32x4LtU => "I32x4LtU",
            Opcode::I32x4GtS => "I32x4GtS",
            Opcode::I32x4GtU => "I32x4GtU",
            Opcode::I32x4LeS => "I32x4LeS",
            Opcode::I32x4LeU => "I32x4LeU",
            Opcode::I32x4GeS => "I32x4GeS",
            Opcode::I32x4GeU => "I32x4GeU",
            Opcode::I64x2Eq => "I64x2Eq",
            Opcode::I64x2Ne => "I64x2Ne",
            Opcode::I64x2LtS => "I64x2LtS",
            Opcode::I64x2GtS => "I64x2GtS",
            Opcode::I64x2LeS => "I64x2LeS",
            Opcode::I64x2GeS => "I64x2GeS",
            Opcode::F32x4Eq => "F32x4Eq",
            Opcode::F32x4Ne => "F32x4Ne",
            Opcode::F32x4Lt => "F32x4Lt",
            Opcode::F32x4Gt => "F32x4Gt",
            Opcode::F32x4Le => "F32x4Le",
            Opcode::F32x4Ge => "F32x4Ge",
            Opcode::F64x2Eq => "F64x2Eq",
            Opcode::F64x2Ne => "F64x2Ne",
            Opcode::F64x2Lt => "F64x2Lt",
            Opcode::F64x2Gt => "F64x2Gt",
            Opcode::F64x2Le => "F64x2Le",
            Opcode::F64x2Ge => "F64x2Ge",
            Opcode::I8x16Neg => "I8x16Neg",
            Opcode::I8x16Popcnt => "I8x16Popcnt",
            Opcode::I16x8Neg => "I16x8Neg",
            Opcode::I32x4Neg => "I32x4Neg",
            Opcode::I64x2Neg => "I64x2Neg",
            Opcode::F32x4Neg => "F32x4Neg",
            Opcode::F64x2Neg => "F64x2Neg",
            Opcode::I8x16Abs => "I8x16Abs",
            Opcode::I16x8Abs => "I16x8Abs",
            Opcode::I32x4Abs => "I32x4Abs",
            Opcode::I64x2Abs => "I64x2Abs",
            Opcode::F32x4Abs => "F32x4Abs",
            Opcode::F64x2Abs => "F64x2Abs",
            Opcode::F32x4Sqrt => "F32x4Sqrt",
            Opcode::F64x2Sqrt => "F64x2Sqrt",
            Opcode::I8x16Add => "I8x16Add",
            Opcode::I16x8Add => "I16x8Add",
            Opcode::I32x4Add => "I32x4Add",
            Opcode::I64x2Add => "I64x2Add",
            Opcode::F32x4Add => "F32x4Add",
            Opcode::F64x2Add => "F64x2Add",
            Opcode::I8x16AddSatS => "I8x16AddSatS",
            Opcode::I8x16AddSatU => "I8x16AddSatU",
            Opcode::I16x8AddSatS => "I16x8AddSatS",
            Opcode::I16x8AddSatU => "I16x8AddSatU",
            Opcode::I8x16Sub => "I8x16Sub",
            Opcode::I16x8Sub => "I16x8Sub",
            Opcode::I32x4Sub => "I32x4Sub",
            Opcode::I64x2Sub => "I64x2Sub",
            Opcode::F32x4Sub => "F32x4Sub",
            Opcode::F64x2Sub => "F64x2Sub",
            Opcode::I8x16SubSatS => "I8x16SubSatS",
            Opcode::I8x16SubSatU => "I8x16SubSatU",
            Opcode::I16x8SubSatS => "I16x8SubSatS",
            Opcode::I16x8SubSatU => "I16x8SubSatU",
            Opcode::I8x16MinS => "I8x16MinS",
            Opcode::I8x16MinU => "I8x16MinU",
            Opcode::I16x8MinS => "I16x8MinS",
            Opcode::I16x8MinU => "I16x8MinU",
            Opcode::I32x4MinS => "I32x4MinS",
            Opcode::I32x4MinU => "I32x4MinU",
            Opcode::I64x2MinS => "I64x2MinS",
            Opcode::I64x2MinU => "I64x2MinU",
            Opcode::F32x4Min => "F32x4Min",
            Opcode::F64x2Min => "F64x2Min",
            Opcode::I8x16MaxS => "I8x16MaxS",
            Opcode::I8x16MaxU => "I8x16MaxU",
            Opcode::I16x8MaxS => "I16x8MaxS",
            Opcode::I16x8MaxU => "I16x8MaxU",
            Opcode::I32x4MaxS => "I32x4MaxS",
            Opcode::I32x4MaxU => "I32x4MaxU",
            Opcode::I64x2MaxS => "I64x2MaxS",
            Opcode::I64x2MaxU => "I64x2MaxU",
            Opcode::F32x4Max => "F32x4Max",
            Opcode::F64x2Max => "F64x2Max",
            Opcode::I8x16AvgrU => "I8x16AvgrU",
            Opcode::I16x8AvgrU => "I16x8AvgrU",
            Opcode::I8x16RoundingAverageU => "I8x16RoundingAverageU",
            Opcode::I16x8RoundingAverageU => "I16x8RoundingAverageU",
            Opcode::I8x16Mul => "I8x16Mul",
            Opcode::I16x8Mul => "I16x8Mul",
            Opcode::I32x4Mul => "I32x4Mul",
            Opcode::I64x2Mul => "I64x2Mul",
            Opcode::F32x4Mul => "F32x4Mul",
            Opcode::F64x2Mul => "F64x2Mul",
            Opcode::I16x8Q15MulrSatS => "I16x8Q15MulrSatS",
            Opcode::I16x8ExtMulLowI8x16S => "I16x8ExtMulLowI8x16S",
            Opcode::I16x8ExtMulHighI8x16S => "I16x8ExtMulHighI8x16S",
            Opcode::I16x8ExtMulLowI8x16U => "I16x8ExtMulLowI8x16U",
            Opcode::I16x8ExtMulHighI8x16U => "I16x8ExtMulHighI8x16U",
            Opcode::I32x4ExtMulLowI16x8S => "I32x4ExtMulLowI16x8S",
            Opcode::I32x4ExtMulHighI16x8S => "I32x4ExtMulHighI16x8S",
            Opcode::I32x4ExtMulLowI16x8U => "I32x4ExtMulLowI16x8U",
            Opcode::I32x4ExtMulHighI16x8U => "I32x4ExtMulHighI16x8U",
            Opcode::I64x2ExtMulLowI32x4S => "I64x2ExtMulLowI32x4S",
            Opcode::I64x2ExtMulHighI32x4S => "I64x2ExtMulHighI32x4S",
            Opcode::I64x2ExtMulLowI32x4U => "I64x2ExtMulLowI32x4U",
            Opcode::I64x2ExtMulHighI32x4U => "I64x2ExtMulHighI32x4U",
            Opcode::I8x16Shl => "I8x16Shl",
            Opcode::I16x8Shl => "I16x8Shl",
            Opcode::I32x4Shl => "I32x4Shl",
            Opcode::I64x2Shl => "I64x2Shl",
            Opcode::I8x16ShrS => "I8x16ShrS",
            Opcode::I8x16ShrU => "I8x16ShrU",
            Opcode::I16x8ShrS => "I16x8ShrS",
            Opcode::I16x8ShrU => "I16x8ShrU",
            Opcode::I32x4ShrS => "I32x4ShrS",
            Opcode::I32x4ShrU => "I32x4ShrU",
            Opcode::I64x2ShrS => "I64x2ShrS",
            Opcode::I64x2ShrU => "I64x2ShrU",
            Opcode::I8x16AllTrue => "I8x16AllTrue",
            Opcode::I16x8AllTrue => "I16x8AllTrue",
            Opcode::I32x4AllTrue => "I32x4AllTrue",
            Opcode::I64x2AllTrue => "I64x2AllTrue",
            Opcode::I8x16Bitmask => "I8x16Bitmask",
            Opcode::I16x8Bitmask => "I16x8Bitmask",
            Opcode::I32x4Bitmask => "I32x4Bitmask",
            Opcode::I64x2Bitmask => "I64x2Bitmask",
            Opcode::I8x16NarrowI16x8S => "I8x16NarrowI16x8S",
            Opcode::I8x16NarrowI16x8U => "I8x16NarrowI16x8U",
            Opcode::I16x8NarrowI32x4S => "I16x8NarrowI32x4S",
            Opcode::I16x8NarrowI32x4U => "I16x8NarrowI32x4U",
            Opcode::I16x8ExtendLowI8x16S => "I16x8ExtendLowI8x16S",
            Opcode::I16x8ExtendHighI8x16S => "I16x8ExtendHighI8x16S",
            Opcode::I16x8ExtendLowI8x16U => "I16x8ExtendLowI8x16U",
            Opcode::I16x8ExtendHighI8x16U => "I16x8ExtendHighI8x16U",
            Opcode::I32x4ExtendLowI16x8S => "I32x4ExtendLowI16x8S",
            Opcode::I32x4ExtendHighI16x8S => "I32x4ExtendHighI16x8S",
            Opcode::I32x4ExtendLowI16x8U => "I32x4ExtendLowI16x8U",
            Opcode::I32x4ExtendHighI16x8U => "I32x4ExtendHighI16x8U",
            Opcode::I64x2ExtendLowI32x4S => "I64x2ExtendLowI32x4S",
            Opcode::I64x2ExtendHighI32x4S => "I64x2ExtendHighI32x4S",
            Opcode::I64x2ExtendLowI32x4U => "I64x2ExtendLowI32x4U",
            Opcode::I64x2ExtendHighI32x4U => "I64x2ExtendHighI32x4U",
            Opcode::I32x4TruncSatF32x4S => "I32x4TruncSatF32x4S",
            Opcode::I32x4TruncSatF32x4U => "I32x4TruncSatF32x4U",
            Opcode::I32x4TruncSatF64x2SZero => "I32x4TruncSatF64x2SZero",
            Opcode::I32x4TruncSatF64x2UZero => "I32x4TruncSatF64x2UZero",
            Opcode::F32x4ConvertI32x4S => "F32x4ConvertI32x4S",
            Opcode::F32x4ConvertI32x4U => "F32x4ConvertI32x4U",
            Opcode::F64x2ConvertLowI32x4S => "F64x2ConvertLowI32x4S",
            Opcode::F64x2ConvertLowI32x4U => "F64x2ConvertLowI32x4U",
            Opcode::F32x4DemoteF64x2Zero => "F32x4DemoteF64x2Zero",
            Opcode::F64x2PromoteLowF32x4 => "F64x2PromoteLowF32x4",
            Opcode::F32x4Ceil => "F32x4Ceil",
            Opcode::F32x4Floor => "F32x4Floor",
            Opcode::F32x4Trunc => "F32x4Trunc",
            Opcode::F32x4Nearest => "F32x4Nearest",
            Opcode::F64x2Ceil => "F64x2Ceil",
            Opcode::F64x2Floor => "F64x2Floor",
            Opcode::F64x2Trunc => "F64x2Trunc",
            Opcode::F64x2Nearest => "F64x2Nearest",
            Opcode::I32x4DotI16x8S => "I32x4DotI16x8S",
            Opcode::I16x8ExtAddPairwiseI8x16S => "I16x8ExtAddPairwiseI8x16S",
            Opcode::I16x8ExtAddPairwiseI8x16U => "I16x8ExtAddPairwiseI8x16U",
            Opcode::I32x4ExtAddPairwiseI16x8S => "I32x4ExtAddPairwiseI16x8S",
            Opcode::I32x4ExtAddPairwiseI16x8U => "I32x4ExtAddPairwiseI16x8U",
            Opcode::V128AnyTrue => "V128AnyTrue",
            Opcode::V128And => "V128And",
            Opcode::V128AndNot => "V128AndNot",
            Opcode::V128Or => "V128Or",
            Opcode::V128Xor => "V128Xor",
            Opcode::V128Not => "V128Not",
            Opcode::V128Bitselect => "V128Bitselect",
            Opcode::F32x4Div => "F32x4Div",
            Opcode::F32x4PMin => "F32x4PMin",
            Opcode::F32x4PMax => "F32x4PMax",
            Opcode::F64x2Div => "F64x2Div",
            Opcode::F64x2PMin => "F64x2PMin",
            Opcode::F64x2PMax => "F64x2PMax",
            Opcode::I8x16RelaxedSwizzle => "I8x16RelaxedSwizzle",
            Opcode::I32x4RelaxedTruncF32x4S => "I32x4RelaxedTruncF32x4S",
            Opcode::I32x4RelaxedTruncF32x4U => "I32x4RelaxedTruncF32x4U",
            Opcode::I32x4RelaxedTruncF64x2SZero => "I32x4RelaxedTruncF64x2SZero",
            Opcode::I32x4RelaxedTruncF64x2UZero => "I32x4RelaxedTruncF64x2UZero",
            Opcode::F32x4RelaxedMadd => "F32x4RelaxedMadd",
            Opcode::F32x4RelaxedNmadd => "F32x4RelaxedNmadd",
            Opcode::F64x2RelaxedMadd => "F64x2RelaxedMadd",
            Opcode::F64x2RelaxedNmadd => "F64x2RelaxedNmadd",
            Opcode::I8x16RelaxedLaneselect => "I8x16RelaxedLaneselect",
            Opcode::I16x8RelaxedLaneselect => "I16x8RelaxedLaneselect",
            Opcode::I32x4RelaxedLaneselect => "I32x4RelaxedLaneselect",
            Opcode::I64x2RelaxedLaneselect => "I64x2RelaxedLaneselect",
            Opcode::F32x4RelaxedMin => "F32x4RelaxedMin",
            Opcode::F32x4RelaxedMax => "F32x4RelaxedMax",
            Opcode::F64x2RelaxedMin => "F64x2RelaxedMin",
            Opcode::F64x2RelaxedMax => "F64x2RelaxedMax",
            Opcode::I16x8RelaxedQ15mulrS => "I16x8RelaxedQ15mulrS",
            Opcode::I16x8RelaxedDotI8x16I7x16S => "I16x8RelaxedDotI8x16I7x16S",
            Opcode::I32x4RelaxedDotI8x16I7x16AddS => "I32x4RelaxedDotI8x16I7x16AddS",
            // Atomic
            Opcode::MemoryAtomicNotify => "MemoryAtomicNotify",
            Opcode::MemoryAtomicWait32 => "MemoryAtomicWait32",
            Opcode::MemoryAtomicWait64 => "MemoryAtomicWait64",
            Opcode::AtomicFence => "AtomicFence",
            Opcode::I32AtomicLoad => "I32AtomicLoad",
            Opcode::I64AtomicLoad => "I64AtomicLoad",
            Opcode::I32AtomicLoad8U => "I32AtomicLoad8U",
            Opcode::I32AtomicLoad16U => "I32AtomicLoad16U",
            Opcode::I64AtomicLoad8U => "I64AtomicLoad8U",
            Opcode::I64AtomicLoad16U => "I64AtomicLoad16U",
            Opcode::I64AtomicLoad32U => "I64AtomicLoad32U",
            Opcode::I32AtomicStore => "I32AtomicStore",
            Opcode::I64AtomicStore => "I64AtomicStore",
            Opcode::I32AtomicStore8 => "I32AtomicStore8",
            Opcode::I32AtomicStore16 => "I32AtomicStore16",
            Opcode::I64AtomicStore8 => "I64AtomicStore8",
            Opcode::I64AtomicStore16 => "I64AtomicStore16",
            Opcode::I64AtomicStore32 => "I64AtomicStore32",
            Opcode::I32AtomicRmwAdd => "I32AtomicRmwAdd",
            Opcode::I64AtomicRmwAdd => "I64AtomicRmwAdd",
            Opcode::I32AtomicRmw8AddU => "I32AtomicRmw8AddU",
            Opcode::I32AtomicRmw16AddU => "I32AtomicRmw16AddU",
            Opcode::I64AtomicRmw8AddU => "I64AtomicRmw8AddU",
            Opcode::I64AtomicRmw16AddU => "I64AtomicRmw16AddU",
            Opcode::I64AtomicRmw32AddU => "I64AtomicRmw32AddU",
            Opcode::I32AtomicRmwSub => "I32AtomicRmwSub",
            Opcode::I64AtomicRmwSub => "I64AtomicRmwSub",
            Opcode::I32AtomicRmw8SubU => "I32AtomicRmw8SubU",
            Opcode::I32AtomicRmw16SubU => "I32AtomicRmw16SubU",
            Opcode::I64AtomicRmw8SubU => "I64AtomicRmw8SubU",
            Opcode::I64AtomicRmw16SubU => "I64AtomicRmw16SubU",
            Opcode::I64AtomicRmw32SubU => "I64AtomicRmw32SubU",
            Opcode::I32AtomicRmwAnd => "I32AtomicRmwAnd",
            Opcode::I64AtomicRmwAnd => "I64AtomicRmwAnd",
            Opcode::I32AtomicRmw8AndU => "I32AtomicRmw8AndU",
            Opcode::I32AtomicRmw16AndU => "I32AtomicRmw16AndU",
            Opcode::I64AtomicRmw8AndU => "I64AtomicRmw8AndU",
            Opcode::I64AtomicRmw16AndU => "I64AtomicRmw16AndU",
            Opcode::I64AtomicRmw32AndU => "I64AtomicRmw32AndU",
            Opcode::I32AtomicRmwOr => "I32AtomicRmwOr",
            Opcode::I64AtomicRmwOr => "I64AtomicRmwOr",
            Opcode::I32AtomicRmw8OrU => "I32AtomicRmw8OrU",
            Opcode::I32AtomicRmw16OrU => "I32AtomicRmw16OrU",
            Opcode::I64AtomicRmw8OrU => "I64AtomicRmw8OrU",
            Opcode::I64AtomicRmw16OrU => "I64AtomicRmw16OrU",
            Opcode::I64AtomicRmw32OrU => "I64AtomicRmw32OrU",
            Opcode::I32AtomicRmwXor => "I32AtomicRmwXor",
            Opcode::I64AtomicRmwXor => "I64AtomicRmwXor",
            Opcode::I32AtomicRmw8XorU => "I32AtomicRmw8XorU",
            Opcode::I32AtomicRmw16XorU => "I32AtomicRmw16XorU",
            Opcode::I64AtomicRmw8XorU => "I64AtomicRmw8XorU",
            Opcode::I64AtomicRmw16XorU => "I64AtomicRmw16XorU",
            Opcode::I64AtomicRmw32XorU => "I64AtomicRmw32XorU",
            Opcode::I32AtomicRmwXchg => "I32AtomicRmwXchg",
            Opcode::I64AtomicRmwXchg => "I64AtomicRmwXchg",
            Opcode::I32AtomicRmw8XchgU => "I32AtomicRmw8XchgU",
            Opcode::I32AtomicRmw16XchgU => "I32AtomicRmw16XchgU",
            Opcode::I64AtomicRmw8XchgU => "I64AtomicRmw8XchgU",
            Opcode::I64AtomicRmw16XchgU => "I64AtomicRmw16XchgU",
            Opcode::I64AtomicRmw32XchgU => "I64AtomicRmw32XchgU",
            Opcode::I32AtomicRmwCmpxchg => "I32AtomicRmwCmpxchg",
            Opcode::I64AtomicRmwCmpxchg => "I64AtomicRmwCmpxchg",
            Opcode::I32AtomicRmw8CmpxchgU => "I32AtomicRmw8CmpxchgU",
            Opcode::I32AtomicRmw16CmpxchgU => "I32AtomicRmw16CmpxchgU",
            Opcode::I64AtomicRmw8CmpxchgU => "I64AtomicRmw8CmpxchgU",
            Opcode::I64AtomicRmw16CmpxchgU => "I64AtomicRmw16CmpxchgU",
            Opcode::I64AtomicRmw32CmpxchgU => "I64AtomicRmw32CmpxchgU",
            // GC
            Opcode::StructNew => "StructNew",
            Opcode::StructNewDefault => "StructNewDefault",
            Opcode::StructGet => "StructGet",
            Opcode::StructGetS => "StructGetS",
            Opcode::StructGetU => "StructGetU",
            Opcode::StructSet => "StructSet",
            Opcode::ArrayNew => "ArrayNew",
            Opcode::ArrayNewDefault => "ArrayNewDefault",
            Opcode::ArrayNewFixed => "ArrayNewFixed",
            Opcode::ArrayNewData => "ArrayNewData",
            Opcode::ArrayNewElem => "ArrayNewElem",
            Opcode::ArrayGet => "ArrayGet",
            Opcode::ArrayGetS => "ArrayGetS",
            Opcode::ArrayGetU => "ArrayGetU",
            Opcode::ArraySet => "ArraySet",
            Opcode::ArrayLen => "ArrayLen",
            Opcode::ArrayFill => "ArrayFill",
            Opcode::ArrayCopy => "ArrayCopy",
            Opcode::ArrayInitData => "ArrayInitData",
            Opcode::ArrayInitElem => "ArrayInitElem",
            Opcode::RefTestRef => "RefTestRef",
            Opcode::RefTestNonNullRef => "RefTestNonNullRef",
            Opcode::RefCastRef => "RefCastRef",
            Opcode::RefCastNonNullRef => "RefCastNonNullRef",
            Opcode::BrOnCast => "BrOnCast",
            Opcode::BrOnCastFail => "BrOnCastFail",
            Opcode::AnyConvertExtern => "AnyConvertExtern",
            Opcode::ExternConvertAny => "ExternConvertAny",
            Opcode::RefI31 => "RefI31",
            Opcode::I31GetS => "I31GetS",
            Opcode::I31GetU => "I31GetU",
            // Exception handling
            Opcode::TryTable => "TryTable",
            Opcode::Throw => "Throw",
            Opcode::ThrowRef => "ThrowRef",
            Opcode::Rethrow => "Rethrow",
            Opcode::Catch => "Catch",
            Opcode::CatchAll => "CatchAll",
            Opcode::Delegate => "Delegate",
            // Unrecognized
            Opcode::Unrecognized(_) => "Unrecognized",
        }
    }
}

fn serialize_unrecognized<S: serde::Serializer>(
    value: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

/// Typed immediate (operand) data for a wasm instruction.
///
/// Each variant corresponds to the operand category of one or more opcodes.
/// `None` covers opcodes that carry no immediate data (e.g. `i32.add`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Immediate {
    /// No immediate operands
    None,
    /// block / loop / if result type
    BlockType(String),
    /// br_table: list of target depths + default depth
    BrTable {
        targets: Vec<u32>,
        default_target: u32,
    },
    /// call / return_call: function index
    Call(u32),
    /// call_indirect / return_call_indirect: type index + table index
    CallIndirect { type_index: u32, table_index: u32 },
    /// call_ref / return_call_ref: type index
    CallRef(u32),
    /// local.get / local.set / local.tee
    Local(u32),
    /// global.get / global.set
    Global(u32),
    /// br / br_if: relative label depth
    Branch(u32),
    /// memory load/store: alignment + offset
    MemArg { align: u32, offset: u64 },
    /// memory.size / memory.grow: memory index
    MemoryIndex(u32),
    /// memory.copy: destination + source memory indices
    MemoryCopy { dst_index: u32, src_index: u32 },
    /// memory.init / data.drop: data segment index
    DataIndex(u32),
    /// table.init / elem.drop: element segment index
    ElemIndex(u32),
    /// table.copy: destination + source table indices
    TableCopy { dst_table: u32, src_table: u32 },
    /// table.get / table.set / table.size / table.grow / table.fill
    TableIndex(u32),
    /// i32.const
    I32Const(i32),
    /// i64.const
    I64Const(i64),
    /// f32.const (bit pattern for Eq compatibility)
    F32Const(u32),
    /// f64.const (bit pattern for Eq compatibility)
    F64Const(u64),
    /// ref.null: heap type
    RefNull(String),
    /// ref.func: function index
    RefFunc(u32),
    /// SIMD lane index
    Lane(u8),
    /// SIMD memory lane: memarg + lane index (for v128.loadN_lane / v128.storeN_lane)
    SimdMemLane { align: u32, offset: u64, lane: u8 },
    /// i8x16.shuffle: 16-byte lane permutation
    Shuffle([u8; 16]),
    /// v128.const: raw bytes
    V128Const(Vec<u8>),
    /// select with type list (for multi-value proposals)
    SelectTypes(Vec<String>),
    /// struct.new / struct.new_default: type index
    StructType(u32),
    /// struct.get / struct.set: type index + field index
    StructField { type_index: u32, field_index: u32 },
    /// array.new / array.new_default / array.get / array.set etc.: type index
    ArrayType(u32),
    /// array.new_fixed: type index + size
    ArrayNewFixed { type_index: u32, size: u32 },
    /// array.new_data / array.init_data: type index + data index
    ArrayNewData { type_index: u32, data_index: u32 },
    /// array.new_elem / array.init_elem: type index + elem index
    ArrayNewElem { type_index: u32, elem_index: u32 },
    /// ref.test / ref.cast / br_on_cast etc.: src type + dst type
    RefCast { src_type: String, dst_type: String },
    /// br_on_cast / br_on_cast_fail: src type + dst type + label depth
    BrOnCast {
        src_type: String,
        dst_type: String,
        label: u32,
    },
    /// try_table: catch tag index list
    TryTable(Vec<u32>),
    /// throw / rethrow: tag index
    TagIndex(u32),
    /// Any unrecognized immediate, stored as the wasmparser Debug text
    /// for display and hashing compatibility.
    Unrecognized(String),
}

impl Immediate {
    /// Produce a deterministic text representation for hashing.
    /// This intentionally does NOT depend on wasmparser's Debug format
    /// for recognized variants.
    pub fn as_hash_text(&self) -> String {
        match self {
            Immediate::None => String::new(),
            Immediate::BlockType(ty) => format!("blockty:{ty}"),
            Immediate::BrTable {
                targets,
                default_target,
            } => {
                let targets_str = targets
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                format!("br_table:[{targets_str}],default:{default_target}")
            }
            Immediate::Call(idx) => format!("function_index:{idx}"),
            Immediate::CallIndirect {
                type_index,
                table_index,
            } => format!("type_index:{type_index},table_index:{table_index}"),
            Immediate::CallRef(type_index) => format!("type_index:{type_index}"),
            Immediate::Local(idx) => format!("local_index:{idx}"),
            Immediate::Global(idx) => format!("global_index:{idx}"),
            Immediate::Branch(depth) => format!("relative_depth:{depth}"),
            Immediate::MemArg { align, offset } => format!("align:{align},offset:{offset}"),
            Immediate::MemoryIndex(idx) => format!("mem:{idx}"),
            Immediate::MemoryCopy {
                dst_index,
                src_index,
            } => format!("dst:{dst_index},src:{src_index}"),
            Immediate::DataIndex(idx) => format!("data:{idx}"),
            Immediate::ElemIndex(idx) => format!("elem:{idx}"),
            Immediate::TableCopy {
                dst_table,
                src_table,
            } => format!("dst:{dst_table},src:{src_table}"),
            Immediate::TableIndex(idx) => format!("table:{idx}"),
            Immediate::I32Const(v) => format!("value:{v}"),
            Immediate::I64Const(v) => format!("value:{v}"),
            Immediate::F32Const(bits) => {
                let v = f32::from_bits(*bits);
                format!("value:{v}")
            }
            Immediate::F64Const(bits) => {
                let v = f64::from_bits(*bits);
                format!("value:{v}")
            }
            Immediate::RefNull(ht) => format!("hty:{ht}"),
            Immediate::RefFunc(idx) => format!("function_index:{idx}"),
            Immediate::Lane(idx) => format!("lane:{idx}"),
            Immediate::SimdMemLane {
                align,
                offset,
                lane,
            } => {
                format!("align:{align},offset:{offset},lane:{lane}")
            }
            Immediate::Shuffle(lanes) => {
                let lanes_str = lanes
                    .iter()
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                format!("lanes:[{lanes_str}]")
            }
            Immediate::V128Const(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                format!("bytes:{hex}")
            }
            Immediate::SelectTypes(types) => {
                let types_str = types.join(",");
                format!("types:[{types_str}]")
            }
            Immediate::StructType(idx) => format!("type_index:{idx}"),
            Immediate::StructField {
                type_index,
                field_index,
            } => format!("type_index:{type_index},field_index:{field_index}"),
            Immediate::ArrayType(idx) => format!("type_index:{idx}"),
            Immediate::ArrayNewFixed { type_index, size } => {
                format!("type_index:{type_index},size:{size}")
            }
            Immediate::ArrayNewData {
                type_index,
                data_index,
            } => format!("type_index:{type_index},data_index:{data_index}"),
            Immediate::ArrayNewElem {
                type_index,
                elem_index,
            } => format!("type_index:{type_index},elem_index:{elem_index}"),
            Immediate::RefCast { src_type, dst_type } => format!("src:{src_type},dst:{dst_type}"),
            Immediate::BrOnCast {
                src_type,
                dst_type,
                label,
            } => format!("src:{src_type},dst:{dst_type},label:{label}"),
            Immediate::TryTable(tags) => {
                let tags_str = tags
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                format!("tags:[{tags_str}]")
            }
            Immediate::TagIndex(idx) => format!("tag_index:{idx}"),
            Immediate::Unrecognized(s) => s.clone(),
        }
    }

    /// Return the function index if this is a Call immediate.
    pub fn call_function_index(&self) -> Option<u32> {
        match self {
            Immediate::Call(idx) => Some(*idx),
            _ => None,
        }
    }
}

/// Typed parsed operator — replaces the string-based `OperatorIr`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedOperator {
    /// Byte offset within the code section
    pub offset: u64,
    /// Typed opcode
    pub opcode: Opcode,
    /// Typed immediate data
    pub immediate: Immediate,
}

impl ParsedOperator {
    /// Produce a display text compatible with the old `OperatorIr` Debug format.
    /// This is used for backward compatibility with report output.
    pub fn display_text(&self) -> String {
        let kind = self.opcode.as_str();
        match &self.immediate {
            Immediate::None => kind.to_string(),
            Immediate::BlockType(ty) => format!("{kind} {{ blockty: {ty} }}"),
            Immediate::BrTable {
                targets,
                default_target,
            } => {
                format!("{kind} {{ targets: {targets:?}, default: {default_target} }}")
            }
            Immediate::Call(idx) => format!("{kind} {{ function_index: {idx} }}"),
            Immediate::CallIndirect {
                type_index,
                table_index,
            } => format!("{kind} {{ type_index: {type_index}, table_index: {table_index} }}"),
            Immediate::CallRef(type_index) => {
                format!("{kind} {{ type_index: {type_index} }}")
            }
            Immediate::Local(idx) => format!("{kind} {{ local_index: {idx} }}"),
            Immediate::Global(idx) => format!("{kind} {{ global_index: {idx} }}"),
            Immediate::Branch(depth) => format!("{kind} {{ relative_depth: {depth} }}"),
            Immediate::MemArg { align, offset } => {
                format!("{kind} {{ memarg: MemArg {{ align: {align}, max_align: 0, offset: {offset}, memory: 0 }} }}")
            }
            Immediate::MemoryIndex(mem) => format!("{kind} {{ mem: {mem} }}"),
            Immediate::MemoryCopy {
                dst_index,
                src_index,
            } => format!("{kind} {{ dst_mem: {dst_index}, src_mem: {src_index} }}"),
            Immediate::DataIndex(idx) => format!("{kind} {{ data_index: {idx} }}"),
            Immediate::ElemIndex(idx) => format!("{kind} {{ elem_index: {idx} }}"),
            Immediate::TableCopy {
                dst_table,
                src_table,
            } => format!("{kind} {{ dst_table: {dst_table}, src_table: {src_table} }}"),
            Immediate::TableIndex(idx) => format!("{kind} {{ table: {idx} }}"),
            Immediate::I32Const(v) => format!("{kind} {{ value: {v} }}"),
            Immediate::I64Const(v) => format!("{kind} {{ value: {v} }}"),
            Immediate::F32Const(bits) => {
                let v = f32::from_bits(*bits);
                format!("{kind} {{ value: {v} }}")
            }
            Immediate::F64Const(bits) => {
                let v = f64::from_bits(*bits);
                format!("{kind} {{ value: {v} }}")
            }
            Immediate::RefNull(ht) => format!("{kind} {{ hty: {ht} }}"),
            Immediate::RefFunc(idx) => format!("{kind} {{ function_index: {idx} }}"),
            Immediate::Lane(idx) => format!("{kind} {{ lane: {idx} }}"),
            Immediate::SimdMemLane {
                align,
                offset,
                lane,
            } => {
                format!("{kind} {{ memarg: MemArg {{ align: {align}, max_align: 0, offset: {offset}, memory: 0 }}, lane: {lane} }}")
            }
            Immediate::Shuffle(lanes) => {
                format!("{kind} {{ lanes: {lanes:?} }}")
            }
            Immediate::V128Const(bytes) => {
                format!(
                    "{kind} {{ bytes: [{hex}] }}",
                    hex = bytes
                        .iter()
                        .map(|b| format!("{b:#04x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Immediate::SelectTypes(types) => {
                format!("{kind} {{ types: {types:?} }}")
            }
            Immediate::StructType(idx) => format!("{kind} {{ type_index: {idx} }}"),
            Immediate::StructField {
                type_index,
                field_index,
            } => format!("{kind} {{ type_index: {type_index}, field_index: {field_index} }}"),
            Immediate::ArrayType(idx) => format!("{kind} {{ type_index: {idx} }}"),
            Immediate::ArrayNewFixed { type_index, size } => {
                format!("{kind} {{ type_index: {type_index}, size: {size} }}")
            }
            Immediate::ArrayNewData {
                type_index,
                data_index,
            } => format!("{kind} {{ type_index: {type_index}, data_index: {data_index} }}"),
            Immediate::ArrayNewElem {
                type_index,
                elem_index,
            } => format!("{kind} {{ type_index: {type_index}, elem_index: {elem_index} }}"),
            Immediate::RefCast { src_type, dst_type } => {
                format!("{kind} {{ src: {src_type}, dst: {dst_type} }}")
            }
            Immediate::BrOnCast {
                src_type,
                dst_type,
                label,
            } => format!("{kind} {{ src: {src_type}, dst: {dst_type}, label: {label} }}"),
            Immediate::TryTable(tags) => {
                format!("{kind} {{ tags: {tags:?} }}")
            }
            Immediate::TagIndex(idx) => format!("{kind} {{ tag_index: {idx} }}"),
            Immediate::Unrecognized(s) => s.clone(),
        }
    }

    /// Return the opcode kind string (backward compat with `OperatorIr.kind`).
    pub fn kind_str(&self) -> &str {
        self.opcode.as_str()
    }
}

// ---------------------------------------------------------------------------
// Layer wrappers (Phase 2/3 — transitional payload, real pipeline boundaries)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ParsedModule {
    #[serde(flatten)]
    pub module: ModuleIr,
}

impl ParsedModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Deref for ParsedModule {
    type Target = ModuleIr;

    fn deref(&self) -> &Self::Target {
        &self.module
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ResolvedModule {
    #[serde(flatten)]
    pub module: ModuleIr,
}

impl ResolvedModule {
    pub fn from_module(module: ModuleIr) -> Self {
        Self { module }
    }
}

impl Deref for ResolvedModule {
    type Target = ModuleIr;

    fn deref(&self) -> &Self::Target {
        &self.module
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NormalizedModule {
    #[serde(flatten)]
    pub module: ModuleIr,
}

impl NormalizedModule {
    pub fn from_module(module: ModuleIr) -> Self {
        Self { module }
    }
}

impl Deref for NormalizedModule {
    type Target = ModuleIr;

    fn deref(&self) -> &Self::Target {
        &self.module
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AnalysisModule {
    #[serde(flatten)]
    pub module: ModuleIr,
    pub cfgs: Vec<FunctionCfgIr>,
    pub call_graph: CallGraphIr,
    pub reachability: ReachabilityIr,
    pub unsafe_paths: Vec<UnsafePathIr>,
}

impl AnalysisModule {
    pub fn from_module(module: ModuleIr) -> Self {
        Self {
            module,
            cfgs: Vec::new(),
            call_graph: CallGraphIr::default(),
            reachability: ReachabilityIr::default(),
            unsafe_paths: Vec::new(),
        }
    }

    pub fn from_parts(
        module: ModuleIr,
        cfgs: Vec<FunctionCfgIr>,
        call_graph: CallGraphIr,
        reachability: ReachabilityIr,
        unsafe_paths: Vec<UnsafePathIr>,
    ) -> Self {
        Self {
            module,
            cfgs,
            call_graph,
            reachability,
            unsafe_paths,
        }
    }
}

impl Deref for AnalysisModule {
    type Target = ModuleIr;

    fn deref(&self) -> &Self::Target {
        &self.module
    }
}

// ---------------------------------------------------------------------------
// MVP payload types (transitional — wrapped by Parsed/Resolved/Normalized layers)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ModuleIr {
    pub types: Vec<TypeIr>,
    pub imports: Vec<ImportIr>,
    pub exports: Vec<ExportIr>,
    pub tables: Vec<TableIr>,
    pub elements: Vec<ElementIr>,
    pub start_function_index: Option<u32>,
    pub functions: Vec<FunctionIr>,
}

impl ModuleIr {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeIr {
    pub id: String,
    pub source_index: u32,
    pub params: Vec<String>,
    pub results: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportIr {
    pub id: String,
    pub source_index: u32,
    pub module: String,
    pub name: String,
    pub kind: ExternalKindIr,
    pub type_ref: TypeRefIr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportIr {
    pub id: String,
    pub source_index: u32,
    pub name: String,
    pub kind: ExternalKindIr,
    pub item_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableIr {
    pub index: u32,
    pub source_index: u32,
    pub init_function_index: Option<u32>,
    pub has_unknown_init: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElementIr {
    pub source_index: u32,
    pub kind: ElementKindIr,
    pub table_index: Option<u32>,
    pub function_indices: Vec<u32>,
    pub has_unknown_items: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ElementKindIr {
    Active,
    Passive,
    Declared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionIr {
    pub id: String,
    pub source_index: u32,
    pub type_index: u32,
    pub type_id: String,
    pub kind: FunctionKindIr,
    pub export_names: Vec<String>,
    pub locals: Vec<LocalIr>,
    /// Phase 1: operators are now typed `ParsedOperator` instead of `OperatorIr`.
    pub operators: Vec<ParsedOperator>,
    pub direct_calls: Vec<u32>,
    pub fingerprint: Option<FuncFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionCfgIr {
    pub function_id: String,
    pub source_index: u32,
    pub kind: FunctionKindIr,
    pub entry_block: Option<usize>,
    pub blocks: Vec<BasicBlockIr>,
    pub call_sites: Vec<CallSiteIr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BasicBlockIr {
    pub id: usize,
    pub start_operator_index: usize,
    pub end_operator_index: usize,
    pub start_offset: Option<u64>,
    pub end_offset: Option<u64>,
    pub operator_indices: Vec<usize>,
    pub operators: Vec<ParsedOperator>,
    pub successors: Vec<CfgEdgeIr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgEdgeIr {
    pub target_block: Option<usize>,
    pub kind: CfgEdgeKindIr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CfgEdgeKindIr {
    Fallthrough,
    BranchTaken,
    BranchNotTaken,
    BranchTableTarget,
    BranchTableDefault,
    Return,
    Trap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallSiteIr {
    pub operator_index: usize,
    pub block_id: usize,
    pub offset: u64,
    pub operator: ParsedOperator,
    pub target_function_index: Option<u32>,
    pub target_function_id: Option<String>,
    pub opcode: String,
    pub tail_call: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CallGraphIr {
    pub roots: Vec<String>,
    pub edges: Vec<CallGraphEdgeIr>,
    pub reachable_functions: Vec<String>,
    pub reachable_imports: Vec<String>,
    pub unreachable_functions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallGraphEdgeIr {
    pub caller_function_id: String,
    pub callee_function_id: String,
    pub call_site_index: usize,
    pub call_site_offset: u64,
    pub kind: CallGraphEdgeKindIr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CallGraphEdgeKindIr {
    Direct,
    TailDirect,
    Indirect,
    TailIndirect,
    Ref,
    TailRef,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReachabilityIr {
    pub roots: Vec<String>,
    pub reachable_functions: Vec<String>,
    pub reachable_imports: Vec<String>,
    pub unreachable_functions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsafePathIr {
    pub entry_function_id: String,
    pub function_path: Vec<String>,
    pub sink: UnsafeSinkIr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsafeSinkIr {
    pub function_id: String,
    pub block_id: usize,
    pub operator_index: usize,
    pub offset: u64,
    pub opcode: String,
    pub kind: UnsafeSinkKindIr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UnsafeSinkKindIr {
    Unreachable,
    MemoryAccess,
    MemoryBulk,
    TableAccess,
    TableBulk,
    IndirectCall,
    Exception,
    Trap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FunctionKindIr {
    Imported,
    Defined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalIr {
    pub count: u32,
    pub value_type: String,
}

/// Legacy operator type — kept only for backward compatibility in diff structures
/// that are consumed by external serialization. New code should use `ParsedOperator`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorIr {
    pub offset: u64,
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExternalKindIr {
    Func,
    Table,
    Memory,
    Global,
    Tag,
}

impl ExternalKindIr {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalKindIr::Func => "func",
            ExternalKindIr::Table => "table",
            ExternalKindIr::Memory => "memory",
            ExternalKindIr::Global => "global",
            ExternalKindIr::Tag => "tag",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrecognized_opcode_rendering_is_non_panicking() {
        let op = Opcode::Unrecognized("0xff".to_string());
        assert_eq!(op.variant_name(), "Unrecognized");
        assert_eq!(op.as_str(), "0xff");
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TypeRefIr {
    Func { type_index: u32, type_id: String },
    Table(String),
    Memory(String),
    Global(String),
    Tag(String),
}
