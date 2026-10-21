//! Standard compatibility is separate from lossless, all-known recognition.
//!
//! `wasmparser` feature presets are an implementation aid, not a historical
//! grammar: decoded values can erase reserved encodings. Consequently both
//! typed requirements and the original wire forms are checked here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write};
use std::str::FromStr;

use serde::Serialize;
use wasmparser::{
    AbstractHeapType, BinaryReader, BlockType, CompositeInnerType, ConstExpr, Data, DataKind,
    Element, ElementItems, ElementKind, Export, ExternalKind, FrameStack, FromReader, FunctionBody,
    Global, GlobalType, HeapType, Imports, MemArg, MemoryType, Operator, OperatorsReader, RecGroup,
    RefType, SectionLimited, StorageType, SubType, Table, TableInit, TableType, TagType, TypeRef,
    ValType, Validator, ValidatorResources, WasmFeatures, WasmModuleResources,
};

use crate::audit::{AuditSection, Region, Span};
pub use crate::core_view::{CustomNameProjection, ValidatorInput};

/// Selects a normative Core release or every grammar known by the pinned parser.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Standard {
    #[serde(rename = "core1")]
    Core1,
    #[serde(rename = "core2")]
    Core2,
    #[serde(rename = "core3")]
    Core3,
    #[default]
    #[serde(rename = "all-known")]
    AllKnown,
}

impl Standard {
    /// Core 3 excludes threads; wasmparser 0.249's draft preset includes it.
    pub fn features(self) -> WasmFeatures {
        match self {
            Self::Core1 => WasmFeatures::WASM1,
            Self::Core2 => WasmFeatures::WASM2,
            Self::Core3 => WasmFeatures::WASM3.difference(WasmFeatures::THREADS),
            Self::AllKnown => WasmFeatures::all(),
        }
    }
    fn allows(self, feature: &str) -> bool {
        let flags = match feature {
            "mvp" | "core1" | "custom" => return true,
            "mutable_global" => WasmFeatures::MUTABLE_GLOBAL,
            "sign_extension" => WasmFeatures::SIGN_EXTENSION,
            "saturating_float_to_int" => WasmFeatures::SATURATING_FLOAT_TO_INT,
            "reference_types" => WasmFeatures::REFERENCE_TYPES,
            "multi_value" => WasmFeatures::MULTI_VALUE,
            "bulk_memory" => WasmFeatures::BULK_MEMORY,
            "simd" => WasmFeatures::SIMD,
            "relaxed_simd" => WasmFeatures::RELAXED_SIMD,
            "threads" => WasmFeatures::THREADS,
            "shared_everything_threads" => WasmFeatures::SHARED_EVERYTHING_THREADS,
            "tail_call" => WasmFeatures::TAIL_CALL,
            "multi_memory" => WasmFeatures::MULTI_MEMORY,
            "exceptions" => WasmFeatures::EXCEPTIONS,
            "memory64" => WasmFeatures::MEMORY64,
            "extended_const" => WasmFeatures::EXTENDED_CONST,
            "function_references" => WasmFeatures::FUNCTION_REFERENCES,
            "memory_control" => WasmFeatures::MEMORY_CONTROL,
            "gc" => WasmFeatures::GC,
            "custom_page_sizes" => WasmFeatures::CUSTOM_PAGE_SIZES,
            "legacy_exceptions" => WasmFeatures::LEGACY_EXCEPTIONS,
            "stack_switching" => WasmFeatures::STACK_SWITCHING,
            "wide_arithmetic" => WasmFeatures::WIDE_ARITHMETIC,
            "custom_descriptors" => WasmFeatures::CUSTOM_DESCRIPTORS,
            "compact_imports" => WasmFeatures::COMPACT_IMPORTS,
            _ => return false,
        };
        self.features().contains(flags)
    }
}

impl fmt::Display for Standard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Core1 => "core1",
            Self::Core2 => "core2",
            Self::Core3 => "core3",
            Self::AllKnown => "all-known",
        })
    }
}
impl FromStr for Standard {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "core1" => Ok(Self::Core1),
            "core2" => Ok(Self::Core2),
            "core3" => Ok(Self::Core3),
            "all-known" => Ok(Self::AllKnown),
            _ => Err(format!(
                "unknown standard {value:?}; expected core1, core2, core3, or all-known"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StandardValidationError {
    pub offset: usize,
    pub message: String,
    /// Bounded raw context, not a claim that these bytes caused the error.
    pub byte_context: ValidationByteContext,
    /// Physical candidates only. Validators may report the cursor after an
    /// instruction, so an end boundary and the following start are both kept.
    pub locations: Vec<ValidationLocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationByteContext {
    pub span: Span,
    pub raw_hex: String,
    pub offset_in_module: bool,
    pub offset_is_eof: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationLocation {
    pub path: String,
    pub span: Span,
    /// contains_offset, ends_at_offset, or empty_at_offset; never causal blame.
    pub relation: String,
}

fn validation_error_context(
    bytes: &[u8],
    sections: &[AuditSection],
    offset: usize,
    message: String,
) -> StandardValidationError {
    fn add(locations: &mut Vec<ValidationLocation>, path: &str, span: Span, offset: usize) {
        let relation = if span.start == offset && span.end == offset {
            "empty_at_offset"
        } else if span.start <= offset && offset < span.end {
            "contains_offset"
        } else if span.start < offset && offset == span.end {
            "ends_at_offset"
        } else {
            return;
        };
        locations.push(ValidationLocation {
            path: path.into(),
            span,
            relation: relation.into(),
        });
    }
    fn regions(locations: &mut Vec<ValidationLocation>, entries: &[Region], offset: usize) {
        for region in entries {
            add(locations, &region.path, region.span, offset);
            regions(locations, &region.children, offset);
        }
    }
    let mut locations = Vec::new();
    for section in sections {
        add(&mut locations, &section.path, section.span, offset);
        regions(&mut locations, &section.regions, offset);
    }
    let cursor = offset.min(bytes.len());
    let span = Span {
        start: cursor.saturating_sub(8),
        end: cursor.saturating_add(8).min(bytes.len()),
    };
    let raw_hex = bytes[span.start..span.end]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    StandardValidationError {
        offset,
        message,
        byte_context: ValidationByteContext {
            span,
            raw_hex,
            offset_in_module: offset <= bytes.len(),
            offset_is_eof: offset == bytes.len(),
        },
        locations,
    }
}

/// Requirements are compatibility evidence, not independent typing proofs.
#[derive(Debug, Clone, Serialize)]
pub struct FeatureEvidence {
    pub path: String,
    pub span: Span,
    pub feature: String,
    /// supported, recognized_but_disabled, invalid_encoding, invalid_semantics,
    /// or unknown.
    pub status: String,
    /// section, structure, instruction, or opaque.
    pub kind: String,
    pub reason: String,
    pub raw_hex: String,
    /// All-known recognition only; disabled instructions are displayed as binary.
    pub recognized: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StandardReport {
    pub selected_standard: Standard,
    /// valid requires both the validator and every observed wire requirement.
    pub validation: String,
    pub validator: String,
    /// Input used by both all-known and selected validators. Raw audit remains original.
    pub validator_input: ValidatorInput,
    pub validator_valid: bool,
    pub validator_error: Option<StandardValidationError>,
    pub interpretation: String,
    pub evidence: Vec<FeatureEvidence>,
}

impl StandardReport {
    pub(crate) fn pending(selected_standard: Standard) -> Self {
        Self {
            selected_standard,
            validation: "not_validated".into(),
            validator: "not_validated".into(),
            validator_input: ValidatorInput::default(),
            validator_valid: false,
            validator_error: None,
            interpretation: "not_classified".into(),
            evidence: Vec::new(),
        }
    }
}

/// Applied directly to all physical regions, including containers.
#[derive(Debug, Clone, Serialize)]
pub struct StandardSupport {
    /// Direct requirement status, or contains_invalid/contains_unknown/
    /// contains_unsupported for a container with affected descendants.
    pub status: String,
    pub required_features: Vec<String>,
    /// instruction, structure, binary, or opaque. Never a typing proof.
    pub display: String,
}

impl Default for StandardSupport {
    fn default() -> Self {
        Self {
            status: "not_classified".into(),
            required_features: Vec::new(),
            display: "structure".into(),
        }
    }
}

pub(crate) fn classify(
    bytes: &[u8],
    sections: &mut [AuditSection],
    standard: Standard,
    reader_view: &crate::core_view::ReaderView<'_>,
) -> StandardReport {
    let mut type_sections = sections.iter().filter(|section| section.id == 1);
    let branch_cast_types = type_sections.next().and_then(|section| {
        (section.status == "decoded" && type_sections.next().is_none())
            .then_some(section.payload_span)
    });
    let mut collector = Collector {
        bytes,
        standard,
        evidence: Vec::new(),
        memories: Vec::new(),
        tables: Vec::new(),
        globals: Vec::new(),
        tags: Vec::new(),
        type_results: Vec::new(),
        pending_type_uses: Vec::new(),
        pending_global_uses: Vec::new(),
        core1_function_types: Vec::new(),
        defined_function_types: Vec::new(),
        core1_semantics: Vec::new(),
        imported_function_types: Vec::new(),
        contexts: IndexContexts::default(),
        branch_cast_types,
        branch_cast_resources: None,
    };
    // Ordering/duplicate errors can invalidate declarations preceding the
    // offending section (notably a late import shifts every defined index).
    // Withdraw those combined maps before collecting any inferred requirements.
    for section in sections.iter().filter(|section| {
        section.regions.iter().any(|region| {
            region.feature.as_deref() == Some("invalid_encoding")
                && region.path == format!("{}/ordering", section.path)
        })
    }) {
        collector.contexts.invalidate(section.id);
        if section.id == 10 {
            collector.contexts.defined_functions = false;
        }
    }
    for section in sections.iter() {
        let feature = match section.id {
            0 => "custom",
            12 => "bulk_memory",
            13 => "exceptions",
            1..=11 => "core1",
            _ => "unknown",
        };
        collector.record(
            &section.path,
            section.header_span,
            feature,
            "section",
            "section kind and framing",
            None,
        );
        let mut unreadable_outer = false;
        for region in section.regions.iter().filter(|region| {
            region.feature.as_deref() == Some("invalid_encoding")
                && (region.path.ends_with("/framing")
                    || region.path.ends_with("/outer_name")
                    || region.path.ends_with("/ordering"))
        }) {
            collector.record(
                &section.path,
                region.span,
                "section_structure",
                "section",
                &region.description,
                None,
            );
            collector.record(
                &region.path,
                region.span,
                "section_structure",
                "structure",
                &region.description,
                None,
            );
            unreadable_outer |=
                region.path.ends_with("/framing") || region.path.ends_with("/outer_name");
        }
        if unreadable_outer {
            collector.contexts.invalidate(section.id);
            continue;
        }
        if section.id == 0 {
            continue;
        }
        if section.id > 13 {
            collector.record(
                &format!("{}/opaque", section.path),
                section.payload_span,
                "unknown",
                "opaque",
                "unknown section grammar; payload boundaries come only from section framing",
                None,
            );
            continue;
        }
        if let Some(frontier) = section
            .regions
            .iter()
            .find(|region| region.feature.as_deref() == Some("unknown_declaration_type"))
        {
            // The primary reader proved only the complete entry/group prefix.
            // Ignore EOF in this deliberately shortened view, and never commit
            // declarations inferred by a permissive value-type fallback.
            let prefix = BinaryReader::new(
                &bytes[section.payload_span.start..frontier.span.start],
                section.payload_span.start,
            );
            let _ = collector.section(section, prefix);
            collector.declaration_prefix(section.id, frontier);
            if section.id == 9 {
                // The entry start is proved even when its reference type is
                // unknown. Its preceding flags remain independent evidence;
                // no count, type, item, or later boundary is inferred here.
                let mut header = collector.reader(frontier.span);
                if let Ok(flags) = header.read_var_u32() {
                    collector.element_flags(
                        &frontier.path,
                        Span {
                            start: frontier.span.start,
                            end: header.original_position(),
                        },
                        flags,
                    );
                }
            }
            collector.contexts.invalidate(section.id);
            for prefix in &frontier.children {
                collector.record(
                    &prefix.path,
                    prefix.span,
                    "unknown",
                    "structure",
                    &prefix.description,
                    None,
                );
            }
            continue;
        }
        if let Some(recovered) = section
            .regions
            .iter()
            .find(|region| region.feature.as_deref() == Some("recovered_expression"))
        {
            // Read only the physical prefix proven by the primary audit. The
            // deliberately shortened view is not itself reported as an EOF;
            // it only prevents a permissive type reader from inventing later
            // declarations after the unknown expression frontier.
            let prefix = BinaryReader::new(
                &bytes[section.payload_span.start..recovered.span.start],
                section.payload_span.start,
            );
            let _ = collector.section(section, prefix);
            collector.contexts.invalidate(section.id);
            collector.recovered_entry(section.id, recovered);
            continue;
        }
        let reader = BinaryReader::new(
            &bytes[section.payload_span.start..section.payload_span.end],
            section.payload_span.start,
        );
        if let Err(error) = collector.section(section, reader) {
            // The primary audit retains the completed prefix. Its opaque suffix
            // is authoritative, rather than an error offset inside an entry.
            let suffix = section.regions.iter().rev().find(|region| {
                region.path.ends_with("/undecoded")
                    || region.path.ends_with("/opaque")
                    || region.path.ends_with("/trailing_bytes")
            });
            // Only bytes beyond a complete entry vector leave its index map
            // intact. A definite malformed entry/count is not trailing data.
            let trailing = suffix.is_some_and(|region| region.path.ends_with("/trailing_bytes"));
            if !trailing {
                collector.contexts.invalidate(section.id);
            }
            let (path, span) = suffix
                .map(|region| (region.path.clone(), region.span))
                .unwrap_or_else(|| {
                    (
                        format!("{}/unclassified", section.path),
                        section.payload_span,
                    )
                });
            let invalid = crate::decode_error::section_failure(
                &error,
                section.id,
                collector.reader(span),
                span.start == section.payload_span.start,
            );
            collector.record(
                &path,
                span,
                if trailing || invalid.is_some() {
                    "section_structure"
                } else {
                    "unknown"
                },
                if trailing { "structure" } else { "opaque" },
                &format!(
                    "{}: {error}; failed entry and remaining payload are not decoded; no later entry boundaries inferred", invalid.unwrap_or(if trailing { "trailing bytes beyond a complete entry vector" } else { "unrecognized or unclassified section grammar" })
                ),
                None,
            );
        }
    }
    // Locals/operator failures need not fail a complete framed body/section.
    fn opaque_regions(collector: &mut Collector<'_>, regions: &[Region], custom: bool) {
        for region in regions {
            if !custom
                && region.feature.as_deref() == Some("invalid_encoding")
                && !collector
                    .evidence
                    .iter()
                    .any(|entry| entry.path == region.path && entry.status == "invalid_encoding")
            {
                collector.record(
                    &region.path,
                    region.span,
                    "section_structure",
                    "structure",
                    &region.description,
                    None,
                );
            }
            if !custom
                && (region.path.ends_with("/opaque") || region.path.ends_with("/undecoded"))
                && region.feature.as_deref() != Some("invalid_encoding")
                && !collector
                    .evidence
                    .iter()
                    .any(|entry| entry.path == region.path && entry.status == "unknown")
            {
                collector.record(
                    &region.path,
                    region.span,
                    "unknown",
                    "opaque",
                    &region.description,
                    None,
                );
            }
            opaque_regions(collector, &region.children, custom);
        }
    }
    for section in sections.iter() {
        opaque_regions(&mut collector, &section.regions, section.id == 0);
    }
    // A declaration can refer forward into a suffix that only later proves
    // unreadable. Resolve availability after every declaration prefix is known;
    // this is not a substitute for the validator's index/type checks.
    collector.resolve_pending_uses();
    let (validator_valid, validator_error) =
        match Validator::new_with_features(standard.features()).validate_all(&reader_view.bytes) {
            Ok(_) => (true, None),
            Err(error) => (
                false,
                Some(validation_error_context(
                    bytes,
                    sections,
                    error.offset(),
                    error.to_string(),
                )),
            ),
        };
    let known_core1 = standard == Standard::Core1
        && validator_valid
        && collector
            .evidence
            .iter()
            .all(|entry| entry.status == "supported");
    // Supplement the modern validator only for otherwise valid, fully known
    // Core1 modules. Later releases deliberately relaxed this typing rule.
    if known_core1 {
        for issue in std::mem::take(&mut collector.core1_semantics) {
            collector.record(
                &issue.path,
                issue.span,
                "core1_br_table_label_types",
                "instruction",
                &issue.reason,
                Some("BrTable".into()),
            );
        }
    }
    let compatible = collector
        .evidence
        .iter()
        .all(|entry| entry.status == "supported");
    let report = StandardReport {
        selected_standard: standard,
        validation: if validator_valid && compatible { "valid" } else { "invalid" }.into(),
        validator: "wasmparser 0.249.0 with uwgit local checked-bounds patch; feature validator on validator_input; independently checked oversized custom names use an offset-preserving reader projection; Core3=WASM3 minus THREADS; Core1 br_table label equality is supplemented for fully known MVP grammar; other historical typing is not reimplemented".into(),
        validator_input: reader_view.report.clone(),
        validator_valid,
        validator_error,
        interpretation: "All regions use all-known grammar recognition. standard_support and evidence describe compatibility with the selected release, never standalone typing proofs. Disabled instructions and invalid encodings/semantics are binary data in the profile view; their recognized names only explain those bytes. invalid_encoding applies to every standard, including all-known; invalid_semantics is a rule of the selected standard. Neither denotes a disabled proposal. Custom payload conventions do not imply Core features. validator_valid refers to the disclosed validator_input; custom-name projections require independently valid original framing and UTF-8, and all raw evidence remains original.".into(),
        evidence: collector.evidence,
    };
    annotate(sections, &report.evidence);
    report
}

fn annotate(sections: &mut [AuditSection], evidence: &[FeatureEvidence]) {
    let mut by_path = BTreeMap::<&str, Vec<&FeatureEvidence>>::new();
    for entry in evidence {
        by_path.entry(&entry.path).or_default().push(entry);
    }
    fn support(
        path: &str,
        children: &[StandardSupport],
        by_path: &BTreeMap<&str, Vec<&FeatureEvidence>>,
    ) -> StandardSupport {
        let own = by_path.get(path).map(Vec::as_slice).unwrap_or_default();
        let mut features = BTreeSet::new();
        for entry in own {
            features.insert(entry.feature.clone());
        }
        for child in children {
            features.extend(child.required_features.iter().cloned());
        }
        let invalid = own.iter().any(|entry| entry.status == "invalid_encoding");
        let invalid_semantics = own.iter().any(|entry| entry.status == "invalid_semantics");
        let unknown = own.iter().any(|entry| entry.status == "unknown");
        let disabled = own
            .iter()
            .any(|entry| entry.status == "recognized_but_disabled");
        let status = if invalid {
            "invalid_encoding"
        } else if invalid_semantics {
            "invalid_semantics"
        } else if unknown {
            "unknown"
        } else if disabled {
            "recognized_but_disabled"
        } else if children.iter().any(|child| {
            matches!(
                child.status.as_str(),
                "invalid_encoding" | "invalid_semantics" | "contains_invalid"
            )
        }) {
            "contains_invalid"
        } else if children
            .iter()
            .any(|child| matches!(child.status.as_str(), "unknown" | "contains_unknown"))
        {
            "contains_unknown"
        } else if children.iter().any(|child| {
            matches!(
                child.status.as_str(),
                "recognized_but_disabled" | "contains_unsupported"
            )
        }) {
            "contains_unsupported"
        } else {
            "supported"
        };
        let display = if invalid || invalid_semantics {
            "binary"
        } else if unknown {
            if own
                .iter()
                .any(|entry| entry.status == "unknown" && entry.kind == "opaque")
            {
                "opaque"
            } else {
                "binary"
            }
        } else if disabled {
            "binary"
        } else if own.iter().any(|entry| entry.kind == "instruction") {
            "instruction"
        } else {
            "structure"
        };
        StandardSupport {
            status: status.into(),
            required_features: features.into_iter().collect(),
            display: display.into(),
        }
    }
    fn regions(entries: &mut [Region], by_path: &BTreeMap<&str, Vec<&FeatureEvidence>>) {
        for region in entries {
            regions(&mut region.children, by_path);
            let children = region
                .children
                .iter()
                .map(|child| child.standard_support.clone())
                .collect::<Vec<_>>();
            region.standard_support = support(&region.path, &children, by_path);
        }
    }
    for section in sections {
        regions(&mut section.regions, &by_path);
        let children = section
            .regions
            .iter()
            .map(|child| child.standard_support.clone())
            .collect::<Vec<_>>();
        section.standard_support = support(&section.path, &children, &by_path);
    }
}

#[derive(Debug, Clone, Copy)]
struct Core1FunctionType {
    result: Option<ValType>,
}

impl Core1FunctionType {
    fn from_subtype(ty: &SubType, plain_wire: bool) -> Option<Self> {
        if !plain_wire || !ty.is_final || ty.supertype_idx.is_some() || ty.composite_type.shared {
            return None;
        }
        let CompositeInnerType::Func(function) = &ty.composite_type.inner else {
            return None;
        };
        if function.results().len() > 1
            || !function
                .params()
                .iter()
                .chain(function.results())
                .all(|ty| core1_number(*ty))
        {
            return None;
        }
        Some(Self {
            result: function.results().first().copied(),
        })
    }
}

fn core1_number(ty: ValType) -> bool {
    matches!(
        ty,
        ValType::I32 | ValType::I64 | ValType::F32 | ValType::F64
    )
}

#[derive(Debug)]
struct Core1SemanticIssue {
    path: String,
    span: Span,
    reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Core1FrameKind {
    Function,
    Block,
    Loop,
    IfThen,
    IfElse,
}

#[derive(Debug, Clone, Copy)]
struct Core1Label {
    kind: Core1FrameKind,
    result: Option<ValType>,
}

fn core1_block_result(block: BlockType) -> Option<Option<ValType>> {
    match block {
        BlockType::Empty => Some(None),
        BlockType::Type(ty) if core1_number(ty) => Some(Some(ty)),
        _ => None,
    }
}

fn mvp_operator(operator: &Operator<'_>) -> bool {
    macro_rules! is_mvp {
        ($( @$proposal:ident $op:ident $({ $($arg:ident: $argty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
            match operator {
                $(Operator::$op $( { $($arg: _),* } )? => stringify!($proposal) == "mvp",)*
                _ => false,
            }
        }
    }
    wasmparser::for_each_operator!(is_mvp)
}

/// Core1 §3.3 requires every br_table label type to equal its default label
/// type, even after unreachable. Core2 instead matches operand types against
/// each label and allows bottom types. This helper proves only the old label
/// equality requirement, without guessing operand stacks or runtime paths.
///
/// A missing type, non-MVP construct, malformed control frame or undecodable
/// byte aborts this supplementary pass. Findings are published only after the
/// selected modern validator and all other Core1 grammar requirements pass.
fn core1_br_table_issues(
    body: &FunctionBody<'_>,
    path: &str,
    function: Core1FunctionType,
) -> Option<Vec<Core1SemanticIssue>> {
    let mut reader = body.get_operators_reader().ok()?;
    let mut labels = vec![Core1Label {
        kind: Core1FrameKind::Function,
        result: function.result,
    }];
    let mut issues = Vec::new();
    let mut ordinal = 0;
    while !reader.eof() {
        if labels.is_empty() {
            return None;
        }
        let start = reader.original_position();
        let operator = reader.read().ok()?;
        if !mvp_operator(&operator) {
            return None;
        }
        match operator {
            Operator::Block { blockty } | Operator::If { blockty } => {
                labels.push(Core1Label {
                    kind: if matches!(operator, Operator::If { .. }) {
                        Core1FrameKind::IfThen
                    } else {
                        Core1FrameKind::Block
                    },
                    result: core1_block_result(blockty)?,
                });
            }
            Operator::Loop { blockty } => {
                // In MVP a branch to a loop accepts no values, regardless of
                // the result type produced when the loop finishes normally.
                core1_block_result(blockty)?;
                labels.push(Core1Label {
                    kind: Core1FrameKind::Loop,
                    result: None,
                });
            }
            Operator::Else => {
                let frame = labels.last_mut()?;
                if frame.kind != Core1FrameKind::IfThen {
                    return None;
                }
                frame.kind = Core1FrameKind::IfElse;
            }
            Operator::End => {
                labels.pop()?;
            }
            Operator::BrTable { targets } => {
                let default_depth = targets.default();
                let default_distance = (default_depth as usize).checked_add(1)?;
                let default = labels
                    .get(labels.len().checked_sub(default_distance)?)?
                    .result;
                let mut mismatch = None;
                for depth in targets.targets() {
                    let depth = depth.ok()?;
                    let distance = (depth as usize).checked_add(1)?;
                    let result = labels.get(labels.len().checked_sub(distance)?)?.result;
                    if result != default && mismatch.is_none() {
                        mismatch = Some((depth, result));
                    }
                }
                if let Some((depth, result)) = mismatch {
                    let label_text = |ty: Option<ValType>| {
                        ty.map_or_else(|| "[]".into(), |ty| format!("[{ty}]"))
                    };
                    issues.push(Core1SemanticIssue {
                        path: format!("{path}/operator[{ordinal}]"),
                        span: Span { start, end: reader.original_position() },
                        reason: format!("Core1 br_table requires all target label types to equal the default label type: target depth={depth} has {}, default depth={default_depth} has {}; unreachable stack polymorphism does not relax this Core1 label equality rule", label_text(result), label_text(default)),
                    });
                }
            }
            _ => {}
        }
        ordinal += 1;
    }
    labels.is_empty().then_some(issues)
}

struct Collector<'a> {
    bytes: &'a [u8],
    standard: Standard,
    evidence: Vec<FeatureEvidence>,
    memories: Vec<MemoryType>,
    tables: Vec<TableType>,
    globals: Vec<GlobalInfo>,
    tags: Vec<u32>,
    type_results: Vec<Option<usize>>,
    pending_type_uses: Vec<IndexUse>,
    pending_global_uses: Vec<IndexUse>,
    core1_function_types: Vec<Option<Core1FunctionType>>,
    defined_function_types: Vec<u32>,
    core1_semantics: Vec<Core1SemanticIssue>,
    imported_function_types: Vec<u32>,
    contexts: IndexContexts,
    branch_cast_types: Option<Span>,
    branch_cast_resources: Option<Option<ValidatorResources>>,
}

/// Preserve the original, fully checked type indices and recursive groups in an
/// independent context. Unrelated globals, exports and function bodies cannot
/// establish or invalidate a relation between these declared types. The one
/// synthetic function merely exposes the pinned validator's public resources;
/// neither its body nor any original function is validated by this helper.
fn branch_cast_type_resources(bytes: &[u8], span: Span) -> Option<ValidatorResources> {
    let mut validator = Validator::new_with_features(WasmFeatures::all());
    validator
        .version(1, wasmparser::Encoding::Module, &(0..8))
        .ok()?;
    let reader = wasmparser::TypeSectionReader::new(BinaryReader::new(
        &bytes[span.start..span.end],
        span.start,
    ))
    .ok()?;
    validator.type_section(&reader).ok()?;
    let types = validator.types(0)?;
    let function_type = (0..types.core_type_count_in_module()).find(|index| {
        types
            .get(types.core_type_at_in_module(*index))
            .is_some_and(|ty| matches!(ty.composite_type.inner, CompositeInnerType::Func(_)))
    })?;
    let mut function = vec![1];
    let mut index = function_type;
    loop {
        let byte = (index & 0x7f) as u8;
        index >>= 7;
        function.push(byte | if index == 0 { 0 } else { 0x80 });
        if index == 0 {
            break;
        }
    }
    let reader = wasmparser::FunctionSectionReader::new(BinaryReader::new(&function, 0)).ok()?;
    validator.function_section(&reader).ok()?;
    validator.code_section_start(&(0..0)).ok()?;
    let body = FunctionBody::new(BinaryReader::new(&[0, 0x0b], 0));
    Some(validator.code_section_entry(&body).ok()?.resources)
}

#[derive(Debug, Clone, Copy)]
struct GlobalInfo {
    ty: GlobalType,
    imported: bool,
}

struct IndexUse {
    path: String,
    span: Span,
    index: u32,
    kind: String,
    role: String,
}

/// Vectors retain only declarations whose original indices are known. A
/// malformed suffix cannot invalidate an already decoded prefix, and a later
/// declaration after a gap must never be appended under a guessed index.
struct IndexContexts {
    types: bool,
    imported_functions: bool,
    defined_functions: bool,
    memories: bool,
    tables: bool,
    globals: bool,
    tags: bool,
}
impl Default for IndexContexts {
    fn default() -> Self {
        Self {
            types: true,
            imported_functions: true,
            defined_functions: true,
            memories: true,
            tables: true,
            globals: true,
            tags: true,
        }
    }
}
impl IndexContexts {
    fn invalidate(&mut self, section: u8) {
        match section {
            1 => self.types = false,
            2 => {
                self.imported_functions = false;
                self.memories = false;
                self.tables = false;
                self.globals = false;
                self.tags = false;
            }
            3 => self.defined_functions = false,
            4 => self.tables = false,
            5 => self.memories = false,
            6 => self.globals = false,
            13 => self.tags = false,
            _ => {}
        }
    }
}

impl<'a> Collector<'a> {
    fn record(
        &mut self,
        path: &str,
        span: Span,
        feature: &str,
        kind: &str,
        reason: &str,
        recognized: Option<String>,
    ) {
        let status = if matches!(
            feature,
            "reference_type_encoding" | "expression_structure" | "section_structure"
        ) {
            "invalid_encoding"
        } else if feature == "core1_br_table_label_types" {
            "invalid_semantics"
        } else if feature == "unknown" {
            "unknown"
        } else if self.standard.allows(feature) {
            "supported"
        } else {
            "recognized_but_disabled"
        };
        let reason = if status == "recognized_but_disabled" {
            format!(
                "{reason}; known {feature} grammar is outside {}",
                self.standard
            )
        } else {
            reason.into()
        };
        let mut raw_hex = String::with_capacity((span.end - span.start).saturating_mul(2));
        for byte in &self.bytes[span.start..span.end] {
            let _ = write!(raw_hex, "{byte:02x}");
        }
        self.evidence.push(FeatureEvidence {
            path: path.into(),
            span,
            feature: feature.into(),
            status: status.into(),
            kind: kind.into(),
            reason,
            raw_hex,
            recognized,
        });
    }

    fn entries<'b, T: FromReader<'b>>(
        &mut self,
        reader: BinaryReader<'b>,
        mut visit: impl FnMut(&mut Self, usize, Span, T) -> wasmparser::Result<()>,
    ) -> wasmparser::Result<()> {
        let mut entries = SectionLimited::<T>::new(reader)?.into_iter();
        let mut index = 0;
        loop {
            let start = entries.original_position();
            let Some(entry) = entries.next() else {
                break;
            };
            let entry = entry?;
            visit(
                self,
                index,
                Span {
                    start,
                    end: entries.original_position(),
                },
                entry,
            )?;
            index += 1;
        }
        Ok(())
    }

    fn section(
        &mut self,
        section: &AuditSection,
        mut reader: BinaryReader<'_>,
    ) -> wasmparser::Result<()> {
        let path = &section.path;
        match section.id {
            1 => {
                let mut type_index = 0;
                self.entries(reader, |this, index, span, group: RecGroup| {
                    let group_path = format!("{path}/group[{index}]");
                    let explicit = group.is_explicit_rec_group();
                    if explicit { this.record(&group_path, span, "gc", "structure", "explicit recursive type group encoding", None); }
                    let types = group.into_types_and_offsets().collect::<Vec<_>>();
                    for (i, (start, ty)) in types.iter().enumerate() {
                        let ty_span = Span { start: *start, end: types.get(i + 1).map_or(span.end, |(offset, _)| *offset) };
                        let ty_path = format!("{path}/type[{type_index}]");
                        this.subtype(&ty_path, ty_span, ty)?;
                        if this.contexts.types {
                            this.type_results.push(match &ty.composite_type.inner { CompositeInnerType::Func(ty) => Some(ty.results().len()), _ => None });
                            this.core1_function_types.push(Core1FunctionType::from_subtype(ty, !explicit && this.bytes[*start] == 0x60));
                        }
                        type_index += 1;
                    }
                    Ok(())
                })
            }
            2 => self.entries(reader, |this, index, span, imports: Imports<'_>| {
                let group_path = format!("{path}/group[{index}]");
                // Compact readers initially skip name strings without checking
                // UTF-8. Prove the complete group before publishing its shared
                // type evidence or any declaration/index side effects.
                let expanded = imports.clone().into_iter().collect::<wasmparser::Result<Vec<_>>>()?;
                if !matches!(&imports, Imports::Single(..)) { this.record(&group_path, span, "compact_imports", "structure", "compact import group encoding", None); }
                let shared_type = this.scan_import_group(&group_path, span, &imports)?;
                for (i, (start, import)) in expanded.iter().enumerate() {
                    let entry = format!("{group_path}/import[{i}]");
                    let entry_span = Span { start: *start, end: expanded.get(i + 1).map_or(span.end, |(start, _)| *start) };
                    if shared_type.is_some() {
                        this.shared_import_instance(&entry, entry_span, import.ty);
                    } else {
                        this.import(&entry, entry_span, import.ty);
                    }
                }
                Ok(())
            }),
            3 => self.entries(reader, |this, index, span, type_index: u32| {
                let entry = format!("{path}/entry[{index}]");
                this.type_operand_role(&entry, span, type_index, "structure", "function declaration type index");
                if this.contexts.defined_functions { this.defined_function_types.push(type_index); }
                else { this.record(&entry, span, "unknown", "structure", "function declaration follows an incomplete function declaration prefix; its type is recognized but its index is unproven", None); }
                Ok(())
            }),
            4 => self.entries(reader, |this, index, span, table: Table<'_>| {
                let entry = format!("{path}/entry[{index}]");
                this.table(&entry, span, table.ty);
                let mut ty_reader = this.reader(span);
                if let TableInit::Expr(expr) = table.init {
                    this.record(&entry, span, "function_references", "structure", "table expression initializer encoding", None);
                    ty_reader.read_u8()?; ty_reader.read_u8()?;
                    this.expression(expr, &format!("{entry}/init"));
                }
                    this.scan_value(&mut ty_reader, &entry, true)?;
                    this.scan_limits(&mut ty_reader, &entry)?;
                Ok(())
            }),
            5 => self.entries(reader, |this, index, span, memory: MemoryType| { let entry = format!("{path}/entry[{index}]"); this.memory(&entry, span, memory); this.scan_limits(&mut this.reader(span), &entry)?; Ok(()) }),
            6 => self.entries(reader, |this, index, span, global: Global<'_>| {
                let entry = format!("{path}/entry[{index}]");
                this.global(&entry, span, global.ty, false);
                this.scan_value(&mut this.reader(span), &entry, false)?;
                // The current declaration is not a preceding global for its initializer.
                if this.contexts.globals { this.globals.pop(); }
                this.expression(global.init_expr, &format!("{entry}/init"));
                if this.contexts.globals { this.globals.push(GlobalInfo { ty: global.ty, imported: false }); }
                Ok(())
            }),
            7 => self.entries(reader, |this, index, span, export: Export<'_>| {
                let entry = format!("{path}/entry[{index}]");
                match export.kind {
                    ExternalKind::Func | ExternalKind::FuncExact => {
                        this.function_operand_role(&entry, span, export.index, "structure", "exported function index");
                        if export.kind == ExternalKind::FuncExact { this.record(&entry, span, "custom_descriptors", "structure", "exact function export", None); }
                    }
                    ExternalKind::Table => this.table_operand(&entry, span, export.index, "structure"),
                    ExternalKind::Memory => this.memory_operand(&entry, span, export.index, "structure"),
                    ExternalKind::Global => {
                        this.global_operand(&entry, span, export.index, "structure");
                        if this.globals.get(export.index as usize).is_some_and(|global| global.ty.mutable) { this.record(&entry, span, "mutable_global", "structure", "mutable global export", None); }
                    }
                    ExternalKind::Tag => {
                        this.record(&entry, span, "exceptions", "structure", "tag export", None);
                        this.tag_operand(&entry, span, export.index, "structure", "exported tag index");
                    }
                }
                Ok(())
            }),
            8 => {
                let start = reader.original_position();
                let index = reader.read_var_u32()?;
                self.function_operand_role(&format!("{path}/value"), Span { start, end: reader.original_position() }, index, "structure", "start function index");
                Ok(())
            }
            12 => Ok(()),
            13 => self.entries(reader, |this, index, span, tag: TagType| { this.tag(&format!("{path}/entry[{index}]"), span, tag); Ok(()) }),
            9 => self.entries(reader, |this, index, span, element: Element<'_>| {
                let entry = format!("{path}/entry[{index}]");
                let mut raw = this.reader(span);
                let flags = raw.read_var_u32()?;
                let flags_span = Span { start: span.start, end: raw.original_position() };
                this.element_flags(&entry, flags_span, flags);
                if flags & 1 == 0 {
                    if flags & 2 != 0 { raw.read_var_u32()?; }
                    raw.read::<ConstExpr<'_>>()?;
                }
                if flags & 4 != 0 && flags & 3 != 0 { this.scan_value(&mut raw, &entry, false)?; }
                match element.kind {
                    ElementKind::Active { table_index, offset_expr } => { this.table_operand(&entry, flags_span, table_index.unwrap_or(0), "structure"); this.expression(offset_expr, &format!("{entry}/offset")); }
                    ElementKind::Passive | ElementKind::Declared => {},
                }
                match element.items {
                    ElementItems::Functions(items) => {
                        let mut items = items.into_iter();
                        let mut index = 0;
                        loop {
                            let start = items.original_position();
                            let Some(function) = items.next() else { break };
                            this.function_operand_role(&format!("{entry}/item[{index}]"), Span { start, end: items.original_position() }, function?, "structure", "element function index");
                            index += 1;
                        }
                    }
                    ElementItems::Expressions(ty, items) => {
                        this.reference(&entry, span, ty, false, "structure");
                        for (i, expr) in items.into_iter().enumerate() { this.expression(expr?, &format!("{entry}/item[{i}]")); }
                    }
                }
                Ok(())
            }),
            10 => self.entries(reader, |this, index, _span, body: FunctionBody<'_>| {
                let entry = format!("{path}/function[{index}]");
                let evidence_start = this.evidence.len();
                match this.defined_function_types.get(index).copied() {
                    Some(type_index) => this.type_operand(&entry, Span { start: body.range().start, end: body.range().end }, type_index, "structure"),
                    None if !this.contexts.defined_functions => this.record(&entry, Span { start: body.range().start, end: body.range().end }, "unknown", "structure", "function signature lies beyond the complete defined-function declaration prefix; body framing and known operators remain independently readable", None),
                    _ => {},
                }
                let mut opaque_start = body.range().start;
                let mut opaque_is_group = false;
                let decoded = (|| -> wasmparser::Result<()> {
                    let mut locals = body.get_locals_reader()?;
                    opaque_start = locals.original_position();
                    let mut total_count = 0u32;
                    for i in 0..locals.get_count() {
                        let start = locals.original_position();
                        opaque_start = start;
                        opaque_is_group = true;
                        let mut value = this.reader(Span { start, end: body.range().end });
                        // Admit the cumulative count before probing a type.
                        if value.read_var_u32().ok().and_then(|count| total_count.checked_add(count)).is_some() && !crate::decode_error::value_prefix_known(&value) {
                            let invalid = crate::decode_error::forbidden_bare_index(&value);
                            this.record(&format!("{entry}/opaque"), Span { start, end: body.range().end }, if invalid { "reference_type_encoding" } else { "unknown" }, "opaque", if invalid { "a bare positive type index is not a value-type shorthand; remaining locals and body are not decoded" } else { "unknown local value-type prefix; remaining locals and body are not decoded" }, None);
                            return Ok(());
                        }
                        let (count, ty) = locals.read()?;
                        total_count += count;
                        let span = Span { start, end: locals.original_position() };
                        let local_path = format!("{entry}/local_group[{i}]");
                        this.value(&local_path, span, ty, false, "structure");
                        let mut raw = this.reader(span); raw.read_var_u32()?;
                        this.scan_value(&mut raw, &local_path, false)?;
                    }
                    this.operators(OperatorsReader::new(locals.get_binary_reader()), body.range().end, &entry, false);
                    Ok(())
                })();
                if let Err(error) = decoded {
                    let invalid = crate::decode_error::locals_failure(&error, this.reader(Span { start: opaque_start, end: body.range().end }), opaque_is_group);
                    this.record(&format!("{entry}/opaque"), Span { start: opaque_start, end: body.range().end }, if invalid.is_some() { "section_structure" } else { "unknown" }, "opaque", &format!("{}: {error}; locals and remaining body are not decoded; the framed next body remains independently readable", invalid.unwrap_or("unrecognized or unclassified locals grammar")), None);
                } else if this.standard == Standard::Core1 && this.evidence[evidence_start..].iter().all(|entry| entry.status == "supported") {
                    let signature = this.defined_function_types.get(index).and_then(|type_index| this.core1_function_types.get(*type_index as usize)).copied().flatten();
                    if let Some(issues) = signature.and_then(|signature| core1_br_table_issues(&body, &entry, signature)) { this.core1_semantics.extend(issues); }
                }
                Ok(())
            }),
            11 => self.entries(reader, |this, index, span, data: Data<'_>| {
                let entry = format!("{path}/entry[{index}]");
                let mut raw = this.reader(span);
                let flags = raw.read_var_u32()?;
                let flags_span = Span { start: span.start, end: raw.original_position() };
                if flags != 0 { this.record(&entry, flags_span, "bulk_memory", "structure", "non-MVP data segment wire form", None); }
                match data.kind {
                    DataKind::Passive => {},
                    DataKind::Active { memory_index, offset_expr } => { this.memory_operand(&entry, flags_span, memory_index, "structure"); this.expression(offset_expr, &format!("{entry}/offset")); }
                }
                Ok(())
            }),
            _ => { let _ = reader.read_bytes(reader.bytes_remaining())?; Ok(()) }
        }
    }

    fn reader(&self, span: Span) -> BinaryReader<'a> {
        BinaryReader::new(&self.bytes[span.start..span.end], span.start)
    }

    fn declaration_prefix(&mut self, section: u8, region: &Region) {
        if !matches!(section, 1 | 2 | 4) {
            return;
        }
        let Some(marker) = region
            .children
            .iter()
            .find(|child| child.feature.as_deref() == Some("unknown_value_type"))
        else {
            return;
        };
        let Some(prefix) =
            crate::value_guard::unknown_entry_prefix(section, self.reader(region.span))
        else {
            return;
        };
        // Evidence is accepted only when the same strict grammar reproduces
        // the primary audit's frontier. No fact may include the unknown byte.
        if prefix.offset != marker.span.start
            || prefix.facts.iter().any(|fact| {
                fact.span.start < region.span.start
                    || fact.span.start >= fact.span.end
                    || fact.span.end > prefix.offset
            })
        {
            return;
        }
        for fact in prefix.facts {
            let span = Span {
                start: fact.span.start,
                end: fact.span.end,
            };
            let mut raw = self.reader(span);
            use crate::value_guard::PrefixKind;
            let _ = (|| -> wasmparser::Result<()> {
                match fact.kind {
                    PrefixKind::Name(role) => {
                        let name = raw.read_unlimited_string()?;
                        self.record(&region.path, span, "core1", "structure", &format!("known import {role} {name:?} before unknown type; physical field only, no declaration published"), None);
                    }
                    PrefixKind::CompactImports => self.record(&region.path, span, "compact_imports", "structure", "compact import discriminator before unknown type; no group member is published", None),
                    PrefixKind::MemberCount => {
                        let count = raw.read_var_u32()?;
                        self.record(&region.path, span, "core1", "structure", &format!("known compact import member count {count} before unknown type; no member indices assigned"), None);
                    }
                    PrefixKind::ImportKind => {
                        let kind: ExternalKind = raw.read()?;
                        let feature = match kind {
                            ExternalKind::Tag => "exceptions",
                            ExternalKind::FuncExact => "custom_descriptors",
                            _ => "core1",
                        };
                        self.record(&region.path, span, feature, "structure", &format!("known import kind {kind:?} before unknown type; descriptor syntax only"), None);
                    }
                    PrefixKind::CompleteImportType => {
                        // Only wire features survive. In particular, indexed
                        // references must not leave pending type dependencies
                        // for a member of an uncommitted import group.
                        let pending = self.pending_type_uses.len();
                        let result = (|| -> wasmparser::Result<()> {
                            let ty: TypeRef = raw.clone().read()?;
                            self.scan_import_type(&mut raw, &region.path)?;
                            self.shared_import_type(&region.path, span, ty, false);
                            self.record(&region.path, span, "core1", "structure", "complete import type wire grammar before unknown type; no declaration or index is published", None);
                            Ok(())
                        })();
                        self.pending_type_uses.truncate(pending);
                        result?;
                    }
                    PrefixKind::TableInitializer => self.record(&region.path, span, "function_references", "structure", "table expression initializer encoding before unknown reference type; no table declaration published", None),
                    PrefixKind::TypeSyntax { feature, description } => self.record(&region.path, span, feature, "structure", &format!("known {description} before unknown type; wire field only, no type declaration published"), None),
                    PrefixKind::TypeCount { feature, role } => {
                        let count = raw.read_var_u32()?;
                        self.record(&region.path, span, feature, "structure", &format!("known {role} {count} before unknown type; no type declaration published"), None);
                        if role == "function result count" && count > 1 {
                            self.record(&region.path, span, "multi_value", "structure", "function result count greater than one before unknown type; result types are not assumed complete", None);
                        }
                    }
                    PrefixKind::TypeValue => {
                        // A failed recursive group publishes no types, even
                        // when an earlier member/value is fully readable.
                        // Keep wire requirements, withdrawing all deferred
                        // dependencies created by indexed reference values.
                        let pending = self.pending_type_uses.len();
                        let result = (|| -> wasmparser::Result<()> {
                            let ty: ValType = raw.clone().read()?;
                            self.scan_value(&mut raw, &region.path, false)?;
                            self.record(&region.path, span, "core1", "structure", &format!("known value-type field boundary ({ty:?}) before unknown type; actual type feature requirements are recorded separately; no type declaration published"), None);
                            Ok(())
                        })();
                        self.pending_type_uses.truncate(pending);
                        result?;
                    }
                }
                Ok(())
            })();
        }
    }

    fn element_flags(&mut self, path: &str, span: Span, flags: u32) {
        // Future flag values need not preserve the current bitfield meaning.
        // Only these eight known wire forms prove mode/index/expression facts.
        if flags > 7 {
            return;
        }
        if flags & 1 != 0 {
            self.record(
                path,
                span,
                "bulk_memory",
                "structure",
                "passive or declarative element segment wire form",
                None,
            );
        }
        if flags == 2 || flags & 4 != 0 {
            self.record(
                path,
                span,
                "reference_types",
                "structure",
                "element segment uses an explicit table index or expression items",
                None,
            );
        }
    }

    fn recovered_entry(&mut self, section: u8, region: &Region) {
        // Only audit-proved expression starts/horizons are replayed. The failed
        // unframed entry never supplies a guessed index to a declaration map.
        let mut raw = self.reader(region.span);
        let metadata = (|| -> wasmparser::Result<()> {
            match section {
                6 => {
                    let mut fields = raw.clone();
                    let global: GlobalType = raw.read()?;
                    self.scan_value(&mut fields, &region.path, false)?;
                    if global.shared {
                        self.record(
                            &region.path,
                            Span {
                                start: region.span.start,
                                end: raw.original_position(),
                            },
                            "shared_everything_threads",
                            "structure",
                            "shared global type before failed initializer",
                            None,
                        );
                    }
                }
                4 => {
                    raw.read_u8()?;
                    raw.read_u8()?;
                    let mut fields = raw.clone();
                    let table: TableType = raw.read()?;
                    let span = Span {
                        start: region.span.start,
                        end: raw.original_position(),
                    };
                    self.record(
                        &region.path,
                        span,
                        "function_references",
                        "structure",
                        "table expression initializer encoding",
                        None,
                    );
                    self.scan_value(&mut fields, &region.path, true)?;
                    self.scan_limits(&mut fields, &region.path)?;
                    // A complete earlier table proves the additional-table
                    // feature, but this failed declaration supplies no index.
                    self.additional_table(&region.path, span);
                    if table.table64 {
                        self.record(
                            &region.path,
                            span,
                            "memory64",
                            "structure",
                            "64-bit table before failed initializer",
                            None,
                        );
                    }
                    if table.shared {
                        self.record(
                            &region.path,
                            span,
                            "shared_everything_threads",
                            "structure",
                            "shared table before failed initializer",
                            None,
                        );
                    }
                }
                11 => {
                    let flags = raw.read_var_u32()?;
                    let memory = if flags == 2 { raw.read_var_u32()? } else { 0 };
                    let span = Span {
                        start: region.span.start,
                        end: raw.original_position(),
                    };
                    if flags != 0 {
                        self.record(
                            &region.path,
                            span,
                            "bulk_memory",
                            "structure",
                            "non-MVP data segment wire form before failed offset",
                            None,
                        );
                    }
                    self.memory_operand(&region.path, span, memory, "structure");
                }
                9 => {
                    let flags = raw.read_var_u32()?;
                    let span = Span {
                        start: region.span.start,
                        end: raw.original_position(),
                    };
                    self.element_flags(&region.path, span, flags);
                    if flags & 1 == 0 {
                        let table = if flags & 2 != 0 {
                            raw.read_var_u32()?
                        } else {
                            0
                        };
                        self.table_operand(&region.path, span, table, "structure");
                        let offset_path = format!("{}/offset", region.path);
                        let complete = region
                            .children
                            .iter()
                            .find(|child| child.path == offset_path)
                            .is_some_and(|expression| {
                                expression.description == "constant expression"
                                    && !expression.children.iter().any(|child| {
                                        child.path.ends_with("/opaque")
                                            || child.path.ends_with("/expression_structure")
                                            || child.path.ends_with("/trailing_bytes")
                                    })
                            });
                        if !complete {
                            return Ok(());
                        }
                        raw.read::<ConstExpr<'_>>()?;
                    }
                    if flags & 4 != 0 && flags & 3 != 0 {
                        self.scan_value(&mut raw, &region.path, false)?;
                    }
                }
                _ => {}
            }
            Ok(())
        })();
        // A failed offset stops metadata here; later bytes are never treated as
        // type fields. Its independently proved operator prefix follows below.
        let _ = metadata;
        for expression in &region.children {
            if expression.feature.as_deref() == Some("recovered_expression") {
                self.operators(
                    OperatorsReader::new(self.reader(expression.span)),
                    expression.span.end,
                    &expression.path,
                    true,
                );
            }
        }
    }

    fn import(&mut self, path: &str, span: Span, ty: TypeRef) {
        if matches!(ty, TypeRef::Func(_) | TypeRef::FuncExact(_))
            && !self.contexts.imported_functions
        {
            self.record(path, span, "unknown", "structure", "function import follows an incomplete imported-function prefix; its type is recognized but its index is unproven", None);
        }
        match ty {
            TypeRef::Func(index) => {
                self.type_operand(path, span, index, "structure");
                if self.contexts.imported_functions {
                    self.imported_function_types.push(index);
                }
            }
            TypeRef::FuncExact(index) => {
                self.type_operand(path, span, index, "structure");
                if self.contexts.imported_functions {
                    self.imported_function_types.push(index);
                }
                self.record(
                    path,
                    span,
                    "custom_descriptors",
                    "structure",
                    "exact function import",
                    None,
                );
            }
            TypeRef::Table(ty) => self.table(path, span, ty),
            TypeRef::Memory(ty) => self.memory(path, span, ty),
            TypeRef::Global(ty) => self.global(path, span, ty, true),
            TypeRef::Tag(ty) => self.tag(path, span, ty),
        }
    }

    // A Compact2 name instantiates the separately encoded shared type. Its
    // name bytes prove an instance, never the shared type's wire features.
    fn shared_import_instance(&mut self, path: &str, span: Span, ty: TypeRef) {
        match ty {
            TypeRef::Func(index) | TypeRef::FuncExact(index) => {
                if self.contexts.imported_functions {
                    self.imported_function_types.push(index);
                } else {
                    self.record(path, span, "unknown", "structure", "function import follows an incomplete imported-function prefix; its type is recognized but its index is unproven", None);
                }
            }
            TypeRef::Table(ty) => self.table_instance(path, span, ty),
            TypeRef::Memory(ty) => self.memory_instance(path, span, ty),
            TypeRef::Global(ty) => {
                self.global_instance(path, span, ty, true);
                self.mutable_global_import(path, span, ty);
            }
            TypeRef::Tag(ty) => self.tag_instance(path, span, ty),
        }
    }

    fn shared_import_type(&mut self, path: &str, span: Span, ty: TypeRef, used: bool) {
        match ty {
            TypeRef::Func(index) => {
                if used {
                    self.type_operand(path, span, index, "structure");
                }
            }
            TypeRef::FuncExact(index) => {
                if used {
                    self.type_operand(path, span, index, "structure");
                }
                self.record(
                    path,
                    span,
                    "custom_descriptors",
                    "structure",
                    "exact function import type encoding",
                    None,
                );
            }
            // scan_import_type already records value/reference types at their
            // actual wire ranges; these helpers add the remaining type flags.
            TypeRef::Table(ty) => self.table_type(path, span, ty),
            TypeRef::Memory(ty) => self.memory_type(path, span, ty),
            TypeRef::Global(ty) => self.global_type(path, span, ty),
            TypeRef::Tag(ty) => self.tag_type(path, span, ty, used),
        }
    }

    fn scan_import_group(
        &mut self,
        path: &str,
        span: Span,
        imports: &Imports<'_>,
    ) -> wasmparser::Result<Option<Span>> {
        let mut reader = self.reader(span);
        reader.read_unlimited_string()?;
        reader.read_unlimited_string()?;
        match imports {
            Imports::Single(..) => {
                self.scan_import_type(&mut reader, &format!("{path}/import[0]"))?;
                Ok(None)
            }
            Imports::Compact1 { .. } => {
                reader.read_u8()?;
                let count = reader.read_var_u32()?;
                for index in 0..count {
                    reader.read_unlimited_string()?;
                    self.scan_import_type(&mut reader, &format!("{path}/import[{index}]"))?;
                }
                Ok(None)
            }
            Imports::Compact2 { ty, names, .. } => {
                reader.read_u8()?;
                // The type appears once on the wire and is shared by all names.
                let start = reader.original_position();
                let shared_path = format!("{path}/shared_type");
                let pending_start = self.pending_type_uses.len();
                self.scan_import_type(&mut reader, &shared_path)?;
                let shared_span = Span {
                    start,
                    end: reader.original_position(),
                };
                let used = names.count() != 0;
                self.shared_import_type(&shared_path, shared_span, *ty, used);
                if !used {
                    // An empty group has wire syntax but no imported entity.
                    // scan_value only appends pending uses; discard precisely
                    // this unused shared type's heap-index dependencies.
                    self.pending_type_uses.truncate(pending_start);
                }
                Ok(Some(shared_span))
            }
        }
    }

    fn scan_import_type(
        &mut self,
        reader: &mut BinaryReader<'_>,
        path: &str,
    ) -> wasmparser::Result<()> {
        let mut fields = reader.clone();
        reader.read::<TypeRef>()?;
        let kind: ExternalKind = fields.read()?;
        if matches!(kind, ExternalKind::Table | ExternalKind::Global) {
            self.scan_value(&mut fields, path, kind == ExternalKind::Table)?;
        }
        if matches!(kind, ExternalKind::Memory | ExternalKind::Table) {
            self.scan_limits(&mut fields, path)?;
        }
        Ok(())
    }

    fn table(&mut self, path: &str, span: Span, ty: TableType) {
        self.table_instance(path, span, ty);
        self.reference(path, span, ty.element_type, true, "structure");
        self.table_type(path, span, ty);
    }
    fn table_instance(&mut self, path: &str, span: Span, ty: TableType) {
        if !self.contexts.tables {
            self.record(path, span, "unknown", "structure", "table declaration follows an incomplete table/import prefix; its type is recognized but its index is unproven", None);
        }
        self.additional_table(path, span);
        if self.contexts.tables {
            self.tables.push(ty);
        }
    }
    fn additional_table(&mut self, path: &str, span: Span) {
        if !self.tables.is_empty() {
            self.record(
                path,
                span,
                "reference_types",
                "structure",
                "additional table in the combined imported/defined table index space",
                None,
            );
        }
    }
    fn table_type(&mut self, path: &str, span: Span, ty: TableType) {
        if ty.table64 {
            self.record(
                path,
                span,
                "memory64",
                "structure",
                "64-bit table limits and address type",
                None,
            );
        }
        if ty.shared {
            self.record(
                path,
                span,
                "shared_everything_threads",
                "structure",
                "shared table type",
                None,
            );
        }
    }
    fn memory(&mut self, path: &str, span: Span, ty: MemoryType) {
        self.memory_instance(path, span, ty);
        self.memory_type(path, span, ty);
    }
    fn memory_instance(&mut self, path: &str, span: Span, ty: MemoryType) {
        if !self.contexts.memories {
            self.record(path, span, "unknown", "structure", "memory declaration follows an incomplete memory/import prefix; its type is recognized but its index is unproven", None);
        }
        if !self.memories.is_empty() {
            self.record(
                path,
                span,
                "multi_memory",
                "structure",
                "additional memory in the combined imported/defined memory index space",
                None,
            );
        }
        if self.contexts.memories {
            self.memories.push(ty);
        }
    }
    fn memory_type(&mut self, path: &str, span: Span, ty: MemoryType) {
        if ty.memory64 {
            self.record(
                path,
                span,
                "memory64",
                "structure",
                "64-bit memory limits and address type",
                None,
            );
        }
        if ty.shared {
            self.record(
                path,
                span,
                "threads",
                "structure",
                "shared linear memory limits",
                None,
            );
        }
        if ty.page_size_log2.is_some() {
            self.record(
                path,
                span,
                "custom_page_sizes",
                "structure",
                "explicit memory page size",
                None,
            );
        }
    }
    fn global(&mut self, path: &str, span: Span, ty: GlobalType, imported: bool) {
        self.global_instance(path, span, ty, imported);
        self.value(path, span, ty.content_type, false, "structure");
        if imported {
            self.mutable_global_import(path, span, ty);
        }
        self.global_type(path, span, ty);
    }
    fn global_instance(&mut self, path: &str, span: Span, ty: GlobalType, imported: bool) {
        if !self.contexts.globals {
            self.record(path, span, "unknown", "structure", "global declaration follows an incomplete global/import prefix; its type is recognized but its index is unproven", None);
        }
        if self.contexts.globals {
            self.globals.push(GlobalInfo { ty, imported });
        }
    }
    fn mutable_global_import(&mut self, path: &str, span: Span, ty: GlobalType) {
        if ty.mutable {
            self.record(
                path,
                span,
                "mutable_global",
                "structure",
                "mutable global import",
                None,
            );
        }
    }
    fn global_type(&mut self, path: &str, span: Span, ty: GlobalType) {
        if ty.shared {
            self.record(
                path,
                span,
                "shared_everything_threads",
                "structure",
                "shared global type",
                None,
            );
        }
    }
    fn tag(&mut self, path: &str, span: Span, ty: TagType) {
        self.tag_instance(path, span, ty);
        self.tag_type(path, span, ty, true);
    }
    fn tag_instance(&mut self, path: &str, span: Span, ty: TagType) {
        if self.contexts.tags {
            self.tags.push(ty.func_type_idx);
        } else {
            self.record(path, span, "unknown", "structure", "tag declaration follows an incomplete tag/import prefix; its signature is recognized but its index is unproven", None);
        }
    }
    fn tag_type(&mut self, path: &str, span: Span, ty: TagType, used: bool) {
        if used {
            self.type_operand(path, span, ty.func_type_idx, "structure");
        }
        self.record(
            path,
            span,
            "exceptions",
            "structure",
            "exception tag import/declaration",
            None,
        );
        if used
            && self
                .type_results
                .get(ty.func_type_idx as usize)
                .is_some_and(|results| results.is_some_and(|count| count != 0))
        {
            self.record(
                path,
                span,
                "stack_switching",
                "structure",
                "tag signature has results; Core exception tags require an empty result type",
                None,
            );
        }
    }

    fn subtype(&mut self, path: &str, span: Span, ty: &SubType) -> wasmparser::Result<()> {
        for (index, role) in [
            (ty.supertype_idx, "supertype index"),
            (ty.composite_type.descriptor_idx, "descriptor type index"),
            (ty.composite_type.describes_idx, "described type index"),
        ] {
            if let Some(index) = index.and_then(|index| index.as_module_index()) {
                self.type_operand_role(path, span, index, "structure", role);
            }
        }
        self.record(
            path,
            span,
            "core1",
            "structure",
            "recognized type definition; validator separately checks typing",
            None,
        );
        if !ty.is_final
            || ty.supertype_idx.is_some()
            || matches!(self.bytes[span.start], 0x4f | 0x50)
        {
            self.record(
                path,
                span,
                "gc",
                "structure",
                "explicit subtyping/finality wire form",
                None,
            );
        }
        if ty.composite_type.shared {
            self.record(
                path,
                span,
                "shared_everything_threads",
                "structure",
                "shared composite type",
                None,
            );
        }
        if ty.composite_type.descriptor_idx.is_some() || ty.composite_type.describes_idx.is_some() {
            self.record(
                path,
                span,
                "custom_descriptors",
                "structure",
                "descriptor or describes clause",
                None,
            );
        }
        match &ty.composite_type.inner {
            CompositeInnerType::Func(function) => {
                if function.results().len() > 1 {
                    self.record(
                        path,
                        span,
                        "multi_value",
                        "structure",
                        "function type with multiple results",
                        None,
                    );
                }
                for value in function.params().iter().chain(function.results()) {
                    self.value(path, span, *value, false, "structure");
                }
            }
            CompositeInnerType::Struct(structure) => {
                self.record(
                    path,
                    span,
                    "gc",
                    "structure",
                    "struct type definition and field storage types",
                    None,
                );
                for field in structure.fields.iter() {
                    if let StorageType::Val(ty) = field.element_type {
                        self.value(path, span, ty, false, "structure");
                    }
                }
            }
            CompositeInnerType::Array(array) => {
                self.record(
                    path,
                    span,
                    "gc",
                    "structure",
                    "array type definition and field storage type",
                    None,
                );
                if let StorageType::Val(ty) = array.0.element_type {
                    self.value(path, span, ty, false, "structure");
                }
            }
            CompositeInnerType::Cont(ty) => {
                if let Some(index) = ty.0.as_module_index() {
                    self.type_operand_role(
                        path,
                        span,
                        index,
                        "structure",
                        "continuation function type index",
                    );
                }
                self.record(
                    path,
                    span,
                    "stack_switching",
                    "structure",
                    "continuation type definition",
                    None,
                );
            }
        }
        // Inspect actual value type encodings: normalization erases (ref null
        // func) vs the pre-Core3 funcref shorthand and explicit final subtypes.
        let mut reader = self.reader(span);
        let mut opcode = reader.read_u8()?;
        if matches!(opcode, 0x4f | 0x50) {
            let count = reader.read_var_u32()?;
            for _ in 0..count {
                reader.read_var_u32()?;
            }
            opcode = reader.read_u8()?;
        }
        if opcode == 0x65 {
            opcode = reader.read_u8()?;
        }
        if opcode == 0x4c {
            reader.read_var_u32()?;
            opcode = reader.read_u8()?;
        }
        if opcode == 0x4d {
            reader.read_var_u32()?;
            opcode = reader.read_u8()?;
        }
        match opcode {
            0x60 => {
                for _ in 0..2 {
                    let count = reader.read_var_u32()?;
                    for _ in 0..count {
                        self.scan_value(&mut reader, path, false)?;
                    }
                }
            }
            0x5e => self.scan_field(&mut reader, path)?,
            0x5f => {
                let count = reader.read_var_u32()?;
                for _ in 0..count {
                    self.scan_field(&mut reader, path)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn scan_field(&mut self, reader: &mut BinaryReader<'_>, path: &str) -> wasmparser::Result<()> {
        if matches!(self.bytes[reader.original_position()], 0x77 | 0x78) {
            reader.read_u8()?;
        } else {
            self.scan_value(reader, path, false)?;
        }
        reader.read_u8()?;
        Ok(())
    }
    fn scan_limits(&mut self, reader: &mut BinaryReader<'_>, path: &str) -> wasmparser::Result<()> {
        let flags = reader.read_u8()?;
        for role in ["minimum", "maximum"] {
            if role == "maximum" && flags & 1 == 0 {
                break;
            }
            let start = reader.original_position();
            let value = reader.read_var_u64()?;
            let span = Span {
                start,
                end: reader.original_position(),
            };
            if value > u32::MAX as u64 || span.end - span.start > 5 {
                self.record(path, span, "memory64", "structure", &format!("{role} limit uses the Core3 u64 wire grammar, including padded small values beyond five bytes"), None);
            }
        }
        Ok(())
    }
    fn scan_value(
        &mut self,
        reader: &mut BinaryReader<'_>,
        path: &str,
        table: bool,
    ) -> wasmparser::Result<()> {
        let start = reader.original_position();
        let ty: ValType = reader.read()?;
        let span = Span {
            start,
            end: reader.original_position(),
        };
        self.value(path, span, ty, table, "structure");
        self.value_encoding(path, span, "structure");
        if matches!(self.bytes[start], 0x63 | 0x64) {
            self.record(
                path,
                span,
                "function_references",
                "structure",
                "explicit ref/nullability value-type encoding (not a shorthand reference byte)",
                None,
            );
        }
        Ok(())
    }

    fn value_encoding(&mut self, path: &str, span: Span, kind: &str) {
        let raw = &self.bytes[span.start..span.end];
        let legal_form = match raw {
            [0x7b..=0x7f] | [0x68..=0x75] => true,
            [0x63 | 0x64, ..] => true,
            // The named shared-everything proposal extends abstract heap types.
            [0x65, 0x68..=0x75] => true,
            _ => false,
        };
        if !legal_form {
            self.record(path, span, "reference_type_encoding", kind, "invalid value/reference-type wire form: a concrete heap index requires a 0x63/0x64 reference constructor; shorthand types are single-byte abstract heap types (or a recognized shared abstract type), never a bare s33 index", None);
        }
    }
    fn value(&mut self, path: &str, span: Span, ty: ValType, table: bool, kind: &str) {
        match ty {
            ValType::V128 => self.record(path, span, "simd", kind, "v128 value type", None),
            ValType::Ref(ty) => self.reference(path, span, ty, table, kind),
            _ => {}
        }
    }
    fn reference(&mut self, path: &str, span: Span, ty: RefType, table: bool, kind: &str) {
        if table && ty == RefType::FUNCREF {
            return;
        }
        self.record(
            path,
            span,
            "reference_types",
            kind,
            "reference value/element type",
            None,
        );
        if !ty.is_nullable() {
            self.record(
                path,
                span,
                "function_references",
                kind,
                "non-nullable reference type",
                None,
            );
        }
        self.heap(path, span, ty.heap_type(), kind);
    }
    fn heap(&mut self, path: &str, span: Span, ty: HeapType, kind: &str) {
        match ty {
            HeapType::Concrete(index) => {
                if let Some(index) = index.as_module_index() {
                    self.type_operand_role(path, span, index, kind, "heap type index");
                }
                self.record(
                    path,
                    span,
                    "function_references",
                    kind,
                    "indexed heap type",
                    None,
                );
            }
            HeapType::Exact(index) => {
                if let Some(index) = index.as_module_index() {
                    self.type_operand_role(path, span, index, kind, "exact heap type index");
                }
                self.record(
                    path,
                    span,
                    "custom_descriptors",
                    kind,
                    "exact heap type",
                    None,
                );
            }
            HeapType::Abstract { shared, ty } => {
                if shared {
                    self.record(
                        path,
                        span,
                        "shared_everything_threads",
                        kind,
                        "shared heap type",
                        None,
                    );
                }
                let feature = match ty {
                    AbstractHeapType::Func | AbstractHeapType::Extern => None,
                    AbstractHeapType::Exn | AbstractHeapType::NoExn => Some("exceptions"),
                    AbstractHeapType::Cont | AbstractHeapType::NoCont => Some("stack_switching"),
                    _ => Some("gc"),
                };
                if let Some(feature) = feature {
                    self.record(path, span, feature, kind, "abstract heap type", None);
                }
            }
        }
    }

    fn expression(&mut self, expression: ConstExpr<'_>, path: &str) {
        let end = expression.get_binary_reader().range().end;
        self.operators(expression.get_operators_reader(), end, path, true);
    }
    fn operators(
        &mut self,
        mut reader: OperatorsReader<'_>,
        end: usize,
        path: &str,
        constant: bool,
    ) {
        let mut index = 0;
        while !reader.eof() {
            let start = reader.original_position();
            if reader.current_frame().is_none() {
                self.record(&format!("{path}/trailing_bytes"), Span { start, end }, "expression_structure", "structure", "bytes after the terminating End are outside the expression grammar; no later instruction boundaries inferred", None);
                return;
            }
            if let Some(invalid) =
                crate::decode_error::select_value_prefix(self.reader(Span { start, end }))
            {
                self.record(&format!("{path}/opaque"), Span { start, end }, if invalid { "reference_type_encoding" } else { "unknown" }, "opaque", if invalid { "a bare positive type index is not a value-type shorthand; typed select and remaining expression are not decoded" } else { "unknown typed-select value-type prefix; instruction and remaining expression are not decoded" }, None);
                return;
            }
            match reader.read() {
                Ok(operator) => {
                    let span = Span {
                        start,
                        end: reader.original_position(),
                    };
                    self.operator(
                        &format!("{path}/operator[{index}]"),
                        span,
                        &operator,
                        constant,
                    );
                    index += 1;
                }
                Err(error) => {
                    let invalid = crate::decode_error::operator_failure(
                        &error,
                        self.reader(Span { start, end }),
                    );
                    self.record(&format!("{path}/opaque"), Span { start, end }, if invalid.is_some() { "expression_structure" } else { "unknown" }, "opaque", &format!("{}: {error}; failed instruction and remaining expression are not decoded; no resynchronization", invalid.unwrap_or("unrecognized or unclassified instruction grammar")), None);
                    return;
                }
            }
        }
        if let Err(error) = reader.finish() {
            self.record(
                &format!("{path}/expression_structure"),
                Span {
                    start: reader.original_position(),
                    end,
                },
                "expression_structure",
                "structure",
                &format!("expression control structure is incomplete: {error}"),
                None,
            );
        }
    }
    fn operator(&mut self, path: &str, span: Span, operator: &Operator<'_>, constant: bool) {
        macro_rules! requirements {
            ($( @$proposal:ident $op:ident $({ $($arg:ident: $argty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
                match operator {
                    $(Operator::$op $( { $($arg),* } )? => {
                        self.record(path, span, stringify!($proposal), "instruction", "recognized opcode grammar", Some(stringify!($op).into()));
                        $($(self.argument(path, span, stringify!($arg), $arg);)*)?
                    },)*
                    _ => self.record(path, span, "unknown", "opaque", "operator not covered by the pinned feature map", None),
                }
            }
        }
        wasmparser::for_each_operator!(requirements);
        if let Operator::BrOnCast {
            from_ref_type,
            to_ref_type,
            ..
        }
        | Operator::BrOnCastFail {
            from_ref_type,
            to_ref_type,
            ..
        } = operator
        {
            self.branch_cast_relation(path, span, *from_ref_type, *to_ref_type);
        }
        if constant {
            match operator {
                Operator::I32Add
                | Operator::I32Sub
                | Operator::I32Mul
                | Operator::I64Add
                | Operator::I64Sub
                | Operator::I64Mul => self.record(
                    path,
                    span,
                    "extended_const",
                    "instruction",
                    "integer arithmetic in a constant-expression context",
                    None,
                ),
                Operator::GlobalGet { global_index } => match self
                    .globals
                    .get(*global_index as usize)
                    .copied()
                {
                    Some(global) if !global.imported => self.record(
                        path,
                        span,
                        "gc",
                        "instruction",
                        "global.get of a preceding module-defined global in a constant expression",
                        None,
                    ),
                    _ => {}
                },
                _ => {}
            }
        }
        match operator {
            Operator::CallIndirect { .. } | Operator::ReturnCallIndirect { .. } => {
                let mut raw = self.reader(span);
                let encoding = (|| -> wasmparser::Result<(u32, usize)> {
                    raw.read_u8()?;
                    raw.read_var_u32()?;
                    let start = raw.original_position();
                    let index = raw.read_var_u32()?;
                    Ok((index, raw.original_position() - start))
                })();
                if encoding.is_ok_and(|(index, len)| index != 0 || len != 1) {
                    self.record(
                        path,
                        span,
                        "reference_types",
                        "instruction",
                        "call_indirect table immediate is not the MVP literal reserved zero byte",
                        None,
                    );
                }
            }
            Operator::MemorySize { .. } | Operator::MemoryGrow { .. }
                if span.end - span.start != 2 || self.bytes[span.start + 1] != 0 =>
            {
                self.record(
                    path,
                    span,
                    "multi_memory",
                    "instruction",
                    "memory index immediate is not the original literal reserved zero byte",
                    None,
                )
            }
            Operator::MemoryInit { .. }
            | Operator::MemoryCopy { .. }
            | Operator::MemoryFill { .. } => {
                let (operation, has_data, roles): (&str, bool, &[&str]) = match operator {
                    Operator::MemoryInit { .. } => ("memory.init", true, &["memory index"]),
                    Operator::MemoryCopy { .. } => (
                        "memory.copy",
                        false,
                        &["destination memory index", "source memory index"],
                    ),
                    _ => ("memory.fill", false, &["memory index"]),
                };
                let mut raw = self.reader(span);
                let _ = (|| -> wasmparser::Result<()> {
                    raw.read_u8()?;
                    // Both the secondary opcode and data index are u32 even in
                    // Core2; their legal padding must not be mistaken for a
                    // changed reserved memory byte.
                    raw.read_var_u32()?;
                    if has_data {
                        raw.read_var_u32()?;
                    }
                    for role in roles {
                        let start = raw.original_position();
                        let index = raw.read_var_u32()?;
                        let immediate = Span {
                            start,
                            end: raw.original_position(),
                        };
                        if index != 0 || immediate.end - start != 1 {
                            self.record(path, immediate, "multi_memory", "instruction", &format!("{operation} {role} {index} is not the Core2 literal reserved zero byte; this uses the newer memory-index wire grammar"), None);
                        }
                    }
                    Ok(())
                })();
            }
            Operator::TypedSelect { .. } | Operator::TypedSelectMulti { .. } => {
                let mut raw = self.reader(span);
                let _ = (|| -> wasmparser::Result<()> {
                    raw.read_u8()?;
                    let count = raw.read_var_u32()?;
                    for _ in 0..count {
                        self.scan_value(&mut raw, path, false)?;
                    }
                    Ok(())
                })();
            }
            _ => {}
        }
    }
    fn argument<T: Operand>(&mut self, path: &str, span: Span, name: &str, argument: &T) {
        argument.requirements(self, path, span, name);
    }
    fn branch_cast_relation(&mut self, path: &str, span: Span, mut from: RefType, mut to: RefType) {
        let relation = if matches!(from.heap_type(), HeapType::Abstract { .. })
            && matches!(to.heap_type(), HeapType::Abstract { .. })
        {
            let types = wasmparser::types::TypeList::default();
            Some((
                types.top_type(&from.heap_type()),
                types.top_type(&to.heap_type()),
                types.reftype_is_subtype(to, from),
            ))
        } else {
            if self.branch_cast_resources.is_none() {
                // Success of the normalizing validator is insufficient: the
                // original type wire forms must also have passed our guards.
                let strict_types = self.contexts.types
                    && !self.evidence.iter().any(|entry| {
                        entry.path.starts_with("type[")
                            && matches!(entry.status.as_str(), "invalid_encoding" | "unknown")
                    });
                self.branch_cast_resources = Some(if strict_types {
                    self.branch_cast_types
                        .and_then(|types| branch_cast_type_resources(self.bytes, types))
                } else {
                    None
                });
            }
            self.branch_cast_resources
                .as_ref()
                .and_then(Option::as_ref)
                .and_then(|resources| {
                    resources.check_ref_type(&mut from, span.start).ok()?;
                    resources.check_ref_type(&mut to, span.start).ok()?;
                    Some((
                        resources.top_type(&from.heap_type()),
                        resources.top_type(&to.heap_type()),
                        resources.is_subtype(to.into(), from.into()),
                    ))
                })
        };
        match relation {
            Some((from_top, to_top, subtype)) if from_top == to_top => {
                let continuation = matches!(
                    to_top,
                    HeapType::Abstract {
                        ty: AbstractHeapType::Cont,
                        ..
                    }
                );
                if !subtype || continuation {
                    self.record(path, span, "custom_descriptors", "instruction", if continuation {
                        "ordinary branching cast to a continuation hierarchy requires the custom-descriptors relaxation; ordinary GC casts forbid continuation targets"
                    } else {
                        "ordinary branching cast target is not a subtype of its source; the same-hierarchy relaxation requires custom descriptors"
                    }, None);
                }
            }
            Some(_) => {} // Different hierarchies remain invalid under either rule.
            None => self.record(path, span, "unknown", "instruction", "ordinary branching cast type relation is unproven because its original type context is unavailable or an operand cannot be resolved; no proposal relaxation is inferred", None),
        }
    }
    fn memory_operand(&mut self, path: &str, span: Span, index: u32, kind: &str) {
        if index != 0 {
            self.record(
                path,
                span,
                "multi_memory",
                kind,
                "nonzero memory index",
                None,
            );
        }
        if let Some(memory) = self.memories.get(index as usize).copied() {
            if memory.memory64 {
                self.record(
                    path,
                    span,
                    "memory64",
                    kind,
                    "referenced memory has a 64-bit address type",
                    None,
                );
            }
        } else if !self.contexts.memories {
            self.record(
                path,
                span,
                "unknown",
                kind,
                &format!(
                    "memory index {index} lies beyond the complete memory/import declaration prefix"
                ),
                None,
            );
        }
    }
    fn table_operand(&mut self, path: &str, span: Span, index: u32, kind: &str) {
        if index != 0 {
            self.record(
                path,
                span,
                "reference_types",
                kind,
                "nonzero table index",
                None,
            );
        }
        if let Some(table) = self.tables.get(index as usize).copied() {
            if table.table64 {
                self.record(
                    path,
                    span,
                    "memory64",
                    kind,
                    "referenced table has a 64-bit address type",
                    None,
                );
            }
        } else if !self.contexts.tables {
            self.record(
                path,
                span,
                "unknown",
                kind,
                &format!(
                    "table index {index} lies beyond the complete table/import declaration prefix"
                ),
                None,
            );
        }
    }

    fn function_operand(&mut self, path: &str, span: Span, index: u32) {
        self.function_operand_role(path, span, index, "instruction", "function index");
    }

    fn function_operand_role(
        &mut self,
        path: &str,
        span: Span,
        index: u32,
        kind: &str,
        role: &str,
    ) {
        let type_index = if let Some(type_index) = self.imported_function_types.get(index as usize)
        {
            Some(*type_index)
        } else if self.contexts.imported_functions {
            let defined = (index as usize).checked_sub(self.imported_function_types.len());
            defined
                .and_then(|index| self.defined_function_types.get(index))
                .copied()
        } else {
            None
        };
        if let Some(type_index) = type_index {
            self.type_operand_role(
                path,
                span,
                type_index,
                kind,
                &format!("{role} {index} signature type index"),
            );
        } else if !self.contexts.imported_functions || !self.contexts.defined_functions {
            self.record(path, span, "unknown", kind, &format!("{role} {index} lies beyond the complete imported/defined function declaration prefixes"), None);
        }
    }

    fn global_operand(&mut self, path: &str, span: Span, index: u32, kind: &str) {
        self.pending_global_uses.push(IndexUse {
            path: path.into(),
            span,
            index,
            kind: kind.into(),
            role: "global index".into(),
        });
    }

    fn tag_operand(&mut self, path: &str, span: Span, index: u32, kind: &str, role: &str) {
        if let Some(type_index) = self.tags.get(index as usize).copied() {
            self.type_operand_role(
                path,
                span,
                type_index,
                kind,
                &format!("{role} {index} signature type index"),
            );
        } else if !self.contexts.tags {
            self.record(
                path,
                span,
                "unknown",
                kind,
                &format!("{role} {index} lies beyond the complete tag/import declaration prefix"),
                None,
            );
        }
    }

    fn type_operand(&mut self, path: &str, span: Span, index: u32, kind: &str) {
        self.type_operand_role(path, span, index, kind, "type index");
    }

    fn type_operand_role(&mut self, path: &str, span: Span, index: u32, kind: &str, role: &str) {
        self.pending_type_uses.push(IndexUse {
            path: path.into(),
            span,
            index,
            kind: kind.into(),
            role: role.into(),
        });
    }

    fn resolve_pending_uses(&mut self) {
        for use_ in std::mem::take(&mut self.pending_type_uses) {
            if !self.contexts.types && self.type_results.get(use_.index as usize).is_none() {
                self.record(
                    &use_.path,
                    use_.span,
                    "unknown",
                    &use_.kind,
                    &format!(
                        "{} {} lies beyond the complete type declaration prefix",
                        use_.role, use_.index
                    ),
                    None,
                );
            }
        }
        for use_ in std::mem::take(&mut self.pending_global_uses) {
            if !self.contexts.globals && self.globals.get(use_.index as usize).is_none() {
                self.record(&use_.path, use_.span, "unknown", &use_.kind, &format!("global index {} lies beyond the complete global/import declaration prefix; its type, mutability and constant-expression role are unproven", use_.index), None);
            }
        }
    }
}

trait Operand {
    fn requirements(&self, collector: &mut Collector<'_>, path: &str, span: Span, name: &str);
}
impl Operand for u32 {
    fn requirements(&self, collector: &mut Collector<'_>, path: &str, span: Span, name: &str) {
        match name {
            "function_index" => collector.function_operand(path, span, *self),
            "global_index" => collector.global_operand(path, span, *self, "instruction"),
            "tag_index" => collector.tag_operand(path, span, *self, "instruction", "tag index"),
            "type_index" | "struct_type_index" | "array_type_index" | "cont_type_index" => {
                collector.type_operand(path, span, *self, "instruction")
            }
            "array_type_index_dst" => collector.type_operand_role(
                path,
                span,
                *self,
                "instruction",
                "destination array type index",
            ),
            "array_type_index_src" => collector.type_operand_role(
                path,
                span,
                *self,
                "instruction",
                "source array type index",
            ),
            "argument_index" => collector.type_operand_role(
                path,
                span,
                *self,
                "instruction",
                "continuation input type index",
            ),
            "result_index" => collector.type_operand_role(
                path,
                span,
                *self,
                "instruction",
                "continuation result type index",
            ),
            "mem" | "memory" | "src_mem" | "dst_mem" => {
                collector.memory_operand(path, span, *self, "instruction")
            }
            "table" | "table_index" | "src_table" | "dst_table" => {
                collector.table_operand(path, span, *self, "instruction")
            }
            _ => {}
        }
    }
}
impl Operand for MemArg {
    fn requirements(&self, collector: &mut Collector<'_>, path: &str, span: Span, _: &str) {
        collector.memory_operand(path, span, self.memory, "instruction");
        if self.offset > u32::MAX as u64 {
            collector.record(
                path,
                span,
                "memory64",
                "instruction",
                "memory offset exceeds the 32-bit immediate range",
                None,
            );
        }
        let mut raw = collector.reader(span);
        let encoding = (|| -> wasmparser::Result<(bool, usize)> {
            let prefix = raw.read_u8()?;
            if matches!(prefix, 0xfb..=0xfe) {
                raw.read_var_u32()?;
            }
            let explicit = raw.read_var_u32()? & 0x40 != 0;
            if explicit {
                raw.read_var_u32()?;
            }
            let start = raw.original_position();
            raw.read_var_u64()?;
            Ok((explicit, raw.original_position() - start))
        })();
        if let Ok((explicit, offset_len)) = encoding {
            if explicit {
                collector.record(path, span, "multi_memory", "instruction", "memarg has an explicit memory-index flag, including an explicitly encoded index zero", None);
            }
            if offset_len > 5 {
                collector.record(path, span, "memory64", "instruction", "memory offset uses the Core3 u64 wire grammar (more than five bytes, even for a small padded value)", None);
            }
        }
    }
}
impl Operand for BlockType {
    fn requirements(&self, collector: &mut Collector<'_>, path: &str, span: Span, _: &str) {
        match self {
            BlockType::FuncType(index) => {
                collector.type_operand(path, span, *index, "instruction");
                collector.record(
                    path,
                    span,
                    "multi_value",
                    "instruction",
                    "indexed block type with function parameters/results",
                    None,
                );
            }
            BlockType::Type(ty) => {
                collector.value(path, span, *ty, false, "instruction");
                let mut raw = collector.reader(Span {
                    start: span.start + 1,
                    end: span.end,
                });
                // Positive block immediates are valid function type indices,
                // handled by FuncType above. Only Type is a value-type wire form.
                let _ = collector.scan_value(&mut raw, path, false);
            }
            BlockType::Empty => {}
        }
        if span.end > span.start + 1 && matches!(collector.bytes[span.start + 1], 0x63 | 0x64) {
            collector.record(
                path,
                span,
                "function_references",
                "instruction",
                "explicit reference value type in a block type",
                None,
            );
        }
    }
}
impl Operand for ValType {
    fn requirements(&self, c: &mut Collector<'_>, p: &str, s: Span, _: &str) {
        c.value(p, s, *self, false, "instruction");
    }
}
impl Operand for RefType {
    fn requirements(&self, c: &mut Collector<'_>, p: &str, s: Span, _: &str) {
        c.reference(p, s, *self, false, "instruction");
    }
}
impl Operand for HeapType {
    fn requirements(&self, c: &mut Collector<'_>, p: &str, s: Span, _: &str) {
        c.heap(p, s, *self, "instruction");
    }
}
impl Operand for Vec<ValType> {
    fn requirements(&self, c: &mut Collector<'_>, p: &str, s: Span, _: &str) {
        for ty in self {
            c.value(p, s, *ty, false, "instruction");
        }
    }
}
impl Operand for wasmparser::TryTable {
    fn requirements(&self, c: &mut Collector<'_>, p: &str, s: Span, _: &str) {
        self.ty.requirements(c, p, s, "blockty");
        for (index, catch) in self.catches.iter().enumerate() {
            if let wasmparser::Catch::One { tag, .. } | wasmparser::Catch::OneRef { tag, .. } =
                catch
            {
                c.tag_operand(
                    p,
                    s,
                    *tag,
                    "instruction",
                    &format!("try_table catch[{index}] tag index"),
                );
            }
        }
    }
}
impl Operand for wasmparser::ResumeTable {
    fn requirements(&self, c: &mut Collector<'_>, p: &str, s: Span, _: &str) {
        for (index, handler) in self.handlers.iter().enumerate() {
            let (wasmparser::Handle::OnLabel { tag, .. } | wasmparser::Handle::OnSwitch { tag }) =
                handler;
            c.tag_operand(
                p,
                s,
                *tag,
                "instruction",
                &format!("resume handler[{index}] tag index"),
            );
        }
    }
}
macro_rules! no_operand_requirement { ($($ty:ty),* $(,)?) => { $(impl Operand for $ty { fn requirements(&self, _: &mut Collector<'_>, _: &str, _: Span, _: &str) {} })* }; }
no_operand_requirement!(
    i32,
    i64,
    u8,
    wasmparser::Ieee32,
    wasmparser::Ieee64,
    wasmparser::V128,
    [u8; 16],
    wasmparser::Ordering,
    wasmparser::BrTable<'_>
);

#[cfg(test)]
mod tests {
    use super::validation_error_context;
    use super::Standard;

    const MIXED_LABELS: &str = "(module (func
        block (result f64)
          block (result f32)
            unreachable i32.const 1 br_table 0 1 1
          end
          drop f64.const 0
        end
        drop))";

    #[test]
    fn core1_requires_equal_br_table_labels_even_after_unreachable() {
        let implicit_function = "(module (func (result f64)
            block (result f32)
              unreachable i32.const 0 br_table 0 1
            end
            drop f64.const 0))";
        for (source, raw_hex) in [
            (MIXED_LABELS, "0e02000101"),
            (implicit_function, "0e010001"),
        ] {
            let bytes = wat::parse_str(source).unwrap();
            for standard in [
                Standard::Core1,
                Standard::Core2,
                Standard::Core3,
                Standard::AllKnown,
            ] {
                let audit = crate::audit::inspect_with_standard(&bytes, standard).unwrap();
                assert!(
                    audit.standard.validator_valid,
                    "modern validator should expose the historical gap"
                );
                assert_eq!(audit.validation, "valid_with_all_known_features");
                let issues = audit
                    .standard
                    .evidence
                    .iter()
                    .filter(|entry| entry.status == "invalid_semantics")
                    .collect::<Vec<_>>();
                if standard == Standard::Core1 {
                    assert_eq!(audit.standard.validation, "invalid");
                    assert_eq!(issues.len(), 1);
                    assert_eq!(issues[0].feature, "core1_br_table_label_types");
                    assert_eq!(issues[0].raw_hex, raw_hex);
                    assert_eq!(bytes[issues[0].span.start], 0x0e);
                    assert_eq!(issues[0].span.end - issues[0].span.start, raw_hex.len() / 2);
                    assert!(issues[0].reason.contains("unreachable"));
                    let section = audit
                        .sections
                        .iter()
                        .find(|section| section.id == 10)
                        .unwrap();
                    assert_eq!(section.standard_support.status, "contains_invalid");
                    let operator = section.regions[1]
                        .children
                        .iter()
                        .find(|region| region.path == issues[0].path)
                        .unwrap();
                    assert_eq!(operator.standard_support.status, "invalid_semantics");
                    assert_eq!(operator.standard_support.display, "binary");
                } else {
                    assert_eq!(audit.standard.validation, "valid");
                    assert!(issues.is_empty());
                }
            }
        }
    }

    #[test]
    fn core1_loop_if_else_and_implicit_function_labels_are_preserved() {
        for source in [
            "(module (func i32.const 1 if unreachable i32.const 0 br_table 0 1 else nop end))",
            "(module (func i32.const 1 if (result f32) f32.const 0 else block (result f32) unreachable i32.const 0 br_table 0 1 end end drop))",
            "(module (func block loop (result i32) unreachable i32.const 0 br_table 0 1 end drop end))",
            "(module (import \"env\" \"unused\" (func)) (func (result f32) block (result f32) unreachable i32.const 0 br_table 0 1 end))",
            "(module (func block (result f32) block (result f32) unreachable i32.const 0 br_table 0 1 end drop f32.const 0 end drop))",
        ] {
            let bytes = wat::parse_str(source).unwrap();
            let audit = crate::audit::inspect_with_standard(&bytes, Standard::Core1).unwrap();
            assert_eq!(audit.standard.validation, "valid", "{source}");
            assert!(audit.standard.validator_valid);
            assert!(
                !audit
                    .standard
                    .evidence
                    .iter()
                    .any(|entry| entry.status == "invalid_semantics")
            );
        }
    }

    #[test]
    fn core1_historical_check_does_not_guess_after_extra_or_unknown_grammar() {
        let extra = MIXED_LABELS.replacen("(func", "(func v128.const i32x4 0 0 0 0 drop", 1);
        let extra = wat::parse_str(extra).unwrap();
        let audit = crate::audit::inspect_with_standard(&extra, Standard::Core1).unwrap();
        assert_eq!(audit.standard.validation, "invalid");
        assert!(!audit
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "invalid_semantics"));

        let mut unknown = wat::parse_str(MIXED_LABELS.replacen("drop))", "drop nop))", 1)).unwrap();
        let mut nop_offset = None;
        for payload in wasmparser::Parser::new(0).parse_all(&unknown) {
            if let wasmparser::Payload::CodeSectionEntry(body) = payload.unwrap() {
                let mut operators = body.get_operators_reader().unwrap();
                while !operators.eof() {
                    let offset = operators.original_position();
                    if matches!(operators.read().unwrap(), wasmparser::Operator::Nop) {
                        nop_offset = Some(offset);
                    }
                }
            }
        }
        unknown[nop_offset.unwrap()] = 0xff;
        let audit = crate::audit::inspect_with_standard(&unknown, Standard::Core1).unwrap();
        assert_eq!(audit.standard.validation, "invalid");
        assert!(audit
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "unknown"));
        assert!(!audit
            .standard
            .evidence
            .iter()
            .any(|entry| entry.status == "invalid_semantics"));
    }

    #[test]
    fn validation_cursor_boundaries_preserve_both_neighbors_and_eof() {
        let bytes = wat::parse_str("(module (func nop nop))").unwrap();
        let audit = crate::audit::inspect(&bytes).unwrap();
        let operators = &audit
            .sections
            .iter()
            .find(|s| s.id == 10)
            .unwrap()
            .regions
            .iter()
            .find(|r| r.path.ends_with("/function[0]"))
            .unwrap()
            .children;
        let first = operators
            .iter()
            .find(|r| r.path.ends_with("/operator[0]"))
            .unwrap();
        let second = operators
            .iter()
            .find(|r| r.path.ends_with("/operator[1]"))
            .unwrap();
        assert_eq!(first.span.end, second.span.start);
        let error = validation_error_context(
            &bytes,
            &audit.sections,
            second.span.start,
            "cursor boundary".into(),
        );
        assert!(error
            .locations
            .iter()
            .any(|l| l.path == first.path && l.relation == "ends_at_offset"));
        assert!(error
            .locations
            .iter()
            .any(|l| l.path == second.path && l.relation == "contains_offset"));
        let eof = validation_error_context(&bytes, &audit.sections, bytes.len(), "eof".into());
        assert!(eof.byte_context.offset_is_eof && eof.byte_context.offset_in_module);
        assert_eq!(eof.byte_context.span.end, bytes.len());
        let beyond = validation_error_context(
            &bytes,
            &audit.sections,
            usize::MAX,
            "external cursor".into(),
        );
        assert!(!beyond.byte_context.offset_is_eof && !beyond.byte_context.offset_in_module);
        assert!(beyond.locations.is_empty());
        assert_eq!(beyond.byte_context.span.end, bytes.len());
    }

    #[test]
    fn malformed_locals_do_not_hide_a_later_framed_disabled_instruction() {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend_from_slice(&[1, 4, 1, 0x60, 0, 0, 3, 3, 2, 0, 0]);
        bytes.extend_from_slice(&[10, 27, 2, 3, 1, 1, 0xff, 21, 0, 0xfd, 0x0c]);
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&[0x1a, 0x0b]);
        let audit = crate::audit::inspect_with_standard(&bytes, Standard::Core1).unwrap();
        assert_eq!(audit.standard.validation, "invalid");
        let later = audit
            .standard
            .evidence
            .iter()
            .find(|entry| {
                entry.path == "code[0]/function[1]/operator[0]" && entry.feature == "simd"
            })
            .expect("a known body-size frame permits recovery after malformed locals");
        assert_eq!(later.status, "recognized_but_disabled");
        assert_eq!(later.span.end - later.span.start, 18);
        assert_eq!(
            &bytes[later.span.start..later.span.start + 2],
            &[0xfd, 0x0c]
        );
        let first = audit
            .standard
            .evidence
            .iter()
            .find(|entry| entry.path == "code[0]/function[0]/opaque")
            .unwrap();
        assert_eq!(first.status, "unknown");
        assert!(first.span.end <= later.span.start);
    }
}
