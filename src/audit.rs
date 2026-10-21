//! Physical, lossless auditing of core WebAssembly binaries.
//!
//! Decoding is evidence, never a substitute for comparing the original bytes.
//! All ranges are physical, half-open byte offsets in the original file. Unknown
//! instructions terminate decoding of their expression; no instruction boundary
//! is guessed. A malformed custom convention is treated as opaque custom data.

use crate::standard::{Standard, StandardReport, StandardSupport};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use wasmparser::{
    BinaryReader, CompositeInnerType, ConstExpr, Data, DataKind, Element, ElementItems,
    ElementKind, Export, FrameStack, FromReader, FunctionBody, Global, Imports, MemoryType,
    Operator, OperatorsReader, RecGroup, Table, TableInit, TagType, TypeRef, Validator,
    WasmFeatures,
};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    fn len(self) -> usize {
        self.end - self.start
    }
    fn intersects(self, other: Self) -> bool {
        if self.start == self.end {
            return false;
        }
        if other.start == other.end {
            self.start <= other.start && other.start < self.end
        } else {
            self.start < other.end && other.start < self.end
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub severity: String,
    pub code: String,
    pub offset: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    pub path: String,
    pub span: Span,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature: Option<String>,
    pub children: Vec<Region>,
    pub standard_support: StandardSupport,
}

impl Region {
    fn new(path: impl Into<String>, span: Span, description: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            span,
            description: description.into(),
            feature: None,
            children: Vec::new(),
            standard_support: StandardSupport::default(),
        }
    }
    fn feature(mut self, feature: &str) -> Self {
        self.feature = Some(feature.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditSection {
    pub ordinal: usize,
    pub id: u8,
    pub kind: String,
    pub path: String,
    pub span: Span,
    pub header_span: Span,
    pub payload_span: Span,
    /// decoded, partially_decoded, opaque, or malformed. Decoding is not validation.
    pub status: String,
    pub regions: Vec<Region>,
    pub standard_support: StandardSupport,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditModule {
    pub byte_len: usize,
    pub format: String,
    /// Validation uses every feature known to the pinned wasmparser version.
    /// Intrinsically invalid wire encodings also fail independently of parser
    /// normalization, including when its all-known validator accepts them.
    /// Unsupported bytes remain auditable even when validation cannot succeed.
    pub validation: String,
    pub sections: Vec<AuditSection>,
    pub diagnostics: Vec<Diagnostic>,
    pub standard: StandardReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct Context {
    pub path: String,
    pub span: Span,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ByteEdit {
    pub old_span: Span,
    pub new_span: Span,
    pub old_hex: String,
    pub new_hex: String,
    pub old_context: Vec<Context>,
    pub new_context: Vec<Context>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticChange {
    pub path: String,
    pub old: Option<Context>,
    pub new: Option<Context>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditDiff {
    pub changed: bool,
    pub old: AuditModule,
    pub new: AuditModule,
    pub edits: Vec<ByteEdit>,
    pub semantic_changes: Vec<SemanticChange>,
    /// True means shortest insertion/deletion distance, with no substitutions.
    pub exact_minimal: bool,
    pub alignment: String,
}

fn issue(
    out: &mut Vec<Diagnostic>,
    severity: &str,
    code: &str,
    offset: usize,
    message: impl Into<String>,
) {
    out.push(Diagnostic {
        severity: severity.into(),
        code: code.into(),
        offset,
        message: message.into(),
    });
}

fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data_count",
        13 => "tag",
        _ => "unknown",
    }
}

/// Inspect a core module without discarding unsupported or malformed payloads.
/// Invalid headers and Component Model encodings are outside this API's scope.
pub fn inspect(bytes: &[u8]) -> Result<AuditModule, String> {
    inspect_with_standard(bytes, Standard::AllKnown)
}

/// Offset-preserving input for pinned Core parsers that discard custom metadata.
/// Complete original custom names are independently checked before hiding only
/// names exceeding the pinned reader's limit. This is not the original module:
/// never use it for audit, storage, hashing, patches, or custom-name identity.
#[doc(hidden)]
pub fn core_reader_bytes(bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    crate::core_view::ReaderView::new(bytes).bytes
}

/// Recognize with all-known grammar, then evaluate the selected Core standard.
pub fn inspect_with_standard(bytes: &[u8], standard: Standard) -> Result<AuditModule, String> {
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        return Err("expected an eight-byte core WebAssembly header".into());
    }
    if bytes[4..8] != [1, 0, 0, 0] {
        return Err("unsupported WebAssembly encoding/version; only core modules are in scope (Component Model excluded)".into());
    }
    let mut module = AuditModule {
        byte_len: bytes.len(),
        format: "core WebAssembly binary, version 1".into(),
        validation: "not_validated".into(),
        sections: Vec::new(),
        diagnostics: Vec::new(),
        standard: StandardReport::pending(standard),
    };
    let mut cursor = BinaryReader::new(&bytes[8..], 8);
    let mut occurrences = BTreeMap::<u8, usize>::new();
    let mut imported_functions = 0u32;
    let mut imported_functions_known = true;
    let mut function_index_context_valid = true;
    let mut last_section_rank = 0;
    while !cursor.eof() {
        let start = cursor.original_position();
        let id = cursor.read_u8().map_err(|e| e.to_string())?;
        let occurrence = occurrences.entry(id).or_default();
        let duplicate = (1..=13).contains(&id) && *occurrence != 0;
        let path = if id > 13 {
            format!("unknown:{id}[{occurrence}]")
        } else {
            format!("{}[{}]", section_name(id), occurrence)
        };
        *occurrence += 1;
        // The id already proves an ordering/uniqueness failure even if the
        // following size cannot be read. In particular, a late unreadable
        // import must retract earlier combined function/index assumptions.
        let ordering_error = section_rank(id).and_then(|rank| {
            let error = if duplicate {
                Some((
                    "section_duplicate",
                    format!("non-custom section {id} occurs more than once"),
                ))
            } else if rank < last_section_rank {
                Some((
                    "section_order",
                    format!("section {id} is out of Core section order"),
                ))
            } else {
                None
            };
            last_section_rank = last_section_rank.max(rank);
            error
        });
        if ordering_error.is_some() {
            if matches!(id, 2 | 3 | 10) {
                function_index_context_valid = false;
            }
            if id == 2 {
                imported_functions_known = false;
            }
        }
        let size = match cursor.read_var_u32() {
            Ok(size) => size as usize,
            Err(error) => {
                issue(
                    &mut module.diagnostics,
                    "error",
                    "section_framing",
                    error.offset(),
                    error.to_string(),
                );
                let mut section = AuditSection {
                    ordinal: module.sections.len(),
                    id,
                    kind: section_name(id).into(),
                    path: format!("unframed[{}]", module.sections.len()),
                    span: Span::new(start, bytes.len()),
                    header_span: Span::new(start, bytes.len()),
                    payload_span: Span::new(bytes.len(), bytes.len()),
                    status: "malformed".into(),
                    regions: vec![Region::new(
                        format!("unframed[{}]/framing", module.sections.len()),
                        Span::new(start, bytes.len()),
                        "invalid section byte length; remaining bytes have no trusted section boundary",
                    ).feature("invalid_encoding")],
                    standard_support: StandardSupport::default(),
                };
                if let Some((code, message)) = ordering_error {
                    mark_section_order(&mut section, &mut module.diagnostics, code, message);
                }
                module.sections.push(section);
                break;
            }
        };
        let payload_start = cursor.original_position();
        let end = payload_start.saturating_add(size).min(bytes.len());
        let mut section = AuditSection {
            ordinal: module.sections.len(),
            id,
            kind: section_name(id).into(),
            path,
            span: Span::new(start, end),
            header_span: Span::new(start, payload_start),
            payload_span: Span::new(payload_start, end),
            status: "decoded".into(),
            regions: Vec::new(),
            standard_support: StandardSupport::default(),
        };
        if size > cursor.bytes_remaining() {
            section.status = "malformed".into();
            section.regions.push(Region::new(
                format!("{}/framing", section.path),
                section.header_span,
                "declared section payload extends beyond the actual file; payload grammar is not decoded",
            ).feature("invalid_encoding"));
            section.regions.push(Region::new(
                format!("{}/opaque", section.path),
                section.payload_span,
                "truncated section payload",
            ));
            issue(
                &mut module.diagnostics,
                "error",
                "section_framing",
                payload_start,
                format!(
                    "section {id} declares {size} bytes, only {} remain",
                    cursor.bytes_remaining()
                ),
            );
            if let Some((code, message)) = ordering_error {
                mark_section_order(&mut section, &mut module.diagnostics, code, message);
            }
            module.sections.push(section);
            break;
        }
        let payload = cursor.read_bytes(size).map_err(|e| e.to_string())?;
        let reader = BinaryReader::new(payload, payload_start);
        let diagnostic_start = module.diagnostics.len();
        let decoded = if id == 0 {
            custom(&mut section, payload, &mut module.diagnostics)
        } else {
            core_section(
                &mut section,
                reader,
                &mut module.diagnostics,
                &mut imported_functions,
                imported_functions_known,
            )
        };
        let decoded = if withdraw_untrusted_expression_suffix(&mut section, &mut module.diagnostics)
        {
            // Any upstream error after the unknown frontier depends on the
            // very value-type fallback whose inferred boundaries we withdrew.
            Ok(())
        } else {
            decoded
        };
        if let Some(frontier) = section
            .regions
            .iter()
            .find(|region| region.feature.as_deref() == Some("unknown_declaration_type"))
        {
            section.status = "partially_decoded".into();
            if id == 2 {
                imported_functions_known = false;
            }
            issue(
                &mut module.diagnostics,
                "warning",
                "unknown_declaration_type",
                frontier
                    .children
                    .first()
                    .map_or(frontier.span.start, |prefix| prefix.span.start),
                frontier.description.clone(),
            );
        }
        if let Err(error) = decoded {
            if id == 2 {
                imported_functions_known = false;
            }
            section.status = "malformed".into();
            // The error may point inside a failed entry. Preserve every
            // completed entry and keep the entire undecoded suffix, including
            // bytes consumed before the decoder noticed the failure.
            let opaque_start = section
                .regions
                .iter()
                .map(|region| region.span.end)
                .max()
                .unwrap_or(payload_start)
                .max(payload_start)
                .min(end);
            issue(
                &mut module.diagnostics,
                "error",
                "core_decode",
                error.offset(),
                error.to_string(),
            );
            if let Some(recovered) =
                recover_failed_expression(&section, bytes, opaque_start, &mut module.diagnostics)
            {
                section.regions.push(recovered);
                withdraw_untrusted_expression_suffix(&mut section, &mut module.diagnostics);
            } else if section
                .regions
                .last()
                .is_none_or(|region| region.feature.as_deref() != Some("invalid_encoding"))
            {
                let invalid = if id == 0 {
                    None
                } else {
                    crate::decode_error::section_failure(
                        &error,
                        id,
                        BinaryReader::new(&bytes[opaque_start..end], opaque_start),
                        opaque_start == payload_start,
                    )
                };
                let mut suffix = Region::new(
                    format!("{}/undecoded", section.path),
                    Span::new(opaque_start, end),
                    format!("{}: {error}; undecoded payload includes the failed entry and remaining bytes, without inferred later entry boundaries", invalid.unwrap_or("unrecognized or unclassified grammar")),
                ).feature(if invalid.is_some() { "invalid_encoding" } else { "unknown" });
                let at_payload_start = opaque_start == payload_start;
                let reader = BinaryReader::new(&bytes[opaque_start..end], opaque_start);
                let (failure, field_path) = if at_payload_start {
                    match id {
                        8 => (
                            crate::value_guard::scalar_failure(id, &error, reader),
                            "start_error",
                        ),
                        12 => (
                            crate::value_guard::scalar_failure(id, &error, reader),
                            "data_count_error",
                        ),
                        _ => (
                            crate::value_guard::count_failure(id, &error, reader),
                            "count_error",
                        ),
                    }
                } else {
                    match id {
                        1 => (
                            crate::value_guard::type_failure(&error, reader),
                            "type_error",
                        ),
                        2 => (
                            crate::value_guard::import_failure(&error, reader),
                            "import_error",
                        ),
                        3 => (
                            crate::value_guard::scalar_failure(id, &error, reader),
                            "function_error",
                        ),
                        7 => (
                            crate::value_guard::scalar_failure(id, &error, reader),
                            "export_error",
                        ),
                        9..=11 => (
                            crate::value_guard::segment_failure(id, &error, reader),
                            match id {
                                9 => "element_error",
                                10 => "code_error",
                                11 => "data_error",
                                _ => unreachable!(),
                            },
                        ),
                        4 | 5 | 6 | 13 => (
                            crate::value_guard::header_failure(id, &error, reader),
                            match id {
                                4 => "table_error",
                                5 => "memory_error",
                                6 => "global_error",
                                13 => "tag_error",
                                _ => unreachable!(),
                            },
                        ),
                        _ => (None, ""),
                    }
                };
                if let Some(failure) = failure {
                    suffix.children.push(
                        Region::new(
                            format!("{}/{}", suffix.path, field_path),
                            Span::new(failure.span.start, failure.span.end),
                            format!("{}: {}; only this field is diagnosed, remaining bytes stay undecoded", failure.field, failure.reason),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if !at_payload_start {
                    if let Some(failure) = crate::decode_error::linkage_failure(
                        id,
                        BinaryReader::new(&bytes[opaque_start..end], opaque_start),
                    ) {
                        suffix.children.push(
                            Region::new(
                                format!("{}/{}", suffix.path, failure.field),
                                Span::new(failure.span.start, failure.span.end),
                                failure.reason,
                            )
                            .feature("invalid_encoding"),
                        );
                    }
                }
                section.regions.push(suffix);
            }
        }
        if section.status == "decoded" {
            let emitted = &module.diagnostics[diagnostic_start..];
            if emitted.iter().any(|d| d.severity == "error") {
                section.status = "malformed".into();
            } else if emitted.iter().any(|d| {
                d.code == "unknown_operator"
                    || (d.code == "locals_decode" && d.severity == "warning")
            }) {
                section.status = "partially_decoded".into();
            }
        }
        if let Some((code, message)) = ordering_error {
            mark_section_order(&mut section, &mut module.diagnostics, code, message);
        }
        module.sections.push(section);
    }
    if !function_index_context_valid {
        // An import after code can change the supposed combined indices of
        // bodies already read. Defined ordinals remain physical positions.
        for section in &mut module.sections {
            if section.id != 10 {
                continue;
            }
            for region in &mut section.regions {
                if let Some((_, suffix)) = region
                    .description
                    .split_once(' ')
                    .filter(|_| region.description.starts_with("function_index="))
                {
                    region.description = format!(
                        "function_index=unknown {suffix}; import/function/code section order or uniqueness prevents a proven declaration mapping"
                    );
                }
            }
        }
    }
    let reader_view = crate::core_view::ReaderView::new(bytes);
    match Validator::new_with_features(WasmFeatures::all()).validate_all(&reader_view.bytes) {
        Ok(_) => module.validation = "valid_with_all_known_features".into(),
        Err(error) => {
            module.validation = "failed_or_unsupported".into();
            issue(
                &mut module.diagnostics,
                "error",
                "validation",
                error.offset(),
                error.to_string(),
            );
        }
    }
    module.standard =
        crate::standard::classify(bytes, &mut module.sections, standard, &reader_view);
    if module
        .sections
        .iter()
        .any(|section| section.id != 0 && section.status != "decoded")
    {
        // A permissive validator may accept a bare value-type fallback even
        // when the primary reader has withdrawn that declaration's grammar.
        // Its actual result remains in standard.validator_valid; the module
        // summary cannot claim complete all-known validity across this gap.
        module.validation = "failed_or_unsupported".into();
    }
    for evidence in module
        .standard
        .evidence
        .iter()
        .filter(|entry| entry.status == "invalid_encoding")
    {
        module.validation = "failed_or_unsupported".into();
        issue(
            &mut module.diagnostics,
            "error",
            "invalid_encoding",
            evidence.span.start,
            evidence.reason.clone(),
        );
    }
    Ok(module)
}

fn section_rank(id: u8) -> Option<u8> {
    Some(match id {
        1..=5 => id,
        13 => 6,
        6..=9 => id + 1,
        12 => 11,
        10 => 12,
        11 => 13,
        _ => return None,
    })
}

fn mark_section_order(
    section: &mut AuditSection,
    diagnostics: &mut Vec<Diagnostic>,
    code: &str,
    message: String,
) {
    section.status = "malformed".into();
    issue(
        diagnostics,
        "error",
        code,
        section.header_span.start,
        message.clone(),
    );
    section.regions.push(
        Region::new(
            format!("{}/ordering", section.path),
            section.header_span,
            message,
        )
        .feature("invalid_encoding"),
    );
}

fn entries<'a, T: FromReader<'a>>(
    reader: &mut BinaryReader<'a>,
    section_id: u8,
    path: &str,
    completed: &mut Vec<Region>,
    mut visit: impl FnMut(usize, Span, T) -> wasmparser::Result<Region>,
) -> wasmparser::Result<Vec<Region>> {
    let start = reader.original_position();
    let section = wasmparser::SectionLimited::<T>::new(reader.clone())?;
    let count = section.count() as usize;
    let mut out = vec![Region::new(
        format!("{path}/count"),
        Span::new(start, section.original_position()),
        section.count().to_string(),
    )];
    let mut it = section.into_iter();
    let mut index = 0;
    loop {
        let start = it.original_position();
        if index < count {
            let mut entry_reader = reader.clone();
            entry_reader.read_bytes(start - reader.original_position())?;
            if let Some(offset) = crate::value_guard::unknown_entry_value(section_id, entry_reader)
            {
                let mut suffix = Region::new(
                    format!("{path}/undecoded"),
                    Span::new(start, reader.range().end),
                    format!("unknown value-type prefix at offset {offset}; the current entry/group and remaining section are not decoded; no later declaration boundaries inferred"),
                ).feature("unknown_declaration_type");
                suffix.children.push(
                    Region::new(
                        format!("{path}/undecoded/value_type_start"),
                        Span::new(offset, offset + 1),
                        "unrecognized value-type form starts here; its complete length is unknown",
                    )
                    .feature("unknown_value_type"),
                );
                out.push(suffix);
                return Ok(out);
            }
        }
        let Some(value) = it.next() else { break };
        if index == count {
            match value {
                Err(error) => {
                    completed.append(&mut out);
                    completed.push(Region::new(format!("{path}/trailing_bytes"), Span::new(start, reader.range().end), "bytes after the declared section entry count; not decoded as entries or instructions").feature("invalid_encoding"));
                    return Err(error);
                }
                Ok(_) => unreachable!("section iterator cannot exceed its declared count"),
            }
        }
        let region =
            value.and_then(|value| visit(index, Span::new(start, it.original_position()), value));
        match region {
            Ok(region) => out.push(region),
            Err(error) => {
                completed.append(&mut out);
                return Err(error);
            }
        }
        index += 1;
    }
    Ok(out)
}

fn simple_entries<'a, T: FromReader<'a> + std::fmt::Debug>(
    reader: &mut BinaryReader<'a>,
    section_id: u8,
    path: &str,
    completed: &mut Vec<Region>,
) -> wasmparser::Result<Vec<Region>> {
    entries(
        reader,
        section_id,
        path,
        completed,
        |index, span, value: T| {
            Ok(Region::new(
                format!("{path}/entry[{index}]"),
                span,
                format!("{value:?}"),
            ))
        },
    )
}

fn locals_field_error(path: &str, failure: crate::value_guard::FieldFailure) -> Region {
    Region::new(
        format!("{path}/opaque/locals_error"),
        Span::new(failure.span.start, failure.span.end),
        format!(
            "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
            failure.field, failure.reason
        ),
    )
    .feature("invalid_encoding")
}

fn core_section(
    section: &mut AuditSection,
    mut reader: BinaryReader<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    imported_functions: &mut u32,
    imported_functions_known: bool,
) -> wasmparser::Result<()> {
    let path = section.path.clone();
    let source = reader.clone();
    // Parse each frame independently. One unknown core section cannot hide later sections.
    section.regions = match section.id {
        1 => {
            let mut type_index = 0usize;
            entries(
                &mut reader,
                section.id,
                &path,
                &mut section.regions,
                |index, span, group: RecGroup| {
                    let mut region = Region::new(
                        format!("{path}/group[{index}]"),
                        span,
                        format!("recursive_group explicit={}", group.is_explicit_rec_group()),
                    );
                    let types: Vec<_> = group.into_types_and_offsets().collect();
                    for (i, (start, ty)) in types.iter().enumerate() {
                        let end = types.get(i + 1).map_or(span.end, |(offset, _)| *offset);
                        let feature = match ty.composite_type.inner {
                            CompositeInnerType::Array(_) | CompositeInnerType::Struct(_) => "gc",
                            CompositeInnerType::Cont(_) => "stack_switching",
                            _ if !ty.is_final || ty.supertype_idx.is_some() => "gc",
                            _ => "core_types",
                        };
                        region.children.push(
                            Region::new(
                                format!("{path}/type[{type_index}]"),
                                Span::new(*start, end),
                                format!("{ty:?}"),
                            )
                            .feature(feature),
                        );
                        type_index += 1;
                    }
                    Ok(region)
                },
            )?
        }
        2 => entries(
            &mut reader,
            section.id,
            &path,
            &mut section.regions,
            |index, span, imports: Imports<'_>| {
                let description = match &imports {
                    Imports::Single(_, import) => format!(
                        "single import module={:?} name={:?} type={:?}",
                        import.module, import.name, import.ty
                    ),
                    Imports::Compact1 { module, .. } => {
                        format!("compact import group, shared module={module:?}")
                    }
                    Imports::Compact2 { module, ty, .. } => {
                        format!("compact import group, shared module={module:?} type={ty:?}")
                    }
                };
                let mut region = Region::new(format!("{path}/group[{index}]"), span, description);
                let shared = matches!(&imports, Imports::Compact2 { .. });
                if let Imports::Compact2 { ty, .. } = &imports {
                    let mut raw = source.clone();
                    raw.read_bytes(span.start - raw.original_position())?;
                    let mut raw =
                        BinaryReader::new(raw.read_bytes(span.end - span.start)?, span.start);
                    raw.read_unlimited_string()?;
                    raw.read_unlimited_string()?;
                    raw.read_u8()?; // Proven Compact2 discriminator, not a type byte.
                    let start = raw.original_position();
                    raw.read::<TypeRef>()?;
                    region.children.push(Region::new(
                        format!("{path}/group[{index}]/shared_type"),
                        Span::new(start, raw.original_position()),
                        format!(
                            "shared_type={ty:?}; encoded once for the group's actual name entries"
                        ),
                    ));
                }
                let imports: Vec<_> = imports.into_iter().collect::<wasmparser::Result<_>>()?;
                for (i, (start, import)) in imports.iter().enumerate() {
                    let end = imports.get(i + 1).map_or(span.end, |(offset, _)| *offset);
                    if matches!(import.ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
                        *imported_functions = imported_functions.saturating_add(1);
                    }
                    region.children.push(Region::new(
                        format!("{path}/group[{index}]/import[{i}]"),
                        Span::new(*start, end),
                        if shared {
                            format!("{import:?}; name entry instantiates {path}/group[{index}]/shared_type")
                        } else {
                            format!("{import:?}")
                        },
                    ));
                }
                Ok(region)
            },
        )?,
        3 => simple_entries::<u32>(&mut reader, section.id, &path, &mut section.regions)?,
        4 => entries(
            &mut reader,
            section.id,
            &path,
            &mut section.regions,
            |index, span, table: Table<'_>| {
                let entry_path = format!("{path}/entry[{index}]");
                let mut region = Region::new(&entry_path, span, format!("{:?}", table.ty));
                if let TableInit::Expr(expr) = table.init {
                    region.children.push(expression(
                        expr,
                        &format!("{entry_path}/init"),
                        diagnostics,
                    ));
                }
                Ok(region)
            },
        )?,
        5 => simple_entries::<MemoryType>(&mut reader, section.id, &path, &mut section.regions)?,
        6 => entries(
            &mut reader,
            section.id,
            &path,
            &mut section.regions,
            |index, span, global: Global<'_>| {
                let entry_path = format!("{path}/entry[{index}]");
                let mut region = Region::new(&entry_path, span, format!("{:?}", global.ty));
                region.children.push(expression(
                    global.init_expr,
                    &format!("{entry_path}/init"),
                    diagnostics,
                ));
                Ok(region)
            },
        )?,
        7 => simple_entries::<Export<'_>>(&mut reader, section.id, &path, &mut section.regions)?,
        8 | 12 => {
            let start = reader.original_position();
            let value = reader.read_var_u32()?;
            let mut regions = vec![Region::new(
                format!("{path}/value"),
                Span::new(start, reader.original_position()),
                value.to_string(),
            )];
            if !reader.eof() {
                section.status = "malformed".into();
                issue(
                    diagnostics,
                    "error",
                    "core_decode",
                    reader.original_position(),
                    "section size mismatch: trailing bytes after scalar payload",
                );
                regions.push(
                    Region::new(
                        format!("{path}/undecoded"),
                        Span::new(reader.original_position(), section.payload_span.end),
                        "trailing bytes after scalar payload",
                    )
                    .feature("invalid_encoding"),
                );
            }
            regions
        }
        9 => entries(
            &mut reader,
            section.id,
            &path,
            &mut section.regions,
            |index, span, element: Element<'_>| {
                let entry_path = format!("{path}/entry[{index}]");
                let (description, offset) = match element.kind {
                    ElementKind::Passive => ("passive".into(), None),
                    ElementKind::Declared => ("declared".into(), None),
                    ElementKind::Active {
                        table_index,
                        offset_expr,
                    } => (
                        format!("active table={}", table_index.unwrap_or(0)),
                        Some(offset_expr),
                    ),
                };
                let mut region = Region::new(&entry_path, span, description);
                if let Some(expr) = offset {
                    region.children.push(expression(
                        expr,
                        &format!("{entry_path}/offset"),
                        diagnostics,
                    ));
                }
                match element.items {
                    ElementItems::Functions(items) => {
                        let mut it = items.into_iter();
                        let mut i = 0;
                        loop {
                            let start = it.original_position();
                            let Some(item) = it.next() else { break };
                            let function = item?;
                            region.children.push(Region::new(
                                format!("{entry_path}/item[{i}]"),
                                Span::new(start, it.original_position()),
                                format!("function={function}"),
                            ));
                            i += 1;
                        }
                    }
                    ElementItems::Expressions(ty, items) => {
                        region
                            .description
                            .push_str(&format!(" element_type={ty:?}"));
                        for (i, expr) in items.into_iter().enumerate() {
                            region.children.push(expression(
                                expr?,
                                &format!("{entry_path}/item[{i}]"),
                                diagnostics,
                            ));
                        }
                    }
                }
                Ok(region)
            },
        )?,
        10 => entries(
            &mut reader,
            section.id,
            &path,
            &mut section.regions,
            |index, span, body: FunctionBody<'_>| {
                let entry_path = format!("{path}/function[{index}]");
                let mut region = Region::new(
                    &entry_path,
                    span,
                    if imported_functions_known {
                        format!(
                            "function_index={} defined_index={index}",
                            (*imported_functions as usize).saturating_add(index)
                        )
                    } else {
                        format!(
                            "function_index=unknown defined_index={index}; import section is incomplete"
                        )
                    },
                );
                let body_span = body.range();
                region.children.push(Region::new(
                    format!("{entry_path}/body_size"),
                    Span::new(span.start, body_span.start),
                    format!("{}", body_span.len()),
                ));
                match body.get_locals_reader() {
                    Ok(mut locals) => {
                        region.children.push(Region::new(
                            format!("{entry_path}/locals_count"),
                            Span::new(body_span.start, locals.original_position()),
                            locals.get_count().to_string(),
                        ));
                        let mut failed = false;
                        let mut total_count = 0u32;
                        for i in 0..locals.get_count() {
                            let start = locals.original_position();
                            let mut raw = body.get_binary_reader();
                            raw.read_bytes(start - body_span.start)
                                .expect("local cursor is inside the framed body");
                            let mut value = raw.clone();
                            // The locals reader checks the cumulative count
                            // before reading this group's value type.
                            if value
                                .read_var_u32()
                                .ok()
                                .and_then(|count| total_count.checked_add(count))
                                .is_some()
                                && !crate::decode_error::value_prefix_known(&value)
                            {
                                let invalid = crate::decode_error::forbidden_bare_index(&value);
                                issue(
                                    diagnostics,
                                    if invalid { "error" } else { "warning" },
                                    "locals_decode",
                                    value.original_position(),
                                    "untrusted local value-type prefix; no later group or instruction boundaries inferred",
                                );
                                region.children.push(Region::new(format!("{entry_path}/opaque"), Span::new(start, body_span.end), if invalid { "a bare positive type index is not a value-type shorthand; remaining locals and body are not decoded" } else { "unknown local value-type prefix; remaining locals and body are not decoded" }).feature(if invalid { "invalid_encoding" } else { "unknown" }));
                                failed = true;
                                break;
                            }
                            match locals.read() {
                                Ok((count, ty)) => {
                                    total_count += count;
                                    region.children.push(Region::new(
                                        format!("{entry_path}/local_group[{i}]"),
                                        Span::new(start, locals.original_position()),
                                        format!("count={count} type={ty:?}"),
                                    ));
                                }
                                Err(error) => {
                                    let failure = crate::value_guard::locals_field_failure(
                                        &error,
                                        raw.clone(),
                                        true,
                                    );
                                    let invalid =
                                        crate::decode_error::locals_failure(&error, raw, true);
                                    issue(
                                        diagnostics,
                                        "error",
                                        "locals_decode",
                                        error.offset(),
                                        error.to_string(),
                                    );
                                    let mut suffix = Region::new(
                                        format!("{entry_path}/opaque"),
                                        Span::new(start, body_span.end),
                                        format!("{}: {error}; undecoded locals and remaining instructions", invalid.unwrap_or("unrecognized or unclassified locals grammar")),
                                    ).feature(if invalid.is_some() { "invalid_encoding" } else { "unknown" });
                                    if let Some(failure) = failure {
                                        suffix
                                            .children
                                            .push(locals_field_error(&entry_path, failure));
                                    }
                                    region.children.push(suffix);
                                    failed = true;
                                    break;
                                }
                            }
                        }
                        if !failed {
                            decode_operators(
                                OperatorsReader::new(locals.get_binary_reader()),
                                body_span.end,
                                &entry_path,
                                &mut region.children,
                                diagnostics,
                            );
                        }
                    }
                    Err(error) => {
                        let failure = crate::value_guard::locals_field_failure(
                            &error,
                            body.get_binary_reader(),
                            false,
                        );
                        let invalid = crate::decode_error::locals_failure(
                            &error,
                            body.get_binary_reader(),
                            false,
                        );
                        issue(
                            diagnostics,
                            "error",
                            "locals_decode",
                            error.offset(),
                            error.to_string(),
                        );
                        let mut suffix = Region::new(
                            format!("{entry_path}/opaque"),
                            Span::new(body_span.start, body_span.end),
                            format!(
                                "{}: {error}; undecoded function body",
                                invalid.unwrap_or("unrecognized or unclassified locals grammar")
                            ),
                        )
                        .feature(if invalid.is_some() {
                            "invalid_encoding"
                        } else {
                            "unknown"
                        });
                        if let Some(failure) = failure {
                            suffix
                                .children
                                .push(locals_field_error(&entry_path, failure));
                        }
                        region.children.push(suffix);
                    }
                }
                Ok(region)
            },
        )?,
        11 => entries(
            &mut reader,
            section.id,
            &path,
            &mut section.regions,
            |index, span, data: Data<'_>| {
                let entry_path = format!("{path}/entry[{index}]");
                let (description, offset) = match data.kind {
                    DataKind::Passive => ("passive".into(), None),
                    DataKind::Active {
                        memory_index,
                        offset_expr,
                    } => (format!("active memory={memory_index}"), Some(offset_expr)),
                };
                let mut region = Region::new(&entry_path, span, description);
                if let Some(expr) = offset {
                    region.children.push(expression(
                        expr,
                        &format!("{entry_path}/offset"),
                        diagnostics,
                    ));
                }
                region.children.push(Region::new(
                    format!("{entry_path}/bytes"),
                    Span::new(span.end - data.data.len(), span.end),
                    format!("data bytes={}", data.data.len()),
                ));
                Ok(region)
            },
        )?,
        13 => entries(
            &mut reader,
            section.id,
            &path,
            &mut section.regions,
            |index, span, tag: TagType| {
                Ok(
                    Region::new(format!("{path}/entry[{index}]"), span, format!("{tag:?}"))
                        .feature("exceptions"),
                )
            },
        )?,
        id => {
            section.status = "opaque".into();
            issue(
                diagnostics,
                "warning",
                "unknown_section",
                section.span.start,
                format!(
                    "unknown core section id {id}; payload preserved without interpreting its format"
                ),
            );
            vec![Region::new(
                format!("{path}/opaque"),
                section.payload_span,
                format!("unknown section id={id}"),
            )]
        }
    };
    Ok(())
}

/// A failed unframed entry can retain an expression prefix only after its
/// preceding grammar proved the expression start. Never look for an End byte,
/// and never reinterpret data/string fields after a successfully read expr.
fn recover_failed_expression(
    section: &AuditSection,
    bytes: &[u8],
    start: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Region> {
    if !matches!(section.id, 4 | 6 | 9 | 11) || start >= section.payload_span.end {
        return None;
    }
    let index = section
        .regions
        .iter()
        .filter(|region| region.path.starts_with(&format!("{}/entry[", section.path)))
        .count();
    let path = format!("{}/entry[{index}]", section.path);
    let end = section.payload_span.end;
    let mut reader = BinaryReader::new(&bytes[start..end], start);
    let mut completed = Vec::new();
    let mut first_expr_start = None;
    fn take_expression<'a>(
        reader: &mut BinaryReader<'a>,
        path: String,
        completed: &mut Vec<(String, ConstExpr<'a>)>,
        first_expr_start: &mut Option<usize>,
    ) -> Option<(String, BinaryReader<'a>)> {
        first_expr_start.get_or_insert(reader.original_position());
        let before = reader.clone();
        if crate::decode_error::expression_needs_recovery(before.clone()) {
            return Some((path, before));
        }
        match reader.read::<ConstExpr<'_>>() {
            Ok(expression) => {
                completed.push((path, expression));
                None
            }
            Err(_) => Some((path, before)),
        }
    }
    let description;
    let (failed_path, failed) = match section.id {
        6 => {
            if !crate::decode_error::value_prefix_known(&reader) {
                return None;
            }
            let ty = reader.read::<wasmparser::GlobalType>().ok()?;
            description = format!("{ty:?}");
            take_expression(
                &mut reader,
                format!("{path}/init"),
                &mut completed,
                &mut first_expr_start,
            )?
        }
        4 => {
            if reader.read_u8().ok()? != 0x40 || reader.read_u8().ok()? != 0 {
                return None;
            }
            if !crate::decode_error::value_prefix_known(&reader) {
                return None;
            }
            let ty = reader.read::<wasmparser::TableType>().ok()?;
            description = format!("{ty:?}");
            take_expression(
                &mut reader,
                format!("{path}/init"),
                &mut completed,
                &mut first_expr_start,
            )?
        }
        11 => {
            let flags = reader.read_var_u32().ok()?;
            let memory = match flags {
                0 => 0,
                2 => reader.read_var_u32().ok()?,
                _ => return None,
            };
            description = format!("active memory={memory}");
            take_expression(
                &mut reader,
                format!("{path}/offset"),
                &mut completed,
                &mut first_expr_start,
            )?
        }
        9 => {
            let flags = reader.read_var_u32().ok()?;
            if flags > 7 {
                return None;
            }
            description = format!("element flags={flags}");
            let mut failure = None;
            if flags & 1 == 0 {
                if flags & 2 != 0 {
                    reader.read_var_u32().ok()?;
                }
                failure = take_expression(
                    &mut reader,
                    format!("{path}/offset"),
                    &mut completed,
                    &mut first_expr_start,
                );
            }
            if let Some(failure) = failure {
                failure
            } else {
                if flags & 3 != 0 {
                    if flags & 4 != 0 {
                        if !crate::decode_error::value_prefix_known(&reader) {
                            return None;
                        }
                        reader.read::<wasmparser::RefType>().ok()?;
                    } else {
                        reader.read::<wasmparser::ExternalKind>().ok()?;
                    }
                }
                if flags & 4 == 0 {
                    return None;
                }
                let count = reader.read_var_u32().ok()?;
                for item in 0..count {
                    failure = take_expression(
                        &mut reader,
                        format!("{path}/item[{item}]"),
                        &mut completed,
                        &mut first_expr_start,
                    );
                    if failure.is_some() {
                        break;
                    }
                }
                failure?
            }
        }
        _ => return None,
    };
    // ConstExpr stops at the first End and requires that it closes the root.
    // The same horizon avoids mistaking following payload bytes for operators
    // when a malformed constant expression contains nested control constructs.
    let mut horizon = end;
    let mut scan = OperatorsReader::new(failed.clone());
    while !scan.eof() {
        if crate::decode_error::select_value_prefix(scan.get_binary_reader()).is_some() {
            break;
        }
        match scan.read() {
            Ok(Operator::End) => {
                horizon = scan.original_position();
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let mut region = Region::new(&path, Span::new(start, end), format!("{description}; incomplete expression/entry, remaining section has no inferred entry boundaries")).feature("recovered_expression");
    region.children.push(Region::new(
        format!("{path}/header"),
        Span::new(start, first_expr_start?),
        "entry fields before the first known constant expression",
    ));
    for (path, expression_value) in completed {
        region
            .children
            .push(expression(expression_value, &path, diagnostics).feature("recovered_expression"));
    }
    let mut failed_region = Region::new(
        &failed_path,
        Span::new(failed.original_position(), horizon),
        "incomplete constant expression",
    )
    .feature("recovered_expression");
    decode_operators(
        OperatorsReader::new(BinaryReader::new(
            &bytes[failed.original_position()..horizon],
            failed.original_position(),
        )),
        horizon,
        &failed_path,
        &mut failed_region.children,
        diagnostics,
    );
    region.children.push(failed_region);
    if horizon < end {
        region.children.push(Region::new(format!("{path}/undecoded"), Span::new(horizon, end), "remaining entry/section bytes after expression failure; no entry or payload boundaries inferred").feature("unknown"));
    }
    Some(region)
}

fn expression(expr: ConstExpr<'_>, path: &str, diagnostics: &mut Vec<Diagnostic>) -> Region {
    let range = expr.get_binary_reader().range();
    let mut region = Region::new(
        path,
        Span::new(range.start, range.end),
        "constant expression",
    );
    decode_operators(
        expr.get_operators_reader(),
        range.end,
        path,
        &mut region.children,
        diagnostics,
    );
    region
}

fn operator_feature(op: &Operator<'_>) -> &'static str {
    macro_rules! feature {
        ($( @$proposal:ident $op:ident $({ $($arg:ident: $argty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
            match op {
                $(Operator::$op $( { $($arg: _),* } )? => stringify!($proposal),)*
                _ => "unknown",
            }
        }
    }
    wasmparser::for_each_operator!(feature)
}

/// A permissive value-type fallback can make the upstream ConstExpr reader
/// return an apparent End. A strict unknown prefix cannot lend credibility to
/// later unframed entries, even when that upstream parse happened to succeed.
fn withdraw_untrusted_expression_suffix(
    section: &mut AuditSection,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    if !matches!(section.id, 4 | 6 | 9 | 11) {
        return false;
    }
    for index in 0..section.regions.len() {
        let entry = &mut section.regions[index];
        let Some((expression_index, opaque_index)) =
            entry
                .children
                .iter()
                .enumerate()
                .find_map(|(i, expression)| {
                    expression
                        .children
                        .iter()
                        .position(|child| {
                            child.path.ends_with("/opaque")
                                && child.feature.as_deref() == Some("unknown_value_type")
                        })
                        .map(|j| (i, j))
                })
        else {
            continue;
        };
        let end = section.payload_span.end;
        let expression = &mut entry.children[expression_index];
        expression.children.truncate(opaque_index + 1);
        let opaque = &mut expression.children[opaque_index];
        opaque.span.end = end;
        opaque
            .description
            .push_str("; remaining section has no trusted entry boundaries");
        let offset = opaque.span.start;
        expression.span.end = end;
        entry.children.truncate(expression_index + 1);
        for expression in &mut entry.children {
            if expression.description == "constant expression" {
                expression.feature = Some("recovered_expression".into());
            }
        }
        entry.span.end = end;
        entry.feature = Some("recovered_expression".into());
        if let Some((prefix, _)) = entry.description.split_once(" element_type=") {
            entry.description = prefix.into();
        }
        entry
            .description
            .push_str("; unknown value-type prefix prevents later expression or entry boundaries");
        section.regions.truncate(index + 1);
        section.status = "partially_decoded".into();
        diagnostics.retain(|diagnostic| {
            diagnostic.offset < offset
                || (diagnostic.offset == offset && diagnostic.code == "unknown_operator")
        });
        issue(
            diagnostics,
            "warning",
            "unknown_expression_suffix",
            offset,
            "unknown typed-select value-type prefix; later entries in this section are not decoded",
        );
        return true;
    }
    false
}

fn decode_operators(
    mut reader: OperatorsReader<'_>,
    end: usize,
    path: &str,
    regions: &mut Vec<Region>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut index = 0;
    while !reader.eof() {
        let start = reader.original_position();
        if reader.current_frame().is_none() {
            let error = reader
                .finish()
                .expect_err("remaining bytes after the terminating End");
            issue(
                diagnostics,
                "error",
                "expression_structure",
                start,
                error.to_string(),
            );
            regions.push(
                Region::new(
                    format!("{path}/trailing_bytes"),
                    Span::new(start, end),
                    "bytes after the expression's terminating End; not decoded as instructions",
                )
                .feature("invalid_encoding"),
            );
            return;
        }
        let raw = reader.get_binary_reader();
        if let Some(invalid) = crate::decode_error::select_value_prefix(raw.clone()) {
            issue(
                diagnostics,
                if invalid { "error" } else { "warning" },
                if invalid {
                    "operator_decode"
                } else {
                    "unknown_operator"
                },
                start,
                "untrusted typed-select value prefix; no later instruction boundaries inferred",
            );
            regions.push(Region::new(format!("{path}/opaque"), Span::new(start, end), if invalid { "a bare positive type index is not a value-type shorthand; typed select and remaining expression are not decoded" } else { "unknown typed-select value-type prefix; instruction and remaining expression are not decoded" }).feature(if invalid { "invalid_encoding" } else { "unknown_value_type" }));
            return;
        }
        match reader.read() {
            Ok(op) => {
                regions.push(
                    Region::new(
                        format!("{path}/operator[{index}]"),
                        Span::new(start, reader.original_position()),
                        format!("{op:?}"),
                    )
                    .feature(operator_feature(&op)),
                );
                index += 1;
            }
            Err(error) => {
                let message = error.to_string();
                let heap_failure = crate::value_guard::heap_operand_failure(&error, raw.clone());
                let br_table_failure = crate::value_guard::br_table_failure(&error, raw.clone());
                let try_table_failure = crate::value_guard::try_table_failure(&error, raw.clone());
                let call_indirect_failure =
                    crate::value_guard::call_indirect_failure(&error, raw.clone());
                let memarg_failure = crate::value_guard::memarg_failure(&error, raw.clone());
                let memory_index_failure =
                    crate::value_guard::memory_index_failure(&error, raw.clone());
                let bulk_index_failure =
                    crate::value_guard::bulk_index_failure(&error, raw.clone());
                let gc_immediate_failure =
                    crate::value_guard::gc_immediate_failure(&error, raw.clone());
                let primary_index_failure =
                    crate::value_guard::primary_index_failure(&error, raw.clone());
                let simd_immediate_failure =
                    crate::value_guard::simd_immediate_failure(&error, raw.clone());
                let invalid = crate::decode_error::operator_failure(&error, raw);
                let unknown = message.contains("unknown") || message.contains("illegal opcode");
                issue(
                    diagnostics,
                    if unknown { "warning" } else { "error" },
                    if unknown {
                        "unknown_operator"
                    } else {
                        "operator_decode"
                    },
                    start,
                    format!(
                        "{message}; remaining expression opaque from byte {start}, no resynchronization attempted"
                    ),
                );
                let mut opaque = Region::new(
                        format!("{path}/opaque"),
                        Span::new(start, end),
                        format!("{}: {error}; failed instruction and remaining expression are not decoded; no later instruction boundaries inferred", invalid.unwrap_or("unrecognized or unclassified instruction grammar")),
                    )
                    .feature(if invalid.is_some() { "invalid_encoding" } else { "unknown" });
                if let Some(failure) = heap_failure {
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/heap_type_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.field, failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(crate::value_guard::BrTableFailure { failure, target }) =
                    br_table_failure
                {
                    let field = target.map_or_else(
                        || failure.field.to_owned(),
                        |index| format!("branch table target[{index}] depth"),
                    );
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/br_table_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{field}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(crate::value_guard::TryTableFailure { failure, catch }) =
                    try_table_failure
                {
                    let field = catch.map_or_else(
                        || failure.field.to_owned(),
                        |index| format!("try table catch[{index}] {}", failure.field),
                    );
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/try_table_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{field}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(failure) = call_indirect_failure {
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/call_indirect_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.field, failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(failure) = memarg_failure {
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/memarg_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.field, failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(failure) = memory_index_failure {
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/memory_index_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.field, failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(failure) = bulk_index_failure {
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/bulk_index_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.field, failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(failure) = gc_immediate_failure {
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/gc_immediate_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.field, failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(failure) = primary_index_failure {
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/primary_index_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.field, failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                if let Some(crate::value_guard::SimdImmediateFailure { failure, lane }) =
                    simd_immediate_failure
                {
                    let field = lane.map_or_else(
                        || failure.field.to_owned(),
                        |index| format!("i8x16.shuffle lane[{index}] index"),
                    );
                    opaque.children.push(
                        Region::new(
                            format!("{path}/opaque/simd_immediate_error"),
                            Span::new(failure.span.start, failure.span.end),
                            format!(
                                "{field}: {}; only this field is diagnosed, remaining bytes stay undecoded",
                                failure.reason
                            ),
                        )
                        .feature("invalid_encoding"),
                    );
                }
                regions.push(opaque);
                return;
            }
        }
    }
    if let Err(error) = reader.finish() {
        issue(
            diagnostics,
            "error",
            "expression_structure",
            reader.original_position(),
            error.to_string(),
        );
        regions.push(
            Region::new(
                format!("{path}/expression_structure"),
                Span::new(reader.original_position(), end),
                "expression ended before all control frames were closed by End",
            )
            .feature("invalid_encoding"),
        );
    }
}

// Custom conventions deliberately require canonical LEBs, unique and ordered
// name indices/subsections, full consumption, and known layouts. Recognizing a
// section name alone is not evidence that its data follows that convention.
struct ConventionReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    pos: usize,
}
impl<'a> ConventionReader<'a> {
    fn new(bytes: &'a [u8], offset: usize) -> Self {
        Self {
            bytes,
            offset,
            pos: 0,
        }
    }
    fn position(&self) -> usize {
        self.offset + self.pos
    }
    fn eof(&self) -> bool {
        self.pos == self.bytes.len()
    }
    fn byte(&mut self) -> Result<u8, String> {
        let byte = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| format!("truncated custom data at {}", self.position()))?;
        self.pos += 1;
        Ok(byte)
    }
    fn u32(&mut self) -> Result<u32, String> {
        let start = self.position();
        let mut value = 0u32;
        for i in 0..5 {
            let byte = self.byte()?;
            if i == 4 && byte & 0xf0 != 0 {
                return Err(format!("invalid custom u32 at {start}"));
            }
            value |= ((byte & 0x7f) as u32) << (7 * i);
            if byte & 0x80 == 0 {
                if i > 0 && byte == 0 {
                    return Err(format!("noncanonical custom LEB at {start}"));
                }
                return Ok(value);
            }
        }
        Err(format!("invalid custom LEB at {start}"))
    }
    fn take(&mut self, len: usize) -> Result<ConventionReader<'a>, String> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| format!("custom length exceeds payload at {}", self.position()))?;
        let reader = Self::new(&self.bytes[self.pos..end], self.position());
        self.pos = end;
        Ok(reader)
    }
    fn string(&mut self) -> Result<&'a str, String> {
        let len = self.u32()? as usize;
        let part = self.take(len)?;
        std::str::from_utf8(part.bytes)
            .map_err(|e| format!("invalid custom UTF-8 at {}: {e}", part.offset))
    }
    fn finish(&self) -> Result<(), String> {
        if self.eof() {
            Ok(())
        } else {
            Err(format!("trailing custom bytes at {}", self.position()))
        }
    }
}

fn custom(
    section: &mut AuditSection,
    payload: &[u8],
    diagnostics: &mut Vec<Diagnostic>,
) -> wasmparser::Result<()> {
    // The custom section name is part of the core binary grammar, including UTF-8.
    let mut outer = BinaryReader::new(payload, section.payload_span.start);
    let name = match (|| {
        let mut probe = outer.clone();
        let length = probe.read_var_u32()? as usize;
        if length > probe.bytes_remaining() {
            // The pinned reader adds position + length internally. Check the
            // bounded payload first so a forged u32 length cannot overflow on
            // 32-bit hosts. This bounded read preserves its public EOF message
            // and count-end offset without using the forged length again.
            probe.read_bytes(probe.bytes_remaining() + 1)?;
        }
        outer.read_unlimited_string()
    })() {
        Ok(name) => name,
        Err(error) => {
            section.regions.push(Region::new(
                format!("{}/outer_name", section.path),
                section.payload_span,
                "invalid Core custom-section name encoding; custom payload convention was not examined",
            ).feature("invalid_encoding"));
            return Err(error);
        }
    };
    let data_start = outer.original_position();
    section.kind = format!("custom:{name}");
    section.regions.push(Region::new(
        format!("{}/name", section.path),
        Span::new(section.payload_span.start, data_start),
        name,
    ));
    // Logical selectors must remain bounded and representable in an OS argv.
    // Arbitrary custom names may contain NUL or exceed argument-size limits.
    let path = if matches!(name, "name" | "producers" | "target_features") {
        format!("{}/{}", section.path, name)
    } else {
        format!("{}/payload", section.path)
    };
    let mut reader = ConventionReader::new(
        &payload[data_start - section.payload_span.start..],
        data_start,
    );
    let recognized = match name {
        "name" => name_convention(&mut reader, &path),
        "producers" => producers_convention(&mut reader, &path),
        "target_features" => features_convention(&mut reader, &path),
        _ => {
            section.status = "opaque".into();
            section.regions.push(Region::new(
                format!("{path}/opaque"),
                Span::new(data_start, section.payload_span.end),
                "unrecognized custom section; uninterpreted bytes",
            ));
            return Ok(());
        }
    };
    match recognized.and_then(|regions| {
        reader.finish()?;
        Ok(regions)
    }) {
        Ok(regions) => section.regions.extend(regions),
        Err(message) => {
            section.status = "opaque".into();
            issue(
                diagnostics,
                "note",
                "custom_opaque",
                data_start,
                format!(
                    "custom {name:?} does not satisfy the recognized fixed convention: {message}; treated as opaque data"
                ),
            );
            section.regions.push(Region::new(
                format!("{path}/opaque"),
                Span::new(data_start, section.payload_span.end),
                "custom payload outside recognized fixed convention",
            ));
        }
    }
    Ok(())
}

fn name_map(
    reader: &mut ConventionReader<'_>,
    path: &str,
    indirect: bool,
) -> Result<Vec<Region>, String> {
    let start = reader.position();
    let count = reader.u32()?;
    let mut out = vec![Region::new(
        format!("{path}/count"),
        Span::new(start, reader.position()),
        count.to_string(),
    )];
    let mut previous = None;
    for _ in 0..count {
        let start = reader.position();
        let index = reader.u32()?;
        if previous.is_some_and(|p| index <= p) {
            return Err("name map indices must increase strictly".into());
        }
        previous = Some(index);
        let entry_path = format!("{path}/index[{index}]");
        if indirect {
            let children = name_map(reader, &entry_path, false)?;
            let mut region = Region::new(
                &entry_path,
                Span::new(start, reader.position()),
                format!("index={index}"),
            );
            region.children = children;
            out.push(region);
        } else {
            let name = reader.string()?;
            out.push(Region::new(
                entry_path,
                Span::new(start, reader.position()),
                format!("index={index} name={name:?}"),
            ));
        }
    }
    Ok(out)
}

fn name_convention(reader: &mut ConventionReader<'_>, path: &str) -> Result<Vec<Region>, String> {
    let mut out = Vec::new();
    let mut previous = None;
    while !reader.eof() {
        let start = reader.position();
        let id = reader.byte()?;
        if id > 11 || previous.is_some_and(|p| id <= p) {
            return Err("unknown, repeated, or unordered name subsection".into());
        }
        previous = Some(id);
        let size = reader.u32()? as usize;
        let mut sub = reader.take(size)?;
        let sub_path = format!("{path}/subsection[{id}]");
        let mut region = Region::new(
            &sub_path,
            Span::new(start, reader.position()),
            format!("name subsection={id}"),
        );
        region.children = if id == 0 {
            let start = sub.position();
            let name = sub.string()?;
            vec![Region::new(
                format!("{sub_path}/module"),
                Span::new(start, sub.position()),
                format!("module={name:?}"),
            )]
        } else {
            name_map(&mut sub, &sub_path, matches!(id, 2 | 3 | 10))?
        };
        sub.finish()?;
        out.push(region);
    }
    Ok(out)
}

fn producers_convention(
    reader: &mut ConventionReader<'_>,
    path: &str,
) -> Result<Vec<Region>, String> {
    let start = reader.position();
    let count = reader.u32()?;
    let mut out = vec![Region::new(
        format!("{path}/count"),
        Span::new(start, reader.position()),
        count.to_string(),
    )];
    let mut fields = BTreeSet::new();
    for _ in 0..count {
        let start = reader.position();
        let field = reader.string()?;
        if !matches!(field, "language" | "sdk" | "processed-by") || !fields.insert(field) {
            return Err("unknown or repeated producer field".into());
        }
        let values = reader.u32()?;
        let mut region = Region::new(
            format!("{path}/{field}"),
            Span::new(start, start),
            format!("field={field} values={values}"),
        );
        let mut names = BTreeSet::new();
        for index in 0..values {
            let start = reader.position();
            let name = reader.string()?;
            let version = reader.string()?;
            if !names.insert(name) {
                return Err("repeated producer name".into());
            }
            region.children.push(Region::new(
                format!("{path}/{field}/value[{index}]"),
                Span::new(start, reader.position()),
                format!("name={name:?} version={version:?}"),
            ));
        }
        region.span.end = reader.position();
        out.push(region);
    }
    Ok(out)
}

fn features_convention(
    reader: &mut ConventionReader<'_>,
    path: &str,
) -> Result<Vec<Region>, String> {
    let start = reader.position();
    let count = reader.u32()?;
    let mut out = vec![Region::new(
        format!("{path}/count"),
        Span::new(start, reader.position()),
        count.to_string(),
    )];
    let mut features = BTreeSet::new();
    for index in 0..count {
        let start = reader.position();
        let prefix = reader.byte()?;
        if !matches!(prefix, b'+' | b'-') {
            return Err("unknown target_features prefix".into());
        }
        let name = reader.string()?;
        if name.is_empty() || !features.insert(name) {
            return Err("empty or repeated target feature".into());
        }
        out.push(Region::new(
            format!("{path}/feature[{index}]"),
            Span::new(start, reader.position()),
            format!("{}{name}", prefix as char),
        ));
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn flatten<'a>(regions: &'a [Region], out: &mut BTreeMap<String, &'a Region>) {
    for region in regions {
        out.insert(region.path.clone(), region);
        flatten(&region.children, out);
    }
}

struct ContextRecord<'a> {
    path: &'a str,
    span: Span,
    description: Cow<'a, str>,
    parent: Option<usize>,
    section_order: usize,
    /// Section containers remain visible even when a child region overlaps.
    container: bool,
}

struct IntervalNode {
    record: usize,
    max_end: usize,
    left: Option<usize>,
    right: Option<usize>,
}

/// Built once per module. Borrow decoded strings, and use an augmented interval
/// tree so each edit visits its overlapping regions rather than every operator.
struct ContextIndex<'a> {
    records: Vec<ContextRecord<'a>>,
    nodes: Vec<IntervalNode>,
    root: Option<usize>,
}

impl<'a> ContextIndex<'a> {
    fn new(module: &'a AuditModule) -> Self {
        fn append<'a>(
            regions: &'a [Region],
            parent: usize,
            section_order: usize,
            records: &mut Vec<ContextRecord<'a>>,
        ) {
            for region in regions {
                let index = records.len();
                records.push(ContextRecord {
                    path: &region.path,
                    span: region.span,
                    description: Cow::Borrowed(&region.description),
                    parent: Some(parent),
                    section_order,
                    container: false,
                });
                append(&region.children, index, section_order, records);
            }
        }
        fn build(
            sorted: &[usize],
            records: &[ContextRecord<'_>],
            nodes: &mut Vec<IntervalNode>,
        ) -> Option<usize> {
            if sorted.is_empty() {
                return None;
            }
            let middle = sorted.len() / 2;
            let left = build(&sorted[..middle], records, nodes);
            let right = build(&sorted[middle + 1..], records, nodes);
            let record = sorted[middle];
            let max_end = records[record]
                .span
                .end
                .max(left.map_or(0, |index| nodes[index].max_end))
                .max(right.map_or(0, |index| nodes[index].max_end));
            let index = nodes.len();
            nodes.push(IntervalNode {
                record,
                max_end,
                left,
                right,
            });
            Some(index)
        }
        let mut records = vec![ContextRecord {
            path: "header",
            span: Span::new(0, 8),
            description: Cow::Borrowed("core WebAssembly header"),
            parent: None,
            section_order: 0,
            container: false,
        }];
        for section in &module.sections {
            let parent = records.len();
            let section_order = section.ordinal + 1;
            records.push(ContextRecord {
                path: &section.path,
                span: section.span,
                description: Cow::Owned(format!("{} ({})", section.kind, section.status)),
                parent: None,
                section_order,
                container: true,
            });
            append(&section.regions, parent, section_order, &mut records);
        }
        let mut sorted: Vec<_> = (0..records.len()).collect();
        sorted.sort_unstable_by_key(|index| {
            (records[*index].span.start, records[*index].span.end, *index)
        });
        let mut nodes = Vec::with_capacity(records.len());
        let root = build(&sorted, &records, &mut nodes);
        Self {
            records,
            nodes,
            root,
        }
    }

    fn overlapping(&self, span: Span) -> (Vec<usize>, usize) {
        fn query(
            index: &ContextIndex<'_>,
            node: Option<usize>,
            span: Span,
            matches: &mut Vec<usize>,
            visited: &mut usize,
        ) {
            let Some(node) = node else { return };
            *visited += 1;
            let node = &index.nodes[node];
            if node.max_end <= span.start {
                return;
            }
            query(index, node.left, span, matches, visited);
            let record = &index.records[node.record];
            if record.span.intersects(span) {
                matches.push(node.record);
            }
            // All starts in the right subtree are >= the current start. Point
            // insertions use <=, while nonempty half-open edits use <.
            let before_end = if span.start == span.end {
                record.span.start <= span.start
            } else {
                record.span.start < span.end
            };
            if before_end {
                query(index, node.right, span, matches, visited);
            }
        }
        let mut matches = Vec::new();
        let mut visited = 0;
        query(self, self.root, span, &mut matches, &mut visited);
        (matches, visited)
    }

    fn context(&self, span: Span) -> Vec<Context> {
        let (mut matches, _) = self.overlapping(span);
        // A matching child's parent is already known; never scan a function's
        // entire child list to decide whether its operator gives closer context.
        let parents: BTreeSet<_> = matches
            .iter()
            .filter_map(|index| self.records[*index].parent)
            .collect();
        matches.retain(|index| self.records[*index].container || !parents.contains(index));
        matches.sort_unstable_by_key(|index| {
            let record = &self.records[*index];
            (
                record.section_order,
                record.container,
                record.span.len(),
                record.span.start,
                *index,
            )
        });
        let mut out: Vec<_> = matches
            .into_iter()
            .map(|index| {
                let record = &self.records[index];
                Context {
                    path: record.path.into(),
                    span: record.span,
                    description: record.description.to_string(),
                }
            })
            .collect();
        if out.is_empty() {
            out.push(Context {
                path: "file_boundary".into(),
                span,
                description: "insertion/deletion at file boundary".into(),
            });
        }
        out
    }
}

fn differing_middle(old: &[u8], new: &[u8], old_base: usize, new_base: usize) -> (Span, Span) {
    let prefix = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let suffix = old[prefix..]
        .iter()
        .rev()
        .zip(new[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    (
        Span::new(old_base + prefix, old_base + old.len() - suffix),
        Span::new(new_base + prefix, new_base + new.len() - suffix),
    )
}

// One call has a bounded edit distance/trace. All fallback gaps share the same
// work counter, so a module with many gaps cannot repeatedly spend that budget.
fn shortest_spans(
    old: &[u8],
    new: &[u8],
    old_base: usize,
    new_base: usize,
    remaining_work: &mut usize,
) -> Option<Vec<(Span, Span)>> {
    let (old_span, new_span) = differing_middle(old, new, old_base, new_base);
    let a = &old[old_span.start - old_base..old_span.end - old_base];
    let b = &new[new_span.start - new_base..new_span.end - new_base];
    if a.is_empty() && b.is_empty() {
        return Some(Vec::new());
    }
    if a.is_empty() || b.is_empty() {
        return Some(vec![(old_span, new_span)]);
    }
    const MAX_DISTANCE: usize = 1024;
    if a.len().abs_diff(b.len()) > MAX_DISTANCE || *remaining_work == 0 {
        return None;
    }
    let max_distance = MAX_DISTANCE.min(a.len().saturating_add(b.len()));
    let offset = max_distance as isize + 1;
    let mut v = vec![0isize; 2 * max_distance + 3];
    let mut trace = Vec::new();
    for distance in 0..=max_distance {
        trace.push(v.clone());
        let d = distance as isize;
        for k in (-d..=d).step_by(2) {
            *remaining_work = remaining_work.checked_sub(1)?;
            let at = (offset + k) as usize;
            let mut x = if k == -d || (k != d && v[at - 1] < v[at + 1]) {
                v[at + 1]
            } else {
                v[at - 1] + 1
            };
            let mut y = x - k;
            while x >= 0
                && y >= 0
                && (x as usize) < a.len()
                && (y as usize) < b.len()
                && a[x as usize] == b[y as usize]
            {
                x += 1;
                y += 1;
                *remaining_work = remaining_work.checked_sub(1)?;
            }
            v[at] = x;
            if x as usize >= a.len() && y as usize >= b.len() {
                let (mut x, mut y) = (a.len() as isize, b.len() as isize);
                let mut atoms = Vec::new();
                for d in (1..=distance).rev() {
                    let prior = &trace[d];
                    let k = x - y;
                    let at = (offset + k) as usize;
                    let previous_k = if k == -(d as isize)
                        || (k != d as isize && prior[at - 1] < prior[at + 1])
                    {
                        k + 1
                    } else {
                        k - 1
                    };
                    let previous_x = prior[(offset + previous_k) as usize];
                    let previous_y = previous_x - previous_k;
                    while x > previous_x && y > previous_y {
                        x -= 1;
                        y -= 1;
                    }
                    if x == previous_x {
                        y -= 1;
                        atoms.push((x as usize, y as usize, false));
                    } else {
                        x -= 1;
                        atoms.push((x as usize, y as usize, true));
                    }
                }
                atoms.reverse();
                let mut edits: Vec<(Span, Span)> = Vec::new();
                for (x, y, deletion) in atoms {
                    let x = old_span.start + x;
                    let y = new_span.start + y;
                    if let Some((old, new)) = edits.last_mut() {
                        if old.end == x && new.end == y {
                            if deletion {
                                old.end += 1;
                            } else {
                                new.end += 1;
                            }
                            continue;
                        }
                    }
                    edits.push((
                        Span::new(x, x + usize::from(deletion)),
                        Span::new(y, y + usize::from(!deletion)),
                    ));
                }
                return Some(edits);
            }
        }
    }
    None
}

const ANCHOR_WINDOW: usize = 32;
const MAX_ANCHOR_CANDIDATES: usize = 65_536;

#[derive(Clone, Copy)]
struct ByteAnchor {
    old: usize,
    new: usize,
}

struct AnchorCandidate {
    old: usize,
    seen_old: bool,
    new: Option<usize>,
}

fn window_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |hash, byte| {
        hash.wrapping_mul(257).wrapping_add(u64::from(*byte) + 1)
    })
}

fn scan_windows(bytes: &[u8], mut visit: impl FnMut(usize, u64) -> bool) {
    if bytes.len() < ANCHOR_WINDOW {
        return;
    }
    let factor = 257u64.wrapping_pow((ANCHOR_WINDOW - 1) as u32);
    let mut hash = window_hash(&bytes[..ANCHOR_WINDOW]);
    for position in 0..=bytes.len() - ANCHOR_WINDOW {
        if !visit(position, hash) {
            return;
        }
        if let Some(incoming) = bytes.get(position + ANCHOR_WINDOW) {
            hash = hash
                .wrapping_sub((u64::from(bytes[position]) + 1).wrapping_mul(factor))
                .wrapping_mul(257)
                .wrapping_add(u64::from(*incoming) + 1);
        }
    }
}

/// Retain only verified byte windows whose hash occurs exactly once on each
/// side of this comparison. Hash collisions can discard anchors, never create
/// a false equality. Repeated/ambiguous windows are deliberately ineligible.
fn unique_anchors(old: &[u8], new: &[u8]) -> Vec<ByteAnchor> {
    if old.len() < ANCHOR_WINDOW || new.len() < ANCHOR_WINDOW {
        return Vec::new();
    }
    let windows = old.len() - ANCHOR_WINDOW + 1;
    let stride = windows
        .div_ceil(MAX_ANCHOR_CANDIDATES)
        .max(2 * ANCHOR_WINDOW);
    let mut candidates = BTreeMap::<u64, AnchorCandidate>::new();
    for position in (0..windows).step_by(stride) {
        candidates
            .entry(window_hash(&old[position..position + ANCHOR_WINDOW]))
            .or_insert(AnchorCandidate {
                old: position,
                seen_old: false,
                new: None,
            });
    }
    // A small membership filter avoids most tree lookups while scanning all
    // byte positions. Both its memory and candidate-map memory have fixed caps.
    const FILTER_BITS: usize = 1 << 20;
    let bit = |hash: u64| {
        ((hash ^ (hash >> 32)).wrapping_mul(0x9e3779b97f4a7c15) as usize) & (FILTER_BITS - 1)
    };
    let mut filter = vec![0u64; FILTER_BITS / 64];
    for hash in candidates.keys() {
        let bit = bit(*hash);
        filter[bit / 64] |= 1u64 << (bit % 64);
    }
    let present = |hash| {
        let bit = bit(hash);
        filter[bit / 64] & (1u64 << (bit % 64)) != 0
    };
    scan_windows(old, |position, hash| {
        if present(hash) {
            if let std::collections::btree_map::Entry::Occupied(mut entry) = candidates.entry(hash)
            {
                if entry.get().seen_old {
                    entry.remove();
                } else {
                    let candidate = entry.get_mut();
                    candidate.old = position;
                    candidate.seen_old = true;
                }
            }
        }
        !candidates.is_empty()
    });
    scan_windows(new, |position, hash| {
        if present(hash) {
            if let std::collections::btree_map::Entry::Occupied(mut entry) = candidates.entry(hash)
            {
                if entry.get().new.is_some() {
                    entry.remove();
                } else {
                    entry.get_mut().new = Some(position);
                }
            }
        }
        !candidates.is_empty()
    });
    let mut anchors: Vec<_> = candidates
        .into_values()
        .filter_map(|candidate| {
            let new_position = candidate.new?;
            if old[candidate.old..candidate.old + ANCHOR_WINDOW]
                == new[new_position..new_position + ANCHOR_WINDOW]
            {
                Some(ByteAnchor {
                    old: candidate.old,
                    new: new_position,
                })
            } else {
                None
            }
        })
        .collect();
    anchors.sort_unstable_by_key(|anchor| anchor.old);
    // Longest increasing subsequence avoids allowing a moved byte block to
    // force all later anchors out of order. This is alignment evidence only.
    let mut tails: Vec<usize> = Vec::new();
    let mut previous = vec![None; anchors.len()];
    for (index, anchor) in anchors.iter().enumerate() {
        let position = tails.partition_point(|prior| anchors[*prior].new < anchor.new);
        if position > 0 {
            previous[index] = Some(tails[position - 1]);
        }
        if position == tails.len() {
            tails.push(index);
        } else {
            tails[position] = index;
        }
    }
    let mut ordered = Vec::new();
    let mut cursor = tails.last().copied();
    while let Some(index) = cursor {
        ordered.push(anchors[index]);
        cursor = previous[index];
    }
    ordered.reverse();
    let (mut old_end, mut new_end) = (0, 0);
    ordered.retain(|anchor| {
        if anchor.old < old_end || anchor.new < new_end {
            return false;
        }
        old_end = anchor.old + ANCHOR_WINDOW;
        new_end = anchor.new + ANCHOR_WINDOW;
        true
    });
    ordered
}

fn fallback_gap(
    old: &[u8],
    new: &[u8],
    old_base: usize,
    new_base: usize,
    remaining_work: &mut usize,
) -> Vec<(Span, Span)> {
    if let Some(edits) = shortest_spans(old, new, old_base, new_base, remaining_work) {
        return edits;
    }
    let (old_span, new_span) = differing_middle(old, new, old_base, new_base);
    let a = &old[old_span.start - old_base..old_span.end - old_base];
    let b = &new[new_span.start - new_base..new_span.end - new_base];
    if a.len() != b.len() {
        return vec![(old_span, new_span)];
    }
    // Positional mismatch runs preserve fine locations when even a local gap
    // exhausts the shared budget. No shortest-alignment claim is made for them.
    let mut edits = Vec::new();
    let mut i = 0;
    while i < a.len() {
        if a[i] == b[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < a.len() && a[i] != b[i] {
            i += 1;
        }
        edits.push((
            Span::new(old_span.start + start, old_span.start + i),
            Span::new(new_span.start + start, new_span.start + i),
        ));
    }
    edits
}

fn anchored_fallback(old: &[u8], new: &[u8], remaining_work: &mut usize) -> Vec<(Span, Span)> {
    let (old_span, new_span) = differing_middle(old, new, 0, 0);
    let a = &old[old_span.start..old_span.end];
    let b = &new[new_span.start..new_span.end];
    let anchors = unique_anchors(a, b);
    let mut edits = Vec::new();
    let (mut old_position, mut new_position) = (0, 0);
    for anchor in anchors.iter().copied().chain(std::iter::once(ByteAnchor {
        old: a.len(),
        new: b.len(),
    })) {
        edits.extend(fallback_gap(
            &a[old_position..anchor.old],
            &b[new_position..anchor.new],
            old_span.start + old_position,
            new_span.start + new_position,
            remaining_work,
        ));
        // The terminal sentinel has no matched window after it.
        old_position = anchor.old.saturating_add(ANCHOR_WINDOW).min(a.len());
        new_position = anchor.new.saturating_add(ANCHOR_WINDOW).min(b.len());
    }
    edits
}

// Exact global Myers gets most of the total work budget. If it cannot finish,
// verified unique-content anchors localize gaps, which share the remainder.
// The fallback is complete and bounded, but never globally minimal by assertion.
fn byte_spans(old: &[u8], new: &[u8]) -> (Vec<(Span, Span)>, bool) {
    let mut global_work = 6_000_000;
    if let Some(edits) = shortest_spans(old, new, 0, 0, &mut global_work) {
        return (edits, true);
    }
    let mut gap_work = 2_000_000 + global_work;
    (anchored_fallback(old, new, &mut gap_work), false)
}

/// Compare original physical bytes and add decoded evidence at both locations.
/// Raw edits are authoritative, including encoding-only and opaque-byte changes.
pub fn compare(old: &[u8], new: &[u8]) -> Result<AuditDiff, String> {
    compare_with_standard(old, new, Standard::AllKnown)
}

/// Standard selection changes compatibility evidence, never physical edits.
pub fn compare_with_standard(
    old: &[u8],
    new: &[u8],
    standard: Standard,
) -> Result<AuditDiff, String> {
    let old_module = inspect_with_standard(old, standard)?;
    let new_module = inspect_with_standard(new, standard)?;
    let (spans, exact_minimal) = byte_spans(old, new);
    let old_context = ContextIndex::new(&old_module);
    let new_context = ContextIndex::new(&new_module);
    let edits = spans
        .into_iter()
        .map(|(old_span, new_span)| ByteEdit {
            old_span,
            new_span,
            old_hex: hex(&old[old_span.start..old_span.end]),
            new_hex: hex(&new[new_span.start..new_span.end]),
            old_context: old_context.context(old_span),
            new_context: new_context.context(new_span),
        })
        .collect();
    let mut old_regions = BTreeMap::new();
    let mut new_regions = BTreeMap::new();
    for section in &old_module.sections {
        flatten(&section.regions, &mut old_regions);
    }
    for section in &new_module.sections {
        flatten(&section.regions, &mut new_regions);
    }
    let paths: BTreeSet<_> = old_regions
        .keys()
        .chain(new_regions.keys())
        .cloned()
        .collect();
    let mut semantic_changes = Vec::new();
    for path in paths {
        let a = old_regions.get(&path);
        let b = new_regions.get(&path);
        if a.map(|r| (&r.description, &r.feature)) == b.map(|r| (&r.description, &r.feature)) {
            continue;
        }
        let convert = |r: &&Region| Context {
            path: r.path.clone(),
            span: r.span,
            description: r.description.clone(),
        };
        semantic_changes.push(SemanticChange {
            path,
            old: a.map(convert),
            new: b.map(convert),
        });
    }
    Ok(AuditDiff {
        changed: old != new, old: old_module, new: new_module, edits, semantic_changes, exact_minimal,
        alignment: if exact_minimal { "shortest byte insertion/deletion script; semantic paths use section occurrence and entry/operator index, not inferred identity" }
            else { "bounded byte-diff fallback: verified unique byte-window anchors with monotone alignment; gaps share a bounded local Myers budget, then positional mismatch runs or complete gap replacements; not guaranteed globally minimal; semantic paths are positional" }.into(),
    })
}

impl AuditModule {
    pub fn to_text(&self) -> String {
        fn regions(out: &mut String, entries: &[Region], depth: usize) {
            for region in entries {
                let description = if region.standard_support.display == "binary" {
                    binary_description(&region.standard_support.status)
                } else {
                    &region.description
                };
                let _ = writeln!(
                    out,
                    "{}{} [{}..{}) {}{} standard_support={} display={}",
                    "  ".repeat(depth),
                    region.path.escape_debug(),
                    region.span.start,
                    region.span.end,
                    description.escape_debug(),
                    region
                        .feature
                        .as_ref()
                        .map(|f| format!(" feature={f}"))
                        .unwrap_or_default(),
                    region.standard_support.status,
                    region.standard_support.display,
                );
                regions(out, &region.children, depth + 1);
            }
        }
        let mut out = format!(
            "{} bytes; {}; validation={}\nphysical offsets are half-open byte ranges\n",
            self.byte_len, self.format, self.validation
        );
        for section in &self.sections {
            let _ = writeln!(
                out,
                "{} {} [{}..{}) header=[{}..{}) payload=[{}..{}) status={} standard_support={}",
                section.path,
                section.kind.escape_debug(),
                section.span.start,
                section.span.end,
                section.header_span.start,
                section.header_span.end,
                section.payload_span.start,
                section.payload_span.end,
                section.status,
                section.standard_support.status,
            );
            regions(&mut out, &section.regions, 1);
        }
        standard_text(&mut out, "", &self.standard);
        for diagnostic in &self.diagnostics {
            let _ = writeln!(
                out,
                "{} {} @{}: {}",
                diagnostic.severity,
                diagnostic.code,
                diagnostic.offset,
                diagnostic.message.escape_debug()
            );
        }
        out
    }
}

impl AuditDiff {
    pub fn to_text(&self) -> String {
        fn binary_paths(module: &AuditModule) -> BTreeMap<&str, &str> {
            let mut flattened = BTreeMap::new();
            for section in &module.sections {
                flatten(&section.regions, &mut flattened);
            }
            flattened
                .into_values()
                .filter_map(|region| {
                    (region.standard_support.display == "binary").then_some((
                        region.path.as_str(),
                        region.standard_support.status.as_str(),
                    ))
                })
                .collect()
        }
        let old_binary = binary_paths(&self.old);
        let new_binary = binary_paths(&self.new);
        let description = |context: &Context, paths: &BTreeMap<&str, &str>| {
            if let Some(status) = paths.get(context.path.as_str()) {
                binary_description(status).to_owned()
            } else {
                context.description.clone()
            }
        };
        let mut out = format!(
            "{}; {} byte edits; exact_minimal={}\n{}\nold validation={}; new validation={}\n",
            if self.changed { "changed" } else { "identical" },
            self.edits.len(),
            self.exact_minimal,
            self.alignment,
            self.old.validation,
            self.new.validation
        );
        standard_text(&mut out, "old ", &self.old.standard);
        standard_text(&mut out, "new ", &self.new.standard);
        for edit in &self.edits {
            let _ = writeln!(
                out,
                "old [{}..{}) {}\nnew [{}..{}) {}",
                edit.old_span.start,
                edit.old_span.end,
                edit.old_hex,
                edit.new_span.start,
                edit.new_span.end,
                edit.new_hex
            );
            for (side, contexts, binary) in [
                ("old", &edit.old_context, &old_binary),
                ("new", &edit.new_context, &new_binary),
            ] {
                for context in contexts {
                    let _ = writeln!(
                        out,
                        "  {side} {} [{}..{}): {}",
                        context.path.escape_debug(),
                        context.span.start,
                        context.span.end,
                        description(context, binary).escape_debug()
                    );
                }
            }
        }
        for change in &self.semantic_changes {
            let _ = writeln!(
                out,
                "decoded {}: {:?} -> {:?}",
                change.path.escape_debug(),
                change.old.as_ref().map(|c| description(c, &old_binary)),
                change.new.as_ref().map(|c| description(c, &new_binary))
            );
        }
        for (side, module) in [("old", &self.old), ("new", &self.new)] {
            for diagnostic in &module.diagnostics {
                let _ = writeln!(
                    out,
                    "{side} {} {} @{}: {}",
                    diagnostic.severity,
                    diagnostic.code,
                    diagnostic.offset,
                    diagnostic.message.escape_debug()
                );
            }
        }
        out
    }
}

fn binary_description(status: &str) -> &'static str {
    match status {
        "invalid_encoding" => "binary (invalid encoding in every standard, including all-known)",
        "invalid_semantics" => {
            "binary (invalid semantics for the selected standard; see standard evidence)"
        }
        "recognized_but_disabled" => {
            "binary (recognized grammar is disabled by the selected standard)"
        }
        "unknown" => "binary (unknown requirements or index context; see standard evidence)",
        _ => "binary (see standard evidence)",
    }
}

fn standard_text(out: &mut String, side: &str, standard: &StandardReport) {
    let _ = writeln!(
        out,
        "{side}standard={} compatibility={} validator_valid={} validator_input={}; all-known recognition is separate from standard validity",
        standard.selected_standard, standard.validation, standard.validator_valid, standard.validator_input.kind
    );
    for projection in &standard.validator_input.projections {
        let _ = writeln!(
            out,
            "{side}validator custom-name projection {} name=[{}..{}) byte=[{}..{}) {}->{}; temporary reader input only, original audit bytes retained",
            projection.path, projection.name_span.start, projection.name_span.end,
            projection.byte_span.start, projection.byte_span.end,
            projection.original_hex, projection.projected_hex
        );
    }
    let opaque_paths: BTreeSet<_> = standard
        .evidence
        .iter()
        .filter(|evidence| evidence.status == "unknown" && evidence.kind == "opaque")
        .map(|evidence| evidence.path.as_str())
        .collect();
    for evidence in &standard.evidence {
        // A wholly decoded region already explains its supported grammar.
        // An opaque declaration still needs its independently proved prefix
        // fields in text, including names and supported wire features.
        if evidence.status == "supported" && !opaque_paths.contains(evidence.path.as_str()) {
            continue;
        }
        let _ = writeln!(
            out,
            "{side}{} {} [{}..{}) binary={} feature={} recognized={:?}: {}",
            evidence.status,
            evidence.path.escape_debug(),
            evidence.span.start,
            evidence.span.end,
            evidence.raw_hex,
            evidence.feature,
            evidence
                .recognized
                .as_ref()
                .map(|name| name.escape_debug().to_string()),
            evidence.reason.escape_debug()
        );
    }
    if let Some(error) = &standard.validator_error {
        let _ = writeln!(
            out,
            "{side}standard validator first error @{}: {}",
            error.offset,
            error.message.escape_debug()
        );
        let _ = writeln!(
            out,
            "{side}validator raw context [{}..{}) binary={} offset_in_module={} offset_is_eof={}; locations are cursor context, not causal attribution",
            error.byte_context.span.start,
            error.byte_context.span.end,
            error.byte_context.raw_hex,
            error.byte_context.offset_in_module,
            error.byte_context.offset_is_eof
        );
        for location in &error.locations {
            let _ = writeln!(
                out,
                "{side}validator location {} [{}..{}) relation={}",
                location.path.escape_debug(),
                location.span.start,
                location.span.end,
                location.relation
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(sections: &[u8]) -> Vec<u8> {
        [b"\0asm\x01\0\0\0".as_slice(), sections].concat()
    }
    fn all_regions(module: &AuditModule) -> BTreeMap<String, &Region> {
        let mut regions = BTreeMap::new();
        for section in &module.sections {
            flatten(&section.regions, &mut regions);
        }
        regions
    }
    fn replay(old: &[u8], new: &[u8], spans: &[(Span, Span)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut position = 0;
        for (a, b) in spans {
            assert!(a.start >= position);
            out.extend_from_slice(&old[position..a.start]);
            out.extend_from_slice(&new[b.start..b.end]);
            position = a.end;
        }
        out.extend_from_slice(&old[position..]);
        out
    }
    #[test]
    fn myers_is_shortest_and_covers_every_byte_exhaustively() {
        // Exhaustive tiny inputs catch backtracking, insertion points and repeated-byte ambiguity.
        fn words(len: usize) -> Vec<Vec<u8>> {
            (0..1usize << len)
                .map(|word| (0..len).map(|i| ((word >> i) & 1) as u8).collect())
                .collect()
        }
        for a_len in 0..=5 {
            for b_len in 0..=5 {
                for a in words(a_len) {
                    for b in words(b_len) {
                        let (spans, exact) = byte_spans(&a, &b);
                        assert!(exact);
                        assert_eq!(replay(&a, &b, &spans), b);
                        let mut dp = vec![vec![0usize; b.len() + 1]; a.len() + 1];
                        for (i, row) in dp.iter_mut().enumerate() {
                            row[0] = i;
                        }
                        for (j, cell) in dp[0].iter_mut().enumerate() {
                            *cell = j;
                        }
                        for i in 1..=a.len() {
                            for j in 1..=b.len() {
                                dp[i][j] = if a[i - 1] == b[j - 1] {
                                    dp[i - 1][j - 1]
                                } else {
                                    (dp[i - 1][j] + 1).min(dp[i][j - 1] + 1)
                                };
                            }
                        }
                        assert_eq!(
                            spans.iter().map(|(a, b)| a.len() + b.len()).sum::<usize>(),
                            dp[a.len()][b.len()]
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn fallback_is_explicit_and_lossless() {
        let a = vec![0; 1200];
        let b = vec![1; 1200];
        let (spans, exact) = byte_spans(&a, &b);
        assert!(!exact);
        assert_eq!(replay(&a, &b, &spans), b);
        let mut b = vec![0; 3600];
        let a = b.clone();
        for i in (0..3600).step_by(3) {
            b[i] = 1;
        }
        let (spans, exact) = byte_spans(&a, &b);
        assert!(!exact);
        assert_eq!(spans.len(), 1200);
        assert_eq!(replay(&a, &b, &spans), b);
    }
    fn deterministic_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x8e7d_631a_9b42_c5f0u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }
    #[test]
    fn content_anchors_localize_insertions_deletions_and_sparse_far_edits() {
        let old = deterministic_bytes(100_000);
        let mut new = old.clone();
        new.splice(137..137, [0xab, 0xcd, 0xef]);
        new[50_000] ^= 0xff;
        new.drain(91_003..91_008);
        let anchors = unique_anchors(&old, &new);
        assert!(!anchors.is_empty());
        for anchor in &anchors {
            assert_eq!(
                &old[anchor.old..anchor.old + ANCHOR_WINDOW],
                &new[anchor.new..anchor.new + ANCHOR_WINDOW]
            );
        }
        assert!(anchors
            .windows(2)
            .all(|pair| pair[0].old + ANCHOR_WINDOW <= pair[1].old
                && pair[0].new + ANCHOR_WINDOW <= pair[1].new));
        // Even an exhausted local search budget retains these separated edits;
        // matching windows, not function indices, anchor the shifted content.
        let mut remaining = 0;
        let spans = anchored_fallback(&old, &new, &mut remaining);
        assert_eq!(remaining, 0);
        assert_eq!(replay(&old, &new, &spans), new);
        assert!(spans.len() >= 3);
        assert!(spans.iter().all(|(a, b)| a.len().max(b.len()) <= 128));
    }
    #[test]
    fn anchor_ambiguity_and_reordering_cannot_hide_bytes() {
        let repeated_old = vec![7; 10_000];
        let repeated_new = vec![7; 10_003];
        assert!(unique_anchors(&repeated_old, &repeated_new).is_empty());
        let old = deterministic_bytes(12_000);
        let new = [&old[4_000..8_000], &old[..4_000], &old[8_000..]].concat();
        let mut remaining = 2_000;
        let spans = anchored_fallback(&old, &new, &mut remaining);
        assert_eq!(replay(&old, &new, &spans), new);
        assert!(remaining <= 2_000);
        assert!(!spans.is_empty());
    }
    #[test]
    fn anchored_fallback_replays_small_inputs_without_a_search_budget() {
        for old_len in 0..=5 {
            for new_len in 0..=5 {
                for old_word in 0..1usize << old_len {
                    for new_word in 0..1usize << new_len {
                        let old: Vec<_> =
                            (0..old_len).map(|i| ((old_word >> i) & 1) as u8).collect();
                        let new: Vec<_> =
                            (0..new_len).map(|i| ((new_word >> i) & 1) as u8).collect();
                        let spans = anchored_fallback(&old, &new, &mut 0);
                        assert_eq!(replay(&old, &new, &spans), new);
                    }
                }
            }
        }
    }
    #[test]
    fn all_anchor_gaps_share_one_search_budget() {
        let old = deterministic_bytes(50_000);
        let mut new = old.clone();
        for position in (200..49_000).step_by(211) {
            new[position] ^= 0x55;
        }
        new.splice(1_000..1_000, [1, 2, 3]);
        let mut remaining = 17;
        let spans = anchored_fallback(&old, &new, &mut remaining);
        assert_eq!(remaining, 0);
        assert_eq!(replay(&old, &new, &spans), new);
        assert!(spans.len() > 100);
        assert!(spans.iter().all(|(a, b)| a.len().max(b.len()) < 512));
    }
    #[test]
    fn large_unequal_core_modules_keep_changes_local_to_function_bodies() {
        fn unsigned(mut value: u32, bytes: &mut Vec<u8>) {
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                bytes.push(byte | if value != 0 { 0x80 } else { 0 });
                if value == 0 {
                    break;
                }
            }
        }
        fn signed(mut value: i32, bytes: &mut Vec<u8>) {
            loop {
                let byte = (value as u8) & 0x7f;
                value >>= 7;
                let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
                bytes.push(byte | if done { 0 } else { 0x80 });
                if done {
                    break;
                }
            }
        }
        fn core(functions: &[Vec<i32>]) -> Vec<u8> {
            let mut sections = vec![1, 4, 1, 0x60, 0, 0];
            let mut declarations = Vec::new();
            unsigned(functions.len() as u32, &mut declarations);
            declarations.resize(declarations.len() + functions.len(), 0);
            sections.push(3);
            unsigned(declarations.len() as u32, &mut sections);
            sections.extend_from_slice(&declarations);
            let mut code = Vec::new();
            unsigned(functions.len() as u32, &mut code);
            for values in functions {
                let mut body = vec![0];
                for value in values {
                    body.push(0x41);
                    signed(*value, &mut body);
                    body.push(0x1a);
                }
                body.push(0x0b);
                unsigned(body.len() as u32, &mut code);
                code.extend_from_slice(&body);
            }
            sections.push(10);
            unsigned(code.len() as u32, &mut sections);
            sections.extend_from_slice(&code);
            module(&sections)
        }
        let old_functions: Vec<Vec<i32>> = (0..64)
            .map(|function| (0..128).map(|i| function * 128 + i).collect())
            .collect();
        let mut new_functions = old_functions.clone();
        for function in &mut new_functions {
            for value in &mut function[..12] {
                *value += 500_000;
            }
        }
        new_functions[17].splice(57..57, [2_000_000, 2_000_001, 2_000_002]);
        new_functions[43].drain(88..91);
        let old = core(&old_functions);
        let new = core(&new_functions);
        assert_ne!(old.len(), new.len());
        let diff = compare(&old, &new).unwrap();
        assert!(!diff.exact_minimal);
        assert_eq!(diff.old.validation, "valid_with_all_known_features");
        assert_eq!(diff.new.validation, "valid_with_all_known_features");
        let spans: Vec<_> = diff
            .edits
            .iter()
            .map(|edit| (edit.old_span, edit.new_span))
            .collect();
        assert_eq!(replay(&old, &new, &spans), new);
        assert!(spans.len() > 100);
        assert!(spans.iter().all(|(a, b)| a.len().max(b.len()) < 1_024));
        let functions: BTreeSet<_> = diff
            .edits
            .iter()
            .flat_map(|edit| &edit.old_context)
            .filter(|context| context.path.starts_with("code[0]/function["))
            .map(|context| {
                context
                    .path
                    .split('/')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .collect();
        assert!(functions.len() >= 60);
    }
    #[test]
    fn raw_encoding_only_changes_are_visible() {
        let a = module(&[1, 1, 0]);
        let b = module(&[1, 2, 0x80, 0]);
        let diff = compare(&a, &b).unwrap();
        assert!(diff.changed);
        assert!(!diff.edits.is_empty());
        assert!(diff.semantic_changes.is_empty());
        assert_eq!(diff.old.validation, "valid_with_all_known_features");
        assert_eq!(diff.new.validation, "valid_with_all_known_features");
    }
    #[test]
    fn every_payload_byte_mutation_is_replayable_even_if_decoding_fails() {
        let bytes = module(&[
            1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 10, 4, 1, 2, 0, 0x0b, 0, 8, 1, b'x', 0, 1, 2, 3, 4, 5,
        ]);
        for index in 8..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 0x80;
            let diff = compare(&bytes, &changed).unwrap();
            assert!(diff.changed);
            let spans: Vec<_> = diff
                .edits
                .iter()
                .map(|edit| {
                    assert_eq!(
                        edit.old_hex,
                        hex(&bytes[edit.old_span.start..edit.old_span.end])
                    );
                    assert_eq!(
                        edit.new_hex,
                        hex(&changed[edit.new_span.start..edit.new_span.end])
                    );
                    (edit.old_span, edit.new_span)
                })
                .collect();
            assert_eq!(
                replay(&bytes, &changed, &spans),
                changed,
                "mutation at byte {index}"
            );
        }
    }
    #[test]
    fn unknown_section_and_unknown_instruction_preserve_later_frames() {
        let bytes = module(&[
            99, 2, 0xaa, 0xbb, 10, 9, 2, 3, 0, 0xff, 0x0b, 3, 0, 1, 0x0b, 0, 2, 1, b'x',
        ]);
        let parsed = inspect(&bytes).unwrap();
        assert_eq!(parsed.sections.len(), 3);
        assert!(parsed
            .diagnostics
            .iter()
            .any(|d| d.code == "unknown_section"));
        assert!(parsed
            .diagnostics
            .iter()
            .any(|d| d.code == "unknown_operator"));
        let regions = all_regions(&parsed);
        assert!(regions.contains_key("code[0]/function[0]/opaque"));
        assert!(regions.contains_key("code[0]/function[1]/operator[1]"));
        assert_eq!(
            regions["code[0]/function[0]/opaque"].span,
            Span::new(17, 19)
        );
    }
    #[test]
    fn gc_ref_and_exception_instructions_have_exact_offsets() {
        let bytes = module(&[
            1, 7, 2, 0x5f, 0, 0x60, 0, 1, 0x6f, 3, 2, 1, 1, 10, 14, 1, 12, 0, 0xfb, 1, 0, 0x1a,
            0xd0, 0x6f, 0x1a, 0xd0, 0x69, 0x0a, 0x0b,
        ]);
        let parsed = inspect(&bytes).unwrap();
        let regions = all_regions(&parsed);
        assert_eq!(regions["type[0]/type[0]"].feature.as_deref(), Some("gc"));
        assert_eq!(
            regions["code[0]/function[0]/operator[0]"].description,
            "StructNewDefault { struct_type_index: 0 }"
        );
        assert_eq!(regions["code[0]/function[0]/operator[0]"].span.len(), 3);
        assert_eq!(
            regions["code[0]/function[0]/operator[0]"]
                .feature
                .as_deref(),
            Some("gc")
        );
        assert_eq!(
            regions["code[0]/function[0]/operator[5]"]
                .feature
                .as_deref(),
            Some("exceptions")
        );
    }
    #[test]
    fn convention_errors_are_opaque_not_core_errors() {
        // Repeated function-name indices violate the recognized name convention.
        let bytes = module(&[
            0, 14, 4, b'n', b'a', b'm', b'e', 1, 7, 2, 0, 1, b'a', 0, 1, b'b',
        ]);
        let parsed = inspect(&bytes).unwrap();
        assert_eq!(parsed.sections[0].status, "opaque");
        assert!(parsed.diagnostics.iter().any(|d| d.code == "custom_opaque"));
        assert!(!parsed.diagnostics.iter().any(|d| d.code == "core_decode"));
    }
    #[test]
    fn valid_name_convention_gets_entry_locations() {
        let bytes = module(&[
            0, 13, 4, b'n', b'a', b'm', b'e', 1, 6, 1, 0, 3, b'f', b'o', b'o',
        ]);
        let parsed = inspect(&bytes).unwrap();
        let regions = all_regions(&parsed);
        assert_eq!(parsed.sections[0].status, "decoded");
        assert_eq!(
            regions["custom[0]/name/subsection[1]/index[0]"].description,
            "index=0 name=\"foo\""
        );
    }
    #[test]
    fn malformed_core_is_explicit_and_component_is_rejected() {
        let parsed = inspect(&module(&[1, 2, 1, 0xff, 0, 2, 1, b'x'])).unwrap();
        assert_eq!(parsed.sections[0].status, "malformed");
        assert_eq!(parsed.sections.len(), 2);
        assert!(parsed.diagnostics.iter().any(|d| d.code == "core_decode"));
        assert!(inspect(b"\0asm\x0d\0\x01\0").is_err());
        assert!(inspect(b"bad").is_err());
    }
    #[test]
    fn a_later_bad_type_preserves_completed_entries_and_their_changes() {
        let old = module(&[1, 6, 2, 0x60, 1, 0x7f, 0, 0xff]);
        let mut new = old.clone();
        new[13] = 0x7e;
        let diff = compare(&old, &new).unwrap();
        let regions = all_regions(&diff.old);
        assert_eq!(diff.old.sections[0].status, "malformed");
        assert_eq!(regions["type[0]/count"].span, Span::new(10, 11));
        assert_eq!(regions["type[0]/type[0]"].span, Span::new(11, 15));
        assert_eq!(regions["type[0]/undecoded"].span, Span::new(15, 16));
        assert!(diff.semantic_changes.iter().any(|change| {
            change.path == "type[0]/type[0]" && change.old.is_some() && change.new.is_some()
        }));
        assert!(diff.edits.iter().any(|edit| {
            edit.old_context
                .iter()
                .any(|context| context.path == "type[0]/type[0]")
        }));
    }
    #[test]
    fn a_bad_import_preserves_the_prefix_without_guessing_function_indices() {
        let bytes = module(&[
            1, 4, 1, 0x60, 0, 0, 2, 10, 2, 1, b'm', 1, b'f', 0, 0, 1, b'x', 0, 3, 2, 1, 0, 10, 4,
            1, 2, 0, 0x0b,
        ]);
        let parsed = inspect(&bytes).unwrap();
        let regions = all_regions(&parsed);
        assert!(regions["import[0]/group[0]/import[0]"]
            .description
            .contains("\"f\""));
        let prefix_end = regions["import[0]/group[0]"].span.end;
        assert_eq!(regions["import[0]/undecoded"].span.start, prefix_end);
        assert_eq!(regions["import[0]/undecoded"].span.end, 26);
        assert!(regions["code[0]/function[0]"]
            .description
            .contains("function_index=unknown"));
        assert!(regions.contains_key("code[0]/function[0]/operator[0]"));
    }
    #[test]
    fn truncated_later_body_keeps_earlier_body_and_next_section() {
        let bytes = module(&[10, 6, 2, 2, 0, 0x0b, 4, 0, 0, 2, 1, b'x']);
        let parsed = inspect(&bytes).unwrap();
        let regions = all_regions(&parsed);
        assert_eq!(parsed.sections.len(), 2);
        assert_eq!(parsed.sections[0].status, "malformed");
        assert_eq!(regions["code[0]/function[0]"].span, Span::new(11, 14));
        assert!(regions.contains_key("code[0]/function[0]/operator[0]"));
        assert_eq!(regions["code[0]/undecoded"].span, Span::new(14, 16));
        assert!(regions.contains_key("custom[0]/name"));
    }
    #[test]
    fn undecoded_suffix_includes_failed_leb_bytes_and_trailing_payload() {
        let bytes = module(&[8, 1, 0x80, 7, 2, 0, 0xff]);
        let parsed = inspect(&bytes).unwrap();
        let regions = all_regions(&parsed);
        assert_eq!(regions["start[0]/undecoded"].span, Span::new(10, 11));
        assert_eq!(&bytes[10..11], &[0x80]);
        assert_eq!(regions["export[0]/count"].span, Span::new(13, 14));
        let trailing = regions["export[0]/trailing_bytes"];
        assert_eq!(trailing.span, Span::new(14, 15));
        assert_eq!(&bytes[trailing.span.start..trailing.span.end], &[0xff]);
        assert_eq!(trailing.standard_support.status, "invalid_encoding");
        assert_eq!(trailing.standard_support.display, "binary");
        assert!(parsed
            .standard
            .evidence
            .iter()
            .any(|entry| entry.path == trailing.path
                && entry.raw_hex == "ff"
                && entry.status == "invalid_encoding"));
        assert!(!regions.keys().any(|path| path.contains("/operator[")));
        assert!(!parsed
            .diagnostics
            .iter()
            .any(|entry| entry.code == "unknown_operator"));
    }
    #[test]
    fn text_reports_escape_control_characters_from_custom_names() {
        let parsed = inspect(&module(&[0, 3, 1, b'\n', 0])).unwrap();
        let text = parsed.to_text();
        assert!(text.contains("custom:\\n"));
        assert!(!text.contains("custom:\n"));
    }
    #[test]
    fn target_feature_names_cannot_collide_with_metadata_paths() {
        fn feature_module(name: &[u8]) -> Vec<u8> {
            let mut payload = vec![15];
            payload.extend_from_slice(b"target_features");
            payload.extend_from_slice(&[1, b'+', name.len() as u8]);
            payload.extend_from_slice(name);
            let mut section = vec![0, payload.len() as u8];
            section.extend_from_slice(&payload);
            module(&section)
        }
        let old = feature_module(b"count");
        let new = feature_module(b"other");
        let parsed = inspect(&old).unwrap();
        let regions = all_regions(&parsed);
        assert_eq!(regions["custom[0]/target_features/count"].description, "1");
        assert_eq!(
            regions["custom[0]/target_features/feature[0]"].description,
            "+count"
        );
        assert_ne!(
            regions["custom[0]/target_features/count"].span,
            regions["custom[0]/target_features/feature[0]"].span
        );
        let diff = compare(&old, &new).unwrap();
        let changes: Vec<_> = diff
            .semantic_changes
            .iter()
            .filter(|change| change.path.starts_with("custom[0]/target_features/"))
            .collect();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "custom[0]/target_features/feature[0]");
        assert_eq!(changes[0].old.as_ref().unwrap().description, "+count");
        assert_eq!(changes[0].new.as_ref().unwrap().description, "+other");
    }
    #[test]
    fn different_unknown_section_ids_have_distinct_paths() {
        let parsed = inspect(&module(&[14, 1, 0xaa, 15, 1, 0xbb])).unwrap();
        let regions = all_regions(&parsed);
        assert!(regions.contains_key("unknown:14[0]/opaque"));
        assert!(regions.contains_key("unknown:15[0]/opaque"));
        assert_ne!(parsed.sections[0].path, parsed.sections[1].path);
    }
    #[test]
    fn context_index_queries_large_functions_without_rescanning_operators() {
        const OPERATORS: usize = 32_768;
        let end = 12 + 2 * OPERATORS;
        let mut function = Region::new("code[0]/function[0]", Span::new(10, end), "function");
        function.children = (0..OPERATORS)
            .map(|i| {
                Region::new(
                    format!("code[0]/function[0]/operator[{i}]"),
                    Span::new(12 + 2 * i, 14 + 2 * i),
                    "operator",
                )
            })
            .collect();
        let parsed = AuditModule {
            byte_len: end,
            format: "test".into(),
            validation: "test".into(),
            diagnostics: Vec::new(),
            standard: StandardReport::pending(Standard::AllKnown),
            sections: vec![AuditSection {
                ordinal: 0,
                id: 10,
                kind: "code".into(),
                path: "code[0]".into(),
                span: Span::new(8, end),
                header_span: Span::new(8, 10),
                payload_span: Span::new(10, end),
                status: "decoded".into(),
                regions: vec![function],
                standard_support: StandardSupport::default(),
            }],
        };
        let index = ContextIndex::new(&parsed);
        for i in (0..OPERATORS).step_by(31) {
            let span = Span::new(12 + 2 * i, 13 + 2 * i);
            let (_, visited) = index.overlapping(span);
            assert!(
                visited < 100,
                "point query visited {visited} nodes among {} records",
                index.records.len()
            );
            let contexts = index.context(span);
            assert_eq!(contexts.len(), 2);
            assert_eq!(
                contexts[0].path,
                format!("code[0]/function[0]/operator[{i}]")
            );
            assert_eq!(contexts[1].path, "code[0]");
        }
        let crossing = index.context(Span::new(13, 15));
        assert_eq!(crossing.len(), 3);
        assert!(crossing
            .iter()
            .any(|context| context.path.ends_with("operator[0]")));
        assert!(crossing
            .iter()
            .any(|context| context.path.ends_with("operator[1]")));
        assert_eq!(
            index.context(Span::new(11, 12))[0].path,
            "code[0]/function[0]"
        );
        assert_eq!(
            index.context(Span::new(14, 14))[0].path,
            "code[0]/function[0]/operator[1]"
        );
        assert_eq!(index.context(Span::new(0, 1))[0].path, "header");
        assert_eq!(index.context(Span::new(end, end))[0].path, "file_boundary");
    }
}
