//! Conservative, byte-preserving three-way merging of core Wasm modules.
//!
//! Indices are not identities. Concurrent edits to index-defining context are
//! rejected, and unknown instructions never become guessed merge boundaries.
//! A synthesized module is returned only after validation, without executing it.

use crate::audit::{self, AuditModule, AuditSection, Region, Span};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use wasmparser::{BinaryReader, Validator, WasmFeatures};

#[derive(Debug, Serialize)]
pub struct MergeEvidence {
    pub span: Span,
    pub hex: String,
}

#[derive(Debug, Serialize)]
pub struct MergeConflict {
    pub path: String,
    pub reason: String,
    pub base: MergeEvidence,
    pub ours: MergeEvidence,
    pub theirs: MergeEvidence,
}

#[derive(Debug, Serialize)]
pub struct MergeDecision {
    pub path: String,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct FramingFixup {
    pub path: String,
    /// Physical, half-open range in the resulting module.
    pub output_span: Span,
    pub hex: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct MergeReport {
    /// `clean` or `conflict`. A conflict never exposes a partial module.
    pub status: String,
    #[serde(skip)]
    pub bytes: Option<Vec<u8>>,
    pub conflicts: Vec<MergeConflict>,
    pub decisions: Vec<MergeDecision>,
    pub framing_fixups: Vec<FramingFixup>,
    pub validation: String,
}

impl MergeReport {
    fn new() -> Self {
        Self {
            status: "conflict".into(),
            bytes: None,
            conflicts: Vec::new(),
            decisions: Vec::new(),
            framing_fixups: Vec::new(),
            validation: "not_synthesized".into(),
        }
    }

    fn decision(&mut self, path: &str, source: &str, reason: &str) {
        self.decisions.push(MergeDecision {
            path: path.into(),
            source: source.into(),
            reason: reason.into(),
        });
    }

    fn conflict(&mut self, path: &str, reason: impl Into<String>, evidence: [(&[u8], Span); 3]) {
        let [base, ours, theirs] = evidence.map(|(bytes, span)| MergeEvidence {
            span,
            hex: hex(&bytes[span.start..span.end]),
        });
        self.conflicts.push(MergeConflict {
            path: path.into(),
            reason: reason.into(),
            base,
            ours,
            theirs,
        });
    }
}

fn span(start: usize, end: usize) -> Span {
    Span { start, end }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn raw(bytes: &[u8], range: Span) -> &[u8] {
    &bytes[range.start..range.end]
}

fn whole_evidence(inputs: [&[u8]; 3]) -> [(&[u8], Span); 3] {
    inputs.map(|bytes| (bytes, span(0, bytes.len())))
}

fn section_evidence<'a>(
    inputs: [&'a [u8]; 3],
    sections: [&AuditSection; 3],
) -> [(&'a [u8], Span); 3] {
    [
        (inputs[0], sections[0].span),
        (inputs[1], sections[1].span),
        (inputs[2], sections[2].span),
    ]
}

/// Return the source chosen by exact three-way equality, or an overlap.
fn choice<T: PartialEq>(base: T, ours: T, theirs: T) -> Option<usize> {
    if ours == theirs || base == theirs {
        Some(1)
    } else if base == ours {
        Some(2)
    } else {
        None
    }
}

fn source(index: usize) -> &'static str {
    ["base", "ours", "theirs"][index]
}

fn context_section(id: u8) -> bool {
    matches!(id, 1 | 2 | 3 | 4 | 5 | 6 | 9 | 11 | 12 | 13)
}

fn custom_key(bytes: &[u8], section: &AuditSection) -> Option<Vec<u8>> {
    let mut reader =
        BinaryReader::new(raw(bytes, section.payload_span), section.payload_span.start);
    // The custom convention itself can remain opaque. Only the binary name
    // string establishes an existing section's position in the layout.
    let name = reader.read_string().ok()?;
    Some(name.as_bytes().to_vec())
}

fn framed(module: &AuditModule, bytes: &[u8]) -> bool {
    let mut end = 8;
    for section in &module.sections {
        if section.span.start != end
            || section.header_span.start != section.span.start
            || section.header_span.end != section.payload_span.start
            || section.payload_span.end != section.span.end
            || section.header_span.end <= section.span.start + 1
        {
            return false;
        }
        let mut reader = BinaryReader::new(
            &bytes[section.span.start + 1..section.header_span.end],
            section.span.start + 1,
        );
        if reader.read_var_u32().ok().map(|size| size as usize)
            != Some(section.payload_span.end - section.payload_span.start)
            || !reader.eof()
        {
            return false;
        }
        end = section.span.end;
    }
    end == bytes.len()
}

/// Merge raw core modules. Exact whole-file choices preserve all input bytes,
/// including unsupported features and noncanonical but legal LEB encodings.
/// Concurrent synthesis deliberately uses a narrower, validated subset.
pub fn merge(base: &[u8], ours: &[u8], theirs: &[u8]) -> Result<MergeReport, String> {
    let inputs = [base, ours, theirs];
    for (index, bytes) in inputs.iter().enumerate() {
        if bytes.len() < 8 || bytes[..8] != *b"\0asm\x01\0\0\0" {
            return Err(format!(
                "{}: expected core WebAssembly version 1 header (Component Model excluded)",
                source(index)
            ));
        }
    }
    let mut report = MergeReport::new();
    if let Some(index) = choice(base, ours, theirs) {
        let selected = inputs[index];
        let inspected = audit::inspect(selected)?;
        report.validation = inspected.validation;
        report.decision(
            "module",
            source(index),
            "exact whole-module three-way selection; every selected byte is preserved; validation failure or unsupported features do not prevent this non-synthesized choice",
        );
        report.status = "clean".into();
        report.bytes = Some(selected.to_vec());
        return Ok(report);
    }

    let modules = [
        audit::inspect(base)?,
        audit::inspect(ours)?,
        audit::inspect(theirs)?,
    ];
    if modules
        .iter()
        .zip(inputs)
        .any(|(module, bytes)| !framed(module, bytes))
    {
        report.conflict(
            "module/framing",
            "concurrent edits require complete, trustworthy section framing",
            whole_evidence(inputs),
        );
        return Ok(report);
    }
    let count = modules[0].sections.len();
    if modules.iter().any(|module| module.sections.len() != count) {
        report.conflict(
            "module/layout",
            "concurrent section additions or removals require explicit resolution",
            whole_evidence(inputs),
        );
        return Ok(report);
    }

    // Never align repeated or anonymous custom sections by a guessed identity.
    let mut keys = BTreeSet::new();
    let mut ambiguous_custom = BTreeSet::new();
    for section in &modules[0].sections {
        if section.id == 0 {
            match custom_key(base, section) {
                Some(key) if keys.insert(key.clone()) => {}
                Some(key) => {
                    ambiguous_custom.insert(Some(key));
                }
                None => {
                    ambiguous_custom.insert(None);
                }
            }
        }
    }
    for index in 0..count {
        let sections = modules.each_ref().map(|module| &module.sections[index]);
        if sections.iter().any(|section| section.id != sections[0].id) {
            report.conflict(
                "module/layout",
                "concurrent section reordering or replacement is not aligned by position",
                section_evidence(inputs, sections),
            );
            continue;
        }
        let section_bytes = [
            raw(base, sections[0].span),
            raw(ours, sections[1].span),
            raw(theirs, sections[2].span),
        ];
        let changed = section_bytes[0] != section_bytes[1] || section_bytes[0] != section_bytes[2];
        if sections[0].id == 0 {
            let names = [
                custom_key(base, sections[0]),
                custom_key(ours, sections[1]),
                custom_key(theirs, sections[2]),
            ];
            if names[0] != names[1]
                || names[0] != names[2]
                || (changed && ambiguous_custom.contains(&names[0]))
            {
                report.conflict(
                    &sections[0].path,
                    "custom section identity changed, is duplicated, or cannot be decoded; no section correspondence is guessed",
                    section_evidence(inputs, sections),
                );
            }
        } else if context_section(sections[0].id) && changed {
            report.conflict(
                &sections[0].path,
                "index-defining or initialization context changed during concurrent edits; combining it could silently rebind references",
                section_evidence(inputs, sections),
            );
        } else if sections[0].id > 13 && changed {
            report.conflict(
                &sections[0].path,
                "unknown section changed during concurrent edits; its reference and framing contracts are unknown",
                section_evidence(inputs, sections),
            );
        }
    }
    if !report.conflicts.is_empty() {
        return Ok(report);
    }

    let mut output = base[..8].to_vec();
    for index in 0..count {
        let sections = modules.each_ref().map(|module| &module.sections[index]);
        let section_bytes = [
            raw(base, sections[0].span),
            raw(ours, sections[1].span),
            raw(theirs, sections[2].span),
        ];
        if let Some(selected) = choice(section_bytes[0], section_bytes[1], section_bytes[2]) {
            output.extend_from_slice(section_bytes[selected]);
            if section_bytes[0] != section_bytes[selected] {
                report.decision(
                    &sections[0].path,
                    source(selected),
                    "exact existing section selected atomically",
                );
            }
        } else if sections[0].id == 10 {
            if let Some(mut merged) = merge_code(inputs, sections, &mut report) {
                let offset = output.len();
                for fixup in &mut merged.fixups {
                    fixup.output_span.start += offset;
                    fixup.output_span.end += offset;
                }
                report.framing_fixups.extend(merged.fixups);
                output.extend_from_slice(&merged.bytes);
            }
        } else {
            report.conflict(
                &sections[0].path,
                "both sides changed the same atomic section differently",
                section_evidence(inputs, sections),
            );
        }
    }
    if !report.conflicts.is_empty() {
        // Any tentative offsets after a conflicting section would refer to a
        // partial output. Expose only physical evidence in the three inputs.
        report.framing_fixups.clear();
        return Ok(report);
    }
    match Validator::new_with_features(WasmFeatures::all()).validate_all(&output) {
        Ok(_) => {
            report.validation = "valid_with_all_known_features".into();
            report.status = "clean".into();
            report.bytes = Some(output);
        }
        Err(error) => {
            report.validation = "failed_or_unsupported".into();
            report.framing_fixups.clear();
            report.conflict(
                "module/validation",
                format!(
                    "synthesized module failed validation: {error}; no output module is returned"
                ),
                whole_evidence(inputs),
            );
        }
    }
    Ok(report)
}

#[derive(Clone, Copy)]
struct Body {
    span: Span,
    size: Span,
    payload: Span,
}

struct Code {
    count: Span,
    bodies: Vec<Body>,
}

fn code_frames(bytes: &[u8], section: &AuditSection) -> Result<Code, String> {
    let mut reader =
        BinaryReader::new(raw(bytes, section.payload_span), section.payload_span.start);
    let count_start = reader.original_position();
    let count = reader.read_var_u32().map_err(|error| error.to_string())?;
    let count_span = span(count_start, reader.original_position());
    // Each body needs at least one size byte. Bound allocation by actual input.
    if count as usize > reader.bytes_remaining() {
        return Err("code count exceeds available body frames".into());
    }
    let mut bodies = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let start = reader.original_position();
        let len = reader.read_var_u32().map_err(|error| error.to_string())? as usize;
        let payload_start = reader.original_position();
        reader.read_bytes(len).map_err(|error| error.to_string())?;
        let end = reader.original_position();
        bodies.push(Body {
            span: span(start, end),
            size: span(start, payload_start),
            payload: span(payload_start, end),
        });
    }
    if !reader.eof() {
        return Err("trailing bytes after code bodies".into());
    }
    Ok(Code {
        count: count_span,
        bodies,
    })
}

struct Built {
    bytes: Vec<u8>,
    fixups: Vec<FramingFixup>,
}

fn choose_width(
    inputs: [&[u8]; 3],
    fields: [Span; 3],
    path: &str,
    report: &mut MergeReport,
) -> Option<usize> {
    let widths = fields.map(|field| field.end - field.start);
    if let Some(index) = choice(widths[0], widths[1], widths[2]) {
        Some(widths[index])
    } else {
        report.conflict(
            path,
            "both sides changed this LEB framing width differently; choosing an encoding would discard a byte-level edit",
            [
                (inputs[0], fields[0]),
                (inputs[1], fields[1]),
                (inputs[2], fields[2]),
            ],
        );
        None
    }
}

fn leb(value: usize, width: usize) -> Result<Vec<u8>, String> {
    let mut value = u32::try_from(value).map_err(|_| "merged framing exceeds u32 length")?;
    let minimum = ((32 - value.leading_zeros()).max(1) as usize).div_ceil(7);
    let width = width.max(minimum);
    if width > 5 {
        return Err("merged framing requires an illegal LEB width".into());
    }
    let mut out = Vec::with_capacity(width);
    for index in 0..width {
        let more = index + 1 != width;
        out.push((value as u8 & 0x7f) | if more { 0x80 } else { 0 });
        value >>= 7;
    }
    Ok(out)
}

fn relocated_bodies(
    inputs: [&[u8]; 3],
    codes: [&Code; 3],
    path: &str,
    report: &mut MergeReport,
) -> bool {
    // A raw index is insufficient correspondence when a distinctive body has
    // visibly moved. Index payloads rather than framing widths, and mark every
    // repeated base payload ambiguous instead of selecting a duplicate.
    let mut unique = BTreeMap::<&[u8], Option<usize>>::new();
    for (index, body) in codes[0].bodies.iter().enumerate() {
        unique
            .entry(raw(inputs[0], body.payload))
            .and_modify(|source| *source = None)
            .or_insert(Some(index));
    }
    let mut seen = BTreeSet::new();
    let mut found = false;
    for (branch, code) in codes.iter().enumerate().skip(1) {
        for (destination, body) in code.bodies.iter().enumerate() {
            let payload = raw(inputs[branch], body.payload);
            if payload == raw(inputs[0], codes[0].bodies[destination].payload) {
                continue;
            }
            let Some(Some(origin)) = unique.get(payload) else {
                continue;
            };
            let origin = *origin;
            if origin == destination
                || raw(inputs[branch], code.bodies[origin].payload)
                    == raw(inputs[0], codes[0].bodies[origin].payload)
                || !seen.insert((branch, origin.min(destination), origin.max(destination)))
            {
                continue;
            }
            found = true;
            let reason = format!(
                "{} function[{destination}] exactly matches unique base function[{origin}], whose original slot also changed; recognizable body relocation makes positional correspondence ambiguous",
                source(branch)
            );
            for (index, role) in [(destination, "destination"), (origin, "source")] {
                report.conflict(
                    &format!("{path}/function[{index}]/relocation_{role}"),
                    &reason,
                    [
                        (inputs[0], codes[0].bodies[index].span),
                        (inputs[1], codes[1].bodies[index].span),
                        (inputs[2], codes[2].bodies[index].span),
                    ],
                );
            }
        }
    }
    found
}

fn merge_code(
    inputs: [&[u8]; 3],
    sections: [&AuditSection; 3],
    report: &mut MergeReport,
) -> Option<Built> {
    let parsed = [
        code_frames(inputs[0], sections[0]),
        code_frames(inputs[1], sections[1]),
        code_frames(inputs[2], sections[2]),
    ];
    if let Some(error) = parsed.iter().find_map(|code| code.as_ref().err()) {
        report.conflict(
            &sections[0].path,
            format!("code body framing is not trustworthy: {error}"),
            section_evidence(inputs, sections),
        );
        return None;
    }
    let [base, ours, theirs] = parsed.map(Result::unwrap);
    let codes = [&base, &ours, &theirs];
    let count = base.bodies.len();
    if codes.iter().any(|code| code.bodies.len() != count) {
        report.conflict(
            &sections[0].path,
            "defined function count changed; positional function identity is not assumed",
            section_evidence(inputs, sections),
        );
        return None;
    }
    if relocated_bodies(inputs, codes, &sections[0].path, report) {
        return None;
    }
    let counts = [
        raw(inputs[0], base.count),
        raw(inputs[1], ours.count),
        raw(inputs[2], theirs.count),
    ];
    let Some(count_source) = choice(counts[0], counts[1], counts[2]) else {
        report.conflict(
            &format!("{}/count", sections[0].path),
            "both sides changed the raw function count encoding differently",
            [
                (inputs[0], base.count),
                (inputs[1], ours.count),
                (inputs[2], theirs.count),
            ],
        );
        return None;
    };
    let start_conflicts = report.conflicts.len();
    let mut payload = counts[count_source].to_vec();
    let mut fixups = Vec::new();
    for index in 0..count {
        let bodies = codes.map(|code| code.bodies[index]);
        let body_bytes = [
            raw(inputs[0], bodies[0].span),
            raw(inputs[1], bodies[1].span),
            raw(inputs[2], bodies[2].span),
        ];
        let path = format!("{}/function[{index}]", sections[0].path);
        if let Some(selected) = choice(body_bytes[0], body_bytes[1], body_bytes[2]) {
            payload.extend_from_slice(body_bytes[selected]);
            if body_bytes[0] != body_bytes[selected] {
                report.decision(
                    &path,
                    source(selected),
                    "exact framed function body selected",
                );
            }
            continue;
        }
        if let Some(mut merged) = merge_body(inputs, sections, bodies, index, &path, report) {
            let offset = payload.len();
            for fixup in &mut merged.fixups {
                fixup.output_span.start += offset;
                fixup.output_span.end += offset;
            }
            fixups.extend(merged.fixups);
            payload.extend_from_slice(&merged.bytes);
        }
    }
    if report.conflicts.len() != start_conflicts {
        return None;
    }
    let fields = sections.map(|section| span(section.span.start + 1, section.payload_span.start));
    let width = choose_width(
        inputs,
        fields,
        &format!("{}/size", sections[0].path),
        report,
    )?;
    let size = match leb(payload.len(), width) {
        Ok(size) => size,
        Err(reason) => {
            report.conflict(
                &sections[0].path,
                reason,
                section_evidence(inputs, sections),
            );
            return None;
        }
    };
    let offset = 1 + size.len();
    for fixup in &mut fixups {
        fixup.output_span.start += offset;
        fixup.output_span.end += offset;
    }
    fixups.insert(0, FramingFixup {
        path: format!("{}/size", sections[0].path),
        output_span: span(1, offset),
        hex: hex(&size),
        reason: format!("recomputed enclosing payload length {}; retained three-way LEB width {width} where sufficient", payload.len()),
    });
    let mut bytes = vec![10];
    bytes.extend_from_slice(&size);
    bytes.extend_from_slice(&payload);
    Some(Built { bytes, fixups })
}

fn operator(region: &Region) -> bool {
    region
        .path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.starts_with("operator["))
}

fn atoms(section: &AuditSection, body: Body, index: usize) -> Option<(Span, Vec<&Region>)> {
    let region = section.regions.get(index + 1)?;
    if region.span != body.span {
        return None;
    }
    let mut result = Vec::new();
    let mut cursor = body.payload.start;
    let mut locals_end = None;
    for child in &region.children {
        if child.path.ends_with("/body_size") {
            continue;
        }
        if child.span.start != cursor || child.span.end < child.span.start {
            return None;
        }
        if operator(child) {
            locals_end.get_or_insert(cursor);
            if child.feature.as_deref() == Some("unknown") || child.span.start == child.span.end {
                return None;
            }
            result.push(child);
        } else if locals_end.is_some()
            || !(child.path.ends_with("/locals_count") || child.path.contains("/local_group["))
        {
            return None;
        }
        cursor = child.span.end;
    }
    if cursor != body.payload.end || result.is_empty() {
        return None;
    }
    Some((span(body.payload.start, locals_end?), result))
}

fn control(region: &Region) -> bool {
    let name = region.description.split([' ', '{']).next().unwrap_or("");
    matches!(
        name,
        "Block" | "Loop" | "If" | "Else" | "End" | "Unreachable"
    ) || [
        "Br", "Return", "Call", "Try", "Catch", "Throw", "Rethrow", "Delegate", "Resume", "Switch",
        "Cont", "Suspend",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn unmodeled_control(region: &Region) -> bool {
    let name = region.description.split([' ', '{']).next().unwrap_or("");
    region
        .feature
        .as_deref()
        .is_some_and(|feature| feature.starts_with("stack_switching"))
        || ["Resume", "Switch", "Cont", "Suspend"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn relocated_atoms(
    inputs: [&[u8]; 3],
    atoms: [&[&Region]; 3],
    path: &str,
    report: &mut MergeReport,
) -> bool {
    let mut seen = BTreeSet::new();
    let mut found = false;
    for (branch, branch_atoms) in atoms.iter().enumerate().skip(1) {
        // Only changed sources participate. An unchanged duplicate or a copy
        // whose original stays intact is not evidence of a relocation.
        let mut changed_sources = BTreeMap::<&[u8], usize>::new();
        for (index, region) in branch_atoms.iter().enumerate() {
            let before = raw(inputs[0], atoms[0][index].span);
            if before != raw(inputs[branch], region.span) {
                changed_sources.entry(before).or_insert(index);
            }
        }
        for (destination, region) in branch_atoms.iter().enumerate() {
            let after = raw(inputs[branch], region.span);
            if after == raw(inputs[0], atoms[0][destination].span) {
                continue;
            }
            let Some(&origin) = changed_sources.get(after) else {
                continue;
            };
            if !seen.insert((branch, origin.min(destination), origin.max(destination))) {
                continue;
            }
            found = true;
            let reason = format!(
                "{} operator[{destination}] matches base operator[{origin}] at another changed position; possible instruction atom relocation makes positional correspondence ambiguous",
                source(branch)
            );
            for (index, role) in [(destination, "destination"), (origin, "source")] {
                report.conflict(
                    &format!("{path}/operator[{index}]/relocation_{role}"),
                    &reason,
                    [
                        (inputs[0], atoms[0][index].span),
                        (inputs[1], atoms[1][index].span),
                        (inputs[2], atoms[2][index].span),
                    ],
                );
            }
        }
    }
    found
}

fn merge_body(
    inputs: [&[u8]; 3],
    sections: [&AuditSection; 3],
    bodies: [Body; 3],
    index: usize,
    path: &str,
    report: &mut MergeReport,
) -> Option<Built> {
    let evidence = [
        (inputs[0], bodies[0].span),
        (inputs[1], bodies[1].span),
        (inputs[2], bodies[2].span),
    ];
    let parsed = [
        atoms(sections[0], bodies[0], index),
        atoms(sections[1], bodies[1], index),
        atoms(sections[2], bodies[2], index),
    ];
    if parsed.iter().any(Option::is_none) {
        report.conflict(path, "concurrently edited body has unknown or malformed instructions or locals; no boundaries are guessed", evidence);
        return None;
    }
    let [(base_locals, base), (ours_locals, ours), (theirs_locals, theirs)] =
        parsed.map(Option::unwrap);
    if base
        .iter()
        .chain(&ours)
        .chain(&theirs)
        .any(|region| unmodeled_control(region))
    {
        report.conflict(
            path,
            "concurrently edited body contains stack-switching control whose structure is not modeled by this merger",
            evidence,
        );
        return None;
    }
    let locals = [
        raw(inputs[0], base_locals),
        raw(inputs[1], ours_locals),
        raw(inputs[2], theirs_locals),
    ];
    if locals[0] != locals[1] || locals[0] != locals[2] {
        report.conflict(
            path,
            "concurrent body edits require byte-identical local declarations",
            evidence,
        );
        return None;
    }
    if base.len() != ours.len() || base.len() != theirs.len() {
        report.conflict(path, "instruction counts differ; concurrent insertion or deletion is not aligned by position", evidence);
        return None;
    }
    if relocated_atoms(inputs, [&base, &ours, &theirs], path, report) {
        return None;
    }
    let start_conflicts = report.conflicts.len();
    let mut payload = locals[0].to_vec();
    for op_index in 0..base.len() {
        let regions = [base[op_index], ours[op_index], theirs[op_index]];
        let bytes = [
            raw(inputs[0], regions[0].span),
            raw(inputs[1], regions[1].span),
            raw(inputs[2], regions[2].span),
        ];
        let op_path = format!("{path}/operator[{op_index}]");
        let op_evidence = [
            (inputs[0], regions[0].span),
            (inputs[1], regions[1].span),
            (inputs[2], regions[2].span),
        ];
        if regions.iter().any(|region| control(region))
            && (bytes[0] != bytes[1] || bytes[0] != bytes[2])
        {
            report.conflict(&op_path, "structured control flow, call/branch targets, or control encoding changed; the control skeleton must be byte-identical", op_evidence);
            continue;
        }
        if let Some(selected) = choice(bytes[0], bytes[1], bytes[2]) {
            payload.extend_from_slice(bytes[selected]);
            if bytes[0] != bytes[selected] {
                report.decision(
                    &op_path,
                    source(selected),
                    "complete decoded instruction atom selected, including every immediate byte",
                );
            }
        } else {
            report.conflict(
                &op_path,
                "both sides changed the same complete instruction atom differently",
                op_evidence,
            );
        }
    }
    if report.conflicts.len() != start_conflicts {
        return None;
    }
    let width = choose_width(
        inputs,
        bodies.map(|body| body.size),
        &format!("{path}/body_size"),
        report,
    )?;
    let size = match leb(payload.len(), width) {
        Ok(size) => size,
        Err(reason) => {
            report.conflict(path, reason, evidence);
            return None;
        }
    };
    let fixups = vec![FramingFixup {
        path: format!("{path}/body_size"),
        output_span: span(0, size.len()),
        hex: hex(&size),
        reason: format!(
            "recomputed body length {}; retained three-way LEB width {width} where sufficient",
            payload.len()
        ),
    }];
    let mut bytes = size;
    bytes.extend_from_slice(&payload);
    Some(Built { bytes, fixups })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wat(source: &str) -> Vec<u8> {
        wat::parse_str(source).unwrap()
    }

    fn clean(base: &[u8], ours: &[u8], theirs: &[u8]) -> Vec<u8> {
        let report = merge(base, ours, theirs).unwrap();
        assert_eq!(report.status, "clean", "{report:?}");
        assert!(report.conflicts.is_empty());
        report.bytes.unwrap()
    }

    fn conflicted(base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeReport {
        let report = merge(base, ours, theirs).unwrap();
        assert_eq!(report.status, "conflict", "{report:?}");
        assert!(report.bytes.is_none());
        assert!(!report.conflicts.is_empty());
        for conflict in &report.conflicts {
            for (bytes, evidence) in [base, ours, theirs].into_iter().zip([
                &conflict.base,
                &conflict.ours,
                &conflict.theirs,
            ]) {
                assert_eq!(evidence.hex, hex(raw(bytes, evidence.span)));
            }
        }
        report
    }

    #[test]
    fn independent_functions_preserve_exact_bodies() {
        let base = wat("(module (func i32.const 1 drop) (func i32.const 2 drop))");
        let ours = wat("(module (func i32.const 1000 drop) (func i32.const 2 drop))");
        let theirs = wat("(module (func i32.const 1 drop) (func i32.const 200000 drop))");
        let expected = wat("(module (func i32.const 1000 drop) (func i32.const 200000 drop))");
        assert_eq!(clean(&base, &ours, &theirs), expected);
    }

    #[test]
    fn exact_body_relocation_refuses_positional_instruction_merge() {
        let base = wat("(module (func i32.const 1 drop i32.const 2 drop) (func i32.const 3 drop i32.const 2 drop))");
        let ours = wat("(module (func i32.const 3 drop i32.const 2 drop) (func i32.const 1 drop i32.const 2 drop))");
        let theirs = wat("(module (func i32.const 1 drop i32.const 4 drop) (func i32.const 3 drop i32.const 2 drop))");
        for (left, right) in [(&ours, &theirs), (&theirs, &ours)] {
            let report = conflicted(&base, left, right);
            assert_eq!(report.conflicts.len(), 2);
            assert!(report.conflicts[0].path.ends_with("relocation_destination"));
            assert!(report.conflicts[1].path.ends_with("relocation_source"));
            assert!(report.conflicts[0].reason.contains("body relocation"));
        }
        assert_eq!(clean(&base, &ours, &base), ours);
        let widened = widen_code_lengths(&ours, 3);
        assert!(conflicted(&base, &widened, &theirs).conflicts[0]
            .reason
            .contains("body relocation"));
    }

    #[test]
    fn body_copy_with_unchanged_origin_is_not_called_a_relocation() {
        let base = wat("(module (func i32.const 1 drop) (func i32.const 2 drop))");
        let ours = wat("(module (func i32.const 2 drop) (func i32.const 2 drop))");
        let theirs = wat("(module (func i32.const 1 drop) (func i32.const 3 drop))");
        let expected = wat("(module (func i32.const 2 drop) (func i32.const 3 drop))");
        assert_eq!(clean(&base, &ours, &theirs), expected);
    }

    #[test]
    fn duplicate_base_bodies_do_not_prove_relocation() {
        let base = wat("(module (func i32.const 1 drop) (func i32.const 2 drop) (func i32.const 2 drop) (func i32.const 9 drop))");
        let ours = wat("(module (func i32.const 2 drop) (func i32.const 3 drop) (func i32.const 2 drop) (func i32.const 9 drop))");
        let theirs = wat("(module (func i32.const 1 drop) (func i32.const 2 drop) (func i32.const 2 drop) (func i32.const 10 drop))");
        let expected = wat("(module (func i32.const 2 drop) (func i32.const 3 drop) (func i32.const 2 drop) (func i32.const 10 drop))");
        assert_eq!(clean(&base, &ours, &theirs), expected);
    }

    #[test]
    fn disjoint_instruction_atoms_with_different_byte_lengths() {
        let base = wat("(module (func i32.const 1 drop i32.const 2 drop))");
        let ours = wat("(module (func i32.const 100000 drop i32.const 2 drop))");
        let theirs = wat("(module (func i32.const 1 drop i32.const 2000 drop))");
        let expected = wat("(module (func i32.const 100000 drop i32.const 2000 drop))");
        let report = merge(&base, &ours, &theirs).unwrap();
        assert_eq!(
            report.bytes.as_deref(),
            Some(expected.as_slice()),
            "{report:?}"
        );
        assert_eq!(report.framing_fixups.len(), 2);
        for fixup in &report.framing_fixups {
            assert_eq!(
                fixup.hex,
                hex(raw(report.bytes.as_ref().unwrap(), fixup.output_span))
            );
        }
    }

    #[test]
    fn instruction_run_relocation_refuses_positional_atom_merge() {
        let base = wat(
            "(module (func i32.const 1 drop i32.const 2 drop i32.const 3 drop i32.const 2 drop))",
        );
        let ours = wat(
            "(module (func i32.const 3 drop i32.const 2 drop i32.const 1 drop i32.const 2 drop))",
        );
        let theirs = wat(
            "(module (func i32.const 1 drop i32.const 4 drop i32.const 3 drop i32.const 2 drop))",
        );
        for (left, right) in [(&ours, &theirs), (&theirs, &ours)] {
            let report = conflicted(&base, left, right);
            assert_eq!(report.conflicts.len(), 2);
            assert!(report.conflicts[0].path.ends_with("relocation_destination"));
            assert!(report.conflicts[1].path.ends_with("relocation_source"));
            assert!(report.conflicts[0]
                .reason
                .contains("possible instruction atom relocation"));
        }
        assert_eq!(clean(&base, &ours, &base), ours);
    }

    #[test]
    fn copied_atom_with_unchanged_source_is_not_called_a_relocation() {
        let base = wat("(module (func i32.const 1 drop i32.const 2 drop i32.const 3 drop))");
        let ours = wat("(module (func i32.const 2 drop i32.const 2 drop i32.const 3 drop))");
        let theirs = wat("(module (func i32.const 1 drop i32.const 2 drop i32.const 4 drop))");
        let expected = wat("(module (func i32.const 2 drop i32.const 2 drop i32.const 4 drop))");
        assert_eq!(clean(&base, &ours, &theirs), expected);
    }

    #[test]
    fn immediate_bytes_cannot_be_merged_inside_one_instruction() {
        let base = wat("(module (func i32.const 128 drop))");
        let ours = wat("(module (func i32.const 129 drop))");
        let theirs = wat("(module (func i32.const 256 drop))");
        let report = conflicted(&base, &ours, &theirs);
        assert_eq!(report.conflicts.len(), 1);
        assert!(report.conflicts[0].path.ends_with("operator[0]"));
        assert_eq!(report.conflicts[0].base.hex, "418001");
    }

    #[test]
    fn unknown_opcode_never_creates_guessed_atoms() {
        let base = wat("(module (func i32.const 1 drop i32.const 2 drop))");
        let mut ours = wat("(module (func i32.const 3 drop i32.const 2 drop))");
        let code = audit::inspect(&ours)
            .unwrap()
            .sections
            .into_iter()
            .find(|section| section.id == 10)
            .unwrap();
        let offset = code.regions[1]
            .children
            .iter()
            .find(|region| operator(region))
            .unwrap()
            .span
            .start;
        ours[offset] = 0xff;
        let theirs = wat("(module (func i32.const 1 drop i32.const 4 drop))");
        let report = conflicted(&base, &ours, &theirs);
        assert!(report.conflicts[0].reason.contains("unknown or malformed"));
        assert_eq!(clean(&base, &ours, &base), ours);
        assert_eq!(clean(&base, &ours, &ours), ours);
    }

    #[test]
    fn import_renumbering_cannot_rebind_other_branch_edits() {
        let base = wat("(module (import \"host\" \"a\" (func)) (func call 0))");
        let ours = wat(
            "(module (import \"host\" \"b\" (func)) (import \"host\" \"a\" (func)) (func call 1))",
        );
        let theirs = wat("(module (import \"host\" \"a\" (func)) (func nop call 0))");
        let report = conflicted(&base, &ours, &theirs);
        assert!(report
            .conflicts
            .iter()
            .any(|conflict| conflict.path == "import[0]"));
    }

    fn append_custom(bytes: &mut Vec<u8>, name: &str, payload: &[u8]) {
        let mut data = leb(name.len(), 1).unwrap();
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(payload);
        bytes.push(0);
        bytes.extend(leb(data.len(), 1).unwrap());
        bytes.extend(data);
    }

    #[test]
    fn malformed_custom_convention_is_preserved_as_one_atomic_section() {
        let mut base = wat("(module (func i32.const 1 drop))");
        append_custom(&mut base, "name", &[1, 0x80]);
        let mut ours = wat("(module (func i32.const 1 drop))");
        append_custom(&mut ours, "name", &[1, 0x81]);
        let mut theirs = wat("(module (func i32.const 2 drop))");
        append_custom(&mut theirs, "name", &[1, 0x80]);
        let mut expected = wat("(module (func i32.const 2 drop))");
        append_custom(&mut expected, "name", &[1, 0x81]);
        assert_eq!(clean(&base, &ours, &theirs), expected);
    }

    fn widen_code_lengths(bytes: &[u8], width: usize) -> Vec<u8> {
        let module = audit::inspect(bytes).unwrap();
        let code = module
            .sections
            .iter()
            .find(|section| section.id == 10)
            .unwrap();
        let frames = code_frames(bytes, code).unwrap();
        let mut payload = raw(bytes, frames.count).to_vec();
        for body in frames.bodies {
            payload.extend(leb(body.payload.end - body.payload.start, width).unwrap());
            payload.extend_from_slice(raw(bytes, body.payload));
        }
        let mut out = bytes[..code.span.start].to_vec();
        out.push(10);
        out.extend(leb(payload.len(), width).unwrap());
        out.extend(payload);
        out.extend_from_slice(&bytes[code.span.end..]);
        out
    }

    #[test]
    fn noncanonical_length_widths_are_preserved_for_synthesis() {
        let base = widen_code_lengths(&wat("(module (func i32.const 1 drop i32.const 2 drop))"), 3);
        let ours = widen_code_lengths(
            &wat("(module (func i32.const 1000 drop i32.const 2 drop))"),
            3,
        );
        let theirs = widen_code_lengths(
            &wat("(module (func i32.const 1 drop i32.const 2000 drop))"),
            3,
        );
        let expected = widen_code_lengths(
            &wat("(module (func i32.const 1000 drop i32.const 2000 drop))"),
            3,
        );
        assert_eq!(clean(&base, &ours, &theirs), expected);
    }

    #[test]
    fn conflicting_width_edits_are_visible() {
        let base = wat("(module (func i32.const 1 drop i32.const 2 drop))");
        let ours = widen_code_lengths(&wat("(module (func i32.const 3 drop i32.const 2 drop))"), 2);
        let theirs =
            widen_code_lengths(&wat("(module (func i32.const 1 drop i32.const 4 drop))"), 3);
        let report = conflicted(&base, &ours, &theirs);
        assert!(report
            .conflicts
            .iter()
            .any(|conflict| conflict.reason.contains("LEB framing width")));
    }

    #[test]
    fn changed_branch_skeleton_requires_resolution() {
        let base = wat("(module (func block block i32.const 1 drop br 0 end end))");
        let ours = wat("(module (func block block i32.const 1 drop br 1 end end))");
        let theirs = wat("(module (func block block i32.const 2 drop br 0 end end))");
        let report = conflicted(&base, &ours, &theirs);
        assert!(report
            .conflicts
            .iter()
            .any(|conflict| conflict.reason.contains("control skeleton")));
    }

    #[test]
    fn unmodeled_stack_switching_refuses_concurrent_body_synthesis() {
        let source = |first, second| {
            format!(
                "(module (type $f (func)) (type $c (cont $f))
                    (func $target (type $f)) (elem declare func $target)
                    (func (export \"run\") ref.func $target cont.new $c drop
                        i32.const {first} drop i32.const {second} drop))"
            )
        };
        let base = wat(&source(1, 2));
        let ours = wat(&source(3, 2));
        let theirs = wat(&source(1, 4));
        for bytes in [&base, &ours, &theirs] {
            assert_eq!(
                audit::inspect(bytes).unwrap().validation,
                "valid_with_all_known_features"
            );
        }
        let report = conflicted(&base, &ours, &theirs);
        assert!(report.conflicts[0]
            .reason
            .contains("stack-switching control"));
        assert_eq!(clean(&base, &ours, &base), ours);
    }

    #[test]
    fn composite_validation_rejects_new_cross_section_inconsistency() {
        let base = wat("(module (func) (func))");
        let ours = wat("(module (export \"f\" (func 0)) (func) (func))");
        let theirs = wat("(module (func nop) (func))");
        // A section addition is conservatively rejected before composition.
        assert!(conflicted(&base, &ours, &theirs).conflicts[0]
            .path
            .contains("layout"));
        let base = wat("(module (func) (export \"f\" (func 0)))");
        let mut ours = base.clone();
        let export = audit::inspect(&ours)
            .unwrap()
            .sections
            .into_iter()
            .find(|section| section.id == 7)
            .unwrap();
        ours[export.payload_span.end - 1] = 42;
        let theirs = wat("(module (func nop) (export \"f\" (func 0)))");
        let report = conflicted(&base, &ours, &theirs);
        assert_eq!(report.validation, "failed_or_unsupported");
        assert_eq!(report.conflicts.last().unwrap().path, "module/validation");
    }

    #[test]
    fn individually_valid_atom_edits_can_have_an_invalid_composite() {
        let base = wat("(module (func (local i32) i32.const 1 drop))");
        let ours = wat("(module (func (local i32) f32.const 1 drop))");
        let theirs = wat("(module (func (local i32) i32.const 1 local.set 0))");
        for bytes in [&base, &ours, &theirs] {
            assert_eq!(
                audit::inspect(bytes).unwrap().validation,
                "valid_with_all_known_features"
            );
        }
        let report = conflicted(&base, &ours, &theirs);
        assert_eq!(report.validation, "failed_or_unsupported");
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflicts[0].path, "module/validation");
        assert!(report.conflicts[0]
            .reason
            .contains("synthesized module failed validation"));
    }

    #[test]
    fn all_exact_wholemodule_choices_preserve_unsupported_bytes() {
        let base = b"\0asm\x01\0\0\0".to_vec();
        let mut changed = base.clone();
        changed.extend_from_slice(&[42, 1, 0xff]);
        assert_eq!(clean(&base, &base, &changed), changed);
        assert_eq!(clean(&base, &changed, &base), changed);
        assert_eq!(clean(&base, &changed, &changed), changed);
        assert_eq!(clean(&changed, &changed, &changed), changed);
    }

    #[test]
    fn repeated_custom_names_are_never_guessed() {
        let mut base = wat("(module (func))");
        append_custom(&mut base, "x", &[1]);
        append_custom(&mut base, "x", &[2]);
        let mut ours = base.clone();
        *ours.last_mut().unwrap() = 3;
        let mut theirs = wat("(module (func nop))");
        append_custom(&mut theirs, "x", &[1]);
        append_custom(&mut theirs, "x", &[2]);
        let report = conflicted(&base, &ours, &theirs);
        assert!(report
            .conflicts
            .iter()
            .any(|conflict| conflict.reason.contains("duplicated")));
    }
}
