//! Opt-in decoding/auditing evidence from an external, pinned official corpus.
//! This harness never instantiates modules or executes runtime assertions.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use wasm_git::audit;
use wasmparser::{Validator, WasmFeatures};
use wast::lexer::{Lexer, TokenKind};
use wast::{parser, QuoteWat, Wast, WastDirective, WastExecute, Wat};

type Counts = BTreeMap<String, u64>;

fn count(counts: &mut Counts, key: &str) {
    *counts.entry(key.to_owned()).or_default() += 1;
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unicode_buffer(source: &str) -> Result<parser::ParseBuffer<'_>, wast::Error> {
    let mut lexer = Lexer::new(source);
    lexer.allow_confusing_unicode(true);
    parser::ParseBuffer::new_with_lexer(lexer)
}

/// Mask only two historical top-level runtime directives. The lexer protects
/// strings and nested comments, and padding preserves every original offset.
fn adapt_core1_runtime(source: &str) -> Result<(String, Vec<SourceAdaptation>), String> {
    let mut lexer = Lexer::new(source);
    lexer.allow_confusing_unicode(true);
    let mut cursor = 0;
    let mut depth = 0usize;
    let mut top_index = 0usize;
    let mut first = false;
    let mut form_start = 0;
    let mut removed = None::<String>;
    let mut ranges = Vec::new();
    let mut adaptations = Vec::new();
    while let Some(token) = lexer
        .parse(&mut cursor)
        .map_err(|error| error.to_string())?
    {
        match token.kind {
            TokenKind::LParen => {
                depth += 1;
                if depth == 1 {
                    form_start = token.offset;
                    first = true;
                }
            }
            TokenKind::RParen => {
                if depth == 1 {
                    if let Some(kind) = removed.take() {
                        let (line, column) =
                            wast::token::Span::from_offset(form_start).linecol_in(source);
                        adaptations.push(SourceAdaptation {
                            location: Location { directive: format!("script/original_directive[{top_index}]"), line: line + 1, column: column + 1 },
                            kind,
                            detail: "Historical runtime-only NaN assertion not executed; its complete token-delimited form is padded with spaces for modern WAST parsing. Original source bytes and hashes are retained.".to_owned(),
                        });
                        ranges.push((form_start, token.offset + token.len as usize));
                    }
                    top_index += 1;
                }
                depth = depth
                    .checked_sub(1)
                    .ok_or("unmatched WAST closing parenthesis")?;
            }
            TokenKind::Whitespace | TokenKind::LineComment | TokenKind::BlockComment => {}
            _ if depth == 1 && first => {
                first = false;
                let keyword = &source[token.offset..token.offset + token.len as usize];
                if token.kind == TokenKind::Keyword
                    && matches!(
                        keyword,
                        "assert_return_canonical_nan" | "assert_return_arithmetic_nan"
                    )
                {
                    removed = Some(keyword.to_owned());
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("unclosed WAST form in historical runtime adapter".into());
    }
    let mut output = source.as_bytes().to_vec();
    for (start, end) in ranges {
        for byte in &mut output[start..end] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    Ok((
        String::from_utf8(output).expect("masking full tokens preserves UTF-8"),
        adaptations,
    ))
}

fn legacy_selector_syntax(source: &str, id: wast::token::Id<'_>, container: &str) -> bool {
    let mut lexer = Lexer::new(source);
    lexer.allow_confusing_unicode(true);
    let mut cursor = id.span().offset();
    let mut meaningful = Vec::new();
    while meaningful.len() < 3 {
        match lexer.parse(&mut cursor) {
            Ok(Some(token))
                if !matches!(
                    token.kind,
                    TokenKind::Whitespace | TokenKind::LineComment | TokenKind::BlockComment
                ) =>
            {
                meaningful.push(token)
            }
            Ok(Some(_)) => {}
            _ => return false,
        }
    }
    meaningful[0].kind == TokenKind::Id
        && meaningful[1].kind == TokenKind::LParen
        && &source[meaningful[2].offset..meaningful[2].offset + meaningful[2].len as usize]
            != container
}

fn adapt_core1_selectors(module: &mut Wat<'_>, source: &str, enabled: bool) -> Vec<String> {
    use wast::core::{DataKind, ElemKind, ModuleField, ModuleKind};
    use wast::token::Index;
    let mut adaptations = Vec::new();
    if !enabled {
        return adaptations;
    }
    let Wat::Module(module) = module else {
        return adaptations;
    };
    let ModuleKind::Text(fields) = &mut module.kind else {
        return adaptations;
    };
    for field in fields {
        match field {
            ModuleField::Data(data) => {
                if let (Some(id), DataKind::Active { memory, .. }) = (data.id, &mut data.kind) {
                    if matches!(memory, Index::Num(0, span) if span.offset() == data.span.offset())
                        && legacy_selector_syntax(source, id, "memory")
                    {
                        *memory = Index::Id(id);
                        data.id = None;
                        adaptations.push(format!("Core1 active data leading identifier ${} at source byte {} reassigned from modern segment ID to historical memory selector", id.name(), id.span().offset()));
                    }
                }
            }
            ModuleField::Elem(element) => {
                if let (Some(id), ElemKind::Active { table, .. }) = (element.id, &mut element.kind)
                {
                    if table.is_none() && legacy_selector_syntax(source, id, "table") {
                        *table = Some(Index::Id(id));
                        element.id = None;
                        adaptations.push(format!("Core1 active elem leading identifier ${} at source byte {} reassigned from modern segment ID to historical table selector", id.name(), id.span().offset()));
                    }
                }
            }
            _ => {}
        }
    }
    adaptations
}

fn encode_quote(
    module: &mut QuoteWat<'_>,
    source: &str,
    core1: bool,
) -> (Result<Vec<u8>, String>, Vec<String>) {
    let mut adaptations = match module {
        QuoteWat::Wat(module) => adapt_core1_selectors(module, source, core1),
        _ => Vec::new(),
    };
    let encoded = (|| match module.to_test().map_err(|error| error.to_string())? {
        wast::QuoteWatTest::Binary(bytes) => Ok(bytes),
        wast::QuoteWatTest::Text(text) => {
            let source = std::str::from_utf8(&text).map_err(|error| error.to_string())?;
            let buffer = unicode_buffer(source).map_err(|error| error.to_string())?;
            let mut module =
                parser::parse::<Wat<'_>>(&buffer).map_err(|error| error.to_string())?;
            adaptations.extend(adapt_core1_selectors(&mut module, source, core1));
            module.encode().map_err(|error| error.to_string())
        }
    })();
    (encoded, adaptations)
}

#[derive(Clone, Serialize)]
struct Location {
    directive: String,
    line: usize,
    column: usize,
}

#[derive(Serialize)]
struct Failure {
    file: String,
    location: Option<Location>,
    code: String,
    message: String,
}

#[derive(Serialize)]
struct ModuleEvidence {
    location: Location,
    expectation: &'static str,
    encoding: &'static str,
    outcome: String,
    byte_len: Option<usize>,
    sha256: Option<String>,
    baseline_valid: Option<bool>,
    baseline_error: Option<String>,
    audit_validation: Option<String>,
    diagnostic_counts: Counts,
    identity_checked: bool,
    mutation_replayed: bool,
    patch_identity_replayed: bool,
    patch_mutation_replayed: bool,
    mutation_offset: Option<usize>,
    adaptations: Vec<String>,
    custom_sections: Vec<CustomSectionEvidence>,
}

#[derive(Serialize)]
struct CustomSectionEvidence {
    kind: String,
    status: String,
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct SourceAdaptation {
    location: Location,
    kind: String,
    detail: String,
}

#[derive(Serialize)]
struct KnownProfileLimitation {
    file: String,
    file_sha256: String,
    module_sha256: String,
    location: Location,
    original_expectation: &'static str,
    actual: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
struct FileEvidence {
    path: String,
    sha256: String,
    byte_len: usize,
    directive_counts: Counts,
    encoding_counts: Counts,
    module_category_counts: Counts,
    outcome_counts: Counts,
    runtime_actions_not_executed: Counts,
    modules: Vec<ModuleEvidence>,
    source_adaptations: Vec<SourceAdaptation>,
}

#[derive(Serialize)]
struct CorpusReport {
    schema_version: u32,
    scope: &'static str,
    runtime_conformance_tested: bool,
    corpus_root: String,
    baseline_profile: String,
    audit_profile: &'static str,
    wast_version: &'static str,
    source_manifest_sha256: String,
    excluded_symlinks: Vec<String>,
    directive_counts: Counts,
    encoding_counts: Counts,
    module_category_counts: Counts,
    outcome_counts: Counts,
    runtime_actions_not_executed: Counts,
    files: Vec<FileEvidence>,
    failures: Vec<Failure>,
    known_profile_limitations: Vec<KnownProfileLimitation>,
}

#[derive(Clone, Copy)]
enum Expectation {
    Valid,
    Invalid,
    Malformed,
    InvalidCustom,
    MalformedCustom,
}

impl Expectation {
    fn name(self) -> &'static str {
        match self {
            Self::Valid => "core_valid",
            Self::Invalid => "core_invalid",
            Self::Malformed => "core_malformed",
            Self::InvalidCustom => "invalid_custom_convention",
            Self::MalformedCustom => "malformed_custom_convention",
        }
    }
    fn permits_text_rejection(self) -> bool {
        matches!(self, Self::Malformed | Self::MalformedCustom)
    }
    fn is_custom(self) -> bool {
        matches!(self, Self::InvalidCustom | Self::MalformedCustom)
    }
}

struct Runner {
    baseline: WasmFeatures,
    core_version: u8,
    source: String,
    failures: Vec<Failure>,
    known_profile_limitations: Vec<KnownProfileLimitation>,
}

impl Runner {
    fn fail(
        &mut self,
        file: &str,
        location: Option<&Location>,
        code: &str,
        message: impl Into<String>,
    ) {
        self.failures.push(Failure {
            file: file.to_owned(),
            location: location.cloned(),
            code: code.to_owned(),
            message: message.into().chars().take(3000).collect(),
        });
    }

    fn module(
        &mut self,
        file: &mut FileEvidence,
        location: Location,
        expected: Expectation,
        encoding: &'static str,
        encoded: Result<Vec<u8>, String>,
        adaptations: Vec<String>,
    ) {
        count(&mut file.encoding_counts, encoding);
        count(&mut file.module_category_counts, expected.name());
        let mut evidence = ModuleEvidence {
            location,
            expectation: expected.name(),
            encoding,
            outcome: String::new(),
            byte_len: None,
            sha256: None,
            baseline_valid: None,
            baseline_error: None,
            audit_validation: None,
            diagnostic_counts: Counts::new(),
            identity_checked: false,
            mutation_replayed: false,
            patch_identity_replayed: false,
            patch_mutation_replayed: false,
            mutation_offset: None,
            adaptations,
            custom_sections: Vec::new(),
        };
        let bytes = match encoded {
            Ok(bytes) => bytes,
            Err(error) => {
                evidence.outcome = if expected.permits_text_rejection() {
                    "expected_text_encoding_rejection".into()
                } else {
                    self.fail(
                        &file.path,
                        Some(&evidence.location),
                        "unexpected_text_encoding_rejection",
                        &error,
                    );
                    "unexpected_text_encoding_rejection".into()
                };
                evidence.baseline_error = Some(error.chars().take(1000).collect());
                count(&mut file.outcome_counts, &evidence.outcome);
                file.modules.push(evidence);
                return;
            }
        };
        evidence.byte_len = Some(bytes.len());
        evidence.sha256 = Some(digest(&bytes));
        let baseline = Validator::new_with_features(self.baseline).validate_all(&bytes);
        evidence.baseline_valid = Some(baseline.is_ok());
        if let Err(error) = baseline {
            evidence.baseline_error = Some(error.to_string());
        }
        if matches!(expected, Expectation::Valid) && evidence.baseline_valid != Some(true) {
            self.fail(
                &file.path,
                Some(&evidence.location),
                "valid_module_baseline_rejected",
                evidence
                    .baseline_error
                    .as_deref()
                    .unwrap_or("baseline validation failed"),
            );
        }
        let historical_deviation = self.core_version == 1
            && matches!(expected, Expectation::Invalid)
            && file.path == "unreached-invalid.wast"
            && file.sha256 == "572b32f9ed9b29385b9150a68115946049d79c85d4b5ac494237d23cba0fac3f"
            && evidence.sha256.as_deref()
                == Some("90e51445cce7caf407bcd2486dee7f2455d6b32e1d21b983ccd3f62bbfa8ee1a")
            && evidence.baseline_valid == Some(true);
        if historical_deviation {
            self.known_profile_limitations.push(KnownProfileLimitation {
                file: file.path.clone(), file_sha256: file.sha256.clone(),
                module_sha256: evidence.sha256.clone().unwrap(), location: evidence.location.clone(),
                original_expectation: "assert_invalid: type mismatch",
                actual: "accepted by wasmparser 0.249.0 WASM1 feature flags",
                reason: "The pinned historical Core1 corpus requires equal br_table label types even after unreachable; the current validator checks branch operands against each target using a polymorphic unreachable stack. WASM1 controls feature flags and does not restore the historical typing algorithm. This discrepancy is not validator-conformance success.",
            });
        }
        if !historical_deviation
            && matches!(expected, Expectation::Invalid | Expectation::Malformed)
            && evidence.baseline_valid == Some(true)
        {
            self.fail(
                &file.path,
                Some(&evidence.location),
                "invalid_module_baseline_accepted",
                format!(
                    "{} module validated under the selected pinned wasmparser baseline profile",
                    expected.name()
                ),
            );
        }
        let inspected = match audit::inspect(&bytes) {
            Ok(inspected) => inspected,
            Err(error) => {
                evidence.outcome = if matches!(expected, Expectation::Malformed) {
                    "expected_core_header_rejection".into()
                } else {
                    self.fail(
                        &file.path,
                        Some(&evidence.location),
                        "unexpected_audit_header_rejection",
                        error,
                    );
                    "unexpected_audit_header_rejection".into()
                };
                count(&mut file.outcome_counts, &evidence.outcome);
                file.modules.push(evidence);
                return;
            }
        };
        evidence.audit_validation = Some(inspected.validation.clone());
        evidence.custom_sections = inspected
            .sections
            .iter()
            .filter(|section| section.id == 0)
            .map(|section| CustomSectionEvidence {
                kind: section.kind.clone(),
                status: section.status.clone(),
                start: section.span.start,
                end: section.span.end,
            })
            .collect();
        for diagnostic in &inspected.diagnostics {
            count(&mut evidence.diagnostic_counts, &diagnostic.code);
        }
        if matches!(expected, Expectation::Valid) {
            if inspected.validation != "valid_with_all_known_features" {
                self.fail(
                    &file.path,
                    Some(&evidence.location),
                    "valid_module_all_features_rejected",
                    format!(
                        "audit validation={}; diagnostics={:?}",
                        inspected.validation, evidence.diagnostic_counts
                    ),
                );
            }
            for diagnostic in &inspected.diagnostics {
                if matches!(
                    diagnostic.code.as_str(),
                    "core_decode"
                        | "unknown_operator"
                        | "operator_decode"
                        | "locals_decode"
                        | "section_framing"
                        | "unknown_section"
                ) {
                    self.fail(
                        &file.path,
                        Some(&evidence.location),
                        "valid_module_decoding_incomplete",
                        format!(
                            "{} at byte {}: {}",
                            diagnostic.code, diagnostic.offset, diagnostic.message
                        ),
                    );
                }
            }
        }
        let recognized_custom = evidence
            .custom_sections
            .iter()
            .filter(|section| {
                matches!(
                    section.kind.as_str(),
                    "custom:name" | "custom:producers" | "custom:target_features"
                )
            })
            .collect::<Vec<_>>();
        let custom_opacity_observed = if recognized_custom.is_empty() {
            evidence
                .custom_sections
                .iter()
                .any(|section| section.status == "opaque")
        } else {
            recognized_custom
                .iter()
                .any(|section| section.status == "opaque")
        };
        if expected.is_custom() && !custom_opacity_observed {
            self.fail(&file.path, Some(&evidence.location), "custom_convention_not_opaque",
                "custom assertion has no opaque custom section or custom-convention diagnostic; Core validity is assessed independently");
        }
        evidence.outcome = if historical_deviation {
            "known_historical_validator_deviation_audited".into()
        } else if evidence.baseline_valid == Some(false)
            && inspected.validation == "valid_with_all_known_features"
        {
            "baseline_rejected_known_extension_accepted".into()
        } else if expected.is_custom() {
            "custom_convention_audited".into()
        } else {
            "core_bytes_audited".into()
        };
        match audit::compare(&bytes, &bytes) {
            Ok(identity)
                if !identity.changed
                    && identity.edits.is_empty()
                    && identity.semantic_changes.is_empty() =>
            {
                evidence.identity_checked = true
            }
            Ok(_) => self.fail(
                &file.path,
                Some(&evidence.location),
                "identity_diff_nonempty",
                "identical module bytes produced a change",
            ),
            Err(error) => self.fail(
                &file.path,
                Some(&evidence.location),
                "identity_diff_failed",
                error,
            ),
        }
        let mut mutation = bytes.clone();
        let position = if bytes.len() > 8 {
            // One edit keeps Myers distance bounded even for large modules.
            let position = 8 + (bytes.len() - 8) / 2;
            mutation[position] ^= 1;
            position
        } else {
            mutation.extend_from_slice(&[0, 1, 0]); // canonical empty-name custom section
            bytes.len()
        };
        evidence.mutation_offset = Some(position);
        match audit::compare(&bytes, &mutation) {
            Ok(difference) => match replay(&bytes, &mutation, &difference) {
                Ok(()) => evidence.mutation_replayed = true,
                Err(error) => self.fail(
                    &file.path,
                    Some(&evidence.location),
                    "mutation_replay_failed",
                    error,
                ),
            },
            Err(error) => self.fail(
                &file.path,
                Some(&evidence.location),
                "mutation_audit_failed",
                error,
            ),
        }
        match patch_roundtrip(&bytes, &bytes) {
            Ok(()) => evidence.patch_identity_replayed = true,
            Err(error) => self.fail(
                &file.path,
                Some(&evidence.location),
                "patch_identity_replay_failed",
                error,
            ),
        }
        match patch_roundtrip(&bytes, &mutation) {
            Ok(()) => evidence.patch_mutation_replayed = true,
            Err(error) => self.fail(
                &file.path,
                Some(&evidence.location),
                "patch_mutation_replay_failed",
                error,
            ),
        }
        count(&mut file.outcome_counts, &evidence.outcome);
        file.modules.push(evidence);
    }

    fn quote(
        &mut self,
        file: &mut FileEvidence,
        location: Location,
        expected: Expectation,
        module: &mut QuoteWat<'_>,
    ) {
        let encoding = match module {
            QuoteWat::Wat(Wat::Module(module)) => match module.kind {
                wast::core::ModuleKind::Text(_) => "text",
                wast::core::ModuleKind::Binary(_) => "binary",
            },
            QuoteWat::QuoteModule(..) => "quoted_text",
            QuoteWat::Wat(Wat::Component(_)) | QuoteWat::QuoteComponent(..) => {
                count(&mut file.encoding_counts, "component_model_excluded");
                count(&mut file.module_category_counts, "component_model_excluded");
                count(&mut file.outcome_counts, "component_model_excluded");
                return;
            }
        };
        let (encoded, adaptations) = encode_quote(module, &self.source, self.core_version == 1);
        self.module(file, location, expected, encoding, encoded, adaptations);
    }

    fn wat(&mut self, file: &mut FileEvidence, location: Location, module: &mut Wat<'_>) {
        let encoding = match module {
            Wat::Module(module) => match module.kind {
                wast::core::ModuleKind::Text(_) => "text",
                wast::core::ModuleKind::Binary(_) => "binary",
            },
            Wat::Component(_) => {
                count(&mut file.encoding_counts, "component_model_excluded");
                count(&mut file.module_category_counts, "component_model_excluded");
                count(&mut file.outcome_counts, "component_model_excluded");
                return;
            }
        };
        let adaptations = adapt_core1_selectors(module, &self.source, self.core_version == 1);
        self.module(
            file,
            location,
            Expectation::Valid,
            encoding,
            module.encode().map_err(|error| error.to_string()),
            adaptations,
        );
    }

    fn execute(
        &mut self,
        file: &mut FileEvidence,
        location: Location,
        category: &str,
        execute: &mut WastExecute<'_>,
    ) {
        match execute {
            WastExecute::Wat(module) => {
                count(
                    &mut file.runtime_actions_not_executed,
                    &format!("{category}.module_instantiation"),
                );
                self.wat(file, location, module);
            }
            WastExecute::Invoke(_) => count(
                &mut file.runtime_actions_not_executed,
                &format!("{category}.invoke"),
            ),
            WastExecute::Get { .. } => count(
                &mut file.runtime_actions_not_executed,
                &format!("{category}.get"),
            ),
        }
    }

    fn directives(
        &mut self,
        file: &mut FileEvidence,
        source: &str,
        directives: &mut [WastDirective<'_>],
        parent: &str,
    ) {
        for (index, directive) in directives.iter_mut().enumerate() {
            let (line, column) = directive.span().linecol_in(source);
            let location = Location {
                directive: format!("{parent}/directive[{index}]"),
                line: line + 1,
                column: column + 1,
            };
            let kind = match directive {
                WastDirective::Module(module) => {
                    count(
                        &mut file.runtime_actions_not_executed,
                        "module_instantiation",
                    );
                    self.quote(file, location, Expectation::Valid, module);
                    "module"
                }
                WastDirective::ModuleDefinition(module) => {
                    self.quote(file, location, Expectation::Valid, module);
                    "module_definition"
                }
                WastDirective::ModuleInstance { .. } => {
                    count(&mut file.runtime_actions_not_executed, "module_instance");
                    "module_instance"
                }
                WastDirective::AssertMalformed { module, .. } => {
                    self.quote(file, location, Expectation::Malformed, module);
                    "assert_malformed"
                }
                WastDirective::AssertInvalid { module, .. } => {
                    self.quote(file, location, Expectation::Invalid, module);
                    "assert_invalid"
                }
                WastDirective::AssertInvalidCustom { module, .. } => {
                    self.quote(file, location, Expectation::InvalidCustom, module);
                    "assert_invalid_custom"
                }
                WastDirective::AssertMalformedCustom { module, .. } => {
                    self.quote(file, location, Expectation::MalformedCustom, module);
                    "assert_malformed_custom"
                }
                WastDirective::AssertUnlinkable { module, .. } => {
                    count(
                        &mut file.runtime_actions_not_executed,
                        "assert_unlinkable.linking",
                    );
                    self.wat(file, location, module);
                    "assert_unlinkable"
                }
                WastDirective::AssertTrap { exec, .. } => {
                    self.execute(file, location, "assert_trap", exec);
                    "assert_trap"
                }
                WastDirective::AssertReturn { exec, .. } => {
                    self.execute(file, location, "assert_return", exec);
                    "assert_return"
                }
                WastDirective::AssertException { exec, .. } => {
                    self.execute(file, location, "assert_exception", exec);
                    "assert_exception"
                }
                WastDirective::AssertSuspension { exec, .. } => {
                    self.execute(file, location, "assert_suspension", exec);
                    "assert_suspension"
                }
                WastDirective::AssertExhaustion { .. } => {
                    count(
                        &mut file.runtime_actions_not_executed,
                        "assert_exhaustion.invoke",
                    );
                    "assert_exhaustion"
                }
                WastDirective::Invoke(_) => {
                    count(&mut file.runtime_actions_not_executed, "invoke");
                    "invoke"
                }
                WastDirective::Register { .. } => {
                    count(&mut file.runtime_actions_not_executed, "register");
                    "register"
                }
                WastDirective::Wait { .. } => {
                    count(&mut file.runtime_actions_not_executed, "wait");
                    "wait"
                }
                WastDirective::Thread(thread) => {
                    count(&mut file.runtime_actions_not_executed, "thread");
                    self.directives(
                        file,
                        source,
                        &mut thread.directives,
                        &format!("{}/thread", location.directive),
                    );
                    "thread"
                }
            };
            count(&mut file.directive_counts, kind);
        }
    }
}

fn patch_roundtrip(old: &[u8], new: &[u8]) -> Result<(), String> {
    let patch = wasm_git::patch::create(old, new)?;
    let encoded = patch.to_bytes()?;
    let decoded = wasm_git::patch::BytePatch::from_bytes(&encoded)?;
    let replayed = decoded.apply(old)?;
    if replayed != new {
        return Err("serialized patch replay differs from the complete target bytes".into());
    }
    if old == new && !decoded.edits.is_empty() {
        return Err("identity patch contains edits".into());
    }
    Ok(())
}

fn replay(old: &[u8], new: &[u8], difference: &audit::AuditDiff) -> Result<(), String> {
    if !difference.changed || difference.edits.is_empty() {
        return Err("mutation produced no physical edits".into());
    }
    let mut output = Vec::with_capacity(new.len());
    let (mut old_cursor, mut new_cursor) = (0, 0);
    for edit in &difference.edits {
        let a = edit.old_span;
        let b = edit.new_span;
        if a.start < old_cursor
            || a.end < a.start
            || a.end > old.len()
            || b.start < new_cursor
            || b.end < b.start
            || b.end > new.len()
        {
            return Err("unordered or out-of-bounds edit span".into());
        }
        if edit.old_hex != hex(&old[a.start..a.end]) || edit.new_hex != hex(&new[b.start..b.end]) {
            return Err("edit hex does not describe source bytes".into());
        }
        output.extend_from_slice(&old[old_cursor..a.start]);
        output.extend_from_slice(&new[b.start..b.end]);
        old_cursor = a.end;
        new_cursor = b.end;
    }
    output.extend_from_slice(&old[old_cursor..]);
    if output != new {
        return Err("reported edits did not reconstruct the mutated module".into());
    }
    Ok(())
}

fn merge_counts(target: &mut Counts, source: &Counts) {
    for (key, value) in source {
        *target.entry(key.clone()).or_default() += value;
    }
}

fn save_report(path: &Path, report: &CorpusReport) -> Result<(), String> {
    let tmp = std::fs::canonicalize("/tmp").map_err(|error| error.to_string())?;
    let parent = path
        .parent()
        .filter(|_| path.is_absolute())
        .ok_or("UWGIT_SPEC_REPORT must be an absolute path under /tmp")?;
    let parent = parent
        .canonicalize()
        .map_err(|error| format!("report parent must already exist: {error}"))?;
    if !parent.starts_with(tmp)
        || std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(
            "UWGIT_SPEC_REPORT must name a regular file under /tmp, without a final symlink".into(),
        );
    }
    let file = std::fs::File::create(path).map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(file, report).map_err(|error| error.to_string())
}

fn discover_wast(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    excluded: &mut Vec<String>,
) {
    let mut entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot enumerate {}: {error}", directory.display()))
        .map(|entry| entry.expect("read corpus directory entry"))
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let kind = entry
            .file_type()
            .expect("read corpus entry type without following symlinks");
        if kind.is_symlink() {
            excluded.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        } else if kind.is_dir() {
            discover_wast(root, &path, files, excluded);
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "wast")
        {
            files.push(path);
        }
    }
}

#[test]
fn historical_runtime_adapter_is_token_aware_and_preserves_source_offsets() {
    let source = r#"(; nested (; (assert_return_canonical_nan (invoke "comment")) ;) ;)
(module (data "(assert_return_arithmetic_nan is a string)"))
(assert_return_canonical_nan (invoke "old-runtime-1"))
(assert_return_arithmetic_nan (invoke "old-runtime-2"))
(module)
"#;
    let (adapted, adaptations) = adapt_core1_runtime(source).unwrap();
    assert_eq!(adaptations.len(), 2);
    assert_eq!(adapted.len(), source.len());
    assert_eq!(
        source
            .match_indices('\n')
            .map(|(offset, _)| offset)
            .collect::<Vec<_>>(),
        adapted
            .match_indices('\n')
            .map(|(offset, _)| offset)
            .collect::<Vec<_>>()
    );
    assert!(adapted.contains("(assert_return_arithmetic_nan is a string)"));
    assert!(adapted.contains("(invoke \"comment\")"));
    let buffer = unicode_buffer(&adapted).unwrap();
    let script = parser::parse::<Wast<'_>>(&buffer).unwrap();
    assert_eq!(script.directives.len(), 2);
}

#[test]
fn historical_active_segment_ids_are_reassigned_to_named_targets() {
    let source = r#"(module
        (memory $memory 1)
        (table $table 1 funcref)
        (data $memory (i32.const 0) "a")
        (data $memory (i32.const 1) "b")
        (elem $table (i32.const 0))
        (elem $table (i32.const 0)))"#;
    let buffer = unicode_buffer(source).unwrap();
    let mut module = parser::parse::<Wat<'_>>(&buffer).unwrap();
    let adaptations = adapt_core1_selectors(&mut module, source, true);
    assert_eq!(adaptations.len(), 4);
    let bytes = module.encode().unwrap();
    Validator::new_with_features(WasmFeatures::WASM1)
        .validate_all(&bytes)
        .unwrap();
}

#[test]
fn modern_explicit_segment_ids_are_not_historical_selectors() {
    let source =
        r#"(module (memory $memory 1) (data $segment (memory $memory) (i32.const 0) "a"))"#;
    let buffer = unicode_buffer(source).unwrap();
    let mut module = parser::parse::<Wat<'_>>(&buffer).unwrap();
    assert!(adapt_core1_selectors(&mut module, source, true).is_empty());
    assert!(adapt_core1_selectors(&mut module, source, false).is_empty());
    module.encode().unwrap();
}

#[test]
#[ignore = "requires pinned official corpus; set UWGIT_SPEC_ROOT and UWGIT_SPEC_VERSION=1|2|3; audits binary decoding, not runtime conformance"]
fn official_core_wast_corpus_audit() {
    let root = PathBuf::from(
        std::env::var_os("UWGIT_SPEC_ROOT")
            .expect("set UWGIT_SPEC_ROOT to a pinned spec/test/core directory"),
    );
    let root = root
        .canonicalize()
        .expect("UWGIT_SPEC_ROOT must be an existing directory");
    let version = std::env::var("UWGIT_SPEC_VERSION")
        .expect("set UWGIT_SPEC_VERSION=1, 2, or 3 for the corresponding official corpus");
    let baseline = match version.as_str() {
        "1" => WasmFeatures::WASM1,
        "2" => WasmFeatures::WASM2,
        "3" => WasmFeatures::WASM3,
        _ => panic!("UWGIT_SPEC_VERSION must be 1, 2, or 3"),
    };
    let mut files = Vec::new();
    let mut excluded_symlinks = Vec::new();
    discover_wast(&root, &root, &mut files, &mut excluded_symlinks);
    files.sort();
    assert!(
        !files.is_empty(),
        "no recursive .wast files in {}",
        root.display()
    );
    let mut runner = Runner {
        baseline,
        core_version: version.parse().unwrap(),
        source: String::new(),
        failures: Vec::new(),
        known_profile_limitations: Vec::new(),
    };
    let mut report = CorpusReport {
        schema_version: 1,
        scope: "all recursive regular core .wast files, symlinks excluded and listed; nested thread and execute modules extracted; runtime assertions and instantiation are explicitly not executed",
        runtime_conformance_tested: false, corpus_root: root.to_string_lossy().into_owned(),
        baseline_profile: format!("wasmparser 0.249.0 WasmFeatures::WASM{version}; a pinned implementation profile, not normative certification"),
        audit_profile: "wasmparser 0.249.0 WasmFeatures::all; known future extensions remain auditable",
        wast_version: "249.0.0", source_manifest_sha256: String::new(), excluded_symlinks,
        directive_counts: Counts::new(), encoding_counts: Counts::new(), module_category_counts: Counts::new(),
        outcome_counts: Counts::new(), runtime_actions_not_executed: Counts::new(), files: Vec::new(), failures: Vec::new(), known_profile_limitations: Vec::new(),
    };
    let mut manifest = Sha256::new();
    for path in files {
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                runner.fail(&relative, None, "file_read", error.to_string());
                continue;
            }
        };
        let sha256 = digest(&bytes);
        manifest.update(relative.as_bytes());
        manifest.update([0]);
        manifest.update(sha256.as_bytes());
        manifest.update(b"\n");
        let mut file = FileEvidence {
            path: relative,
            sha256,
            byte_len: bytes.len(),
            directive_counts: Counts::new(),
            encoding_counts: Counts::new(),
            module_category_counts: Counts::new(),
            outcome_counts: Counts::new(),
            runtime_actions_not_executed: Counts::new(),
            modules: Vec::new(),
            source_adaptations: Vec::new(),
        };
        match std::str::from_utf8(&bytes) {
            Err(error) => runner.fail(&file.path, None, "source_utf8", error.to_string()),
            Ok(source) => {
                let adapted = if runner.core_version == 1 {
                    adapt_core1_runtime(source)
                } else {
                    Ok((source.to_owned(), Vec::new()))
                };
                match adapted {
                    Err(error) => {
                        runner.fail(&file.path, None, "historical_runtime_adapter", error)
                    }
                    Ok((adapted, adaptations)) => {
                        for adaptation in &adaptations {
                            count(&mut file.directive_counts, &adaptation.kind);
                            count(&mut file.runtime_actions_not_executed, &adaptation.kind);
                        }
                        file.source_adaptations = adaptations;
                        runner.source = source.to_owned();
                        match unicode_buffer(&adapted) {
                            Err(error) => {
                                runner.fail(&file.path, None, "wast_lex", error.to_string())
                            }
                            Ok(buffer) => match parser::parse::<Wast<'_>>(&buffer) {
                                Err(error) => {
                                    runner.fail(&file.path, None, "wast_parse", error.to_string())
                                }
                                Ok(mut script) => runner.directives(
                                    &mut file,
                                    source,
                                    &mut script.directives,
                                    "script",
                                ),
                            },
                        }
                    }
                }
            }
        }
        merge_counts(&mut report.directive_counts, &file.directive_counts);
        merge_counts(&mut report.encoding_counts, &file.encoding_counts);
        merge_counts(
            &mut report.module_category_counts,
            &file.module_category_counts,
        );
        merge_counts(&mut report.outcome_counts, &file.outcome_counts);
        merge_counts(
            &mut report.runtime_actions_not_executed,
            &file.runtime_actions_not_executed,
        );
        report.files.push(file);
    }
    report.source_manifest_sha256 = format!("{:x}", manifest.finalize());
    report.failures = runner.failures;
    report.known_profile_limitations = runner.known_profile_limitations;
    if let Some(path) = std::env::var_os("UWGIT_SPEC_REPORT") {
        save_report(Path::new(&path), &report)
            .expect("write corpus audit evidence only under /tmp");
    }
    eprintln!("spec WASM{version}: files={}, modules={}, outcomes={:?}, failures={}, known_profile_discrepancies={}, runtime assertions NOT executed",
        report.files.len(), report.files.iter().map(|file| file.modules.len()).sum::<usize>(), report.outcome_counts, report.failures.len(), report.known_profile_limitations.len());
    for failure in report.failures.iter().take(20) {
        eprintln!(
            "{}:{}: {}: {}",
            failure.file,
            failure
                .location
                .as_ref()
                .map_or(0, |location| location.line),
            failure.code,
            failure.message
        );
    }
    assert!(report.failures.is_empty(), "{} corpus audit failures; inspect UWGIT_SPEC_REPORT JSON for complete per-file/directive evidence", report.failures.len());
}
