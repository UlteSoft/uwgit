//! Function matching using deterministic anchors and fingerprints.
//! Maps functions from old and new modules even under index drift.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::fingerprint::canonical_operators;
use crate::ir::{FunctionIr, FunctionKindIr, Immediate, NormalizedModule, ParsedOperator};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FunctionMatch {
    pub old_id: String,
    pub new_id: String,
    pub old_source_index: u32,
    pub new_source_index: u32,
    pub confidence: f32,
    pub similarity: f32,
    pub reason: MatchReason,
    /// Both bodies have resolved static function-reference contexts. A unique
    /// import/export role may still anchor a body whose context is incomplete.
    pub reference_context_complete: bool,
    /// Multiple candidates support this pairing, or an earlier ambiguous group
    /// affected an endpoint. Ordering is not a proven historical identity.
    pub ambiguous: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum MatchReason {
    SameStableId,
    SameExactBodyHash,
    SameCanonicalBodyHash,
    SameMatchedReferenceBody,
    SimilarityFallback,
}

#[derive(Default)]
struct MatchUncertainty {
    old: BTreeSet<usize>,
    new: BTreeSet<usize>,
}

pub fn match_functions(old: &NormalizedModule, new: &NormalizedModule) -> Vec<FunctionMatch> {
    let mut matches = Vec::new();
    let mut matched_old = BTreeSet::new();
    let mut matched_new = BTreeSet::new();
    let mut uncertainty = MatchUncertainty::default();

    match_by_key(
        old,
        new,
        |_, function| {
            (function.kind == FunctionKindIr::Imported || !function.export_names.is_empty())
                .then(|| function.id.clone())
        },
        MatchReason::SameStableId,
        1.0,
        &mut matched_old,
        &mut matched_new,
        &mut uncertainty,
        &mut matches,
    );
    match_by_key(
        old,
        new,
        |module, function| {
            if function.kind != FunctionKindIr::Defined {
                return None;
            }
            function
                .fingerprint
                .as_ref()
                .filter(|fingerprint| fingerprint.reference_context_complete)
                .map(|fingerprint| {
                    // A hash is an accelerator, not proof. Include the actual
                    // decoded operands so a hash collision cannot make an exact
                    // body pairing appear certain.
                    let operators: Vec<_> = function
                        .operators
                        .iter()
                        .map(|op| (op.opcode.as_str(), &op.immediate))
                        .collect();
                    serde_json::to_string(&(
                        &function.type_id,
                        fingerprint.exact_body_hash.hex(),
                        &function.locals,
                        operators,
                        canonical_operators(module, function),
                    ))
                    .expect("function keys are serializable")
                })
        },
        MatchReason::SameExactBodyHash,
        1.0,
        &mut matched_old,
        &mut matched_new,
        &mut uncertainty,
        &mut matches,
    );
    match_by_key(
        old,
        new,
        |module, function| {
            if function.kind != FunctionKindIr::Defined {
                return None;
            }
            function
                .fingerprint
                .as_ref()
                .filter(|fingerprint| fingerprint.reference_context_complete)
                .map(|fingerprint| {
                    serde_json::to_string(&(
                        &function.type_id,
                        fingerprint.canonical_body_hash.hex(),
                        &function.locals,
                        canonical_operators(module, function),
                    ))
                    .expect("function keys are serializable")
                })
        },
        MatchReason::SameCanonicalBodyHash,
        0.95,
        &mut matched_old,
        &mut matched_new,
        &mut uncertainty,
        &mut matches,
    );
    match_by_similarity(
        old,
        new,
        0.6,
        &mut matched_old,
        &mut matched_new,
        &mut uncertainty,
        &mut matches,
    );
    match_by_reference_neighborhood(
        old,
        new,
        &mut matched_old,
        &mut matched_new,
        &mut uncertainty,
        &mut matches,
    );

    matches.sort_by(|left, right| {
        left.old_id
            .cmp(&right.old_id)
            .then_with(|| left.new_id.cmp(&right.new_id))
            .then_with(|| left.old_source_index.cmp(&right.old_source_index))
            .then_with(|| left.new_source_index.cmp(&right.new_source_index))
    });
    matches
}

pub fn unmatched_old_function_ids(
    old: &NormalizedModule,
    matches: &[FunctionMatch],
) -> Vec<String> {
    let matched = matches
        .iter()
        .map(|function_match| function_match.old_source_index)
        .collect::<BTreeSet<_>>();

    old.functions
        .iter()
        .filter(|function| !matched.contains(&function.source_index))
        .map(|function| function.id.clone())
        .collect()
}

pub fn unmatched_new_function_ids(
    new: &NormalizedModule,
    matches: &[FunctionMatch],
) -> Vec<String> {
    let matched = matches
        .iter()
        .map(|function_match| function_match.new_source_index)
        .collect::<BTreeSet<_>>();

    new.functions
        .iter()
        .filter(|function| !matched.contains(&function.source_index))
        .map(|function| function.id.clone())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn match_by_key(
    old: &NormalizedModule,
    new: &NormalizedModule,
    key: impl Fn(&NormalizedModule, &FunctionIr) -> Option<String>,
    reason: MatchReason,
    confidence: f32,
    matched_old: &mut BTreeSet<usize>,
    matched_new: &mut BTreeSet<usize>,
    uncertainty: &mut MatchUncertainty,
    matches: &mut Vec<FunctionMatch>,
) {
    let old_candidates = grouped_candidates(old, &key, matched_old);
    let new_candidates = grouped_candidates(new, &key, matched_new);

    for (candidate_key, old_indices) in old_candidates {
        let Some(new_indices) = new_candidates.get(&candidate_key) else {
            continue;
        };
        let ambiguous = old_indices.len() != 1
            || new_indices.len() != 1
            || old_indices
                .iter()
                .any(|index| uncertainty.old.contains(index))
            || new_indices
                .iter()
                .any(|index| uncertainty.new.contains(index));
        if ambiguous {
            // Keep uncertainty for every endpoint, including a surplus function
            // left for a later pass. Choosing one occurrence does not establish
            // which historical function remains to be matched.
            uncertainty.old.extend(old_indices.iter().copied());
            uncertainty.new.extend(new_indices.iter().copied());
        }
        for (old_index, new_index) in old_indices.iter().zip(new_indices) {
            if matched_old.contains(old_index) || matched_new.contains(new_index) {
                continue;
            }

            let old_function = &old.functions[*old_index];
            let new_function = &new.functions[*new_index];
            let similarity = function_similarity(old, old_function, new, new_function);

            matched_old.insert(*old_index);
            matched_new.insert(*new_index);
            matches.push(FunctionMatch {
                old_id: old_function.id.clone(),
                new_id: new_function.id.clone(),
                old_source_index: old_function.source_index,
                new_source_index: new_function.source_index,
                confidence: if ambiguous {
                    0.5
                } else if reason != MatchReason::SameStableId && old_function.id != new_function.id
                {
                    confidence.min(0.9)
                } else {
                    confidence
                },
                similarity,
                reason,
                reference_context_complete: complete_reference_context(old_function)
                    && complete_reference_context(new_function),
                ambiguous,
            });
        }
    }
}

fn grouped_candidates(
    module: &NormalizedModule,
    key: &impl Fn(&NormalizedModule, &FunctionIr) -> Option<String>,
    already_matched: &BTreeSet<usize>,
) -> BTreeMap<String, Vec<usize>> {
    let mut candidates = BTreeMap::<String, Vec<usize>>::new();
    for (index, function) in module.functions.iter().enumerate() {
        if already_matched.contains(&index) {
            continue;
        }
        if let Some(candidate_key) = key(module, function) {
            candidates.entry(candidate_key).or_default().push(index);
        }
    }

    candidates
}

#[derive(Debug, Clone)]
struct SimilarityCandidate {
    old_index: usize,
    new_index: usize,
    score: SimilarityScore,
    locals_equal: bool,
    direct_call_similarity: f32,
}

#[derive(Debug, Clone, Copy)]
struct SimilarityScore {
    combined: f32,
    opcode: f32,
    immediate: f32,
    length: f32,
}

fn match_by_similarity(
    old: &NormalizedModule,
    new: &NormalizedModule,
    threshold: f32,
    matched_old: &mut BTreeSet<usize>,
    matched_new: &mut BTreeSet<usize>,
    uncertainty: &mut MatchUncertainty,
    matches: &mut Vec<FunctionMatch>,
) {
    let mut candidates = Vec::new();

    for (old_index, old_function) in old.functions.iter().enumerate() {
        if matched_old.contains(&old_index) {
            continue;
        }
        if old_function.kind != FunctionKindIr::Defined {
            continue;
        }
        for (new_index, new_function) in new.functions.iter().enumerate() {
            if matched_new.contains(&new_index)
                || new_function.kind != FunctionKindIr::Defined
                || old_function.type_id != new_function.type_id
            {
                continue;
            }

            let score = function_similarity_score(old, old_function, new, new_function);
            if score.combined < threshold {
                continue;
            }

            candidates.push(SimilarityCandidate {
                old_index,
                new_index,
                score,
                locals_equal: old_function.locals == new_function.locals,
                direct_call_similarity: direct_call_similarity(old_function, new_function),
            });
        }
    }

    candidates.sort_by(|left, right| {
        right
            .score
            .combined
            .total_cmp(&left.score.combined)
            .then_with(|| right.locals_equal.cmp(&left.locals_equal))
            .then_with(|| {
                right
                    .direct_call_similarity
                    .total_cmp(&left.direct_call_similarity)
            })
            .then_with(|| left.old_index.cmp(&right.old_index))
            .then_with(|| left.new_index.cmp(&right.new_index))
    });

    for candidate in &candidates {
        if matched_old.contains(&candidate.old_index) || matched_new.contains(&candidate.new_index)
        {
            continue;
        }

        let old_function = &old.functions[candidate.old_index];
        let new_function = &new.functions[candidate.new_index];
        let reference_context_complete =
            complete_reference_context(old_function) && complete_reference_context(new_function);
        // Candidates contain only functions left unanchored at the start of
        // this pass. Greedy assignment cannot resolve an existing score tie:
        // its deterministic ordering is not additional identity evidence.
        let alternatives: Vec<_> = candidates
            .iter()
            .filter(|other| {
                (other.old_index != candidate.old_index || other.new_index != candidate.new_index)
                    && (other.old_index == candidate.old_index
                        || other.new_index == candidate.new_index)
                    && other.score.combined == candidate.score.combined
                    && other.locals_equal == candidate.locals_equal
                    && other.direct_call_similarity == candidate.direct_call_similarity
            })
            .collect();
        let ambiguous = !reference_context_complete
            || uncertainty.old.contains(&candidate.old_index)
            || uncertainty.new.contains(&candidate.new_index)
            || !alternatives.is_empty();
        if ambiguous {
            uncertainty.old.insert(candidate.old_index);
            uncertainty.new.insert(candidate.new_index);
            for other in alternatives {
                uncertainty.old.insert(other.old_index);
                uncertainty.new.insert(other.new_index);
            }
        }

        matched_old.insert(candidate.old_index);
        matched_new.insert(candidate.new_index);
        matches.push(FunctionMatch {
            old_id: old_function.id.clone(),
            new_id: new_function.id.clone(),
            old_source_index: old_function.source_index,
            new_source_index: new_function.source_index,
            confidence: if ambiguous {
                0.5
            } else {
                similarity_confidence(old_function, new_function, candidate)
            },
            similarity: candidate.score.combined,
            reason: MatchReason::SimilarityFallback,
            reference_context_complete,
            ambiguous,
        });
    }
}

fn complete_reference_context(function: &FunctionIr) -> bool {
    function
        .fingerprint
        .as_ref()
        .is_some_and(|fingerprint| fingerprint.reference_context_complete)
}

type ReferenceMap = BTreeMap<u32, (u32, f32)>;
type ReferenceBodyCandidates = BTreeMap<String, Vec<(usize, f32)>>;

fn reference_body_candidates(
    module: &NormalizedModule,
    matched: &BTreeSet<usize>,
    references: &ReferenceMap,
) -> ReferenceBodyCandidates {
    let mut candidates = ReferenceBodyCandidates::new();
    for (index, function) in module.functions.iter().enumerate() {
        if matched.contains(&index)
            || function.kind != FunctionKindIr::Defined
            || !complete_reference_context(function)
        {
            continue;
        }
        if let Some((key, confidence)) = matched_reference_body_key(function, references) {
            candidates.entry(key).or_default().push((index, confidence));
        }
    }
    candidates
}

/// Function references are translated only through established, nonambiguous
/// candidates. Every other decoded operand and the ordered opcode sequence stay
/// exact. The translated index denotes a candidate in the new module, never a
/// guessed correspondence between equal numbers in different modules.
fn matched_reference_body_key(
    function: &FunctionIr,
    references: &ReferenceMap,
) -> Option<(String, f32)> {
    let mut confidence = 0.9_f32;
    let mut has_reference = false;
    let mut operators = Vec::with_capacity(function.operators.len());
    for operator in &function.operators {
        let key = match &operator.immediate {
            Immediate::Call(index) | Immediate::RefFunc(index) => {
                let &(translated, support_confidence) = references.get(index)?;
                confidence = confidence.min(support_confidence);
                has_reference = true;
                serde_json::to_string(&(operator.opcode.as_str(), "matched_function", translated))
            }
            immediate => serde_json::to_string(&(operator.opcode.as_str(), immediate)),
        }
        .expect("function keys are serializable");
        operators.push(key);
    }
    has_reference.then(|| {
        (
            serde_json::to_string(&(&function.type_id, &function.locals, operators))
                .expect("function keys are serializable"),
            confidence,
        )
    })
}

fn match_by_reference_neighborhood(
    old: &NormalizedModule,
    new: &NormalizedModule,
    matched_old: &mut BTreeSet<usize>,
    matched_new: &mut BTreeSet<usize>,
    uncertainty: &mut MatchUncertainty,
    matches: &mut Vec<FunctionMatch>,
) {
    loop {
        let mut old_references = ReferenceMap::new();
        let mut new_references = ReferenceMap::new();
        for function_match in matches.iter().filter(|candidate| !candidate.ambiguous) {
            old_references.insert(
                function_match.old_source_index,
                (function_match.new_source_index, function_match.confidence),
            );
            new_references.insert(
                function_match.new_source_index,
                (function_match.new_source_index, function_match.confidence),
            );
        }
        let old_candidates = reference_body_candidates(old, matched_old, &old_references);
        let new_candidates = reference_body_candidates(new, matched_new, &new_references);
        let before = matches.len();
        for (key, old_group) in old_candidates {
            let Some(new_group) = new_candidates.get(&key) else {
                continue;
            };
            let ambiguous = old_group.len() != 1
                || new_group.len() != 1
                || old_group
                    .iter()
                    .any(|(index, _)| uncertainty.old.contains(index))
                || new_group
                    .iter()
                    .any(|(index, _)| uncertainty.new.contains(index));
            if ambiguous {
                uncertainty
                    .old
                    .extend(old_group.iter().map(|(index, _)| *index));
                uncertainty
                    .new
                    .extend(new_group.iter().map(|(index, _)| *index));
            }
            for (&(old_index, old_support), &(new_index, new_support)) in
                old_group.iter().zip(new_group)
            {
                let old_function = &old.functions[old_index];
                let new_function = &new.functions[new_index];
                matched_old.insert(old_index);
                matched_new.insert(new_index);
                matches.push(FunctionMatch {
                    old_id: old_function.id.clone(),
                    new_id: new_function.id.clone(),
                    old_source_index: old_function.source_index,
                    new_source_index: new_function.source_index,
                    confidence: old_support
                        .min(new_support)
                        .min(if ambiguous { 0.5 } else { 0.9 }),
                    similarity: function_similarity(old, old_function, new, new_function),
                    reason: MatchReason::SameMatchedReferenceBody,
                    reference_context_complete: true,
                    ambiguous,
                });
            }
        }
        // Each successful round consumes at least one previously unmatched
        // function on both sides. No fixed iteration count or recursive walk.
        if matches.len() == before {
            break;
        }
    }
}

fn function_similarity(
    old_module: &NormalizedModule,
    old: &FunctionIr,
    new_module: &NormalizedModule,
    new: &FunctionIr,
) -> f32 {
    function_similarity_score(old_module, old, new_module, new).combined
}

fn function_similarity_score(
    old_module: &NormalizedModule,
    old: &FunctionIr,
    new_module: &NormalizedModule,
    new: &FunctionIr,
) -> SimilarityScore {
    if old.type_id != new.type_id {
        return SimilarityScore::zero();
    }
    if old.operators.is_empty() && new.operators.is_empty() {
        return SimilarityScore::exact();
    }
    if old.operators.is_empty() || new.operators.is_empty() {
        return SimilarityScore::zero();
    }

    let opcode_similarity = opcode_histogram_similarity(old_module, old, new_module, new);
    let immediate_similarity = immediate_histogram_similarity(old_module, old, new_module, new);
    let length_similarity = length_similarity(old.operators.len(), new.operators.len());
    let combined = opcode_similarity * 0.7 + immediate_similarity * 0.15 + length_similarity * 0.15;

    SimilarityScore {
        combined,
        opcode: opcode_similarity,
        immediate: immediate_similarity,
        length: length_similarity,
    }
}

impl SimilarityScore {
    fn zero() -> Self {
        Self {
            combined: 0.0,
            opcode: 0.0,
            immediate: 0.0,
            length: 0.0,
        }
    }

    fn exact() -> Self {
        Self {
            combined: 1.0,
            opcode: 1.0,
            immediate: 1.0,
            length: 1.0,
        }
    }
}

fn similarity_confidence(
    old_function: &FunctionIr,
    new_function: &FunctionIr,
    candidate: &SimilarityCandidate,
) -> f32 {
    let mut confidence = 0.5
        + candidate.score.combined * 0.2
        + candidate.score.opcode * 0.08
        + candidate.score.immediate * 0.04
        + candidate.score.length * 0.03
        + candidate.direct_call_similarity * 0.1;

    if candidate.locals_equal {
        confidence += 0.05;
    }

    if !old_function.direct_calls.is_empty()
        && !new_function.direct_calls.is_empty()
        && candidate.direct_call_similarity == 0.0
    {
        confidence = confidence.min(0.55);
    }

    confidence.clamp(0.5, 0.9)
}

fn direct_call_similarity(old: &FunctionIr, new: &FunctionIr) -> f32 {
    if old.direct_calls.is_empty() && new.direct_calls.is_empty() {
        return 1.0;
    }
    if old.direct_calls.is_empty() || new.direct_calls.is_empty() {
        return 0.0;
    }

    let old_histogram = item_histogram(&old.direct_calls);
    let new_histogram = item_histogram(&new.direct_calls);

    histogram_similarity(
        &old_histogram,
        &new_histogram,
        old.direct_calls.len().max(new.direct_calls.len()),
    )
}

fn item_histogram<T: Clone + Ord>(items: &[T]) -> BTreeMap<T, usize> {
    let mut histogram = BTreeMap::new();
    for item in items {
        *histogram.entry(item.clone()).or_default() += 1;
    }
    histogram
}

fn opcode_histogram_similarity(
    old_module: &NormalizedModule,
    old: &FunctionIr,
    new_module: &NormalizedModule,
    new: &FunctionIr,
) -> f32 {
    let old_histogram = opcode_histogram(old_module, old);
    let new_histogram = opcode_histogram(new_module, new);

    let total_count = old.operators.len().max(new.operators.len());

    histogram_similarity(&old_histogram, &new_histogram, total_count)
}

fn opcode_histogram(module: &NormalizedModule, function: &FunctionIr) -> BTreeMap<String, usize> {
    let mut histogram = BTreeMap::new();
    for operator in &function.operators {
        *histogram
            .entry(opcode_histogram_key(module, operator))
            .or_default() += 1;
    }
    histogram
}

fn immediate_histogram_similarity(
    old_module: &NormalizedModule,
    old: &FunctionIr,
    new_module: &NormalizedModule,
    new: &FunctionIr,
) -> f32 {
    let old_histogram = immediate_histogram(old_module, old);
    let new_histogram = immediate_histogram(new_module, new);

    let total_count = old.operators.len().max(new.operators.len());

    histogram_similarity(&old_histogram, &new_histogram, total_count)
}

fn histogram_similarity<T: Ord>(
    old_histogram: &BTreeMap<T, usize>,
    new_histogram: &BTreeMap<T, usize>,
    total_count: usize,
) -> f32 {
    if total_count == 0 {
        return 1.0;
    }

    let common_count = old_histogram
        .iter()
        .filter_map(|(key, old_count)| {
            new_histogram
                .get(key)
                .map(|new_count| old_count.min(new_count))
        })
        .sum::<usize>();

    common_count as f32 / total_count as f32
}

fn immediate_histogram(
    module: &NormalizedModule,
    function: &FunctionIr,
) -> BTreeMap<String, usize> {
    let mut histogram = BTreeMap::new();
    for operator in &function.operators {
        *histogram
            .entry(immediate_histogram_key(module, operator))
            .or_default() += 1;
    }
    histogram
}

fn opcode_histogram_key(module: &NormalizedModule, operator: &ParsedOperator) -> String {
    match &operator.immediate {
        Immediate::Call(index) | Immediate::RefFunc(index) => {
            module.functions.get(*index as usize).map_or_else(
                || format!("{}:function_index:{index}", operator.opcode.as_str()),
                |target| format!("{}:{}", operator.opcode.as_str(), target.id),
            )
        }
        _ => operator.opcode.as_str().to_owned(),
    }
}

fn immediate_histogram_key(module: &NormalizedModule, operator: &ParsedOperator) -> String {
    let opcode = operator.opcode.as_str();
    match &operator.immediate {
        Immediate::None => opcode.to_owned(),
        Immediate::Call(index) | Immediate::RefFunc(index) => {
            module.functions.get(*index as usize).map_or_else(
                || format!("{opcode}:function_index:{index}"),
                |target| format!("{opcode}:{}", target.id),
            )
        }
        immediate => format!("{opcode}:{}", immediate.as_hash_text()),
    }
}

fn length_similarity(old_len: usize, new_len: usize) -> f32 {
    let max_len = old_len.max(new_len);
    if max_len == 0 {
        return 1.0;
    }

    old_len.min(new_len) as f32 / max_len as f32
}

#[cfg(test)]
mod tests {
    use super::{
        direct_call_similarity, function_similarity, match_functions, unmatched_new_function_ids,
        MatchReason,
    };
    use crate::normalize::normalize_module;
    use crate::parse::parse_module;
    use crate::resolve::resolve_module;

    fn normalized(bytes: &[u8]) -> crate::ir::NormalizedModule {
        let resolved = resolve_module(parse_module(bytes).unwrap());
        normalize_module(&resolved)
    }

    fn make_simple_wasm(with_import: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]);
        if with_import {
            bytes.extend_from_slice(&[0x02, 0x14]);
            bytes.extend_from_slice(b"\x01\x03env\x0cimported_add\x00\x00");
        }
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        bytes.extend_from_slice(&[0x07, 0x07]);
        if with_import {
            bytes.extend_from_slice(b"\x01\x03add\x00\x01");
        } else {
            bytes.extend_from_slice(b"\x01\x03add\x00\x00");
        }
        bytes.extend_from_slice(&[
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
        ]);
        bytes
    }

    fn make_duplicate_empty_functions_wasm() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: [] -> []
            0x03, 0x04, 0x03, 0x00, 0x00, 0x00, // three defined funcs
            0x0a, 0x0a, 0x03, // code section, three bodies
            0x02, 0x00, 0x0b, 0x02, 0x00, 0x0b, 0x02, 0x00, 0x0b,
        ]
    }

    fn make_similar_functions_wasm(first_variant: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]);
        bytes.extend_from_slice(&[0x03, 0x03, 0x02, 0x00, 0x00]);
        bytes.extend_from_slice(&[
            0x0a, 0x11, 0x02, 0x07, 0x00, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x0b, 0x07, 0x00, 0x20,
            0x00,
        ]);
        if first_variant {
            bytes.extend_from_slice(&[0x41, 0x02, 0x6a, 0x0b]);
        } else {
            bytes.extend_from_slice(&[0x41, 0x03, 0x6a, 0x0b]);
        }
        bytes
    }

    fn make_reordered_ops_wasm(first_variant: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f]);
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        bytes.extend_from_slice(&[0x0a, 0x09, 0x01, 0x07, 0x00]);
        if first_variant {
            bytes.extend_from_slice(&[0x20, 0x00, 0x41, 0x01, 0x6a, 0x0b]);
        } else {
            bytes.extend_from_slice(&[0x41, 0x01, 0x20, 0x00, 0x6a, 0x0b]);
        }
        bytes
    }

    fn make_different_call_target_wasm(call_first_import: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        bytes.extend_from_slice(&[
            0x02, 0x11, 0x02, 0x03, b'e', b'n', b'v', 0x01, b'a', 0x00, 0x00, 0x03, b'e', b'n',
            b'v', 0x01, b'b', 0x00, 0x00,
        ]);
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        let target = if call_first_import { 0x00 } else { 0x01 };
        bytes.extend_from_slice(&[0x0a, 0x06, 0x01, 0x04, 0x00, 0x10, target, 0x0b]);
        bytes
    }

    #[test]
    fn matches_canonical_fixture_by_stable_id_not_source_index() {
        let old_module = normalized(include_bytes!("../tests/fixtures/old.wasm"));
        let new_module = normalized(include_bytes!("../tests/fixtures/new.wasm"));

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].old_id, "func:export:add:type:i32,i32->i32");
        assert_eq!(matches[0].new_id, "func:export:add:type:i32,i32->i32");
        assert_eq!(matches[0].reason, MatchReason::SameStableId);
        assert_eq!(matches[0].similarity, 0.7875);
    }

    #[test]
    fn matching_succeeds_with_index_drift() {
        let no_import = make_simple_wasm(false);
        let with_import = make_simple_wasm(true);

        let mod_no_import = normalized(&no_import);
        let mod_with_import = normalized(&with_import);

        let matches = match_functions(&mod_no_import, &mod_with_import);

        assert!(
            !matches.is_empty(),
            "at least the exported function should match"
        );

        let matched_add = matches
            .iter()
            .find(|m| m.old_id == "func:export:add:type:i32,i32->i32")
            .expect("add function should be matched");

        assert_eq!(matched_add.old_source_index, 0);
        assert_eq!(matched_add.new_source_index, 1);
        assert_eq!(matched_add.reason, MatchReason::SameStableId);
        assert_eq!(matched_add.confidence, 1.0);

        let unmatched_new = unmatched_new_function_ids(&mod_with_import, &matches);
        assert_eq!(unmatched_new.len(), 1);
        assert!(
            unmatched_new[0].starts_with("import:"),
            "the unmatched function should be the import"
        );
    }

    #[test]
    fn matches_duplicate_stable_ids_by_occurrence() {
        let wasm = make_duplicate_empty_functions_wasm();
        let old_module = normalized(&wasm);
        let new_module = normalized(&wasm);

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 3);
        assert!(matches.iter().all(|m| m.ambiguous && m.confidence < 1.0));
        assert_eq!(matches[0].old_source_index, 0);
        assert_eq!(matches[0].new_source_index, 0);
        assert_eq!(matches[1].old_source_index, 1);
        assert_eq!(matches[1].new_source_index, 1);
        assert_eq!(matches[2].old_source_index, 2);
        assert_eq!(matches[2].new_source_index, 2);
        assert!(unmatched_new_function_ids(&new_module, &matches).is_empty());
    }

    #[test]
    fn matches_similar_unmatched_functions_by_operator_similarity() {
        let old_module = normalized(&make_similar_functions_wasm(true));
        let new_module = normalized(&make_similar_functions_wasm(false));

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 2);
        assert!(matches
            .iter()
            .any(|m| m.reason == MatchReason::SimilarityFallback));
        assert!(unmatched_new_function_ids(&new_module, &matches).is_empty());
    }

    #[test]
    fn duplicate_modified_functions_keep_every_similarity_pair_ambiguous() {
        let old_module = normalized(
            &wat::parse_str(
                "(module (func (result i32) i32.const 0) (func (result i32) i32.const 0))",
            )
            .unwrap(),
        );
        let new_module = normalized(
            &wat::parse_str(
                "(module (func (result i32) i32.const 1) (func (result i32) i32.const 1))",
            )
            .unwrap(),
        );

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 2);
        for function_match in &matches {
            assert_eq!(function_match.reason, MatchReason::SimilarityFallback);
            assert!(function_match.ambiguous);
            assert_eq!(function_match.confidence, 0.5);
            assert!(function_match.similarity > 0.9);
        }
        assert_eq!(matches[0].old_source_index, 0);
        assert_eq!(matches[0].new_source_index, 0);
        assert_eq!(matches[1].old_source_index, 1);
        assert_eq!(matches[1].new_source_index, 1);
    }

    #[test]
    fn exact_body_ambiguity_survives_into_later_similarity_matching() {
        let module = |values: [i32; 2]| {
            let bodies = values
                .iter()
                .map(|value| format!("(func (result i32) i32.const {value})"))
                .collect::<String>();
            normalized(&wat::parse_str(format!("(module {bodies})")).unwrap())
        };
        for (old_values, new_values) in [([0, 0], [0, 1]), ([0, 1], [0, 0])] {
            let old_module = module(old_values);
            let new_module = module(new_values);

            let matches = match_functions(&old_module, &new_module);

            assert_eq!(matches.len(), 2);
            assert_eq!(
                matches
                    .iter()
                    .filter(|function_match| function_match.reason == MatchReason::SameExactBodyHash)
                    .count(),
                1
            );
            assert_eq!(
                matches
                    .iter()
                    .filter(
                        |function_match| function_match.reason == MatchReason::SimilarityFallback
                    )
                    .count(),
                1
            );
            assert!(
                matches
                    .iter()
                    .all(|function_match| function_match.ambiguous
                        && function_match.confidence == 0.5)
            );
        }
    }

    #[test]
    fn unique_export_anchors_remove_body_duplicates_before_ambiguity_tracking() {
        let old_module = normalized(
            &wat::parse_str(
                "(module (func (export \"kept\") (result i32) i32.const 0) (func (result i32) i32.const 0))",
            )
            .unwrap(),
        );
        let new_module = normalized(
            &wat::parse_str(
                "(module (func (export \"kept\") (result i32) i32.const 0) (func (result i32) i32.const 1))",
            )
            .unwrap(),
        );
        for (old_module, new_module) in [(&old_module, &new_module), (&new_module, &old_module)] {
            let matches = match_functions(old_module, new_module);

            assert_eq!(matches.len(), 2);
            let anchor = matches
                .iter()
                .find(|function_match| function_match.reason == MatchReason::SameStableId)
                .unwrap();
            assert!(!anchor.ambiguous);
            assert_eq!(anchor.confidence, 1.0);
            let fallback = matches
                .iter()
                .find(|function_match| function_match.reason == MatchReason::SimilarityFallback)
                .unwrap();
            assert!(!fallback.ambiguous);
            assert!(fallback.confidence > 0.5);
        }
    }

    #[test]
    fn reordered_three_level_chain_matches_actual_callees_in_both_directions() {
        let old_module = normalized(
            &wat::parse_str(
                "(module
                    (func $leaf (result i32) i32.const 7)
                    (func $mid (result i32) call $leaf)
                    (func $top (result i32) call $mid))",
            )
            .unwrap(),
        );
        let new_module = normalized(
            &wat::parse_str(
                "(module
                    (func $top (result i32) call $mid)
                    (func $leaf (result i32) i32.const 7)
                    (func $mid (result i32) call $leaf))",
            )
            .unwrap(),
        );

        for (old, new, expected) in [
            (&old_module, &new_module, [(0, 1), (1, 2), (2, 0)]),
            (&new_module, &old_module, [(0, 2), (1, 0), (2, 1)]),
        ] {
            let matches = match_functions(old, new);
            assert_eq!(matches.len(), 3);
            for (old_index, new_index) in expected {
                let function_match = matches
                    .iter()
                    .find(|function_match| function_match.old_source_index == old_index)
                    .unwrap();
                assert_eq!(function_match.new_source_index, new_index);
                assert!(!function_match.ambiguous);
                assert!(function_match.reference_context_complete);
                assert!(function_match.confidence >= 0.9);
                assert_ne!(function_match.reason, MatchReason::SimilarityFallback);
            }
        }
    }

    #[test]
    fn deep_reordered_chain_matches_both_directions_without_index_identity() {
        const DEPTH: usize = 128;
        let chain = |reverse: bool| {
            let mut text = String::from("(module ");
            for position in 0..DEPTH {
                let index = if reverse {
                    DEPTH - position - 1
                } else {
                    position
                };
                let body = if index == 0 {
                    "i32.const 7".to_owned()
                } else {
                    format!("call $f{}", index - 1)
                };
                text.push_str(&format!("(func $f{index} (result i32) {body})"));
            }
            text.push(')');
            normalized(&wat::parse_str(text).unwrap())
        };
        let forward = chain(false);
        let reverse = chain(true);

        for (old, new) in [(&forward, &reverse), (&reverse, &forward)] {
            let matches = match_functions(old, new);
            assert_eq!(matches.len(), DEPTH);
            for function_match in matches {
                assert_eq!(
                    function_match.new_source_index as usize,
                    DEPTH - function_match.old_source_index as usize - 1
                );
                assert!(function_match.reference_context_complete);
                assert!(!function_match.ambiguous);
                assert_ne!(function_match.reason, MatchReason::SimilarityFallback);
            }
        }
    }

    #[test]
    fn unused_import_preserves_unexported_multilevel_caller_matches() {
        let old_module = normalized(
            &wat::parse_str(
                "(module
                    (func $leaf (result i32) i32.const 7)
                    (func $mid (result i32) call $leaf)
                    (func $top (result i32) call $mid))",
            )
            .unwrap(),
        );
        let new_module = normalized(
            &wat::parse_str(
                "(module
                    (import \"env\" \"unused\" (func))
                    (func $leaf (result i32) i32.const 7)
                    (func $mid (result i32) call $leaf)
                    (func $top (result i32) call $mid))",
            )
            .unwrap(),
        );
        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 3);
        for function_match in matches {
            assert_eq!(
                function_match.new_source_index,
                function_match.old_source_index + 1
            );
            assert!(function_match.reference_context_complete);
            assert!(!function_match.ambiguous);
            assert_ne!(function_match.reason, MatchReason::SimilarityFallback);
        }
    }

    #[test]
    fn identical_raw_call_indices_with_different_targets_cannot_match_exactly() {
        let old_module = normalized(
            &wat::parse_str(
                "(module
                    (import \"env\" \"a\" (func (result i32)))
                    (import \"env\" \"b\" (func (result i32)))
                    (func (result i32) call 0))",
            )
            .unwrap(),
        );
        let new_module = normalized(
            &wat::parse_str(
                "(module
                    (import \"env\" \"b\" (func (result i32)))
                    (import \"env\" \"a\" (func (result i32)))
                    (func (result i32) call 0))",
            )
            .unwrap(),
        );
        let old_fingerprint = old_module.functions[2].fingerprint.as_ref().unwrap();
        let new_fingerprint = new_module.functions[2].fingerprint.as_ref().unwrap();
        assert_eq!(
            old_fingerprint.exact_body_hash,
            new_fingerprint.exact_body_hash
        );
        assert_ne!(
            old_fingerprint.canonical_body_hash,
            new_fingerprint.canonical_body_hash
        );

        for (old, new) in [(&old_module, &new_module), (&new_module, &old_module)] {
            let matches = match_functions(old, new);
            assert_eq!(matches.len(), 2);
            assert!(matches.iter().all(|function_match| {
                function_match.old_source_index < 2
                    && function_match.reason == MatchReason::SameStableId
            }));
        }
    }

    #[test]
    fn recursive_context_uses_explicitly_ambiguous_similarity_fallback() {
        let module =
            normalized(&wat::parse_str("(module (func $cycle (result i32) call $cycle))").unwrap());
        let matches = match_functions(&module, &module);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].reason, MatchReason::SimilarityFallback);
        assert!(!matches[0].reference_context_complete);
        assert!(matches[0].ambiguous);
        assert_eq!(matches[0].confidence, 0.5);
    }

    #[test]
    fn incomplete_context_on_either_side_prevents_strong_body_matching() {
        let recursive =
            normalized(&wat::parse_str("(module (func $cycle (result i32) call $cycle))").unwrap());
        let acyclic = normalized(
            &wat::parse_str(
                "(module
                    (func $leaf (result i32) i32.const 7)
                    (func (result i32) call $leaf))",
            )
            .unwrap(),
        );
        assert_eq!(
            recursive.functions[0]
                .fingerprint
                .as_ref()
                .unwrap()
                .exact_body_hash,
            acyclic.functions[1]
                .fingerprint
                .as_ref()
                .unwrap()
                .exact_body_hash,
        );
        for (old, new) in [(&recursive, &acyclic), (&acyclic, &recursive)] {
            assert!(match_functions(old, new).is_empty());
        }
    }

    #[test]
    fn unique_export_role_can_anchor_an_incomplete_body_context() {
        let module = normalized(
            &wat::parse_str(
                "(module
                    (func $cycle (result i32) call $cycle)
                    (func (export \"entry\") (result i32) call $cycle))",
            )
            .unwrap(),
        );
        let matches = match_functions(&module, &module);
        let entry = matches
            .iter()
            .find(|function_match| function_match.old_source_index == 1)
            .unwrap();

        assert_eq!(entry.reason, MatchReason::SameStableId);
        assert!(!entry.reference_context_complete);
        assert!(!entry.ambiguous);
        assert_eq!(entry.confidence, 1.0);
    }

    #[test]
    fn changed_unexported_leaf_preserves_two_levels_of_matched_reference_callers() {
        let module = |value| {
            normalized(
                &wat::parse_str(format!(
                    "(module
                        (func $leaf (result i32) i32.const {value})
                        (func $wrapper (result i32) call $leaf)
                        (func $top (result i32) call $wrapper))"
                ))
                .unwrap(),
            )
        };
        let old_module = module(1);
        let new_module = module(2);

        for (old, new) in [(&old_module, &new_module), (&new_module, &old_module)] {
            let matches = match_functions(old, new);
            assert_eq!(matches.len(), 3);
            let leaf = matches
                .iter()
                .find(|candidate| candidate.old_source_index == 0)
                .unwrap();
            assert_eq!(leaf.reason, MatchReason::SimilarityFallback);
            assert!(!leaf.ambiguous);
            for old_index in [1, 2] {
                let caller = matches
                    .iter()
                    .find(|candidate| candidate.old_source_index == old_index)
                    .unwrap();
                assert_eq!(caller.new_source_index, old_index);
                assert_eq!(caller.reason, MatchReason::SameMatchedReferenceBody);
                assert!(!caller.ambiguous);
                assert!(caller.reference_context_complete);
                assert!(caller.confidence <= leaf.confidence.min(0.9));
                assert!(caller.similarity < 0.6);
            }
        }
    }

    #[test]
    fn reference_neighborhood_does_not_substitute_a_different_matched_callee() {
        let old_module = normalized(
            &wat::parse_str(
                "(module
                    (func $changed (result i32) i32.const 1)
                    (func $other (result i32) i32.const 4)
                    (func (result i32) call $changed))",
            )
            .unwrap(),
        );
        let new_module = normalized(
            &wat::parse_str(
                "(module
                    (func $changed (result i32) i32.const 2)
                    (func $other (result i32) i32.const 4)
                    (func (result i32) call $other))",
            )
            .unwrap(),
        );

        for (old, new) in [(&old_module, &new_module), (&new_module, &old_module)] {
            let matches = match_functions(old, new);
            assert_eq!(matches.len(), 2);
            assert!(matches
                .iter()
                .all(|candidate| candidate.old_source_index < 2));
        }
    }

    #[test]
    fn duplicate_reference_wrappers_remain_ambiguous_and_cannot_support_callers() {
        let module = |value| {
            normalized(
                &wat::parse_str(format!(
                    "(module
                        (func $leaf (result i32) i32.const {value})
                        (func $wrapper (result i32) call $leaf)
                        (func $duplicate (result i32) call $leaf)
                        (func $top (result i32) call $wrapper))"
                ))
                .unwrap(),
            )
        };
        let old_module = module(1);
        let new_module = module(2);
        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 3);
        for old_index in [1, 2] {
            let wrapper = matches
                .iter()
                .find(|candidate| candidate.old_source_index == old_index)
                .unwrap();
            assert_eq!(wrapper.reason, MatchReason::SameMatchedReferenceBody);
            assert!(wrapper.ambiguous);
            assert_eq!(wrapper.confidence, 0.5);
        }
        assert!(matches
            .iter()
            .all(|candidate| candidate.old_source_index != 3));
    }

    #[test]
    fn reference_neighborhood_requires_nonreference_immediates_to_stay_exact() {
        let module = |leaf_value, wrapper_value| {
            let mut body = "call $leaf".to_owned();
            for _ in 1..32 {
                body.push_str(" call $leaf i32.add");
            }
            normalized(
                &wat::parse_str(format!(
                    "(module
                        (func $leaf (result i32) i32.const {leaf_value})
                        (func (result i32) {body} i32.const {wrapper_value} drop))"
                ))
                .unwrap(),
            )
        };
        let old_module = module(1, 3);
        let new_module = module(2, 4);
        assert!(
            function_similarity(
                &old_module,
                &old_module.functions[1],
                &new_module,
                &new_module.functions[1],
            ) < 0.6
        );

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].old_source_index, 0);
        assert_eq!(matches[0].new_source_index, 0);
    }

    #[test]
    fn reference_neighborhood_supports_return_call_and_ref_func() {
        for (body, result) in [("return_call $leaf", "i32"), ("ref.func $leaf", "funcref")] {
            let module = |value| {
                normalized(
                    &wat::parse_str(format!(
                        "(module
                            (func $leaf (result i32) i32.const {value})
                            (elem declare func $leaf)
                            (func (result {result}) {body}))"
                    ))
                    .unwrap(),
                )
            };
            let old_module = module(1);
            let new_module = module(2);
            let matches = match_functions(&old_module, &new_module);
            let wrapper = matches
                .iter()
                .find(|candidate| candidate.old_source_index == 1)
                .unwrap();

            assert_eq!(matches.len(), 2);
            assert_eq!(wrapper.new_source_index, 1);
            assert_eq!(wrapper.reason, MatchReason::SameMatchedReferenceBody);
            assert!(!wrapper.ambiguous);
            assert!(wrapper.reference_context_complete);
            assert!(wrapper.confidence <= 0.9);
        }
    }

    #[test]
    fn similarity_ties_at_either_endpoint_are_ambiguous() {
        for (old_bodies, new_bodies) in [(2, 1), (1, 2)] {
            let old_wat = format!(
                "(module {})",
                "(func (result i32) i32.const 0)".repeat(old_bodies)
            );
            let new_wat = format!(
                "(module {})",
                "(func (result i32) i32.const 1)".repeat(new_bodies)
            );
            let old_module = normalized(&wat::parse_str(old_wat).unwrap());
            let new_module = normalized(&wat::parse_str(new_wat).unwrap());

            let matches = match_functions(&old_module, &new_module);

            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].reason, MatchReason::SimilarityFallback);
            assert!(matches[0].ambiguous);
            assert_eq!(matches[0].confidence, 0.5);
        }
    }

    #[test]
    fn lower_scoring_similarity_candidates_do_not_create_ambiguity() {
        let old_module = normalized(
            &wat::parse_str(
                "(module (func (result i32) i32.const 0) (func (result i32) i32.const 0 i32.eqz))",
            )
            .unwrap(),
        );
        let new_module = normalized(
            &wat::parse_str(
                "(module (func (result i32) i32.const 1) (func (result i32) i32.const 1 i32.eqz))",
            )
            .unwrap(),
        );
        let cross_similarity = function_similarity(
            &old_module,
            &old_module.functions[0],
            &new_module,
            &new_module.functions[1],
        );
        assert!(cross_similarity >= 0.6);

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 2);
        for function_match in &matches {
            assert_eq!(function_match.reason, MatchReason::SimilarityFallback);
            assert!(!function_match.ambiguous);
            assert!(function_match.confidence > 0.5);
            assert!(function_match.similarity > cross_similarity);
            assert_eq!(
                function_match.old_source_index,
                function_match.new_source_index
            );
        }
    }

    #[test]
    fn opcode_similarity_matches_reordered_operator_bodies() {
        let old_module = normalized(&make_reordered_ops_wasm(true));
        let new_module = normalized(&make_reordered_ops_wasm(false));

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].reason, MatchReason::SimilarityFallback);
        assert!(matches[0].similarity >= 0.6);
    }

    #[test]
    fn immediate_similarity_penalizes_different_constants() {
        let old_module = normalized(&make_similar_functions_wasm(true));
        let new_module = normalized(&make_similar_functions_wasm(false));

        let old_function = &old_module.functions[1];
        let new_function = &new_module.functions[1];
        let similarity = function_similarity(&old_module, old_function, &new_module, new_function);

        assert!(similarity < 1.0);
        assert!(similarity >= 0.6);
    }

    #[test]
    fn opcode_similarity_does_not_treat_distinct_call_targets_as_identical() {
        let old_module = normalized(&make_different_call_target_wasm(true));
        let new_module = normalized(&make_different_call_target_wasm(false));

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 2);
        assert!(matches
            .iter()
            .all(|m| m.reason == MatchReason::SameStableId));
        assert_eq!(unmatched_new_function_ids(&new_module, &matches).len(), 1);
    }

    #[test]
    fn direct_call_similarity_distinguishes_different_targets() {
        let old_module = normalized(&make_different_call_target_wasm(true));
        let new_module = normalized(&make_different_call_target_wasm(false));

        let old_function = &old_module.functions[2];
        let new_function = &new_module.functions[2];

        assert_eq!(direct_call_similarity(old_function, new_function), 0.0);
    }
}
