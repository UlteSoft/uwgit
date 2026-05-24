//! Function matching using deterministic anchors and fingerprints.
//! Maps functions from old and new modules even under index drift.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum MatchReason {
    SameStableId,
    SameExactBodyHash,
    SameCanonicalBodyHash,
    SimilarityFallback,
}

pub fn match_functions(old: &NormalizedModule, new: &NormalizedModule) -> Vec<FunctionMatch> {
    let mut matches = Vec::new();
    let mut matched_old = BTreeSet::new();
    let mut matched_new = BTreeSet::new();

    match_by_key(
        old,
        new,
        |function| Some(function.id.clone()),
        MatchReason::SameStableId,
        1.0,
        &mut matched_old,
        &mut matched_new,
        &mut matches,
    );
    match_by_key(
        old,
        new,
        |function| {
            if function.kind != FunctionKindIr::Defined {
                return None;
            }
            function.fingerprint.as_ref().map(|fingerprint| {
                format!("{}:{}", function.type_id, fingerprint.exact_body_hash.hex())
            })
        },
        MatchReason::SameExactBodyHash,
        1.0,
        &mut matched_old,
        &mut matched_new,
        &mut matches,
    );
    match_by_key(
        old,
        new,
        |function| {
            if function.kind != FunctionKindIr::Defined {
                return None;
            }
            function.fingerprint.as_ref().map(|fingerprint| {
                format!(
                    "{}:{}",
                    function.type_id,
                    fingerprint.canonical_body_hash.hex()
                )
            })
        },
        MatchReason::SameCanonicalBodyHash,
        0.95,
        &mut matched_old,
        &mut matched_new,
        &mut matches,
    );
    match_by_similarity(
        old,
        new,
        0.6,
        &mut matched_old,
        &mut matched_new,
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
    key: impl Fn(&FunctionIr) -> Option<String>,
    reason: MatchReason,
    confidence: f32,
    matched_old: &mut BTreeSet<usize>,
    matched_new: &mut BTreeSet<usize>,
    matches: &mut Vec<FunctionMatch>,
) {
    let old_candidates = grouped_candidates(old, &key, matched_old);
    let new_candidates = grouped_candidates(new, &key, matched_new);

    for (candidate_key, old_indices) in old_candidates {
        let Some(new_indices) = new_candidates.get(&candidate_key) else {
            continue;
        };
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
                confidence,
                similarity,
                reason,
            });
        }
    }
}

fn grouped_candidates(
    module: &NormalizedModule,
    key: &impl Fn(&FunctionIr) -> Option<String>,
    already_matched: &BTreeSet<usize>,
) -> BTreeMap<String, Vec<usize>> {
    let mut candidates = BTreeMap::<String, Vec<usize>>::new();
    for (index, function) in module.functions.iter().enumerate() {
        if already_matched.contains(&index) {
            continue;
        }
        if let Some(candidate_key) = key(function) {
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

    for candidate in candidates {
        if matched_old.contains(&candidate.old_index) || matched_new.contains(&candidate.new_index)
        {
            continue;
        }

        let old_function = &old.functions[candidate.old_index];
        let new_function = &new.functions[candidate.new_index];

        matched_old.insert(candidate.old_index);
        matched_new.insert(candidate.new_index);
        matches.push(FunctionMatch {
            old_id: old_function.id.clone(),
            new_id: new_function.id.clone(),
            old_source_index: old_function.source_index,
            new_source_index: new_function.source_index,
            confidence: similarity_confidence(old_function, new_function, &candidate),
            similarity: candidate.score.combined,
            reason: MatchReason::SimilarityFallback,
        });
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
