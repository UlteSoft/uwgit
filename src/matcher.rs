//! Function matching using deterministic anchors and fingerprints.
//! Maps functions from old and new modules even under index drift.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::ir::{FunctionIr, NormalizedModule};

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

    matches.sort_by(|left, right| {
        left.old_id
            .cmp(&right.old_id)
            .then_with(|| left.new_id.cmp(&right.new_id))
    });
    matches
}

pub fn unmatched_old_function_ids(
    old: &NormalizedModule,
    matches: &[FunctionMatch],
) -> Vec<String> {
    let matched = matches
        .iter()
        .map(|function_match| function_match.old_id.as_str())
        .collect::<BTreeSet<_>>();

    old.functions
        .iter()
        .filter(|function| !matched.contains(function.id.as_str()))
        .map(|function| function.id.clone())
        .collect()
}

pub fn unmatched_new_function_ids(
    new: &NormalizedModule,
    matches: &[FunctionMatch],
) -> Vec<String> {
    let matched = matches
        .iter()
        .map(|function_match| function_match.new_id.as_str())
        .collect::<BTreeSet<_>>();

    new.functions
        .iter()
        .filter(|function| !matched.contains(function.id.as_str()))
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
    let old_candidates = unique_candidates(old, &key, matched_old);
    let new_candidates = unique_candidates(new, &key, matched_new);

    for (candidate_key, old_index) in old_candidates {
        let Some(new_index) = new_candidates.get(&candidate_key) else {
            continue;
        };
        if matched_old.contains(&old_index) || matched_new.contains(new_index) {
            continue;
        }

        let old_function = &old.functions[old_index];
        let new_function = &new.functions[*new_index];
        let similarity = function_similarity(old_function, new_function);

        matched_old.insert(old_index);
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

fn unique_candidates(
    module: &NormalizedModule,
    key: &impl Fn(&FunctionIr) -> Option<String>,
    already_matched: &BTreeSet<usize>,
) -> BTreeMap<String, usize> {
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
        .into_iter()
        .filter_map(|(candidate_key, indices)| {
            if indices.len() == 1 {
                Some((candidate_key, indices[0]))
            } else {
                None
            }
        })
        .collect()
}

fn function_similarity(old: &FunctionIr, new: &FunctionIr) -> f32 {
    if old.type_id != new.type_id {
        return 0.0;
    }
    if old.operators.is_empty() && new.operators.is_empty() {
        return 1.0;
    }

    let equal_count = old
        .operators
        .iter()
        .zip(&new.operators)
        .filter(|(old_operator, new_operator)| old_operator == new_operator)
        .count();
    let total_count = old.operators.len().max(new.operators.len());
    equal_count as f32 / total_count as f32
}

#[cfg(test)]
mod tests {
    use super::{match_functions, unmatched_new_function_ids, MatchReason};
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

    #[test]
    fn matches_canonical_fixture_by_stable_id_not_source_index() {
        let old_module = normalized(include_bytes!("../tests/fixtures/old.wasm"));
        let new_module = normalized(include_bytes!("../tests/fixtures/new.wasm"));

        let matches = match_functions(&old_module, &new_module);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].old_id, "func:export:add:type:i32,i32->i32");
        assert_eq!(matches[0].new_id, "func:export:add:type:i32,i32->i32");
        assert_eq!(matches[0].reason, MatchReason::SameStableId);
        assert_eq!(matches[0].similarity, 0.75);
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
}
