//! Module-, function-, and operator-level diff engine.
//! Consumes Normalized Diff IR and produces structured deltas.
//!
//! Phase 1: diff operators now compare using typed ParsedOperator
//! (Opcode + Immediate) instead of string-based OperatorIr.

use std::collections::BTreeMap;

use crate::export_dependencies::{DependencyGraph, DependencyRoot};
use serde::Serialize;

use crate::ir::{
    ExportIr, ExternalKindIr, FunctionIr, FunctionKindIr, Immediate, ImportIr, ModuleIr,
    NormalizedModule, ParsedOperator, TypeIr, TypeRefIr,
};
use crate::matcher::{
    match_functions, unmatched_new_function_ids, unmatched_old_function_ids, FunctionMatch,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffReport {
    pub old: String,
    pub new: String,
    pub summary: DiffSummary,
    pub function_matches: Vec<FunctionMatch>,
    pub changes: Vec<DiffChange>,
    pub call_binding_notes: Vec<FunctionBindingNotes>,
    pub export_binding_notes: Vec<ExportBindingDelta>,
    pub export_dependency_graph: DependencyGraph,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffSummary {
    pub types_added: usize,
    pub types_removed: usize,
    pub imports_added: usize,
    pub imports_removed: usize,
    pub exports_added: usize,
    pub exports_removed: usize,
    pub functions_added: usize,
    pub functions_removed: usize,
    pub functions_changed: usize,
    pub operator_replacements: usize,
    pub operator_insertions: usize,
    pub operator_deletions: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiffChange {
    TypeAdded { id: String },
    TypeRemoved { id: String },
    ImportAdded { id: String },
    ImportRemoved { id: String },
    ExportAdded { id: String },
    ExportRemoved { id: String },
    FunctionAdded { id: String },
    FunctionRemoved { id: String },
    FunctionChanged { function: FunctionDelta },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FunctionDelta {
    pub old_id: String,
    pub new_id: String,
    pub type_changed: bool,
    pub locals_changed: bool,
    pub direct_calls_changed: bool,
    pub call_bindings: Vec<CallBindingDelta>,
    pub operators: Vec<OperatorDelta>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FunctionBindingNotes {
    pub old_id: String,
    pub new_id: String,
    pub call_bindings: Vec<CallBindingDelta>,
}

/// Positional call/reference evidence, separate from original operand edits.
/// Unique targets require export-independent static dependency evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TargetMatchEvidence {
    pub old_source_index: u32,
    pub new_source_index: u32,
    pub reason: crate::matcher::MatchReason,
    pub confidence: f32,
    pub ambiguous: bool,
    pub reference_context_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportBindingEvidence {
    pub module: String,
    pub name: String,
    pub type_id: String,
    pub exact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetEvidence {
    pub kind: String,
    pub id: String,
    pub source_index: u32,
    pub type_index: u32,
    pub type_id: String,
    pub export_names: Vec<String>,
    pub import: Option<ImportBindingEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallBindingSite {
    pub operator_index: usize,
    pub offset: u64,
    pub opcode: String,
    pub function_index: u32,
    pub target: Option<TargetEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CallBindingDelta {
    pub pairing: String,
    pub relation: String,
    pub target_changed: Option<bool>,
    pub identity_unproven: bool,
    pub match_scope: String,
    pub old: Option<CallBindingSite>,
    pub new: Option<CallBindingSite>,
    pub target_match: Option<TargetMatchEvidence>,
    pub dependency_proof: Option<DependencyRoot>,
}

/// Export membership is paired by name/kind, independently of function roles.
/// Original indices remain evidence even when a separate body candidate moves.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportBindingSite {
    pub export_index: u32,
    pub name: String,
    pub kind: String,
    pub item_index: u32,
    pub exact: bool,
    pub target: Option<TargetEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportBindingDelta {
    pub pairing: String,
    pub relation: String,
    pub target_changed: Option<bool>,
    pub identity_unproven: bool,
    pub match_scope: String,
    pub old: ExportBindingSite,
    pub new: ExportBindingSite,
    pub target_match: Option<TargetMatchEvidence>,
    pub dependency_proof: Option<DependencyRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperatorDelta {
    Replace {
        index: usize,
        old: OperatorRecord,
        new: OperatorRecord,
    },
    Insert {
        index: usize,
        operator: OperatorRecord,
    },
    Delete {
        index: usize,
        operator: OperatorRecord,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorRecord {
    pub offset: u64,
    pub opcode: String,
    pub text: String,
}

pub fn diff_modules(
    old_name: &str,
    old: &NormalizedModule,
    new_name: &str,
    new: &NormalizedModule,
) -> DiffReport {
    let function_matches = match_functions(old, new);
    let mut changes = Vec::new();
    let mut call_binding_notes = Vec::new();

    push_collection_changes(
        ids_by_type(&old.types),
        ids_by_type(&new.types),
        |id| DiffChange::TypeRemoved { id },
        |id| DiffChange::TypeAdded { id },
        &mut changes,
    );
    push_collection_changes(
        ids_by_import(&old.imports),
        ids_by_import(&new.imports),
        |id| DiffChange::ImportRemoved { id },
        |id| DiffChange::ImportAdded { id },
        &mut changes,
    );
    push_collection_changes(
        ids_by_export(&old.exports),
        ids_by_export(&new.exports),
        |id| DiffChange::ExportRemoved { id },
        |id| DiffChange::ExportAdded { id },
        &mut changes,
    );

    for id in unmatched_old_function_ids(old, &function_matches) {
        changes.push(DiffChange::FunctionRemoved { id });
    }
    for id in unmatched_new_function_ids(new, &function_matches) {
        changes.push(DiffChange::FunctionAdded { id });
    }

    let old_functions = old
        .functions
        .iter()
        .map(|function| (function.source_index, function))
        .collect::<BTreeMap<_, _>>();
    let new_functions = new
        .functions
        .iter()
        .map(|function| (function.source_index, function))
        .collect::<BTreeMap<_, _>>();

    let same_module = old.module == new.module;
    // This graph also serves callers in modules without exports. Caller
    // alignment still follows the ordinary matcher; callee conclusions must
    // not use its export roles or consume duplicate candidates.
    let export_dependency_graph = if same_module {
        DependencyGraph::empty()
    } else {
        DependencyGraph::build(old, new)
    };
    let context = BindingContext::new(old, new, &export_dependency_graph, same_module);
    for function_match in &function_matches {
        if same_module {
            continue;
        }
        let old_function = old_functions[&function_match.old_source_index];
        let new_function = new_functions[&function_match.new_source_index];
        let mut bindings = diff_call_bindings(old_function, new_function, old, new, &context);
        if let Some(function_delta) = diff_function(old_function, new_function, &mut bindings) {
            changes.push(DiffChange::FunctionChanged {
                function: function_delta,
            });
        } else if !bindings.is_empty() {
            call_binding_notes.push(FunctionBindingNotes {
                old_id: old_function.id.clone(),
                new_id: new_function.id.clone(),
                call_bindings: bindings,
            });
        }
    }

    let summary = summarize(&changes);
    let export_binding_notes = diff_export_bindings(old, new, &context);
    DiffReport {
        old: old_name.to_owned(),
        new: new_name.to_owned(),
        summary,
        function_matches,
        changes,
        call_binding_notes,
        export_binding_notes,
        export_dependency_graph,
    }
}

fn diff_function(
    old: &FunctionIr,
    new: &FunctionIr,
    call_bindings: &mut Vec<CallBindingDelta>,
) -> Option<FunctionDelta> {
    let type_changed = old.type_id != new.type_id;
    let locals_changed = old.locals != new.locals;
    let direct_calls_changed = old.direct_calls != new.direct_calls;
    let operators = diff_operators(&old.operators, &new.operators);

    if !type_changed
        && !locals_changed
        && !direct_calls_changed
        && operators.is_empty()
        && !call_bindings
            .iter()
            .any(|binding| binding.target_changed == Some(true))
    {
        return None;
    }

    Some(FunctionDelta {
        old_id: old.id.clone(),
        new_id: new.id.clone(),
        type_changed,
        locals_changed,
        direct_calls_changed,
        call_bindings: std::mem::take(call_bindings),
        operators,
    })
}

fn target_function(module: &ModuleIr, index: u32) -> Option<&FunctionIr> {
    module
        .functions
        .get(index as usize)
        .filter(|target| target.source_index == index)
        .or_else(|| {
            module
                .functions
                .iter()
                .find(|target| target.source_index == index)
        })
}

fn binding_site(
    module: &ModuleIr,
    index: usize,
    operator: &ParsedOperator,
) -> Option<CallBindingSite> {
    let function_index = match &operator.immediate {
        Immediate::Call(index) | Immediate::RefFunc(index) => *index,
        _ => return None,
    };
    let target = target_evidence(module, function_index);
    Some(CallBindingSite {
        operator_index: index,
        offset: operator.offset,
        opcode: operator.opcode.as_str().into(),
        function_index,
        target,
    })
}

fn target_evidence(module: &ModuleIr, function_index: u32) -> Option<TargetEvidence> {
    target_function(module, function_index).map(|target| {
        let import = if target.kind == FunctionKindIr::Imported {
            module
                .imports
                .iter()
                .filter(|import| import.kind == ExternalKindIr::Func)
                .nth(function_index as usize)
                .and_then(|import| match &import.type_ref {
                    TypeRefIr::Func { type_id, exact, .. } => Some(ImportBindingEvidence {
                        module: import.module.clone(),
                        name: import.name.clone(),
                        type_id: type_id.clone(),
                        exact: *exact,
                    }),
                    _ => None,
                })
        } else {
            None
        };
        TargetEvidence {
            kind: if target.kind == FunctionKindIr::Imported {
                "imported"
            } else {
                "defined"
            }
            .into(),
            id: target.id.clone(),
            source_index: target.source_index,
            type_index: target.type_index,
            type_id: target.type_id.clone(),
            export_names: target.export_names.clone(),
            import,
        }
    })
}

fn export_site(module: &ModuleIr, export: &ExportIr) -> ExportBindingSite {
    ExportBindingSite {
        export_index: export.source_index,
        name: export.name.clone(),
        kind: export.kind.as_str().into(),
        item_index: export.item_index,
        exact: export.exact,
        target: (export.kind == ExternalKindIr::Func)
            .then(|| target_evidence(module, export.item_index))
            .flatten(),
    }
}

fn export_neutral(module: &NormalizedModule) -> NormalizedModule {
    let mut neutral = module.module.clone();
    neutral.exports.clear();
    let imports: Vec<_> = module
        .imports
        .iter()
        .filter(|import| import.kind == ExternalKindIr::Func)
        .map(|import| match &import.type_ref {
            TypeRefIr::Func { type_id, exact, .. } => Some(ImportBindingEvidence {
                module: import.module.clone(),
                name: import.name.clone(),
                type_id: type_id.clone(),
                exact: *exact,
            }),
            _ => None,
        })
        .collect();
    for function in &mut neutral.functions {
        function.export_names.clear();
        function.fingerprint = None;
        if function.kind == FunctionKindIr::Imported {
            if let Some(Some(binding)) = imports.get(function.source_index as usize) {
                // Import strings may themselves contain identity delimiters.
                // This independent view uses an unambiguous structural key.
                function.id = serde_json::to_string(&binding).expect("import binding serializes");
            }
        }
    }
    crate::normalize::normalize_module(&crate::resolve::resolve_module(crate::ir::ParsedModule {
        module: neutral,
    }))
}

fn match_evidence(candidate: &FunctionMatch) -> TargetMatchEvidence {
    TargetMatchEvidence {
        old_source_index: candidate.old_source_index,
        new_source_index: candidate.new_source_index,
        reason: candidate.reason,
        confidence: candidate.confidence,
        ambiguous: candidate.ambiguous,
        reference_context_complete: candidate.reference_context_complete,
    }
}

fn export_groups(module: &ModuleIr) -> BTreeMap<(String, String), Vec<&ExportIr>> {
    let mut groups = BTreeMap::<_, Vec<_>>::new();
    for export in &module.exports {
        groups
            .entry((export.name.clone(), export.kind.as_str().to_string()))
            .or_default()
            .push(export);
    }
    groups
}

fn reference_free(module: &ModuleIr, index: u32) -> bool {
    target_function(module, index).is_some_and(|function| {
        function
            .operators
            .iter()
            .all(|op| !matches!(op.immediate, Immediate::Call(_) | Immediate::RefFunc(_)))
    })
}

fn import_counts(module: &ModuleIr) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for import in &module.imports {
        if let TypeRefIr::Func { type_id, exact, .. } = &import.type_ref {
            let binding = ImportBindingEvidence {
                module: import.module.clone(),
                name: import.name.clone(),
                type_id: type_id.clone(),
                exact: *exact,
            };
            *counts
                .entry(serde_json::to_string(&binding).expect("binding serializes"))
                .or_default() += 1;
        }
    }
    counts
}

struct BindingContext<'a> {
    proofs: &'a DependencyGraph,
    ambiguous_candidates: BTreeMap<u32, TargetMatchEvidence>,
    old_imports: BTreeMap<String, usize>,
    new_imports: BTreeMap<String, usize>,
}

impl<'a> BindingContext<'a> {
    fn new(
        old: &NormalizedModule,
        new: &NormalizedModule,
        proofs: &'a DependencyGraph,
        same_module: bool,
    ) -> Self {
        let ambiguous_candidates = if same_module {
            BTreeMap::new()
        } else {
            match_functions(&export_neutral(old), &export_neutral(new))
                .iter()
                .filter(|candidate| candidate.ambiguous)
                .map(|candidate| (candidate.old_source_index, match_evidence(candidate)))
                .collect()
        };
        Self {
            proofs,
            ambiguous_candidates,
            old_imports: import_counts(old),
            new_imports: import_counts(new),
        }
    }

    fn unique_imports(&self, old: &ImportBindingEvidence, new: &ImportBindingEvidence) -> bool {
        self.old_imports
            .get(&serde_json::to_string(old).expect("binding serializes"))
            == Some(&1)
            && self
                .new_imports
                .get(&serde_json::to_string(new).expect("binding serializes"))
                == Some(&1)
    }

    fn candidate(
        &self,
        module: &ModuleIr,
        index: u32,
        ambiguous_fallback: bool,
    ) -> (Option<DependencyRoot>, Option<TargetMatchEvidence>) {
        let root = self.proofs.root(index);
        let candidate = root
            .as_ref()
            .map(|root| TargetMatchEvidence {
                old_source_index: root.old_source_index,
                new_source_index: root.new_source_index,
                reason: if target_function(module, index)
                    .is_some_and(|function| function.kind == FunctionKindIr::Imported)
                {
                    crate::matcher::MatchReason::SameStableId
                } else if root.depth == 0 {
                    crate::matcher::MatchReason::SameExactBodyHash
                } else {
                    crate::matcher::MatchReason::SameMatchedReferenceBody
                },
                confidence: if root.depth == 0 { 1.0 } else { 0.9 },
                ambiguous: false,
                reference_context_complete: true,
            })
            .or_else(|| {
                ambiguous_fallback
                    .then(|| self.ambiguous_candidates.get(&index).cloned())
                    .flatten()
            });
        (root, candidate)
    }
}

fn diff_export_bindings(
    old: &NormalizedModule,
    new: &NormalizedModule,
    context: &BindingContext<'_>,
) -> Vec<ExportBindingDelta> {
    if old.module == new.module || old.exports.is_empty() || new.exports.is_empty() {
        return Vec::new();
    }
    let old_groups = export_groups(old);
    let new_groups = export_groups(new);
    let mut notes = Vec::new();
    for (key, old_exports) in old_groups {
        let Some(new_exports) = new_groups.get(&key) else {
            continue;
        };
        let duplicate_name = old_exports.len() != 1 || new_exports.len() != 1;
        for (a, b) in old_exports.iter().zip(new_exports) {
            let old_site = export_site(old, a);
            let new_site = export_site(new, b);
            // Ambiguous leaf candidates explain uncertainty, never uniqueness.
            let (dependency_proof, candidate) = if a.kind == ExternalKindIr::Func {
                context.candidate(
                    old,
                    a.item_index,
                    reference_free(old, a.item_index) && reference_free(new, b.item_index),
                )
            } else {
                (None, None)
            };
            let raw_changed = a.item_index != b.item_index || a.exact != b.exact;
            let (relation, changed) = if duplicate_name {
                if !raw_changed {
                    continue;
                }
                ("ambiguous_target", None)
            } else if a.exact != b.exact {
                // A changed descriptor flag is not an index relocation, even
                // for a manually constructed IR outside valid Core exports.
                ("export_descriptor_changed", None)
            } else {
                match (&old_site.target, &new_site.target) {
                    (Some(x), Some(y)) if x.kind == "imported" && y.kind == "imported" => {
                        match (&x.import, &y.import) {
                            (Some(p), Some(q)) if p != q => ("different_target", Some(true)),
                            (Some(p), Some(q)) if context.unique_imports(p, q) => {
                                if !raw_changed {
                                    continue;
                                }
                                ("candidate_same_target_index_relocated", Some(false))
                            }
                            (Some(_), Some(_)) => {
                                if !raw_changed {
                                    continue;
                                }
                                ("ambiguous_target", None)
                            }
                            _ => ("unresolved_target", None),
                        }
                    }
                    (Some(x), Some(y)) if x.kind != y.kind => ("different_target", Some(true)),
                    (Some(_), Some(_)) => {
                        if let Some(candidate) = candidate.as_ref() {
                            if candidate.ambiguous {
                                if !raw_changed {
                                    continue;
                                }
                                ("ambiguous_target", None)
                            } else if candidate.reference_context_complete
                                && dependency_proof.is_some()
                            {
                                if candidate.new_source_index != b.item_index {
                                    ("different_target", Some(true))
                                } else {
                                    if !raw_changed {
                                        continue;
                                    }
                                    ("candidate_same_target_index_relocated", Some(false))
                                }
                            } else {
                                if !raw_changed {
                                    continue;
                                }
                                ("unresolved_target", None)
                            }
                        } else {
                            if !raw_changed {
                                continue;
                            }
                            ("unresolved_target", None)
                        }
                    }
                    _ => {
                        if !raw_changed {
                            continue;
                        }
                        ("unresolved_target", None)
                    }
                }
            };
            notes.push(ExportBindingDelta {
                pairing: "export_name_kind".into(),
                relation: relation.into(),
                target_changed: changed,
                identity_unproven: true,
                match_scope: "exports_removed_from_candidate_matching".into(),
                old: old_site,
                new: new_site,
                target_match: candidate,
                dependency_proof,
            });
        }
    }
    notes
}

fn diff_call_bindings(
    old: &FunctionIr,
    new: &FunctionIr,
    old_module: &ModuleIr,
    new_module: &ModuleIr,
    context: &BindingContext<'_>,
) -> Vec<CallBindingDelta> {
    let mut bindings = Vec::new();
    let key = |operator: &ParsedOperator| match &operator.immediate {
        Immediate::Call(_) | Immediate::RefFunc(_) => {
            format!("{}:<function-reference>", operator.opcode.as_str())
        }
        _ => operator.display_text(),
    };
    let old_keys = old.operators.iter().map(key).collect::<Vec<_>>();
    let new_keys = new.operators.iter().map(key).collect::<Vec<_>>();
    let alignment = similar::capture_diff_slices(similar::Algorithm::Myers, &old_keys, &new_keys);
    let mut positions = Vec::new();
    for operation in alignment {
        match operation {
            similar::DiffOp::Equal {
                old_index,
                new_index,
                len,
            } => positions.extend((0..len).map(|i| (Some(old_index + i), Some(new_index + i)))),
            similar::DiffOp::Replace {
                old_index,
                old_len,
                new_index,
                new_len,
            } => {
                let shared = old_len.min(new_len);
                positions.extend((0..shared).map(|i| (Some(old_index + i), Some(new_index + i))));
                positions.extend((shared..old_len).map(|i| (Some(old_index + i), None)));
                positions.extend((shared..new_len).map(|i| (None, Some(new_index + i))));
            }
            similar::DiffOp::Delete {
                old_index, old_len, ..
            } => positions.extend((0..old_len).map(|i| (Some(old_index + i), None))),
            similar::DiffOp::Insert {
                new_index, new_len, ..
            } => positions.extend((0..new_len).map(|i| (None, Some(new_index + i)))),
        }
    }
    for (old_index, new_index) in positions {
        let old_site =
            old_index.and_then(|index| binding_site(old_module, index, &old.operators[index]));
        let new_site =
            new_index.and_then(|index| binding_site(new_module, index, &new.operators[index]));
        if old_site.is_none() && new_site.is_none() {
            continue;
        }
        let (dependency_proof, target_match) = old_site
            .as_ref()
            .map(|site| context.candidate(old_module, site.function_index, true))
            .unwrap_or((None, None));
        let (relation, target_changed) = match (&old_site, &new_site) {
            (Some(a), Some(b)) => match (&a.target, &b.target) {
                (Some(old_target), Some(new_target)) => {
                    if old_target.kind == "imported" && new_target.kind == "imported" {
                        match (&old_target.import, &new_target.import) {
                            (Some(old_import), Some(new_import)) if old_import == new_import => {
                                if !context.unique_imports(old_import, new_import) {
                                    ("ambiguous_target", None)
                                } else {
                                    if a.function_index == b.function_index {
                                        continue;
                                    }
                                    ("same_target_index_relocated", Some(false))
                                }
                            }
                            (Some(_), Some(_)) => ("different_target", Some(true)),
                            _ => ("unresolved_target", None),
                        }
                    } else if old_target.kind != new_target.kind {
                        ("different_target", Some(true))
                    } else if let Some(root) = &dependency_proof {
                        if root.new_source_index != b.function_index {
                            ("different_target", Some(true))
                        } else {
                            if a.function_index == b.function_index {
                                continue;
                            }
                            ("same_target_index_relocated", Some(false))
                        }
                    } else if target_match
                        .as_ref()
                        .is_some_and(|candidate| candidate.ambiguous)
                    {
                        ("ambiguous_target", None)
                    } else {
                        // Equal physical indices with only a changed callee
                        // implementation are not a new binding event. Its
                        // body bytes remain in the ordinary complete audit.
                        if a.function_index == b.function_index {
                            continue;
                        }
                        ("unresolved_target", None)
                    }
                }
                _ => ("unresolved_target", None),
            },
            (Some(_), None) => ("site_removed", None),
            (None, Some(_)) => ("site_added", None),
            (None, None) => unreachable!(),
        };
        bindings.push(CallBindingDelta {
            pairing: "opcode_alignment".into(),
            relation: relation.into(),
            target_changed,
            identity_unproven: true,
            match_scope: "exports_removed_from_candidate_matching".into(),
            old: old_site,
            new: new_site,
            target_match,
            dependency_proof,
        });
    }
    bindings
}

fn diff_operators(old: &[ParsedOperator], new: &[ParsedOperator]) -> Vec<OperatorDelta> {
    let old_keys: Vec<(&str, String)> = old
        .iter()
        .map(|op| (op.opcode.as_str(), op.display_text()))
        .collect();
    let new_keys: Vec<(&str, String)> = new
        .iter()
        .map(|op| (op.opcode.as_str(), op.display_text()))
        .collect();

    let old_cmp: Vec<(&str, &str)> = old_keys.iter().map(|(k, t)| (*k, t.as_str())).collect();
    let new_cmp: Vec<(&str, &str)> = new_keys.iter().map(|(k, t)| (*k, t.as_str())).collect();

    let ops = similar::capture_diff_slices(similar::Algorithm::Myers, &old_cmp, &new_cmp);

    let mut deltas = Vec::new();
    for op in ops {
        match op {
            similar::DiffOp::Equal { .. } => {}
            similar::DiffOp::Delete {
                old_index, old_len, ..
            } => {
                for (i, operator) in old.iter().enumerate().skip(old_index).take(old_len) {
                    deltas.push(OperatorDelta::Delete {
                        index: i,
                        operator: operator_record(operator),
                    });
                }
            }
            similar::DiffOp::Insert {
                new_index, new_len, ..
            } => {
                for (i, operator) in new.iter().enumerate().skip(new_index).take(new_len) {
                    deltas.push(OperatorDelta::Insert {
                        index: i,
                        operator: operator_record(operator),
                    });
                }
            }
            similar::DiffOp::Replace {
                old_index,
                new_index,
                old_len,
                new_len,
            } => {
                let shared = old_len.min(new_len);
                for offset in 0..shared {
                    deltas.push(OperatorDelta::Replace {
                        index: old_index + offset,
                        old: operator_record(&old[old_index + offset]),
                        new: operator_record(&new[new_index + offset]),
                    });
                }
                for offset in shared..old_len {
                    deltas.push(OperatorDelta::Delete {
                        index: old_index + offset,
                        operator: operator_record(&old[old_index + offset]),
                    });
                }
                for offset in shared..new_len {
                    deltas.push(OperatorDelta::Insert {
                        index: new_index + offset,
                        operator: operator_record(&new[new_index + offset]),
                    });
                }
            }
        }
    }
    deltas
}

fn operator_record(operator: &ParsedOperator) -> OperatorRecord {
    OperatorRecord {
        offset: operator.offset,
        opcode: operator.opcode.as_str().to_owned(),
        text: operator.display_text(),
    }
}

fn ids_by_type(items: &[TypeIr]) -> Vec<String> {
    items.iter().map(|item| item.id.clone()).collect()
}

fn ids_by_import(items: &[ImportIr]) -> Vec<String> {
    items.iter().map(|item| item.id.clone()).collect()
}

fn ids_by_export(items: &[ExportIr]) -> Vec<String> {
    items
        .iter()
        .map(|item| {
            format!(
                "{}:target:{}:exact:{}",
                item.id, item.item_index, item.exact
            )
        })
        .collect()
}

fn push_collection_changes(
    mut old_ids: Vec<String>,
    mut new_ids: Vec<String>,
    removed: impl Fn(String) -> DiffChange,
    added: impl Fn(String) -> DiffChange,
    changes: &mut Vec<DiffChange>,
) {
    old_ids.sort();
    new_ids.sort();

    let (mut old_index, mut new_index) = (0, 0);
    while old_index < old_ids.len() || new_index < new_ids.len() {
        match (old_ids.get(old_index), new_ids.get(new_index)) {
            (Some(old), Some(new)) if old == new => {
                old_index += 1;
                new_index += 1;
            }
            (Some(old), new) if new.is_none_or(|new| old < new) => {
                changes.push(removed(old.clone()));
                old_index += 1;
            }
            (_, Some(new)) => {
                changes.push(added(new.clone()));
                new_index += 1;
            }
            _ => unreachable!(),
        }
    }
}

fn summarize(changes: &[DiffChange]) -> DiffSummary {
    let mut summary = DiffSummary {
        types_added: 0,
        types_removed: 0,
        imports_added: 0,
        imports_removed: 0,
        exports_added: 0,
        exports_removed: 0,
        functions_added: 0,
        functions_removed: 0,
        functions_changed: 0,
        operator_replacements: 0,
        operator_insertions: 0,
        operator_deletions: 0,
    };

    for change in changes {
        match change {
            DiffChange::TypeAdded { .. } => summary.types_added += 1,
            DiffChange::TypeRemoved { .. } => summary.types_removed += 1,
            DiffChange::ImportAdded { .. } => summary.imports_added += 1,
            DiffChange::ImportRemoved { .. } => summary.imports_removed += 1,
            DiffChange::ExportAdded { .. } => summary.exports_added += 1,
            DiffChange::ExportRemoved { .. } => summary.exports_removed += 1,
            DiffChange::FunctionAdded { .. } => summary.functions_added += 1,
            DiffChange::FunctionRemoved { .. } => summary.functions_removed += 1,
            DiffChange::FunctionChanged { function } => {
                summary.functions_changed += 1;
                for operator in &function.operators {
                    match operator {
                        OperatorDelta::Replace { .. } => summary.operator_replacements += 1,
                        OperatorDelta::Insert { .. } => summary.operator_insertions += 1,
                        OperatorDelta::Delete { .. } => summary.operator_deletions += 1,
                    }
                }
            }
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::{diff_modules, DiffChange, OperatorDelta};
    use crate::normalize::normalize_module;
    use crate::parse::parse_module;
    use crate::resolve::resolve_module;

    #[test]
    fn collection_deltas_preserve_duplicate_multiplicity() {
        let mut changes = Vec::new();
        super::push_collection_changes(
            vec!["same".into(), "same".into()],
            vec!["same".into()],
            |id| DiffChange::ImportRemoved { id },
            |id| DiffChange::ImportAdded { id },
            &mut changes,
        );
        assert_eq!(
            changes,
            vec![DiffChange::ImportRemoved { id: "same".into() }]
        );
    }

    #[test]
    fn export_target_changes_are_reported() {
        let old = normalized_fixture(include_bytes!("../tests/fixtures/old.wasm"));
        let mut new = old.clone();
        new.module.exports[0].item_index += 1;
        let report = diff_modules("old", &old, "new", &new);
        assert_eq!(
            (report.summary.exports_added, report.summary.exports_removed),
            (1, 1)
        );
    }

    fn normalized_fixture(bytes: &[u8]) -> crate::ir::NormalizedModule {
        let resolved = resolve_module(parse_module(bytes).unwrap());
        normalize_module(&resolved)
    }

    fn duplicate_empty_functions_wasm() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: [] -> []
            0x03, 0x04, 0x03, 0x00, 0x00, 0x00, // three defined funcs
            0x0a, 0x0a, 0x03, // code section, three bodies
            0x02, 0x00, 0x0b, 0x02, 0x00, 0x0b, 0x02, 0x00, 0x0b,
        ]
    }

    fn similar_functions_wasm(first_variant: bool) -> Vec<u8> {
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

    #[test]
    fn reports_canonical_fixture_as_single_operator_replacement() {
        let old_module = normalized_fixture(include_bytes!("../tests/fixtures/old.wasm"));
        let new_module = normalized_fixture(include_bytes!("../tests/fixtures/new.wasm"));

        let report = diff_modules("old.wasm", &old_module, "new.wasm", &new_module);

        assert_eq!(report.summary.functions_changed, 1);
        assert_eq!(report.summary.operator_replacements, 1);
        assert_eq!(report.summary.operator_insertions, 0);
        assert_eq!(report.summary.operator_deletions, 0);
        assert_eq!(report.summary.exports_added, 0);
        assert_eq!(report.summary.exports_removed, 0);
        assert_eq!(report.changes.len(), 1);

        let DiffChange::FunctionChanged { function } = &report.changes[0] else {
            panic!("expected changed function");
        };
        assert_eq!(function.old_id, "func:export:add:type:i32,i32->i32");
        assert_eq!(function.new_id, "func:export:add:type:i32,i32->i32");
        assert!(!function.type_changed);
        assert!(!function.locals_changed);
        assert!(!function.direct_calls_changed);
        assert_eq!(function.operators.len(), 1);

        let OperatorDelta::Replace { index, old, new } = &function.operators[0] else {
            panic!("expected replacement");
        };
        assert_eq!(*index, 1);
        assert_eq!(old.text, "LocalGet { local_index: 1 }");
        assert_eq!(new.text, "I32Const { value: 1 }");
    }

    #[test]
    fn reports_no_function_churn_for_identical_duplicate_functions() {
        let wasm = duplicate_empty_functions_wasm();
        let old_module = normalized_fixture(&wasm);
        let new_module = normalized_fixture(&wasm);

        let report = diff_modules("same.wasm", &old_module, "same.wasm", &new_module);

        assert_eq!(report.summary.functions_added, 0);
        assert_eq!(report.summary.functions_removed, 0);
        assert_eq!(report.summary.functions_changed, 0);
        assert_eq!(report.function_matches.len(), 3);
        assert!(report.changes.is_empty());
    }

    #[test]
    fn reports_similar_functions_without_added_or_removed_churn() {
        let old_module = normalized_fixture(&similar_functions_wasm(true));
        let new_module = normalized_fixture(&similar_functions_wasm(false));

        let report = diff_modules("old.wasm", &old_module, "new.wasm", &new_module);

        assert_eq!(report.summary.functions_added, 0);
        assert_eq!(report.summary.functions_removed, 0);
        assert_eq!(report.summary.functions_changed, 1);
        assert_eq!(report.function_matches.len(), 2);
    }
}
