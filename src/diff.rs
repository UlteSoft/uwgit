//! Module-, function-, and operator-level diff engine.
//! Consumes Normalized Diff IR and produces structured deltas.
//!
//! Phase 1: diff operators now compare using typed ParsedOperator
//! (Opcode + Immediate) instead of string-based OperatorIr.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::ir::{ExportIr, FunctionIr, ImportIr, NormalizedModule, ParsedOperator, TypeIr};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionDelta {
    pub old_id: String,
    pub new_id: String,
    pub type_changed: bool,
    pub locals_changed: bool,
    pub direct_calls_changed: bool,
    pub operators: Vec<OperatorDelta>,
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

    for function_match in &function_matches {
        let old_function = old_functions[&function_match.old_source_index];
        let new_function = new_functions[&function_match.new_source_index];
        if let Some(function_delta) = diff_function(old_function, new_function) {
            changes.push(DiffChange::FunctionChanged {
                function: function_delta,
            });
        }
    }

    let summary = summarize(&changes);
    DiffReport {
        old: old_name.to_owned(),
        new: new_name.to_owned(),
        summary,
        function_matches,
        changes,
    }
}

fn diff_function(old: &FunctionIr, new: &FunctionIr) -> Option<FunctionDelta> {
    let type_changed = old.type_id != new.type_id;
    let locals_changed = old.locals != new.locals;
    let direct_calls_changed = old.direct_calls != new.direct_calls;
    let operators = diff_operators(&old.operators, &new.operators);

    if !type_changed && !locals_changed && !direct_calls_changed && operators.is_empty() {
        return None;
    }

    Some(FunctionDelta {
        old_id: old.id.clone(),
        new_id: new.id.clone(),
        type_changed,
        locals_changed,
        direct_calls_changed,
        operators,
    })
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
    items.iter().map(|item| item.id.clone()).collect()
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

    for id in old_ids.iter().filter(|id| !new_ids.contains(id)) {
        changes.push(removed(id.clone()));
    }
    for id in new_ids.iter().filter(|id| !old_ids.contains(id)) {
        changes.push(added(id.clone()));
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
}
