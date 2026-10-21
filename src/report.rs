//! Deterministic output formatting: text summary and structured JSON.
//! Used by both the inspect and diff CLI commands.

use colored::Colorize;
use serde::Serialize;

use crate::diff::{CallBindingDelta, CallBindingSite, DiffChange, DiffReport, OperatorDelta};
use crate::ir::ModuleIr;
use crate::matcher::MatchReason;

#[derive(Serialize)]
struct InspectOutput<'a> {
    module: &'a ModuleIr,
    summary: ModuleSummary,
}

#[derive(Serialize)]
struct ModuleSummary {
    types: usize,
    imports: usize,
    exports: usize,
    functions: usize,
    defined_functions: usize,
    imported_functions: usize,
}

pub fn inspect_json(module: &ModuleIr) -> String {
    let defined_functions = module
        .functions
        .iter()
        .filter(|f| matches!(f.kind, crate::ir::FunctionKindIr::Defined))
        .count();
    let imported_functions = module
        .functions
        .iter()
        .filter(|f| matches!(f.kind, crate::ir::FunctionKindIr::Imported))
        .count();

    let output = InspectOutput {
        module,
        summary: ModuleSummary {
            types: module.types.len(),
            imports: module.imports.len(),
            exports: module.exports.len(),
            functions: module.functions.len(),
            defined_functions,
            imported_functions,
        },
    };

    serde_json::to_string_pretty(&output).expect("serialization should not fail")
}

pub fn diff_json(report: &DiffReport) -> String {
    serde_json::to_string_pretty(report).expect("serialization should not fail")
}

pub fn diff_text(report: &DiffReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "{}: {} -> {}",
        "Diff".bold(),
        safe_text(&report.old),
        safe_text(&report.new)
    ));
    push_summary_lines(report, &mut lines);

    lines.push(format!("{}", "Function matches:".bold()));
    if report.function_matches.is_empty() {
        lines.push("  none".to_owned());
    } else {
        for function_match in &report.function_matches {
            lines.push(format!(
                "  {} {} -> {} confidence={:.2} similarity={:.2} reason={:?} old_index={} new_index={} ambiguous={}",
                "=".cyan(),
                safe_text(&function_match.old_id),
                safe_text(&function_match.new_id),
                function_match.confidence,
                function_match.similarity,
                function_match.reason,
                function_match.old_source_index,
                function_match.new_source_index
                ,function_match.ambiguous
            ));
        }
    }

    lines.push(format!(
        "{}",
        "Function/interface projection changes:".bold()
    ));
    if report.changes.is_empty() {
        lines.push("  none".to_owned());
    } else {
        for change in &report.changes {
            push_change_text(change, &mut lines);
        }
    }

    if !report.call_binding_notes.is_empty() {
        lines.push(
            "Uncertain call/reference bindings (no known function modification counted):".into(),
        );
        for note in &report.call_binding_notes {
            lines.push(format!(
                "  {} -> {}",
                safe_text(&note.old_id),
                safe_text(&note.new_id)
            ));
            push_binding_text(&note.call_bindings, &mut lines);
        }
    }

    if !report.export_binding_notes.is_empty() {
        lines.push("Export binding evidence (export roles excluded; static references require a unique dependency proof; identity unproven):".into());
        for note in &report.export_binding_notes {
            lines.push(format!(
                "  {} ({}) export_index={} -> {} item_index={} -> {} relation={} target_changed={:?} identity_unproven={}",
                safe_text(&note.old.name), note.old.kind, note.old.export_index, note.new.export_index,
                note.old.item_index, note.new.item_index, note.relation, note.target_changed,
                note.identity_unproven,
            ));
            lines.push(format!(
                "    old target={:?}; new target={:?}; independent match={:?}",
                note.old
                    .target
                    .as_ref()
                    .map(|target| safe_text(&format!("{target:?}"))),
                note.new
                    .target
                    .as_ref()
                    .map(|target| safe_text(&format!("{target:?}"))),
                note.target_match
            ));
            if let Some(root) = &note.dependency_proof {
                lines.push(format!(
                    "    dependency proof root {} -> {} depth={}",
                    root.old_source_index, root.new_source_index, root.depth
                ));
            }
        }
    }
    push_dependency_text(report, &mut lines);

    lines.join("\n")
}

pub fn diff_short(report: &DiffReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "{}: {} -> {}",
        "Diff".bold(),
        safe_text(&report.old),
        safe_text(&report.new)
    ));
    push_summary_lines(report, &mut lines);

    let fallback_matches = report
        .function_matches
        .iter()
        .filter(|function_match| function_match.reason == MatchReason::SimilarityFallback)
        .count();
    if fallback_matches > 0 {
        lines.push(format!(
            "  fallback matches: {}",
            fallback_matches.to_string().bright_black()
        ));
    }
    let ambiguous = report
        .function_matches
        .iter()
        .filter(|m| m.ambiguous)
        .count();
    if ambiguous > 0 {
        lines.push(format!(
            "  ambiguous function pairings: {ambiguous} (identity unproven)"
        ));
    }

    if report.changes.is_empty() {
        lines.push(format!("  {}", "function/interface changes: none".green()));
    } else {
        let changed_functions = report
            .changes
            .iter()
            .filter(|change| matches!(change, DiffChange::FunctionChanged { .. }))
            .count();
        lines.push(format!(
            "  function/interface changes: {} total, {} functions",
            report.changes.len().to_string().yellow(),
            changed_functions.to_string().yellow()
        ));
    }

    lines.join("\n")
}

fn push_summary_lines(report: &DiffReport, lines: &mut Vec<String>) {
    lines.push(format!("{}", "Summary:".bold()));
    lines.push(format!(
        "  functions: {} {}, {} {}, {} {}, {} {}",
        report.function_matches.len().to_string().bright_black(),
        "matched",
        report.summary.functions_changed.to_string().yellow(),
        "changed",
        report.summary.functions_added.to_string().green(),
        "added",
        report.summary.functions_removed.to_string().red(),
        "removed"
    ));
    lines.push(format!(
        "  operators: {} {}, {} {}, {} {}",
        report.summary.operator_replacements.to_string().yellow(),
        "replaced",
        report.summary.operator_insertions.to_string().green(),
        "inserted",
        report.summary.operator_deletions.to_string().red(),
        "deleted"
    ));
    let binding_changes = report
        .changes
        .iter()
        .filter_map(|change| match change {
            DiffChange::FunctionChanged { function } => Some(&function.call_bindings),
            _ => None,
        })
        .flatten()
        .filter(|binding| binding.target_changed == Some(true))
        .count();
    if binding_changes > 0 {
        lines.push(format!("  call/reference target changes: {binding_changes} (alignment-relative; identity unproven)"));
    }
    if !report.call_binding_notes.is_empty() {
        lines.push(format!(
            "  uncertain call/reference binding notes: {} (not counted as known modifications)",
            report.call_binding_notes.len()
        ));
    }
    if !report.export_binding_notes.is_empty() {
        let notes = &report.export_binding_notes;
        lines.push(format!("  export bindings: {} evidence records, {} candidate relocations, {} different targets, {} unproved (identity unproven)",
            notes.len(), notes.iter().filter(|note| note.target_changed == Some(false)).count(),
            notes.iter().filter(|note| note.target_changed == Some(true)).count(),
            notes.iter().filter(|note| note.target_changed.is_none()).count()));
    }
    if report
        .export_binding_notes
        .iter()
        .any(|note| note.dependency_proof.is_some())
    {
        lines.push(format!("  export dependency proof: {} unique static nodes (identity unproven; no runtime equivalence claim)",
            report.export_dependency_graph.nodes.len()));
    }
    let call_proofs = call_bindings(report)
        .filter(|binding| binding.dependency_proof.is_some())
        .count();
    if call_proofs > 0 {
        lines.push(format!("  call/reference dependency proofs: {call_proofs} roots in export_dependency_graph (export roles excluded; identity unproven)"));
    }

    if report.summary.types_added > 0
        || report.summary.types_removed > 0
        || report.summary.imports_added > 0
        || report.summary.imports_removed > 0
        || report.summary.exports_added > 0
        || report.summary.exports_removed > 0
        || report
            .export_binding_notes
            .iter()
            .any(|note| note.target_changed != Some(false))
    {
        lines.push(format!(
            "  abi: types {} {}, imports {} {}, exports {} {}",
            format!("+{}", report.summary.types_added).green(),
            format!("-{}", report.summary.types_removed).red(),
            format!("+{}", report.summary.imports_added).green(),
            format!("-{}", report.summary.imports_removed).red(),
            format!("+{}", report.summary.exports_added).green(),
            format!("-{}", report.summary.exports_removed).red(),
        ));
        if report.summary.exports_added > 0 || report.summary.exports_removed > 0 {
            lines.push("  export counts are raw target keys, including index movement; see export binding evidence".into());
        }
    } else {
        lines.push(format!(
            "  {}",
            "abi: unchanged in the listed type/import/export projection; see complete binary audit"
                .green()
        ));
    }
}

fn call_bindings(report: &DiffReport) -> impl Iterator<Item = &CallBindingDelta> {
    report
        .changes
        .iter()
        .filter_map(|change| match change {
            DiffChange::FunctionChanged { function } => Some(function.call_bindings.iter()),
            _ => None,
        })
        .flatten()
        .chain(
            report
                .call_binding_notes
                .iter()
                .flat_map(|note| &note.call_bindings),
        )
}

fn push_dependency_text(report: &DiffReport, lines: &mut Vec<String>) {
    use std::collections::{BTreeMap, BTreeSet};
    let nodes: BTreeMap<_, _> = report
        .export_dependency_graph
        .nodes
        .iter()
        .map(|node| (node.old_source_index, node))
        .collect();
    let mut pending: Vec<_> = report
        .export_binding_notes
        .iter()
        .filter_map(|note| {
            note.dependency_proof
                .as_ref()
                .map(|root| root.old_source_index)
        })
        .collect();
    pending.extend(call_bindings(report).filter_map(|binding| {
        binding
            .dependency_proof
            .as_ref()
            .map(|root| root.old_source_index)
    }));
    let mut selected = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if selected.insert(index) {
            if let Some(node) = nodes.get(&index) {
                pending.extend(node.references.iter().map(|reference| reference.old_target));
            }
        }
    }
    if selected.is_empty() {
        return;
    }
    lines.push("Export dependency proof witnesses (shared with call/reference roots; typed bodies and static references only; identity unproven):".into());
    let mut selected: Vec<_> = selected
        .iter()
        .filter_map(|index| nodes.get(index).copied())
        .collect();
    selected.sort_by_key(|node| (node.depth, node.old_source_index));
    for node in selected {
        lines.push(format!(
            "  {} -> {} {} depth={} type={} import={:?}",
            node.old_source_index,
            node.new_source_index,
            node.kind,
            node.depth,
            safe_text(&node.type_id),
            node.import.as_ref().map(|binding| safe_text(
                &serde_json::to_string(binding).expect("binding serializes")
            ))
        ));
        for reference in &node.references {
            lines.push(format!(
                "    {} old operator[{}] @{} target={} -> new operator[{}] @{} target={}",
                safe_text(&reference.opcode),
                reference.old_operator_index,
                reference.old_offset,
                reference.old_target,
                reference.new_operator_index,
                reference.new_offset,
                reference.new_target
            ));
        }
    }
}

fn push_change_text(change: &DiffChange, lines: &mut Vec<String>) {
    match change {
        DiffChange::TypeAdded { id } => {
            lines.push(format!("  {}", format!("+ type {}", safe_text(id)).green()))
        }
        DiffChange::TypeRemoved { id } => {
            lines.push(format!("  {}", format!("- type {}", safe_text(id)).red()))
        }
        DiffChange::ImportAdded { id } => lines.push(format!(
            "  {}",
            format!("+ import {}", safe_text(id)).green()
        )),
        DiffChange::ImportRemoved { id } => {
            lines.push(format!("  {}", format!("- import {}", safe_text(id)).red()))
        }
        DiffChange::ExportAdded { id } => lines.push(format!(
            "  {}",
            format!("+ export {}", safe_text(id)).green()
        )),
        DiffChange::ExportRemoved { id } => {
            lines.push(format!("  {}", format!("- export {}", safe_text(id)).red()))
        }
        DiffChange::FunctionAdded { id } => lines.push(format!(
            "  {}",
            format!("+ function {}", safe_text(id)).green()
        )),
        DiffChange::FunctionRemoved { id } => lines.push(format!(
            "  {}",
            format!("- function {}", safe_text(id)).red()
        )),
        DiffChange::FunctionChanged { function } => {
            lines.push(format!(
                "  {} {} -> {}",
                "~".yellow(),
                safe_text(&function.old_id),
                safe_text(&function.new_id)
            ));
            if function.type_changed {
                lines.push(format!("    {} type signature changed", "~".yellow()));
            }
            if function.locals_changed {
                lines.push(format!("    {} locals changed", "~".yellow()));
            }
            if function.direct_calls_changed {
                lines.push(format!(
                    "    {} raw direct-call indices changed",
                    "~".yellow()
                ));
            }
            push_binding_text(&function.call_bindings, lines);
            for operator in &function.operators {
                match operator {
                    OperatorDelta::Replace { index, old, new } => lines.push(format!(
                        "    {} op[{}]: {} -> {}",
                        "~".yellow(),
                        index,
                        old.text.as_str().red(),
                        new.text.as_str().green()
                    )),
                    OperatorDelta::Insert { index, operator } => {
                        lines.push(format!(
                            "    {} op[{}]: {}",
                            "+".green(),
                            index,
                            operator.text
                        ));
                    }
                    OperatorDelta::Delete { index, operator } => {
                        lines.push(format!(
                            "    {} op[{}]: {}",
                            "-".red(),
                            index,
                            operator.text
                        ));
                    }
                }
            }
        }
    }
}

fn binding_site_text(site: &Option<CallBindingSite>) -> String {
    let Some(site) = site else {
        return "no aligned reference site".into();
    };
    let target = site.target.as_ref().map_or_else(
        || "unresolved target".into(),
        |target| {
            if let Some(import) = &target.import {
                format!(
                    "import {:?}.{:?} type={} exact={}",
                    safe_text(&import.module),
                    safe_text(&import.name),
                    safe_text(&import.type_id),
                    import.exact
                )
            } else {
                format!(
                    "{} {} type={} exports={:?}",
                    target.kind,
                    safe_text(&target.id),
                    safe_text(&target.type_id),
                    target
                        .export_names
                        .iter()
                        .map(|name| safe_text(name))
                        .collect::<Vec<_>>()
                )
            }
        },
    );
    format!(
        "op[{}] @{} {} function_index={} [{}]",
        site.operator_index, site.offset, site.opcode, site.function_index, target
    )
}

fn push_binding_text(bindings: &[CallBindingDelta], lines: &mut Vec<String>) {
    for binding in bindings {
        lines.push(format!(
            "    binding {}: {} -> {}; target_changed={} pairing={} identity_unproven={} match_scope={}",
            binding.relation,
            binding_site_text(&binding.old),
            binding_site_text(&binding.new),
            match binding.target_changed {
                Some(true) => "true",
                Some(false) => "false",
                None => "unknown",
            },
            binding.pairing,
            binding.identity_unproven,
            binding.match_scope,
        ));
        if let Some(candidate) = &binding.target_match {
            lines.push(format!("      callee candidate {} -> {} reason={:?} confidence={:.2} ambiguous={} reference_context_complete={}",candidate.old_source_index,candidate.new_source_index,candidate.reason,candidate.confidence,candidate.ambiguous,candidate.reference_context_complete));
        }
        if let Some(root) = &binding.dependency_proof {
            lines.push(format!("      call/reference dependency proof root {} -> {} depth={} graph=export_dependency_graph", root.old_source_index, root.new_source_index, root.depth));
        }
    }
}

// Names in Wasm are arbitrary UTF-8. Preserve them without allowing embedded
// terminal controls to forge report lines or color escapes.
fn safe_text(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                ch.escape_default().to_string()
            } else {
                ch.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{diff_json, diff_short, diff_text};
    use crate::diff::diff_modules;
    use crate::normalize::normalize_module;
    use crate::parse::parse_module;
    use crate::resolve::resolve_module;

    fn normalized(bytes: &[u8]) -> crate::ir::NormalizedModule {
        let resolved = resolve_module(parse_module(bytes).unwrap());
        normalize_module(&resolved)
    }

    #[test]
    fn textual_names_cannot_inject_report_lines() {
        assert_eq!(super::safe_text("name\n\u{1b}[31m"), r"name\n\u{1b}[31m");
        assert_eq!(super::safe_text("name\u{202e}"), r"name\u{202e}");
    }

    #[test]
    fn renders_canonical_text_and_json_diff() {
        let old_module = normalized(include_bytes!("../tests/fixtures/old.wasm"));
        let new_module = normalized(include_bytes!("../tests/fixtures/new.wasm"));
        let report = diff_modules("old.wasm", &old_module, "new.wasm", &new_module);

        // make sure color codes are stripped from the output for test
        colored::control::set_override(false);
        let text = diff_text(&report);
        assert!(text.contains("abi: unchanged"));
        assert!(text.contains("~ op[1]: LocalGet { local_index: 1 } -> I32Const { value: 1 }"));

        let json = diff_json(&report);
        assert!(json.contains("\"function_matches\""));
        assert!(json.contains("\"kind\": \"replace\""));
        assert!(json.contains("LocalGet { local_index: 1 }"));
        assert!(json.contains("I32Const { value: 1 }"));
    }

    #[test]
    fn renders_short_diff_without_match_or_operator_details() {
        let old_module = normalized(include_bytes!("../tests/fixtures/old.wasm"));
        let new_module = normalized(include_bytes!("../tests/fixtures/new.wasm"));
        let report = diff_modules("old.wasm", &old_module, "new.wasm", &new_module);

        colored::control::set_override(false);
        let short = diff_short(&report);

        assert!(short.contains("Summary:"));
        assert!(short.contains("1 matched, 1 changed"));
        assert!(short.contains("changes: 1 total, 1 functions"));
        assert!(!short.contains("Function matches:"));
        assert!(!short.contains("~ op[1]:"));
    }
}
