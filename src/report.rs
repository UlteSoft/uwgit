//! Deterministic output formatting: text summary and structured JSON.
//! Used by both the inspect and diff CLI commands.

use colored::Colorize;
use serde::Serialize;

use crate::diff::{DiffChange, DiffReport, OperatorDelta};
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
        report.old,
        report.new
    ));
    push_summary_lines(report, &mut lines);

    lines.push(format!("{}", "Function matches:".bold()));
    if report.function_matches.is_empty() {
        lines.push("  none".to_owned());
    } else {
        for function_match in &report.function_matches {
            lines.push(format!(
                "  {} {} -> {} confidence={:.2} similarity={:.2} reason={:?} old_index={} new_index={}",
                "=".cyan(),
                function_match.old_id,
                function_match.new_id,
                function_match.confidence,
                function_match.similarity,
                function_match.reason,
                function_match.old_source_index,
                function_match.new_source_index
            ));
        }
    }

    lines.push(format!("{}", "Changes:".bold()));
    if report.changes.is_empty() {
        lines.push("  none".to_owned());
    } else {
        for change in &report.changes {
            push_change_text(change, &mut lines);
        }
    }

    lines.join("\n")
}

pub fn diff_short(report: &DiffReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "{}: {} -> {}",
        "Diff".bold(),
        report.old,
        report.new
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

    if report.changes.is_empty() {
        lines.push(format!("  {}", "changes: none".green()));
    } else {
        let changed_functions = report
            .changes
            .iter()
            .filter(|change| matches!(change, DiffChange::FunctionChanged { .. }))
            .count();
        lines.push(format!(
            "  changes: {} total, {} functions",
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

    if report.summary.types_added > 0
        || report.summary.types_removed > 0
        || report.summary.imports_added > 0
        || report.summary.imports_removed > 0
        || report.summary.exports_added > 0
        || report.summary.exports_removed > 0
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
    } else {
        lines.push(format!("  {}", "abi: unchanged".green()));
    }
}

fn push_change_text(change: &DiffChange, lines: &mut Vec<String>) {
    match change {
        DiffChange::TypeAdded { id } => lines.push(format!("  {}", format!("+ type {id}").green())),
        DiffChange::TypeRemoved { id } => lines.push(format!("  {}", format!("- type {id}").red())),
        DiffChange::ImportAdded { id } => {
            lines.push(format!("  {}", format!("+ import {id}").green()))
        }
        DiffChange::ImportRemoved { id } => {
            lines.push(format!("  {}", format!("- import {id}").red()))
        }
        DiffChange::ExportAdded { id } => {
            lines.push(format!("  {}", format!("+ export {id}").green()))
        }
        DiffChange::ExportRemoved { id } => {
            lines.push(format!("  {}", format!("- export {id}").red()))
        }
        DiffChange::FunctionAdded { id } => {
            lines.push(format!("  {}", format!("+ function {id}").green()))
        }
        DiffChange::FunctionRemoved { id } => {
            lines.push(format!("  {}", format!("- function {id}").red()))
        }
        DiffChange::FunctionChanged { function } => {
            lines.push(format!(
                "  {} {} -> {}",
                "~".yellow(),
                function.old_id,
                function.new_id
            ));
            if function.type_changed {
                lines.push(format!("    {} type signature changed", "~".yellow()));
            }
            if function.locals_changed {
                lines.push(format!("    {} locals changed", "~".yellow()));
            }
            if function.direct_calls_changed {
                lines.push(format!("    {} direct calls changed", "~".yellow()));
            }
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
