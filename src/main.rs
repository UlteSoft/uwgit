pub mod analysis;
pub use wasm_git::audit;
mod diff;
mod fingerprint;
pub mod ir;
mod matcher;
mod normalize;
mod output;
pub mod parse;
mod report;
mod repository;
mod resolve;

use clap::{Parser, ValueEnum};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Parser)]
struct InspectArgs {
    filepath: String,
    #[arg(long)]
    json: bool,
    /// Read a committed revision instead of a filesystem path.
    #[arg(long)]
    repo: Option<String>,
}

#[derive(Debug, Parser)]
struct DiffArgs {
    old_path: String,
    new_path: String,
    #[arg(long, value_enum, default_value_t = DiffFormat::Text)]
    format: DiffFormat,
    #[arg(long)]
    short: bool,
    /// Interpret OLD and NEW as repository revisions.
    #[arg(long)]
    repo: Option<String>,
}

#[derive(Debug, Parser)]
struct PatchArgs {
    old_path: String,
    new_path: String,
    /// Create a new patch file; existing destinations are never replaced.
    #[arg(long)]
    output: String,
    /// Interpret OLD and NEW as revisions in one repository snapshot.
    #[arg(long)]
    repo: Option<String>,
}

#[derive(Debug, Parser)]
struct ApplyArgs {
    old_path: String,
    patch_path: String,
    /// Publish verified bytes to a new file.
    #[arg(long, required_unless_present = "check", conflicts_with = "check")]
    output: Option<String>,
    /// Verify and audit the result without writing a file.
    #[arg(long)]
    check: bool,
    /// Interpret OLD as a repository revision; PATCH is always a file.
    #[arg(long)]
    repo: Option<String>,
}

#[derive(Debug, Parser)]
struct TraceArgs {
    repo_dir: String,
    revision: String,
    /// Nonempty half-open byte range in the selected revision: START:END.
    #[arg(long, required_unless_present = "path", conflicts_with = "path")]
    range: Option<String>,
    /// Exact audit section/region path in the selected revision, or module.
    #[arg(long)]
    path: Option<String>,
    /// Global parent-edge processing budget; zero returns explicit boundaries.
    #[arg(long, default_value_t = 256)]
    max_edges: usize,
    /// Global input-byte comparison budget; snapshot loading is separate.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_bytes: usize,
}

struct Input {
    bytes: Vec<u8>,
    origin: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DiffFormat {
    Text,
    Json,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }
    let result = match args[1].as_str() {
        "inspect" => cmd_inspect(&args[2..]),
        "diff" => cmd_diff(&args[2..]),
        "patch" => cmd_patch(&args[2..]),
        "apply" => cmd_apply(&args[2..]),
        "trace" => cmd_trace(&args[2..]),
        "init" | "commit" | "log" | "show" | "checkout" | "branch" | "switch" | "clone"
        | "bundle" | "unbundle" | "fsck" | "merge" | "merge-base" => repository::run(&args[1..]),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(String::new())
        }
        other => {
            eprintln!("unknown command: {other}");
            print_usage();
            std::process::exit(1);
        }
    };
    match result {
        Ok(output) if !output.is_empty() => {
            let conflict = args[1] == "merge"
                && serde_json::from_str::<Value>(&output)
                    .is_ok_and(|report| report["status"] == "conflict");
            println!("{output}");
            if conflict {
                std::process::exit(2);
            }
        }
        Ok(_) => {}
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

fn cmd_inspect(args: &[String]) -> Result<String, String> {
    if args.is_empty() {
        return Err("usage: wasm-git inspect <FILE|REVISION> [--repo DIR] [--json]".into());
    }
    let parsed = match InspectArgs::try_parse_from(
        std::iter::once("wasm-git inspect").chain(args.iter().map(String::as_str)),
    ) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(error.to_string());
        }
        Err(error) => return Err(error.to_string()),
    };
    let inputs = read_inputs(&[&parsed.filepath], parsed.repo.as_deref())?;
    let input = &inputs[0];
    let audit =
        audit::inspect(&input.bytes).map_err(|error| format!("wasm parse error: {error}"))?;
    let (mut output, status) = match normalize_bytes(&input.bytes) {
        Ok(module) => (
            serde_json::from_str::<Value>(&report::inspect_json(&module)).unwrap(),
            json!({"available": true}),
        ),
        Err(error) => (
            json!({"module": null, "summary": null}),
            json!({"available": false, "reason": error}),
        ),
    };
    output["schema_version"] = json!(1);
    output["function_analysis"] = status;
    output["input"] = input.origin.clone();
    output["audit"] = serde_json::to_value(audit).map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&output).map_err(|error| error.to_string())
}

fn cmd_diff(args: &[String]) -> Result<String, String> {
    if args.len() < 2
        && !args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err("usage: wasm-git diff <OLD> <NEW> [--repo DIR] [--format text|json]".into());
    }
    let parsed = match DiffArgs::try_parse_from(
        std::iter::once("wasm-git diff").chain(args.iter().map(String::as_str)),
    ) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(error.to_string());
        }
        Err(error) => return Err(error.to_string()),
    };
    let inputs = read_inputs(
        &[&parsed.old_path, &parsed.new_path],
        parsed.repo.as_deref(),
    )?;
    let old = &inputs[0].bytes;
    let new = &inputs[1].bytes;
    let bindings = if parsed.repo.is_some() {
        format!(
            "Resolved repository inputs: old={}, new={}\n",
            inputs[0].origin["commit"].as_str().unwrap(),
            inputs[1].origin["commit"].as_str().unwrap()
        )
    } else {
        String::new()
    };
    let audit = audit::compare(old, new).map_err(|error| format!("wasm parse error: {error}"))?;
    let comparison = normalize_bytes(old).and_then(|old_module| {
        normalize_bytes(new).map(|new_module| {
            diff::diff_modules(&parsed.old_path, &old_module, &parsed.new_path, &new_module)
        })
    });
    if parsed.short {
        let functions = match &comparison {
            Ok(report) => report::diff_short(report),
            Err(error) => format!("Function comparison unavailable: {error}"),
        };
        return Ok(format!(
            "{bindings}{functions}\nBinary audit: {} ({} edit groups, exact_minimal={})\nDiagnostics: old={}, new={}",
            if audit.changed { "changed" } else { "identical" },
            audit.edits.len(), audit.exact_minimal,
            audit.old.diagnostics.len(), audit.new.diagnostics.len()
        ));
    }
    match parsed.format {
        DiffFormat::Json => {
            let (mut output, status) = match comparison {
                Ok(report) => (
                    serde_json::from_str::<Value>(&report::diff_json(&report)).unwrap(),
                    json!({"available": true}),
                ),
                Err(error) => (
                    json!({"old": parsed.old_path, "new": parsed.new_path,
                        "summary": null, "function_matches": [], "changes": []}),
                    json!({"available": false, "reason": error}),
                ),
            };
            output["schema_version"] = json!(1);
            output["binary_changed"] = json!(audit.changed);
            output["function_analysis"] = status;
            output["inputs"] = json!({"old": &inputs[0].origin, "new": &inputs[1].origin});
            output["audit"] = serde_json::to_value(audit).map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&output).map_err(|error| error.to_string())
        }
        DiffFormat::Text => {
            let functions = match comparison {
                Ok(report) => report::diff_text(&report),
                Err(error) => format!("Function comparison unavailable: {error}"),
            };
            Ok(format!("{bindings}{}\n\n{functions}", audit.to_text()))
        }
    }
}

fn read_inputs(inputs: &[&str], repo: Option<&str>) -> Result<Vec<Input>, String> {
    match repo {
        Some(directory) => {
            repository::read_revisions(Path::new(directory), inputs).map(|resolved| {
                inputs
                    .iter()
                    .zip(resolved)
                    .map(|(reference, revision)| Input {
                        bytes: revision.bytes,
                        origin: json!({"revision": reference, "commit": revision.commit}),
                    })
                    .collect()
            })
        }
        None => inputs
            .iter()
            .map(|path| {
                std::fs::read(path)
                    .map(|bytes| Input {
                        bytes,
                        origin: json!({"path": path}),
                    })
                    .map_err(|error| format!("cannot read {path}: {error}"))
            })
            .collect(),
    }
}

fn patch_summary(patch: &wasm_git::patch::BytePatch) -> Value {
    json!({
        "format": patch.format,
        "old_sha256": patch.old_sha256,
        "new_sha256": patch.new_sha256,
        "old_len": patch.old_len,
        "new_len": patch.new_len,
        "edit_count": patch.edits.len()
    })
}

fn cmd_patch(args: &[String]) -> Result<String, String> {
    let parsed = match PatchArgs::try_parse_from(
        std::iter::once("wasm-git patch").chain(args.iter().map(String::as_str)),
    ) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(error.to_string());
        }
        Err(error) => return Err(error.to_string()),
    };
    let inputs = read_inputs(
        &[&parsed.old_path, &parsed.new_path],
        parsed.repo.as_deref(),
    )?;
    let patch = wasm_git::patch::create(&inputs[0].bytes, &inputs[1].bytes)?;
    let encoded = patch.to_bytes()?;
    output::write_new_file(Path::new(&parsed.output), &encoded)?;
    serde_json::to_string_pretty(&json!({
        "schema_version": 1,
        "patch": patch_summary(&patch),
        "written": true,
        "output": parsed.output,
        "inputs": {"old": &inputs[0].origin, "new": &inputs[1].origin}
    }))
    .map_err(|error| error.to_string())
}

fn cmd_apply(args: &[String]) -> Result<String, String> {
    let parsed = match ApplyArgs::try_parse_from(
        std::iter::once("wasm-git apply").chain(args.iter().map(String::as_str)),
    ) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(error.to_string());
        }
        Err(error) => return Err(error.to_string()),
    };
    let inputs = read_inputs(&[&parsed.old_path], parsed.repo.as_deref())?;
    let encoded = std::fs::read(&parsed.patch_path)
        .map_err(|error| format!("cannot read {}: {error}", parsed.patch_path))?;
    let patch = wasm_git::patch::BytePatch::from_bytes(&encoded)?;
    let bytes = patch.apply(&inputs[0].bytes)?;
    // Recompute explanations from verified bytes. The artifact supplies no
    // trusted feature, context, validation, or minimum-edit claims.
    let audit = audit::compare(&inputs[0].bytes, &bytes)?;
    if let Some(destination) = &parsed.output {
        output::write_new_file(Path::new(destination), &bytes)?;
    }
    serde_json::to_string_pretty(&json!({
        "schema_version": 1,
        "patch": patch_summary(&patch),
        "written": parsed.output.is_some(),
        "output": parsed.output,
        "inputs": {"old": &inputs[0].origin, "patch": {"path": parsed.patch_path}},
        "audit": audit
    }))
    .map_err(|error| error.to_string())
}

fn normalize_bytes(bytes: &[u8]) -> Result<ir::NormalizedModule, String> {
    parse::parse_module(bytes)
        .map(|parsed| parsed.resolve().normalize())
        .map_err(|error| error.to_string())
}

fn parse_trace_range(value: &str) -> Result<audit::Span, String> {
    let (start, end) = value
        .split_once(':')
        .ok_or("trace range must be START:END in decimal bytes")?;
    let number = |text: &str| -> Result<usize, String> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("trace offsets must contain only decimal ASCII digits".into());
        }
        let value = text
            .parse::<u64>()
            .map_err(|_| "trace offset exceeds u64")?;
        usize::try_from(value).map_err(|_| "trace offset exceeds this host's address space".into())
    };
    let span = audit::Span {
        start: number(start)?,
        end: number(end)?,
    };
    if span.start >= span.end {
        return Err("trace range must be nonempty with START < END".into());
    }
    Ok(span)
}

fn trace_path_span(module: &audit::AuditModule, path: &str) -> Result<audit::Span, String> {
    if path == "module" {
        return Ok(audit::Span {
            start: 0,
            end: module.byte_len,
        });
    }
    let mut matches = Vec::new();
    let mut pending = Vec::new();
    for section in &module.sections {
        if section.path == path {
            matches.push(section.span);
        }
        pending.extend(&section.regions);
    }
    while let Some(region) = pending.pop() {
        if region.path == path {
            matches.push(region.span);
        }
        pending.extend(&region.children);
    }
    match matches.as_slice() {
        [span] if span.start < span.end => Ok(*span),
        [_] => Err("trace path selects an empty region; select a nonempty byte range".into()),
        [] => Err(format!(
            "trace path is not present in the selected revision: {path:?}"
        )),
        _ => Err(format!(
            "trace path is ambiguous in the selected revision: {path:?}"
        )),
    }
}

fn cmd_trace(args: &[String]) -> Result<String, String> {
    let parsed = match TraceArgs::try_parse_from(
        std::iter::once("wasm-git trace").chain(args.iter().map(String::as_str)),
    ) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(error.to_string());
        }
        Err(error) => return Err(error.to_string()),
    };
    let numeric_range = parsed.range.as_deref().map(parse_trace_range).transpose()?;
    let history = repository::read_history(Path::new(&parsed.repo_dir), &parsed.revision)?;
    let commit = history
        .commits
        .get(&history.tip)
        .ok_or("trace snapshot is missing its tip")?;
    let bytes = history
        .blobs
        .get(&commit.wasm)
        .ok_or("trace snapshot is missing its tip blob")?;
    let span = if let Some(range) = numeric_range {
        range
    } else {
        let module = audit::inspect(bytes)?;
        trace_path_span(
            &module,
            parsed
                .path
                .as_deref()
                .ok_or("trace requires --range or --path")?,
        )?
    };
    if span.end > bytes.len() {
        return Err(format!(
            "trace range exceeds the selected revision's {} bytes",
            bytes.len()
        ));
    }
    let limits = wasm_git::trace::TraceLimits {
        max_edges: parsed.max_edges,
        max_compared_bytes: parsed.max_bytes,
        ..Default::default()
    };
    let report = wasm_git::trace::trace(&history, span, limits)?;
    serde_json::to_string_pretty(&json!({
        "schema_version": 1,
        "repository_verified": true,
        "selection": {"kind": if parsed.path.is_some() { "path" } else { "range" },
            "path": parsed.path, "span": span},
        "trace": report
    }))
    .map_err(|error| error.to_string())
}

fn print_usage() {
    eprintln!("usage: wasm-git <command> [<args>]\n");
    eprintln!("  inspect <FILE|REV> [--repo DIR] [--json]");
    eprintln!("  diff <OLD> <NEW> [--repo DIR] [--short] [--format text|json]");
    eprintln!("  patch <OLD> <NEW> --output NEW_PATCH [--repo DIR]");
    eprintln!("  apply <OLD> <PATCH> (--check | --output NEW_WASM) [--repo DIR]");
    eprintln!(
        "  trace <DIR> <REV> (--range START:END | --path PATH) [--max-edges N] [--max-bytes N]"
    );
    eprintln!("  init <DIR> | commit <DIR> <WASM> -m <MESSAGE> | log <DIR> [REV]");
    eprintln!("  show <DIR> <REV> [--output NEW_FILE] | checkout <DIR> <REV> <NEW_FILE>");
    eprintln!("  branch <DIR> [NAME [REV]] | switch <DIR> <NAME>");
    eprintln!("  clone <SOURCE_DIR> <NEW_DIR> | bundle <DIR> <NEW_BUNDLE_FILE>");
    eprintln!("  unbundle <DIR> <BUNDLE> <BRANCH> | fsck <DIR>");
    eprintln!("  merge <DIR> <REV> -m <MESSAGE> | merge-base <DIR> <LEFT> <RIGHT>");
}
