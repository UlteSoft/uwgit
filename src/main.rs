pub mod analysis;
mod archive_commands;
mod bisect_commands;
pub use wasm_git::audit;
mod checkout;
mod command_args;
mod describe_commands;
mod diff;
mod diff_plumbing;
mod export_dependencies;
mod fingerprint;
mod history_commands;
mod history_query_commands;
pub mod ir;
mod maintenance_commands;
mod matcher;
mod merge_base_commands;
mod normalize;
mod notes_commands;
mod object_batch;
mod operation_commands;
mod output;
pub mod parse;
mod plumbing_commands;
mod porcelain;
mod protocol;
mod query_commands;
mod rebase_commands;
mod ref_commands;
mod remote;
mod report;
mod repository;
mod resolve;
mod server;
mod tree_output;
mod tree_resolution;
mod worktree_commands;

use clap::{Parser, ValueEnum};
use serde_json::{json, Value};
use std::path::Path;
use wasm_git::standard::Standard;

#[derive(Debug, Parser)]
struct InspectArgs {
    filepath: String,
    #[arg(long)]
    json: bool,
    /// Read a committed revision instead of a filesystem path.
    #[arg(long)]
    repo: Option<String>,
    /// Select one path in a committed file tree.
    #[arg(long, requires = "repo")]
    file: Option<String>,
    /// Audit against core1, core2, core3, or every decoder-known proposal.
    #[arg(long, default_value = "all-known")]
    standard: Standard,
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
    #[arg(long, requires = "repo")]
    file: Option<String>,
    /// Select allowed features without changing instruction boundary decoding.
    #[arg(long, default_value = "all-known")]
    standard: Standard,
}

#[derive(Debug, Parser)]
struct WorktreeDiffArgs {
    repo_dir: String,
    #[arg(long)]
    cached: bool,
    #[arg(long)]
    file: Option<String>,
    #[arg(long, value_enum, default_value_t = DiffFormat::Text)]
    format: DiffFormat,
    #[arg(long)]
    short: bool,
    #[arg(long, default_value = "all-known")]
    standard: Standard,
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
    #[arg(long, requires = "repo")]
    file: Option<String>,
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
    #[arg(long, requires = "repo")]
    file: Option<String>,
    /// Audit the verified result against the selected Core standard.
    #[arg(long, default_value = "all-known")]
    standard: Standard,
}

#[derive(Debug, Parser)]
struct TraceArgs {
    repo_dir: String,
    revision: String,
    /// Trace this exact file path; renames are separate delete/add events.
    #[arg(long)]
    file: Option<String>,
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

#[derive(Debug, Parser)]
struct BlameArgs {
    repo_dir: String,
    revision: String,
    #[arg(long)]
    file: Option<String>,
    #[arg(long, conflicts_with = "path")]
    range: Option<String>,
    #[arg(long)]
    path: Option<String>,
    #[arg(long)]
    first_parent: bool,
    #[arg(long, default_value_t = 256)]
    max_edges: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_bytes: usize,
}

#[derive(clap::Parser)]
struct SquashArgs {
    repo_dir: String,
    target: String,
    #[arg(long, required = true)]
    squash: bool,
    #[arg(short = 'm', long = "message", allow_hyphen_values = true)]
    message: Option<String>,
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
    if args[1] == "cat-file" && object_batch::requested(&args[1..]) {
        if let Err(error) = object_batch::run(&args[1..]) {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
        return;
    }
    if query_commands::handles(&args[1])
        || plumbing_commands::handles(&args[1])
        || maintenance_commands::handles(&args[1])
        || args[1] == "worktree"
        || args[1] == "notes"
        || history_query_commands::handles(&args[1])
        || ref_commands::handles(&args[1])
        || diff_plumbing::handles(&args[1])
        || args[1] == "merge-base"
        || args[1] == "bisect"
    {
        let output = if args[1] == "merge-base" {
            merge_base_commands::run(&args[1..])
        } else if diff_plumbing::handles(&args[1]) {
            diff_plumbing::run(&args[1..])
        } else if ref_commands::handles(&args[1]) {
            ref_commands::run(&args[1..])
        } else if history_query_commands::handles(&args[1]) {
            history_query_commands::run(&args[1..])
        } else if args[1] == "notes" {
            notes_commands::run(&args[1..])
        } else if args[1] == "worktree" {
            worktree_commands::run(&args[1..])
        } else if maintenance_commands::handles(&args[1]) {
            maintenance_commands::run(&args[1..])
        } else if plumbing_commands::handles(&args[1]) {
            plumbing_commands::run(&args[1..])
        } else if args[1] == "bisect" {
            bisect_commands::bisect_query(&args[1..])
        } else {
            query_commands::run(&args[1..])
        };
        match output {
            Ok(output) => {
                use std::io::Write;
                let mut stdout = std::io::stdout().lock();
                if let Err(error) = stdout
                    .write_all(output.stdout.as_bytes())
                    .and_then(|_| stdout.flush())
                {
                    eprintln!("error: {error}");
                    std::process::exit(1);
                }
                if output.exit_code != 0 {
                    std::process::exit(output.exit_code);
                }
            }
            Err(error) => {
                eprintln!("error: {error}");
                std::process::exit(if args[1] == "merge-base" { 2 } else { 1 });
            }
        }
        return;
    }
    let result = match args[1].as_str() {
        "version" | "--version" | "-v" if args.len() == 2 => Ok(format!("wasm-git {}", env!("CARGO_PKG_VERSION"))),
        "version" if args.len() == 3 && args[2] == "--build-options" => serde_json::to_string_pretty(&json!({"version":env!("CARGO_PKG_VERSION"),"backend":"native_uwgit","original_wasm_bytes":true,"pointer_width":usize::BITS,"object_hash":"sha256"})).map_err(|error|error.to_string()),
        "inspect" => cmd_inspect(&args[2..]),
        "diff" => cmd_diff(&args[2..]),
        "patch" => cmd_patch(&args[2..]),
        "apply" => cmd_apply(&args[2..]),
        "trace" => cmd_trace(&args[2..]),
        "blame" => cmd_blame(&args[2..]),
        "merge" if !command_args::option_indices(&args[1..],"--squash").is_empty() => {
            match SquashArgs::try_parse_from(&args[1..]) {
                Ok(parsed)=>porcelain::squash_merge(&parsed.repo_dir,&parsed.target,parsed.message.as_deref()),
                Err(error) if error.kind()==clap::error::ErrorKind::DisplayHelp=>Ok(error.to_string()),
                Err(error)=>Err(error.to_string()),
            }
        }
        "checkout" => checkout::run(&args[1..]),
        "show"
            if args
                .iter()
                .any(|arg| arg == "--file" || arg.starts_with("--file=")) =>
        {
            tree_output::export_file(&args[1..])
        }
        "server" | "serve" => server::run(&args[1..]),
        "pull" if args.len() >= 3 && !command_args::help_requested(&args[1..]) => {
            porcelain::with_clean_history(&args[2], |_| remote::run(&args[1..]))
        }
        "remote" | "fetch" | "pull" | "push" => remote::run(&args[1..]),
        "clone" if args.get(2).is_some_and(|url| remote::is_remote_url(url)) => {
            remote::run(&args[1..])
        }
        "merge" | "cherry-pick" | "revert" | "rebase"
            if operation_commands::requested(&args[1..]) =>
        {
            operation_commands::run(&args[1..])
        }
        "cherry-pick" | "revert" | "rebase" => history_commands::run(&args[1..]),
        "status" | "add" | "rm" | "mv" | "restore" | "reset" | "stash" | "config" | "tag"
        | "reflog" | "rev-parse" | "cat-file" | "ls-files" => porcelain::run(&args[1..]),
        "commit" if args.get(3).is_some_and(|arg| arg.starts_with('-')) => {
            porcelain::run(&args[1..])
        }
        "branch" | "switch" => porcelain::run(&args[1..]),
        "commit" if args.len() >= 3 && !command_args::help_requested(&args[1..]) => {
            porcelain::with_no_pending(&args[2], |_| repository::run(&args[1..]))
        }
        "merge" if tree_resolution::requested(&args[1..]) => tree_resolution::run(&args[2..]),
        "merge" if args.len() >= 3 && !command_args::help_requested(&args[1..]) => {
            porcelain::with_clean_history(&args[2], |_| repository::run(&args[1..]))
        }
        "init" | "commit" | "log" | "show" | "clone" | "bundle" | "unbundle" | "fsck" | "merge" => repository::run(&args[1..]),
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
            let conflict = matches!(
                args[1].as_str(),
                "merge" | "pull" | "cherry-pick" | "revert" | "rebase"
            ) && serde_json::from_str::<Value>(&output)
                .is_ok_and(|report| report["status"] == "conflict");
            println!("{output}");
            if conflict {
                std::process::exit(2);
            }
            if args[1] == "push"
                && serde_json::from_str::<Value>(&output).is_ok_and(|report| {
                    matches!(
                        report["status"].as_str(),
                        Some("partial" | "rejected" | "unknown")
                    )
                })
            {
                std::process::exit(1);
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
    if let Some(root) = &parsed.repo {
        let revisions = repository::read_file_revisions(Path::new(root), &[&parsed.filepath])?;
        let revision = revisions
            .into_iter()
            .next()
            .ok_or("missing revision snapshot")?;
        if parsed.file.is_none() && revision.legacy.is_none() {
            return tree_output::inspect_tree(&parsed.filepath, revision, parsed.standard);
        }
        let input = tree_output::select_input(&parsed.filepath, revision, parsed.file.as_deref())?;
        return serde_json::to_string_pretty(&inspect_input(&input, parsed.standard)?)
            .map_err(|e| e.to_string());
    }
    let inputs = read_inputs(&[&parsed.filepath], None, None)?;
    let input = &inputs[0];
    serde_json::to_string_pretty(&inspect_input(input, parsed.standard)?).map_err(|e| e.to_string())
}

fn inspect_input(input: &Input, standard: Standard) -> Result<Value, String> {
    let audit = audit::inspect_with_standard(&input.bytes, standard)
        .map_err(|error| format!("wasm parse error: {error}"))?;
    let (mut output, status) = match normalize_bytes(&input.bytes, &audit) {
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
    output["function_analysis"] = analysis_scope(status, standard);
    output["input"] = input.origin.clone();
    output["audit"] = serde_json::to_value(audit).map_err(|error| error.to_string())?;
    Ok(output)
}

fn cmd_diff(args: &[String]) -> Result<String, String> {
    if args
        .first()
        .is_some_and(|root| Path::new(root).join(".uwgit").is_dir())
        && (args.len() == 1 || args.get(1).is_some_and(|arg| arg.starts_with('-')))
    {
        let parsed = match WorktreeDiffArgs::try_parse_from(
            std::iter::once("wasm-git diff DIR").chain(args.iter().map(String::as_str)),
        ) {
            Ok(parsed) => parsed,
            Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
                return Ok(error.to_string())
            }
            Err(error) => return Err(error.to_string()),
        };
        let inputs = porcelain::diff_snapshot(&parsed.repo_dir, parsed.cached)?;
        let labels = DiffArgs {
            old_path: if parsed.cached { "HEAD" } else { "INDEX" }.into(),
            new_path: if parsed.cached { "INDEX" } else { "WORKTREE" }.into(),
            format: parsed.format,
            short: parsed.short,
            repo: None,
            file: parsed.file,
            standard: parsed.standard,
        };
        return tree_output::render_files(
            &labels,
            inputs,
            json!({"kind":if parsed.cached{"commit"}else{"index"}}),
            json!({"kind":if parsed.cached{"index"}else{"worktree"}}),
        );
    }
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
    if let Some(root) = &parsed.repo {
        let revisions = repository::read_file_revisions(
            Path::new(root),
            &[&parsed.old_path, &parsed.new_path],
        )?;
        if parsed.file.is_some() || revisions.iter().any(|r| r.legacy.is_none()) {
            return tree_output::diff_revisions(&parsed, revisions);
        }
    }
    let inputs = read_inputs(
        &[&parsed.old_path, &parsed.new_path],
        parsed.repo.as_deref(),
        parsed.file.as_deref(),
    )?;
    render_diff(&parsed, &inputs)
}

fn render_diff(parsed: &DiffArgs, inputs: &[Input]) -> Result<String, String> {
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
    let audit = audit::compare_with_standard(old, new, parsed.standard)
        .map_err(|error| format!("wasm parse error: {error}"))?;
    let comparison = normalize_bytes(old, &audit.old).and_then(|old_module| {
        normalize_bytes(new, &audit.new).map(|new_module| {
            diff::diff_modules(&parsed.old_path, &old_module, &parsed.new_path, &new_module)
        })
    });
    if parsed.short {
        let functions = match &comparison {
            Ok(report) => report::diff_short(report),
            Err(error) => format!("Function comparison unavailable: {error}"),
        };
        return Ok(format!(
            "{bindings}{functions}\nBinary audit: {} ({} edit groups, exact_minimal={})\nDiagnostics: old={}, new={}\nSelected standard: {}; validation: old={}, new={} (function interpretation decodes all known proposals)",
            if audit.changed { "changed" } else { "identical" },
            audit.edits.len(), audit.exact_minimal,
            audit.old.diagnostics.len(), audit.new.diagnostics.len(),
            parsed.standard, audit.old.standard.validation, audit.new.standard.validation
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
                        "summary": null, "function_matches": [], "changes": [],
                        "call_binding_notes": [], "export_binding_notes": [],
                        "export_dependency_graph": null}),
                    json!({"available": false, "reason": error}),
                ),
            };
            output["schema_version"] = json!(1);
            output["binary_changed"] = json!(audit.changed);
            output["function_analysis"] = analysis_scope(status, parsed.standard);
            output["inputs"] = json!({"old": &inputs[0].origin, "new": &inputs[1].origin});
            output["audit"] = serde_json::to_value(audit).map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&output).map_err(|error| error.to_string())
        }
        DiffFormat::Text => {
            let functions = match comparison {
                Ok(report) => report::diff_text(&report),
                Err(error) => format!("Function comparison unavailable: {error}"),
            };
            Ok(format!("{bindings}{}\n\nFunction interpretation (all decoder-known proposals; selected-standard validity is reported above):\n{functions}", audit.to_text()))
        }
    }
}

fn analysis_scope(mut status: Value, standard: Standard) -> Value {
    status["decoding_standard"] = json!("all-known");
    status["selected_standard"] = json!(standard);
    status["standard_validity_is_separate"] = json!(true);
    status
}

fn read_inputs(
    inputs: &[&str],
    repo: Option<&str>,
    file: Option<&str>,
) -> Result<Vec<Input>, String> {
    match repo {
        Some(directory) if file.is_none() => {
            repository::read_revisions(Path::new(directory), inputs).map(|resolved| {
                inputs
                    .iter()
                    .zip(resolved)
                    .map(|(reference, revision)| Input {
                        bytes: revision.bytes,
                        origin: json!({"revision":reference,"commit":revision.commit}),
                    })
                    .collect()
            })
        }
        Some(directory) => repository::read_file_revisions(Path::new(directory), inputs)
            .and_then(|resolved| tree_output::select_inputs(inputs, resolved, file)),
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
        parsed.file.as_deref(),
    )?;
    let patch = wasm_git::patch::create(&inputs[0].bytes, &inputs[1].bytes)?;
    let encoded = patch.to_bytes()?;
    output::write_export_file(Path::new(&parsed.output), &encoded)?;
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
    let inputs = read_inputs(
        &[&parsed.old_path],
        parsed.repo.as_deref(),
        parsed.file.as_deref(),
    )?;
    let encoded = std::fs::read(&parsed.patch_path)
        .map_err(|error| format!("cannot read {}: {error}", parsed.patch_path))?;
    let patch = wasm_git::patch::BytePatch::from_bytes(&encoded)?;
    let bytes = patch.apply(&inputs[0].bytes)?;
    // Recompute explanations from verified bytes. The artifact supplies no
    // trusted feature, context, validation, or minimum-edit claims.
    let audit = audit::compare_with_standard(&inputs[0].bytes, &bytes, parsed.standard)?;
    if let Some(destination) = &parsed.output {
        output::write_export_file(Path::new(destination), &bytes)?;
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

fn normalize_bytes(
    bytes: &[u8],
    audit: &audit::AuditModule,
) -> Result<ir::NormalizedModule, String> {
    if let Some(section) = audit
        .sections
        .iter()
        .find(|section| section.id != 0 && section.status != "decoded")
    {
        return Err(format!(
            "incomplete Core grammar at {} ({}); function analysis cannot use unproven declaration or instruction boundaries; see the lossless binary audit",
            section.path, section.status
        ));
    }
    if let Some(entry) = audit
        .standard
        .evidence
        .iter()
        .find(|entry| entry.status == "invalid_encoding")
    {
        return Err(format!(
            "invalid Core encoding at {} [{},{}); function analysis cannot normalize an invalid wire form; see the lossless binary audit",
            entry.path, entry.span.start, entry.span.end
        ));
    }
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

fn cmd_blame(args: &[String]) -> Result<String, String> {
    let parsed = match BlameArgs::try_parse_from(
        std::iter::once("wasm-git blame").chain(args.iter().map(String::as_str)),
    ) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(error.to_string())
        }
        Err(error) => return Err(error.to_string()),
    };
    let (history, absent) = if let Some(file) = &parsed.file {
        let selected =
            repository::read_file_history(Path::new(&parsed.repo_dir), &parsed.revision, file)?;
        (selected.history, selected.absent)
    } else {
        (
            repository::read_history(Path::new(&parsed.repo_dir), &parsed.revision)?,
            Default::default(),
        )
    };
    let bytes = &history.blobs[&history.commits[&history.tip].wasm];
    let query = if let Some(range) = &parsed.range {
        parse_trace_range(range)?
    } else {
        trace_path_span(
            &audit::inspect(bytes)?,
            parsed.path.as_deref().unwrap_or("module"),
        )?
    };
    let limits = wasm_git::trace::TraceLimits {
        max_edges: parsed.max_edges,
        max_compared_bytes: parsed.max_bytes,
        ..Default::default()
    };
    let report = wasm_git::blame::blame(&history, &absent, query, parsed.first_parent, limits)?;
    serde_json::to_string_pretty(&json!({"schema_version":1,"repository_verified":true,"file":parsed.file,"selection":{"range":parsed.range,"path":parsed.path},"blame":report})).map_err(|error| error.to_string())
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
    let (history, absent, legacy_path, tip_legacy) = if let Some(file) = &parsed.file {
        let selected =
            repository::read_file_history(Path::new(&parsed.repo_dir), &parsed.revision, file)?;
        (
            selected.history,
            selected.absent,
            selected.legacy_path,
            selected.tip_legacy,
        )
    } else {
        (
            repository::read_history(Path::new(&parsed.repo_dir), &parsed.revision)?,
            Default::default(),
            None,
            false,
        )
    };
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
    let report = wasm_git::trace::trace_with_absences(&history, &absent, span, limits)?;
    let mut selection = json!({"kind": if parsed.path.is_some() { "path" } else { "range" }, "path":parsed.path,"span":span});
    if let Some(file) = parsed.file {
        selection["file"] = json!(file);
        selection["file_identity"] = json!(if tip_legacy {
            "explicit selected path; legacy commits have no filename"
        } else {
            "exact_path; rename identity is not inferred"
        });
        selection["legacy_path"] = json!(legacy_path);
    }
    serde_json::to_string_pretty(&json!({
        "schema_version": 1,
        "repository_verified": true,
        "selection": selection,
        "trace": report
    }))
    .map_err(|error| error.to_string())
}

fn print_usage() {
    eprintln!("usage: wasm-git <command> [<args>]\n");
    eprintln!("  version [--build-options]");
    eprintln!(
        "  blame <DIR> <REV> [--file PATH] [--range START:END|--path REGION] [--first-parent]"
    );
    eprintln!("  hash-object <DIR> [-w] [-t wasm|tree|commit] (--stdin|FILE) | mktree <DIR> [-z]");
    eprintln!("  write-tree <DIR> | read-tree <DIR> <REV|--empty> | commit-tree <DIR> <TREE> [-p PARENT]... -m MESSAGE");
    eprintln!("  update-ref <DIR> [-d] [-m MESSAGE] <REF> [NEW] [OLD] | rev-list <DIR> [OPTIONS] [REVISIONS...]");
    eprintln!("  merge-base <DIR> [-a] [--octopus|--independent|--is-ancestor|--fork-point] <REVISIONS...> [--text|--json]");
    eprintln!(
        "  symbolic-ref <DIR> [--short] HEAD [refs/heads/BRANCH] | check-ref-format [--branch] REF"
    );
    eprintln!("  diff-files <DIR> | diff-index <DIR> <REV> [--cached] | diff-tree <DIR> <OLD> <NEW> [OPTIONS]");
    eprintln!("  cat-file <DIR> --batch|--batch-check|--batch-command [--buffer] [-z|-Z]");
    eprintln!(
        "  clean <DIR> -n|-f [-d] [-x|-X] [-e PATTERN] [-- PATH...] | gc <DIR> [--prune=now] [-n]"
    );
    eprintln!("  maintenance <DIR> run [--task verify|gc] | worktree <DIR> add|list|remove|move|lock|unlock|prune|repair [OPTIONS]");
    eprintln!("  notes <DIR> [--ref NAMESPACE] list|show|add|append|copy|remove [OPTIONS]");
    eprintln!("  shortlog <DIR> [REV] [--group path|subject] [-s] [-n] | range-diff <DIR> <BASE..TIP> <BASE..TIP>");
    eprintln!(
        "  mergetool <DIR> --output NEW_DIR [--tool PROGRAM --stage] [--delete PATH] [-- PATH...]"
    );
    eprintln!(
        "  inspect <FILE|REV> [--repo DIR] [--file PATH] [--json] [--standard core1|core2|core3|all-known]"
    );
    eprintln!(
        "  diff <OLD> <NEW> [--repo DIR] [--file PATH] [--short] [--format text|json] [--standard STANDARD]"
    );
    eprintln!("  diff <DIR> [--cached] [--file PATH] [--short] [--format text|json] [--standard STANDARD]");
    eprintln!("  patch <OLD> <NEW> --output NEW_PATCH [--repo DIR --file PATH]");
    eprintln!(
        "  apply <OLD> <PATCH> (--check | --output NEW_WASM) [--repo DIR --file PATH] [--standard STANDARD]"
    );
    eprintln!(
        "  trace <DIR> <REV> [--file PATH] (--range START:END | --path PATH) [--max-edges N] [--max-bytes N]"
    );
    eprintln!("  init <DIR> | commit <DIR> <WASM> -m <MESSAGE> | log <DIR> [REV]");
    eprintln!("  show <DIR> <REV> [--file PATH] [--output NEW_FILE] | checkout <DIR> <REV> <NEW_FILE> [--file PATH]");
    eprintln!("  checkout <DIR> <BRANCH> | checkout <DIR> -b <NAME> [REV]");
    eprintln!("  checkout <DIR> [REV] -- <PATH>...");
    eprintln!("  branch <DIR> [NAME [REV]|-r|-a|-M [OLD] NEW|-c [OLD] NEW|-C [OLD] NEW|-f NAME [REV]] | switch <DIR> <NAME|-> [or --detach REV|--orphan NAME]");
    eprintln!("  branch <DIR> -u <REMOTE/BRANCH> [NAME] | branch <DIR> --unset-upstream [NAME] | branch <DIR> -vv");
    eprintln!("  clone <SOURCE_DIR> <NEW_DIR> | bundle <DIR> <NEW_BUNDLE_FILE>");
    eprintln!("  unbundle <DIR> <BUNDLE> <BRANCH> | fsck <DIR>");
    eprintln!("  merge <DIR> <REV> -m <MESSAGE> | merge-base <DIR> <LEFT> <RIGHT>");
    eprintln!("  merge <DIR> <REV> --ff-only [-m MESSAGE]");
    eprintln!("  merge <DIR> <TARGET_ID> -m <MESSAGE> --resolved-index --expect-head <HEAD_ID> [--expect-branch NAME]");
    eprintln!("  add <DIR> <RELATIVE_WASM>... | status <DIR> | commit <DIR> -m <MESSAGE>");
    eprintln!("  restore <DIR> [--source REV] | reset <DIR> [--soft|--mixed|--hard] [REV]");
    eprintln!(
        "  rm <DIR> [--cached] [FILE...] | mv <DIR> <OLD> <NEW> | stash <DIR> [push|list|apply|pop|drop]"
    );
    eprintln!("  tag <DIR> [NAME [REV]|-d NAME] | reflog <DIR> | rev-parse <DIR> <REV>");
    eprintln!("  cat-file <DIR> <REV> | ls-files <DIR> | config <DIR> [KEY [VALUE]]");
    eprintln!("  ls-tree <DIR> <REV> [-r] [--json|--name-only|--object-only] [-z] [-- PATH...]");
    eprintln!("  show-ref <DIR> [--head] [--heads|--tags] [--verify] [--quiet|--hash|--json] [PATTERN...]");
    eprintln!(
        "  for-each-ref <DIR> [--json|--format STR] [--sort KEY]... [--count N] [PATTERN...]"
    );
    eprintln!(
        "  count-objects <DIR> [-v] [-H] | ls-remote <URL|DIR [REMOTE]> [--json] [PATTERN...]"
    );
    eprintln!(
        "  cherry-pick <DIR> <REV> | revert <DIR> <REV> | rebase <DIR> <UPSTREAM> [--onto REV]"
    );
    eprintln!("  cherry-pick|revert <DIR> <TARGET_ID> [--mainline N] --resolved-index --expect-head <HEAD_ID> [--expect-branch NAME] [-m MESSAGE]");
    eprintln!(
        "  merge|cherry-pick|revert <DIR> <REV> --record-conflict [-m MESSAGE] [--mainline N]"
    );
    eprintln!("  merge|cherry-pick|revert <DIR> --continue --resolved-index | --abort | --quit");
    eprintln!("  cherry-pick|revert <DIR> --skip");
    eprintln!("  rebase <DIR> <UPSTREAM> [--onto REV] --record-conflict");
    eprintln!("  rebase <DIR> --continue --resolved-index | --abort | --skip | --quit");
    eprintln!("  remote <DIR> [add NAME URL|remove NAME|-v] | fetch <DIR> [REMOTE]");
    eprintln!("  push <DIR> [REMOTE] [SRC:DST] | pull <DIR> [REMOTE] [BRANCH] -m <MESSAGE>");
    eprintln!("  push <DIR> [REMOTE] [LOCAL_BRANCH:REMOTE_BRANCH] --set-upstream");
    eprintln!("  pull <DIR> [REMOTE] [BRANCH] --ff-only [-m MESSAGE]");
    eprintln!("  clone <http(s)://HOST/REPO|ssh://USER@HOST/ROOT/REPO> <NEW_DIR>");
    eprintln!("  describe <DIR> [REV] [--tags] [--exact-match] [--always] [--long] [--first-parent] [--abbrev N]");
    eprintln!("  archive <DIR> <REV> --output NEW_TAR [--format tar] [--prefix PREFIX/] [--legacy-path NAME] [-- PATH...]");
    eprintln!("  bisect <DIR> start [--no-checkout] [--first-parent] <BAD> <GOOD>...");
    eprintln!("  bisect <DIR> good|skip [REV...] | bad [REV] | status | next | log | reset");
    eprintln!("  server --root <DIR> [--listen ADDRESS] [--token-file FILE --allow-write]");
    eprintln!("  server --stdio --root <DIR> [--allow-force]");
}
