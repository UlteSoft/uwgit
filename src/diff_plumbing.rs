//! File-tree/index/worktree plumbing using the same Wasm audit renderer.
use crate::porcelain::FileDiffSnapshot;
use crate::query_commands::QueryOutput;
use crate::repository::RepositoryResult;
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use wasm_git::standard::Standard;
#[derive(Parser)]
#[command(name = "wasm-git")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Args)]
struct Options {
    #[arg(long, conflicts_with = "name_status")]
    name_only: bool,
    #[arg(long)]
    name_status: bool,
    #[arg(short = 'z')]
    nul: bool,
    #[arg(long)]
    exit_code: bool,
    #[arg(long)]
    quiet: bool,
    #[arg(long, value_enum, default_value_t=crate::DiffFormat::Json)]
    format: crate::DiffFormat,
    #[arg(long)]
    short: bool,
    #[arg(long, default_value = "all-known")]
    standard: Standard,
    #[arg(last = true)]
    paths: Vec<String>,
}
#[derive(Subcommand)]
enum Action {
    #[command(name = "diff-files")]
    Files {
        dir: String,
        #[command(flatten)]
        options: Options,
    },
    #[command(name = "diff-index")]
    Index {
        dir: String,
        revision: String,
        #[arg(long, alias = "staged")]
        cached: bool,
        #[command(flatten)]
        options: Options,
    },
    #[command(name = "diff-tree")]
    Tree {
        dir: String,
        old: String,
        new: String,
        #[command(flatten)]
        options: Options,
    },
}
pub fn handles(command: &str) -> bool {
    matches!(command, "diff-files" | "diff-index" | "diff-tree")
}
pub fn run(args: &[String]) -> RepositoryResult<QueryOutput> {
    let cli = match Cli::try_parse_from(
        std::iter::once("wasm-git").chain(args.iter().map(String::as_str)),
    ) {
        Ok(cli) => cli,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(QueryOutput::new(error.to_string(), 0))
        }
        Err(error) => return Err(error.to_string()),
    };
    let (rows, options, old_origin, new_origin) = match cli.command {
        Action::Files { dir, options } => (
            crate::porcelain::diff_snapshot(&dir, false)?,
            options,
            json!({"kind":"index"}),
            json!({"kind":"worktree"}),
        ),
        Action::Index {
            dir,
            revision,
            cached,
            options,
        } => (
            crate::porcelain::diff_index_snapshot(&dir, &revision, cached)?,
            options,
            json!({"kind":"commit","revision":revision}),
            json!({"kind":if cached{"index"}else{"worktree"}}),
        ),
        Action::Tree {
            dir,
            old,
            new,
            options,
        } => {
            let mut inputs =
                crate::repository::read_file_revisions(std::path::Path::new(&dir), &[&old, &new])?
                    .into_iter();
            let old_files = inputs.next().ok_or("missing old tree")?;
            let new_files = inputs.next().ok_or("missing new tree")?;
            if old_files.legacy.is_some() || new_files.legacy.is_some() {
                return Err(
                    "diff-tree requires named trees; use diff --repo for legacy single modules"
                        .into(),
                );
            }
            let paths: std::collections::BTreeSet<_> = old_files
                .files
                .keys()
                .chain(new_files.files.keys())
                .cloned()
                .collect();
            let rows = paths
                .into_iter()
                .map(|path| FileDiffSnapshot {
                    old: old_files.files.get(&path).cloned(),
                    new: new_files.files.get(&path).cloned(),
                    old_origin: json!({"commit":old_files.commit,"path":path}),
                    new_origin: json!({"commit":new_files.commit,"path":path}),
                    path,
                })
                .collect();
            (
                rows,
                options,
                json!({"commit":old_files.commit}),
                json!({"commit":new_files.commit}),
            )
        }
    };
    if options.nul && !(options.name_only || options.name_status) {
        return Err("-z requires --name-only or --name-status".into());
    }
    for selector in &options.paths {
        if selector != "." {
            crate::repository::validate_tree_path(selector.trim_end_matches('/'))?;
        }
        if !rows.iter().any(|row| matches(&row.path, selector)) {
            return Err(format!("diff path selector has no match: {selector:?}"));
        }
    }
    let rows: Vec<_> = rows
        .into_iter()
        .filter(|row| {
            options.paths.is_empty()
                || options
                    .paths
                    .iter()
                    .any(|selector| matches(&row.path, selector))
        })
        .collect();
    let changed = rows.iter().any(|row| row.old != row.new);
    let output = if options.quiet {
        String::new()
    } else if options.name_only || options.name_status {
        let mut output = String::new();
        for row in &rows {
            if row.old == row.new {
                continue;
            }
            if options.name_status {
                output.push_str(match (&row.old, &row.new) {
                    (None, Some(_)) => "A",
                    (Some(_), None) => "D",
                    _ => "M",
                });
                output.push(if options.nul { '\0' } else { '\t' });
            }
            output.push_str(&row.path);
            output.push(if options.nul { '\0' } else { '\n' });
        }
        output
    } else {
        let parsed = crate::DiffArgs {
            old_path: "index".into(),
            new_path: "worktree".into(),
            format: options.format,
            short: options.short,
            repo: None,
            file: None,
            standard: options.standard,
        };
        let output = crate::tree_output::render_files(&parsed, rows, old_origin, new_origin)?;
        format!("{output}\n")
    };
    Ok(QueryOutput::new(
        output,
        if changed && (options.exit_code || options.quiet) {
            1
        } else {
            0
        },
    ))
}
fn matches(path: &str, selector: &str) -> bool {
    let directory = selector.ends_with('/');
    let selector = selector.trim_end_matches('/');
    selector == "." || (!directory && path == selector) || path.starts_with(&format!("{selector}/"))
}
