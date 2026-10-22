//! Explicit local maintenance for native Wasm stores and worktrees.
use crate::query_commands::QueryOutput;
use crate::repository::{Repository, RepositoryResult};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "wasm-git")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Export frozen conflict sides and optionally stage reviewed binary output.
    Mergetool {
        dir: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long, requires = "tool")]
        stage: bool,
        #[arg(long = "delete", action = clap::ArgAction::Append, requires = "stage")]
        deletions: Vec<String>,
        paths: Vec<String>,
    },
    /// Preview or explicitly remove untracked regular files and empty directories.
    Clean {
        dir: String,
        #[arg(short = 'n', long, required_unless_present = "force")]
        dry_run: bool,
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(short = 'd')]
        directories: bool,
        #[arg(short = 'x', conflicts_with = "only_ignored")]
        all: bool,
        #[arg(short = 'X')]
        only_ignored: bool,
        #[arg(short = 'e', long = "exclude", action = clap::ArgAction::Append, allow_hyphen_values = true)]
        excludes: Vec<String>,
        #[arg(short = 'q', long)]
        quiet: bool,
        paths: Vec<String>,
    },
    /// Verify and report unreachable objects; prune only with --prune=now.
    Gc {
        dir: String,
        #[arg(long, value_parser = ["now", "never"], default_value = "never")]
        prune: String,
        #[arg(short = 'n', long)]
        dry_run: bool,
        #[arg(short = 'q', long)]
        quiet: bool,
    },
    /// Run integrity checking and optional explicit native loose-object GC.
    Maintenance {
        dir: String,
        #[arg(value_parser = ["run"], default_value = "run")]
        action: String,
        #[arg(long, value_parser = ["verify", "gc"], action = clap::ArgAction::Append)]
        task: Vec<String>,
        #[arg(long, value_parser = ["now", "never"], default_value = "never")]
        prune: String,
    },
}

pub fn handles(command: &str) -> bool {
    matches!(command, "clean" | "gc" | "maintenance" | "mergetool")
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
    let (output, quiet) = match cli.command {
        Command::Mergetool {
            dir,
            output,
            tool,
            stage,
            deletions,
            paths,
        } => (
            crate::porcelain::mergetool(&dir, &output, tool.as_deref(), stage, &paths, &deletions)?,
            false,
        ),
        Command::Clean {
            dir,
            dry_run,
            force: _,
            directories,
            all,
            only_ignored,
            excludes,
            quiet,
            paths,
        } => (
            crate::porcelain::clean(
                &dir,
                dry_run,
                directories,
                all,
                only_ignored,
                &excludes,
                &paths,
            )?,
            quiet,
        ),
        Command::Gc {
            dir,
            prune,
            dry_run,
            quiet,
        } => (
            crate::porcelain::garbage_collect(&dir, prune == "now" && !dry_run)?,
            quiet,
        ),
        Command::Maintenance {
            dir,
            action: _,
            task,
            prune,
        } => {
            if task.iter().collect::<std::collections::BTreeSet<_>>().len() != task.len() {
                return Err("duplicate maintenance task".into());
            }
            let mut report = serde_json::Map::new();
            if task.is_empty() || task.iter().any(|task| task == "verify") {
                report.insert(
                    "verify".into(),
                    serde_json::to_value(Repository::open(&dir)?.fsck()?)
                        .map_err(|error| error.to_string())?,
                );
            }
            if task.is_empty() || task.iter().any(|task| task == "gc") {
                report.insert(
                    "gc".into(),
                    serde_json::from_str(&crate::porcelain::garbage_collect(&dir, prune == "now")?)
                        .map_err(|error| error.to_string())?,
                );
            } else if prune != "never" {
                return Err("--prune requires the gc maintenance task".into());
            }
            (
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?,
                false,
            )
        }
    };
    Ok(QueryOutput::new(
        if quiet {
            String::new()
        } else {
            format!("{output}\n")
        },
        0,
    ))
}
