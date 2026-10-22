//! Wasm-oriented summaries and original-byte transition comparisons.
use crate::query_commands::QueryOutput;
use crate::repository::{Repository, RepositoryResult};
use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(name = "wasm-git")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Shortlog {
        dir: String,
        #[arg(default_value = "HEAD")]
        revision: String,
        #[arg(long, value_parser = ["path", "subject"], default_value = "path")]
        group: String,
        #[arg(short = 's', long)]
        summary: bool,
        #[arg(short = 'n', long)]
        number: bool,
        #[arg(long)]
        first_parent: bool,
    },
    RangeDiff {
        dir: String,
        old_range: String,
        new_range: String,
        #[arg(long)]
        first_parent: bool,
        #[arg(long, default_value_t = 1024)]
        max_commits: usize,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_bytes: usize,
        #[arg(long)]
        no_audit: bool,
    },
}
pub fn handles(command: &str) -> bool {
    matches!(command, "shortlog" | "range-diff")
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
    let report = match cli.command {
        Action::Shortlog {
            dir,
            revision,
            group,
            summary,
            number,
            first_parent,
        } => Repository::open(dir)?.shortlog(&revision, first_parent, &group, summary, number)?,
        Action::RangeDiff {
            dir,
            old_range,
            new_range,
            first_parent,
            max_commits,
            max_bytes,
            no_audit,
        } => Repository::open(dir)?.range_diff(
            &old_range,
            &new_range,
            first_parent,
            max_commits,
            max_bytes,
            !no_audit,
        )?,
    };
    QueryOutput::json(report)
}
