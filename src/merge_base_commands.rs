//! Ancestor and reflog graph queries over the independent uwgit object DAG.
use crate::query_commands::QueryOutput;
use crate::repository::{MergeBaseMode, Repository, RepositoryResult};
use clap::{ArgGroup, Parser};

#[derive(Parser)]
#[command(name = "merge-base", group(ArgGroup::new("mode").args(["octopus", "independent", "is_ancestor", "fork_point"])))]
struct Args {
    dir: String,
    #[arg(short = 'a', long, conflicts_with_all = ["independent", "is_ancestor", "fork_point"])]
    all: bool,
    #[arg(long)]
    octopus: bool,
    #[arg(long)]
    independent: bool,
    #[arg(long)]
    is_ancestor: bool,
    #[arg(long)]
    fork_point: bool,
    #[arg(long, conflicts_with_all = ["text", "is_ancestor"])]
    json: bool,
    /// Select line-oriented output instead of the original two-operand JSON form.
    #[arg(long)]
    text: bool,
    revisions: Vec<String>,
}

pub fn run(args: &[String]) -> RepositoryResult<QueryOutput> {
    let mut parsed = match Args::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(QueryOutput::new(error.to_string(), 0));
        }
        Err(error) => return Err(error.to_string()),
    };
    // The existing native command returned all bases as JSON for two bare
    // operands. Keep that contract; explicit modes/options use line output.
    let legacy = args.len() == 4 && args[2..].iter().all(|arg| !arg.starts_with('-'));
    let mode = if parsed.fork_point {
        if !(1..=2).contains(&parsed.revisions.len()) {
            return Err("--fork-point requires REF [REV]".into());
        }
        if parsed.revisions.len() == 1 {
            parsed.revisions.push("HEAD".into());
        }
        MergeBaseMode::ForkPoint
    } else if parsed.is_ancestor {
        if parsed.revisions.len() != 2 {
            return Err("--is-ancestor requires exactly two revisions".into());
        }
        MergeBaseMode::IsAncestor
    } else if parsed.independent {
        MergeBaseMode::Independent
    } else if parsed.octopus {
        if parsed.revisions.is_empty() {
            return Err("--octopus requires at least one revision".into());
        }
        MergeBaseMode::Octopus
    } else {
        if parsed.revisions.len() < 2 {
            return Err("merge-base requires at least two revisions".into());
        }
        MergeBaseMode::Pair
    };
    let mut ids = Repository::open(&parsed.dir)?.merge_base_query(&parsed.revisions, mode)?;
    if parsed.is_ancestor {
        return Ok(QueryOutput::new(String::new(), i32::from(ids.is_empty())));
    }
    if !parsed.all && !legacy && !parsed.independent {
        ids.truncate(1);
    }
    let exit_code = if legacy { 0 } else { i32::from(ids.is_empty()) };
    let output = if parsed.json || legacy {
        serde_json::to_string_pretty(&ids).map_err(|error| error.to_string())?
    } else {
        ids.join("\n")
    };
    Ok(QueryOutput::new(
        if output.is_empty() {
            output
        } else {
            format!("{output}\n")
        },
        exit_code,
    ))
}
