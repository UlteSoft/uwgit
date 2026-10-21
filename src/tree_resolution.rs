//! Explicit complete-tree resolution uses exactly the staged bytes. It does not
//! materialize any worktree files or discard unstaged edits.

use crate::porcelain;
use clap::Parser;
use serde_json::json;

#[derive(Parser)]
#[command(about = "Record an explicitly resolved index with both reviewed parents")]
struct ResolutionArgs {
    repo_dir: String,
    /// Complete immutable ID of the other reviewed tip.
    target: String,
    #[arg(short = 'm', long = "message", allow_hyphen_values = true)]
    message: String,
    /// Use the complete staged tree, including deletions and an empty tree.
    #[arg(long, required = true)]
    resolved_index: bool,
    #[arg(long)]
    expect_head: String,
    /// Also bind the branch name from the conflict report.
    #[arg(long)]
    expect_branch: Option<String>,
}

/// Do not mistake a message or file argument containing this literal option
/// for the resolution mode. Existing merge dispatch remains unchanged.
pub fn requested(args: &[String]) -> bool {
    let mut index = 1;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--resolved-index" || arg.starts_with("--resolved-index=") {
            return true;
        }
        if matches!(
            arg,
            "-m" | "--message" | "--resolved" | "--expect-head" | "--expect-branch"
        ) {
            index += 1;
        }
        index += 1;
    }
    false
}

pub fn run(args: &[String]) -> Result<String, String> {
    let parsed = match ResolutionArgs::try_parse_from(
        std::iter::once("wasm-git merge").chain(args.iter().map(String::as_str)),
    ) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(error.to_string())
        }
        Err(error) => return Err(error.to_string()),
    };
    porcelain::with_index_resolution(&parsed.repo_dir, |repo, files, anchor| {
        let state = repo.state()?;
        let branch = parsed.expect_branch.as_deref().unwrap_or(&state.head);
        let outcome = repo.merge_files_resolved_on_branch(
            branch,
            &parsed.expect_head,
            &parsed.target,
            files,
            anchor,
            &parsed.message,
        )?;
        let mut report = serde_json::to_value(outcome).map_err(|error| error.to_string())?;
        report["resolution_source"] = json!("index");
        report["index_updated"] = json!(false);
        report["worktree_updated"] = json!(false);
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
    })
}
