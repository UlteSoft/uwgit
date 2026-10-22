//! Linked worktrees sharing native Wasm objects and branch/tag references.
use crate::query_commands::QueryOutput;
use crate::repository::{Repository, RepositoryResult};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::Path;

#[derive(Parser)]
#[command(name = "wasm-git worktree")]
struct Cli {
    dir: String,
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Add {
        path: String,
        revision: Option<String>,
        #[arg(short = 'b')]
        branch: Option<String>,
        #[arg(short = 'd', long, conflicts_with = "branch")]
        detach: bool,
        #[arg(long)]
        legacy_path: Option<String>,
    },
    List {
        #[arg(long, conflicts_with = "porcelain")]
        json: bool,
        #[arg(long)]
        porcelain: bool,
        #[arg(short = 'z', requires = "porcelain")]
        nul: bool,
    },
    Remove {
        path: String,
        #[arg(short = 'f', long)]
        force: bool,
    },
    Move {
        path: String,
        new_path: String,
    },
    Lock {
        path: String,
        #[arg(long, default_value = "locked", allow_hyphen_values = true)]
        reason: String,
    },
    Unlock {
        path: String,
    },
    Prune {
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    Repair {
        #[arg(required = true)]
        paths: Vec<String>,
    },
}

pub fn run(args: &[String]) -> RepositoryResult<QueryOutput> {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(QueryOutput::new(error.to_string(), 0))
        }
        Err(error) => return Err(error.to_string()),
    };
    let repo = Repository::open(&cli.dir)?;
    let value = match cli.action {
        Action::Add {
            path,
            revision,
            branch,
            detach,
            legacy_path,
        } => {
            let (branch, revision) = if detach {
                (repo.resolve(revision.as_deref().unwrap_or("HEAD"))?, None)
            } else if let Some(branch) = branch {
                (branch, Some(revision.unwrap_or_else(|| "HEAD".into())))
            } else if let Some(branch) = revision {
                (branch, None)
            } else {
                let branch = Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("worktree path needs a UTF-8 basename")?
                    .to_owned();
                let create = !repo.branches()?.contains_key(&branch);
                (branch, create.then(|| "HEAD".into()))
            };
            repo.add_linked_worktree(
                Path::new(&path),
                &branch,
                revision.as_deref(),
                legacy_path.as_deref(),
            )?
        }
        Action::List {
            json: _,
            porcelain,
            nul,
        } => {
            let value = repo.linked_worktrees()?;
            if porcelain {
                let separator = if nul { '\0' } else { '\n' };
                let mut output = String::new();
                for worktree in value["worktrees"]
                    .as_array()
                    .ok_or("invalid worktree report")?
                {
                    for row in [
                        format!(
                            "worktree {}",
                            worktree["path"].as_str().ok_or("missing worktree path")?
                        ),
                        format!(
                            "HEAD {}",
                            worktree["head"].as_str().unwrap_or(
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            )
                        ),
                        if worktree["detached"] == true {
                            "detached".into()
                        } else {
                            format!(
                                "branch refs/heads/{}",
                                worktree["branch"]
                                    .as_str()
                                    .ok_or("missing worktree branch")?
                            )
                        },
                    ] {
                        output.push_str(&row);
                        output.push(separator);
                    }
                    if let Some(reason) = worktree["locked"].as_str() {
                        output.push_str("locked ");
                        output.push_str(reason);
                        output.push(separator);
                    }
                    if worktree["missing"] == true {
                        output.push_str("prunable missing worktree");
                        output.push(separator);
                    }
                    output.push(separator);
                }
                return Ok(QueryOutput::new(output, 0));
            }
            value
        }
        Action::Remove { path, force } => serde_json::from_str(
            &crate::porcelain::remove_linked_worktree(&cli.dir, &path, force)?,
        )
        .map_err(|error| error.to_string())?,
        Action::Move { path, new_path } => serde_json::from_str(
            &crate::porcelain::move_linked_worktree(&cli.dir, &path, &new_path)?,
        )
        .map_err(|error| error.to_string())?,
        Action::Lock { path, reason } => repo.set_worktree_lock(Path::new(&path), Some(&reason))?,
        Action::Unlock { path } => repo.set_worktree_lock(Path::new(&path), None)?,
        Action::Prune { dry_run } => repo.prune_worktrees(dry_run)?,
        Action::Repair { paths } => {
            let mut reports = Vec::<Value>::new();
            for path in paths {
                reports.push(repo.repair_worktree(Path::new(&path))?);
            }
            serde_json::json!({"repaired":reports})
        }
    };
    QueryOutput::json(value)
}
