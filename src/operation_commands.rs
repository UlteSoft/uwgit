//! Explicit, single-target conflict continuation. Ordinary conflict reporting
//! remains stateless; the caller opts in to saving a local operation journal.

use crate::porcelain;
use crate::repository::{PendingRequest, RepositoryResult};
use serde_json::{json, Value};

const USAGE: &str = "merge DIR REV --record-conflict -m MESSAGE; cherry-pick|revert DIR REV --record-conflict [-m MESSAGE] [--mainline N]; merge|cherry-pick|revert DIR --continue --resolved-index; merge|cherry-pick|revert DIR --abort|--quit; cherry-pick|revert DIR --skip. Continuation uses the complete explicitly reviewed index; it does not infer that conflicts were resolved.";

const CONTROLS: [&str; 5] = [
    "--record-conflict",
    "--continue",
    "--abort",
    "--quit",
    "--skip",
];

pub fn requested(args: &[String]) -> bool {
    CONTROLS
        .iter()
        .any(|flag| !crate::command_args::option_indices(args, flag).is_empty())
}

enum Mode {
    Start {
        revision: String,
        message: Option<String>,
        mainline: Option<usize>,
    },
    Continue,
    Abort,
    Quit,
    Skip,
}

fn parse(args: &[String]) -> RepositoryResult<Mode> {
    if args.len() < 3 || !matches!(args[0].as_str(), "merge" | "cherry-pick" | "revert") {
        return Err(USAGE.into());
    }
    let mut revision = None;
    let mut message = None;
    let mut mainline = None;
    let mut control = None;
    let mut resolved_index = false;
    let mut index = 2;
    while index < args.len() {
        let arg = args[index].as_str();
        if CONTROLS.contains(&arg) {
            if control.replace(arg).is_some() {
                return Err(
                    "conflict controls are mutually exclusive and cannot be repeated".into(),
                );
            }
        } else {
            match arg {
                "--resolved-index" if !resolved_index => resolved_index = true,
                "-m" | "--message" if message.is_none() => {
                    index += 1;
                    message = Some(args.get(index).ok_or(USAGE)?.clone());
                }
                "--mainline" if mainline.is_none() && args[0] != "merge" => {
                    index += 1;
                    let value = args.get(index).ok_or(USAGE)?;
                    mainline = Some(
                        value
                            .parse::<usize>()
                            .ok()
                            .filter(|value| *value > 0)
                            .ok_or("mainline must be a positive parent number")?,
                    );
                }
                value if !value.starts_with('-') && revision.is_none() => {
                    revision = Some(value.to_owned());
                }
                _ => return Err(USAGE.into()),
            }
        }
        index += 1;
    }
    let control = control.ok_or(USAGE)?;
    if control == "--record-conflict" {
        if resolved_index {
            return Err("--record-conflict cannot be combined with --resolved-index".into());
        }
        if args[0] == "merge" && message.is_none() {
            return Err("recorded merge requires -m MESSAGE".into());
        }
        return Ok(Mode::Start {
            revision: revision.ok_or(USAGE)?,
            message,
            mainline,
        });
    }
    if revision.is_some() || message.is_some() || mainline.is_some() {
        return Err("continuation controls use the saved target, message and mainline; do not supply replacements".into());
    }
    match control {
        "--continue" if resolved_index => Ok(Mode::Continue),
        "--continue" => Err(
            "--continue requires --resolved-index: review and stage the complete result tree first"
                .into(),
        ),
        "--abort" if !resolved_index => Ok(Mode::Abort),
        "--quit" if !resolved_index => Ok(Mode::Quit),
        "--skip" if !resolved_index && args[0] != "merge" => Ok(Mode::Skip),
        "--skip" if args[0] == "merge" => Err("merge has no --skip; use --abort or --quit".into()),
        _ => Err(USAGE.into()),
    }
}

pub fn run(args: &[String]) -> RepositoryResult<String> {
    if args.first().is_some_and(|operation| operation == "rebase") {
        return crate::rebase_commands::run(args);
    }
    if crate::command_args::help_requested(args) {
        return Ok(USAGE.into());
    }
    let mode = parse(args)?;
    let operation = args[0].as_str();
    let root = &args[1];
    match mode {
        Mode::Continue => porcelain::with_pending_index(root, |repo, index| {
            let pending = repo.pending()?.ok_or("no conflict operation is pending")?;
            if pending.operation != operation {
                return Err(format!(
                    "pending operation is {}; use its matching continuation command",
                    pending.operation
                ));
            }
            let outcome = repo.continue_pending(&pending, index)?;
            serde_json::to_string_pretty(&outcome).map_err(|error| error.to_string())
        }),
        Mode::Abort => porcelain::pending_abort(root, operation, false),
        Mode::Skip => porcelain::pending_abort(root, operation, true),
        Mode::Quit => porcelain::pending_quit(root, operation),
        Mode::Start {
            revision,
            message,
            mainline,
        } => porcelain::with_pending_begin(root, |repo, baseline, anchor| {
            let state = repo.state()?;
            let head = state
                .branches
                .get(&state.head)
                .ok_or("recorded conflict operation requires a committed HEAD")?;
            let selected = repo.read_commit(&revision)?;
            let saved_message = message.clone().unwrap_or_else(|| {
                if operation == "revert" {
                    format!(
                        "Revert \"{}\"\n\nThis reverts commit {}.",
                        selected.commit.message, selected.id
                    )
                } else {
                    selected.commit.message.clone()
                }
            });
            let output = if operation == "merge" {
                serde_json::to_string_pretty(&repo.merge_on_branch(
                    &selected.id,
                    &saved_message,
                    &state.head,
                    Some(head),
                )?)
                .map_err(|error| error.to_string())?
            } else {
                crate::history_commands::apply_one_bound(
                    repo,
                    operation,
                    &selected.id,
                    message,
                    mainline,
                    Some((&state.head, head)),
                )?
            };
            let mut report: Value = serde_json::from_str(&output)
                .map_err(|error| format!("operation returned an invalid report: {error}"))?;
            if report["status"] != "conflict" {
                return Ok(output);
            }
            // A concurrent low-level ref writer may have changed the branch
            // while the operation ran. Bind to exactly the reported conflict;
            // record_pending rechecks that binding under its writer lock.
            let branch = report["branch"]
                .as_str()
                .ok_or("conflict report lacks its bound branch")?;
            let head = report["old_head"]
                .as_str()
                .ok_or("conflict report lacks its bound committed HEAD")?;
            if branch != state.head || state.branches.get(branch).map(String::as_str) != Some(head)
            {
                return Err(
                    "branch or HEAD changed during conflict computation; no operation recorded"
                        .into(),
                );
            }
            if report["target"].as_str() != Some(selected.id.as_str()) {
                return Err(
                    "conflict report changed its immutable target; no operation recorded".into(),
                );
            }
            let pending = repo.record_pending(PendingRequest {
                operation: operation.into(),
                branch: branch.into(),
                head: head.into(),
                target: selected.id,
                mainline,
                message: saved_message,
                baseline_index: baseline.map(<[u8]>::to_vec),
                legacy_path: anchor.map(str::to_owned),
            })?;
            report["pending"] = json!({
                "id":pending.id,
                "operation":pending.operation,
                "branch":pending.branch,
                "old_head":pending.head,
                "target":pending.target,
                "base":pending.base,
                "selected_parent":pending.selected_parent,
                "mainline":pending.mainline,
                "phase":"conflict",
                "index_updated":false,
                "worktree_updated":false,
                "complete_index_required":true
            });
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
        }),
    }
}
