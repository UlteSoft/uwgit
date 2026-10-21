//! Explicit continuation of a frozen linear replay. Intermediate commits stay
//! off the branch until the complete queue has a final, reviewed result.

use crate::porcelain;
use crate::repository::{PendingRebaseRequest, RepositoryResult};

const USAGE: &str = "rebase DIR UPSTREAM [--onto NEW_BASE] --record-conflict; rebase DIR --continue --resolved-index; rebase DIR --abort|--skip|--quit. Each continuation reviews the complete staged tree for the current stopped step; HEAD advances only after the whole replay succeeds.";

enum Mode {
    Start {
        upstream: String,
        onto: Option<String>,
    },
    Continue,
    Abort,
    Skip,
    Quit,
}

fn parse(args: &[String]) -> RepositoryResult<Mode> {
    if args.len() < 3 || args[0] != "rebase" {
        return Err(USAGE.into());
    }
    let mut upstream = None;
    let mut onto = None;
    let mut control = None;
    let mut resolved = false;
    let mut index = 2;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "--record-conflict" | "--continue" | "--abort" | "--skip" | "--quit" => {
                if control.replace(arg).is_some() {
                    return Err(
                        "rebase controls are mutually exclusive and cannot be repeated".into(),
                    );
                }
            }
            "--resolved-index" if !resolved => resolved = true,
            "--onto" if onto.is_none() => {
                index += 1;
                onto = Some(args.get(index).ok_or(USAGE)?.clone());
            }
            value if !value.starts_with('-') && upstream.is_none() => {
                upstream = Some(value.to_owned());
            }
            _ => return Err(USAGE.into()),
        }
        index += 1;
    }
    if control == Some("--record-conflict") {
        if resolved {
            return Err("--record-conflict cannot be combined with --resolved-index".into());
        }
        return Ok(Mode::Start {
            upstream: upstream.ok_or(USAGE)?,
            onto,
        });
    }
    if upstream.is_some() || onto.is_some() {
        return Err("rebase continuation uses the saved upstream, onto and replay queue; do not supply replacements".into());
    }
    match (control, resolved) {
        (Some("--continue"), true) => Ok(Mode::Continue),
        (Some("--continue"), false) => Err("rebase --continue requires --resolved-index: review and stage the complete result of the current stopped step first".into()),
        (Some("--abort"), false) => Ok(Mode::Abort),
        (Some("--skip"), false) => Ok(Mode::Skip),
        (Some("--quit"), false) => Ok(Mode::Quit),
        _ => Err(USAGE.into()),
    }
}

pub fn run(args: &[String]) -> RepositoryResult<String> {
    if crate::command_args::help_requested(args) {
        return Ok(USAGE.into());
    }
    let mode = parse(args)?;
    let root = &args[1];
    match mode {
        Mode::Start { upstream, onto } => {
            porcelain::with_pending_begin(root, |repo, baseline, anchor| {
                let state = repo.state()?;
                let head = state
                    .branches
                    .get(&state.head)
                    .ok_or("recorded rebase requires a committed HEAD")?;
                let upstream = repo.read_commit(&upstream)?.id;
                let onto = onto
                    .as_deref()
                    .map(|value| repo.read_commit(value).map(|commit| commit.id))
                    .transpose()?
                    .unwrap_or_else(|| upstream.clone());
                let mut report = repo.begin_rebase_pending(PendingRebaseRequest {
                    branch: state.head,
                    head: head.clone(),
                    upstream,
                    onto,
                    baseline_index: baseline.map(<[u8]>::to_vec),
                    legacy_path: anchor.map(str::to_owned),
                })?;
                if report["status"] == "rebased" {
                    let synchronized =
                        baseline.is_some() && report["commit"].as_str() != Some(head.as_str());
                    // The clean-history wrapper synchronizes an existing index and
                    // worktree after this callback. Core-only preservation flags
                    // must not claim that this outer synchronization did not run.
                    if let Some(report) = report.as_object_mut() {
                        report.remove("index_updated");
                        report.remove("worktree_updated");
                        report.insert(
                            "existing_clean_workspace_synchronized".into(),
                            serde_json::json!(synchronized),
                        );
                    }
                }
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
            })
        }
        Mode::Continue => porcelain::with_pending_index(root, |repo, index| {
            let pending = repo.pending()?.ok_or("no rebase operation is pending")?;
            let report = repo.continue_rebase_pending(&pending, index)?;
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
        }),
        Mode::Skip => porcelain::with_pending_control(root, |repo| {
            let pending = repo.pending()?.ok_or("no rebase operation is pending")?;
            let report = repo.skip_rebase_pending(&pending)?;
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
        }),
        Mode::Abort => porcelain::pending_abort(root, "rebase", false),
        Mode::Quit => porcelain::pending_quit(root, "rebase"),
    }
}
