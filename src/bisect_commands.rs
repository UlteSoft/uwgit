//! Manual history classification without checking out or running a revision.
use crate::query_commands::QueryOutput;
use crate::repository::{BisectKind, BisectRequest, Repository, RepositoryResult};
use serde_json::json;
use std::collections::BTreeSet;

const USAGE: &str = "usage: wasm-git bisect DIR start [--no-checkout] [--first-parent] BAD GOOD... [--json]\n       wasm-git bisect DIR good|skip [REV...] [--json]\n       wasm-git bisect DIR bad [REV] [--json]\n       wasm-git bisect DIR status|next|log|reset [--json]\nOnly committed history is classified; every mode leaves HEAD, the index, and worktree unchanged. --no-checkout is always active and can be stated explicitly at start. Start requires one bad and at least one good commit and never replaces a session. Revisions are frozen as full IDs; omitting a mark's REV selects the recorded candidate, never HEAD. --first-parent fixes the traversal policy at start. Skipped commits remain suspects and may prevent a unique result. Status, next and log are read-only JSON; reset only removes the local session, including an invalid regular journal. Reset cannot accept a revision. Run, replay, alternate terms, pathspecs and automatic checkout are unsupported. Ranges are not expanded; exact existing ref names keep their normal meaning. A single redundant --json is accepted. Use archive/show with the returned candidate to inspect committed bytes separately.";

enum Mode {
    Help,
    Run {
        directory: String,
        request: BisectRequest,
    },
}

fn parse(args: &[String]) -> RepositoryResult<Mode> {
    if args.first().map(String::as_str) != Some("bisect") {
        return Err(USAGE.into());
    }
    if crate::command_args::help_requested(args) {
        return Ok(Mode::Help);
    }
    let mut seen = BTreeSet::new();
    let mut positional = Vec::new();
    let mut first_parent = false;
    let mut no_checkout = false;
    for arg in &args[1..] {
        if arg.starts_with('-') {
            if !seen.insert(arg.as_str()) {
                return Err(format!("duplicate bisect option: {arg}"));
            }
            match arg.as_str() {
                "--json" => {}
                "--no-checkout" => no_checkout = true,
                "--first-parent" => first_parent = true,
                "--" => return Err("bisect does not accept pathspecs or a '--' separator".into()),
                _ => return Err(format!("unsupported bisect option: {arg}")),
            }
        } else {
            if arg.is_empty() || arg.chars().any(char::is_control) {
                return Err("bisect requires nonempty arguments without control characters".into());
            }
            positional.push(arg.as_str());
        }
    }
    if (positional.len() == 1 && positional[0] == "help")
        || (positional.len() == 2 && positional[1] == "help")
    {
        if first_parent || no_checkout {
            return Err("bisect start options only apply to start".into());
        }
        return Ok(Mode::Help);
    }
    if positional.len() < 2 {
        return Err(USAGE.into());
    }
    let directory = positional[0].to_owned();
    let command = positional[1];
    let revisions = &positional[2..];
    if command != "start" && (first_parent || no_checkout) {
        return Err("--first-parent and --no-checkout are fixed at bisect start".into());
    }
    let revisions = || {
        revisions
            .iter()
            .map(|revision| (*revision).to_owned())
            .collect::<Vec<_>>()
    };
    let request = match command {
        "start" if positional.len() >= 4 => {
            let mut revisions = revisions();
            BisectRequest::Start {
                bad: revisions.remove(0),
                good: revisions,
                first_parent,
            }
        }
        "good" => BisectRequest::Mark {
            kind: BisectKind::Good,
            revisions: revisions(),
        },
        "skip" => BisectRequest::Mark {
            kind: BisectKind::Skip,
            revisions: revisions(),
        },
        "bad" if positional.len() <= 3 => BisectRequest::Mark {
            kind: BisectKind::Bad,
            revisions: revisions(),
        },
        "status" | "next" | "log" | "reset" if positional.len() == 2 => match command {
            "status" => BisectRequest::Status,
            "next" => BisectRequest::Next,
            "log" => BisectRequest::Log,
            "reset" => BisectRequest::Reset,
            _ => unreachable!(),
        },
        "start" => {
            return Err("bisect start requires one BAD and at least one GOOD revision".into())
        }
        "bad" => return Err("bisect bad accepts at most one revision".into()),
        "status" | "next" | "log" | "reset" => {
            return Err(format!("bisect {command} does not accept revisions"))
        }
        _ => return Err(format!("unsupported bisect command: {command}")),
    };
    Ok(Mode::Run { directory, request })
}

pub fn bisect_query(args: &[String]) -> RepositoryResult<QueryOutput> {
    let (directory, request) = match parse(args)? {
        Mode::Help => return Ok(QueryOutput::new(format!("{USAGE}\n"), 0)),
        Mode::Run { directory, request } => (directory, request),
    };
    let report = Repository::open(directory)?.bisect(request)?;
    let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
    value["command"] = json!("bisect");
    QueryOutput::json(value)
}
