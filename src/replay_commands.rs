//! Multi-target cherry-pick/revert use a frozen native sequencer. Existing
//! stateless single-target and explicit full-ID resolution interfaces remain.
use crate::repository::{ReplayOptions, Repository, RepositoryResult};
use crate::{command_args, history_commands, operation_commands, porcelain};
use std::io::Read;
const USAGE:&str="cherry-pick|revert DIR REV... [--stdin] [-n|--no-commit] [--sequence] [--reverse] [--mainline N] [-m MESSAGE] [--empty stop|drop|keep] [--allow-empty] [--ff] [-x]; cherry-pick|revert DIR --continue --resolved-index|--skip|--abort|--quit. Bare target lists retain argument order; ranges freeze one DAG walk (parent-first for pick, child-first for revert). HEAD advances only after the complete queue succeeds. No-commit writes complete index/work images without creating commits.";
pub fn run(args: &[String]) -> RepositoryResult<String> {
    if command_args::help_requested(args) {
        return Ok(USAGE.into());
    }
    if args.len() < 3 {
        return Err(USAGE.into());
    }
    let controls = ["--continue", "--skip", "--abort", "--quit"];
    if !controls
        .iter()
        .any(|control| !command_args::option_indices(args, control).is_empty())
        && !command_args::option_indices(args, "--resolved-index").is_empty()
    {
        return history_commands::run(args);
    }
    let mut options = ReplayOptions {
        no_commit: false,
        mainline: None,
        message: None,
        append_source: false,
        empty: "stop".into(),
        allow_empty: false,
        fast_forward: false,
        reverse: false,
    };
    let mut revisions = Vec::new();
    let mut control = None;
    let mut resolved = false;
    let mut stdin = false;
    let mut record = false;
    let mut sequence = false;
    let mut extended = false;
    let mut seen = std::collections::BTreeSet::new();
    let mut at = 2;
    while at < args.len() {
        let value = &args[at];
        if !value.starts_with('-') {
            revisions.push(value.clone());
            at += 1;
            continue;
        }
        if let Some(value) = value.strip_prefix("--empty=") {
            if !seen.insert("--empty") {
                return Err("duplicate empty policy".into());
            }
            options.empty = value.into();
            extended = true;
            at += 1;
            continue;
        }
        if controls.contains(&value.as_str()) {
            if control.replace(value.trim_start_matches('-')).is_some() {
                return Err("replay controls cannot be combined or repeated".into());
            }
            at += 1;
            continue;
        }
        let key = match value.as_str() {
            "-n" => "--no-commit",
            "-m" => "--message",
            "--keep-redundant-commits" => "--empty",
            other => other,
        };
        if !seen.insert(key) {
            return Err(format!("duplicate replay option: {value}"));
        }
        match value.as_str() {
            "--resolved-index" => resolved = true,
            "--record-conflict" => record = true,
            "--sequence" => {
                sequence = true;
                extended = true;
            }
            "--stdin" => {
                stdin = true;
                extended = true;
            }
            "-n" | "--no-commit" => {
                options.no_commit = true;
                extended = true;
            }
            "--reverse" => {
                options.reverse = true;
                extended = true;
            }
            "--allow-empty" => {
                options.allow_empty = true;
                extended = true;
            }
            "--ff" => {
                options.fast_forward = true;
                extended = true;
            }
            "-x" => {
                options.append_source = true;
                extended = true;
            }
            "--keep-redundant-commits" => {
                options.empty = "keep".into();
                extended = true;
            }
            "-m" | "--message" => {
                at += 1;
                options.message = Some(args.get(at).ok_or(USAGE)?.clone());
            }
            "--mainline" => {
                at += 1;
                options.mainline = Some(
                    args.get(at)
                        .ok_or(USAGE)?
                        .parse::<usize>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or("mainline must be a positive parent number")?,
                );
            }
            "--empty" => {
                at += 1;
                options.empty = args.get(at).ok_or(USAGE)?.clone();
                extended = true;
            }
            _ => return Err(USAGE.into()),
        }
        at += 1;
    }
    if let Some(control) = control {
        if !revisions.is_empty()
            || extended
            || options.message.is_some()
            || options.mainline.is_some()
            || record
        {
            return Err(
                "continuation uses its frozen options and queue; do not supply replacements".into(),
            );
        }
        let pending = Repository::open(&args[1])?
            .pending()?
            .ok_or("no replay operation is pending")?;
        if pending.replay.is_none() {
            return operation_commands::run(args);
        }
        if control == "continue"
            && !resolved
            && pending
                .replay
                .as_ref()
                .is_some_and(|replay| replay.checkpoint.is_none() && replay.stop != "complete")
        {
            return Err(
                "continue requires --resolved-index after reviewing the complete stopped result"
                    .into(),
            );
        }
        if control != "continue" && resolved {
            return Err("resolved-index is only valid with continue".into());
        }
        return porcelain::replay_control(&args[1], &args[0], control);
    }
    if resolved {
        return Err("resolved-index continuation needs a control or full-ID resolution".into());
    }
    if !matches!(options.empty.as_str(), "stop" | "drop" | "keep") {
        return Err("empty policy must be stop, drop, or keep".into());
    }
    if options.no_commit
        && (options.fast_forward || options.message.is_some() || options.append_source)
    {
        return Err("no-commit cannot combine commit identity/message options".into());
    }
    if options.fast_forward
        && (args[0] != "cherry-pick" || options.message.is_some() || options.append_source)
    {
        return Err("ff requires an unchanged cherry-pick source identity".into());
    }
    if options.append_source && args[0] != "cherry-pick" {
        return Err("-x applies only to cherry-pick".into());
    }
    if stdin {
        if !revisions.is_empty() {
            return Err("stdin revision input cannot combine positional targets".into());
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .lock()
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 64 * 1024 * 1024 {
            return Err("replay stdin exceeds 64 MiB".into());
        }
        revisions = std::str::from_utf8(&bytes)
            .map_err(|_| "replay revisions must be UTF-8")?
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if revisions.is_empty() {
        return Err(USAGE.into());
    }
    let range = revisions.iter().any(|revision| {
        revision.contains("..")
            || revision.starts_with('^')
            || revision.ends_with("^@")
            || revision.ends_with("^!")
            || revision.contains("^-")
    });
    if revisions.len() == 1 && !range && !extended && !sequence {
        let mut legacy = vec![args[0].clone(), args[1].clone(), revisions[0].clone()];
        if let Some(message) = options.message {
            legacy.extend(["-m".into(), message]);
        }
        if let Some(mainline) = options.mainline {
            legacy.extend(["--mainline".into(), mainline.to_string()]);
        }
        if record {
            legacy.push("--record-conflict".into());
        }
        return if record {
            operation_commands::run(&legacy)
        } else {
            history_commands::run(&legacy)
        };
    }
    porcelain::replay_start(&args[1], &args[0], revisions, options)
}
