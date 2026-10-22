//! Explicit checkout modes reuse the index/worktree locks and preflight used
//! by switch and restore. The existing exclusive export syntax is retained.

use crate::{command_args, porcelain, repository, tree_output};

const USAGE: &str = "checkout DIR BRANCH_OR_REV; checkout DIR --detach [REV]; checkout DIR --orphan NAME; checkout DIR -; checkout DIR -b NAME [REV]; checkout DIR -- PATH...; checkout DIR [--ours|--theirs|--merge|-m] [--ignore-skip-worktree-bits] -- PATHSPEC...; checkout DIR REV -- PATH...; checkout DIR REV NEW_FILE [--file PATH]. Revision path mode restores source-present paths into index/worktree, including tracked file/directory transitions, and preserves unrelated paths absent from that revision (overlay). Commit/tag checkout uses a true detached HEAD. Path replacement requires an explicit -- separator.";

pub fn run(args: &[String]) -> Result<String, String> {
    if command_args::help_requested(args) {
        return Ok(USAGE.into());
    }
    if args.len() < 3 {
        return Err(USAGE.into());
    }
    if let Some(separator) = command_args::separator_index(args) {
        if separator + 1 == args.len() {
            return Err("checkout path mode requires at least one path after --".into());
        }
        let mut forwarded = vec!["restore".to_owned(), args[1].clone()];
        match separator {
            2 => {}
            3 if !args[2].starts_with('-') => forwarded.extend([
                "--source".into(),
                args[2].clone(),
                "--staged".into(),
                "--worktree".into(),
                "--overlay".into(),
            ]),
            _ if args[2..separator].iter().all(|option| {
                matches!(
                    option.as_str(),
                    "--ours" | "--theirs" | "-m" | "--merge" | "--ignore-skip-worktree-bits"
                )
            }) =>
            {
                forwarded.extend_from_slice(&args[2..separator])
            }
            _ => return Err(USAGE.into()),
        }
        forwarded.push("--".into());
        forwarded.extend_from_slice(&args[separator + 1..]);
        return porcelain::run(&forwarded);
    }
    match &args[2..] {
        [option, rest @ ..] if matches!(option.as_str(), "--detach" | "--orphan") => {
            let mut forwarded = vec!["switch".into(), args[1].clone(), option.clone()];
            forwarded.extend_from_slice(rest);
            porcelain::run(&forwarded)
        }
        [name] if name == "-" => porcelain::run(&["switch".into(), args[1].clone(), name.clone()]),
        [name] if !name.starts_with('-') => {
            if repository::Repository::open(&args[1])?
                .branches()?
                .contains_key(name)
            {
                porcelain::run(&["switch".into(), args[1].clone(), name.clone()])
            } else {
                porcelain::run(&[
                    "switch".into(),
                    args[1].clone(),
                    "--detach".into(),
                    name.clone(),
                ])
            }
        }
        [option, name] if option == "-b" => {
            porcelain::run(&["switch".into(), args[1].clone(), "-c".into(), name.clone()])
        }
        [option, name, revision] if option == "-b" => porcelain::run(&[
            "switch".into(),
            args[1].clone(),
            "-c".into(),
            name.clone(),
            revision.clone(),
        ]),
        _ if args
            .iter()
            .any(|arg| arg == "--file" || arg.starts_with("--file=")) =>
        {
            tree_output::export_file(args)
        }
        [revision, _output] if !revision.starts_with('-') => repository::run(args),
        _ => Err(USAGE.into()),
    }
}
