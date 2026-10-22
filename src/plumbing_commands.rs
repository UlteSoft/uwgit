//! Native Wasm object plumbing. Payloads retain uwgit's canonical envelopes.
use crate::query_commands::QueryOutput;
use crate::repository::{Repository, RepositoryResult};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Parser)]
#[command(
    name = "wasm-git",
    about = "Native uwgit object and reference plumbing"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash a Core Wasm or canonical native metadata payload.
    HashObject {
        dir: String,
        #[arg(short = 'w')]
        write: bool,
        #[arg(short = 't', default_value = "wasm")]
        kind: String,
        #[arg(long, conflicts_with = "file", required_unless_present = "file")]
        stdin: bool,
        file: Option<String>,
    },
    /// Read "100644 wasm ID<TAB>PATH" records and store one flat tree.
    Mktree {
        dir: String,
        #[arg(short = 'z')]
        nul: bool,
    },
    /// Write the current complete index as immutable objects, keeping HEAD.
    WriteTree { dir: String },
    /// Replace only the index from a commit/tree, or an explicit empty tree.
    ReadTree {
        dir: String,
        #[arg(
            long,
            conflicts_with = "revision",
            required_unless_present = "revision"
        )]
        empty: bool,
        revision: Option<String>,
    },
    /// Build a commit from an existing tree without moving references.
    CommitTree {
        dir: String,
        tree: String,
        #[arg(short = 'p', action = clap::ArgAction::Append)]
        parents: Vec<String>,
        #[arg(short = 'm', action = clap::ArgAction::Append, required = true, allow_hyphen_values = true)]
        messages: Vec<String>,
    },
    /// Compare-and-swap a non-current native branch or tag.
    UpdateRef {
        dir: String,
        #[arg(short = 'd')]
        delete: bool,
        #[arg(short = 'm', default_value = "update-ref", allow_hyphen_values = true)]
        message: String,
        reference: String,
        values: Vec<String>,
    },
    /// List unique commits in deterministic child-before-parent order.
    RevList {
        dir: String,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        first_parent: bool,
        #[arg(long)]
        reverse: bool,
        #[arg(long, conflicts_with = "parents")]
        count: bool,
        #[arg(long)]
        parents: bool,
        #[arg(short = 'n', long)]
        max_count: Option<usize>,
        #[arg(allow_hyphen_values = true)]
        revisions: Vec<String>,
    },
}

pub fn handles(command: &str) -> bool {
    matches!(
        command,
        "hash-object"
            | "mktree"
            | "write-tree"
            | "read-tree"
            | "commit-tree"
            | "update-ref"
            | "rev-list"
    )
}

fn read_input(file: Option<String>) -> RepositoryResult<Vec<u8>> {
    if let Some(file) = file {
        std::fs::read(&file).map_err(|error| format!("cannot read input {file:?}: {error}"))
    } else {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        Ok(bytes)
    }
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
    let output = match cli.command {
        Command::HashObject {
            dir,
            write,
            kind,
            stdin: _,
            file,
        } => {
            let bytes = read_input(file)?;
            Repository::open(dir)?.hash_payload(&kind, &bytes, write)?
        }
        Command::Mktree { dir, nul } => {
            let bytes = read_input(None)?;
            let separator = if nul { 0 } else { b'\n' };
            let mut entries = BTreeMap::new();
            for record in bytes
                .split(|byte| *byte == separator)
                .filter(|record| !record.is_empty())
            {
                let record =
                    std::str::from_utf8(record).map_err(|_| "mktree requires UTF-8 records")?;
                let (header, path) = record
                    .split_once('\t')
                    .ok_or("mktree requires MODE TYPE ID<TAB>PATH")?;
                let header: Vec<_> = header.split(' ').collect();
                let ["100644", kind, id] = header.as_slice() else {
                    return Err("mktree accepts regular mode 100644 only".into());
                };
                if !matches!(*kind, "wasm" | "blob") {
                    return Err("mktree entries must name Wasm blob objects".into());
                }
                crate::repository::validate_tree_path(path)?;
                if entries.insert(path.into(), (*id).into()).is_some() {
                    return Err("duplicate mktree path".into());
                }
            }
            Repository::open(dir)?.create_tree_object(entries)?
        }
        Command::WriteTree { dir } => crate::porcelain::write_tree(&dir)?,
        Command::ReadTree {
            dir,
            empty: _,
            revision,
        } => crate::porcelain::read_tree(&dir, revision.as_deref())?,
        Command::CommitTree {
            dir,
            tree,
            parents,
            messages,
        } => {
            Repository::open(dir)?.create_commit_object(&tree, &parents, &messages.join("\n\n"))?
        }
        Command::UpdateRef {
            dir,
            delete,
            message,
            reference,
            values,
        } => {
            let (new, expected) = match (delete, values.as_slice()) {
                (false, [new]) => (Some(new.as_str()), None),
                (false, [new, old]) => (Some(new.as_str()), Some(old.as_str())),
                (true, []) => (None, None),
                (true, [old]) => (None, Some(old.as_str())),
                _ => return Err("update-ref DIR [-d] [-m MESSAGE] REF [NEW] [OLD]".into()),
            };
            crate::porcelain::with_no_pending(&dir, |repo| {
                repo.update_reference(&reference, new, expected, &message)
                    .and_then(|report| {
                        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
                    })
            })?
        }
        Command::RevList {
            dir,
            all,
            first_parent,
            reverse,
            count,
            parents,
            max_count,
            revisions,
        } => {
            let (mut includes, mut excludes) = (Vec::new(), Vec::new());
            for revision in revisions {
                if revision.starts_with('-') {
                    return Err(format!("unsupported rev-list option: {revision}"));
                }
                if revision.contains("...") {
                    includes.push(revision);
                    continue;
                }
                if let Some((left, right)) = revision.split_once("..") {
                    excludes.push(if left.is_empty() {
                        "HEAD".into()
                    } else {
                        left.into()
                    });
                    includes.push(if right.is_empty() {
                        "HEAD".into()
                    } else {
                        right.into()
                    });
                } else if let Some(revision) = revision.strip_prefix('^') {
                    excludes.push(revision.into());
                } else {
                    includes.push(revision);
                }
            }
            let mut commits =
                Repository::open(dir)?.revision_list(&includes, &excludes, all, first_parent)?;
            if let Some(max) = max_count {
                commits.truncate(max);
            }
            if reverse {
                commits.reverse();
            }
            if count {
                commits.len().to_string()
            } else {
                commits
                    .into_iter()
                    .map(|info| {
                        let mut row = info.id;
                        if parents {
                            for parent in info.commit.parents {
                                row.push(' ');
                                row.push_str(&parent);
                            }
                        }
                        row
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
    };
    Ok(QueryOutput::new(
        if output.is_empty() {
            output
        } else {
            format!("{output}\n")
        },
        0,
    ))
}
