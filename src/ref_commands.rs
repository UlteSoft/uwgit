//! Native symbolic references and explicit reference-name validation.
use crate::query_commands::QueryOutput;
use crate::repository::{self, Repository, RepositoryResult};
use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(name = "wasm-git")]
struct Cli {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    SymbolicRef {
        dir: String,
        #[arg(long)]
        short: bool,
        #[arg(short = 'q', long)]
        quiet: bool,
        #[arg(
            short = 'm',
            default_value = "symbolic-ref",
            allow_hyphen_values = true
        )]
        message: String,
        #[arg(default_value = "HEAD")]
        reference: String,
        target: Option<String>,
    },
    CheckRefFormat {
        #[arg(long, conflicts_with = "allow_onelevel")]
        branch: bool,
        #[arg(long)]
        allow_onelevel: bool,
        #[arg(long, conflicts_with = "branch")]
        normalize: bool,
        reference: String,
    },
}
pub fn handles(command: &str) -> bool {
    matches!(command, "symbolic-ref" | "check-ref-format")
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
    let output = match cli.action {
        Action::SymbolicRef {
            dir,
            short,
            quiet,
            message,
            reference,
            target,
        } => {
            if reference != "HEAD" {
                return Err("HEAD is the native symbolic reference".into());
            }
            if target.is_none() && Repository::open(&dir)?.state()?.detached() {
                if quiet {
                    return Ok(QueryOutput::new(String::new(), 1));
                }
                return Err("HEAD is detached".into());
            }
            let target = target
                .as_deref()
                .map(|target| {
                    target
                        .strip_prefix("refs/heads/")
                        .ok_or("symbolic HEAD target must use refs/heads/NAME")
                })
                .transpose()?;
            let name = if target.is_some() {
                crate::porcelain::with_no_pending(&dir, |repo| {
                    repo.symbolic_head(target, &message)
                })?
            } else {
                Repository::open(&dir)?.symbolic_head(None, &message)?
            };
            if target.is_some() {
                String::new()
            } else if short {
                name
            } else {
                format!("refs/heads/{name}")
            }
        }
        Action::CheckRefFormat {
            branch,
            allow_onelevel,
            normalize,
            reference,
        } => {
            let reference = if normalize {
                reference
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join("/")
            } else {
                reference
            };
            if branch {
                repository::validate_ref_name(&reference)?;
            } else if let Some(name) = reference
                .strip_prefix("refs/heads/")
                .or_else(|| reference.strip_prefix("refs/tags/"))
            {
                repository::validate_ref_name(name)?;
            } else if allow_onelevel {
                repository::validate_ref_name(&reference)?;
            } else {
                return Err("native full refs require refs/heads/NAME or refs/tags/NAME".into());
            }
            if branch || normalize {
                reference
            } else {
                String::new()
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
