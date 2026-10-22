//! Notes are native Wasm histories and travel through existing bundle/remotes.
use crate::query_commands::QueryOutput;
use crate::repository::{NotesRequest, Repository, RepositoryResult};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "wasm-git notes")]
struct Cli {
    dir: String,
    #[arg(long = "ref", default_value = "commits", global = true)]
    namespace: String,
    #[command(subcommand)]
    action: Option<Action>,
}
#[derive(Subcommand)]
enum Action {
    List {
        object: Option<String>,
    },
    Show {
        #[arg(default_value = "HEAD")]
        object: String,
    },
    Add {
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(short = 'm', long = "message", required = true, action = clap::ArgAction::Append, allow_hyphen_values = true)]
        messages: Vec<String>,
        #[arg(default_value = "HEAD")]
        object: String,
    },
    Append {
        #[arg(short = 'm', long = "message", required = true, action = clap::ArgAction::Append, allow_hyphen_values = true)]
        messages: Vec<String>,
        #[arg(default_value = "HEAD")]
        object: String,
    },
    Copy {
        #[arg(short = 'f', long)]
        force: bool,
        source: String,
        target: String,
    },
    Remove {
        #[arg(long)]
        ignore_missing: bool,
        objects: Vec<String>,
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
    let action = cli.action.unwrap_or(Action::List { object: None });
    let show = matches!(action, Action::Show { .. });
    let request = match action {
        Action::List { object } => NotesRequest::List(object),
        Action::Show { object } => NotesRequest::Show(object),
        Action::Add {
            force,
            messages,
            object,
        } => NotesRequest::Set {
            target: object,
            message: messages.join("\n\n"),
            force,
            append: false,
        },
        Action::Append { messages, object } => NotesRequest::Set {
            target: object,
            message: messages.join("\n\n"),
            force: false,
            append: true,
        },
        Action::Copy {
            force,
            source,
            target,
        } => NotesRequest::Copy {
            source,
            target,
            force,
        },
        Action::Remove {
            ignore_missing,
            mut objects,
        } => {
            if objects.is_empty() {
                objects.push("HEAD".into());
            }
            NotesRequest::Remove {
                targets: objects,
                ignore_missing,
            }
        }
    };
    let report = Repository::open(cli.dir)?.notes(&cli.namespace, request)?;
    if show {
        Ok(QueryOutput::new(
            format!("{}\n", report["text"].as_str().ok_or("missing note text")?),
            0,
        ))
    } else {
        QueryOutput::json(report)
    }
}
