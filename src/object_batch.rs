//! Byte-exact streaming access to native object payloads.
use crate::repository::{Repository, RepositoryResult};
use clap::Parser;
use std::io::{BufRead, Write};
#[derive(Parser)]
#[command(name = "wasm-git cat-file")]
struct Args {
    dir: String,
    #[arg(long, conflicts_with_all = ["batch_check", "batch_command"])]
    batch: bool,
    #[arg(long, conflicts_with_all = ["batch", "batch_command"])]
    batch_check: bool,
    #[arg(long, conflicts_with_all = ["batch", "batch_check"])]
    batch_command: bool,
    #[arg(long)]
    buffer: bool,
    #[arg(short = 'z', conflicts_with = "nul_all")]
    nul_input: bool,
    #[arg(short = 'Z')]
    nul_all: bool,
}
fn request(reader: &mut impl BufRead, delimiter: u8) -> RepositoryResult<Option<Vec<u8>>> {
    let mut result = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|error| error.to_string())?;
        if available.is_empty() {
            return Ok((!result.is_empty()).then_some(result));
        }
        let count = available.iter().position(|byte| *byte == delimiter);
        let take = count.unwrap_or(available.len());
        if result.len().saturating_add(take) > 8192 {
            return Err("batch object request exceeds 8192 bytes".into());
        }
        result.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(count.is_some()));
        if count.is_some() {
            return Ok(Some(result));
        }
    }
}
pub fn requested(args: &[String]) -> bool {
    ["--batch", "--batch-check", "--batch-command"]
        .iter()
        .any(|flag| !crate::command_args::option_indices(args, flag).is_empty())
}
pub fn run(args: &[String]) -> RepositoryResult<()> {
    let args = match Args::try_parse_from(args) {
        Ok(args) => args,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            print!("{error}");
            return Ok(());
        }
        Err(error) => return Err(error.to_string()),
    };
    let repo = Repository::open(&args.dir)?;
    let input = if args.nul_input || args.nul_all {
        0
    } else {
        b'\n'
    };
    let output = if args.nul_all { 0 } else { b'\n' };
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    while let Some(bytes) = request(&mut stdin, input)? {
        let value = std::str::from_utf8(&bytes).map_err(|_| "batch revision must be UTF-8")?;
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err("batch revision requires nonempty text without control characters".into());
        }
        let (value, contents) = if args.batch_command {
            if value == "flush" {
                stdout.flush().map_err(|error| error.to_string())?;
                continue;
            }
            if let Some(value) = value.strip_prefix("info ") {
                (value, false)
            } else if let Some(value) = value.strip_prefix("contents ") {
                (value, true)
            } else {
                return Err("batch-command accepts info OBJECT, contents OBJECT, or flush".into());
            }
        } else {
            (value, args.batch)
        };
        if value.is_empty() {
            return Err("batch-command requires an object argument".into());
        }
        match repo.resolve_object(value) {
            Ok((id, kind, bytes)) => {
                write!(stdout, "{id} {kind} {}", bytes.len()).map_err(|error| error.to_string())?;
                stdout
                    .write_all(&[output])
                    .map_err(|error| error.to_string())?;
                if contents {
                    stdout
                        .write_all(&bytes)
                        .and_then(|()| stdout.write_all(&[output]))
                        .map_err(|error| error.to_string())?;
                }
            }
            Err(error)
                if matches!(
                    error.as_str(),
                    "unknown object revision"
                        | "unknown object prefix"
                        | "object path is absent from revision"
                        | "ambiguous object prefix"
                ) =>
            {
                write!(
                    stdout,
                    "{value} {}",
                    if error == "ambiguous object prefix" {
                        "ambiguous"
                    } else {
                        "missing"
                    }
                )
                .map_err(|error| error.to_string())?;
                stdout
                    .write_all(&[output])
                    .map_err(|error| error.to_string())?;
            }
            Err(error) => return Err(error),
        }
        if !args.buffer {
            stdout.flush().map_err(|error| error.to_string())?;
        }
    }
    stdout.flush().map_err(|error| error.to_string())
}
