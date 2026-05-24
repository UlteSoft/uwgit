pub mod analysis;
mod diff;
mod fingerprint;
pub mod ir;
mod matcher;
mod normalize;
pub mod parse;
mod report;
mod resolve;

use clap::{Parser, ValueEnum};
use std::io::Read;

#[derive(Debug, Parser)]
struct InspectArgs {
    filepath: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct DiffArgs {
    old_path: String,
    new_path: String,
    #[arg(long, value_enum, default_value_t = DiffFormat::Text)]
    format: DiffFormat,
    #[arg(long)]
    short: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DiffFormat {
    Text,
    Json,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage_and_exit();
    }

    match args[1].as_str() {
        "inspect" => cmd_inspect(&args[1..]),
        "diff" => cmd_diff(&args[1..]),
        other => {
            eprintln!("unknown command: {other}");
            print_usage_and_exit();
        }
    }
}

fn cmd_inspect(args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: wasm-git inspect <FILE> [--json]");
        std::process::exit(1);
    }

    let parsed = match InspectArgs::try_parse_from(
        std::iter::once("wasm-git").chain(args[1..].iter().map(String::as_str)),
    ) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let filepath = parsed.filepath;
    let _ = parsed.json;

    let mut file = match std::fs::File::open(&filepath) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("error: cannot open {filepath}: {err}");
            std::process::exit(1);
        }
    };

    let mut bytes = Vec::new();
    if let Err(err) = file.read_to_end(&mut bytes) {
        eprintln!("error: cannot read {filepath}: {err}");
        std::process::exit(1);
    }

    let parsed = match parse::parse_module(&bytes) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    let resolved = parsed.resolve();
    let module = resolved.normalize();

    let json = report::inspect_json(&module);
    println!("{json}");
}

fn cmd_diff(args: &[String]) {
    if args.len() < 3 {
        eprintln!("usage: wasm-git diff <OLD> <NEW> --format text|json");
        std::process::exit(1);
    }

    let parsed = match DiffArgs::try_parse_from(
        std::iter::once("wasm-git").chain(args[1..].iter().map(String::as_str)),
    ) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let old_module = read_module(&parsed.old_path);
    let new_module = read_module(&parsed.new_path);
    let report = diff::diff_modules(&parsed.old_path, &old_module, &parsed.new_path, &new_module);

    if parsed.short {
        println!("{}", report::diff_short(&report));
        return;
    }

    match parsed.format {
        DiffFormat::Text => println!("{}", report::diff_text(&report)),
        DiffFormat::Json => println!("{}", report::diff_json(&report)),
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!("usage: wasm-git <command> [<args>]");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  inspect <FILE> [--json]  Print a deterministic JSON module summary");
    eprintln!("  diff    <OLD> <NEW> [--short] [--format text|json]  Compare two Wasm modules");
    std::process::exit(1);
}

fn read_module(filepath: &str) -> ir::NormalizedModule {
    let mut file = match std::fs::File::open(filepath) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("error: cannot open {filepath}: {err}");
            std::process::exit(1);
        }
    };

    let mut bytes = Vec::new();
    if let Err(err) = file.read_to_end(&mut bytes) {
        eprintln!("error: cannot read {filepath}: {err}");
        std::process::exit(1);
    }

    match parse::parse_module(&bytes) {
        Ok(parsed) => {
            let resolved = parsed.resolve();
            resolved.normalize()
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}
