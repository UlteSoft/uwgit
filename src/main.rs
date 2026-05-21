pub mod analysis;
mod diff;
mod fingerprint;
pub mod ir;
mod matcher;
mod normalize;
pub mod parse;
mod report;
mod resolve;

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: wasm-git <command> [<args>]");
        eprintln!();
        eprintln!("commands:");
        eprintln!("  inspect <FILE> [--json]  Print a deterministic JSON module summary");
        eprintln!("  diff    <OLD> <NEW> --format text|json  Compare two Wasm modules");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "inspect" => cmd_inspect(&args[2..]),
        "diff" => cmd_diff(&args[2..]),
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: wasm-git <command> [<args>]");
            std::process::exit(1);
        }
    }
}

fn cmd_inspect(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: wasm-git inspect <FILE> [--json]");
        std::process::exit(1);
    }

    let filepath = &args[0];

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

    let parsed = match parse::parse_module(&bytes) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    let resolved = resolve::resolve_module(parsed);
    let module = normalize::normalize_module(&resolved);

    let json = report::inspect_json(&module);
    println!("{json}");
}

fn cmd_diff(args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: wasm-git diff <OLD> <NEW> --format text|json");
        std::process::exit(1);
    }

    let old_path = &args[0];
    let new_path = &args[1];
    let format = parse_diff_format(&args[2..]);
    let old_module = read_module(old_path);
    let new_module = read_module(new_path);
    let report = diff::diff_modules(old_path, &old_module, new_path, &new_module);

    match format.as_str() {
        "text" => println!("{}", report::diff_text(&report)),
        "json" => println!("{}", report::diff_json(&report)),
        _ => unreachable!("format is validated by parse_diff_format"),
    }
}

fn parse_diff_format(args: &[String]) -> String {
    if args.is_empty() {
        return "text".to_owned();
    }
    if args.len() != 2 || args[0] != "--format" {
        eprintln!("usage: wasm-git diff <OLD> <NEW> --format text|json");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "text" | "json" => args[1].clone(),
        other => {
            eprintln!("error: unsupported diff format: {other}");
            eprintln!("usage: wasm-git diff <OLD> <NEW> --format text|json");
            std::process::exit(1);
        }
    }
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
            let resolved = resolve::resolve_module(parsed);
            normalize::normalize_module(&resolved)
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}
