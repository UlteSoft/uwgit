//! Read-only views bound to one verified repository snapshot per query.
use crate::repository::{self, QueryRef, QueryRefs, Repository, RepositoryResult};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub struct QueryOutput {
    pub stdout: String,
    pub exit_code: i32,
}

impl QueryOutput {
    pub fn new(stdout: String, exit_code: i32) -> Self {
        Self { stdout, exit_code }
    }

    pub fn json(value: Value) -> RepositoryResult<Self> {
        Ok(Self::new(
            format!(
                "{}\n",
                serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?
            ),
            0,
        ))
    }
}

const TREE_USAGE: &str = "usage: wasm-git ls-tree DIR REV [-r] [--json | --name-only | --object-only] [-z] [-- PATH...]\nThe stored tree is flat: -r includes the same complete paths. JSON reports actual object IDs and payload/envelope sizes; no directory objects or modes are invented. Text modes require a named tree. Paths select an exact file, a directory prefix, or '.'; every selector must match. -z requires a text mode and emits raw UTF-8/NUL without an extra newline.";
const SHOW_USAGE: &str = "usage: wasm-git show-ref DIR [--head] [--heads|--branches] [--tags] [--verify] [--quiet|-q | --hash | --json] [PATTERN...]\nDefault output: ID SPACE full-ref LF. Patterns are literal component-boundary suffixes. --head adds the committed HEAD regardless of non-verify filters. --verify requires exact full refs or HEAD and fails atomically with exit 1 if any are missing. No match exits 1; --quiet suppresses output. Unborn HEAD has no invented ID.";
const EACH_USAGE: &str = "usage: wasm-git for-each-ref DIR [--json | --format STR] [--sort KEY]... [--count N] [PATTERN...]\nPatterns are full-ref literal prefixes at slash boundaries, or full-ref globs using only '*' and '?'. Sort keys: refname, objectname, objectsize (payload bytes); '-' reverses order and the last key is primary. Count 0 means unlimited. Format atoms: refname, objectname, objecttype, objectsize, HEAD, upstream. %% and %00..%7f are supported; one LF is appended per row. Other atoms/modifiers/escapes are rejected. HEAD is not a ref row.";
const COUNT_USAGE: &str = "usage: wasm-git count-objects DIR [-v|--verbose] [-H|--human-readable]\nJSON counts unique loose SHA-256 objects and logical payload/envelope bytes, not allocated filesystem blocks or compressed Git packs. -v includes per-kind counts; -H adds human-readable byte sizes. Reachability includes local refs, fetched tracking branches and reflog endpoints; pending/index and remote-only cached tags are excluded. Unreachable does not imply safe deletion.";

pub fn handles(command: &str) -> bool {
    matches!(
        command,
        "ls-tree"
            | "show-ref"
            | "for-each-ref"
            | "count-objects"
            | "ls-remote"
            | "describe"
            | "archive"
    )
}

pub fn run(args: &[String]) -> RepositoryResult<QueryOutput> {
    let command = args.first().map_or("", String::as_str);
    if command == "describe" {
        return crate::describe_commands::describe_query(args);
    }
    if command == "archive" {
        return crate::archive_commands::archive_query(args);
    }
    if command == "ls-remote" {
        return crate::remote::ls_remote_query(args);
    }
    let usage = match command {
        "ls-tree" => TREE_USAGE,
        "show-ref" => SHOW_USAGE,
        "for-each-ref" => EACH_USAGE,
        "count-objects" => COUNT_USAGE,
        _ => return Err("unknown query command".into()),
    };
    if crate::command_args::help_requested(args) {
        return Ok(QueryOutput::new(format!("{usage}\n"), 0));
    }
    match command {
        "ls-tree" => ls_tree(&args[1..]),
        "show-ref" => show_ref(&args[1..]),
        "for-each-ref" => for_each_ref(&args[1..]),
        "count-objects" => count_objects(&args[1..]),
        _ => unreachable!(),
    }
}

fn once(seen: &mut BTreeSet<String>, flag: &str) -> RepositoryResult<()> {
    if !seen.insert(flag.to_owned()) {
        return Err(format!("duplicate option: {flag}"));
    }
    Ok(())
}

fn unknown(option: &str) -> String {
    format!("unsupported query option: {option}")
}

fn ls_tree(args: &[String]) -> RepositoryResult<QueryOutput> {
    let mut seen = BTreeSet::new();
    let mut positional = Vec::new();
    let mut paths = Vec::new();
    let mut separated = false;
    let (mut json_mode, mut names, mut objects, mut nul) = (false, false, false, false);
    for arg in args {
        if separated {
            paths.push(arg.as_str());
        } else if arg == "--" {
            separated = true;
        } else if arg.starts_with('-') {
            once(&mut seen, arg)?;
            match arg.as_str() {
                "--json" => json_mode = true,
                "--name-only" => names = true,
                "--object-only" => objects = true,
                "-z" => nul = true,
                "-r" => {}
                _ => return Err(unknown(arg)),
            }
        } else {
            positional.push(arg);
        }
    }
    if positional.len() != 2 || (separated && paths.is_empty()) {
        return Err(TREE_USAGE.into());
    }
    if usize::from(json_mode) + usize::from(names) + usize::from(objects) > 1 {
        return Err("--json, --name-only and --object-only are mutually exclusive".into());
    }
    if nul && !(names || objects) {
        return Err("-z requires --name-only or --object-only".into());
    }
    let selectors: Vec<_> = paths
        .iter()
        .map(|path| {
            let normalized = path.strip_suffix('/').unwrap_or(path);
            if normalized != "." {
                repository::validate_tree_path(normalized)?;
            }
            Ok(*path)
        })
        .collect::<RepositoryResult<_>>()?;
    let mut report = Repository::open(positional[0])?.query_tree(positional[1])?;
    if !report.named && (!selectors.is_empty() || names || objects) {
        return Err(
            "legacy commit has no named tree; use JSON to inspect its actual legacy object".into(),
        );
    }
    for selector in &selectors {
        if !report
            .entries
            .iter()
            .any(|entry| tree_matches(&entry.path, selector))
        {
            return Err(format!("tree path selector has no match: {selector:?}"));
        }
    }
    if !selectors.is_empty() {
        report
            .entries
            .retain(|entry| selectors.iter().any(|path| tree_matches(&entry.path, path)));
    }
    if names || objects {
        let mut output = String::new();
        for entry in report.entries {
            output.push_str(if names { &entry.path } else { &entry.object_id });
            output.push(if nul { '\0' } else { '\n' });
        }
        Ok(QueryOutput::new(output, 0))
    } else {
        QueryOutput::json(serde_json::to_value(report).map_err(|error| error.to_string())?)
    }
}

fn tree_matches(path: &str, selector: &str) -> bool {
    let directory_only = selector.ends_with('/');
    let selector = selector.strip_suffix('/').unwrap_or(selector);
    selector == "."
        || (!directory_only && path == selector)
        || path
            .strip_prefix(selector)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn head_ref(report: &QueryRefs) -> Option<QueryRef> {
    report
        .refs
        .iter()
        .find(|reference| reference.current)
        .cloned()
        .map(|mut reference| {
            reference.name = "HEAD".into();
            reference
        })
}

fn query_json(report: &QueryRefs, refs: &[QueryRef]) -> Value {
    json!({"schema_version":report.schema_version, "head":report.head,
        "head_tip":report.head_tip, "refs":refs})
}

fn literal_pattern(pattern: &str) -> RepositoryResult<()> {
    if pattern.is_empty()
        || pattern.len() > 1024
        || pattern.chars().any(char::is_control)
        || pattern.contains('\\')
    {
        return Err(format!("invalid reference pattern: {pattern:?}"));
    }
    Ok(())
}

fn verify_name(name: &str) -> RepositoryResult<()> {
    literal_pattern(name)?;
    if name == "HEAD" {
        return Ok(());
    }
    if !name.starts_with("refs/")
        || name
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b"/._-".contains(&byte))
    {
        return Err(format!(
            "--verify requires an exact full reference or HEAD: {name:?}"
        ));
    }
    Ok(())
}

fn show_ref(args: &[String]) -> RepositoryResult<QueryOutput> {
    let mut seen = BTreeSet::new();
    let mut positional = Vec::new();
    let mut options = true;
    let (mut head, mut heads, mut tags, mut verify, mut quiet, mut hash, mut json_mode) =
        (false, false, false, false, false, false, false);
    for arg in args {
        if options && arg == "--" {
            options = false;
            continue;
        }
        if options && arg.starts_with('-') {
            let key = match arg.as_str() {
                "--branches" => "--heads",
                "-q" => "--quiet",
                _ => arg,
            };
            once(&mut seen, key)?;
            match key {
                "--head" => head = true,
                "--heads" => heads = true,
                "--tags" => tags = true,
                "--verify" => verify = true,
                "--quiet" => quiet = true,
                "--hash" => hash = true,
                "--json" => json_mode = true,
                _ => return Err(unknown(arg)),
            }
        } else {
            positional.push(arg);
        }
    }
    if positional.is_empty() {
        return Err(SHOW_USAGE.into());
    }
    if usize::from(quiet) + usize::from(hash) + usize::from(json_mode) > 1 {
        return Err("--quiet, --hash and --json are mutually exclusive".into());
    }
    let patterns = &positional[1..];
    if verify && patterns.is_empty() {
        return Err("--verify requires at least one full reference or HEAD".into());
    }
    for pattern in patterns {
        if verify {
            verify_name(pattern)?;
        } else {
            literal_pattern(pattern)?;
        }
    }
    let report = Repository::open(positional[0])?.query_refs()?;
    let mut rows = report.refs.clone();
    let selected_head = head_ref(&report);
    if verify {
        if let Some(reference) = selected_head {
            rows.insert(0, reference);
        }
        let missing: Vec<_> = patterns
            .iter()
            .filter(|pattern| !rows.iter().any(|row| row.name == pattern.as_str()))
            .collect();
        if !missing.is_empty() {
            if quiet {
                return Ok(QueryOutput::new(String::new(), 1));
            }
            return Err(format!(
                "reference not found: {}",
                missing
                    .iter()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        rows = patterns
            .iter()
            .map(|pattern| {
                rows.iter()
                    .find(|row| row.name == pattern.as_str())
                    .unwrap()
                    .clone()
            })
            .collect();
    } else {
        rows.retain(|row| {
            (!(heads || tags)
                || (heads && row.name.starts_with("refs/heads/"))
                || (tags && row.name.starts_with("refs/tags/")))
                && (patterns.is_empty()
                    || patterns.iter().any(|pattern| {
                        row.name == pattern.as_str()
                            || row
                                .name
                                .strip_suffix(pattern.as_str())
                                .is_some_and(|prefix| prefix.ends_with('/'))
                    }))
        });
        if head {
            if let Some(reference) = selected_head {
                rows.insert(0, reference);
            }
        }
    }
    let exit_code = if rows.is_empty() { 1 } else { 0 };
    if quiet {
        return Ok(QueryOutput::new(String::new(), exit_code));
    }
    if json_mode {
        let mut output = QueryOutput::json(query_json(&report, &rows))?;
        output.exit_code = exit_code;
        return Ok(output);
    }
    let stdout = rows
        .iter()
        .map(|row| {
            if hash {
                format!("{}\n", row.id)
            } else {
                format!("{} {}\n", row.id, row.name)
            }
        })
        .collect();
    Ok(QueryOutput::new(stdout, exit_code))
}

/// Explicitly bounded wildcard grammar shared with advertisement-only queries.
pub fn validate_ref_pattern(pattern: &str) -> RepositoryResult<()> {
    literal_pattern(pattern)?;
    if pattern.contains(['[', ']']) {
        return Err("reference globs support only '*' and '?' (no brackets or escapes)".into());
    }
    Ok(())
}

fn glob_match(value: &str, pattern: &str) -> bool {
    let (value, pattern) = (value.as_bytes(), pattern.as_bytes());
    let (mut index, mut at, mut star, mut retry) = (0, 0, None, 0);
    while index < value.len() {
        if at < pattern.len() && (pattern[at] == b'?' || pattern[at] == value[index]) {
            index += 1;
            at += 1;
        } else if at < pattern.len() && pattern[at] == b'*' {
            star = Some(at);
            at += 1;
            retry = index;
        } else if let Some(previous) = star {
            retry += 1;
            index = retry;
            at = previous + 1;
        } else {
            return false;
        }
    }
    while at < pattern.len() && pattern[at] == b'*' {
        at += 1;
    }
    at == pattern.len()
}

pub fn tail_ref_match(reference: &str, pattern: &str) -> RepositoryResult<bool> {
    validate_ref_pattern(pattern)?;
    Ok(glob_match(reference, pattern)
        || reference
            .match_indices('/')
            .any(|(index, _)| glob_match(&reference[index + 1..], pattern)))
}

#[derive(Clone, Copy)]
enum Atom {
    Refname,
    Objectname,
    Objecttype,
    Objectsize,
    Head,
    Upstream,
}
enum Fragment {
    Literal(String),
    Atom(Atom),
}

fn compile_format(format: &str) -> RepositoryResult<Vec<Fragment>> {
    if format.len() > 64 * 1024 {
        return Err("query format exceeds 64 KiB".into());
    }
    let mut fragments = Vec::new();
    let mut literal = String::new();
    let mut rest = format;
    while let Some(index) = rest.find('%') {
        literal.push_str(&rest[..index]);
        rest = &rest[index + 1..];
        if let Some(tail) = rest.strip_prefix('%') {
            literal.push('%');
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('(') {
            let end = tail.find(')').ok_or("unterminated query format atom")?;
            let atom = match &tail[..end] {
                "refname" => Atom::Refname,
                "objectname" => Atom::Objectname,
                "objecttype" => Atom::Objecttype,
                "objectsize" => Atom::Objectsize,
                "HEAD" => Atom::Head,
                "upstream" => Atom::Upstream,
                name => return Err(format!("unsupported query format atom: {name:?}")),
            };
            fragments.push(Fragment::Literal(std::mem::take(&mut literal)));
            fragments.push(Fragment::Atom(atom));
            rest = &tail[end + 1..];
        } else {
            let digits = rest.as_bytes();
            if digits.len() < 2 || !digits[..2].iter().all(u8::is_ascii_hexdigit) {
                return Err("format '%' requires %, an atom, or two ASCII hex digits".into());
            }
            let byte = u8::from_str_radix(&rest[..2], 16).map_err(|error| error.to_string())?;
            if byte > 127 {
                return Err(
                    "format %xx only supports ASCII bytes 00..7f; use literal UTF-8 for other text"
                        .into(),
                );
            }
            literal.push(char::from(byte));
            rest = &rest[2..];
        }
    }
    literal.push_str(rest);
    fragments.push(Fragment::Literal(literal));
    Ok(fragments)
}

fn render_format(fragments: &[Fragment], row: &QueryRef, output: &mut String) {
    for fragment in fragments {
        match fragment {
            Fragment::Literal(text) => output.push_str(text),
            Fragment::Atom(atom) => match atom {
                Atom::Refname => output.push_str(&row.name),
                Atom::Objectname => output.push_str(&row.id),
                Atom::Objecttype => output.push_str(&row.kind),
                Atom::Objectsize => output.push_str(&row.byte_len.to_string()),
                Atom::Head => output.push(if row.current { '*' } else { ' ' }),
                Atom::Upstream => {
                    if let Some(upstream) = &row.upstream {
                        output.push_str(&format!(
                            "refs/remotes/{}/{}",
                            upstream.remote, upstream.branch
                        ));
                    }
                }
            },
        }
    }
    output.push('\n');
}

fn for_each_ref(args: &[String]) -> RepositoryResult<QueryOutput> {
    let mut seen = BTreeSet::new();
    let mut positional = Vec::new();
    let mut options = true;
    let mut json_mode = false;
    let mut format = None;
    let mut sorts = Vec::new();
    let mut count = 0_usize;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if options && arg == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && arg.starts_with('-') {
            if arg == "--json" {
                once(&mut seen, arg)?;
                json_mode = true;
            } else {
                let (key, attached) = arg
                    .split_once('=')
                    .map_or((arg.as_str(), None), |(key, value)| (key, Some(value)));
                if !matches!(key, "--format" | "--sort" | "--count") {
                    return Err(unknown(arg));
                }
                if key != "--sort" {
                    once(&mut seen, key)?;
                }
                let value = if let Some(value) = attached {
                    value
                } else {
                    index += 1;
                    args.get(index)
                        .ok_or_else(|| format!("{key} requires a value"))?
                };
                match key {
                    "--format" => format = Some(compile_format(value)?),
                    "--sort" => {
                        let key = value.strip_prefix('-').unwrap_or(value);
                        if !matches!(key, "refname" | "objectname" | "objectsize") {
                            return Err(format!("unsupported reference sort key: {value:?}"));
                        }
                        sorts.push((key.to_owned(), value.starts_with('-')));
                    }
                    "--count" => {
                        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                            return Err("--count requires an unsigned integer".into());
                        }
                        count = value
                            .parse()
                            .map_err(|_| "--count exceeds the supported integer range")?;
                    }
                    _ => unreachable!(),
                }
            }
        } else {
            positional.push(arg);
        }
        index += 1;
    }
    if positional.is_empty() {
        return Err(EACH_USAGE.into());
    }
    if json_mode && format.is_some() {
        return Err("--json and --format are mutually exclusive".into());
    }
    let patterns = &positional[1..];
    for pattern in patterns {
        validate_ref_pattern(pattern)?;
    }
    let report = Repository::open(positional[0])?.query_refs()?;
    let mut rows: Vec<_> = report
        .refs
        .iter()
        .filter(|row| {
            patterns.is_empty()
                || patterns.iter().any(|pattern| {
                    if pattern.contains(['*', '?']) {
                        glob_match(&row.name, pattern)
                    } else {
                        row.name == pattern.as_str()
                            || (pattern.ends_with('/') && row.name.starts_with(pattern.as_str()))
                            || row
                                .name
                                .strip_prefix(pattern.as_str())
                                .is_some_and(|tail| tail.starts_with('/'))
                    }
                })
        })
        .cloned()
        .collect();
    for (key, descending) in sorts {
        rows.sort_by(|left, right| {
            let order = match key.as_str() {
                "objectname" => left.id.cmp(&right.id),
                "objectsize" => left.byte_len.cmp(&right.byte_len),
                _ => left.name.cmp(&right.name),
            };
            if descending {
                order.reverse()
            } else {
                order
            }
        });
    }
    if count > 0 {
        rows.truncate(count);
    }
    if json_mode {
        return QueryOutput::json(query_json(&report, &rows));
    }
    let mut output = String::new();
    for row in rows {
        if let Some(format) = &format {
            render_format(format, &row, &mut output);
        } else {
            output.push_str(&format!("{} {}\t{}\n", row.id, row.kind, row.name));
        }
    }
    Ok(QueryOutput::new(output, 0))
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn count_objects(args: &[String]) -> RepositoryResult<QueryOutput> {
    let mut seen = BTreeSet::new();
    let mut positional = Vec::new();
    let (mut verbose, mut human, mut options) = (false, false, true);
    for arg in args {
        if options && arg == "--" {
            options = false;
            continue;
        }
        if options && arg.starts_with('-') {
            let key = match arg.as_str() {
                "-v" => "--verbose",
                "-H" => "--human-readable",
                _ => arg,
            };
            once(&mut seen, key)?;
            match key {
                "--verbose" => verbose = true,
                "--human-readable" => human = true,
                _ => return Err(unknown(arg)),
            }
        } else {
            positional.push(arg);
        }
    }
    if positional.len() != 1 {
        return Err(COUNT_USAGE.into());
    }
    let report = Repository::open(positional[0])?.query_objects()?;
    let mut value = serde_json::to_value(&report).map_err(|error| error.to_string())?;
    if !verbose {
        value.as_object_mut().unwrap().remove("by_kind");
    } else {
        value["packs_supported"] = json!(false);
    }
    value["storage"] = json!("loose_uncompressed_sha256");
    value["disk_allocation_reported"] = json!(false);
    if human {
        value["payload_human"] = json!(human_bytes(report.payload_bytes));
        value["stored_human"] = json!(human_bytes(report.stored_bytes));
    }
    QueryOutput::json(value)
}
