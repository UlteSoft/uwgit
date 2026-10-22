//! Explicit read-only branch views share the native reference query snapshot.
use super::*;

const USAGE: &str = "branch DIR --list|-l [-r|--remotes|-a|--all] [--contains [REV]] [--no-contains [REV]] [--merged [REV]] [--no-merged [REV]] [--points-at OBJECT] [--ignore-case|-i] [--sort KEY]... [--format STR|--json] [--omit-empty] [--] [PATTERN...]\nbranch DIR --show-current\nbranch DIR [NAME [REV]|-d NAME|-D NAME|-m [OLD] NEW|-M [OLD] NEW|-c [OLD] NEW|-C [OLD] NEW|-f NAME [REV]|-vv|-u REMOTE/BRANCH [LOCAL_BRANCH]|--set-upstream-to REMOTE/BRANCH [LOCAL_BRANCH]|--unset-upstream [LOCAL_BRANCH]]\nFilters, format and sort imply listing. Patterns match whole displayed branch names with '*' and '?'. Output lists existing refs, never a synthetic detached/unborn branch. Bare branch and branch -vv retain their existing native display contracts.";

pub fn requested(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == "branch")
        && crate::command_args::option_arguments(args).any(|(_, value)| {
            let key = value.split_once('=').map_or(value, |(key, _)| key);
            matches!(
                key,
                "--list"
                    | "-l"
                    | "--help"
                    | "-h"
                    | "--show-current"
                    | "--contains"
                    | "--no-contains"
                    | "--merged"
                    | "--no-merged"
                    | "--points-at"
                    | "--format"
                    | "--sort"
                    | "--json"
                    | "--ignore-case"
                    | "-i"
                    | "--omit-empty"
                    | "--remotes"
                    | "-r"
                    | "--all"
                    | "-a"
            )
        })
}

pub(super) fn run(args: &[String]) -> RepositoryResult<QueryOutput> {
    if crate::command_args::help_requested(args) {
        return Ok(QueryOutput::new(format!("{USAGE}\n"), 0));
    }
    let dir = args.get(1).ok_or(USAGE)?;
    let mut seen = BTreeSet::new();
    let mut filter = ReferenceFilter::default();
    let mut patterns = Vec::new();
    let mut format = None;
    let mut sorts = Vec::new();
    let (mut json_mode, mut ignore_case, mut omit_empty, mut show_current) =
        (false, false, false, false);
    let mut scope = 0;
    let mut options = true;
    let mut cursor = 2;
    while cursor < args.len() {
        let arg = &args[cursor];
        let key = arg.split_once('=').map_or(arg.as_str(), |(key, _)| key);
        if options && arg == "--" {
            options = false;
        } else if options && arg.starts_with('-') {
            if graph_option(&mut filter, args, &mut cursor)? {
                // Graph terms are resolved together, before any row is emitted.
            } else if matches!(key, "--format" | "--sort") {
                if key == "--format" {
                    once(&mut seen, key)?;
                }
                let value = option_value(args, &mut cursor, arg)?;
                if key == "--format" {
                    format = Some(compile_format(value)?);
                } else {
                    sorts.push((
                        parse_atom(value.strip_prefix('-').unwrap_or(value))?,
                        value.starts_with('-'),
                    ));
                }
            } else {
                let flag = match arg.as_str() {
                    "-l" => "--list",
                    "-r" => "--remotes",
                    "-a" => "--all",
                    "-i" => "--ignore-case",
                    _ => arg,
                };
                once(&mut seen, flag)?;
                match flag {
                    "--list" => {}
                    "--show-current" => show_current = true,
                    "--json" => json_mode = true,
                    "--ignore-case" => ignore_case = true,
                    "--omit-empty" => omit_empty = true,
                    "--remotes" | "--all" if scope == 0 => {
                        scope = if flag == "--all" { 2 } else { 1 }
                    }
                    _ => {
                        return Err(format!(
                            "unsupported or conflicting branch listing option: {arg}"
                        ))
                    }
                }
            }
        } else {
            validate_ref_pattern(arg)?;
            patterns.push(arg.as_str());
        }
        cursor += 1;
    }
    if show_current && args.len() != 3 {
        return Err("--show-current must be used alone".into());
    }
    if json_mode && (format.is_some() || omit_empty) {
        return Err("--json cannot combine with --format or --omit-empty".into());
    }
    let (report, selected) = Repository::open(dir)?.query_refs_selected(&filter)?;
    if show_current {
        return Ok(QueryOutput::new(
            if crate::repository::is_detached_identity(&report.head) {
                String::new()
            } else {
                format!("{}\n", report.head)
            },
            0,
        ));
    }
    let displayed = |row: &QueryRef| {
        row.name
            .strip_prefix("refs/heads/")
            .or_else(|| row.name.strip_prefix("refs/remotes/"))
            .unwrap_or(&row.name)
            .to_owned()
    };
    let mut rows: Vec<_> = report
        .refs
        .iter()
        .filter(|row| {
            let local = row.name.starts_with("refs/heads/");
            let remote = row.name.starts_with("refs/remotes/");
            selected.contains(&row.name)
                && ((local && scope != 1) || (remote && scope != 0))
                && (patterns.is_empty()
                    || patterns.iter().any(|pattern| {
                        if ignore_case {
                            glob_match(
                                &displayed(row).to_ascii_lowercase(),
                                &pattern.to_ascii_lowercase(),
                            )
                        } else {
                            glob_match(&displayed(row), pattern)
                        }
                    }))
        })
        .cloned()
        .collect();
    sort_rows(&mut rows, &sorts, ignore_case, &report);
    if json_mode {
        return QueryOutput::json(query_json(&report, &rows));
    }
    let mut output = String::new();
    for row in rows {
        let mut line = String::new();
        if let Some(format) = &format {
            render_format(format, &row, &report, &mut line);
        } else {
            // Preserve the previous native -r/-a spelling and full IDs.
            let name = row.name.strip_prefix("refs/heads/").unwrap_or(&row.name);
            line = format!("{} {name} {}", if row.current { "*" } else { " " }, row.id);
        }
        if !omit_empty || !line.is_empty() {
            output.push_str(&line);
            output.push('\n');
        }
    }
    Ok(QueryOutput::new(output, 0))
}
