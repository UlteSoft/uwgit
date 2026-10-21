//! Names from committed tag history; no worktree or index interpretation.
use crate::query_commands::{tail_ref_match, validate_ref_pattern, QueryOutput};
use crate::repository::{DescribeOptions, Repository, RepositoryResult};
use serde_json::json;
use std::collections::BTreeSet;

const USAGE: &str = "usage: wasm-git describe DIR [REV] [--tags] [--exact-match] [--always] [--long] [--first-parent] [--abbrev N] [--match GLOB]... [--exclude GLOB]... [--no-match] [--no-exclude] [--json]\nREV defaults to HEAD. All stored tags are lightweight and are considered by default; --tags makes this explicit. Select the ancestor tag minimizing the number of target ancestors absent from the tag's ancestor closure; ties use ASCII tag name, because no tag dates are stored. --first-parent restricts both walks. Abbreviations are unique across all verified objects, at least max(4,N) digits (default 12, range 0..64). Zero suppresses long tag output and uses the full commit ID for --always fallback; it cannot combine with --long. --exact-match never falls back, even with --always. Globs support only '*' and '?'; match/exclude options accumulate, reset options clear them in argument order. Unsupported options and repeated ordinary flags are rejected.";

pub fn describe_query(args: &[String]) -> RepositoryResult<QueryOutput> {
    if crate::command_args::help_requested(args) {
        return Ok(QueryOutput::new(format!("{USAGE}\n"), 0));
    }
    if args.first().map(String::as_str) != Some("describe") {
        return Err(USAGE.into());
    }
    let mut positional = Vec::new();
    let mut seen = BTreeSet::new();
    let mut matches = Vec::new();
    let mut excludes = Vec::new();
    let (mut always, mut long, mut json_mode, mut first_parent, mut exact_match) =
        (false, false, false, false, false);
    let mut abbreviation = 12_usize;
    let mut options = true;
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if options && arg == "--" {
            options = false;
        } else if options && arg.starts_with('-') {
            let (key, attached) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(key, value)| (key, Some(value)));
            if matches!(key, "--match" | "--exclude" | "--abbrev") {
                if key == "--abbrev" && !seen.insert(key) {
                    return Err(format!("duplicate describe option: {key}"));
                }
                let value = if let Some(value) = attached {
                    value
                } else {
                    index += 1;
                    args.get(index)
                        .ok_or_else(|| format!("{key} requires a value"))?
                };
                if key == "--abbrev" {
                    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err("--abbrev requires an unsigned integer from 0 to 64".into());
                    }
                    abbreviation = value
                        .parse()
                        .map_err(|_| "--abbrev exceeds the supported integer range")?;
                    if abbreviation > 64 {
                        return Err("--abbrev must be between 0 and 64".into());
                    }
                } else {
                    validate_ref_pattern(value)?;
                    if key == "--match" {
                        matches.push(value.to_owned());
                    } else {
                        excludes.push(value.to_owned());
                    }
                }
            } else {
                if attached.is_some() {
                    return Err(format!("unsupported describe option: {arg}"));
                }
                if !matches!(key, "--no-match" | "--no-exclude") && !seen.insert(key) {
                    return Err(format!("duplicate describe option: {key}"));
                }
                match key {
                    "--tags" => {}
                    "--exact-match" => exact_match = true,
                    "--always" => always = true,
                    "--long" => long = true,
                    "--first-parent" => first_parent = true,
                    "--json" => json_mode = true,
                    "--no-match" => matches.clear(),
                    "--no-exclude" => excludes.clear(),
                    _ => return Err(format!("unsupported describe option: {arg}")),
                }
            }
        } else {
            positional.push(arg);
        }
        index += 1;
    }
    if !(1..=2).contains(&positional.len()) {
        return Err(USAGE.into());
    }
    if long && abbreviation == 0 {
        return Err("--long cannot be combined with --abbrev=0".into());
    }
    let revision = positional.get(1).map_or("HEAD", |value| value.as_str());
    let accept_tag = |tag: &str| -> RepositoryResult<bool> {
        let mut accepted = matches.is_empty();
        for pattern in &matches {
            accepted |= tail_ref_match(tag, pattern)?;
        }
        for pattern in &excludes {
            if tail_ref_match(tag, pattern)? {
                return Ok(false);
            }
        }
        Ok(accepted)
    };
    let report = Repository::open(positional[0])?.describe(
        revision,
        &DescribeOptions {
            first_parent,
            exact_match,
            abbrev: abbreviation,
        },
        accept_tag,
    )?;
    let fallback = report.tag.is_none();
    let description = if let Some(tag) = &report.tag {
        let distance = report
            .distance
            .ok_or("described tag lacks its verified distance")?;
        if abbreviation == 0 || (report.exact && !long) {
            tag.clone()
        } else {
            format!("{tag}-{distance}-g{}", report.abbreviation)
        }
    } else if always && !exact_match {
        report.abbreviation.clone()
    } else {
        return Err(format!(
            "no eligible {}tag for commit {}{}",
            if exact_match { "exact " } else { "ancestor " },
            report.commit,
            if exact_match {
                ""
            } else {
                "; use --always for a unique commit ID"
            }
        ));
    };
    if json_mode {
        let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
        value["description"] = json!(description);
        value["fallback"] = json!(fallback);
        value["long"] = json!(long);
        value["exact_match"] = json!(exact_match);
        value["match"] = json!(matches);
        value["exclude"] = json!(excludes);
        value["tags_policy"] = json!("all_stored_lightweight_tags");
        QueryOutput::json(value)
    } else {
        Ok(QueryOutput::new(format!("{description}\n"), 0))
    }
}
