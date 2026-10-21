//! File-tree presentation keeps absence separate from zero-length bytes. Every
//! path is shown; a rename is a deletion and an addition, never inferred identity.

use crate::porcelain::FileDiffSnapshot;
use crate::repository::{self, RevisionFiles};
use crate::{audit, DiffArgs, DiffFormat, Input};
use clap::Parser;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use wasm_git::standard::Standard;

fn origin(reference: &str, revision: &RevisionFiles, file: Option<&str>) -> Value {
    let mut result = json!({"revision": reference,"commit":revision.commit});
    if let Some(file) = file {
        result["file"] = json!(file);
        if revision.legacy.is_some() {
            result["legacy_binding"] =
                json!("explicit selected path; legacy commit has no filename");
        }
    }
    result
}

pub fn select_input(
    reference: &str,
    revision: RevisionFiles,
    file: Option<&str>,
) -> Result<Input, String> {
    if let Some(file) = file {
        repository::validate_tree_path(file)?;
    }
    if let Some(bytes) = &revision.legacy {
        return Ok(Input {
            bytes: bytes.clone(),
            origin: origin(reference, &revision, file),
        });
    }
    let file = match file {
        Some(file) => file,
        None if revision.files.len() == 1 => revision.files.keys().next().ok_or("missing file")?,
        None => {
            return Err("this revision is a file tree; select a module with --file PATH".into())
        }
    };
    let bytes = revision
        .files
        .get(file)
        .ok_or_else(|| format!("file {file:?} is absent from revision {}", revision.commit))?
        .clone();
    Ok(Input {
        bytes,
        origin: origin(reference, &revision, Some(file)),
    })
}

pub fn select_inputs(
    references: &[&str],
    mut revisions: Vec<RevisionFiles>,
    file: Option<&str>,
) -> Result<Vec<Input>, String> {
    if references.len() != revisions.len() {
        return Err("input references do not match pinned snapshots".into());
    }
    if file.is_none() && revisions.iter().any(|r| r.legacy.is_none()) {
        return Err("file-tree byte operations require --file PATH".into());
    }
    let anchors: BTreeSet<_> = revisions
        .iter()
        .filter_map(|r| r.legacy_path.clone())
        .collect();
    if let Some(file) = file {
        repository::validate_tree_path(file)?;
        if anchors.len() > 1 && revisions.iter().any(|r| r.legacy.is_some()) {
            return Err("conflicting recorded legacy path mappings".into());
        }
        if let Some(anchor) = anchors.first() {
            if anchor != file && revisions.iter().any(|r| r.legacy.is_some()) {
                return Err(format!("file {file:?} is absent in the unnamed legacy revision, whose recorded binding is {anchor:?}"));
            }
        }
    }
    references
        .iter()
        .zip(revisions.drain(..))
        .map(|(reference, revision)| select_input(reference, revision, file))
        .collect()
}

pub fn inspect_tree(
    reference: &str,
    revision: RevisionFiles,
    standard: Standard,
) -> Result<String, String> {
    let files = revision
        .files
        .iter()
        .map(|(file, bytes)| {
            let input = Input {
                bytes: bytes.clone(),
                origin: origin(reference, &revision, Some(file)),
            };
            crate::inspect_input(&input, standard)
                .map(|report| json!({"path":file,"report":report}))
        })
        .collect::<Result<Vec<_>, _>>()?;
    serde_json::to_string_pretty(&json!({"schema_version":2,"kind":"tree_inspect","input":origin(reference,&revision,None),"file_count":files.len(),"files":files})).map_err(|e|e.to_string())
}

pub fn diff_revisions(
    parsed: &DiffArgs,
    mut revisions: Vec<RevisionFiles>,
) -> Result<String, String> {
    if revisions.len() != 2 {
        return Err("diff requires two pinned revision snapshots".into());
    }
    if let Some(file) = &parsed.file {
        repository::validate_tree_path(file)?;
    }
    let anchors: BTreeSet<String> = revisions
        .iter()
        .filter_map(|r| r.legacy_path.clone())
        .collect();
    // A recorded promotion anchor wins over a later path filter. Otherwise an
    // unrelated newly added path would appear to contain the old unnamed blob.
    let anchor = if anchors.len() == 1 {
        anchors.first().cloned()
    } else if anchors.is_empty() {
        parsed.file.clone()
    } else {
        None
    };
    let old_origin = origin(&parsed.old_path, &revisions[0], None);
    let new_origin = origin(&parsed.new_path, &revisions[1], None);
    let references = [parsed.old_path.as_str(), parsed.new_path.as_str()];
    let mut origins = Vec::new();
    for (r, reference) in revisions.iter_mut().zip(references) {
        let mut per_file = std::collections::BTreeMap::new();
        if r.legacy.is_some() {
            let path=anchor.as_ref().ok_or("cannot compare unnamed legacy content with a tree without one explicit legacy mapping; use --file PATH")?;
            per_file.insert(path.clone(), origin(reference, r, Some(path)));
            r.files
                .insert(path.clone(), r.legacy.take().ok_or("missing legacy bytes")?);
        } else {
            for path in r.files.keys() {
                per_file.insert(path.clone(), origin(reference, r, Some(path)));
            }
        }
        origins.push(per_file);
    }
    let paths: BTreeSet<_> = revisions[0]
        .files
        .keys()
        .chain(revisions[1].files.keys())
        .cloned()
        .collect();
    let rows = paths
        .into_iter()
        .map(|path| FileDiffSnapshot {
            old: revisions[0].files.get(&path).cloned(),
            new: revisions[1].files.get(&path).cloned(),
            old_origin: origins[0].get(&path).cloned().unwrap_or(Value::Null),
            new_origin: origins[1].get(&path).cloned().unwrap_or(Value::Null),
            path,
        })
        .collect();
    render_files(parsed, rows, old_origin, new_origin)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn witness(side: &str, bytes: &[u8]) -> Value {
    json!({"side":side,"byte_len":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),"span":{"start":0,"end":bytes.len()},"hex":hex(bytes)})
}

fn audit_side(bytes: &[u8], standard: Standard) -> Value {
    match audit::inspect_with_standard(bytes, standard) {
        Ok(report) => json!(report),
        Err(reason) => {
            json!({"available":false,"view":"binary","reason":reason,"byte_len":bytes.len(),"selected_standard":standard})
        }
    }
}

// A corrupt worktree header still has physical bytes. Keep its complete byte
// witness and one prefix/suffix-bounded edit. No minimum-edit claim is made.
fn binary_diff(old: &Input, new: &Input, standard: Standard, reason: &str) -> Value {
    let a = &old.bytes;
    let b = &new.bytes;
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (a_end, b_end) = (a.len() - suffix, b.len() - suffix);
    let edits = if a == b {
        Vec::new()
    } else {
        vec![
            json!({"old_span":{"start":prefix,"end":a_end},"new_span":{"start":prefix,"end":b_end},"old_hex":hex(&a[prefix..a_end]),"new_hex":hex(&b[prefix..b_end]),"view":"binary"}),
        ]
    };
    json!({"schema_version":1,"binary_changed":a!=b,"inputs":{"old":old.origin,"new":new.origin},"function_analysis":crate::analysis_scope(json!({"available":false,"reason":reason}),standard),"audit":{"changed":a!=b,"exact_minimal":false,"alignment":"equal prefix/suffix with complete middle replacement; invalid Core header","old":audit_side(a,standard),"new":audit_side(b,standard),"edits":edits,"binary_witnesses":{"old":witness("old",a),"new":witness("new",b)}}})
}

fn labels(parsed: &DiffArgs, format: DiffFormat) -> DiffArgs {
    DiffArgs {
        old_path: parsed.old_path.clone(),
        new_path: parsed.new_path.clone(),
        format,
        short: parsed.short,
        repo: None,
        file: None,
        standard: parsed.standard,
    }
}

pub fn render_files(
    parsed: &DiffArgs,
    mut rows: Vec<FileDiffSnapshot>,
    old_origin: Value,
    new_origin: Value,
) -> Result<String, String> {
    if let Some(file) = &parsed.file {
        repository::validate_tree_path(file)?;
        rows.retain(|row| row.path == *file);
        if rows.is_empty() {
            return Err(format!("file {file:?} is absent from both inputs"));
        }
        if rows.len() == 1 && rows[0].old.is_some() && rows[0].new.is_some() {
            let row = rows.pop().ok_or("missing selected path")?;
            let old = Input {
                bytes: row.old.ok_or("missing old bytes")?,
                origin: row.old_origin,
            };
            let new = Input {
                bytes: row.new.ok_or("missing new bytes")?,
                origin: row.new_origin,
            };
            return render_pair(parsed, old, new);
        }
    }
    let mut files = Vec::new();
    let (mut added, mut deleted, mut modified, mut unchanged) = (0, 0, 0, 0);
    let mut text = Vec::new();
    for row in rows {
        let status = match (&row.old, &row.new) {
            (None, Some(_)) => {
                added += 1;
                "added"
            }
            (Some(_), None) => {
                deleted += 1;
                "deleted"
            }
            (Some(a), Some(b)) if a != b => {
                modified += 1;
                "modified"
            }
            (Some(_), Some(_)) => {
                unchanged += 1;
                "unchanged"
            }
            (None, None) => continue,
        };
        let mut entry = json!({"path":row.path,"status":status,"old":if row.old.is_some(){row.old_origin.clone()}else{Value::Null},"new":if row.new.is_some(){row.new_origin.clone()}else{Value::Null},"diff":null,"content":null,"audit":null});
        let details = match (row.old, row.new) {
            (Some(a), Some(b)) => {
                let old = Input {
                    bytes: a,
                    origin: row.old_origin,
                };
                let new = Input {
                    bytes: b,
                    origin: row.new_origin,
                };
                let mut json_args = labels(parsed, DiffFormat::Json);
                json_args.short = false;
                let report = render_pair(
                    &json_args,
                    Input {
                        bytes: old.bytes.clone(),
                        origin: old.origin.clone(),
                    },
                    Input {
                        bytes: new.bytes.clone(),
                        origin: new.origin.clone(),
                    },
                )?;
                entry["diff"] = serde_json::from_str(&report)
                    .map_err(|e| format!("decode file diff report: {e}"))?;
                if parsed.format == DiffFormat::Text || parsed.short {
                    render_pair(&labels(parsed, DiffFormat::Text), old, new)?
                } else {
                    String::new()
                }
            }
            (Some(bytes), None) => {
                entry["content"] = witness("old", &bytes);
                entry["audit"] = audit_side(&bytes, parsed.standard);
                format!(
                    "Deleted {} bytes; sha256={}\nOld bytes: {}",
                    bytes.len(),
                    entry["content"]["sha256"],
                    hex(&bytes)
                )
            }
            (None, Some(bytes)) => {
                entry["content"] = witness("new", &bytes);
                entry["audit"] = audit_side(&bytes, parsed.standard);
                format!(
                    "Added {} bytes; sha256={}\nNew bytes: {}",
                    bytes.len(),
                    entry["content"]["sha256"],
                    hex(&bytes)
                )
            }
            _ => unreachable!(),
        };
        text.push(format!("File {:?}: {status}\n{details}", row.path));
        files.push(entry);
    }
    let changed = added + deleted + modified > 0;
    if parsed.format == DiffFormat::Text || parsed.short {
        return Ok(format!("File tree: {} ({added} added, {deleted} deleted, {modified} modified, {unchanged} unchanged)\n{}",if changed{"changed"}else{"identical"},text.join("\n\n")));
    }
    serde_json::to_string_pretty(&json!({"schema_version":2,"kind":"tree_diff","tree_changed":changed,"binary_changed":changed,"inputs":{"old":old_origin,"new":new_origin},"summary":{"added":added,"deleted":deleted,"modified":modified,"unchanged":unchanged},"files":files})).map_err(|e|e.to_string())
}

fn render_pair(parsed: &DiffArgs, old: Input, new: Input) -> Result<String, String> {
    let mut args = labels(parsed, parsed.format);
    // Function-only --short is handled by render_diff. JSON reports underneath
    // a whole-tree report are always complete and have short disabled above.
    args.short = parsed.short;
    let inputs = [old, new];
    match crate::render_diff(&args, &inputs) {
        Ok(report) => Ok(report),
        Err(reason) => {
            let fallback = binary_diff(&inputs[0], &inputs[1], parsed.standard, &reason);
            if parsed.format == DiffFormat::Json && !parsed.short {
                serde_json::to_string_pretty(&fallback).map_err(|e| e.to_string())
            } else {
                Ok(format!(
                    "Binary view: {}\n{}",
                    fallback["function_analysis"]["reason"],
                    serde_json::to_string_pretty(&fallback["audit"]).map_err(|e| e.to_string())?
                ))
            }
        }
    }
}

#[derive(Parser)]
struct ShowFileArgs {
    repo_dir: String,
    revision: String,
    #[arg(long, allow_hyphen_values = true)]
    file: String,
    #[arg(long)]
    output: Option<String>,
}

#[derive(Parser)]
struct CheckoutFileArgs {
    repo_dir: String,
    revision: String,
    output: String,
    #[arg(long, allow_hyphen_values = true)]
    file: String,
}

pub fn export_file(args: &[String]) -> Result<String, String> {
    let parsed = if args[0] == "show" {
        ShowFileArgs::try_parse_from(
            std::iter::once("wasm-git show").chain(args[1..].iter().map(String::as_str)),
        )
    } else {
        CheckoutFileArgs::try_parse_from(
            std::iter::once("wasm-git checkout").chain(args[1..].iter().map(String::as_str)),
        )
        .map(|p| ShowFileArgs {
            repo_dir: p.repo_dir,
            revision: p.revision,
            file: p.file,
            output: Some(p.output),
        })
    };
    let parsed = match parsed {
        Ok(p) => p,
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => return Ok(e.to_string()),
        Err(e) => return Err(e.to_string()),
    };
    let revision =
        repository::read_file_revisions(Path::new(&parsed.repo_dir), &[&parsed.revision])?
            .into_iter()
            .next()
            .ok_or("missing selected revision")?;
    let input = select_input(&parsed.revision, revision, Some(&parsed.file))?;
    if let Some(destination) = parsed.output {
        crate::output::write_export_file(Path::new(&destination), &input.bytes)?;
        return Ok(format!(
            "wrote {} file {:?} to {destination}",
            input.origin["commit"], parsed.file
        ));
    }
    let mut report = crate::inspect_input(&input, Standard::AllKnown)?;
    report["content"] = witness("selected", &input.bytes);
    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())
}
