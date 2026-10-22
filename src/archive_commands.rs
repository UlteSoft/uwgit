//! Deterministic exports of raw committed files to an exclusive POSIX ustar.
use crate::query_commands::QueryOutput;
use crate::repository::{self, Repository, RepositoryResult};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const USAGE: &str = "usage: wasm-git archive DIR REV --output|-o NEW_TAR [--format tar] [--prefix PREFIX[/]] [--legacy-path NAME] [-- PATH...]\n       wasm-git archive --list|-l\nExports only raw committed files, including unknown Wasm bytes, from one verified snapshot. REV accepts commit expressions or a complete tree ID. Output must be a new file outside repository metadata; stdout is an audit JSON report. Only POSIX ustar is supported, independent of the output suffix. Prefixes are portable relative directories; a missing trailing slash is added. Paths select an exact file, directory descendants, or '.'; every selector must match. A trailing slash only selects descendants. Legacy single-module commits require an explicit portable --legacy-path even when a stored binding exists; this export name may differ from that binding. Tar metadata is an export policy: regular files, mode 0644, uid/gid/mtime 0 and empty owner names. Names use UTF-8 bytes; names that cannot fit ustar's 100-byte name and 155-byte prefix fields are rejected, without truncation or extensions. No worktree attributes, directories, links, compression, extra manifest, or remote execution are included.";
const BLOCK: usize = 512;

struct Options {
    directory: String,
    revision: String,
    output: String,
    prefix: String,
    legacy_path: Option<String>,
    selectors: Vec<String>,
}

enum Mode {
    Help,
    List,
    Export(Options),
}

fn takes_value(option: &str) -> bool {
    matches!(
        option,
        "--output" | "-o" | "--format" | "--prefix" | "--legacy-path"
    )
}

fn help_requested(args: &[String]) -> bool {
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        if takes_value(arg) {
            let _ = args.next();
        } else if matches!(arg.as_str(), "--help" | "-h") {
            return true;
        }
    }
    false
}

fn once(seen: &mut BTreeSet<String>, key: &str) -> RepositoryResult<()> {
    if !seen.insert(key.to_owned()) {
        return Err(format!("duplicate archive option: {key}"));
    }
    Ok(())
}

fn validate_selector(value: &str) -> RepositoryResult<()> {
    wasm_git::pathspec::Pathspec::new(&[value.into()])?;
    Ok(())
}

fn parse(args: &[String]) -> RepositoryResult<Mode> {
    if args.first().map(String::as_str) != Some("archive") {
        return Err(USAGE.into());
    }
    if help_requested(args) {
        return Ok(Mode::Help);
    }
    let mut seen = BTreeSet::new();
    let mut positional = Vec::new();
    let mut selectors = Vec::new();
    let (mut output, mut prefix, mut legacy_path) = (None, String::new(), None);
    let (mut list, mut separated) = (false, false);
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        if separated {
            validate_selector(arg)?;
            selectors.push(arg.clone());
            continue;
        }
        if arg == "--" {
            separated = true;
            continue;
        }
        if matches!(arg.as_str(), "--list" | "-l") {
            once(&mut seen, "--list")?;
            list = true;
            continue;
        }
        if arg.starts_with('-') {
            let (key, inline) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(key, value)| (key, Some(value)));
            if !takes_value(key) || (key == "-o" && inline.is_some()) {
                return Err(format!("unsupported archive option: {arg}"));
            }
            let canonical_key = if key == "-o" { "--output" } else { key };
            once(&mut seen, canonical_key)?;
            let value = inline
                .or_else(|| args.next().map(String::as_str))
                .ok_or_else(|| format!("archive option requires a value: {key}"))?;
            match canonical_key {
                "--output" => {
                    let last = value
                        .rsplit(std::path::is_separator)
                        .next()
                        .unwrap_or_default();
                    if value.is_empty()
                        || value == "-"
                        || value.chars().any(char::is_control)
                        || matches!(last, "" | "." | "..")
                    {
                        return Err(
                            "archive output must name a new file; binary stdout is unsupported"
                                .into(),
                        );
                    }
                    output = Some(value.to_owned());
                }
                "--format" => {
                    if value != "tar" {
                        return Err(format!(
                            "unsupported archive format {value:?}; only tar is available"
                        ));
                    }
                }
                "--prefix" => {
                    let base = value.strip_suffix('/').unwrap_or(value);
                    repository::validate_tree_path(base)?;
                    prefix = format!("{base}/");
                }
                "--legacy-path" => {
                    repository::validate_tree_path(value)?;
                    legacy_path = Some(value.to_owned());
                }
                _ => unreachable!(),
            }
        } else {
            positional.push(arg.clone());
        }
    }
    if list {
        if seen.len() != 1 || !positional.is_empty() || separated {
            return Err("--list must be used alone".into());
        }
        return Ok(Mode::List);
    }
    if positional.len() != 2
        || (separated && selectors.is_empty())
        || positional.iter().any(String::is_empty)
    {
        return Err(USAGE.into());
    }
    let output = output.ok_or_else(|| "archive requires --output NEW_TAR".to_owned())?;
    Ok(Mode::Export(Options {
        directory: positional.remove(0),
        revision: positional.remove(0),
        output,
        prefix,
        legacy_path,
        selectors,
    }))
}

/// Choose a slash boundary without splitting any UTF-8 code point. Full-width
/// fields are allowed by ustar; no byte is dropped to make room for a NUL.
fn name_fields(path: &str) -> RepositoryResult<(&[u8], &[u8])> {
    let bytes = path.as_bytes();
    if bytes.len() <= 100 {
        return Ok((bytes, &[]));
    }
    for (offset, _) in path.match_indices('/').rev() {
        if offset <= 155 && bytes.len() - offset - 1 <= 100 {
            return Ok((&bytes[offset + 1..], &bytes[..offset]));
        }
    }
    Err(format!(
        "archive path cannot be represented by POSIX ustar name[100]/prefix[155]: {path:?}"
    ))
}

fn octal(field: &mut [u8], value: u64) -> RepositoryResult<()> {
    let digits = format!("{value:o}");
    if digits.len() >= field.len() {
        return Err("archive numeric value exceeds POSIX ustar octal field".into());
    }
    field.fill(b'0');
    let end = field.len() - 1;
    field[end - digits.len()..end].copy_from_slice(digits.as_bytes());
    field[end] = 0;
    Ok(())
}

fn header(path: &str, size: usize) -> RepositoryResult<[u8; BLOCK]> {
    let (name, prefix) = name_fields(path)?;
    let mut header = [0; BLOCK];
    header[..name.len()].copy_from_slice(name);
    header[345..345 + prefix.len()].copy_from_slice(prefix);
    octal(&mut header[100..108], 0o644)?;
    octal(&mut header[108..116], 0)?;
    octal(&mut header[116..124], 0)?;
    octal(
        &mut header[124..136],
        u64::try_from(size).map_err(|_| "archive file size exceeds u64")?,
    )?;
    octal(&mut header[136..148], 0)?;
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    octal(&mut header[329..337], 0)?;
    octal(&mut header[337..345], 0)?;
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum = format!("{checksum:06o}\0 ");
    if checksum.len() != 8 {
        return Err("archive header checksum exceeds POSIX ustar field".into());
    }
    header[148..156].copy_from_slice(checksum.as_bytes());
    Ok(header)
}

fn archive_bytes(files: &BTreeMap<String, Vec<u8>>, prefix: &str) -> RepositoryResult<Vec<u8>> {
    let mut headers = Vec::new();
    headers
        .try_reserve_exact(files.len())
        .map_err(|error| format!("cannot allocate archive headers: {error}"))?;
    let mut total = BLOCK * 2;
    for (path, bytes) in files {
        let path = format!("{prefix}{path}");
        let header = header(&path, bytes.len())?;
        let padded = bytes
            .len()
            .checked_add(BLOCK - 1)
            .map(|n| n / BLOCK * BLOCK)
            .ok_or("archive length exceeds addressable memory")?;
        total = total
            .checked_add(BLOCK)
            .and_then(|n| n.checked_add(padded))
            .ok_or("archive length exceeds addressable memory")?;
        headers.push(header);
    }
    let mut archive = Vec::new();
    archive
        .try_reserve_exact(total)
        .map_err(|error| format!("cannot allocate complete archive: {error}"))?;
    for ((_, bytes), header) in files.iter().zip(headers) {
        archive.extend_from_slice(&header);
        archive.extend_from_slice(bytes);
        let padding = (BLOCK - bytes.len() % BLOCK) % BLOCK;
        archive.resize(archive.len() + padding, 0);
    }
    archive.resize(total, 0);
    Ok(archive)
}

pub fn archive_query(args: &[String]) -> RepositoryResult<QueryOutput> {
    let options = match parse(args)? {
        Mode::Help => return Ok(QueryOutput::new(format!("{USAGE}\n"), 0)),
        Mode::List => return Ok(QueryOutput::new("tar\n".into(), 0)),
        Mode::Export(options) => options,
    };
    let mut source = Repository::open(&options.directory)?.archive_files(&options.revision)?;
    let is_legacy = source.legacy.is_some();
    let mut files = match source.legacy.take() {
        Some(bytes) => {
            let path = options
                .legacy_path
                .as_ref()
                .ok_or("legacy single-module commits require explicit --legacy-path NAME")?;
            BTreeMap::from([(path.clone(), bytes)])
        }
        None => {
            if options.legacy_path.is_some() {
                return Err("--legacy-path only applies to legacy single-module commits".into());
            }
            std::mem::take(&mut source.files)
        }
    };
    let selected =
        wasm_git::pathspec::select(&files.keys().cloned().collect(), &options.selectors)?;
    files.retain(|path, _| selected.contains(path));
    let archive = archive_bytes(&files, &options.prefix)?;
    let file_report: Vec<_> = files
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path":path, "archive_path":format!("{}{path}", options.prefix),
                "raw_sha256":format!("{:x}", Sha256::digest(bytes)), "byte_len":bytes.len()
            })
        })
        .collect();
    let report = QueryOutput::json(json!({
        "schema_version":1, "command":"archive", "format":"tar", "tar_format":"ustar",
        "revision":options.revision, "object_id":source.object_id, "kind":source.kind,
        "commit":source.commit, "tree":source.tree, "stored_legacy_path":source.legacy_path,
        "legacy_path":options.legacy_path, "legacy_name_explicit":is_legacy,
        "prefix":options.prefix, "output":options.output, "file_count":file_report.len(), "files":file_report,
        "archive_sha256":format!("{:x}", Sha256::digest(&archive)), "archive_byte_len":archive.len(),
        "metadata_policy":{"source":"export_policy", "stored_metadata":false,
            "entry_type":"regular_file", "mode_octal":"0644", "uid":0, "gid":0,
            "mtime":0, "uname":"", "gname":"", "path_encoding":"UTF-8 bytes",
            "encoding_boundary":"ustar byte fields; UTF-8 names require a UTF-8-aware consumer"}
    }))?;
    crate::output::write_export_file(Path::new(&options.output), &archive)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ustar_name_fields_preserve_full_width_and_utf8_slash_boundaries() {
        let exact = "a".repeat(100);
        assert_eq!(name_fields(&exact).unwrap(), (exact.as_bytes(), &[][..]));
        assert!(name_fields(&"a".repeat(101)).is_err());
        let prefix = "p".repeat(155);
        let name = "n".repeat(100);
        let path = format!("{prefix}/{name}");
        assert_eq!(
            name_fields(&path).unwrap(),
            (name.as_bytes(), prefix.as_bytes())
        );
        assert!(name_fields(&format!("p{path}")).is_err());
        let prefix = "中".repeat(51);
        let name = "文".repeat(33);
        let path = format!("{prefix}/{name}");
        assert_eq!(
            name_fields(&path).unwrap(),
            (name.as_bytes(), prefix.as_bytes())
        );
    }

    #[test]
    fn ustar_numeric_limits_checksum_and_fixed_metadata_are_exact() {
        let mut size = [0; 12];
        octal(&mut size, 0o77777777777).unwrap();
        assert_eq!(&size, b"77777777777\0");
        assert!(octal(&mut size, 0o100000000000).is_err());
        let mut header = header("中文.wasm", 513).unwrap();
        assert_eq!(&header[100..108], b"0000644\0");
        assert_eq!(&header[124..136], b"00000001001\0");
        assert_eq!(&header[257..265], b"ustar\0\x30\x30");
        let stored =
            u64::from_str_radix(std::str::from_utf8(&header[148..154]).unwrap(), 8).unwrap();
        assert_eq!(&header[154..156], b"\0 ");
        header[148..156].fill(b' ');
        assert_eq!(
            stored,
            header.iter().map(|byte| u64::from(*byte)).sum::<u64>()
        );
        assert!(header[265..329].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn ustar_empty_and_block_boundaries_have_exact_padding_and_two_end_blocks() {
        assert_eq!(archive_bytes(&BTreeMap::new(), "").unwrap(), vec![0; 1024]);
        let files = BTreeMap::from([
            ("a.wasm".into(), vec![1; 512]),
            ("b.wasm".into(), vec![2; 513]),
        ]);
        let archive = archive_bytes(&files, "").unwrap();
        assert_eq!(archive.len(), 512 + 512 + 512 + 1024 + 1024);
        assert_eq!(&archive[512..1024], &[1; 512]);
        assert_eq!(&archive[1536..2049], &[2; 513]);
        assert!(archive[2049..].iter().all(|byte| *byte == 0));
    }
}
