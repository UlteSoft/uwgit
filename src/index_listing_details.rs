//! Read-only directory views and byte-level line-ending observations. Neither
//! operation changes Wasm images or applies text conversion attributes.
use super::*;

fn entries(state: &State) -> Result<(BTreeMap<String, bool>, BTreeSet<String>), String> {
    let mut result = BTreeMap::new();
    let mut opaque = BTreeSet::new();
    let mut pending = vec![String::new()];
    while let Some(parent) = pending.pop() {
        let directory = state.repo.root.join(&parent);
        let metadata = fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("ls-files directory changed during its scan".into());
        }
        for entry in fs::read_dir(&directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "ls-files requires UTF-8 worktree paths")?;
            if name.eq_ignore_ascii_case(".git") || name.eq_ignore_ascii_case(".uwgit") {
                continue;
            }
            let path = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };
            validate_tree_path(&path)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            let mut boundary =
                metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir());
            if metadata.is_dir() && !boundary {
                for marker in [".git", ".uwgit"] {
                    match fs::symlink_metadata(entry.path().join(marker)) {
                        Ok(_) => boundary = true,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
            }
            if boundary {
                // A collapsed ancestor must never hide an unexamined nested
                // repository, symlink or special file behind an "other" row.
                for (offset, _) in path.match_indices('/') {
                    opaque.insert(path[..offset].to_owned());
                }
                continue;
            }
            result.insert(path.clone(), metadata.is_dir());
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok((result, opaque))
}

pub(super) fn worktree_rows<'a>(
    state: &State,
    options: &Args,
    rules: &mut Rules,
    controlled: &BTreeSet<String>,
    pathspec: &wasm_git::pathspec::Pathspec,
) -> Result<Vec<Row<'a>>, String> {
    let (entries, opaque) = entries(state)?;
    let mut ignored = BTreeMap::new();
    let mut selected_files = BTreeSet::new();
    for (path, directory) in &entries {
        if *directory || controlled.contains(path) {
            continue;
        }
        let selected = pathspec.matches(path);
        let needed_for_fold = options.others
            && options.directory
            && path
                .match_indices('/')
                .any(|(offset, _)| pathspec.matches(&format!("{}/", &path[..offset])));
        if !selected && !needed_for_fold {
            continue;
        }
        let excluded = rules.excluded(state, path)?;
        ignored.insert(path.clone(), excluded);
        if excluded == options.ignored && selected {
            selected_files.insert(path.clone());
        }
    }
    let mut collapsed = BTreeSet::new();
    let mut rows = Vec::new();
    if options.others && options.directory {
        for (path, directory) in &entries {
            if !directory
                || controlled.contains(path)
                || has_descendant(controlled, path)
                || opaque.contains(path)
                || path
                    .match_indices('/')
                    .any(|(offset, _)| collapsed.contains(&path[..offset]))
                || !pathspec.matches(&format!("{path}/"))
            {
                continue;
            }
            let nonempty = has_descendant(&selected_files, path);
            if options.no_empty_directory && !nonempty {
                continue;
            }
            let excluded = rules.excluded_kind(state, path, true)?;
            let all_ignored = nonempty
                && !ignored
                    .iter()
                    .any(|(file, excluded)| !excluded && file.starts_with(&format!("{path}/")));
            if if options.ignored {
                !(excluded || all_ignored)
            } else {
                excluded
            } {
                continue;
            }
            collapsed.insert(path.clone());
            rows.push(Row {
                path: format!("{path}/"),
                stage: None,
                bytes: None,
                reason: '?',
                undo: false,
                directory: true,
                historical: false,
            });
        }
    }
    for path in selected_files {
        let folded = path
            .match_indices('/')
            .any(|(offset, _)| collapsed.contains(&path[..offset]));
        if options.others && !folded {
            rows.push(Row {
                path: path.clone(),
                stage: None,
                bytes: None,
                reason: '?',
                undo: false,
                directory: false,
                historical: false,
            });
        }
        if options.killed
            && (has_descendant(controlled, &path)
                || path
                    .match_indices('/')
                    .any(|(offset, _)| controlled.contains(&path[..offset])))
        {
            rows.push(Row {
                path,
                stage: None,
                bytes: None,
                reason: 'K',
                undo: false,
                directory: false,
                historical: false,
            });
        }
    }
    Ok(rows)
}

fn line_endings(mut input: impl Read) -> Result<&'static str, String> {
    let (mut printable, mut control) = (0u64, 0u64);
    let (mut lf, mut crlf, mut cr) = (false, false, false);
    let mut last = None;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        for &byte in &buffer[..count] {
            last = Some(byte);
            if cr {
                if byte != b'\n' {
                    return Ok("-text");
                }
                crlf = true;
                cr = false;
                continue;
            }
            match byte {
                0 => return Ok("-text"),
                b'\r' => cr = true,
                b'\n' => lf = true,
                8 | 9 | 12 | 27 => printable += 1,
                1..=31 | 127 => control += 1,
                _ => printable += 1,
            }
        }
    }
    // A trailing DOS EOF byte is not evidence of binary content.
    if last == Some(26) {
        control -= 1;
    }
    Ok(if cr || control > printable / 128 {
        "-text"
    } else if lf && crlf {
        "mixed"
    } else if crlf {
        "crlf"
    } else if lf {
        "lf"
    } else {
        "none"
    })
}

pub(super) fn index_eol(bytes: Option<&Vec<u8>>) -> Result<&'static str, String> {
    bytes
        .map(|bytes| line_endings(bytes.as_slice()))
        .transpose()
        .map(|value| value.unwrap_or(""))
}

pub(super) fn worktree_eol(state: &State, path: &str) -> Result<&'static str, String> {
    validate_tree_path(path)?;
    let components: Vec<_> = path.split('/').collect();
    let mut full = state.repo.root.clone();
    for (position, component) in components.iter().enumerate() {
        full.push(component);
        let metadata = match fs::symlink_metadata(&full) {
            Ok(value) => value,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok("")
            }
            Err(e) => return Err(e.to_string()),
        };
        if metadata.file_type().is_symlink() {
            return Ok("");
        }
        if position + 1 < components.len() {
            if !metadata.is_dir() {
                return Ok("");
            }
        } else if metadata.is_file() {
            return line_endings(File::open(&full).map_err(|e| e.to_string())?);
        }
    }
    Ok("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_eol_classification_keeps_crlf_pairs_at_chunk_boundaries_and_byte_evidence() {
        for (bytes, expected) in [
            (vec![], "none"),
            (b"plain".to_vec(), "none"),
            (b"one\ntwo\n".to_vec(), "lf"),
            (b"one\r\ntwo\r\n".to_vec(), "crlf"),
            (b"one\r\ntwo\n".to_vec(), "mixed"),
            (b"one\rtwo".to_vec(), "-text"),
            (b"one\r".to_vec(), "-text"),
            (WASM.to_vec(), "-text"),
            (b"text\x1a".to_vec(), "none"),
            (b"\x01\n".to_vec(), "-text"),
            ([vec![b'x'; 65535], b"\r\n".to_vec()].concat(), "crlf"),
            (
                [vec![b'x'; 65535], b"\r\ntail\n".to_vec()].concat(),
                "mixed",
            ),
        ] {
            assert_eq!(line_endings(bytes.as_slice()).unwrap(), expected);
            assert_eq!(
                line_endings(std::io::Read::chain(
                    std::io::Cursor::new(&bytes[..bytes.len() / 2]),
                    std::io::Cursor::new(&bytes[bytes.len() / 2..])
                ))
                .unwrap(),
                expected
            );
        }
    }
}
