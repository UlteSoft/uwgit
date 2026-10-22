//! Worktree cleanup with complete preflight and explicit publication reporting.
use super::*;
use ignore::{gitignore::GitignoreBuilder, WalkBuilder};
use sha2::{Digest, Sha256};

pub(super) fn visible_paths(root: &Path, respect_ignore: bool) -> Result<BTreeSet<String>, String> {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(false)
        .ignore(false)
        .git_global(false)
        .git_exclude(false)
        .git_ignore(respect_ignore)
        .require_git(false)
        .follow_links(false);
    if respect_ignore {
        builder.add_custom_ignore_filename(".uwgitignore");
    }
    builder.filter_entry(|entry| {
        if entry.depth() == 0 {
            return true;
        }
        let name = entry.file_name().to_string_lossy();
        if name.eq_ignore_ascii_case(".uwgit") || name.eq_ignore_ascii_case(".git") {
            return false;
        }
        if entry.file_type().is_some_and(|kind| kind.is_dir()) {
            return !entry.path().join(".uwgit").exists() && !entry.path().join(".git").exists();
        }
        true
    });
    let mut result = BTreeSet::new();
    for entry in builder.build() {
        let entry = entry.map_err(|error| error.to_string())?;
        if let Some(error) = entry.error() {
            return Err(format!("cannot apply ignore rules: {error}"));
        }
        if entry.depth() == 0
            || !entry
                .file_type()
                .is_some_and(|kind| kind.is_file() || kind.is_dir())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| "cleanup path escaped repository")?
            .to_str()
            .ok_or("cleanup requires UTF-8 paths")?
            .to_owned();
        validate_tree_path(&relative)?;
        result.insert(relative);
    }
    Ok(result)
}

fn fingerprint(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("cleanup candidate is no longer a regular file".into());
    }
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn clean(
    root: &str,
    dry_run: bool,
    directories: bool,
    all: bool,
    only_ignored: bool,
    excludes: &[String],
    selectors: &[String],
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    require_no_pending(&state.repo)?;
    let index = state.index()?.unwrap_or_else(Index::empty);
    let controlled = controlled_paths(&index);
    state.repo.fsck()?;
    let pathspec = wasm_git::pathspec::Pathspec::new(selectors)?;
    let every = visible_paths(&state.repo.root, false)?;
    let visible = if all {
        BTreeSet::new()
    } else {
        visible_paths(&state.repo.root, true)?
    };
    let mut ignore = GitignoreBuilder::new(&state.repo.root);
    for pattern in excludes {
        ignore
            .add_line(None, pattern)
            .map_err(|error| error.to_string())?;
    }
    let ignore = ignore.build().map_err(|error| error.to_string())?;
    let selected = pathspec.select(&every)?;
    let mut candidates = BTreeMap::new();
    let mut candidate_dirs = Vec::new();
    for path in &every {
        let full = state.worktree_path(path)?;
        let metadata = fs::symlink_metadata(&full).map_err(|error| error.to_string())?;
        let is_dir = metadata.is_dir();
        if !selected.contains(path)
            || controlled.contains(path)
            || (is_dir
                && controlled
                    .iter()
                    .any(|tracked| tracked.starts_with(&format!("{path}/"))))
        {
            continue;
        }
        let ignored = !visible.contains(path);
        if (!all && ignored != only_ignored)
            || ignore
                .matched_path_or_any_parents(&full, is_dir)
                .is_ignore()
        {
            continue;
        }
        if selectors.is_empty() && !directories {
            if is_dir {
                continue;
            }
            let mut permitted = true;
            for (position, _) in path.match_indices('/') {
                let parent = &path[..position];
                if !controlled
                    .iter()
                    .any(|tracked| tracked.starts_with(&format!("{parent}/")))
                {
                    permitted = false;
                    break;
                }
            }
            if !permitted {
                continue;
            }
        }
        if is_dir {
            candidate_dirs.push(path.clone());
        } else {
            candidates.insert(path.clone(), fingerprint(&full)?);
        }
    }
    candidate_dirs.sort_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
    let mut removable_dirs = BTreeSet::new();
    for path in &candidate_dirs {
        let full = state.worktree_path(path)?;
        let mut removable = true;
        for child in fs::read_dir(&full).map_err(|error| error.to_string())? {
            let child = child.map_err(|error| error.to_string())?;
            let relative = child
                .path()
                .strip_prefix(&state.repo.root)
                .map_err(|_| "cleanup directory escaped repository")?
                .to_str()
                .ok_or("cleanup requires UTF-8 paths")?
                .to_owned();
            if !candidates.contains_key(&relative) && !removable_dirs.contains(&relative) {
                removable = false;
                break;
            }
        }
        if removable {
            removable_dirs.insert(path.clone());
        }
    }
    let mut removed = Vec::new();
    if !dry_run {
        // Recheck the entire plan before the first deletion, then each file
        // immediately before unlink. Failures name the completed publication.
        for (path, expected) in &candidates {
            if fingerprint(&state.worktree_path(path)?)? != *expected {
                return Err("cleanup candidates changed during preflight".into());
            }
        }
        for (path, expected) in &candidates {
            let full = state.worktree_path(path)?;
            let result = (|| {
                if fingerprint(&full)? != *expected {
                    return Err("cleanup candidate changed before removal".into());
                }
                fs::remove_file(&full).map_err(|error| error.to_string())
            })();
            if let Err(error) = result {
                return Err(format!(
                    "cleanup stopped after removing {removed:?}: {error}"
                ));
            }
            removed.push(path.clone());
        }
        for path in &candidate_dirs {
            if removable_dirs.contains(path) {
                fs::remove_dir(state.worktree_path(path)?).map_err(|error| format!("cleanup removed {removed:?}, but could not remove directory {path:?}: {error}"))?;
                removed.push(format!("{path}/"));
            }
        }
    }
    json_text(
        &json!({"dry_run":dry_run,"files":candidates.keys().collect::<Vec<_>>(),"directories":removable_dirs,"removed":removed,"tracked_paths_preserved":true,"nested_repositories_preserved":true,"symbolic_links_preserved":true}),
    )
}

pub fn mergetool(
    root: &str,
    output: &str,
    program: Option<&str>,
    stage: bool,
    selectors: &[String],
    deletions: &[String],
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let original_index = regular(&state.metadata.join("index"))?;
    let mut index = state.index()?;
    if stage && (program.is_none() || index.is_none()) {
        return Err("--stage requires --tool and an existing complete index".into());
    }
    let mut inputs = state.repo.merge_tool_inputs()?;
    for selector in selectors {
        if selector != "." {
            validate_tree_path(selector.trim_end_matches('/'))?;
        }
        if !inputs.files.keys().any(|path| {
            selector == "."
                || path == selector.trim_end_matches('/')
                || path.starts_with(&format!("{}/", selector.trim_end_matches('/')))
        }) {
            return Err(format!(
                "mergetool selector has no conflicting path: {selector:?}"
            ));
        }
    }
    if !selectors.is_empty() {
        inputs.files.retain(|path, _| {
            selectors.iter().any(|selector| {
                selector == "."
                    || path == selector.trim_end_matches('/')
                    || path.starts_with(&format!("{}/", selector.trim_end_matches('/')))
            })
        });
    }
    let deletes: BTreeSet<_> = deletions.iter().collect();
    if deletes.len() != deletions.len()
        || deletes.iter().any(|path| !inputs.files.contains_key(*path))
    {
        return Err("every --delete path must name a unique selected conflicting file".into());
    }
    if inputs.files.is_empty() {
        return Err("pending operation has no selected file conflicts".into());
    }
    let directory = crate::output::create_export_directory(Path::new(output))?;
    let mut entries = Vec::new();
    let mut resolutions = BTreeMap::new();
    for (position, (path, sides)) in inputs.files.iter().enumerate() {
        let selected = directory.join(format!("module-{position:04}"));
        fs::create_dir(&selected).map_err(|error| error.to_string())?;
        let mut manifest = json!({"path":path});
        let mut files = BTreeMap::new();
        for (name, bytes) in ["BASE", "LOCAL", "REMOTE"].into_iter().zip(sides) {
            if let Some(bytes) = bytes {
                let file = selected.join(format!("{}.wasm", name.to_lowercase()));
                crate::output::write_export_file(&file, bytes)?;
                manifest[name.to_lowercase()] = json!({"file":file,"sha256":format!("{:x}",Sha256::digest(bytes)),"byte_len":bytes.len()});
                files.insert(name, file);
            } else {
                manifest[name.to_lowercase()] = Value::Null;
            }
        }
        let merged = selected.join("merged.wasm");
        manifest["merged"] = json!(merged);
        if let Some(program) = program {
            let mut command = std::process::Command::new(program);
            command.env("MERGED", &merged).env("UWGIT_PATH", path);
            for name in ["BASE", "LOCAL", "REMOTE"] {
                if let Some(file) = files.get(name) {
                    command.env(name, file);
                } else {
                    command.env_remove(name);
                }
            }
            command.stdout(std::process::Stdio::from(
                File::create(selected.join("tool.stdout")).map_err(|error| error.to_string())?,
            ));
            command.stderr(std::process::Stdio::from(
                File::create(selected.join("tool.stderr")).map_err(|error| error.to_string())?,
            ));
            let status = command.status().map_err(|error| {
                format!(
                    "cannot run merge tool; exported inputs retained at {}: {error}",
                    directory.display()
                )
            })?;
            if !status.success() {
                return Err(format!("merge tool failed with {status}; exported inputs retained at {}; tool result not staged",directory.display()));
            }
            for (name, original) in ["BASE", "LOCAL", "REMOTE"].into_iter().zip(sides) {
                if let Some(original) = original {
                    if regular(&files[name])?.as_deref() != Some(original.as_slice()) {
                        return Err(
                            "merge tool changed an exported input; tool result not staged".into(),
                        );
                    }
                }
            }
            if deletes.contains(path) {
                if merged.symlink_metadata().is_ok() {
                    return Err(
                        "--delete conflicts with an existing merged output; tool result not staged"
                            .into(),
                    );
                }
                resolutions.insert(path.clone(), None);
                manifest["resolution"] = json!("delete");
            } else {
                let bytes = regular(&merged)?.ok_or(
                    "merge tool succeeded without creating MERGED; tool result not staged",
                )?;
                validate_wasm(&bytes)?;
                let audited = wasm_git::audit::inspect(&bytes)?;
                manifest["resolution"] = json!({"sha256":format!("{:x}",Sha256::digest(&bytes)),"byte_len":bytes.len(),"validation":audited.validation});
                resolutions.insert(path.clone(), Some(bytes));
            }
        }
        entries.push(manifest);
    }
    if stage {
        let index = index.as_mut().ok_or("missing resolution index")?;
        for (path, bytes) in resolutions {
            index.conflicts.remove(&path);
            if let Some(bytes) = bytes {
                index.files.insert(path, bytes);
            } else {
                index.files.remove(&path);
            }
        }
        validate_index(index)?;
        state.repo.with_merge_tool_lease(&inputs.pending, || {
            if regular(&state.metadata.join("index"))? != original_index {
                return Err(
                    "index changed while merge tool ran; resolution index not published".into(),
                );
            }
            state.save_index(index)
        })?;
    }
    let report = json!({"schema_version":1,"pending_id":inputs.pending.id,"operation":inputs.pending.operation,"base":inputs.base,"ours":inputs.ours,"theirs":inputs.theirs,"output":directory,"files":entries,"index_updated":stage,"worktree_updated":false,"pending_continued":false,"complete_tree_review_still_required":true});
    crate::output::write_export_file(
        &directory.join("manifest.json"),
        json_text(&report)?.as_bytes(),
    )
    .map_err(|error| {
        if stage {
            format!("resolution index was published, but output manifest writing failed: {error}")
        } else {
            error
        }
    })?;
    json_text(&report)
}

pub fn squash_merge(root: &str, target: &str, message: Option<&str>) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    require_no_pending(&state.repo)?;
    let tracked = clean_index(&state)?;
    let before = regular(&state.metadata.join("index"))?;
    let index = state.starting_index(None)?;
    let planned = state
        .repo
        .squash_plan(target, index.legacy_path.as_deref())?;
    if let Some(files) = &planned.files {
        let replacement = Index {
            format: 2,
            files: files.clone(),
            legacy_path: planned.legacy_path.clone(),
            conflicts: BTreeMap::new(),
        };
        validate_index(&replacement)?;
        let owned = tracked
            .as_ref()
            .map(|index| keys(&index.files))
            .unwrap_or_default();
        let changes = plan(&state, &owned, &files_worktree(files))?;
        state.repo.with_head_lease(&planned.branch,&planned.head,||{
            if regular(&state.metadata.join("index"))?!=before{return Err("index changed during squash preflight".into());}
            apply_plan(&state,&changes).map_err(|error|format!("squash work files may have been partly updated; HEAD preserved: {error}"))?;
            if regular(&state.metadata.join("index"))?!=before{return Err("squash work files were updated, but index changed concurrently; index not overwritten".into());}
            state.save_index(&replacement).map_err(|error|format!("squash work files were updated; index publication is uncertain: {error}"))
        })?;
    }
    json_text(
        &json!({"schema_version":1,"status":planned.status,"branch":planned.branch,"old_head":planned.head,"target":planned.target,"base":planned.base,"commit":null,"head_updated":false,"index_updated":planned.files.is_some(),"worktree_updated":planned.files.is_some(),"suggested_message":message,"file_reports":planned.reports,"next":"review the complete index, then commit with an explicit message"}),
    )
}
