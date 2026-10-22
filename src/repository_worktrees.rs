//! Shared native objects and references, with one HEAD/index per worktree.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Worktrees {
    version: u32,
    entries: BTreeMap<String, WorktreeRecord>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorktreeRecord {
    path: String,
    branch: String,
    locked: Option<String>,
}

fn registry(common: &Path) -> RepositoryResult<Worktrees> {
    let path = common.join("worktrees.json");
    let bytes = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Worktrees {
                version: 1,
                entries: BTreeMap::new(),
            })
        }
        Err(error) => return Err(error.to_string()),
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 4 * 1024 * 1024 =>
        {
            read_regular(&path)?
        }
        Ok(_) => return Err("worktree registry must be a regular file of at most 4 MiB".into()),
    };
    let value: Worktrees = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if value.version != 1 || serde_json::to_vec(&value).map_err(|error| error.to_string())? != bytes
    {
        return Err("invalid, duplicate-key, or non-canonical worktree registry".into());
    }
    let mut paths = BTreeSet::new();
    for (id, record) in &value.entries {
        require_id(id)?;
        validate_head_identity(&record.branch)?;
        if record
            .locked
            .as_ref()
            .is_some_and(|reason| reason.chars().any(char::is_control))
        {
            return Err("worktree lock reason must be one line without control characters".into());
        }
        if !Path::new(&record.path).is_absolute()
            || record.path.chars().any(char::is_control)
            || !paths.insert(&record.path)
        {
            return Err("invalid or duplicate worktree registry path".into());
        }
    }
    Ok(value)
}

pub(super) fn has_entries(common: &Path) -> RepositoryResult<bool> {
    Ok(!registry(common)?.entries.is_empty())
}
fn canonical(path: &Path) -> RepositoryResult<PathBuf> {
    fs::canonicalize(path).map_err(|error| format!("cannot resolve {}: {error}", path.display()))
}
fn marker(path: &Path) -> RepositoryResult<String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
        return Err("worktree marker must be a bounded regular file".into());
    }
    let bytes = read_regular(path)?;
    if bytes.len() > 8192 {
        return Err("worktree path marker is too large".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "worktree marker is not UTF-8")?;
    let value = text
        .strip_suffix('\n')
        .ok_or("worktree marker requires one final newline")?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("invalid worktree marker".into());
    }
    Ok(value.into())
}
fn destination(path: &Path) -> RepositoryResult<PathBuf> {
    let name = path
        .file_name()
        .ok_or("worktree destination requires a new directory name")?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = canonical(parent)?;
    if parent.components().any(|part| {
        part.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(".uwgit")
    }) || name.to_string_lossy().eq_ignore_ascii_case(".uwgit")
    {
        return Err("worktree destination must be outside repository metadata".into());
    }
    let result = parent.join(name);
    if result
        .to_str()
        .is_none_or(|path| path.chars().any(char::is_control))
    {
        return Err("worktree destination requires a UTF-8 path without control characters".into());
    }
    match fs::symlink_metadata(&result) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(result),
        Err(error) => Err(error.to_string()),
        Ok(_) => Err("worktree destination already exists".into()),
    }
}

pub(super) fn open_common(root: &Path, metadata: &Path) -> RepositoryResult<PathBuf> {
    let path = metadata.join("commondir");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if metadata.join("worktree-id").symlink_metadata().is_ok() {
                return Err("incomplete linked worktree metadata".into());
            }
            Ok(metadata.to_path_buf())
        }
        Err(error) => Err(error.to_string()),
        Ok(_) => {
            let common = PathBuf::from(marker(&path)?);
            if !common.is_absolute() || canonical(&common)? != common {
                return Err(
                    "worktree common directory must be a canonical absolute directory".into(),
                );
            }
            require_directory(&common)?;
            let id = marker(&metadata.join("worktree-id"))?;
            require_id(&id)?;
            let records = registry(&common)?;
            let record = records
                .entries
                .get(&id)
                .ok_or("linked worktree is not registered; use worktree repair")?;
            if canonical(root)? != Path::new(&record.path)
                || parse_ref_file(&read_regular(&metadata.join("HEAD"))?, false)? != record.branch
            {
                return Err("linked worktree registration differs from its path or HEAD; use worktree repair".into());
            }
            Ok(common)
        }
    }
}

impl Repository {
    pub fn common_metadata(&self) -> &Path {
        &self.common_metadata
    }

    fn write_worktrees(&self, records: &Worktrees) -> RepositoryResult<()> {
        let bytes = serde_json::to_vec(records).map_err(|error| error.to_string())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("worktree registry exceeds 4 MiB".into());
        }
        self.atomic_write(&self.common_metadata.join("worktrees.json"), &bytes)
            .map_err(|error| format!("worktree registry publication may have occurred: {error}; inspect worktree list before retrying"))
    }

    pub fn assert_branch_available(&self, branch: &str) -> RepositoryResult<()> {
        match self.branch_unavailable_reason(branch)? {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    // Reservation is a semantic refusal; malformed metadata and filesystem
    // failures remain errors, including in partial reference-update mode.
    pub(super) fn branch_unavailable_reason(
        &self,
        branch: &str,
    ) -> RepositoryResult<Option<String>> {
        if valid_id(branch) {
            return Ok(None);
        }
        let records = registry(&self.common_metadata)?;
        if records.entries.is_empty() && self.common_metadata == self.metadata {
            return Ok(None);
        }
        let here = canonical(&self.root)?;
        let primary = canonical(&self.common_metadata)?
            .parent()
            .ok_or("common metadata has no primary worktree")?
            .to_path_buf();
        if here != primary
            && parse_ref_file(&read_regular(&self.common_metadata.join("HEAD"))?, false)? == branch
        {
            return Ok(Some(format!(
                "branch {branch} is checked out in primary worktree {}",
                primary.display()
            )));
        }
        for record in records.entries.values() {
            if Path::new(&record.path) != here && record.branch == branch {
                return Ok(Some(format!(
                    "branch {branch} is reserved by worktree {}",
                    record.path
                )));
            }
        }
        Ok(None)
    }

    pub(super) fn register_selected_branch(&self, branch: &str) -> RepositoryResult<()> {
        if self.common_metadata == self.metadata {
            return Ok(());
        }
        let id = marker(&self.metadata.join("worktree-id"))?;
        let mut records = registry(&self.common_metadata)?;
        records
            .entries
            .get_mut(&id)
            .ok_or("linked worktree registration disappeared")?
            .branch = branch.into();
        self.write_worktrees(&records)
    }

    pub fn linked_worktrees(&self) -> RepositoryResult<Value> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let records = registry(&self.common_metadata)?;
        let primary = canonical(&self.common_metadata)?
            .parent()
            .ok_or("missing primary worktree")?
            .to_path_buf();
        let branch = parse_ref_file(&read_regular(&self.common_metadata.join("HEAD"))?, false)?;
        let mut rows = vec![
            json!({"path":primary,"branch":if valid_id(&branch) { None } else { Some(&branch) },"head":head_tip(&branch,&snapshot.manifest.refs),"detached":valid_id(&branch),"primary":true,"locked":null,"missing":false}),
        ];
        for (id, record) in records.entries {
            let missing = match fs::symlink_metadata(&record.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(error) => return Err(error.to_string()),
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => false,
                Ok(_) => {
                    return Err("registered worktree path is no longer a real directory".into())
                }
            };
            rows.push(json!({"id":id,"path":record.path,"branch":if valid_id(&record.branch) { None } else { Some(&record.branch) },"head":head_tip(&record.branch,&snapshot.manifest.refs),"detached":valid_id(&record.branch),"primary":false,"locked":record.locked,"missing":missing}));
        }
        Ok(json!({"schema_version":1,"shared_objects_and_refs":true,"worktrees":rows}))
    }

    pub fn add_linked_worktree(
        &self,
        target: &Path,
        branch: &str,
        revision: Option<&str>,
        legacy_path: Option<&str>,
    ) -> RepositoryResult<Value> {
        validate_head_identity(branch)?;
        let target = destination(target)?;
        let common = canonical(&self.common_metadata)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        self.assert_branch_available(branch)?;
        if !valid_id(branch) && branch == snapshot.manifest.head {
            return Err("a worktree requires a different branch from the calling worktree".into());
        }
        let create = revision.is_some() && !valid_id(branch);
        if create && snapshot.manifest.refs.contains_key(branch) {
            return Err("worktree branch already exists".into());
        }
        let id = snapshot_revision(&snapshot, revision.unwrap_or(branch))?;
        let selected = snapshot_files(&snapshot, &id)?;
        let mut files = selected.files;
        let anchor = legacy_path.map(str::to_owned).or(selected.legacy_path);
        if let Some(bytes) = selected.legacy {
            let path = anchor
                .as_deref()
                .ok_or("legacy worktree materialization requires --legacy-path PATH")?;
            validate_tree_path(path)?;
            files.insert(path.into(), bytes);
        } else if legacy_path.is_some() {
            return Err("--legacy-path applies only to an unnamed legacy commit".into());
        }
        let index = crate::porcelain::encode_worktree_index(&files, anchor.as_deref())?;
        let mut records = registry(&self.common_metadata)?;
        let worktree_id =
            object_id(format!("{}:{}", target.display(), unique_name("worktree")).as_bytes());
        let result = (|| {
            fs::create_dir(&target).map_err(|error| error.to_string())?;
            let metadata = target.join(".uwgit");
            fs::create_dir(&metadata).map_err(|error| error.to_string())?;
            fs::create_dir(metadata.join("tmp")).map_err(|error| error.to_string())?;
            write_new_file(&metadata.join("HEAD"), format!("{branch}\n").as_bytes())?;
            let head_log = vec![ReflogEntry {
                sequence: 1,
                reference: "HEAD".into(),
                old: None,
                new: Some(id.clone()),
                operation: "worktree-add".into(),
            }];
            write_new_file(
                &metadata.join("head-reflog.json"),
                &serde_json::to_vec(&head_log).map_err(|error| error.to_string())?,
            )?;
            write_new_file(
                &metadata.join("commondir"),
                format!(
                    "{}\n",
                    common.to_str().ok_or("common directory is not UTF-8")?
                )
                .as_bytes(),
            )?;
            write_new_file(
                &metadata.join("worktree-id"),
                format!("{worktree_id}\n").as_bytes(),
            )?;
            write_new_file(&metadata.join("index"), &index)?;
            for (path, bytes) in &files {
                let full = target.join(path);
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                }
                write_new_file(&full, bytes)?;
            }
            if create {
                self.write_named_ref("refs", branch, &id, "worktree-add")?;
            }
            records.entries.insert(
                worktree_id.clone(),
                WorktreeRecord {
                    path: target.to_str().ok_or("non-UTF-8 worktree path")?.into(),
                    branch: branch.into(),
                    locked: None,
                },
            );
            self.write_worktrees(&records)?;
            write_new_file(&metadata.join("format"), FORMAT)?;
            sync_directory(&metadata)?;
            sync_directory(&target)?;
            Ok(
                json!({"status":"added","path":target,"branch":branch,"head":id,"shared_objects_and_refs":true,"paths":files.keys().collect::<Vec<_>>()}),
            )
        })();
        result.map_err(|error: String| format!("worktree add may have created files or a branch at {}: {error}; inspect that path and worktree list before retrying", target.display()))
    }

    pub fn set_worktree_lock(
        &self,
        target: &Path,
        reason: Option<&str>,
    ) -> RepositoryResult<Value> {
        if reason.is_some_and(|reason| reason.chars().any(char::is_control)) {
            return Err("worktree lock reason must be one line without control characters".into());
        }
        let target = match fs::canonicalize(target) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let target = if target.is_absolute() {
                    target.to_path_buf()
                } else {
                    std::env::current_dir()
                        .map_err(|error| error.to_string())?
                        .join(target)
                };
                if target.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                }) {
                    return Err("missing worktree path must be normalized".into());
                }
                target
            }
            Err(error) => return Err(error.to_string()),
        };
        let _lock = self.lock()?;
        self.snapshot()?;
        let mut records = registry(&self.common_metadata)?;
        let record = records
            .entries
            .values_mut()
            .find(|record| Path::new(&record.path) == target)
            .ok_or("target is not a registered linked worktree")?;
        if reason.is_some() == record.locked.is_some() {
            return Err("worktree is already in the requested lock state".into());
        }
        record.locked = reason.map(str::to_owned);
        self.write_worktrees(&records)?;
        Ok(json!({"path":target,"locked":reason}))
    }

    pub fn repair_worktree(&self, target: &Path) -> RepositoryResult<Value> {
        let target = canonical(target)?;
        require_directory(&target.join(".uwgit"))?;
        let metadata = target.join(".uwgit");
        if marker(&metadata.join("commondir"))?
            != canonical(&self.common_metadata)?
                .to_str()
                .ok_or("non-UTF-8 common path")?
            || read_regular(&metadata.join("format"))? != FORMAT
        {
            return Err("repair target belongs to a different or incomplete repository".into());
        }
        let id = marker(&metadata.join("worktree-id"))?;
        let _lock = self.lock()?;
        self.snapshot()?;
        let branch = parse_ref_file(&read_regular(&metadata.join("HEAD"))?, false)?;
        let mut records = registry(&self.common_metadata)?;
        let old = records
            .entries
            .get(&id)
            .ok_or("repair target has no registered worktree ID")?
            .clone();
        if Path::new(&old.path) != target && fs::symlink_metadata(&old.path).is_ok() {
            return Err(
                "old worktree path still exists; refusing to reassign its registration".into(),
            );
        }
        let primary_branch =
            parse_ref_file(&read_regular(&self.common_metadata.join("HEAD"))?, false)?;
        if !valid_id(&branch)
            && (primary_branch == branch
                || records
                    .entries
                    .iter()
                    .any(|(other_id, record)| other_id != &id && record.branch == branch))
        {
            return Err(
                "repaired HEAD would reuse a branch checked out in another worktree".into(),
            );
        }
        let record = records.entries.get_mut(&id).ok_or("worktree disappeared")?;
        record.path = target.to_str().ok_or("non-UTF-8 worktree path")?.into();
        record.branch = branch;
        self.write_worktrees(&records)?;
        Ok(json!({"status":"repaired","old_path":old.path,"path":target,"id":id}))
    }

    pub fn move_linked_worktree(&self, target: &Path, new_path: &Path) -> RepositoryResult<Value> {
        let target = canonical(target)?;
        let new_path = destination(new_path)?;
        if target == canonical(&self.root)? || new_path.starts_with(&target) {
            return Err("cannot move the calling worktree or move a worktree inside itself".into());
        }
        let _lock = self.lock()?;
        self.snapshot()?;
        let mut records = registry(&self.common_metadata)?;
        let id = records
            .entries
            .iter()
            .find(|(_, record)| Path::new(&record.path) == target)
            .map(|(id, _)| id.clone())
            .ok_or("target is not a linked worktree")?;
        if records.entries[&id].locked.is_some() {
            return Err("linked worktree is locked".into());
        }
        if open_common(&target, &target.join(".uwgit"))? != canonical(&self.common_metadata)? {
            return Err("worktree common directory changed".into());
        }
        fs::rename(&target, &new_path).map_err(|error| error.to_string())?;
        records
            .entries
            .get_mut(&id)
            .ok_or("worktree disappeared")?
            .path = new_path.to_str().ok_or("non-UTF-8 worktree path")?.into();
        self.write_worktrees(&records).map_err(|error| {
            format!(
                "worktree moved to {}, but registration may need worktree repair: {error}",
                new_path.display()
            )
        })?;
        Ok(json!({"status":"moved","old_path":target,"path":new_path,"id":id}))
    }

    pub fn prune_worktrees(&self, dry_run: bool) -> RepositoryResult<Value> {
        let _lock = self.lock()?;
        self.snapshot()?;
        let mut records = registry(&self.common_metadata)?;
        let mut candidates = Vec::new();
        for (id, record) in &records.entries {
            if record.locked.is_some() {
                continue;
            }
            match fs::symlink_metadata(&record.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    candidates.push(id.clone())
                }
                Err(error) => return Err(error.to_string()),
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => {
                    return Err(
                        "prune refuses a registered path replaced by a file or symlink".into(),
                    )
                }
            }
        }
        let paths: Vec<_> = candidates
            .iter()
            .map(|id| records.entries[id].path.clone())
            .collect();
        if !dry_run {
            for id in &candidates {
                records.entries.remove(id);
            }
            if !candidates.is_empty() {
                self.write_worktrees(&records)?;
            }
        }
        Ok(
            json!({"dry_run":dry_run,"paths":paths,"objects_removed":false,"branches_removed":false}),
        )
    }

    /// The caller holds the target worktree's index lock throughout this call.
    pub fn remove_linked_worktree(&self, target: &Path) -> RepositoryResult<Value> {
        let target = canonical(target)?;
        if target == canonical(&self.root)? {
            return Err("cannot remove the calling worktree".into());
        }
        let _lock = self.lock()?;
        self.snapshot()?;
        let mut records = registry(&self.common_metadata)?;
        let id = records
            .entries
            .iter()
            .find(|(_, record)| Path::new(&record.path) == target)
            .map(|(id, _)| id.clone())
            .ok_or("target is not a linked worktree")?;
        let record = &records.entries[&id];
        if record.locked.is_some() {
            return Err("linked worktree is locked".into());
        }
        if open_common(&target, &target.join(".uwgit"))? != canonical(&self.common_metadata)? {
            return Err("linked worktree common directory changed".into());
        }
        fs::remove_dir_all(&target).map_err(|error| {
            format!("worktree files may have been partly removed; registration retained: {error}")
        })?;
        records.entries.remove(&id);
        self.write_worktrees(&records)?;
        Ok(json!({"status":"removed","path":target,"branch_removed":false,"objects_removed":false}))
    }
}
