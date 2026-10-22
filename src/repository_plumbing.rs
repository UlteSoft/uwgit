//! Object and reference plumbing for uwgit's native object format.
use super::*;

#[derive(Clone, Copy)]
pub enum MergeBaseMode {
    Pair,
    Octopus,
    Independent,
    IsAncestor,
    ForkPoint,
}

impl Repository {
    pub fn symbolic_head(&self, new: Option<&str>, message: &str) -> RepositoryResult<String> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if let Some(branch) = new {
            if message.is_empty() {
                return Err("symbolic-ref message must not be empty".into());
            }
            validate_ref_name(branch)?;
            self.assert_branch_available(branch)?;
            if branch != snapshot.manifest.head {
                self.register_selected_branch(branch)?;
                self.atomic_write(
                    &self.metadata.join("HEAD"),
                    format!("{branch}\n").as_bytes(),
                )?;
                self.record_reflog(
                    "HEAD",
                    snapshot.manifest.refs.get(&snapshot.manifest.head).cloned(),
                    snapshot.manifest.refs.get(branch).cloned(),
                    message,
                )?;
            }
            Ok(branch.into())
        } else {
            Ok(snapshot.manifest.head)
        }
    }

    pub fn resolve_object(&self, revision: &str) -> RepositoryResult<(String, String, Vec<u8>)> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let id = if let Some((reference, path)) = revision.split_once(':') {
            validate_tree_path(path)?;
            let commit = snapshot_revision(&snapshot, reference)?;
            let Some(Object::Commit(commit)) = snapshot.objects.get(&commit) else {
                return Err("object path revision is not a commit".into());
            };
            let Some(tree) = &commit.tree else {
                return Err("legacy commit has no named tree".into());
            };
            let Some(Object::Tree(tree)) = snapshot.objects.get(tree) else {
                return Err("missing object path tree".into());
            };
            tree.entries
                .get(path)
                .ok_or("object path is absent from revision")?
                .clone()
        } else if let Some(reference) = revision.strip_suffix("^{tree}") {
            let commit = snapshot_revision(&snapshot, reference)?;
            let Some(Object::Commit(commit)) = snapshot.objects.get(&commit) else {
                return Err("expected commit".into());
            };
            commit
                .tree
                .clone()
                .ok_or("legacy commit has no tree object")?
        } else if valid_id(revision) && snapshot.objects.contains_key(revision) {
            revision.into()
        } else if revision == "HEAD"
            || snapshot.manifest.refs.contains_key(revision)
            || snapshot.manifest.tags.contains_key(revision)
            || snapshot.tracking.contains_key(revision)
            || revision.contains('~')
            || revision.contains('^')
            || revision.starts_with("refs/")
        {
            snapshot_revision(&snapshot, revision)?
        } else {
            if !(4..64).contains(&revision.len())
                || !revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("unknown object revision".into());
            }
            let ids: Vec<_> = snapshot
                .objects
                .keys()
                .filter(|id| id.starts_with(revision))
                .collect();
            match ids.as_slice() {
                [id] => (*id).clone(),
                [] => return Err("unknown object prefix".into()),
                _ => return Err("ambiguous object prefix".into()),
            }
        };
        let object = query_object(&snapshot, &id)?;
        let bytes = snapshot.encoded.get(&id).ok_or("missing encoded object")?;
        Ok((id, object.kind, bytes[OBJECT_HEADER_LENGTH..].to_vec()))
    }
    /// Explicit pruning retains every recovery root. Deleting commits from
    /// children toward parents keeps every interrupted prefix verifiable.
    pub fn garbage_collect(&self, extra_roots: &[String], prune: bool) -> RepositoryResult<Value> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let mut roots: BTreeSet<String> = snapshot
            .manifest
            .refs
            .values()
            .chain(snapshot.manifest.tags.values())
            .chain(snapshot.tracking.values())
            .chain(
                snapshot
                    .reflog
                    .iter()
                    .flat_map(|entry| entry.old.iter().chain(&entry.new)),
            )
            .chain(extra_roots.iter())
            .cloned()
            .collect();
        roots.extend(super::notes_storage::retention_roots(&snapshot)?);
        // Fetched remote-only tags are validated by snapshot(), but are not
        // exposed as tracking branches. They still protect recovery objects.
        let remotes = self.common_metadata.join("remotes");
        if remotes.exists() {
            for entry in fs::read_dir(&remotes).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                if entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tracking.json")
                {
                    let value: Value = serde_json::from_slice(&read_regular(&entry.path())?)
                        .map_err(|error| error.to_string())?;
                    if let Some(tags) = value["state"]["tags"].as_object() {
                        for id in tags.values() {
                            roots.insert(id.as_str().ok_or("invalid remote tag root")?.into());
                        }
                    }
                }
            }
        }
        let mut pinned = Vec::new();
        for name in [
            "pending.json",
            "bisect.json",
            "notes.json",
            "worktrees.json",
        ] {
            if name == "worktrees.json"
                && !super::linked_worktrees::has_entries(&self.common_metadata)?
            {
                continue;
            }
            let directory = if name == "worktrees.json" {
                &self.common_metadata
            } else {
                &self.metadata
            };
            match fs::symlink_metadata(directory.join(name)) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    pinned.push(name)
                }
                Ok(_) => return Err(format!("invalid recovery metadata: {name}")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        let reachable = if pinned.is_empty() {
            reachable_from_roots(roots.iter().cloned(), &snapshot.objects)?
        } else {
            snapshot.objects.keys().cloned().collect()
        };
        let candidates: BTreeSet<_> = snapshot
            .objects
            .keys()
            .filter(|id| !reachable.contains(*id))
            .cloned()
            .collect();
        let mut order: Vec<_> = validated_commit_order(&snapshot.objects)?
            .into_iter()
            .rev()
            .filter(|id| candidates.contains(id))
            .collect();
        for kind in [TREE_KIND, WASM_KIND] {
            order.extend(
                candidates
                    .iter()
                    .filter(|id| snapshot.encoded[*id][8] == kind)
                    .cloned(),
            );
        }
        let mut removed = Vec::new();
        if prune {
            for id in &order {
                let path = self.common_metadata.join("objects").join(id);
                if read_regular(&path)? != snapshot.encoded[id] {
                    return Err("GC object changed after preflight".into());
                }
            }
            for id in &order {
                let path = self.common_metadata.join("objects").join(id);
                fs::remove_file(&path)
                    .map_err(|error| format!("GC stopped after removing {removed:?}: {error}"))?;
                removed.push(id.clone());
            }
            sync_directory(&self.common_metadata.join("objects"))?;
        }
        Ok(
            json!({"schema_version":1,"dry_run":!prune,"objects_before":snapshot.objects.len(),"retained":reachable.len(),"candidates":candidates,"deletion_order":order,"removed":removed,"conservative_recovery_metadata":pinned,"root_policy":"branches+tags+fetched_branches+fetched_tags+reflog+stash_bases+notes_targets; active_auxiliary_metadata_pins_all_objects","packing":false}),
        )
    }
    /// Hash canonical native payloads. Writing also validates the entire graph
    /// before installing any object; a dry hash never mutates the store.
    pub fn hash_payload(&self, kind: &str, bytes: &[u8], write: bool) -> RepositoryResult<String> {
        let kind = match kind {
            "blob" | "wasm" => WASM_KIND,
            "tree" => TREE_KIND,
            "commit" => COMMIT_KIND,
            _ => return Err("object type must be wasm, blob, tree, or commit".into()),
        };
        let encoded = encode_object(kind, bytes)?;
        let id = object_id(&encoded);
        let object = decode_object(&id, &encoded)?;
        let _lock = self.lock()?;
        let mut snapshot = self.snapshot()?;
        snapshot.objects.insert(id.clone(), object);
        validate_object_graph(&snapshot.objects)?;
        if write {
            self.store_object(kind, bytes)?;
        }
        Ok(id)
    }

    pub fn create_tree_object(
        &self,
        entries: BTreeMap<String, String>,
    ) -> RepositoryResult<String> {
        let tree = Tree { format: 1, entries };
        let payload = serde_json::to_vec(&tree).map_err(|error| error.to_string())?;
        self.hash_payload("tree", &payload, true)
    }

    pub fn create_files_tree(&self, files: &BTreeMap<String, Vec<u8>>) -> RepositoryResult<String> {
        validate_tree_paths(files.keys().map(String::as_str))?;
        for bytes in files.values() {
            validate_wasm_header(bytes)?;
        }
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let mut staged = BTreeMap::new();
        let mut entries = BTreeMap::new();
        for (path, bytes) in files {
            entries.insert(
                path.clone(),
                stage_tree_object(WASM_KIND, bytes, &snapshot.encoded, &mut staged)?,
            );
        }
        let payload =
            serde_json::to_vec(&Tree { format: 1, entries }).map_err(|error| error.to_string())?;
        let tree = stage_tree_object(TREE_KIND, &payload, &snapshot.encoded, &mut staged)?;
        self.install_tree_objects(&staged, &[])?;
        Ok(tree)
    }

    /// Construct an immutable commit without moving any reference or index.
    pub fn create_commit_object(
        &self,
        tree: &str,
        parents: &[String],
        message: &str,
    ) -> RepositoryResult<String> {
        require_id(tree)?;
        let _lock = self.lock()?;
        let mut snapshot = self.snapshot()?;
        if !matches!(snapshot.objects.get(tree), Some(Object::Tree(_))) {
            return Err("commit-tree requires an existing tree object ID".into());
        }
        let mut resolved = Vec::new();
        for parent in parents {
            let id = snapshot_revision(&snapshot, parent)?;
            if resolved.contains(&id) {
                return Err("duplicate commit-tree parent".into());
            }
            resolved.push(id);
        }
        let commit = Commit {
            format: 2,
            wasm: String::new(),
            parents: resolved,
            message: message.into(),
            tree: Some(tree.into()),
            legacy_path: None,
        };
        let payload = encode_commit(&commit)?;
        let encoded = encode_object(COMMIT_KIND, &payload)?;
        let id = object_id(&encoded);
        snapshot.objects.insert(id.clone(), Object::Commit(commit));
        validate_object_graph(&snapshot.objects)?;
        self.store_object(COMMIT_KIND, &payload)?;
        Ok(id)
    }

    /// CAS applies to both creation (zero old ID) and deletion. Worktree callers
    /// hold the index lock first; checked-out committed branches are protected.
    pub fn update_reference(
        &self,
        reference: &str,
        new: Option<&str>,
        expected: Option<&str>,
        message: &str,
    ) -> RepositoryResult<Value> {
        let (namespace, name) = if let Some(name) = reference.strip_prefix("refs/heads/") {
            ("refs", name)
        } else if let Some(name) = reference.strip_prefix("refs/tags/") {
            ("tags", name)
        } else {
            return Err("update-ref requires refs/heads/NAME or refs/tags/NAME".into());
        };
        validate_ref_name(name)?;
        if message.is_empty() {
            return Err("reference update message must not be empty".into());
        }
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let refs = if namespace == "refs" {
            &snapshot.manifest.refs
        } else {
            &snapshot.manifest.tags
        };
        let old = refs.get(name).map(String::as_str);
        if let Some(expected) = expected {
            require_id(expected)?;
            let expected = if expected.bytes().all(|byte| byte == b'0') {
                None
            } else {
                Some(expected)
            };
            if old != expected {
                return Err("reference old-value lease does not match".into());
            }
        }
        if let Some(new) = new {
            require_id(new)?;
            if !matches!(snapshot.objects.get(new), Some(Object::Commit(_))) {
                return Err("reference target must be an existing commit object".into());
            }
        }
        if namespace == "refs" && name == snapshot.manifest.head && old != new {
            return Err("update-ref refuses the checked-out branch; use commit or reset".into());
        }
        match (old, new) {
            (Some(old), None) => self.remove_named_ref(namespace, name, old, message)?,
            (_, Some(new)) => self.write_named_ref(namespace, name, new, message)?,
            (None, None) => {}
        }
        Ok(json!({"reference":reference,"old":old,"new":new,"updated":old != new}))
    }

    /// A single verified snapshot supplies the whole walk and every exclusion.
    pub fn revision_list(
        &self,
        includes: &[String],
        excludes: &[String],
        all: bool,
        first_parent: bool,
    ) -> RepositoryResult<Vec<CommitInfo>> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let mut expanded = Vec::new();
        let mut excludes = excludes.to_vec();
        for revision in includes {
            if let Some((left, right)) = revision.split_once("...") {
                if right.contains("..") || left.contains("..") {
                    return Err("invalid symmetric revision range".into());
                }
                let left =
                    snapshot_revision(&snapshot, if left.is_empty() { "HEAD" } else { left })?;
                let right =
                    snapshot_revision(&snapshot, if right.is_empty() { "HEAD" } else { right })?;
                excludes.extend(best_merge_bases(&left, &right, &snapshot.objects)?);
                expanded.extend([left, right]);
            } else {
                expanded.push(revision.clone());
            }
        }
        walk_snapshot(&snapshot, &expanded, &excludes, all, first_parent)
    }

    /// All graph calculations and reflog identities come from one verified
    /// snapshot. No synthetic merge commits or guessed fork points are stored.
    pub fn merge_base_query(
        &self,
        revisions: &[String],
        mode: MergeBaseMode,
    ) -> RepositoryResult<Vec<String>> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if matches!(mode, MergeBaseMode::ForkPoint) {
            let [reference, derived] = revisions else {
                return Err("fork-point requires REF and an explicit/default HEAD revision".into());
            };
            let (reference, tip) = fork_reference(&snapshot, reference)?;
            let derived = snapshot_revision(&snapshot, derived)?;
            let mut tips: BTreeSet<_> = snapshot
                .reflog
                .iter()
                .filter(|entry| entry.reference == reference)
                .flat_map(|entry| entry.old.iter().chain(&entry.new))
                .cloned()
                .collect();
            tips.insert(tip);
            let mut witnessed = BTreeSet::new();
            for tip in &tips {
                witnessed.extend(ancestors(tip, &snapshot.objects)?);
            }
            let common = ancestors(&derived, &snapshot.objects)?
                .intersection(&witnessed)
                .cloned()
                .collect();
            let bases = best_in_common(&common, &snapshot.objects)?;
            return Ok(match bases.as_slice() {
                [base] if tips.contains(base) => bases,
                _ => Vec::new(),
            });
        }
        let ids: Vec<_> = revisions
            .iter()
            .map(|revision| snapshot_revision(&snapshot, revision))
            .collect::<RepositoryResult<_>>()?;
        if matches!(mode, MergeBaseMode::IsAncestor) {
            let [left, right] = ids.as_slice() else {
                return Err("--is-ancestor requires exactly two revisions".into());
            };
            return Ok(if ancestors(right, &snapshot.objects)?.contains(left) {
                vec![left.clone()]
            } else {
                Vec::new()
            });
        }
        let closures: Vec<_> = ids
            .iter()
            .map(|id| ancestors(id, &snapshot.objects))
            .collect::<RepositoryResult<_>>()?;
        if matches!(mode, MergeBaseMode::Independent) {
            let unique: BTreeSet<_> = ids.iter().cloned().collect();
            return Ok(unique
                .into_iter()
                .filter(|id| {
                    !ids.iter()
                        .zip(&closures)
                        .any(|(other, closure)| other != id && closure.contains(id))
                })
                .collect());
        }
        let Some(first) = closures.first() else {
            return Err("merge-base requires revisions".into());
        };
        let mut common = first.clone();
        if matches!(mode, MergeBaseMode::Octopus) {
            for closure in &closures[1..] {
                common.retain(|id| closure.contains(id));
            }
        } else {
            if ids.len() < 2 {
                return Err("merge-base requires at least two revisions".into());
            }
            let other: BTreeSet<_> = closures[1..].iter().flatten().cloned().collect();
            common.retain(|id| other.contains(id));
        }
        best_in_common(&common, &snapshot.objects)
    }
}

fn fork_reference(snapshot: &Snapshot, reference: &str) -> RepositoryResult<(String, String)> {
    let reference = if reference == "HEAD" {
        format!("refs/heads/{}", snapshot.manifest.head)
    } else {
        reference.into()
    };
    let mut candidates = Vec::new();
    for (prefix, refs) in [
        ("refs/heads/", &snapshot.manifest.refs),
        ("refs/tags/", &snapshot.manifest.tags),
        ("refs/remotes/", &snapshot.tracking),
    ] {
        if let Some(name) = reference.strip_prefix(prefix) {
            if let Some(id) = refs.get(name) {
                candidates.push((reference.clone(), id.clone()));
            }
        } else if !reference.starts_with("refs/") {
            if let Some(id) = refs.get(&reference) {
                candidates.push((format!("{prefix}{reference}"), id.clone()));
            }
        }
    }
    match candidates.as_slice() {
        [candidate] => Ok(candidate.clone()),
        [] => Err("fork-point requires an existing branch, tag, or tracking reference".into()),
        _ => Err("ambiguous fork-point reference; use its full namespace".into()),
    }
}

fn best_in_common(
    common: &BTreeSet<String>,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<Vec<String>> {
    let mut dominated = BTreeSet::new();
    for id in common {
        let Some(Object::Commit(commit)) = objects.get(id) else {
            return Err("common ancestor is not a stored commit".into());
        };
        dominated.extend(commit.parents.iter().cloned());
    }
    Ok(common.difference(&dominated).cloned().collect())
}

pub(super) fn walk_snapshot(
    snapshot: &Snapshot,
    includes: &[String],
    excludes: &[String],
    all: bool,
    first_parent: bool,
) -> RepositoryResult<Vec<CommitInfo>> {
    let mut tips: Vec<String> = includes
        .iter()
        .map(|revision| snapshot_revision(snapshot, revision))
        .collect::<RepositoryResult<_>>()?;
    if all {
        tips.extend(snapshot.manifest.refs.values().cloned());
        tips.extend(snapshot.manifest.tags.values().cloned());
        tips.extend(snapshot.tracking.values().cloned());
    }
    if tips.is_empty() && !all && includes.is_empty() {
        tips.push(snapshot_revision(snapshot, "HEAD")?);
    }
    let mut omitted = BTreeSet::new();
    for revision in excludes {
        let tip = snapshot_revision(snapshot, revision)?;
        collect_commits(snapshot, tip, false, &mut omitted)?;
    }
    let mut selected = BTreeSet::new();
    for tip in tips {
        collect_commits(snapshot, tip, first_parent, &mut selected)?;
    }
    selected.retain(|id| !omitted.contains(id));
    let mut children: BTreeMap<String, usize> = selected.iter().map(|id| (id.clone(), 0)).collect();
    for id in &selected {
        let Some(Object::Commit(commit)) = snapshot.objects.get(id) else {
            return Err("walk contains a non-commit".into());
        };
        for parent in commit
            .parents
            .iter()
            .take(if first_parent { 1 } else { usize::MAX })
        {
            if let Some(count) = children.get_mut(parent) {
                *count += 1;
            }
        }
    }
    let mut ready: BTreeSet<_> = children
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut result = Vec::new();
    while let Some(id) = ready.pop_first() {
        let Some(Object::Commit(commit)) = snapshot.objects.get(&id) else {
            return Err("walk contains a non-commit".into());
        };
        result.push(CommitInfo {
            id: id.clone(),
            commit: commit.clone(),
        });
        for parent in commit
            .parents
            .iter()
            .take(if first_parent { 1 } else { usize::MAX })
        {
            if let Some(count) = children.get_mut(parent) {
                *count -= 1;
                if *count == 0 {
                    ready.insert(parent.clone());
                }
            }
        }
    }
    if result.len() != selected.len() {
        return Err("invalid cyclic revision walk".into());
    }
    Ok(result)
}

fn collect_commits(
    snapshot: &Snapshot,
    tip: String,
    first_parent: bool,
    selected: &mut BTreeSet<String>,
) -> RepositoryResult<()> {
    let mut pending = vec![tip];
    while let Some(id) = pending.pop() {
        if !selected.insert(id.clone()) {
            continue;
        }
        let Some(Object::Commit(commit)) = snapshot.objects.get(&id) else {
            return Err("walk target is not a commit".into());
        };
        pending.extend(
            commit
                .parents
                .iter()
                .take(if first_parent { 1 } else { usize::MAX })
                .cloned(),
        );
    }
    Ok(())
}
