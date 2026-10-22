//! Frozen multi-target replay over native Wasm images. HEAD is published only
//! after the complete queue and its index/worktree checkpoint have succeeded.
use super::*;
type Files = BTreeMap<String, Vec<u8>>;
type Worktree = BTreeMap<String, Option<Vec<u8>>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayOptions {
    pub no_commit: bool,
    pub mainline: Option<usize>,
    pub message: Option<String>,
    pub append_source: bool,
    pub empty: String,
    pub allow_empty: bool,
    pub fast_forward: bool,
    pub reverse: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayJournal {
    pub selection_sha256: String,
    pub options: ReplayOptions,
    pub queue: Vec<String>,
    pub cursor: usize,
    pub initial_tree: String,
    pub progress: String,
    pub initial_worktree: Worktree,
    pub owned: BTreeSet<String>,
    pub steps: Vec<ReplayStep>,
    pub stop: String,
    pub checkpoint: Option<ReplayCheckpoint>,
    pub index_changed: bool,
    pub worktree_changed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayStep {
    pub source: String,
    pub before: String,
    pub result: Option<String>,
    pub action: String,
    pub index_sha256: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCheckpoint {
    pub action: String,
    pub index_before: Option<Vec<u8>>,
    pub index_after: Vec<u8>,
    pub work_before: Worktree,
    pub work_after: Worktree,
    pub owned_before: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReplayImages {
    pub files: Files,
    pub conflicts: BTreeMap<String, [Option<Vec<u8>>; 3]>,
}
pub struct ReplayRequest {
    pub operation: String,
    pub branch: String,
    pub head: String,
    pub revisions: Vec<String>,
    pub options: ReplayOptions,
    pub baseline_index: Option<Vec<u8>>,
    pub legacy_path: Option<String>,
    pub worktree: Worktree,
}
fn mapped(snapshot: &Snapshot, id: &str, anchor: Option<&str>) -> RepositoryResult<RevisionFiles> {
    let mut revision = if let Some(Object::Tree(tree)) = snapshot.objects.get(id) {
        let mut files = Files::new();
        for (path, id) in &tree.entries {
            let Some(Object::Wasm(bytes)) = snapshot.objects.get(id) else {
                return Err("replay tree contains a missing original Wasm image".into());
            };
            files.insert(path.clone(), bytes.clone());
        }
        RevisionFiles {
            commit: String::new(),
            legacy: None,
            files,
            legacy_path: anchor.map(str::to_owned),
        }
    } else {
        snapshot_files(snapshot, id)?
    };
    if revision
        .legacy_path
        .as_deref()
        .is_some_and(|path| Some(path) != anchor)
    {
        return Err("replay revisions have conflicting legacy path anchors".into());
    }
    if let Some(bytes) = revision.legacy.take() {
        revision.files.insert(
            anchor
                .ok_or("legacy replay needs an explicit path before starting")?
                .into(),
            bytes,
        );
    }
    revision.legacy_path = anchor.map(str::to_owned);
    Ok(revision)
}
fn empty(anchor: Option<&str>) -> RevisionFiles {
    RevisionFiles {
        commit: String::new(),
        legacy: None,
        files: Files::new(),
        legacy_path: anchor.map(str::to_owned),
    }
}
fn selected_parent(
    snapshot: &Snapshot,
    pending: &PendingOperation,
    source: &str,
) -> RepositoryResult<Option<String>> {
    Ok(pending_identity(
        snapshot,
        &pending.operation,
        &pending.head,
        source,
        pending.mainline,
    )?
    .1)
}
fn message(
    snapshot: &Snapshot,
    pending: &PendingOperation,
    source: &str,
) -> RepositoryResult<String> {
    let options = &pending
        .replay
        .as_ref()
        .ok_or("missing replay state")?
        .options;
    let Some(Object::Commit(original)) = snapshot.objects.get(source) else {
        return Err("replay target is not a commit".into());
    };
    let mut text = options.message.clone().unwrap_or_else(|| {
        if pending.operation == "revert" {
            format!(
                "Revert \"{}\"\n\nThis reverts commit {source}.",
                original.message
            )
        } else {
            original.message.clone()
        }
    });
    if options.append_source {
        text.push_str(&format!("\n\n(cherry picked from commit {source})"));
    }
    Ok(text)
}
fn stops_empty(
    options: &ReplayOptions,
    unchanged: bool,
    originally_empty: bool,
    fast_forward: bool,
) -> bool {
    unchanged
        && !fast_forward
        && ((originally_empty && !options.allow_empty && options.empty != "keep")
            || (!originally_empty && options.empty == "stop"))
}
fn views(
    snapshot: &Snapshot,
    pending: &PendingOperation,
    source: &str,
    progress: &str,
) -> RepositoryResult<[RevisionFiles; 3]> {
    let anchor = pending.legacy_path.as_deref();
    let parent = selected_parent(snapshot, pending, source)?;
    let parent = parent
        .as_deref()
        .map(|id| mapped(snapshot, id, anchor))
        .transpose()?
        .unwrap_or_else(|| empty(anchor));
    let selected = mapped(snapshot, source, anchor)?;
    let ours = mapped(snapshot, progress, anchor)?;
    Ok(if pending.operation == "revert" {
        [selected, ours, parent]
    } else {
        [parent, ours, selected]
    })
}
pub(super) fn revisions(
    snapshot: &Snapshot,
    pending: &PendingOperation,
) -> RepositoryResult<[RevisionFiles; 3]> {
    let replay = pending.replay.as_ref().ok_or("missing replay state")?;
    views(snapshot, pending, &pending.target, &replay.progress)
}
fn prefix_pairs(paths: &BTreeSet<String>) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for path in paths {
        for (offset, _) in path.match_indices('/') {
            let prefix = &path[..offset];
            if paths.contains(prefix) {
                result.insert(prefix.to_owned());
                result.insert(path.clone());
            }
        }
    }
    result
}
fn merge_images(
    revisions: [RevisionFiles; 3],
    anchor: Option<&str>,
) -> RepositoryResult<ReplayImages> {
    let all: BTreeSet<_> = revisions
        .iter()
        .flat_map(|side| side.files.keys().cloned())
        .collect();
    let mut conflicts = BTreeSet::new();
    let mut files = match merge_file_revisions(revisions.clone(), anchor) {
        Ok(merged) => {
            for row in &merged.reports {
                if row.status == "conflict" && !row.path.is_empty() {
                    conflicts.insert(row.path.clone());
                }
            }
            merged.files
        }
        // Unsupported file-internal composition remains a real three-side
        // stop. It must not discard opaque original modules or fake a merge.
        Err(_) => {
            conflicts.extend(all.clone());
            Files::new()
        }
    };
    let present: BTreeSet<_> = files
        .keys()
        .cloned()
        .chain(conflicts.iter().cloned())
        .collect();
    conflicts.extend(prefix_pairs(&present));
    let mut stages = BTreeMap::new();
    for path in conflicts {
        files.remove(&path);
        stages.insert(
            path.clone(),
            std::array::from_fn(|side| revisions[side].files.get(&path).cloned()),
        );
    }
    validate_tree_paths(files.keys().map(String::as_str))?;
    Ok(ReplayImages {
        files,
        conflicts: stages,
    })
}
fn stage_image(
    snapshot: &mut Snapshot,
    encoded: &mut BTreeMap<String, Vec<u8>>,
    files: &Files,
    before: Option<&str>,
    message: &str,
    anchor: Option<&str>,
) -> RepositoryResult<String> {
    let mut staged = BTreeMap::new();
    let id = if let Some(before) = before {
        check_tree_parents(snapshot, &[before.into()], anchor)?;
        prepare_tree_commit(
            files,
            message,
            &[before.into()],
            anchor,
            &snapshot.encoded,
            &mut staged,
        )?
    } else {
        validate_tree_paths(files.keys().map(String::as_str))?;
        let mut entries = BTreeMap::new();
        for (path, bytes) in files {
            validate_wasm_header(bytes)?;
            entries.insert(
                path.clone(),
                stage_tree_object(WASM_KIND, bytes, &snapshot.encoded, &mut staged)?,
            );
        }
        let bytes = serde_json::to_vec(&Tree { format: 1, entries }).map_err(|e| e.to_string())?;
        stage_tree_object(TREE_KIND, &bytes, &snapshot.encoded, &mut staged)?
    };
    for (key, bytes) in staged {
        snapshot
            .objects
            .insert(key.clone(), decode_object(&key, &bytes)?);
        snapshot.encoded.insert(key.clone(), bytes.clone());
        encoded.insert(key, bytes);
    }
    Ok(id)
}
fn bind(snapshot: &Snapshot, pending: &mut PendingOperation) -> RepositoryResult<()> {
    let replay = pending.replay.as_ref().ok_or("missing replay state")?;
    let source = replay
        .queue
        .get(replay.cursor.min(replay.queue.len().saturating_sub(1)))
        .ok_or("empty replay queue")?
        .clone();
    let (base, parent) = pending_identity(
        snapshot,
        &pending.operation,
        &pending.head,
        &source,
        pending.mainline,
    )?;
    let text = message(snapshot, pending, &source)?;
    pending.target = source;
    pending.base = base;
    pending.selected_parent = parent;
    pending.message = text;
    Ok(())
}
fn frozen_queue(
    snapshot: &Snapshot,
    operation: &str,
    revisions: &[String],
    reverse: bool,
) -> RepositoryResult<Vec<String>> {
    if revisions.is_empty() || revisions.len() > 4096 {
        return Err("replay requires 1..4096 revision selectors".into());
    }
    let walk = revisions.iter().any(|value| {
        value.contains("..")
            || value.starts_with('^')
            || value.ends_with("^@")
            || value.ends_with("^!")
            || value.contains("^-")
    });
    let mut queue = if walk {
        let includes: Vec<_> = revisions
            .iter()
            .filter(|value| !value.starts_with('^'))
            .cloned()
            .collect();
        let excludes: Vec<_> = revisions
            .iter()
            .filter_map(|value| value.strip_prefix('^').map(str::to_owned))
            .collect();
        let mut values =
            Repository::revision_list_snapshot(snapshot, &includes, &excludes, false, false)?
                .into_iter()
                .map(|commit| commit.id)
                .collect::<Vec<_>>();
        if operation == "cherry-pick" {
            values.reverse();
        }
        values
    } else {
        revisions
            .iter()
            .map(|value| snapshot_revision(snapshot, value))
            .collect::<RepositoryResult<Vec<_>>>()?
    };
    let mut seen = BTreeSet::new();
    queue.retain(|id| seen.insert(id.clone()));
    if reverse {
        queue.reverse();
    }
    if queue.is_empty() || queue.len() > 4096 {
        return Err("selected replay queue must contain 1..4096 commits".into());
    }
    Ok(queue)
}
impl Repository {
    pub fn begin_replay_pending(
        &self,
        request: ReplayRequest,
        checkpoint: impl FnOnce(&PendingOperation, &ReplayImages) -> RepositoryResult<ReplayCheckpoint>,
    ) -> RepositoryResult<PendingOperation> {
        let _lock = self.lock()?;
        let mut snapshot = self.snapshot()?;
        if self.read_pending()?.is_some() {
            return Err("finish the existing pending operation first".into());
        }
        check_expected_branch(&snapshot.manifest.head, Some(&request.branch))?;
        check_expected(snapshot.manifest.tip(), Some(&request.head))?;
        let queue = frozen_queue(
            &snapshot,
            &request.operation,
            &request.revisions,
            request.options.reverse,
        )?;
        let head = mapped(&snapshot, &request.head, request.legacy_path.as_deref())?;
        let files = crate::porcelain::replay_baseline_files(
            request.baseline_index.as_deref(),
            &head,
            request.legacy_path.as_deref(),
            request.options.no_commit,
        )?;
        let mut encoded = BTreeMap::new();
        let initial_tree = stage_image(
            &mut snapshot,
            &mut encoded,
            &files,
            None,
            "",
            request.legacy_path.as_deref(),
        )?;
        let progress = if request.options.no_commit {
            initial_tree.clone()
        } else {
            request.head.clone()
        };
        let mut pending = PendingOperation {
            version: 2,
            id: format!(
                "{:x}",
                Sha256::digest(unique_name("pending-replay").as_bytes())
            ),
            operation: request.operation,
            branch: request.branch,
            head: request.head,
            target: queue[0].clone(),
            base: None,
            selected_parent: None,
            mainline: request.options.mainline,
            message: String::new(),
            baseline_index: request.baseline_index,
            legacy_path: request.legacy_path,
            prepared: None,
            rebase: None,
            replay: Some(ReplayJournal {
                selection_sha256: String::new(),
                options: request.options,
                queue,
                cursor: 0,
                initial_tree,
                progress,
                owned: request.worktree.keys().cloned().collect(),
                initial_worktree: request.worktree,
                steps: Vec::new(),
                stop: "running".into(),
                checkpoint: None,
                index_changed: false,
                worktree_changed: false,
            }),
        };
        pending.replay.as_mut().unwrap().selection_sha256 = selection_digest(&pending)?;
        bind(&snapshot, &mut pending)?;
        validate_shape(&pending)?;
        // Freeze every selected parent and path identity before installing a
        // clean prefix, even when a later selected commit would fail.
        for source in &pending.replay.as_ref().unwrap().queue {
            let _ = views(
                &snapshot,
                &pending,
                source,
                &pending.replay.as_ref().unwrap().progress,
            )?;
        }
        self.advance_replay(snapshot, pending, "begin", None, encoded, checkpoint)
    }
    pub fn advance_replay_pending(
        &self,
        expected: &PendingOperation,
        action: &str,
        index: Option<PendingIndex<'_>>,
        checkpoint: impl FnOnce(&PendingOperation, &ReplayImages) -> RepositoryResult<ReplayCheckpoint>,
    ) -> RepositoryResult<PendingOperation> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let pending = self.checked_pending(&snapshot, expected)?;
        check_pending_head(&snapshot, &pending)?;
        check_expected(snapshot.manifest.tip(), Some(&pending.head))?;
        let replay = pending.replay.as_ref().ok_or("not a multi-target replay")?;
        if replay.checkpoint.is_some() || replay.stop == "complete" {
            return Err("repair/finalize the prepared replay checkpoint before advancing".into());
        }
        if !matches!(action, "continue" | "skip") {
            return Err("invalid replay action".into());
        }
        self.advance_replay(
            snapshot,
            pending,
            action,
            index,
            BTreeMap::new(),
            checkpoint,
        )
    }
    fn advance_replay(
        &self,
        mut snapshot: Snapshot,
        mut pending: PendingOperation,
        action: &str,
        index: Option<PendingIndex<'_>>,
        mut encoded: BTreeMap<String, Vec<u8>>,
        checkpoint: impl FnOnce(&PendingOperation, &ReplayImages) -> RepositoryResult<ReplayCheckpoint>,
    ) -> RepositoryResult<PendingOperation> {
        if action != "begin" {
            let replay = pending.replay.as_ref().ok_or("not a multi-target replay")?;
            let source = replay.queue[replay.cursor].clone();
            let before = replay.progress.clone();
            let no_commit = replay.options.no_commit;
            let (result, sha) = if action == "continue" {
                let index = index
                    .as_ref()
                    .ok_or("replay continuation requires a complete reviewed index")?;
                crate::porcelain::validate_pending_resolution_index(
                    index.raw,
                    index.files,
                    index.legacy_path,
                )?;
                if index.legacy_path != pending.legacy_path.as_deref() {
                    return Err("replay resolution changed its original path anchor".into());
                }
                let text = message(&snapshot, &pending, &source)?;
                let id = stage_image(
                    &mut snapshot,
                    &mut encoded,
                    index.files,
                    (!no_commit).then_some(before.as_str()),
                    &text,
                    pending.legacy_path.as_deref(),
                )?;
                (Some(id), Some(format!("{:x}", Sha256::digest(index.raw))))
            } else {
                (None, None)
            };
            let replay = pending.replay.as_mut().unwrap();
            if let Some(result) = &result {
                replay.progress = result.clone();
            }
            replay.steps.push(ReplayStep {
                source,
                before,
                result,
                action: if action == "continue" {
                    "manual"
                } else {
                    "skipped"
                }
                .into(),
                index_sha256: sha,
            });
            replay.cursor += 1;
        }
        let images = loop {
            let replay = pending.replay.as_ref().unwrap();
            if replay.cursor == replay.queue.len() {
                let files =
                    mapped(&snapshot, &replay.progress, pending.legacy_path.as_deref())?.files;
                pending.replay.as_mut().unwrap().stop = "complete".into();
                break ReplayImages {
                    files,
                    conflicts: BTreeMap::new(),
                };
            }
            let source = replay.queue[replay.cursor].clone();
            let before = replay.progress.clone();
            let options = replay.options.clone();
            let sides = views(&snapshot, &pending, &source, &before)?;
            let images = merge_images(sides.clone(), pending.legacy_path.as_deref())?;
            if !images.conflicts.is_empty() {
                pending.replay.as_mut().unwrap().stop = "conflict".into();
                break images;
            }
            let unchanged = images.files == sides[1].files;
            let originally_empty = sides[0].files == sides[2].files;
            let fast_forward = options.fast_forward
                && selected_parent(&snapshot, &pending, &source)?.as_deref()
                    == Some(before.as_str())
                && matches!(snapshot.objects.get(&source),Some(Object::Commit(commit)) if commit.format==2 && commit.legacy_path==pending.legacy_path);
            if stops_empty(&options, unchanged, originally_empty, fast_forward) {
                pending.replay.as_mut().unwrap().stop = "empty".into();
                break images;
            }
            let drop_empty = unchanged && options.empty == "drop" && !originally_empty;
            let text = message(&snapshot, &pending, &source)?;
            let (result, kind) = if drop_empty {
                (None, "empty-dropped")
            } else if fast_forward {
                (Some(source.clone()), "fast-forward")
            } else {
                (
                    Some(stage_image(
                        &mut snapshot,
                        &mut encoded,
                        &images.files,
                        (!options.no_commit).then_some(before.as_str()),
                        &text,
                        pending.legacy_path.as_deref(),
                    )?),
                    "automatic",
                )
            };
            let replay = pending.replay.as_mut().unwrap();
            if let Some(result) = &result {
                replay.progress = result.clone();
            }
            replay.steps.push(ReplayStep {
                source,
                before,
                result,
                action: kind.into(),
                index_sha256: None,
            });
            replay.cursor += 1;
        };
        bind(&snapshot, &mut pending)?;
        if pending.replay.as_ref().unwrap().stop == "complete"
            && !pending.replay.as_ref().unwrap().options.no_commit
        {
            pending.prepared = Some(PendingPrepared {
                commit: pending.replay.as_ref().unwrap().progress.clone(),
                index_sha256: format!("{:x}", Sha256::digest(b"native replay checkpoint")),
            });
        }
        let prepared = checkpoint(&pending, &images)?;
        if prepared.action != action {
            return Err("replay checkpoint changed its action identity".into());
        }
        let replay = pending.replay.as_mut().unwrap();
        replay.owned.extend(prepared.work_after.keys().cloned());
        replay.checkpoint = Some(prepared);
        validate_snapshot(&snapshot, &pending)?;
        let bytes = encode_pending(&pending)?;
        let commits: Vec<_> = validated_commit_order(&snapshot.objects)?
            .into_iter()
            .filter(|id| encoded.contains_key(id))
            .collect();
        self.install_tree_objects(&encoded,&commits).map_err(|e|format!("replay objects may be partly installed; original HEAD and previous journal remain: {e}"))?;
        self.publish_pending(&bytes, "save replay checkpoint")?;
        Ok(pending)
    }
    pub fn settle_replay_checkpoint(
        &self,
        expected: &PendingOperation,
        apply: impl FnOnce(&ReplayCheckpoint) -> RepositoryResult<()>,
    ) -> RepositoryResult<PendingOperation> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let mut pending = self.checked_pending(&snapshot, expected)?;
        check_pending_head(&snapshot, &pending)?;
        check_expected(snapshot.manifest.tip(), Some(&pending.head))?;
        let checkpoint = pending
            .replay
            .as_ref()
            .ok_or("not a replay")?
            .checkpoint
            .as_ref()
            .ok_or("no replay checkpoint to settle")?;
        apply(checkpoint).map_err(|e|format!("replay checkpoint retained; index/worktree publication may be partly completed: {e}"))?;
        let index_changed =
            checkpoint.index_before.as_deref() != Some(checkpoint.index_after.as_slice());
        let worktree_changed = checkpoint.work_before != checkpoint.work_after;
        let replay = pending.replay.as_mut().unwrap();
        replay.index_changed |= index_changed;
        replay.worktree_changed |= worktree_changed;
        replay.checkpoint = None;
        self.publish_pending(&encode_pending(&pending)?, "settle replay checkpoint")?;
        Ok(pending)
    }
    pub fn finish_replay_pending(&self, expected: &PendingOperation) -> RepositoryResult<Value> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let pending = self.checked_pending(&snapshot, expected)?;
        check_pending_head(&snapshot, &pending)?;
        let replay = pending.replay.as_ref().ok_or("not a multi-target replay")?;
        if replay.stop != "complete" || replay.checkpoint.is_some() {
            return Err("replay has not finished its index/worktree checkpoint".into());
        }
        let published = !replay.options.no_commit
            && replay.progress != pending.head
            && snapshot.manifest.tip() == Some(&replay.progress);
        if !published {
            check_expected(snapshot.manifest.tip(), Some(&pending.head))?;
        }
        if !replay.options.no_commit && replay.progress != pending.head {
            let operation = format!("pending-continue-{}", pending.id);
            if !published {
                self.write_named_ref("refs",&pending.branch,&replay.progress,&operation).map_err(|e|format!("replay final reference/reflog may be published; keep the journal and retry --continue: {e}"))?;
            }
            self.ensure_pending_reflog(&pending, &replay.progress, &operation)?;
        }
        let mut report = report(&pending);
        report["status"] = json!(if replay.options.no_commit {
            "staged"
        } else if replay.progress == pending.head {
            "unchanged"
        } else {
            "committed"
        });
        report["already_published"] = json!(published);
        report["pending_cleared"] = json!(true);
        report["head_updated"] =
            json!(!replay.options.no_commit && replay.progress != pending.head);
        self.remove_pending_checked(&pending)?;
        Ok(report)
    }
    pub fn replay_progress_images(&self, pending: &PendingOperation) -> RepositoryResult<Files> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let pending = self.checked_pending(&snapshot, pending)?;
        let replay = pending.replay.as_ref().ok_or("not a replay")?;
        Ok(mapped(&snapshot, &replay.progress, pending.legacy_path.as_deref())?.files)
    }
    pub fn replay_status(&self, pending: &PendingOperation) -> RepositoryResult<Value> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let pending = self.checked_pending(&snapshot, pending)?;
        Ok(report(&pending))
    }
}
fn selection_digest(pending: &PendingOperation) -> RepositoryResult<String> {
    let replay = pending.replay.as_ref().ok_or("missing replay state")?;
    let bytes = serde_json::to_vec(&(
        &pending.id,
        &pending.operation,
        &pending.branch,
        &pending.head,
        &pending.baseline_index,
        &pending.legacy_path,
        &replay.options,
        &replay.queue,
        &replay.initial_tree,
        &replay.initial_worktree,
    ))
    .map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub(super) fn validate_shape(pending: &PendingOperation) -> RepositoryResult<()> {
    let replay = pending.replay.as_ref().ok_or("missing replay state")?;
    if !matches!(pending.operation.as_str(), "cherry-pick" | "revert")
        || pending.rebase.is_some()
        || pending.version != 2
    {
        return Err("replay journal has an incompatible operation or version".into());
    }
    if replay.queue.is_empty()
        || replay.queue.len() > 4096
        || replay.cursor > replay.queue.len()
        || replay.steps.len() != replay.cursor
    {
        return Err("invalid replay queue or cursor".into());
    }
    let opts = &replay.options;
    if !matches!(opts.empty.as_str(), "stop" | "drop" | "keep")
        || opts.mainline == Some(0)
        || opts.mainline != pending.mainline
        || (opts.no_commit && (opts.fast_forward || opts.message.is_some() || opts.append_source))
        || (opts.fast_forward
            && (opts.message.is_some() || opts.append_source || pending.operation != "cherry-pick"))
        || (opts.append_source && pending.operation != "cherry-pick")
    {
        return Err("invalid frozen replay options".into());
    }
    if selection_digest(pending)? != replay.selection_sha256 {
        return Err("frozen replay selection digest changed".into());
    }
    for id in replay
        .queue
        .iter()
        .chain([&replay.initial_tree, &replay.progress])
    {
        require_id(id)?;
    }
    if replay.queue.iter().collect::<BTreeSet<_>>().len() != replay.queue.len() {
        return Err("frozen replay queue contains duplicates".into());
    }
    if !matches!(
        replay.stop.as_str(),
        "running" | "conflict" | "empty" | "complete"
    ) {
        return Err("invalid replay stop state".into());
    }
    for path in replay.initial_worktree.keys().chain(replay.owned.iter()) {
        validate_tree_path(path)?;
    }
    for step in &replay.steps {
        require_id(&step.source)?;
        require_id(&step.before)?;
        for id in step.result.iter().chain(step.index_sha256.iter()) {
            require_id(id)?;
        }
        if !matches!(
            step.action.as_str(),
            "automatic" | "manual" | "skipped" | "empty-dropped" | "fast-forward"
        ) || matches!(step.action.as_str(), "skipped" | "empty-dropped") != step.result.is_none()
            || (step.action == "manual") != step.index_sha256.is_some()
        {
            return Err("invalid replay step action or image".into());
        }
    }
    if let Some(cp) = &replay.checkpoint {
        if !matches!(cp.action.as_str(), "begin" | "continue" | "skip") {
            return Err("invalid replay checkpoint action".into());
        }
        for path in cp
            .work_before
            .keys()
            .chain(cp.work_after.keys())
            .chain(cp.owned_before.iter())
        {
            validate_tree_path(path)?;
        }
        if cp.work_before.keys().collect::<Vec<_>>() != cp.work_after.keys().collect::<Vec<_>>() {
            return Err("replay checkpoint observation scope changed".into());
        }
        if !cp.owned_before.is_subset(&replay.owned)
            || cp
                .work_after
                .keys()
                .any(|path| !replay.owned.contains(path))
        {
            return Err("replay checkpoint escaped its recorded ownership".into());
        }
    }
    Ok(())
}
pub(super) fn validate_snapshot(
    snapshot: &Snapshot,
    pending: &PendingOperation,
) -> RepositoryResult<()> {
    validate_shape(pending)?;
    let replay = pending.replay.as_ref().unwrap();
    if replay.stop == "running" {
        return Err("unfinished replay planning is not a durable checkpoint".into());
    }
    let head = mapped(snapshot, &pending.head, pending.legacy_path.as_deref())?;
    let baseline = crate::porcelain::replay_baseline_files(
        pending.baseline_index.as_deref(),
        &head,
        pending.legacy_path.as_deref(),
        replay.options.no_commit,
    )?;
    if !matches!(
        snapshot.objects.get(&replay.initial_tree),
        Some(Object::Tree(_))
    ) || mapped(
        snapshot,
        &replay.initial_tree,
        pending.legacy_path.as_deref(),
    )?
    .files
        != baseline
    {
        return Err("replay initial tree differs from the original index".into());
    }
    crate::porcelain::validate_replay_initial_worktree(
        pending.baseline_index.as_deref(),
        &replay.initial_worktree,
        replay.options.no_commit,
    )?;
    for source in &replay.queue {
        let _ = views(snapshot, pending, source, &pending.head)?;
    }
    let mut progress = if replay.options.no_commit {
        replay.initial_tree.clone()
    } else {
        pending.head.clone()
    };
    let mut allowed: BTreeSet<_> = replay
        .initial_worktree
        .keys()
        .cloned()
        .chain(baseline.keys().cloned())
        .collect();
    for (position, step) in replay.steps.iter().enumerate() {
        if replay.queue.get(position) != Some(&step.source) || step.before != progress {
            return Err("replay step order or input image changed".into());
        }
        let sides = views(snapshot, pending, &step.source, &progress)?;
        let merged = merge_images(sides.clone(), pending.legacy_path.as_deref())?;
        let conflict = !merged.conflicts.is_empty();
        let unchanged = merged.files == sides[1].files;
        let originally_empty = sides[0].files == sides[2].files;
        let can_ff = replay.options.fast_forward
            && selected_parent(snapshot, pending, &step.source)?.as_deref()
                == Some(progress.as_str())
            && matches!(snapshot.objects.get(&step.source),Some(Object::Commit(commit)) if commit.format==2 && commit.legacy_path==pending.legacy_path);
        let stopped = conflict || stops_empty(&replay.options, unchanged, originally_empty, can_ff);
        if matches!(step.action.as_str(), "manual" | "skipped") && !stopped {
            return Err(
                "replay manual/skip step did not stop at a conflict or empty change".into(),
            );
        }
        if step.action == "skipped" {
            allowed.extend(sides.iter().flat_map(|side| side.files.keys().cloned()));
            continue;
        }
        if step.action == "empty-dropped" {
            if conflict || !unchanged || replay.options.empty != "drop" || originally_empty {
                return Err("replay dropped a nonempty or protected empty step".into());
            }
            continue;
        }
        let result = step.result.as_ref().ok_or("replay result is absent")?;
        let files = mapped(snapshot, result, pending.legacy_path.as_deref())?.files;
        match step.action.as_str() {
            "fast-forward" => {
                if !can_ff || result != &step.source || files != merged.files {
                    return Err(
                        "replay fast-forward does not name the exact selected source".into(),
                    );
                }
            }
            "automatic" | "manual" => {
                if replay.options.no_commit {
                    if !matches!(snapshot.objects.get(result), Some(Object::Tree(_))) {
                        return Err("no-commit replay manufactured a commit image".into());
                    }
                } else {
                    let Some(Object::Commit(commit)) = snapshot.objects.get(result) else {
                        return Err("replay result is not a commit".into());
                    };
                    if commit.format != 2
                        || commit.parents != [progress.clone()]
                        || commit.message != message(snapshot, pending, &step.source)?
                        || commit.legacy_path != pending.legacy_path
                    {
                        return Err(
                            "replay result has different parents, message, or path anchor".into(),
                        );
                    }
                }
                if step.action == "automatic"
                    && (stopped
                        || conflict
                        || files != merged.files
                        || (unchanged && replay.options.empty == "drop" && !originally_empty))
                {
                    return Err(
                        "automatic replay differs from the exact native Wasm composition".into(),
                    );
                }
            }
            _ => return Err("invalid replay result action".into()),
        }
        allowed.extend(sides.iter().flat_map(|side| side.files.keys().cloned()));
        allowed.extend(files.keys().cloned());
        progress = result.clone();
    }
    if progress != replay.progress {
        return Err("replay progress differs from its frozen step chain".into());
    }
    let mut identity = pending.clone();
    bind(snapshot, &mut identity)?;
    if pending.target != identity.target
        || pending.base != identity.base
        || pending.selected_parent != identity.selected_parent
        || pending.message != identity.message
    {
        return Err("replay stopped-source metadata changed".into());
    }
    let images = if replay.cursor == replay.queue.len() {
        if replay.stop != "complete" {
            return Err("finished replay is not prepared for publication".into());
        }
        ReplayImages {
            files: mapped(snapshot, &progress, pending.legacy_path.as_deref())?.files,
            conflicts: BTreeMap::new(),
        }
    } else {
        let sides = views(snapshot, pending, &replay.queue[replay.cursor], &progress)?;
        allowed.extend(sides.iter().flat_map(|side| side.files.keys().cloned()));
        let images = merge_images(sides.clone(), pending.legacy_path.as_deref())?;
        let can_ff = replay.options.fast_forward
            && selected_parent(snapshot, pending, &replay.queue[replay.cursor])?.as_deref()
                == Some(progress.as_str())
            && matches!(snapshot.objects.get(&replay.queue[replay.cursor]),Some(Object::Commit(commit)) if commit.format==2 && commit.legacy_path==pending.legacy_path);
        let expected = if !images.conflicts.is_empty() {
            "conflict"
        } else if stops_empty(
            &replay.options,
            images.files == sides[1].files,
            sides[0].files == sides[2].files,
            can_ff,
        ) {
            "empty"
        } else {
            return Err("replay claims a stop at an automatically clean source".into());
        };
        if replay.stop != expected {
            return Err("replay stop reason differs from its original images".into());
        }
        images
    };
    if !replay.owned.is_subset(&allowed) {
        return Err("replay ownership contains an unrelated path".into());
    }
    if let Some(cp) = &replay.checkpoint {
        if cp.action == "begin" && cp.index_before != pending.baseline_index {
            return Err("initial replay checkpoint changed its baseline index".into());
        }
        if cp.action == "continue" {
            let manual = replay
                .steps
                .iter()
                .rev()
                .find(|step| matches!(step.action.as_str(), "manual" | "skipped"))
                .ok_or("continued replay has no manual step")?;
            let raw = cp
                .index_before
                .as_deref()
                .ok_or("manual checkpoint lacks its reviewed index")?;
            if manual.action != "manual"
                || manual.index_sha256.as_deref()
                    != Some(format!("{:x}", Sha256::digest(raw)).as_str())
            {
                return Err("replay checkpoint no longer names its reviewed index".into());
            }
        }
        crate::porcelain::validate_replay_checkpoint(cp, &images, pending.legacy_path.as_deref())?;
    }
    if replay.options.no_commit {
        if pending.prepared.is_some() {
            return Err("no-commit replay has a prepared commit".into());
        }
    } else if replay.stop == "complete" {
        if pending.prepared.as_ref().is_none_or(|prepared| {
            prepared.commit != progress
                || prepared.index_sha256
                    != format!("{:x}", Sha256::digest(b"native replay checkpoint"))
        }) {
            return Err("final replay preparation differs from its complete chain".into());
        }
    } else if pending.prepared.is_some() {
        return Err("stopped replay has a final prepared commit".into());
    }
    Ok(())
}
pub(super) fn report(pending: &PendingOperation) -> Value {
    let replay = pending.replay.as_ref().expect("replay report");
    json!({"schema_version":1,"status":if replay.stop=="complete"{"prepared"}else{&replay.stop},"operation":pending.operation,"pending_id":pending.id,"branch":pending.branch,"old_head":pending.head,"target":pending.target,"queue":replay.queue,"cursor":replay.cursor,"remaining":replay.queue.len()-replay.cursor,"progress":replay.progress,"progress_kind":if replay.options.no_commit{"tree"}else{"commit"},"no_commit":replay.options.no_commit,"steps":replay.steps,"checkpoint_pending":replay.checkpoint.is_some(),"head_updated":false,"index_updated":replay.index_changed,"worktree_updated":replay.worktree_changed,"pending_cleared":false})
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        repo: Repository,
        original: Files,
        head: String,
        pending: PendingOperation,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.repo.root);
        }
    }
    fn wasm(n: u8) -> Vec<u8> {
        [WASM_HEADER.as_slice(), &[0, 3, 1, b'x', n]].concat()
    }
    fn files(a: u8, b: u8, c: u8) -> Files {
        [
            ("a.wasm".into(), wasm(a)),
            ("b.wasm".into(), wasm(b)),
            ("c.wasm".into(), wasm(c)),
        ]
        .into()
    }
    fn index(files: &Files) -> Vec<u8> {
        crate::porcelain::encode_worktree_index(files, None).unwrap()
    }
    fn commit(repo: &Repository, files: &Files, message: &str) -> String {
        let state = repo.state().unwrap();
        repo.commit_files_on_branch(
            files,
            message,
            &state.tip().cloned().into_iter().collect::<Vec<_>>(),
            &state.head,
            state.tip().map(String::as_str),
            None,
        )
        .unwrap()
    }
    fn fixture(conflict: bool) -> Fixture {
        let path = PathBuf::from("/tmp").join(unique_name("uwgit-replay-recovery"));
        fs::create_dir(&path).unwrap();
        let repo = Repository::init(&path).unwrap();
        let base = commit(&repo, &files(1, 1, 1), "base");
        repo.create_branch("source", &base).unwrap();
        repo.switch_branch("source").unwrap();
        let first = commit(&repo, &files(2, 1, 1), "first");
        let second = commit(&repo, &files(2, 2, 1), "second");
        repo.switch_branch("main").unwrap();
        let original = files(if conflict { 3 } else { 1 }, 1, 9);
        let head = commit(&repo, &original, "ours");
        for (path, bytes) in &original {
            fs::write(repo.root.join(path), bytes).unwrap();
        }
        let raw = index(&original);
        fs::write(repo.metadata.join("index"), &raw).unwrap();
        let work: Worktree = original
            .iter()
            .map(|(p, b)| (p.clone(), Some(b.clone())))
            .collect();
        let request = ReplayRequest {
            operation: "cherry-pick".into(),
            branch: "main".into(),
            head: head.clone(),
            revisions: vec![first, second],
            options: ReplayOptions {
                no_commit: false,
                mainline: None,
                message: None,
                append_source: false,
                empty: "stop".into(),
                allow_empty: false,
                fast_forward: false,
                reverse: false,
            },
            baseline_index: Some(raw.clone()),
            legacy_path: None,
            worktree: work.clone(),
        };
        let pending = repo
            .begin_replay_pending(request, |_, images| {
                let mut after = images.files.clone();
                for (path, sides) in &images.conflicts {
                    if let Some(ours) = &sides[1] {
                        after.insert(path.clone(), ours.clone());
                    }
                }
                let index_after = if images.conflicts.is_empty() {
                    index(&images.files)
                } else {
                    #[derive(Serialize)]
                    struct Stage<'a> {
                        base: &'a Option<Vec<u8>>,
                        ours: &'a Option<Vec<u8>>,
                        theirs: &'a Option<Vec<u8>>,
                    }
                    #[derive(Serialize)]
                    struct Raw<'a> {
                        format: u32,
                        files: &'a Files,
                        legacy_path: Option<&'a str>,
                        conflicts: BTreeMap<&'a str, Stage<'a>>,
                    }
                    let conflicts = images
                        .conflicts
                        .iter()
                        .map(|(p, s)| {
                            (
                                p.as_str(),
                                Stage {
                                    base: &s[0],
                                    ours: &s[1],
                                    theirs: &s[2],
                                },
                            )
                        })
                        .collect();
                    let mut raw = b"UWGITIDX\x03".to_vec();
                    raw.extend(
                        serde_json::to_vec(&Raw {
                            format: 3,
                            files: &images.files,
                            legacy_path: None,
                            conflicts,
                        })
                        .unwrap(),
                    );
                    raw.push(b'\n');
                    raw
                };
                Ok(ReplayCheckpoint {
                    action: "begin".into(),
                    index_before: Some(raw),
                    index_after,
                    work_before: work.clone(),
                    work_after: original
                        .keys()
                        .map(|p| (p.clone(), after.get(p).cloned()))
                        .collect(),
                    owned_before: original.keys().cloned().collect(),
                })
            })
            .unwrap();
        Fixture {
            repo,
            original,
            head,
            pending,
        }
    }
    fn write_checkpoint(f: &Fixture) {
        let cp = f
            .pending
            .replay
            .as_ref()
            .unwrap()
            .checkpoint
            .as_ref()
            .unwrap();
        for (path, bytes) in &cp.work_after {
            if let Some(bytes) = bytes {
                fs::write(f.repo.root.join(path), bytes).unwrap();
            } else {
                let _ = fs::remove_file(f.repo.root.join(path));
            }
        }
        fs::write(f.repo.metadata.join("index"), &cp.index_after).unwrap();
    }
    fn control(f: &Fixture, action: &str) -> RepositoryResult<Value> {
        crate::porcelain::replay_control(f.repo.root.to_str().unwrap(), "cherry-pick", action)
            .map(|v| serde_json::from_str(&v).unwrap())
    }

    #[test]
    fn replay_checkpoint_recovers_every_partial_file_and_index_write_without_duplicate_objects() {
        for cut in 0..=4 {
            let f = fixture(false);
            let cp = f
                .pending
                .replay
                .as_ref()
                .unwrap()
                .checkpoint
                .as_ref()
                .unwrap();
            for (path, bytes) in cp.work_after.iter().take(cut.min(3)) {
                fs::write(f.repo.root.join(path), bytes.as_ref().unwrap()).unwrap();
            }
            if cut == 4 {
                fs::write(f.repo.metadata.join("index"), &cp.index_after).unwrap();
            }
            let objects = f.repo.snapshot().unwrap().encoded;
            let log = f.repo.reflog().unwrap().len();
            let report = control(&f, "continue").unwrap();
            assert_eq!(report["status"], "committed");
            assert_eq!(
                f.repo.state().unwrap().tip(),
                Some(&f.pending.replay.as_ref().unwrap().progress)
            );
            assert_eq!(f.repo.snapshot().unwrap().encoded, objects);
            assert_eq!(f.repo.reflog().unwrap().len(), log + 1);
            assert_eq!(
                fs::read(f.repo.metadata.join("index")).unwrap(),
                cp.index_after
            );
            for (path, bytes) in &cp.work_after {
                assert_eq!(
                    fs::read(f.repo.root.join(path)).unwrap(),
                    *bytes.as_ref().unwrap()
                );
            }
            assert!(f.repo.pending().unwrap().is_none());
        }
    }

    #[test]
    fn replay_checkpoint_refuses_later_edits_before_any_repair_and_abort_restores_baseline() {
        let f = fixture(false);
        fs::write(f.repo.root.join("b.wasm"), b"later editor bytes").unwrap();
        let raw = fs::read(f.repo.metadata.join("index")).unwrap();
        assert!(control(&f, "continue")
            .unwrap_err()
            .contains("work path changed"));
        assert_eq!(
            fs::read(f.repo.root.join("a.wasm")).unwrap(),
            f.original["a.wasm"]
        );
        assert_eq!(fs::read(f.repo.metadata.join("index")).unwrap(), raw);
        assert_eq!(f.repo.state().unwrap().tip(), Some(&f.head));
        assert!(f.repo.pending().unwrap().is_some());
        control(&f, "abort").unwrap();
        for (path, bytes) in &f.original {
            assert_eq!(fs::read(f.repo.root.join(path)).unwrap(), *bytes);
        }
        assert_eq!(fs::read(f.repo.metadata.join("index")).unwrap(), raw);
    }

    #[test]
    fn replay_settled_and_published_retries_preserve_editor_bytes_repair_reflog_once_and_create_no_objects(
    ) {
        for published in [false, true] {
            let f = fixture(false);
            write_checkpoint(&f);
            let settled = f
                .repo
                .settle_replay_checkpoint(&f.pending, |_| Ok(()))
                .unwrap();
            let progress = settled.replay.as_ref().unwrap().progress.clone();
            if published {
                fs::write(f.repo.metadata.join("refs/main"), format!("{progress}\n")).unwrap();
            }
            fs::write(f.repo.metadata.join("index"), b"later broken editor index").unwrap();
            fs::write(f.repo.root.join("a.wasm"), b"later raw edit").unwrap();
            let count = f.repo.reflog().unwrap().len();
            let objects = f.repo.snapshot().unwrap().encoded;
            let report = control(&f, "continue").unwrap();
            assert_eq!(report["already_published"], published);
            assert_eq!(f.repo.reflog().unwrap().len(), count + 1);
            assert_eq!(f.repo.snapshot().unwrap().encoded, objects);
            assert_eq!(
                fs::read(f.repo.root.join("a.wasm")).unwrap(),
                b"later raw edit"
            );
            assert_eq!(
                fs::read(f.repo.metadata.join("index")).unwrap(),
                b"later broken editor index"
            );
            fs::write(
                f.repo.metadata.join("pending.json"),
                encode_pending(&settled).unwrap(),
            )
            .unwrap();
            assert_eq!(control(&f, "continue").unwrap()["already_published"], true);
            assert_eq!(f.repo.reflog().unwrap().len(), count + 1);
        }
    }

    #[test]
    fn replay_repair_of_conflict_checkpoint_does_not_consume_an_unreviewed_index() {
        let f = fixture(true);
        write_checkpoint(&f);
        let report = control(&f, "continue").unwrap();
        assert_eq!(report["status"], "conflict");
        assert_eq!(report["cursor"], 0);
        assert_eq!(f.repo.state().unwrap().tip(), Some(&f.head));
        assert!(control(&f, "continue").unwrap_err().contains("unresolved"));
        assert_eq!(f.repo.pending().unwrap().unwrap().replay.unwrap().cursor, 0);
    }

    #[test]
    fn replay_stale_head_or_branch_and_forged_step_or_checkpoint_are_rejected_without_writes() {
        let f = fixture(false);
        let objects = f.repo.snapshot().unwrap().encoded;
        let raw = fs::read(f.repo.metadata.join("index")).unwrap();
        f.repo.create_branch("other", &f.head).unwrap();
        f.repo
            .atomic_write(&f.repo.metadata.join("HEAD"), b"other\n")
            .unwrap();
        assert!(control(&f, "continue").is_err());
        assert!(control(&f, "abort").is_err());
        f.repo
            .atomic_write(&f.repo.metadata.join("HEAD"), b"main\n")
            .unwrap();
        for field in 0..4 {
            let mut forged = f.pending.clone();
            let replay = forged.replay.as_mut().unwrap();
            match field {
                0 => replay.steps[0].result = Some(f.head.clone()),
                1 => replay.options.no_commit = true,
                2 => replay.checkpoint.as_mut().unwrap().index_after = index(&files(8, 8, 8)),
                _ => replay
                    .checkpoint
                    .as_mut()
                    .unwrap()
                    .work_after
                    .insert("a.wasm".into(), Some(wasm(8)))
                    .map(|_| ())
                    .unwrap(),
            }
            let bytes = serde_json::to_vec(&forged).unwrap();
            // Add canonical trailing newline just as encode_pending does.
            fs::write(
                f.repo.metadata.join("pending.json"),
                [bytes, b"\n".to_vec()].concat(),
            )
            .unwrap();
            assert!(f.repo.pending().is_err());
            assert_eq!(fs::read(f.repo.metadata.join("index")).unwrap(), raw);
            assert_eq!(f.repo.snapshot().unwrap().encoded, objects);
        }
        fs::write(
            f.repo.metadata.join("pending.json"),
            encode_pending(&f.pending).unwrap(),
        )
        .unwrap();
        control(&f, "quit").unwrap();
    }
}
