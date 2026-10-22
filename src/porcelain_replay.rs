//! Index leases and resumable physical writes for the native replay journal.
use super::*;
use crate::repository::{ReplayCheckpoint, ReplayImages, ReplayOptions, ReplayRequest};

fn result_index(images: &ReplayImages, anchor: Option<&str>, old: &Index) -> Result<Index, String> {
    let mut index = Index::empty();
    index.files = images.files.clone();
    index.legacy_path = anchor.map(str::to_owned);
    index.conflicts = images
        .conflicts
        .iter()
        .map(|(path, sides)| {
            (
                path.clone(),
                ConflictStages {
                    base: sides[0].clone(),
                    ours: sides[1].clone(),
                    theirs: sides[2].clone(),
                },
            )
        })
        .collect();
    if !index.conflicts.is_empty() {
        index.format = 3;
    }
    index_flags::inherit(&mut index, old);
    index.tidy();
    validate_index(&index)?;
    Ok(index)
}
fn checkpoint(
    state: &State,
    pending: &PendingOperation,
    images: &ReplayImages,
    action: &str,
    before_progress: &Files,
) -> Result<ReplayCheckpoint, String> {
    let raw = regular(&state.metadata.join("index"))?;
    let decoded = raw.as_deref().map(decode_index).transpose();
    let old = match decoded {
        Ok(index) => index.unwrap_or_else(Index::empty),
        Err(_) if action == "skip" => {
            let mut index = Index::empty();
            index.files = before_progress.clone();
            index.legacy_path = pending.legacy_path.clone();
            index
        }
        Err(e) => return Err(e),
    };
    if !old.intents.is_empty() {
        return Err("stage or remove intent-to-add paths before replay publication".into());
    }
    let target = result_index(images, pending.legacy_path.as_deref(), &old)?;
    let replay = pending.replay.as_ref().ok_or("missing replay state")?;
    let owned_before: BTreeSet<_> = replay
        .owned
        .iter()
        .cloned()
        .chain(controlled_paths(&old))
        .collect();
    let scope: BTreeSet<_> = owned_before
        .iter()
        .cloned()
        .chain(controlled_paths(&target))
        .collect();
    let work_before = state.snapshot_worktree(scope.iter().cloned())?;
    let mut work_after = files_worktree(&target.files);
    work_after.extend(
        target
            .conflicts
            .iter()
            .map(|(path, sides)| (path.clone(), sides.ours.clone())),
    );
    for path in &scope {
        let actual = work_before.get(path).cloned().flatten();
        let before = old.files.get(path).or_else(|| {
            old.conflicts
                .get(path)
                .and_then(|sides| sides.ours.as_ref())
        });
        let after = work_after.get(path).and_then(Option::as_ref);
        let sparse_conflict =
            old.skipped(path) && actual.is_none() && images.conflicts.contains_key(path);
        if (target.skipped(path) && actual.is_none())
            || (action != "skip" && before == after && !sparse_conflict)
        {
            work_after.insert(path.clone(), actual);
        } else if action != "skip"
            && actual.as_ref() != before
            && !(old.skipped(path) && actual.is_none())
        {
            return Err(format!("replay would discard dirty work bytes at {path}; index and journal were not advanced"));
        } else {
            work_after.entry(path.clone()).or_insert(None);
        }
    }
    // Original index ownership authorizes overwrites. A target's newly added
    // path remains untracked until this preflight has proved it absent.
    plan(state, &owned_before, &work_after)?;
    let result = ReplayCheckpoint {
        action: action.into(),
        index_before: raw,
        index_after: index_bytes(&target)?,
        work_before,
        work_after,
        owned_before,
    };
    validate_replay_checkpoint(&result, images, pending.legacy_path.as_deref())?;
    Ok(result)
}
fn apply_checkpoint(state: &State, checkpoint: &ReplayCheckpoint) -> Result<(), String> {
    let actual_index = regular(&state.metadata.join("index"))?;
    if actual_index != checkpoint.index_before
        && actual_index.as_deref() != Some(checkpoint.index_after.as_slice())
    {
        return Err("index changed after replay preparation; saved checkpoint retained".into());
    }
    let current = state.snapshot_worktree(checkpoint.work_after.keys().cloned())?;
    for (path, value) in &current {
        if checkpoint.work_before.get(path) != Some(value)
            && checkpoint.work_after.get(path) != Some(value)
        {
            return Err(format!(
                "work path changed after replay preparation: {path}; checkpoint retained"
            ));
        }
    }
    let owned: BTreeSet<_> = checkpoint
        .owned_before
        .iter()
        .cloned()
        .chain(checkpoint.work_after.keys().cloned())
        .collect();
    let changes = plan(state, &owned, &checkpoint.work_after)?;
    apply_plan(state, &changes)?;
    let actual = regular(&state.metadata.join("index"))?;
    if actual != actual_index {
        return Err(
            "work files updated, but index changed during replay publication; checkpoint retained"
                .into(),
        );
    }
    if actual.as_deref() != Some(checkpoint.index_after.as_slice()) {
        state.write("index", &checkpoint.index_after)?;
    }
    Ok(())
}
fn settle(state: &State, pending: &PendingOperation) -> Result<PendingOperation, String> {
    if pending
        .replay
        .as_ref()
        .is_some_and(|replay| replay.checkpoint.is_some())
    {
        state
            .repo
            .settle_replay_checkpoint(pending, |checkpoint| apply_checkpoint(state, checkpoint))
    } else {
        Ok(pending.clone())
    }
}
fn finish_or_report(state: &State, pending: PendingOperation) -> Result<String, String> {
    let pending = settle(state, &pending)?;
    let report = if pending
        .replay
        .as_ref()
        .is_some_and(|replay| replay.stop == "complete")
    {
        state.repo.finish_replay_pending(&pending)?
    } else {
        state.repo.replay_status(&pending)?
    };
    json_text(&report)
}
pub fn replay_start(
    root: &str,
    operation: &str,
    revisions: Vec<String>,
    options: ReplayOptions,
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    require_no_pending(&state.repo)?;
    let snapshot = state.repo.state()?;
    let head = snapshot
        .tip()
        .ok_or("multi-target replay requires a committed HEAD")?
        .clone();
    if !options.no_commit {
        clean_index(&state)?;
    }
    let raw = regular(&state.metadata.join("index"))?;
    let old = raw
        .as_deref()
        .map(decode_index)
        .transpose()?
        .unwrap_or_else(Index::empty);
    require_resolved_index(&old)?;
    if !old.intents.is_empty() {
        return Err(
            "replay requires complete original images; stage or remove intent-to-add paths first"
                .into(),
        );
    }
    let source = state.repo.files_at(&head)?;
    let anchor = old.legacy_path.clone().or(source.legacy_path);
    let work = state.snapshot_worktree(controlled_paths(&old))?;
    let request = ReplayRequest {
        operation: operation.into(),
        branch: snapshot.head,
        head,
        revisions,
        options,
        baseline_index: raw.clone(),
        legacy_path: anchor,
        worktree: work,
    };
    let pending = state
        .repo
        .begin_replay_pending(request, |pending, images| {
            if regular(&state.metadata.join("index"))? != raw {
                return Err("index changed during replay planning; nothing published".into());
            }
            checkpoint(&state, pending, images, "begin", &old.files)
        })?;
    finish_or_report(&state, pending)
}
pub fn replay_control(root: &str, operation: &str, action: &str) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let pending = selected_pending(&state.repo, operation)?;
    if pending.replay.is_none() {
        return Err("the saved operation is not a multi-target replay".into());
    }
    match action {
        "quit" => {
            state.repo.quit_pending(&pending)?;
            json_text(
                &json!({"status":"quit","operation":operation,"pending_id":pending.id,"head_updated":false,"index_updated":false,"worktree_updated":false,"pending_cleared":true}),
            )
        }
        "abort" => {
            state.repo.abort_pending(&pending, |pending, _| {
                let replay = pending.replay.as_ref().ok_or("missing replay state")?;
                let original = regular(&state.metadata.join("index"))?;
                let changes = plan(&state, &replay.owned, &replay.initial_worktree)?;
                apply_plan(&state, &changes)?;
                if regular(&state.metadata.join("index"))? != original {
                    return Err("index changed during replay abort; journal retained".into());
                }
                if let Some(raw) = &pending.baseline_index {
                    state.write("index", raw)?;
                } else if original.is_some() {
                    fs::remove_file(state.metadata.join("index")).map_err(|e| e.to_string())?;
                    File::open(&state.metadata)
                        .and_then(|file| file.sync_all())
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            })?;
            json_text(
                &json!({"status":"aborted","operation":operation,"pending_id":pending.id,"head_updated":false,"original_index_restored":true,"original_tracked_work_restored":true,"pending_cleared":true}),
            )
        }
        "continue" | "skip" => {
            let recovering = pending
                .replay
                .as_ref()
                .is_some_and(|replay| replay.checkpoint.is_some());
            let pending = settle(&state, &pending)?;
            if pending
                .replay
                .as_ref()
                .is_some_and(|replay| replay.stop == "complete")
            {
                return json_text(&state.repo.finish_replay_pending(&pending)?);
            }
            if recovering {
                return json_text(&state.repo.replay_status(&pending)?);
            }
            let progress = state.repo.replay_progress_images(&pending)?;
            let raw = regular(&state.metadata.join("index"))?;
            let index = if action == "continue" {
                let index = decode_index(
                    raw.as_deref()
                        .ok_or("continue requires a complete reviewed index")?,
                )?;
                require_resolved_index(&index)?;
                if !index.intents.is_empty() {
                    return Err("stage or remove intent-to-add paths before continuing".into());
                }
                Some(index)
            } else {
                None
            };
            let supplied = index.as_ref().map(|index| PendingIndex {
                files: &index.files,
                legacy_path: index.legacy_path.as_deref(),
                raw: raw.as_deref().unwrap(),
            });
            let next = state.repo.advance_replay_pending(
                &pending,
                action,
                supplied,
                |pending, images| {
                    if regular(&state.metadata.join("index"))? != raw {
                        return Err(
                            "index changed during replay continuation; nothing published".into(),
                        );
                    }
                    checkpoint(&state, pending, images, action, &progress)
                },
            )?;
            finish_or_report(&state, next)
        }
        _ => Err("unknown replay control".into()),
    }
}
