//! Restore original native conflict images without ever inserting text markers
//! into a Wasm module. A successful worktree merge does not resolve the index.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Ours,
    Theirs,
    Merge,
    IgnoreUnmerged,
}

pub(super) fn restore(
    state: &State,
    mode: Mode,
    ignore_skip: bool,
    selectors: &[String],
) -> Result<String, String> {
    if selectors.is_empty() {
        return Err("unmerged restore requires explicit path selectors".into());
    }
    let original = state.index()?.ok_or("no index to restore")?;
    let owned = controlled_paths(&original);
    let mut candidates = owned.clone();
    if mode == Mode::Merge {
        candidates.extend(original.resolve_undo.keys().cloned());
    }
    let selected: BTreeSet<_> = select_paths(&candidates, selectors)?
        .into_iter()
        .filter(|path| ignore_skip || !original.skipped(path))
        .collect();
    let mut index = original.clone();
    if mode == Mode::Merge {
        // Validate the entire restored stage tree, including any D/F group,
        // before preparing or publishing a single worktree image.
        index_resolve_undo::unresolve(&mut index, &selected.iter().cloned().collect::<Vec<_>>())?;
    }
    let mut images = Worktree::new();
    let mut merged = 0;
    let mut fallbacks = Vec::new();
    for path in &selected {
        let image = if let Some(sides) = index.conflicts.get(path) {
            match mode {
                Mode::Ours => sides.ours.clone(),
                Mode::Theirs => sides.theirs.clone(),
                Mode::IgnoreUnmerged => continue,
                Mode::Merge => {
                    // Like path checkout -m, both live sides are required.
                    // A deleted side stays absent in the index; never invent
                    // an empty Wasm module to make the merge possible.
                    if sides.ours.is_none() || sides.theirs.is_none() {
                        return Err(format!(
                            "cannot recreate merge for {path}: stages 2 and 3 are required; use --ours/--theirs or an explicit tree resolution"
                        ));
                    }
                    match merge_file(
                        sides.base.as_ref(),
                        sides.ours.as_ref(),
                        sides.theirs.as_ref(),
                        path,
                    ) {
                        Ok(image) => {
                            merged += 1;
                            image
                        }
                        Err(reason) => {
                            fallbacks.push(format!("{path}: {reason}"));
                            sides.ours.clone()
                        }
                    }
                }
            }
        } else if index.intents.contains(path) {
            return Err(format!("intent-to-add has no image to restore: {path}"));
        } else {
            index.files.get(path).cloned()
        };
        if let Some(bytes) = &image {
            validate_wasm(bytes)?;
        }
        images.insert(path.clone(), image);
    }
    // Only the old index grants ownership. Undo-only names may have become
    // untracked user files since a deletion was resolved; protect those files.
    let restored = images.len();
    // Scope ownership as well as the desired images. Unselected and ignored
    // paths must not be read (they may contain editor symlinks/special files),
    // and still obstruct destructive D/F replacement during preflight.
    let selected_owned = owned
        .into_iter()
        .filter(|path| images.contains_key(path))
        .collect();
    let changes = plan(state, &selected_owned, &images)?;
    apply_plan(state, &changes)?;
    let index_updated = index != original;
    if index_updated {
        state.save_index(&index).map_err(|error| {
            format!("worktree restored, resolve-undo index update failed: {error}")
        })?;
    }
    let mut result = format!(
        "restored {restored} work paths; index {}; unmerged stages preserved",
        if index_updated {
            "restored from resolve-undo"
        } else {
            "preserved"
        }
    );
    if mode == Mode::Merge {
        result.push_str(&format!(
            "; native Wasm merges: {merged}; ours fallbacks: {}",
            fallbacks.len()
        ));
        for reason in fallbacks {
            result.push_str(&format!("\nours fallback: {reason}"));
        }
    }
    Ok(result)
}
