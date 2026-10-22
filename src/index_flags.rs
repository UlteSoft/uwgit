//! Native index promises and image validity. No empty Wasm images are invented.
use super::*;
use sha2::{Digest, Sha256};

#[derive(clap::Args, Default)]
pub(super) struct Options {
    #[arg(long, conflicts_with = "no_assume_unchanged")]
    assume_unchanged: bool,
    #[arg(long)]
    no_assume_unchanged: bool,
    #[arg(long, conflicts_with = "no_skip_worktree")]
    skip_worktree: bool,
    #[arg(long)]
    no_skip_worktree: bool,
    #[arg(long, conflicts_with = "no_fsmonitor_valid")]
    fsmonitor_valid: bool,
    #[arg(long)]
    no_fsmonitor_valid: bool,
    #[arg(long, conflicts_with = "really_refresh")]
    refresh: bool,
    #[arg(long)]
    really_refresh: bool,
    #[arg(long)]
    ignore_missing: bool,
    #[arg(long)]
    unmerged: bool,
}
impl Options {
    pub(super) fn enabled(&self) -> bool {
        self.assume_unchanged
            || self.no_assume_unchanged
            || self.skip_worktree
            || self.no_skip_worktree
            || self.fsmonitor_valid
            || self.no_fsmonitor_valid
            || self.refresh
            || self.really_refresh
            || self.ignore_missing
            || self.unmerged
    }
    fn changes_flags(&self) -> bool {
        self.assume_unchanged
            || self.no_assume_unchanged
            || self.skip_worktree
            || self.no_skip_worktree
            || self.fsmonitor_valid
            || self.no_fsmonitor_valid
    }
    pub(super) fn update(
        &self,
        state: &State,
        index: &mut Index,
        paths: Vec<String>,
    ) -> Result<usize, String> {
        let refresh = self.refresh || self.really_refresh;
        if (self.ignore_missing || self.unmerged) && !refresh {
            return Err("--ignore-missing and --unmerged require refresh".into());
        }
        if self.changes_flags() && paths.is_empty() {
            return Err("index flag changes require explicit paths".into());
        }
        let paths = if paths.is_empty() {
            controlled_paths(index).into_iter().collect()
        } else {
            paths
        };
        let mut checked = 0;
        for path in paths {
            validate_tree_path(&path)?;
            if index.conflicts.contains_key(&path) {
                if refresh && self.unmerged && !self.changes_flags() {
                    continue;
                }
                return Err(format!(
                    "index flags/refresh require resolved entries: {path}"
                ));
            }
            if !index.files.contains_key(&path) && !index.intents.contains(&path) {
                return Err(format!("path is not in the index: {path}"));
            }
            let mut flag = index.flags.get(&path).cloned().unwrap_or_default();
            if refresh && (self.really_refresh || !flag.hidden()) {
                let current = state.worktree_module(&path)?;
                if !(current.is_none() && self.ignore_missing)
                    && current.as_ref() != index.files.get(&path)
                {
                    return Err(format!(
                        "index refresh needs update: {path}; bytes were not staged"
                    ));
                }
                checked += 1;
                if flag.fsmonitor_valid.is_some() {
                    flag.fsmonitor_valid = current.as_ref().map(|bytes| digest(bytes));
                }
            }
            if self.assume_unchanged {
                flag.assume_unchanged = true;
            }
            if self.no_assume_unchanged {
                flag.assume_unchanged = false;
            }
            if self.skip_worktree {
                flag.skip_worktree = true;
            }
            if self.no_skip_worktree {
                flag.skip_worktree = false;
            }
            if self.fsmonitor_valid {
                let bytes = state
                    .worktree_module(&path)?
                    .ok_or("fsmonitor validity requires a present original image")?;
                if index.files.get(&path) != Some(&bytes) {
                    return Err(
                        "fsmonitor validity requires work bytes identical to the index".into(),
                    );
                }
                flag.fsmonitor_valid = Some(digest(&bytes));
            }
            if self.no_fsmonitor_valid {
                flag.fsmonitor_valid = None;
            }
            if flag.empty() {
                index.flags.remove(&path);
            } else {
                index.flags.insert(path, flag);
            }
        }
        index.tidy();
        if !index.flags.is_empty() || !index.intents.is_empty() {
            index.format = index.format.max(4);
        }
        validate_index(index)?;
        Ok(checked)
    }
}
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn monitor_valid(state: &State, index: &Index, path: &str) -> Result<bool, String> {
    let Some(expected) = index
        .flags
        .get(path)
        .and_then(|flag| flag.fsmonitor_valid.as_ref())
    else {
        return Ok(false);
    };
    Ok(state
        .worktree_module(path)?
        .is_some_and(|bytes| digest(&bytes) == *expected))
}
pub(super) fn query_worktree(state: &State, index: &Index) -> Result<Worktree, String> {
    controlled_paths(index)
        .into_iter()
        .map(|path| {
            let bytes = if index.hidden(&path) {
                index.files.get(&path).cloned()
            } else {
                state.worktree_module(&path)?
            };
            Ok((path, bytes))
        })
        .collect()
}

/// Preserve explicit sparse omissions, and dirty bytes on unchanged images.
/// Every writer still reads real files before it decides what can be replaced.
pub(super) fn transition_worktree(
    state: &State,
    old: &Index,
    target: &Index,
    discard: bool,
) -> Result<Worktree, String> {
    let paths: BTreeSet<_> = controlled_paths(old)
        .into_iter()
        .chain(controlled_paths(target))
        .collect();
    let current = state.snapshot_worktree(paths.iter().cloned())?;
    let mut work = files_worktree(&target.files);
    for path in paths {
        let actual = current.get(&path).cloned().flatten();
        let before = old.files.get(&path);
        let after = target.files.get(&path);
        if target.intents.contains(&path)
            || ((target.skipped(&path) || old.skipped(&path)) && actual.is_none())
            || (!discard && before == after)
        {
            work.insert(path, actual);
        } else if !discard && actual.as_ref() != before {
            if before.is_none() && !controlled_paths(old).contains(&path) {
                return Err(format!("untracked file would be overwritten: {path}"));
            }
            return Err(format!("worktree update would discard dirty bytes: {path}"));
        }
    }
    Ok(work)
}
pub(super) fn inherit(target: &mut Index, old: &Index) {
    target.flags = old
        .flags
        .iter()
        .filter(|(path, _)| target.files.contains_key(*path))
        .map(|(path, flag)| {
            let mut flag = flag.clone();
            if target.files.get(path) != old.files.get(path) {
                flag.fsmonitor_valid = None;
            }
            (path.clone(), flag)
        })
        .filter(|(_, flag)| !flag.empty())
        .collect();
    if !target.flags.is_empty() {
        target.format = target.format.max(4);
    }
}
