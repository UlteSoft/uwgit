//! Frozen three-way inputs for explicit external binary merge tools.
use super::*;

pub struct MergeToolInputs {
    pub pending: PendingOperation,
    pub base: Option<String>,
    pub ours: String,
    pub theirs: Option<String>,
    pub files: BTreeMap<String, [Option<Vec<u8>>; 3]>,
}
impl Repository {
    pub fn merge_tool_inputs(&self) -> RepositoryResult<MergeToolInputs> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let pending = self
            .read_pending()?
            .ok_or("mergetool requires an explicitly recorded pending conflict")?;
        validate_pending_snapshot(&snapshot, &pending)?;
        check_expected_branch(&snapshot.manifest.head, Some(&pending.branch))?;
        check_expected(
            snapshot.manifest.refs.get(&pending.branch),
            Some(&pending.head),
        )?;
        if pending.prepared.is_some() {
            return Err(
                "pending publication is prepared; finish --continue before running a merge tool"
                    .into(),
            );
        }
        let ours = pending
            .rebase
            .as_ref()
            .map(|rebase| rebase.progress_tip.clone())
            .unwrap_or_else(|| pending.head.clone());
        let (base, theirs) = if pending.operation == "revert" {
            (
                Some(pending.target.clone()),
                pending.selected_parent.clone(),
            )
        } else {
            (
                pending
                    .base
                    .clone()
                    .or_else(|| pending.selected_parent.clone()),
                Some(pending.target.clone()),
            )
        };
        let empty = || RevisionFiles {
            commit: String::new(),
            legacy: None,
            files: BTreeMap::new(),
            legacy_path: pending.legacy_path.clone(),
        };
        let mut revisions = [
            base.as_ref()
                .map(|id| snapshot_files(&snapshot, id))
                .transpose()?
                .unwrap_or_else(empty),
            snapshot_files(&snapshot, &ours)?,
            theirs
                .as_ref()
                .map(|id| snapshot_files(&snapshot, id))
                .transpose()?
                .unwrap_or_else(empty),
        ];
        let merged = merge_file_revisions(revisions.clone(), pending.legacy_path.as_deref())?;
        for revision in &mut revisions {
            if let Some(bytes) = revision.legacy.take() {
                let path = pending
                    .legacy_path
                    .as_deref()
                    .or(revision.legacy_path.as_deref())
                    .ok_or("mergetool requires an explicit saved legacy path mapping")?;
                revision.files.insert(path.into(), bytes);
            }
        }
        let all: BTreeSet<_> = revisions
            .iter()
            .flat_map(|revision| revision.files.keys().cloned())
            .collect();
        let conflicts: BTreeSet<_> = if merged
            .reports
            .iter()
            .any(|report| report.status == "conflict" && report.path.is_empty())
        {
            all
        } else {
            merged
                .reports
                .iter()
                .filter(|report| report.status == "conflict")
                .map(|report| report.path.clone())
                .collect()
        };
        let files = conflicts
            .into_iter()
            .map(|path| {
                let sides = [
                    revisions[0].files.get(&path).cloned(),
                    revisions[1].files.get(&path).cloned(),
                    revisions[2].files.get(&path).cloned(),
                ];
                (path, sides)
            })
            .collect();
        Ok(MergeToolInputs {
            pending,
            base,
            ours,
            theirs,
            files,
        })
    }

    pub fn with_merge_tool_lease<T>(
        &self,
        expected: &PendingOperation,
        operation: impl FnOnce() -> RepositoryResult<T>,
    ) -> RepositoryResult<T> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if self.read_pending()?.as_ref() != Some(expected) {
            return Err(
                "pending conflict changed while the merge tool ran; index preserved".into(),
            );
        }
        check_expected_branch(&snapshot.manifest.head, Some(&expected.branch))?;
        check_expected(
            snapshot.manifest.refs.get(&expected.branch),
            Some(&expected.head),
        )?;
        operation()
    }
}

pub struct SquashPlan {
    pub branch: String,
    pub head: String,
    pub target: String,
    pub base: Option<String>,
    pub status: String,
    pub files: Option<BTreeMap<String, Vec<u8>>>,
    pub legacy_path: Option<String>,
    pub reports: Vec<FileMergeReport>,
}
impl Repository {
    pub fn squash_plan(&self, target: &str, anchor: Option<&str>) -> RepositoryResult<SquashPlan> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let branch = snapshot.manifest.head.clone();
        let head = snapshot
            .manifest
            .refs
            .get(&branch)
            .ok_or("--squash requires a committed HEAD")?
            .clone();
        let target = snapshot_revision(&snapshot, target)?;
        if is_ancestor(&target, &head, &snapshot.objects)? {
            return Ok(SquashPlan {
                branch,
                head,
                target,
                base: None,
                status: "already_up_to_date".into(),
                files: None,
                legacy_path: anchor.map(str::to_owned),
                reports: Vec::new(),
            });
        }
        let base = unique_merge_base(&head, &target, &snapshot.objects)?;
        let merged = merge_file_revisions(
            [
                snapshot_files(&snapshot, &base)?,
                snapshot_files(&snapshot, &head)?,
                snapshot_files(&snapshot, &target)?,
            ],
            anchor,
        )?;
        let conflicted = merged
            .reports
            .iter()
            .any(|report| report.status == "conflict");
        Ok(SquashPlan {
            branch,
            head,
            target,
            base: Some(base),
            status: if conflicted { "conflict" } else { "squashed" }.into(),
            files: (!conflicted).then_some(merged.files),
            legacy_path: merged.legacy_path,
            reports: merged.reports,
        })
    }
    pub fn with_head_lease<T>(
        &self,
        branch: &str,
        head: &str,
        operation: impl FnOnce() -> RepositoryResult<T>,
    ) -> RepositoryResult<T> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        check_expected_branch(&snapshot.manifest.head, Some(branch))?;
        check_expected(snapshot.manifest.refs.get(branch), Some(head))?;
        if self.read_pending()?.is_some() {
            return Err("a pending operation appeared during merge preparation".into());
        }
        operation()
    }
}
