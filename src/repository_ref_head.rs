//! A worktree's native HEAD participates in the common reference journal.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceHead {
    pub worktree: Option<String>,
    pub before: String,
    pub after: String,
    pub head_reflog: Option<Vec<u8>>,
    pub worktrees: Option<Vec<u8>>,
}

impl ReferenceHead {
    pub fn capture(
        repo: &Repository,
        snapshot: &Snapshot,
        after: String,
    ) -> RepositoryResult<Self> {
        let (worktree, worktrees) = repo.reference_head_registry()?;
        Ok(Self {
            worktree,
            before: snapshot.manifest.head.clone(),
            after,
            head_reflog: optional_file(&repo.metadata.join("head-reflog.json"))?,
            worktrees,
        })
    }

    pub fn origin(&self, repo: &Repository) -> RepositoryResult<Repository> {
        validate_head_identity(&self.before)?;
        validate_head_identity(&self.after)?;
        self.registry_after()?;
        linked_worktrees::reference_head_origin(
            &repo.common_metadata,
            self.worktree.as_deref(),
            self.worktrees.as_deref(),
        )
    }

    fn registry_after(&self) -> RepositoryResult<Option<Vec<u8>>> {
        linked_worktrees::reference_registry_after(
            self.worktree.as_deref(),
            self.worktrees.as_deref(),
            &self.before,
            &self.after,
        )
    }

    pub fn changed(&self) -> bool {
        self.before != self.after
    }

    pub fn validate_images(
        &self,
        before: &ReferenceState,
        after: &ReferenceState,
        message: &str,
    ) -> RepositoryResult<()> {
        validate_head_identity(&self.before)?;
        validate_head_identity(&self.after)?;
        self.registry_after()?;
        self.reflog_after(before, after, message)?;
        Ok(())
    }

    pub fn event(
        &self,
        before: &ReferenceState,
        after: &ReferenceState,
        message: &str,
        sequence: u64,
    ) -> ReflogEntry {
        ReflogEntry {
            sequence,
            reference: "HEAD".into(),
            old: head_tip(&self.before, &before.refs).cloned(),
            new: head_tip(&self.after, &after.refs).cloned(),
            operation: message.into(),
        }
    }

    fn reflog_after(
        &self,
        before: &ReferenceState,
        after: &ReferenceState,
        message: &str,
    ) -> RepositoryResult<Option<Vec<u8>>> {
        let mut entries = head_storage::decode_head_reflog(self.head_reflog.as_deref())?;
        if !self.changed() {
            return Ok(self.head_reflog.clone());
        }
        let sequence = entries
            .last()
            .map_or(Some(1), |entry| entry.sequence.checked_add(1))
            .ok_or("HEAD reflog sequence overflow")?;
        if entries.len() == 4096 {
            entries.remove(0);
        }
        entries.push(self.event(before, after, message, sequence));
        let bytes = serde_json::to_vec(&entries).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_PENDING_BYTES {
            return Err("HEAD reflog exceeds its size limit".into());
        }
        Ok(Some(bytes))
    }

    pub fn check_preimages(
        &self,
        repo: &Repository,
        before: &ReferenceState,
        after: &ReferenceState,
        message: &str,
    ) -> RepositoryResult<()> {
        let origin = self.origin(repo)?;
        let actual = origin.current_branch()?;
        if actual != self.before && actual != self.after {
            return Err(
                "HEAD differs from both transaction images; restore it before recovery".into(),
            );
        }
        let registry_after = self.registry_after()?;
        let reflog_after = self.reflog_after(before, after, message)?;
        for (path, before, after) in [
            (
                repo.common_metadata.join("worktrees.json"),
                &self.worktrees,
                &registry_after,
            ),
            (
                origin.metadata.join("head-reflog.json"),
                &self.head_reflog,
                &reflog_after,
            ),
        ] {
            let actual = optional_file(&path)?;
            if &actual != before && &actual != after {
                return Err(format!(
                    "{} differs from both transaction images; restore it before recovery",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    pub fn apply(
        &self,
        repo: &Repository,
        before: &ReferenceState,
        after: &ReferenceState,
        message: &str,
        checkpoint: &mut impl FnMut() -> RepositoryResult<()>,
    ) -> RepositoryResult<()> {
        if !self.changed() {
            return Ok(());
        }
        let origin = self.origin(repo)?;
        origin.atomic_write(
            &origin.metadata.join("HEAD"),
            format!("{}\n", self.after).as_bytes(),
        )?;
        checkpoint()?;
        let registry_after = self.registry_after()?;
        if registry_after != self.worktrees {
            repo.atomic_write(
                &repo.common_metadata.join("worktrees.json"),
                registry_after
                    .as_deref()
                    .ok_or("missing resulting worktree registry")?,
            )?;
            checkpoint()?;
        }
        let bytes = self
            .reflog_after(before, after, message)?
            .ok_or("missing resulting HEAD reflog")?;
        origin.atomic_write(&origin.metadata.join("head-reflog.json"), &bytes)?;
        checkpoint()
    }

    pub fn report(&self, before: &ReferenceState, after: &ReferenceState) -> Value {
        let identity = |value: &str| {
            if valid_id(value) {
                value.into()
            } else {
                format!("refs/heads/{value}")
            }
        };
        json!({"reference":"HEAD","old":identity(&self.before),"new":identity(&self.after),"old_kind":if valid_id(&self.before){"commit"}else{"symbolic"},"new_kind":if valid_id(&self.after){"commit"}else{"symbolic"},"old_commit":head_tip(&self.before,&before.refs),"new_commit":head_tip(&self.after,&after.refs),"updated":self.changed()})
    }
}

pub(super) struct ResolvedHeadEdit {
    pub after: String,
    pub rejection: Option<ReferenceRejection>,
}

fn target(value: &str) -> RepositoryResult<String> {
    let branch = value
        .strip_prefix("refs/heads/")
        .ok_or("native symbolic HEAD requires refs/heads/NAME")?;
    validate_ref_name(branch)?;
    Ok(branch.into())
}

fn lease_reason(actual: Option<&String>, expected: Option<&String>) -> Option<RejectionReason> {
    if actual == expected {
        None
    } else if actual.is_none() {
        Some(RejectionReason::Missing)
    } else if expected.is_none() {
        Some(RejectionReason::Exists)
    } else {
        Some(RejectionReason::IncorrectOld)
    }
}

impl ResolvedHeadEdit {
    pub fn resolve(
        repo: &Repository,
        snapshot: &Snapshot,
        edit: &ReferenceEdit,
    ) -> RepositoryResult<Self> {
        if edit.reference != "HEAD" {
            return Err("HEAD is the native symbolic reference".into());
        }
        let before = &snapshot.manifest.head;
        let tip = snapshot.manifest.tip();
        let symbolic = matches!(
            edit.kind,
            ReferenceEditKind::SymrefUpdate | ReferenceEditKind::SymrefVerify
        );
        if symbolic && !edit.no_deref {
            return Err("native symref HEAD commands require --no-deref or option no-deref".into());
        }
        let expected = match edit.expected.as_ref() {
            Some(ReferenceExpectation::Oid(value)) => Some(resolve_reference_oid(snapshot, value)?),
            _ => None,
        };
        let expected_target = match edit.expected.as_ref() {
            Some(ReferenceExpectation::Target(value)) => Some(target(value)?),
            _ => None,
        };
        let mut after = before.clone();
        let mut reason = None;
        let mut requested_new = None;
        let mut reported_old = expected.clone().flatten();
        if let Some(expected_target) = &expected_target {
            reported_old = Some(format!("refs/heads/{expected_target}"));
        }
        if symbolic {
            if matches!(edit.kind, ReferenceEditKind::SymrefUpdate) {
                let new = edit
                    .new
                    .as_deref()
                    .ok_or("symref-update requires a new target")?;
                after = target(new)?;
                requested_new = Some(format!("refs/heads/{after}"));
            } else if matches!(edit.expected, Some(ReferenceExpectation::Oid(_))) {
                return Err("symref-verify requires an old symbolic target".into());
            }
            if let Some(expected_target) = expected_target {
                reason = if valid_id(before) {
                    Some(RejectionReason::ExpectedSymbolic)
                } else if before != &expected_target {
                    Some(RejectionReason::IncorrectOld)
                } else {
                    None
                };
            } else if let Some(expected) = &expected {
                reason = lease_reason(tip, expected.as_ref());
            } else if matches!(edit.kind, ReferenceEditKind::SymrefVerify) {
                reason = Some(RejectionReason::Exists);
            }
        } else {
            if expected_target.is_some() {
                return Err("direct HEAD commands require an old object ID".into());
            }
            requested_new = match edit.kind {
                ReferenceEditKind::Update | ReferenceEditKind::Create => resolve_reference_oid(
                    snapshot,
                    edit.new
                        .as_deref()
                        .ok_or("HEAD update requires a new value")?,
                )?,
                _ => None,
            };
            if matches!(edit.kind, ReferenceEditKind::Create) && requested_new.is_none() {
                return Err("create requires a nonzero new value".into());
            }
            if matches!(edit.kind, ReferenceEditKind::Delete) && expected == Some(None) {
                return Err("delete old value must not be zero".into());
            }
            if matches!(edit.kind, ReferenceEditKind::Create) {
                reason = Some(RejectionReason::Exists);
            } else if let Some(expected) = &expected {
                reason = lease_reason(tip, expected.as_ref());
            } else if matches!(edit.kind, ReferenceEditKind::Verify) {
                reason = lease_reason(tip, None);
            }
            if reason.is_none()
                && requested_new.as_ref().is_some_and(|new| {
                    !matches!(snapshot.objects.get(new), Some(Object::Commit(_)))
                })
            {
                reason = Some(RejectionReason::InvalidNew);
            }
            if !matches!(edit.kind, ReferenceEditKind::Verify) {
                if edit.no_deref || valid_id(before) {
                    if let Some(new) = &requested_new {
                        after = new.clone();
                    } else if reason.is_none() {
                        reason = Some(RejectionReason::RequiredHead);
                    }
                } else if tip != requested_new.as_ref() && reason.is_none() {
                    reason = Some(RejectionReason::CheckedOut);
                }
            }
        }
        if reason.is_none()
            && after != *before
            && !valid_id(&after)
            && repo.branch_unavailable_reason(&after)?.is_some()
        {
            reason = Some(RejectionReason::CheckedOut);
        }
        let rejection = reason.map(|reason| ReferenceRejection {
            reference: "HEAD".into(),
            new: requested_new,
            old: reported_old,
            reason,
        });
        Ok(Self { after, rejection })
    }
}
