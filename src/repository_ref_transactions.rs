//! Shared-lock reference transactions. A durable commit decision is rolled
//! forward before any later locked operation can observe the repository.
use super::*;

const JOURNAL: &str = "ref-transaction.json";
const MAX_TRANSACTION_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_REFERENCE_EDITS: usize = 4096;

#[derive(Clone, Copy)]
pub enum ReferenceEditKind {
    Update,
    Create,
    Delete,
    Verify,
}

pub struct ReferenceEdit {
    pub kind: ReferenceEditKind,
    pub reference: String,
    pub new: Option<String>,
    pub expected: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RejectionReason {
    Missing,
    Exists,
    IncorrectOld,
    InvalidNew,
    NameConflict,
    CheckedOut,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "reference does not exist",
            Self::Exists => "reference already exists",
            Self::IncorrectOld => "incorrect old value provided",
            Self::InvalidNew => "invalid new value provided",
            Self::NameConflict => "refname conflict",
            Self::CheckedOut => "reference is checked out in a worktree",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceRejection {
    pub reference: String,
    pub new: Option<String>,
    pub old: Option<String>,
    reason: RejectionReason,
}

impl std::fmt::Display for ReferenceRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
        write!(
            formatter,
            "rejected {} {} {} {}",
            self.reference,
            self.new.as_deref().unwrap_or(ZERO),
            self.old.as_deref().unwrap_or(ZERO),
            self.reason
        )
    }
}

pub struct ReferenceCommitOutcome {
    pub updates: Vec<Value>,
    pub rejections: Vec<ReferenceRejection>,
}

struct ResolvedEdit {
    change: ReferenceChange,
    expected: Option<Option<String>>,
    requested_new: Option<String>,
}

impl ResolvedEdit {
    fn reject(&self, reason: RejectionReason) -> ReferenceRejection {
        ReferenceRejection {
            reference: self.change.reference.clone(),
            new: self.requested_new.clone(),
            old: self.expected.clone().flatten(),
            reason,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceState {
    pub(super) refs: BTreeMap<String, String>,
    pub(super) tags: BTreeMap<String, String>,
    pub(super) upstreams: Option<Vec<u8>>,
    pub(super) reflog: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceChange {
    reference: String,
    old: Option<String>,
    new: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferencePlan {
    version: u32,
    message: String,
    before: ReferenceState,
    changes: Vec<ReferenceChange>,
}

pub struct PreparedReferences<'a> {
    repo: &'a Repository,
    _lock: WriteLock,
    plan: ReferencePlan,
    rejections: Vec<ReferenceRejection>,
}

fn reference_parts(reference: &str) -> RepositoryResult<(&str, &str)> {
    let (namespace, name) = reference
        .strip_prefix("refs/heads/")
        .map(|name| ("refs", name))
        .or_else(|| {
            reference
                .strip_prefix("refs/tags/")
                .map(|name| ("tags", name))
        })
        .ok_or("update-ref requires refs/heads/NAME or refs/tags/NAME")?;
    validate_ref_name(name)?;
    Ok((namespace, name))
}

fn resolve_reference_edit(
    snapshot: &Snapshot,
    edit: &ReferenceEdit,
) -> RepositoryResult<ResolvedEdit> {
    let (namespace, name) = reference_parts(&edit.reference)?;
    let refs = if namespace == "refs" {
        &snapshot.manifest.refs
    } else {
        &snapshot.manifest.tags
    };
    let old = refs.get(name).cloned();
    let resolve = |value: &str| -> RepositoryResult<Option<String>> {
        if value.is_empty() || (value.len() == 64 && value.bytes().all(|byte| byte == b'0')) {
            return Ok(None);
        }
        // A syntactically valid full ID can name an absent or wrong-type object.
        // Classify that at prepare, separately from an unparseable revision.
        if valid_id(value) {
            return Ok(Some(value.into()));
        }
        snapshot_revision(snapshot, value).map(Some)
    };
    let mut expected = edit.expected.as_deref().map(resolve).transpose()?;
    let requested_new = match edit.kind {
        ReferenceEditKind::Update | ReferenceEditKind::Create => resolve(
            edit.new
                .as_deref()
                .ok_or("reference update needs a new value")?,
        )?,
        _ => None,
    };
    match edit.kind {
        ReferenceEditKind::Create => {
            if requested_new.is_none() {
                return Err("create requires a nonzero new value".into());
            }
            expected = Some(None);
        }
        ReferenceEditKind::Delete if expected == Some(None) => {
            return Err("delete old value must not be zero".into())
        }
        ReferenceEditKind::Verify if expected.is_none() => expected = Some(None),
        _ => {}
    }
    let new = if matches!(edit.kind, ReferenceEditKind::Verify) {
        old.clone()
    } else {
        requested_new.clone()
    };
    Ok(ResolvedEdit {
        change: ReferenceChange {
            reference: edit.reference.clone(),
            old,
            new,
        },
        expected,
        requested_new,
    })
}

fn conflicting_creations(
    snapshot: &Snapshot,
    edits: &[ResolvedEdit],
    reasons: &[Option<RejectionReason>],
) -> RepositoryResult<BTreeSet<usize>> {
    let mut refs = snapshot.manifest.refs.clone();
    let mut tags = snapshot.manifest.tags.clone();
    validate_prefixes(&refs)?;
    validate_prefixes(&tags)?;
    let mut created = BTreeMap::new();
    for (index, edit) in edits.iter().enumerate() {
        if reasons[index].is_some() {
            continue;
        }
        let (namespace, name) = reference_parts(&edit.change.reference)?;
        let target = if namespace == "refs" {
            &mut refs
        } else {
            &mut tags
        };
        if let Some(new) = &edit.change.new {
            target.insert(name.into(), new.clone());
            if edit.change.old.is_none() {
                created.insert(edit.change.reference.as_str(), index);
            }
        } else {
            target.remove(name);
        }
    }
    let mut conflicts = BTreeSet::new();
    for (namespace, refs) in [("heads", refs), ("tags", tags)] {
        for name in refs.keys() {
            for (offset, _) in name.match_indices('/') {
                let ancestor = &name[..offset];
                if !refs.contains_key(ancestor) {
                    continue;
                }
                for conflicted in [name.as_str(), ancestor] {
                    if let Some(index) =
                        created.get(format!("refs/{namespace}/{conflicted}").as_str())
                    {
                        conflicts.insert(*index);
                    }
                }
            }
        }
    }
    Ok(conflicts)
}

fn optional_file(path: &Path) -> RepositoryResult<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_regular(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(
            "inspect reference transaction metadata",
            path,
            error,
        )),
    }
}

fn validate_prefixes(refs: &BTreeMap<String, String>) -> RepositoryResult<()> {
    for name in refs.keys() {
        validate_ref_name(name)?;
        for (offset, _) in name.match_indices('/') {
            if refs.contains_key(&name[..offset]) {
                return Err(format!("reference file/directory collision: {name}"));
            }
        }
    }
    Ok(())
}

impl ReferenceState {
    fn map(&self, namespace: &str) -> &BTreeMap<String, String> {
        if namespace == "refs" {
            &self.refs
        } else {
            &self.tags
        }
    }

    fn map_mut(&mut self, namespace: &str) -> &mut BTreeMap<String, String> {
        if namespace == "refs" {
            &mut self.refs
        } else {
            &mut self.tags
        }
    }
}

impl ReferencePlan {
    fn after(&self) -> RepositoryResult<ReferenceState> {
        if self.version != 1 || self.message.is_empty() || self.changes.len() > MAX_REFERENCE_EDITS
        {
            return Err("invalid reference transaction version, message or size".into());
        }
        validate_prefixes(&self.before.refs)?;
        validate_prefixes(&self.before.tags)?;
        let mut after = self.before.clone();
        let mut seen = BTreeSet::new();
        let mut upstreams =
            decode_upstreams_optional(self.before.upstreams.as_deref(), &self.before.refs)?;
        let mut reflog = decode_reflog(self.before.reflog.as_deref().unwrap_or_default())?;
        let mut changed = false;
        for change in &self.changes {
            let (namespace, name) = reference_parts(&change.reference)?;
            if !seen.insert(&change.reference)
                || self.before.map(namespace).get(name) != change.old.as_ref()
            {
                return Err("duplicate reference or inconsistent old value in transaction".into());
            }
            for id in change.old.iter().chain(&change.new) {
                require_id(id)?;
            }
            if change.old == change.new {
                continue;
            }
            changed = true;
            if let Some(new) = &change.new {
                after.map_mut(namespace).insert(name.into(), new.clone());
            } else {
                after.map_mut(namespace).remove(name);
                if namespace == "refs" {
                    upstreams.remove(name);
                }
            }
            let sequence = u64::try_from(reflog.len())
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or("reflog sequence overflow")?;
            reflog.push(ReflogEntry {
                sequence,
                reference: change.reference.clone(),
                old: change.old.clone(),
                new: change.new.clone(),
                operation: self.message.clone(),
            });
        }
        validate_prefixes(&after.refs)?;
        validate_prefixes(&after.tags)?;
        if upstreams
            != decode_upstreams_optional(self.before.upstreams.as_deref(), &self.before.refs)?
        {
            after.upstreams = Some(encode_upstreams(&upstreams)?);
        }
        if changed {
            let mut bytes = Vec::new();
            for entry in reflog {
                serde_json::to_writer(&mut bytes, &entry).map_err(|error| error.to_string())?;
                bytes.push(b'\n');
            }
            after.reflog = Some(bytes);
        }
        Ok(after)
    }

    fn bytes(&self) -> RepositoryResult<Vec<u8>> {
        self.after()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
            return Err("reference transaction exceeds 64 MiB".into());
        }
        Ok(bytes)
    }
}

impl Repository {
    pub fn prepare_reference_edits<'a>(
        &'a self,
        edits: &[ReferenceEdit],
        message: &str,
    ) -> RepositoryResult<PreparedReferences<'a>> {
        self.prepare_reference_batch(edits, message, false)
    }

    pub fn prepare_reference_batch<'a>(
        &'a self,
        edits: &[ReferenceEdit],
        message: &str,
        allow_failures: bool,
    ) -> RepositoryResult<PreparedReferences<'a>> {
        if edits.len() > MAX_REFERENCE_EDITS || message.is_empty() {
            return Err("reference transaction needs a message and at most 4096 edits".into());
        }
        let lock = self.lock()?;
        let snapshot = self.snapshot()?;
        // Metadata damage is fatal even if every requested branch is rejected.
        linked_worktrees::has_entries(&self.common_metadata)?;
        let mut names = BTreeSet::new();
        let mut resolved = Vec::new();
        for edit in edits {
            if !names.insert(&edit.reference) {
                return Err("duplicate reference in transaction".into());
            }
            resolved.push(resolve_reference_edit(&snapshot, edit)?);
        }
        let mut reasons = Vec::new();
        for edit in &resolved {
            reasons.push(self.reference_rejection_reason(&snapshot, edit)?);
        }
        // Resolve final namespace conflicts after dropping failed leases and
        // protected branches. Both mutually conflicting new names are rejected;
        // an existing reference keeps its valid update and wins over a new name.
        for index in conflicting_creations(&snapshot, &resolved, &reasons)? {
            reasons[index] = Some(RejectionReason::NameConflict);
        }
        let mut changes = Vec::new();
        let mut rejections = Vec::new();
        for (edit, reason) in resolved.into_iter().zip(reasons) {
            if let Some(reason) = reason {
                let rejection = edit.reject(reason);
                if !allow_failures {
                    return Err(rejection.to_string());
                }
                rejections.push(rejection);
            } else {
                changes.push(edit.change);
            }
        }
        rejections.sort_by(|left, right| left.reference.cmp(&right.reference));
        let plan = ReferencePlan {
            version: 1,
            message: message.into(),
            before: ReferenceState {
                refs: snapshot.manifest.refs,
                tags: snapshot.manifest.tags,
                upstreams: optional_file(&self.common_metadata.join("upstreams.json"))?,
                reflog: optional_file(&self.common_metadata.join("reflog"))?,
            },
            changes,
        };
        self.validate_reference_plan(&plan)?;
        plan.bytes()?;
        Ok(PreparedReferences {
            repo: self,
            _lock: lock,
            plan,
            rejections,
        })
    }

    fn reference_rejection_reason(
        &self,
        snapshot: &Snapshot,
        edit: &ResolvedEdit,
    ) -> RepositoryResult<Option<RejectionReason>> {
        if let Some(expected) = &edit.expected {
            if expected != &edit.change.old {
                return Ok(Some(if edit.change.old.is_none() {
                    RejectionReason::Missing
                } else if expected.is_none() {
                    RejectionReason::Exists
                } else {
                    RejectionReason::IncorrectOld
                }));
            }
        }
        if edit
            .requested_new
            .as_ref()
            .is_some_and(|new| !matches!(snapshot.objects.get(new), Some(Object::Commit(_))))
        {
            return Ok(Some(RejectionReason::InvalidNew));
        }
        let (namespace, name) = reference_parts(&edit.change.reference)?;
        if edit.change.old != edit.change.new
            && namespace == "refs"
            && (name == snapshot.manifest.head || self.branch_unavailable_reason(name)?.is_some())
        {
            return Ok(Some(RejectionReason::CheckedOut));
        }
        Ok(None)
    }

    fn validate_reference_plan(&self, plan: &ReferencePlan) -> RepositoryResult<ReferenceState> {
        let after = plan.after()?;
        // Disk refs/upstreams/reflog may be between writes during recovery.
        // Verify the complete immutable store and other metadata using the saved
        // preimage, then independently verify the resulting reference graph.
        let snapshot = self.snapshot_with_reference_state(Some(&plan.before))?;
        let manifest = Manifest {
            format: manifest_format(&snapshot.manifest.head, &after.tags, &snapshot.objects),
            head: snapshot.manifest.head.clone(),
            refs: after.refs.clone(),
            tags: after.tags.clone(),
        };
        validate_snapshot(&manifest, &snapshot.objects)?;
        for change in &plan.changes {
            let (namespace, name) = reference_parts(&change.reference)?;
            if change.old != change.new && namespace == "refs" {
                if name == snapshot.manifest.head {
                    return Err(
                        "update-ref refuses the checked-out branch; use commit or reset".into(),
                    );
                }
                self.assert_branch_available(name)?;
            }
        }
        Ok(after)
    }

    fn check_reference_preimages(
        &self,
        plan: &ReferencePlan,
        after: &ReferenceState,
    ) -> RepositoryResult<()> {
        for namespace in ["refs", "tags"] {
            let current = self.read_named_refs(namespace, namespace == "tags")?;
            let before = plan.before.map(namespace);
            let after = after.map(namespace);
            for name in before.keys().chain(after.keys()).chain(current.keys()) {
                let actual = current.get(name);
                if actual != before.get(name) && actual != after.get(name) {
                    return Err(format!("reference {namespace}/{name} differs from both transaction images; restore it before recovery"));
                }
            }
        }
        for (name, before, after) in [
            ("upstreams.json", &plan.before.upstreams, &after.upstreams),
            ("reflog", &plan.before.reflog, &after.reflog),
        ] {
            let actual = optional_file(&self.common_metadata.join(name))?;
            if &actual != before && &actual != after {
                return Err(format!(
                    "{name} differs from both transaction images; restore it before recovery"
                ));
            }
        }
        Ok(())
    }

    fn apply_reference_plan(
        &self,
        plan: &ReferencePlan,
        after: &ReferenceState,
        mut checkpoint: impl FnMut() -> RepositoryResult<()>,
    ) -> RepositoryResult<()> {
        // Check every preimage before changing anything, including unrelated
        // refs and the exact shared log/config bytes.
        self.check_reference_preimages(plan, after)?;
        if after.upstreams != plan.before.upstreams {
            self.atomic_write(
                &self.common_metadata.join("upstreams.json"),
                after
                    .upstreams
                    .as_deref()
                    .ok_or("missing resulting upstream metadata")?,
            )?;
            checkpoint()?;
        }
        // Remove deletions first, allowing atomic rename-like a -> a/b batches.
        for change in &plan.changes {
            if change.new.is_some() || change.old == change.new {
                continue;
            }
            let (namespace, name) = reference_parts(&change.reference)?;
            let root = self.common_metadata.join(namespace);
            let path = root.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() => {} // a/b already published
                Ok(_) => {
                    fs::remove_file(&path)
                        .map_err(|error| io_error("delete transaction reference", &path, error))?;
                    sync_directory(path.parent().ok_or("reference has no parent")?)?;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        || error.kind() == std::io::ErrorKind::NotADirectory => {}
                Err(error) => return Err(io_error("inspect transaction deletion", &path, error)),
            }
            let mut parent = path
                .parent()
                .ok_or("reference has no parent")?
                .to_path_buf();
            while parent != root {
                match fs::remove_dir(&parent) {
                    Ok(()) => {
                        parent = parent
                            .parent()
                            .ok_or("reference cleanup escaped namespace")?
                            .to_path_buf();
                        sync_directory(&parent)?;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound
                                | std::io::ErrorKind::NotADirectory
                                | std::io::ErrorKind::DirectoryNotEmpty
                        ) =>
                    {
                        break
                    }
                    Err(error) => {
                        return Err(io_error("clean transaction directory", &parent, error))
                    }
                }
            }
            checkpoint()?;
        }
        for change in &plan.changes {
            let Some(new) = &change.new else {
                continue;
            };
            if change.old == change.new {
                continue;
            }
            let (namespace, name) = reference_parts(&change.reference)?;
            let mut parent = self.common_metadata.clone();
            for component in
                std::iter::once(namespace).chain(name.split('/').take(name.split('/').count() - 1))
            {
                let next = parent.join(component);
                match fs::create_dir(&next) {
                    Ok(()) => sync_directory(&parent)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        require_directory(&next)?
                    }
                    Err(error) => {
                        return Err(io_error(
                            "create transaction reference directory",
                            &next,
                            error,
                        ))
                    }
                }
                parent = next;
            }
            self.atomic_write(
                &self.common_metadata.join(namespace).join(name),
                format!("{new}\n").as_bytes(),
            )?;
            checkpoint()?;
        }
        if after.reflog != plan.before.reflog {
            self.atomic_write(
                &self.common_metadata.join("reflog"),
                after.reflog.as_deref().ok_or("missing resulting reflog")?,
            )?;
            checkpoint()?;
        }
        Ok(())
    }

    fn clear_reference_transaction(&self) -> RepositoryResult<()> {
        fs::remove_file(self.common_metadata.join(JOURNAL)).map_err(|error| error.to_string())?;
        sync_directory(&self.common_metadata)
    }

    pub(super) fn recover_reference_transaction(&self) -> RepositoryResult<()> {
        let path = self.common_metadata.join(JOURNAL);
        let metadata = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error("inspect reference transaction", &path, error)),
            Ok(metadata) => metadata,
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_TRANSACTION_BYTES
        {
            return Err("reference transaction must be a bounded regular file".into());
        }
        let bytes = read_regular(&path)?;
        let plan: ReferencePlan = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid reference transaction: {error}"))?;
        if plan.bytes()? != bytes {
            return Err("noncanonical reference transaction".into());
        }
        let result = (|| {
            let after = self.validate_reference_plan(&plan)?;
            self.apply_reference_plan(&plan, &after, || Ok(()))?;
            self.clear_reference_transaction()
        })();
        result.map_err(|error| format!("committed reference transaction requires recovery; no later operation may proceed: {error}"))
    }
}

impl PreparedReferences<'_> {
    pub fn commit(self) -> RepositoryResult<ReferenceCommitOutcome> {
        let after = self.plan.after()?;
        let reports = self.plan.changes.iter().map(|change| json!({"reference":change.reference,"old":change.old,"new":change.new,"updated":change.old != change.new})).collect();
        if self
            .plan
            .changes
            .iter()
            .all(|change| change.old == change.new)
        {
            return Ok(ReferenceCommitOutcome {
                updates: reports,
                rejections: self.rejections,
            });
        }
        self.repo.check_reference_preimages(&self.plan, &after)?;
        self.repo.atomic_write(&self.repo.common_metadata.join(JOURNAL), &self.plan.bytes()?).map_err(|error| format!("reference commit decision may be durable; inspect or retry a locked query to recover: {error}"))?;
        self.repo.apply_reference_plan(&self.plan, &after, || Ok(())).and_then(|()| self.repo.clear_reference_transaction()).map_err(|error| format!("reference transaction is committed and may be partially installed; a locked query will finish recovery: {error}"))?;
        Ok(ReferenceCommitOutcome {
            updates: reports,
            rejections: self.rejections,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(unique_name("uwgit-ref-recovery"));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn edit(kind: ReferenceEditKind, reference: &str, new: Option<&str>) -> ReferenceEdit {
        ReferenceEdit {
            kind,
            reference: reference.into(),
            new: new.map(str::to_owned),
            expected: None,
        }
    }
    fn fixture(temp: &Temp) -> (Repository, ReferencePlan, ReferenceState) {
        let repo = Repository::init(temp.0.join("repo")).unwrap();
        let first = repo.commit(WASM_HEADER, "first").unwrap();
        let second = repo
            .commit(&[WASM_HEADER.as_slice(), &[0, 2, 0, 1]].concat(), "second")
            .unwrap();
        repo.create_branch("topic", &first).unwrap();
        repo.create_branch("nested/old", &first).unwrap();
        // A deleted branch must not leave an orphaned upstream association,
        // even when a crash occurs between config and reference publication.
        repo.atomic_write(
            &repo.common_metadata.join("upstreams.json"),
            &encode_upstreams(&BTreeMap::from([(
                "topic".into(),
                Upstream {
                    remote: "origin".into(),
                    branch: "topic".into(),
                },
            )]))
            .unwrap(),
        )
        .unwrap();
        let prepared = repo
            .prepare_reference_edits(
                &[
                    edit(
                        ReferenceEditKind::Create,
                        "refs/heads/topic/child",
                        Some(&second),
                    ),
                    edit(ReferenceEditKind::Delete, "refs/heads/topic", None),
                    edit(
                        ReferenceEditKind::Create,
                        "refs/heads/nested",
                        Some(&second),
                    ),
                    edit(ReferenceEditKind::Delete, "refs/heads/nested/old", None),
                    edit(
                        ReferenceEditKind::Create,
                        "refs/tags/release/v1",
                        Some(&first),
                    ),
                ],
                "recover atomic batch",
            )
            .unwrap();
        let plan = prepared.plan.clone();
        let after = plan.after().unwrap();
        drop(prepared);
        (repo, plan, after)
    }
    fn persist(repo: &Repository, plan: &ReferencePlan) {
        repo.atomic_write(&repo.common_metadata.join(JOURNAL), &plan.bytes().unwrap())
            .unwrap();
    }

    #[test]
    fn every_write_prefix_recovers_before_queries_and_records_each_change_once() {
        // Config, two deletions, three writes, and the final shared reflog.
        for stop in 0..=7 {
            let temp = Temp::new();
            let (repo, plan, after) = fixture(&temp);
            persist(&repo, &plan);
            if stop > 0 {
                let mut writes = 0;
                let result = repo.apply_reference_plan(&plan, &after, || {
                    writes += 1;
                    if writes == stop {
                        Err("injected interruption".into())
                    } else {
                        Ok(())
                    }
                });
                assert!(result.is_err(), "missing write prefix {stop}");
            }
            // A normal reader takes the shared lock and must finish recovery.
            let refs = repo.branches().unwrap();
            assert_eq!(refs, after.refs);
            assert_eq!(repo.read_named_refs("tags", true).unwrap(), after.tags);
            assert_eq!(
                optional_file(&repo.common_metadata.join("upstreams.json")).unwrap(),
                after.upstreams
            );
            assert_eq!(
                optional_file(&repo.common_metadata.join("reflog")).unwrap(),
                after.reflog
            );
            assert!(!repo.common_metadata.join(JOURNAL).exists());
            let before_count = decode_reflog(plan.before.reflog.as_deref().unwrap())
                .unwrap()
                .len();
            assert_eq!(
                repo.read_reflog().unwrap().len(),
                before_count + plan.changes.len()
            );
            // Recreating the same durable decision after full publication is
            // idempotent and cannot append the generation a second time.
            persist(&repo, &plan);
            repo.branches().unwrap();
            assert_eq!(
                optional_file(&repo.common_metadata.join("reflog")).unwrap(),
                after.reflog
            );
        }
    }

    #[test]
    fn later_third_images_are_rejected_before_any_recovery_write() {
        for target in ["ref", "reflog", "upstreams", "unrelated"] {
            let temp = Temp::new();
            let (repo, plan, after) = fixture(&temp);
            persist(&repo, &plan);
            let second = plan.before.refs["main"].clone();
            let path = match target {
                "ref" => repo.common_metadata.join("refs/topic"),
                "reflog" => repo.common_metadata.join("reflog"),
                "upstreams" => repo.common_metadata.join("upstreams.json"),
                _ => repo.common_metadata.join("refs/later"),
            };
            let bytes = match target {
                "reflog" => b"later log bytes".to_vec(),
                "upstreams" => b"later config bytes".to_vec(),
                _ => format!("{second}\n").into_bytes(),
            };
            fs::write(&path, &bytes).unwrap();
            assert!(repo.branches().is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert!(!repo.common_metadata.join("refs/topic/child").exists());
            assert!(!repo.common_metadata.join("tags/release/v1").exists());
            assert_eq!(
                fs::read(repo.common_metadata.join(JOURNAL)).unwrap(),
                plan.bytes().unwrap()
            );
            assert!(repo.check_reference_preimages(&plan, &after).is_err());
        }
    }

    #[test]
    fn malformed_duplicate_and_missing_object_decisions_fail_closed() {
        for mutation in ["duplicate", "old", "target", "noncanonical", "object"] {
            let temp = Temp::new();
            let (repo, mut plan, _) = fixture(&temp);
            match mutation {
                "duplicate" => plan.changes.push(plan.changes[0].clone()),
                "old" => plan.changes[0].old = Some(plan.before.refs["main"].clone()),
                "target" => plan.changes[0].new = Some("f".repeat(64)),
                "object" => {
                    fs::write(
                        repo.common_metadata
                            .join("objects")
                            .join(&plan.before.refs["main"]),
                        b"corrupt object",
                    )
                    .unwrap();
                }
                _ => {}
            }
            let mut bytes = serde_json::to_vec(&plan).unwrap();
            if mutation == "noncanonical" {
                bytes.push(b'\n');
            }
            repo.atomic_write(&repo.common_metadata.join(JOURNAL), &bytes)
                .unwrap();
            let refs = repo.read_refs().unwrap();
            let log = optional_file(&repo.common_metadata.join("reflog")).unwrap();
            assert!(repo.branches().is_err(), "{mutation}");
            assert_eq!(repo.read_refs().unwrap(), refs);
            assert_eq!(
                optional_file(&repo.common_metadata.join("reflog")).unwrap(),
                log
            );
            assert!(repo.common_metadata.join(JOURNAL).exists());
        }
    }

    #[test]
    fn unprepared_and_aborted_guards_have_no_durable_decision() {
        let temp = Temp::new();
        let (repo, plan, _) = fixture(&temp);
        let prepared = repo
            .prepare_reference_edits(
                &[edit(
                    ReferenceEditKind::Create,
                    "refs/tags/uncommitted",
                    Some(&plan.before.refs["main"]),
                )],
                "abort me",
            )
            .unwrap();
        assert!(repo.common_metadata.join("write.lock").exists());
        assert!(!repo.common_metadata.join(JOURNAL).exists());
        drop(prepared);
        assert!(!repo.common_metadata.join("write.lock").exists());
        assert!(!repo
            .read_named_refs("tags", true)
            .unwrap()
            .contains_key("uncommitted"));
    }

    #[test]
    fn interrupted_partial_batch_recovers_only_the_frozen_accepted_subset() {
        // Upstream cleanup, one deletion, two writes, and the shared log.
        for stop in 0..=5 {
            let temp = Temp::new();
            let (repo, original, _) = fixture(&temp);
            let first = &original.before.refs["topic"];
            let second = &original.before.refs["main"];
            let mut missing = edit(ReferenceEditKind::Update, "refs/heads/missing", Some(first));
            missing.expected = Some(second.clone());
            let prepared = repo
                .prepare_reference_batch(
                    &[
                        edit(ReferenceEditKind::Delete, "refs/heads/topic", None),
                        edit(
                            ReferenceEditKind::Create,
                            "refs/heads/topic/child",
                            Some(second),
                        ),
                        edit(
                            ReferenceEditKind::Create,
                            "refs/tags/release/partial",
                            Some(first),
                        ),
                        edit(ReferenceEditKind::Update, "refs/heads/main", Some(first)),
                        missing,
                    ],
                    "recover partial batch",
                    true,
                )
                .unwrap();
            assert_eq!(prepared.rejections.len(), 2);
            assert_eq!(prepared.plan.changes.len(), 3);
            let plan = prepared.plan.clone();
            let after = plan.after().unwrap();
            drop(prepared);
            persist(&repo, &plan);
            if stop > 0 {
                let mut count = 0;
                assert!(repo
                    .apply_reference_plan(&plan, &after, || {
                        count += 1;
                        if count == stop {
                            Err("injected interrupted partial publication".into())
                        } else {
                            Ok(())
                        }
                    })
                    .is_err());
            }
            assert_eq!(repo.branches().unwrap(), after.refs);
            assert_eq!(repo.read_named_refs("tags", true).unwrap(), after.tags);
            assert_eq!(repo.read_refs().unwrap().get("main"), Some(second));
            assert!(!repo.read_refs().unwrap().contains_key("missing"));
            let before = decode_reflog(plan.before.reflog.as_deref().unwrap()).unwrap();
            let log = repo.read_reflog().unwrap();
            assert_eq!(log.len(), before.len() + 3);
            assert!(log[before.len()..].iter().all(|entry| !matches!(
                entry.reference.as_str(),
                "refs/heads/main" | "refs/heads/missing"
            )));
            persist(&repo, &plan);
            repo.branches().unwrap();
            assert_eq!(repo.read_reflog().unwrap(), log);
        }
    }
}
