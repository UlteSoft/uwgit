//! Symbolic/unborn and detached HEAD without a synthetic branch. A complete
//! lowercase object ID cannot be a branch name, so the old one-line HEAD file
//! has an unambiguous extension that older clients reject closed.
use super::*;
pub(crate) fn is_detached_identity(identity: &str) -> bool {
    valid_id(identity)
}

pub(crate) fn validate_head_identity(identity: &str) -> RepositoryResult<()> {
    if valid_id(identity) {
        Ok(())
    } else {
        validate_ref_name(identity)
    }
}
pub(super) fn head_tip<'a>(
    identity: &'a String,
    refs: &'a BTreeMap<String, String>,
) -> Option<&'a String> {
    if valid_id(identity) {
        Some(identity)
    } else {
        refs.get(identity)
    }
}
impl Manifest {
    pub(super) fn tip(&self) -> Option<&String> {
        head_tip(&self.head, &self.refs)
    }
}
impl RepositoryState {
    pub fn tip(&self) -> Option<&String> {
        head_tip(&self.head, &self.branches)
    }
    pub fn detached(&self) -> bool {
        valid_id(&self.head)
    }
}
impl PendingOperation {
    pub fn matches_head_identity(&self, identity: &str) -> bool {
        identity == self.branch
            || (valid_id(&self.branch)
                && self
                    .prepared
                    .as_ref()
                    .is_some_and(|prepared| prepared.commit == identity))
    }
}
pub(super) fn decode_head_reflog(bytes: Option<&[u8]>) -> RepositoryResult<Vec<ReflogEntry>> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    if bytes.len() as u64 > MAX_PENDING_BYTES {
        return Err("HEAD reflog exceeds its size limit".into());
    }
    let entries: Vec<ReflogEntry> =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if entries.len() > 4096
        || serde_json::to_vec(&entries).map_err(|error| error.to_string())? != bytes
    {
        return Err("noncanonical or oversized HEAD reflog".into());
    }
    let mut previous: Option<u64> = None;
    for entry in &entries {
        if entry.reference != "HEAD"
            || entry.sequence == 0
            || entry.operation.is_empty()
            || previous.is_some_and(|old| old.checked_add(1) != Some(entry.sequence))
        {
            return Err("invalid HEAD reflog entry".into());
        }
        for id in entry.old.iter().chain(&entry.new) {
            require_id(id)?;
        }
        previous = Some(entry.sequence);
    }
    Ok(entries)
}

impl Repository {
    pub(super) fn read_head_reflog(&self) -> RepositoryResult<Vec<ReflogEntry>> {
        let path = self.metadata.join("head-reflog.json");
        let metadata = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.to_string()),
            Ok(metadata) => metadata,
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_PENDING_BYTES
        {
            return Err("HEAD reflog must be a bounded regular file".into());
        }
        let bytes = read_regular(&path)?;
        decode_head_reflog(Some(&bytes))
    }
    pub(super) fn record_head_event(
        &self,
        old: Option<String>,
        new: Option<String>,
        operation: &str,
    ) -> RepositoryResult<()> {
        let mut entries = self.read_head_reflog()?;
        if entries.last().is_some_and(|entry| {
            entry.old == old && entry.new == new && entry.operation == operation
        }) {
            return Ok(());
        }
        let sequence = entries
            .last()
            .map_or(Some(1), |entry| entry.sequence.checked_add(1))
            .ok_or("HEAD reflog sequence overflow")?;
        if entries.len() == 4096 {
            entries.remove(0);
        }
        entries.push(ReflogEntry {
            sequence,
            reference: "HEAD".into(),
            old,
            new,
            operation: operation.into(),
        });
        self.atomic_write(
            &self.metadata.join("head-reflog.json"),
            &serde_json::to_vec(&entries).map_err(|error| error.to_string())?,
        )
        .map_err(|error| {
            format!("HEAD publication completed, but its local reflog may be incomplete: {error}")
        })
    }
    pub fn detach_head(&self, revision: &str) -> RepositoryResult<String> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let id = snapshot_revision(&snapshot, revision)?;
        if snapshot.manifest.head != id {
            self.register_selected_branch(&id)?;
            self.atomic_write(&self.metadata.join("HEAD"), format!("{id}\n").as_bytes())?;
            self.record_reflog(
                "HEAD",
                snapshot.manifest.tip().cloned(),
                Some(id.clone()),
                "checkout-detach",
            )?;
            self.record_head_event(
                snapshot.manifest.tip().cloned(),
                Some(id.clone()),
                "checkout-detach",
            )?;
            self.record_checkout(&snapshot.checkouts, &snapshot.manifest.head)?;
        }
        Ok(id)
    }
    pub fn orphan_head(&self, branch: &str) -> RepositoryResult<()> {
        validate_ref_name(branch)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if snapshot.manifest.refs.contains_key(branch) {
            return Err("orphan branch already exists".into());
        }
        self.assert_branch_available(branch)?;
        self.register_selected_branch(branch)?;
        self.atomic_write(
            &self.metadata.join("HEAD"),
            format!("{branch}\n").as_bytes(),
        )?;
        self.record_reflog(
            "HEAD",
            snapshot.manifest.tip().cloned(),
            None,
            "checkout-orphan",
        )?;
        self.record_head_event(snapshot.manifest.tip().cloned(), None, "checkout-orphan")?;
        self.record_checkout(&snapshot.checkouts, &snapshot.manifest.head)
    }
    pub(super) fn write_detached_tip(
        &self,
        expected: &str,
        id: &str,
        operation: &str,
    ) -> RepositoryResult<()> {
        if self.current_branch()? != expected {
            return Err("detached HEAD changed before publication".into());
        }
        self.read_commit_id(id)?;
        self.register_selected_branch(id)?;
        self.atomic_write(&self.metadata.join("HEAD"), format!("{id}\n").as_bytes())?;
        self.record_reflog("HEAD", Some(expected.into()), Some(id.into()), operation)?;
        self.record_head_event(Some(expected.into()), Some(id.into()), operation)
    }
}

pub(super) fn check_pending_head(
    snapshot: &Snapshot,
    pending: &PendingOperation,
) -> RepositoryResult<()> {
    if pending.matches_head_identity(&snapshot.manifest.head) {
        Ok(())
    } else {
        Err("HEAD identity changed since the pending operation was recorded".into())
    }
}
