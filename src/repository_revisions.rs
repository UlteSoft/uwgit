//! Reference-relative revision syntax bound to the caller's verified snapshot.
use super::*;

impl Repository {
    pub(super) fn checkout_history(&self) -> RepositoryResult<Vec<String>> {
        let path = self.metadata.join("checkouts.json");
        let metadata = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.to_string()),
            Ok(metadata) => metadata,
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_UPSTREAM_BYTES
        {
            return Err("checkout history must be a bounded regular file".into());
        }
        let bytes = read_regular(&path)?;
        let values: Vec<String> =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if values.len() > 4096
            || serde_json::to_vec(&values).map_err(|error| error.to_string())? != bytes
        {
            return Err("noncanonical or oversized checkout history".into());
        }
        for branch in &values {
            validate_head_identity(branch)?;
        }
        Ok(values)
    }
    pub(super) fn record_checkout(
        &self,
        previous: &[String],
        branch: &str,
    ) -> RepositoryResult<()> {
        let mut values: Vec<_> = previous.iter().rev().take(4095).cloned().collect();
        values.reverse();
        values.push(branch.into());
        self.atomic_write(&self.metadata.join("checkouts.json"), &serde_json::to_vec(&values).map_err(|error| error.to_string())?)
            .map_err(|error| format!("HEAD switch was published, but its local checkout history may be incomplete: {error}"))
    }
    pub fn previous_checkout_branch(&self, number: usize) -> RepositoryResult<String> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let branch = previous_branch(&snapshot, number)?;
        if !valid_id(&branch) && !snapshot.manifest.refs.contains_key(&branch) {
            return Err("previous checkout branch no longer exists".into());
        }
        Ok(branch)
    }
}

pub(super) fn upstream_tips(
    repo: &Repository,
    upstreams: &BTreeMap<String, Upstream>,
    tracking: &BTreeMap<String, String>,
) -> BTreeMap<String, RepositoryResult<String>> {
    upstreams
        .iter()
        .map(|(local, upstream)| {
            let expected = tracking.get(&format!("{}/{}", upstream.remote, upstream.branch));
            (
                local.clone(),
                crate::remote::snapshot_upstream_tip(repo, upstream, expected),
            )
        })
        .collect()
}

pub(super) fn previous_branch(snapshot: &Snapshot, number: usize) -> RepositoryResult<String> {
    if number == 0 {
        return Err("previous-checkout number must be positive".into());
    }
    snapshot
        .checkouts
        .iter()
        .rev()
        .nth(number - 1)
        .cloned()
        .ok_or_else(|| "previous checkout is absent from the native reflog".into())
}

pub(super) fn special_revision(
    snapshot: &Snapshot,
    revision: &str,
) -> RepositoryResult<Option<String>> {
    if revision == "@" {
        return snapshot_revision(snapshot, "HEAD").map(Some);
    }
    let Some((reference, ordinal)) = revision
        .strip_suffix('}')
        .and_then(|text| text.rsplit_once("@{"))
    else {
        return Ok(None);
    };
    if reference.contains("@{") {
        return Err("nested reference selectors are invalid".into());
    }
    if ordinal.eq_ignore_ascii_case("u") || ordinal.eq_ignore_ascii_case("upstream") {
        let local = if reference.is_empty() || reference == "HEAD" {
            &snapshot.manifest.head
        } else {
            reference.strip_prefix("refs/heads/").unwrap_or(reference)
        };
        validate_ref_name(local)?;
        return snapshot
            .upstream_tips
            .get(local)
            .ok_or_else(|| format!("branch {local:?} has no upstream"))?
            .clone()
            .map(Some);
    }
    if let Some(number) = ordinal.strip_prefix('-') {
        if !reference.is_empty() {
            return Err("previous checkout uses @{-N} without a reference prefix".into());
        }
        let number = number
            .parse::<usize>()
            .map_err(|_| "invalid previous-checkout number")?;
        return snapshot_revision(snapshot, &previous_branch(snapshot, number)?).map(Some);
    }
    if ordinal.is_empty() || !ordinal.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("this history has no wall-clock timestamps; reflog selectors require a nonnegative ordinal".into());
    }
    let number = ordinal
        .parse::<usize>()
        .map_err(|_| "reflog ordinal exceeds host size")?;
    let reference = if reference == "HEAD" {
        "HEAD".into()
    } else if reference.is_empty() {
        if valid_id(&snapshot.manifest.head) {
            "HEAD".into()
        } else {
            format!("refs/heads/{}", snapshot.manifest.head)
        }
    } else if reference.starts_with("refs/heads/") || reference.starts_with("refs/tags/") {
        reference.into()
    } else {
        let branch = snapshot.manifest.refs.contains_key(reference);
        let tag = snapshot.manifest.tags.contains_key(reference);
        match (branch, tag) {
            (true, false) => format!("refs/heads/{reference}"),
            (false, true) => format!("refs/tags/{reference}"),
            (true, true) => return Err("ambiguous reflog reference; qualify its namespace".into()),
            _ => return Err("reflog selection requires an existing local branch or tag".into()),
        }
    };
    // Confirm that this reference still exists. Deleted/recreated branches do
    // not inherit the earlier incarnation's ordinal history.
    snapshot_revision(snapshot, &reference)?;
    let mut remaining = number;
    if reference == "HEAD" && snapshot.head_reflog.is_empty() {
        return if number == 0 {
            snapshot_revision(snapshot, "HEAD").map(Some)
        } else {
            Err("historical HEAD log was not recorded by this older repository".into())
        };
    }
    let entries = if reference == "HEAD" && !snapshot.head_reflog.is_empty() {
        &snapshot.head_reflog
    } else {
        &snapshot.reflog
    };
    for entry in entries
        .iter()
        .rev()
        .filter(|entry| entry.reference == reference)
    {
        if let Some(id) = &entry.new {
            if remaining == 0 {
                return Ok(Some(id.clone()));
            }
            remaining -= 1;
        }
        if reference != "HEAD" && entry.old.is_none() {
            break;
        }
    }
    Err(format!(
        "reflog ordinal {number} is unavailable for {reference}"
    ))
}
