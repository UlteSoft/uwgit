//! Reference filtering and names are derived from one verified native DAG.
use super::*;

#[derive(Default)]
pub struct ReferenceFilter {
    pub contains: Vec<String>,
    pub no_contains: Vec<String>,
    pub merged: Vec<String>,
    pub no_merged: Vec<String>,
    pub points_at: Vec<String>,
}

fn resolve_commits(snapshot: &Snapshot, values: &[String]) -> RepositoryResult<BTreeSet<String>> {
    values
        .iter()
        .map(|value| snapshot_revision(snapshot, value))
        .collect()
}

fn ancestor_union(
    snapshot: &Snapshot,
    roots: BTreeSet<String>,
) -> RepositoryResult<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    let mut pending: Vec<_> = roots.into_iter().collect();
    while let Some(id) = pending.pop() {
        if seen.insert(id.clone()) {
            let Some(Object::Commit(commit)) = snapshot.objects.get(&id) else {
                return Err(format!("missing native commit {id} in reference query"));
            };
            pending.extend(commit.parents.iter().cloned());
        }
    }
    Ok(seen)
}

fn short_name(snapshot: &Snapshot, name: &str) -> String {
    let short = name
        .strip_prefix("refs/heads/")
        .or_else(|| name.strip_prefix("refs/tags/"))
        .or_else(|| name.strip_prefix("refs/remotes/"))
        .unwrap_or(name);
    let refs = usize::from(snapshot.manifest.refs.contains_key(short))
        + usize::from(snapshot.manifest.tags.contains_key(short))
        + usize::from(snapshot.tracking.contains_key(short));
    let exists = name
        .strip_prefix("refs/heads/")
        .is_some_and(|name| snapshot.manifest.refs.contains_key(name))
        || name
            .strip_prefix("refs/tags/")
            .is_some_and(|name| snapshot.manifest.tags.contains_key(name))
        || name
            .strip_prefix("refs/remotes/")
            .is_some_and(|name| snapshot.tracking.contains_key(name));
    let prefix = (4..64).contains(&short.len())
        && short
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let ambiguous_object = prefix
        && snapshot
            .objects
            .iter()
            .any(|(id, object)| id.starts_with(short) && matches!(object, Object::Commit(_)));
    if matches!(short, "HEAD" | "@")
        || short.starts_with("refs/")
        || valid_id(short)
        || refs > usize::from(exists)
        || ambiguous_object
    {
        name.into()
    } else {
        short.into()
    }
}

impl Repository {
    /// Return the complete name context and the selected ref names together.
    /// Resolving every filter before selection prevents an empty candidate set
    /// from hiding a bad revision. No index or working copy is inspected.
    pub fn query_refs_selected(
        &self,
        filter: &ReferenceFilter,
    ) -> RepositoryResult<(QueryRefs, BTreeSet<String>)> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let contains = resolve_commits(&snapshot, &filter.contains)?;
        let no_contains = resolve_commits(&snapshot, &filter.no_contains)?;
        let merged = ancestor_union(&snapshot, resolve_commits(&snapshot, &filter.merged)?)?;
        let no_merged = ancestor_union(&snapshot, resolve_commits(&snapshot, &filter.no_merged)?)?;
        let points_at = filter
            .points_at
            .iter()
            .map(|value| plumbing_storage::snapshot_object_id(&snapshot, value))
            .collect::<RepositoryResult<BTreeSet<_>>>()?;
        let mut refs = Vec::new();
        for (prefix, names) in [
            ("refs/heads", &snapshot.manifest.refs),
            ("refs/tags", &snapshot.manifest.tags),
            ("refs/remotes", &snapshot.tracking),
        ] {
            for (name, id) in names {
                let object = query_object(&snapshot, id)?;
                let local = prefix == "refs/heads";
                refs.push(QueryRef {
                    name: format!("{prefix}/{name}"),
                    id: id.clone(),
                    kind: object.kind,
                    byte_len: object.byte_len,
                    stored_byte_len: object.stored_byte_len,
                    current: local && name == &snapshot.manifest.head,
                    upstream: if local {
                        snapshot.upstreams.get(name).cloned()
                    } else {
                        None
                    },
                });
            }
        }
        refs.sort_by(|a, b| a.name.cmp(&b.name));
        let mut selected = BTreeSet::new();
        let mut tested = BTreeMap::new();
        for row in &refs {
            let accepted = if let Some(accepted) = tested.get(&row.id) {
                *accepted
            } else {
                let mut accepted = (points_at.is_empty() || points_at.contains(&row.id))
                    && (filter.merged.is_empty() || merged.contains(&row.id))
                    && !no_merged.contains(&row.id);
                if accepted && (!contains.is_empty() || !no_contains.is_empty()) {
                    let history = ancestors(&row.id, &snapshot.objects)?;
                    accepted = (contains.is_empty() || !history.is_disjoint(&contains))
                        && history.is_disjoint(&no_contains);
                }
                tested.insert(row.id.clone(), accepted);
                accepted
            };
            if accepted {
                selected.insert(row.name.clone());
            }
        }
        let mut short_names = BTreeMap::new();
        for row in &refs {
            short_names.insert(row.name.clone(), short_name(&snapshot, &row.name));
            if let Some(upstream) = &row.upstream {
                let name = format!("refs/remotes/{}/{}", upstream.remote, upstream.branch);
                short_names.insert(name.clone(), short_name(&snapshot, &name));
            }
        }
        Ok((
            QueryRefs {
                schema_version: 1,
                head: snapshot.manifest.head.clone(),
                head_tip: snapshot.manifest.tip().cloned(),
                head_object: snapshot
                    .manifest
                    .tip()
                    .map(|id| query_object(&snapshot, id))
                    .transpose()?,
                refs,
                short_names,
            },
            selected,
        ))
    }
}
