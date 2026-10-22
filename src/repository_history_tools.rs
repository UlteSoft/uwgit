//! Original-byte file summaries and exact transition comparison of series.
use super::*;
type FileIds = BTreeMap<Option<String>, String>;
fn file_ids(snapshot: &Snapshot, id: &str) -> RepositoryResult<FileIds> {
    let Some(Object::Commit(commit)) = snapshot.objects.get(id) else {
        return Err("expected history commit".into());
    };
    if let Some(tree) = &commit.tree {
        let Some(Object::Tree(tree)) = snapshot.objects.get(tree) else {
            return Err("missing history tree".into());
        };
        Ok(tree
            .entries
            .iter()
            .map(|(path, id)| (Some(path.clone()), id.clone()))
            .collect())
    } else {
        Ok(BTreeMap::from([(None, commit.wasm.clone())]))
    }
}
fn blob<'a>(snapshot: &'a Snapshot, id: &str) -> RepositoryResult<&'a [u8]> {
    match snapshot.objects.get(id) {
        Some(Object::Wasm(bytes)) => Ok(bytes),
        _ => Err("expected history Wasm blob".into()),
    }
}
fn witness(snapshot: &Snapshot, id: Option<&String>) -> RepositoryResult<Value> {
    id.map(|id| {
        blob(snapshot, id)
            .map(|bytes| json!({"object_id":id,"byte_len":bytes.len(),"sha256":object_id(bytes)}))
    })
    .transpose()
    .map(|value| value.unwrap_or(Value::Null))
}
fn series(
    snapshot: &Snapshot,
    range: &str,
    first_parent: bool,
    limit: usize,
) -> RepositoryResult<(String, String, Vec<CommitInfo>)> {
    if range.contains("...") {
        return Err("range-diff requires two BASE..TIP ranges".into());
    }
    let (base, tip) = range
        .split_once("..")
        .ok_or("range-diff requires two BASE..TIP ranges")?;
    if base.is_empty() || tip.is_empty() {
        return Err("range-diff requires explicit range endpoints".into());
    }
    let base = snapshot_revision(snapshot, base)?;
    let tip = snapshot_revision(snapshot, tip)?;
    let mut current = tip.clone();
    let mut commits = Vec::new();
    while current != base {
        if commits.len() >= limit {
            return Err("range-diff commit budget exceeded".into());
        }
        let Some(Object::Commit(commit)) = snapshot.objects.get(&current) else {
            return Err("range endpoint is not a commit".into());
        };
        if commit.parents.is_empty() {
            return Err("range base is not on the selected parent chain".into());
        }
        if commit.parents.len() > 1 && !first_parent {
            return Err("range-diff requires linear ranges; use --first-parent for an explicit merge projection".into());
        }
        commits.push(CommitInfo {
            id: current,
            commit: commit.clone(),
        });
        current = commit.parents[0].clone();
    }
    commits.reverse();
    Ok((base, tip, commits))
}
fn transitions(
    snapshot: &Snapshot,
    commits: &[CommitInfo],
    remaining: &mut usize,
    audit_details: bool,
) -> RepositoryResult<Vec<Value>> {
    let mut result = Vec::new();
    for info in commits {
        let current = file_ids(snapshot, &info.id)?;
        let old = if let Some(parent) = info.commit.parents.first() {
            file_ids(snapshot, parent)?
        } else {
            BTreeMap::new()
        };
        let paths: BTreeSet<_> = old.keys().chain(current.keys()).cloned().collect();
        let mut signature = Vec::new();
        let mut changes = Vec::new();
        for path in paths {
            let (before, after) = (old.get(&path), current.get(&path));
            if before == after {
                continue;
            }
            signature.push((path.clone(), before.cloned(), after.cloned()));
            let mut change = json!({"path":path,"legacy_unnamed":path.is_none(),"status":match (before, after) {(None, Some(_))=>"added",(Some(_),None)=>"deleted",_=>"modified"},"old":witness(snapshot,before)?,"new":witness(snapshot,after)?});
            if audit_details {
                if let (Some(before), Some(after)) = (before, after) {
                    let before = blob(snapshot, before)?;
                    let after = blob(snapshot, after)?;
                    let cost = before
                        .len()
                        .checked_add(after.len())
                        .ok_or("range diff byte count overflow")?;
                    if cost > *remaining {
                        return Err("range-diff compared-byte budget exceeded".into());
                    }
                    *remaining -= cost;
                    change["audit"] =
                        serde_json::to_value(wasm_git::audit::compare(before, after)?)
                            .map_err(|error| error.to_string())?;
                }
            }
            changes.push(change);
        }
        let signature =
            object_id(&serde_json::to_vec(&signature).map_err(|error| error.to_string())?);
        result.push(json!({"commit":info.id,"parents":info.commit.parents,"message":info.commit.message,"transition_id":signature,"changes":changes}));
    }
    Ok(result)
}

impl Repository {
    pub fn shortlog(
        &self,
        revision: &str,
        first_parent: bool,
        group: &str,
        summary: bool,
        number: bool,
    ) -> RepositoryResult<Value> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let tip = snapshot_revision(&snapshot, revision)?;
        let commits = super::plumbing_storage::walk_snapshot(
            &snapshot,
            std::slice::from_ref(&tip),
            &[],
            false,
            first_parent,
        )?;
        let mut groups = BTreeMap::<Option<String>, Vec<Value>>::new();
        for info in &commits {
            let keys: BTreeSet<_> = if group == "subject" {
                BTreeSet::from([Some(
                    info.commit.message.lines().next().unwrap_or("").into(),
                )])
            } else {
                let current = file_ids(&snapshot, &info.id)?;
                let mut changed = BTreeSet::new();
                if info.commit.parents.is_empty() {
                    changed.extend(current.keys().cloned());
                }
                for parent in
                    info.commit
                        .parents
                        .iter()
                        .take(if first_parent { 1 } else { usize::MAX })
                {
                    let before = file_ids(&snapshot, parent)?;
                    changed.extend(
                        current
                            .keys()
                            .chain(before.keys())
                            .filter(|path| current.get(*path) != before.get(*path))
                            .cloned(),
                    );
                }
                changed
            };
            for key in keys {
                groups.entry(key).or_default().push(json!({"commit":info.id,"subject":info.commit.message.lines().next().unwrap_or("")}));
            }
        }
        let mut rows: Vec<_> = groups
            .into_iter()
            .map(|(key, items)| {
                let mut row = json!({"key":key,"count":items.len()});
                if !summary {
                    row["commits"] = json!(items);
                }
                row
            })
            .collect();
        if number {
            rows.sort_by(|a, b| {
                b["count"]
                    .as_u64()
                    .cmp(&a["count"].as_u64())
                    .then_with(|| a["key"].as_str().cmp(&b["key"].as_str()))
            });
        }
        Ok(
            json!({"schema_version":1,"tip":tip,"commits":commits.len(),"group_by":group,"parent_policy":if first_parent {"first_parent"} else {"any_parent"},"groups":rows,"authors_available":false}),
        )
    }

    pub fn range_diff(
        &self,
        old_range: &str,
        new_range: &str,
        first_parent: bool,
        max_commits: usize,
        max_bytes: usize,
        audit_details: bool,
    ) -> RepositoryResult<Value> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let (old_base, old_tip, old_commits) =
            series(&snapshot, old_range, first_parent, max_commits)?;
        let (new_base, new_tip, new_commits) =
            series(&snapshot, new_range, first_parent, max_commits)?;
        let mut remaining = max_bytes;
        let old = transitions(&snapshot, &old_commits, &mut remaining, audit_details)?;
        let new = transitions(&snapshot, &new_commits, &mut remaining, audit_details)?;
        let mut old_ids = BTreeMap::<&str, Vec<usize>>::new();
        let mut new_ids = BTreeMap::<&str, Vec<usize>>::new();
        for (index, commit) in old.iter().enumerate() {
            old_ids
                .entry(
                    commit["transition_id"]
                        .as_str()
                        .ok_or("missing old transition ID")?,
                )
                .or_default()
                .push(index);
        }
        for (index, commit) in new.iter().enumerate() {
            new_ids
                .entry(
                    commit["transition_id"]
                        .as_str()
                        .ok_or("missing new transition ID")?,
                )
                .or_default()
                .push(index);
        }
        let mut rows = Vec::new();
        let mut paired = BTreeSet::new();
        for (index, commit) in old.iter().enumerate() {
            let id = commit["transition_id"]
                .as_str()
                .ok_or("missing transition ID")?;
            let candidates = new_ids.get(id).cloned().unwrap_or_default();
            if candidates.len() == 1 && old_ids[id].len() == 1 {
                let target = candidates[0];
                paired.insert(target);
                rows.push(json!({"status":"equal_transition","old":index,"new":target,"message_changed":commit["message"] != new[target]["message"]}));
            } else {
                rows.push(json!({"status":if candidates.is_empty() {"removed"} else {"ambiguous"},"old":index,"new":null,"new_candidates":candidates}));
            }
        }
        for (index, commit) in new.iter().enumerate() {
            if paired.contains(&index) {
                continue;
            }
            let candidates = old_ids
                .get(
                    commit["transition_id"]
                        .as_str()
                        .ok_or("missing transition ID")?,
                )
                .cloned()
                .unwrap_or_default();
            rows.push(json!({"status":if candidates.is_empty() {"added"} else {"ambiguous"},"old":null,"new":index,"old_candidates":candidates}));
        }
        Ok(
            json!({"schema_version":1,"comparison":"exact_original_per_path_transitions","semantic_equivalence_proven":false,"first_parent":first_parent,"old":{"base":old_base,"tip":old_tip,"commits":old},"new":{"base":new_base,"tip":new_tip,"commits":new},"rows":rows,"compared_bytes":max_bytes-remaining}),
        )
    }
}
