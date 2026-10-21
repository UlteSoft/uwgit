//! Transactional, byte-preserving replay for legacy modules and named file trees.

use crate::porcelain;
use crate::repository::{
    read_file_revisions, validate_tree_path, CommitInfo, Repository, RepositoryResult,
    RevisionFiles,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const EMPTY: &[u8] = b"\0asm\x01\0\0\0";
const USAGE: &str = "cherry-pick DIR REV [-m MESSAGE] [--mainline N]; revert DIR REV [-m MESSAGE] [--mainline N]; cherry-pick|revert DIR TARGET_FULL_ID [--mainline N] --resolved-index --expect-head FULL_ID [--expect-branch NAME] [-m MESSAGE]; rebase DIR UPSTREAM [--onto NEW_BASE] [--record-conflict]; rebase DIR --continue --resolved-index|--abort|--skip|--quit";

pub fn run(args: &[String]) -> RepositoryResult<String> {
    if crate::command_args::help_requested(args) {
        return Ok(USAGE.into());
    }
    if args.len() < 3 {
        return Err(USAGE.into());
    }
    let mut message = None;
    let mut mainline = None;
    let mut onto = None;
    let mut resolved_index = false;
    let mut expected_head = None;
    let mut expected_branch = None;
    let mut index = 3;
    while index < args.len() {
        let flag = &args[index];
        index += 1;
        if flag == "--resolved-index" && !resolved_index {
            if args[0] == "rebase" {
                return Err(
                    "rebase does not support --resolved-index; no replay state is created".into(),
                );
            }
            resolved_index = true;
            continue;
        }
        let value = args.get(index).ok_or(USAGE)?;
        match flag.as_str() {
            "-m" | "--message" if message.is_none() && args[0] != "rebase" => {
                message = Some(value.clone())
            }
            "--mainline" if mainline.is_none() && args[0] != "rebase" => {
                mainline = Some(
                    value
                        .parse::<usize>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or("mainline must be a positive parent number")?,
                );
            }
            "--onto" if onto.is_none() && args[0] == "rebase" => onto = Some(value.clone()),
            "--expect-head" if expected_head.is_none() && args[0] != "rebase" => {
                expected_head = Some(value.clone())
            }
            "--expect-branch" if expected_branch.is_none() && args[0] != "rebase" => {
                expected_branch = Some(value.clone())
            }
            _ => return Err(USAGE.into()),
        }
        index += 1;
    }
    if resolved_index {
        if !matches!(args[0].as_str(), "cherry-pick" | "revert") {
            return Err(USAGE.into());
        }
        let expected_head =
            expected_head.ok_or("--resolved-index requires --expect-head FULL_ID")?;
        immutable_id(&args[2], "resolution target")?;
        immutable_id(&expected_head, "expected HEAD")?;
        return porcelain::with_index_resolution(&args[1], |repo, files, anchor| {
            apply_resolved_index(
                repo,
                ReviewedReplay {
                    operation: &args[0],
                    target: &args[2],
                    expected_head: &expected_head,
                    expected_branch: expected_branch.as_deref(),
                    mainline,
                    message: message.as_deref(),
                },
                files,
                anchor,
            )
        });
    }
    if expected_head.is_some() || expected_branch.is_some() {
        return Err("--expect-head and --expect-branch require --resolved-index".into());
    }
    porcelain::with_clean_history(&args[1], |repo| match args[0].as_str() {
        "cherry-pick" | "revert" => apply_one(repo, &args[0], &args[2], message, mainline),
        "rebase" => rebase(repo, &args[2], onto.as_deref()),
        _ => Err(USAGE.into()),
    })
}

fn immutable_id(value: &str, label: &str) -> RepositoryResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} requires a complete lowercase hexadecimal commit ID"
        ));
    }
    Ok(())
}

fn replay_parent(selected: &CommitInfo, mainline: Option<usize>) -> RepositoryResult<Option<&str>> {
    match (selected.commit.parents.len(), mainline) {
        (0, None) => Ok(None),
        (1, None) => Ok(selected.commit.parents.first().map(String::as_str)),
        (count, Some(n)) if n > 0 && n <= count => {
            Ok(selected.commit.parents.get(n - 1).map(String::as_str))
        }
        (_, Some(_)) => Err("mainline parent number is out of range".into()),
        _ => Err("merge commit requires --mainline N".into()),
    }
}

fn replay_report(
    mut report: serde_json::Value,
    branch: &str,
    head: &str,
    selected: &CommitInfo,
    parent: Option<&str>,
) -> RepositoryResult<String> {
    report["branch"] = json!(branch);
    report["old_head"] = json!(head);
    report["target"] = json!(selected.id);
    report["selected_parent"] = json!(parent);
    report["mainline"] = json!(parent.and_then(|id| {
        selected
            .commit
            .parents
            .iter()
            .position(|p| p == id)
            .map(|n| n + 1)
    }));
    serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
}

fn apply_one(
    repo: &Repository,
    operation: &str,
    revision: &str,
    message: Option<String>,
    mainline: Option<usize>,
) -> RepositoryResult<String> {
    apply_one_bound(repo, operation, revision, message, mainline, None)
}

pub(crate) fn apply_one_bound(
    repo: &Repository,
    operation: &str,
    revision: &str,
    message: Option<String>,
    mainline: Option<usize>,
    expected: Option<(&str, &str)>,
) -> RepositoryResult<String> {
    let state = repo.state()?;
    let head = state
        .branches
        .get(&state.head)
        .ok_or("history replay requires a committed HEAD")?;
    if expected.is_some_and(|(branch, tip)| state.head != branch || head != tip) {
        return Err(
            "branch or HEAD changed before the recorded replay started; no replay published".into(),
        );
    }
    let selected = repo.read_commit(revision)?;
    let parent = replay_parent(&selected, mainline)?;
    let mut references = vec![head.as_str(), selected.id.as_str()];
    if let Some(parent) = parent {
        references.push(parent);
    }
    let files = read_file_revisions(&repo.root, &references)?;
    if files.iter().any(|revision| revision.legacy.is_none()) {
        return apply_tree(
            repo,
            operation,
            &state.head,
            head,
            &selected,
            &files,
            message,
        );
    }
    let parent_bytes = parent
        .map(|id| repo.wasm_bytes(id))
        .transpose()?
        .unwrap_or_else(|| EMPTY.to_vec());
    let selected_bytes = repo.wasm_bytes(&selected.id)?;
    let ours = repo.wasm_bytes(head)?;
    let (base, theirs) = if operation == "revert" {
        (&selected_bytes, &parent_bytes)
    } else {
        (&parent_bytes, &selected_bytes)
    };
    let report = wasm_git::merge::merge(base, &ours, theirs)?;
    let Some(bytes) = &report.bytes else {
        return replay_report(
            json!({"status":"conflict","operation":operation,"report":report}),
            &state.head,
            head,
            &selected,
            parent,
        );
    };
    let message = message.unwrap_or_else(|| {
        if operation == "revert" {
            format!(
                "Revert \"{}\"\n\nThis reverts commit {}.",
                selected.commit.message, selected.id
            )
        } else {
            selected.commit.message.clone()
        }
    });
    let commit = repo.commit_on_branch(
        bytes,
        &message,
        std::slice::from_ref(head),
        &state.head,
        Some(head),
    )?;
    replay_report(
        json!({"status":"committed","operation":operation,"commit":commit}),
        &state.head,
        head,
        &selected,
        parent,
    )
}

fn rebase(repo: &Repository, upstream: &str, onto: Option<&str>) -> RepositoryResult<String> {
    let state = repo.state()?;
    let head = state
        .branches
        .get(&state.head)
        .ok_or("rebase requires a committed HEAD")?;
    let upstream = repo.resolve(upstream)?;
    let target = repo.resolve(onto.unwrap_or(&upstream))?;
    let bases = repo.merge_bases(head, &upstream)?;
    if bases.len() != 1 {
        return Err("rebase requires one unambiguous merge base".into());
    }
    let base = &bases[0];
    let mut pending = Vec::new();
    let mut cursor = head.clone();
    while &cursor != base {
        let commit = repo.read_commit(&cursor)?;
        if commit.commit.parents.len() != 1 {
            return Err(
                "linear rebase cannot replay a root or merge commit; use an explicit merge instead"
                    .into(),
            );
        }
        cursor = commit.commit.parents[0].clone();
        pending.push(commit);
    }
    pending.reverse();
    let mut references = vec![head.as_str(), target.as_str()];
    for commit in &pending {
        references.push(&commit.id);
        references.push(&commit.commit.parents[0]);
    }
    let files = read_file_revisions(&repo.root, &references)?;
    if files.iter().any(|revision| revision.legacy.is_none()) {
        return rebase_trees(repo, &state.head, head, &target, &pending, &files);
    }
    let mut ours = repo.wasm_bytes(&target)?;
    let mut replay = Vec::new();
    for commit in &pending {
        let base_bytes = repo.wasm_bytes(&commit.commit.parents[0])?;
        let theirs = repo.wasm_bytes(&commit.id)?;
        let report = wasm_git::merge::merge(&base_bytes, &ours, &theirs)?;
        let Some(bytes) = report.bytes.clone() else {
            return serde_json::to_string_pretty(&json!({"status":"conflict","operation":"rebase","old_head":head,"onto":target,"stopped_at":commit.id,"report":report})).map_err(|e| e.to_string());
        };
        ours = bytes.clone();
        replay.push((bytes, commit.commit.message.clone()));
    }
    let commits = if replay.is_empty() {
        // An already merged branch is moved to the selected new base, as with
        // an empty successful replay. No intermediate reference is published.
        repo.reset_on_branch(&target, &state.head, Some(head))?;
        Vec::new()
    } else {
        repo.replay_on_branch(&state.head, Some(head), &target, &replay)?
    };
    Ok(json!({"status":"rebased","old_head":head,"onto":target,"commits":commits,"commit":commits.last().unwrap_or(&target)}).to_string())
}

type Files = BTreeMap<String, Vec<u8>>;

struct ReviewedReplay<'a> {
    operation: &'a str,
    target: &'a str,
    expected_head: &'a str,
    expected_branch: Option<&'a str>,
    mainline: Option<usize>,
    message: Option<&'a str>,
}

fn resolution_witness(bytes: &[u8]) -> serde_json::Value {
    let audit = match wasm_git::audit::inspect(bytes) {
        Ok(report) => json!(report),
        Err(reason) => json!({"available":false,"view":"binary","reason":reason}),
    };
    json!({
        "byte_len":bytes.len(),
        "sha256":format!("{:x}", Sha256::digest(bytes)),
        "hex":bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "audit":audit
    })
}

fn resolution_delta(before: Option<&[u8]>, after: Option<&[u8]>) -> serde_json::Value {
    let status = match (before, after) {
        (None, None) => "absent",
        (None, Some(_)) => "added",
        (Some(_), None) => "deleted",
        (Some(old), Some(new)) if old == new => "unchanged",
        _ => "modified",
    };
    let audit = match (before, after) {
        (Some(old), Some(new)) if old != new => match wasm_git::audit::compare(old, new) {
            Ok(report) => json!(report),
            Err(reason) => json!({"available":false,"view":"binary","reason":reason}),
        },
        _ => serde_json::Value::Null,
    };
    json!({"status":status,"binary_changed":before!=after,"audit":audit})
}

/// Record the user's complete reviewed index without claiming an automatic
/// replay succeeded or requiring a persisted conflict. Only HEAD is a parent;
/// the selected target and mainline explain the intended operation, not a merge.
/// The index lock spans validation and publication, while immutable revision
/// reads and commit_files_on_branch each verify the store under its writer lock.
fn apply_resolved_index(
    repo: &Repository,
    review: ReviewedReplay<'_>,
    files: &Files,
    anchor: Option<&str>,
) -> RepositoryResult<String> {
    let state = repo.state()?;
    let branch = review.expected_branch.unwrap_or(&state.head);
    if state.head != branch {
        return Err(format!(
            "branch changed since replay resolution was reviewed: expected {branch}, actual {}",
            state.head
        ));
    }
    let head = state
        .branches
        .get(branch)
        .ok_or("replay resolution requires a committed HEAD")?;
    if head != review.expected_head {
        return Err(format!(
            "HEAD changed since replay resolution was reviewed: expected {}, actual {head}",
            review.expected_head
        ));
    }
    let selected = repo.read_commit(review.target)?;
    if selected.id != review.target {
        return Err("resolution target must select that exact immutable commit ID".into());
    }
    let parent = replay_parent(&selected, review.mainline)?;
    let mut references = vec![review.expected_head, review.target];
    if let Some(parent) = parent {
        references.push(parent);
    }
    let revisions = read_file_revisions(&repo.root, &references)?;
    if revisions
        .iter()
        .zip(&references)
        .any(|(revision, id)| revision.commit != *id)
    {
        return Err("reviewed replay revisions must resolve to their exact immutable IDs".into());
    }
    if common_anchor(repo, &revisions)?.as_deref() != anchor {
        return Err("resolved index must retain the explicit legacy path shared by the reviewed replay revisions".into());
    }
    let ours = mapped_files(&revisions[0], anchor)?;
    let selected_files = mapped_files(&revisions[1], anchor)?;
    let parent_files = revisions
        .get(2)
        .map(|revision| mapped_files(revision, anchor))
        .transpose()?
        .unwrap_or_default();
    let (base, theirs) = if review.operation == "revert" {
        (&selected_files, &parent_files)
    } else {
        (&parent_files, &selected_files)
    };
    let paths: BTreeSet<_> = ours
        .keys()
        .chain(base.keys())
        .chain(theirs.keys())
        .chain(files.keys())
        .cloned()
        .collect();
    let reports: Vec<_> = paths
        .into_iter()
        .map(|path| {
            let before = base.get(&path).map(Vec::as_slice);
            let current = ours.get(&path).map(Vec::as_slice);
            let change = theirs.get(&path).map(Vec::as_slice);
            let resolved = files.get(&path).map(Vec::as_slice);
            json!({
                "path":path,
                "base":before.map(resolution_witness),
                "ours":current.map(resolution_witness),
                "theirs":change.map(resolution_witness),
                "resolved":resolved.map(resolution_witness),
                "intended_change":resolution_delta(before, change),
                "from_head":resolution_delta(current, resolved)
            })
        })
        .collect();
    let default_message = if review.operation == "revert" {
        format!(
            "Revert \"{}\"\n\nThis reverts commit {}.",
            selected.commit.message, selected.id
        )
    } else {
        selected.commit.message.clone()
    };
    let parents = vec![review.expected_head.to_owned()];
    let commit = repo.commit_files_on_branch(
        files,
        review.message.unwrap_or(&default_message),
        &parents,
        branch,
        Some(review.expected_head),
        anchor,
    )?;
    replay_report(
        json!({
            "schema_version":1,
            "status":"committed_resolved",
            "operation":review.operation,
            "commit":commit,
            "parents":parents,
            "resolution_source":"index",
            "provenance":"user_supplied_complete_tree; metadata_only; no_automatic_replay_claim",
            "supplied_complete_tree":true,
            "automatic_replay_checked":false,
            "pending_state_required":false,
            "index_updated":false,
            "worktree_updated":false,
            "legacy_path":anchor,
            "file_reports":reports
        }),
        branch,
        review.expected_head,
        &selected,
        parent,
    )
}

fn common_anchor(
    repo: &Repository,
    revisions: &[RevisionFiles],
) -> RepositoryResult<Option<String>> {
    let mut anchors: BTreeSet<_> = revisions
        .iter()
        .filter_map(|revision| revision.legacy_path.clone())
        .collect();
    if let Some(anchor) = porcelain::worktree_legacy_path(repo)? {
        anchors.insert(anchor);
    }
    if anchors.len() > 1 {
        return Err(format!(
            "conflicting legacy path anchors; no filename guessed: {anchors:?}"
        ));
    }
    let anchor = anchors.first().cloned();
    if anchor.is_none() && revisions.iter().any(|revision| revision.legacy.is_some()) {
        return Err("unnamed v1 history needs an explicit legacy path; stage its known filename with add before mixing file trees".into());
    }
    Ok(anchor)
}

fn mapped_files(revision: &RevisionFiles, anchor: Option<&str>) -> RepositoryResult<Files> {
    let mut files = revision.files.clone();
    if let Some(bytes) = &revision.legacy {
        files.insert(
            anchor
                .ok_or("legacy history has no explicit path mapping")?
                .into(),
            bytes.clone(),
        );
    }
    Ok(files)
}

struct TreeMerge {
    files: Files,
    reports: Vec<serde_json::Value>,
    conflict: bool,
}

fn merge_maps(base: &Files, ours: &Files, theirs: &Files) -> RepositoryResult<TreeMerge> {
    let mut result = TreeMerge {
        files: BTreeMap::new(),
        reports: Vec::new(),
        conflict: false,
    };
    let paths: BTreeSet<_> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .cloned()
        .collect();
    for path in paths {
        let before = base.get(&path);
        let left = ours.get(&path);
        let right = theirs.get(&path);
        if before == left && before == right {
            if let Some(bytes) = before {
                result.files.insert(path, bytes.clone());
            }
            continue;
        }
        let mut report = None;
        let mut reason = None;
        let bytes = if left == right {
            Some(left.cloned())
        } else if before == left {
            Some(right.cloned())
        } else if before == right {
            Some(left.cloned())
        } else if let (Some(base), Some(ours), Some(theirs)) = (before, left, right) {
            let mut merged = wasm_git::merge::merge(base, ours, theirs)?;
            let bytes = if merged.status == "clean" {
                Some(Some(
                    merged.bytes.take().ok_or("clean file replay lacks bytes")?,
                ))
            } else {
                None
            };
            report = Some(merged);
            bytes
        } else {
            reason = Some(if before.is_none() {
                "different files added at the same path"
            } else {
                "delete/modify conflict"
            });
            None
        };
        if let Some(bytes) = bytes {
            let status = match (before, &bytes) {
                (None, Some(_)) => "added",
                (Some(_), None) => "deleted",
                _ => "modified",
            };
            if let Some(bytes) = bytes {
                result.files.insert(path.clone(), bytes);
            }
            result
                .reports
                .push(json!({"path":path,"status":status,"report":report}));
        } else {
            result.conflict = true;
            result
                .reports
                .push(json!({"path":path,"status":"conflict","reason":reason,"report":report}));
        }
    }
    for path in result.files.keys() {
        validate_tree_path(path)?;
        for (offset, _) in path.match_indices('/') {
            if result.files.contains_key(&path[..offset]) {
                result.conflict = true;
                result.reports.push(json!({"path":path,"status":"conflict","reason":"file/directory prefix conflict"}));
            }
        }
    }
    Ok(result)
}

fn anchor_conflict(
    operation: &str,
    head: &str,
    target: &str,
    reason: String,
) -> RepositoryResult<String> {
    serde_json::to_string_pretty(&json!({"status":"conflict","operation":operation,"old_head":head,"target":target,"reason":reason,"file_reports":[]})).map_err(|e| e.to_string())
}

fn apply_tree(
    repo: &Repository,
    operation: &str,
    branch: &str,
    head: &str,
    selected: &CommitInfo,
    revisions: &[RevisionFiles],
    message: Option<String>,
) -> RepositoryResult<String> {
    let parent = revisions.get(2).map(|revision| revision.commit.as_str());
    let anchor = match common_anchor(repo, revisions) {
        Ok(anchor) => anchor,
        Err(reason) => {
            return replay_report(
                json!({"status":"conflict","operation":operation,"reason":reason,"file_reports":[]}),
                branch,
                head,
                selected,
                parent,
            )
        }
    };
    let ours = mapped_files(&revisions[0], anchor.as_deref())?;
    let selected_files = mapped_files(&revisions[1], anchor.as_deref())?;
    let parent_files = revisions
        .get(2)
        .map(|revision| mapped_files(revision, anchor.as_deref()))
        .transpose()?
        .unwrap_or_default();
    let (base, theirs) = if operation == "revert" {
        (&selected_files, &parent_files)
    } else {
        (&parent_files, &selected_files)
    };
    let merged = merge_maps(base, &ours, theirs)?;
    if merged.conflict {
        return replay_report(
            json!({"status":"conflict","operation":operation,"file_reports":merged.reports}),
            branch,
            head,
            selected,
            parent,
        );
    }
    porcelain::assert_worktree_target_safe(repo, &merged.files)?;
    let message = message.unwrap_or_else(|| {
        if operation == "revert" {
            format!(
                "Revert \"{}\"\n\nThis reverts commit {}.",
                selected.commit.message, selected.id
            )
        } else {
            selected.commit.message.clone()
        }
    });
    let commit = repo.commit_files_on_branch(
        &merged.files,
        &message,
        &[head.into()],
        branch,
        Some(head),
        anchor.as_deref(),
    )?;
    replay_report(
        json!({"status":"committed","operation":operation,"commit":commit,"file_reports":merged.reports}),
        branch,
        head,
        selected,
        parent,
    )
}

fn rebase_trees(
    repo: &Repository,
    branch: &str,
    head: &str,
    target: &str,
    pending: &[CommitInfo],
    revisions: &[RevisionFiles],
) -> RepositoryResult<String> {
    let anchor = match common_anchor(repo, revisions) {
        Ok(anchor) => anchor,
        Err(reason) => return anchor_conflict("rebase", head, target, reason),
    };
    let mut ours = mapped_files(&revisions[1], anchor.as_deref())?;
    let mut replay = Vec::new();
    let mut reports = Vec::new();
    for (index, commit) in pending.iter().enumerate() {
        let theirs = mapped_files(&revisions[2 + index * 2], anchor.as_deref())?;
        let base = mapped_files(&revisions[3 + index * 2], anchor.as_deref())?;
        let merged = merge_maps(&base, &ours, &theirs)?;
        if merged.conflict {
            return serde_json::to_string_pretty(&json!({"status":"conflict","operation":"rebase","old_head":head,"onto":target,"stopped_at":commit.id,"file_reports":merged.reports})).map_err(|e| e.to_string());
        }
        ours = merged.files;
        reports.push(json!({"source":commit.id,"files":merged.reports}));
        replay.push((ours.clone(), commit.commit.message.clone()));
    }
    porcelain::assert_worktree_target_safe(repo, &ours)?;
    let commits = if replay.is_empty() {
        repo.reset_on_branch(target, branch, Some(head))?;
        Vec::new()
    } else {
        repo.replay_files_on_branch(branch, Some(head), target, &replay, anchor.as_deref())?
    };
    Ok(json!({"status":"rebased","old_head":head,"onto":target,"commits":commits,"commit":commits.last().map_or(target, String::as_str),"file_reports":reports}).to_string())
}
