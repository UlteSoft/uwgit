//! A lossless, local, content-addressed Wasm repository.
//!
//! Objects contain the original bytes, never a normalized representation. The
//! versioned object envelope (including its type and payload length) is hashed
//! with SHA-256. Commits form an immutable DAG; branch files are the only mutable
//! history pointers. Bundles are self-contained and verified before publication.
//! Mutations and consistent snapshots use `.uwgit/write.lock`; a crashed writer's
//! lock requires manual inspection and removal before another writer proceeds.
//!
//! The object format has no signatures or pack compression. Explicit GC
//! preserves recovery roots and only prunes after a verified full-store plan.
//! Network authentication belongs to the separate transport layer.
//! Object verification currently reads the
//! complete store into memory. Hashes establish integrity, not an author's identity.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "repository_worktrees.rs"]
mod linked_worktrees;
#[path = "repository_notes.rs"]
mod notes_storage;
pub use notes_storage::NotesRequest;
#[path = "repository_history_tools.rs"]
mod history_tools;
#[path = "repository_merge_tool.rs"]
mod merge_tool_storage;
#[path = "repository_plumbing.rs"]
mod plumbing_storage;
pub use plumbing_storage::MergeBaseMode;
#[path = "repository_head.rs"]
mod head_storage;
#[path = "repository_revisions.rs"]
mod revision_syntax;
pub(crate) use head_storage::is_detached_identity;
pub(crate) use head_storage::validate_head_identity;
use head_storage::{check_pending_head, head_tip};

pub type RepositoryResult<T> = Result<T, String>;

/// A local branch's configured remote branch. This metadata never enters a
/// repository advertisement, object, bundle or clone of the source repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub remote: String,
    pub branch: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamFile {
    version: u32,
    branches: BTreeMap<String, Upstream>,
}

/// A local, opt-in conflict continuation. It never enters an object, bundle or
/// repository advertisement. The original index is kept verbatim for abort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingOperation {
    pub version: u32,
    pub id: String,
    pub operation: String,
    pub branch: String,
    pub head: String,
    pub target: String,
    pub base: Option<String>,
    pub selected_parent: Option<String>,
    pub mainline: Option<usize>,
    pub message: String,
    pub baseline_index: Option<Vec<u8>>,
    pub legacy_path: Option<String>,
    pub prepared: Option<PendingPrepared>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebase: Option<PendingRebase>,
}

/// A frozen linear replay. Its original branch remains at `head` until every
/// source has either been replayed or explicitly skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRebase {
    pub upstream: String,
    pub onto: String,
    pub fork_base: String,
    pub queue: Vec<String>,
    pub cursor: usize,
    pub progress_tip: String,
    pub steps: Vec<PendingRebaseStep>,
    pub prepared_action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRebaseStep {
    pub source: String,
    pub before: String,
    pub commit: Option<String>,
    pub action: String,
    pub index_sha256: Option<String>,
}

pub struct PendingRebaseRequest {
    pub branch: String,
    pub head: String,
    pub upstream: String,
    pub onto: String,
    pub baseline_index: Option<Vec<u8>>,
    pub legacy_path: Option<String>,
}

/// Persisted before publishing the new ref, after its entire object closure is
/// installed. This makes a repeated continuation identify the same commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingPrepared {
    pub commit: String,
    pub index_sha256: String,
}

pub struct PendingRequest {
    pub operation: String,
    pub branch: String,
    pub head: String,
    pub target: String,
    pub mainline: Option<usize>,
    pub message: String,
    pub baseline_index: Option<Vec<u8>>,
    pub legacy_path: Option<String>,
}

/// Only a current decoded index may propose a new continuation. A published
/// prepared result can be finished without an index, preserving later edits.
pub struct PendingIndex<'a> {
    pub files: &'a BTreeMap<String, Vec<u8>>,
    pub legacy_path: Option<&'a str>,
    pub raw: &'a [u8],
}

#[derive(Debug, Serialize)]
pub struct PendingResolutionOutcome {
    pub schema_version: u32,
    pub status: String,
    pub operation: String,
    pub pending_id: String,
    pub branch: String,
    pub old_head: String,
    pub target: String,
    pub base: Option<String>,
    pub selected_parent: Option<String>,
    pub mainline: Option<usize>,
    pub commit: String,
    pub parents: Vec<String>,
    pub already_published: bool,
    pub resumed_prepared: bool,
    pub index_matches_prepared: Option<bool>,
    pub resolution_source: String,
    pub index_updated: bool,
    pub worktree_updated: bool,
    pub pending_cleared: bool,
    pub tree_manual_resolution: TreeManualResolution,
}

/// Network receive errors distinguish pre-publication rejection from an update
/// whose publication may already have happened. The classification is phase
/// based and never inferred from human-readable error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveError {
    pub message: String,
    pub publication_unknown: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionFiles {
    pub commit: String,
    pub legacy: Option<Vec<u8>>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub legacy_path: Option<String>,
}

#[derive(Debug)]
pub struct ResolvedRevision {
    pub commit: String,
    pub bytes: Vec<u8>,
}

/// Resolve every requested name against one verified, locked repository state.
/// Returned IDs and byte copies remain bound after the writer lock is released.
pub fn read_revisions(
    repo_dir: &Path,
    references: &[&str],
) -> RepositoryResult<Vec<ResolvedRevision>> {
    Repository::open(repo_dir)?.resolved_revisions(references)
}

/// Read every requested complete file tree from one verified, locked snapshot.
pub fn read_file_revisions(
    repo_dir: &Path,
    references: &[&str],
) -> RepositoryResult<Vec<RevisionFiles>> {
    let repository = Repository::open(repo_dir)?;
    let _lock = repository.lock()?;
    let snapshot = repository.snapshot()?;
    references
        .iter()
        .map(|revision| {
            let id = snapshot_revision(&snapshot, revision)?;
            snapshot_files(&snapshot, &id)
        })
        .collect()
}

/// Return the selected revision's entire ancestor DAG from one verified,
/// locked repository snapshot. Objects outside that DAG are still verified,
/// but do not become trace evidence. Shared Wasm blobs are copied only once.
pub fn read_history(
    repo_dir: &Path,
    revision: &str,
) -> RepositoryResult<wasm_git::trace::HistorySnapshot> {
    let repository = Repository::open(repo_dir)?;
    let _lock = repository.lock()?;
    let snapshot = repository.snapshot()?;
    let tip = snapshot_revision(&snapshot, revision)?;
    let mut pending = vec![tip.clone()];
    let mut commits = BTreeMap::new();
    let mut blobs = BTreeMap::new();
    while let Some(id) = pending.pop() {
        if commits.contains_key(&id) {
            continue;
        }
        let Some(Object::Commit(commit)) = snapshot.objects.get(&id) else {
            return Err(format!("missing commit {id} in verified history snapshot"));
        };
        require_legacy_commit(commit)?;
        if let std::collections::btree_map::Entry::Vacant(entry) = blobs.entry(commit.wasm.clone())
        {
            let Some(Object::Wasm(bytes)) = snapshot.objects.get(&commit.wasm) else {
                return Err(format!(
                    "history commit {id} has a missing or non-Wasm blob"
                ));
            };
            entry.insert(bytes.clone());
        }
        pending.extend(commit.parents.iter().cloned());
        commits.insert(
            id.clone(),
            wasm_git::trace::HistoryCommit {
                id,
                wasm: commit.wasm.clone(),
                parents: commit.parents.clone(),
                message: commit.message.clone(),
            },
        );
    }
    Ok(wasm_git::trace::HistorySnapshot {
        tip,
        commits,
        blobs,
    })
}

pub struct RepositoryFileHistory {
    pub history: wasm_git::trace::HistorySnapshot,
    pub absent: BTreeSet<String>,
    pub legacy_path: Option<String>,
    pub tip_legacy: bool,
}

/// Trace one explicitly selected path, retaining the real DAG even where that
/// file is absent. Absence is not a synthetic empty Wasm blob or a rename guess.
pub fn read_file_history(
    repo_dir: &Path,
    revision: &str,
    path: &str,
) -> RepositoryResult<RepositoryFileHistory> {
    validate_tree_path(path)?;
    let repository = Repository::open(repo_dir)?;
    let _lock = repository.lock()?;
    let snapshot = repository.snapshot()?;
    let tip = snapshot_revision(&snapshot, revision)?;
    let selected = snapshot_files(&snapshot, &tip)?;
    let tip_legacy = selected.legacy.is_some();
    let anchor = selected.legacy_path;
    let mut pending = vec![tip.clone()];
    let mut commits = BTreeMap::new();
    let mut blobs = BTreeMap::new();
    let mut absent = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if commits.contains_key(&id) {
            continue;
        }
        let Some(Object::Commit(commit)) = snapshot.objects.get(&id) else {
            return Err(format!("missing history commit {id}"));
        };
        let blob = if let Some(tree) = &commit.tree {
            let Some(Object::Tree(tree)) = snapshot.objects.get(tree) else {
                return Err("missing history tree".into());
            };
            tree.entries.get(path).cloned()
        } else if anchor.as_deref().is_some_and(|anchor| anchor != path) {
            None
        } else {
            Some(commit.wasm.clone())
        };
        let wasm = if let Some(blob) = blob {
            let Some(Object::Wasm(bytes)) = snapshot.objects.get(&blob) else {
                return Err("missing history Wasm".into());
            };
            blobs.entry(blob.clone()).or_insert_with(|| bytes.clone());
            blob
        } else {
            if id == tip {
                return Err(format!("file {path:?} is absent at selected tip {id}"));
            }
            absent.insert(id.clone());
            String::new()
        };
        pending.extend(commit.parents.iter().cloned());
        commits.insert(
            id.clone(),
            wasm_git::trace::HistoryCommit {
                id,
                wasm,
                parents: commit.parents.clone(),
                message: commit.message.clone(),
            },
        );
    }
    Ok(RepositoryFileHistory {
        history: wasm_git::trace::HistorySnapshot {
            tip,
            commits,
            blobs,
        },
        absent,
        legacy_path: anchor,
        tip_legacy,
    })
}

const FORMAT: &[u8] = b"uwgit-repository-v1\n";
const OBJECT_MAGIC: &[u8; 8] = b"UWGO\0\0\0\x01";
const BUNDLE_MAGIC: &[u8; 8] = b"UWGB\0\0\0\x01";
const WASM_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";
const OBJECT_HEADER_LENGTH: usize = 17;
const MAX_UPSTREAM_BYTES: u64 = 1024 * 1024;
const MAX_PENDING_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BISECT_BYTES: u64 = 1024 * 1024;
const MAX_BISECT_MARKS: usize = 4096;
const WASM_KIND: u8 = 1;
const COMMIT_KIND: u8 = 2;
const TREE_KIND: u8 = 3;
const REPOSITORY_USAGE: &str = "repository commands: init <DIR>; commit <DIR> <WASM> -m <MESSAGE>; merge <DIR> <REF_OR_ID> -m <MESSAGE>; merge <DIR> <REF_OR_ID> [-m <MESSAGE>] --ff-only; merge <DIR> <TARGET_ID> -m <MESSAGE> --resolved <WASM> --expect-head <HEAD_ID>; merge <DIR> <TARGET_ID> -m <MESSAGE> --resolved-index --expect-head <HEAD_ID> [--expect-branch <BRANCH>]; merge-base <DIR> <LEFT> <RIGHT>; log <DIR> [REF_OR_ID]; show <DIR> <REF_OR_ID> [--output <NEW_FILE>]; checkout <DIR> <REF_OR_ID> <NEW_FILE>; branch <DIR> [NAME [REF_OR_ID]]; switch <DIR> <BRANCH>; clone <SOURCE_DIR> <NEW_DIR>; bundle <DIR> <NEW_BUNDLE_FILE>; unbundle <DIR> <BUNDLE> <BRANCH>; fsck <DIR>";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct Repository {
    pub root: PathBuf,
    metadata: PathBuf,
    common_metadata: PathBuf,
}

/// Field order is part of the version-one canonical commit encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub format: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wasm: String,
    pub parents: Vec<String>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_path: Option<String>,
}

/// A flat, canonical path-to-blob tree; directory names are implicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub format: u32,
    #[serde(deserialize_with = "deserialize_unique_refs")]
    pub entries: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommitInfo {
    pub id: String,
    #[serde(flatten)]
    pub commit: Commit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FsckReport {
    pub format: u32,
    pub objects: usize,
    pub commits: usize,
    pub wasm_blobs: usize,
    pub trees: usize,
    pub branches: usize,
    pub tags: usize,
    pub unreachable_objects: usize,
}

/// Local references and their stored commit sizes from one verified snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryRefs {
    pub schema_version: u32,
    pub head: String,
    pub head_tip: Option<String>,
    pub head_object: Option<QueryObject>,
    pub refs: Vec<QueryRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryRef {
    pub name: String,
    pub id: String,
    pub kind: String,
    pub byte_len: u64,
    pub stored_byte_len: u64,
    pub current: bool,
    pub upstream: Option<Upstream>,
}

/// Sizes refer to the original payload and its stored versioned envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryObject {
    pub object_id: String,
    pub kind: String,
    pub byte_len: u64,
    pub stored_byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryTreeEntry {
    pub path: String,
    pub object_id: String,
    pub kind: String,
    pub byte_len: u64,
    pub stored_byte_len: u64,
}

/// Flat stored paths, without synthetic directory objects or guessed names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryTree {
    pub schema_version: u32,
    pub object_id: String,
    pub kind: String,
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub legacy_path: Option<String>,
    pub named: bool,
    pub legacy: Option<QueryObject>,
    pub entries: Vec<QueryTreeEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct QueryObjectCounts {
    pub objects: usize,
    pub payload_bytes: u64,
    pub stored_bytes: u64,
    pub reachable_objects: usize,
    pub unreachable_objects: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryObjects {
    pub schema_version: u32,
    pub objects: usize,
    pub payload_bytes: u64,
    pub stored_bytes: u64,
    pub reachable_objects: usize,
    pub unreachable_objects: usize,
    pub root_commits: usize,
    pub root_policy: String,
    pub by_kind: BTreeMap<String, QueryObjectCounts>,
}

/// Describe local lightweight tags; abbreviation zero retains the full ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescribeOptions {
    pub first_parent: bool,
    pub exact_match: bool,
    pub abbrev: usize,
}

impl Default for DescribeOptions {
    fn default() -> Self {
        Self {
            first_parent: false,
            exact_match: false,
            abbrev: 12,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DescribeResult {
    pub schema_version: u32,
    pub commit: String,
    pub abbreviation: String,
    pub tag: Option<String>,
    pub tag_commit: Option<String>,
    pub distance: Option<usize>,
    pub exact: bool,
    pub first_parent: bool,
    /// Local tags accepted by the caller's filter, including non-ancestors.
    pub evaluated_tags: usize,
    pub selection_policy: String,
    pub requested_abbrev: usize,
}

/// Original committed bytes without interpreting file contents or naming a
/// legacy blob. A directly selected tree is never reported as a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSnapshot {
    pub object_id: String,
    pub kind: String,
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub legacy_path: Option<String>,
    pub legacy: Option<Vec<u8>>,
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BisectKind {
    Good,
    Bad,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BisectMark {
    pub kind: BisectKind,
    pub revisions: Vec<String>,
}

pub enum BisectRequest {
    Start {
        bad: String,
        good: Vec<String>,
        first_parent: bool,
    },
    Mark {
        kind: BisectKind,
        revisions: Vec<String>,
    },
    Status,
    Log,
    Next,
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BisectReport {
    pub schema_version: u32,
    pub operation: String,
    pub status: String,
    pub active: bool,
    pub changed: bool,
    pub generation: Option<String>,
    pub first_parent: bool,
    pub original_bad: Option<String>,
    pub initial_good: Vec<String>,
    pub bad: Option<String>,
    pub good: Vec<String>,
    pub skip: Vec<String>,
    pub candidate: Option<String>,
    pub remaining: Vec<String>,
    pub testable: Vec<String>,
    pub suspects: Vec<String>,
    pub first_bad: Option<String>,
    pub marks: Vec<BisectMark>,
    pub object_verification: String,
    pub no_checkout: bool,
    pub head_updated: bool,
    pub index_updated: bool,
    pub worktree_updated: bool,
    pub pending_updated: bool,
    pub selection_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BisectState {
    version: u32,
    id: String,
    original_bad: String,
    initial_good: Vec<String>,
    first_parent: bool,
    marks: Vec<BisectMark>,
}

struct BisectProgress {
    bad: String,
    good: BTreeSet<String>,
    skip: BTreeSet<String>,
}

/// A consistent advertisement of a verified repository, including unborn HEAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryState {
    pub format: u32,
    pub head: String,
    #[serde(deserialize_with = "deserialize_unique_refs")]
    pub branches: BTreeMap<String, String>,
    #[serde(deserialize_with = "deserialize_unique_refs")]
    pub tags: BTreeMap<String, String>,
}

/// Ref updates are recorded after publication, under the same writer lock.
/// An I/O failure while recording a published update is reported explicitly;
/// the caller must inspect the ref before retrying rather than assume rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflogEntry {
    pub sequence: u64,
    pub reference: String,
    pub old: Option<String>,
    pub new: Option<String>,
    pub operation: String,
}

#[derive(Debug, Serialize)]
pub struct RepositoryMergeOutcome {
    pub schema_version: u32,
    pub status: String,
    pub branch: String,
    pub old_head: Option<String>,
    pub target: String,
    pub base: Option<String>,
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<wasm_git::merge::MergeReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual_resolution: Option<ManualResolution>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub file_reports: Vec<FileMergeReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_manual_resolution: Option<TreeManualResolution>,
}

#[derive(Debug, Serialize)]
pub struct FileMergeReport {
    /// Empty only for a whole-tree mapping or file/directory conflict.
    pub path: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<wasm_git::merge::MergeReport>,
}

#[derive(Debug, Serialize)]
pub struct ManualResolution {
    pub supplied_bytes: bool,
    pub wasm: String,
    pub audit_validation: String,
    pub diagnostic_count: usize,
}

/// Evidence for an explicitly supplied complete tree, compared with both
/// immutable parents. No automatic-merge or semantic-validation claim is made.
#[derive(Debug, Serialize)]
pub struct TreeManualResolution {
    pub supplied_complete_tree: bool,
    pub provenance: String,
    pub legacy_path: Option<String>,
    pub files: Vec<ManualTreeFile>,
}

#[derive(Debug, Serialize)]
pub struct ManualTreeFile {
    pub path: String,
    pub base: Option<ManualTreeByteWitness>,
    pub ours: Option<ManualTreeByteWitness>,
    pub theirs: Option<ManualTreeByteWitness>,
    pub resolved: Option<ManualTreeByteWitness>,
    pub from_ours: ManualTreeFileDelta,
    pub from_theirs: ManualTreeFileDelta,
}

/// Physical original bytes and their raw SHA-256, distinct from an object ID.
/// The audit includes diagnostics even for unknown or invalid module bodies.
#[derive(Debug, Serialize)]
pub struct ManualTreeByteWitness {
    pub byte_len: usize,
    pub sha256: String,
    pub hex: String,
    pub audit: wasm_git::audit::AuditModule,
}

#[derive(Debug, Serialize)]
pub struct ManualTreeFileDelta {
    /// absent, unchanged, added, deleted, or modified relative to this parent.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<wasm_git::audit::AuditDiff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    head: String,
    #[serde(deserialize_with = "deserialize_unique_refs")]
    refs: BTreeMap<String, String>,
    // Empty tags must retain the byte-exact original version-one encoding.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_unique_refs"
    )]
    tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
enum Object {
    Wasm(Vec<u8>),
    Commit(Commit),
    Tree(Tree),
}

#[derive(Debug, Clone)]
struct Snapshot {
    manifest: Manifest,
    upstreams: BTreeMap<String, Upstream>,
    upstream_tips: BTreeMap<String, RepositoryResult<String>>,
    checkouts: Vec<String>,
    head_reflog: Vec<ReflogEntry>,
    tracking: BTreeMap<String, String>,
    reflog: Vec<ReflogEntry>,
    encoded: BTreeMap<String, Vec<u8>>,
    objects: BTreeMap<String, Object>,
}

struct WriteLock {
    path: PathBuf,
    // Keep the file open until the entire mutation is finished.
    _file: File,
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Repository {
    pub fn init(root: impl AsRef<Path>) -> RepositoryResult<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|e| io_error("create repository directory", &root, e))?;
        require_directory(&root)?;
        let metadata = root.join(".uwgit");
        // Reserving the directory with create_dir never replaces an existing repo.
        fs::create_dir(&metadata).map_err(|e| io_error("initialize repository", &metadata, e))?;
        for child in ["objects", "refs", "tags", "tmp"] {
            let path = metadata.join(child);
            fs::create_dir(&path).map_err(|e| io_error("create repository directory", &path, e))?;
        }
        write_new_file(&metadata.join("HEAD"), b"main\n")?;
        // Write the format marker last; incomplete initialization cannot be opened.
        write_new_file(&metadata.join("format"), FORMAT)?;
        sync_directory(&metadata)?;
        Ok(Self {
            root,
            common_metadata: metadata.clone(),
            metadata,
        })
    }

    pub fn open(root: impl AsRef<Path>) -> RepositoryResult<Self> {
        let root = root.as_ref().to_path_buf();
        require_directory(&root)?;
        let metadata = root.join(".uwgit");
        require_directory(&metadata)?;
        let common_metadata = linked_worktrees::open_common(&root, &metadata)?;
        for child in ["objects", "refs", "tmp"] {
            require_directory(&common_metadata.join(child))?;
        }
        require_directory(&metadata.join("tmp"))?;
        if read_regular(&metadata.join("format"))? != FORMAT
            || read_regular(&common_metadata.join("format"))? != FORMAT
        {
            return Err("unsupported or incomplete uwgit repository format".into());
        }
        let repo = Self {
            root,
            metadata,
            common_metadata,
        };
        repo.current_branch()?;
        Ok(repo)
    }

    pub fn current_branch(&self) -> RepositoryResult<String> {
        parse_ref_file(&read_regular(&self.metadata.join("HEAD"))?, false)
    }

    pub fn branches(&self) -> RepositoryResult<BTreeMap<String, String>> {
        let _lock = self.lock()?;
        Ok(self.snapshot()?.manifest.refs)
    }

    /// Store any core Wasm byte stream, including unknown or future features.
    /// Header validation intentionally does not impose an instruction validator.
    pub fn commit(&self, bytes: &[u8], message: &str) -> RepositoryResult<String> {
        validate_wasm_header(bytes)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if let Some(Object::Commit(commit)) = snapshot
            .manifest
            .tip()
            .and_then(|id| snapshot.objects.get(id))
        {
            require_legacy_commit(commit)?;
        }
        let parents = snapshot.manifest.tip().cloned().into_iter().collect();
        let branch = snapshot.manifest.head;
        let wasm = self.store_object(WASM_KIND, bytes)?;
        let commit = Commit {
            format: 1,
            tree: None,
            legacy_path: None,
            wasm,
            parents,
            message: message.to_owned(),
        };
        let payload = encode_commit(&commit)?;
        let id = self.store_object(COMMIT_KIND, &payload)?;
        self.write_ref(&branch, &id)?;
        Ok(id)
    }

    /// Integrate a revision while holding the writer lock from source reads
    /// through publication. A conflict leaves both objects and refs unchanged.
    #[cfg(test)]
    pub fn merge(
        &self,
        target_revision: &str,
        message: &str,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        let state = self.state()?;
        self.merge_on_branch(
            target_revision,
            message,
            &state.head,
            state.tip().map(String::as_str),
        )
    }

    /// Bind an integration to the branch and tip captured before a fetch or
    /// review. A switch to another branch at the same commit is still rejected.
    pub fn merge_on_branch(
        &self,
        target_revision: &str,
        message: &str,
        expected_branch: &str,
        expected_head: Option<&str>,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        self.merge_with_policy_on_branch(
            target_revision,
            message,
            expected_branch,
            expected_head,
            false,
            false,
        )
    }

    /// Integrate only an existing descendant (or an already included revision).
    /// Divergence is rejected before selecting a base or constructing objects.
    pub fn merge_ff_only_on_branch(
        &self,
        target_revision: &str,
        message: &str,
        expected_branch: &str,
        expected_head: Option<&str>,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        self.merge_with_policy_on_branch(
            target_revision,
            message,
            expected_branch,
            expected_head,
            true,
            false,
        )
    }

    pub fn merge_no_ff_on_branch(
        &self,
        target: &str,
        message: &str,
        expected_branch: &str,
        expected_head: Option<&str>,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        if expected_head.is_none() {
            return Err("--no-ff requires a committed HEAD".into());
        }
        self.merge_with_policy_on_branch(
            target,
            message,
            expected_branch,
            expected_head,
            false,
            true,
        )
    }

    fn merge_with_policy_on_branch(
        &self,
        target_revision: &str,
        message: &str,
        expected_branch: &str,
        expected_head: Option<&str>,
        ff_only: bool,
        no_ff: bool,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        validate_head_identity(expected_branch)?;
        let _lock = self.lock()?;
        // Verify the whole store, including dangling histories, before treating
        // ancestry as evidence or allowing a fast-forward to hide corruption.
        let snapshot = self.snapshot()?;
        check_expected_branch(&snapshot.manifest.head, Some(expected_branch))?;
        check_expected(snapshot.manifest.tip(), expected_head)?;
        let branch = snapshot.manifest.head.clone();
        let target = snapshot_revision(&snapshot, target_revision)?;
        let old_head = snapshot.manifest.tip().cloned();
        let mut outcome = RepositoryMergeOutcome {
            schema_version: 1,
            status: String::new(),
            branch: branch.clone(),
            old_head: old_head.clone(),
            target: target.clone(),
            base: None,
            commit: None,
            report: None,
            manual_resolution: None,
            file_reports: Vec::new(),
            tree_manual_resolution: None,
        };
        let Some(ours) = old_head else {
            crate::porcelain::assert_worktree_revision_safe(
                self,
                &snapshot_files(&snapshot, &target)?,
            )?;
            self.write_ref(&branch, &target)?;
            outcome.status = "fast_forward".into();
            outcome.commit = Some(target);
            return Ok(outcome);
        };
        if is_ancestor(&target, &ours, &snapshot.objects)? {
            outcome.status = "already_up_to_date".into();
            outcome.base = Some(target);
            outcome.commit = Some(ours);
            return Ok(outcome);
        }
        if !no_ff && is_ancestor(&ours, &target, &snapshot.objects)? {
            crate::porcelain::assert_worktree_revision_safe(
                self,
                &snapshot_files(&snapshot, &target)?,
            )?;
            self.write_ref(&branch, &target)?;
            outcome.status = "fast_forward".into();
            outcome.base = Some(ours);
            outcome.commit = Some(target);
            return Ok(outcome);
        }
        if ff_only {
            return Err(format!(
                "fast-forward-only merge refused: target {target} is not a descendant of HEAD {ours}; no merge published"
            ));
        }
        let base = unique_merge_base(&ours, &target, &snapshot.objects)?;
        if [&base, &ours, &target].iter().any(|id| matches!(snapshot.objects.get(*id), Some(Object::Commit(commit)) if commit.format == 2)) {
            let merged = merge_file_trees(&snapshot, &base, &ours, &target)?;
            outcome.base = Some(base);
            outcome.file_reports = merged.reports;
            if outcome.file_reports.iter().any(|report| report.status == "conflict") {
                outcome.status = "conflict".into();
                return Ok(outcome);
            }
            let parents = vec![ours, target];
            check_tree_parents(&snapshot, &parents, merged.legacy_path.as_deref())?;
            crate::porcelain::assert_worktree_target_safe(self, &merged.files)?;
            let mut encoded = BTreeMap::new();
            let id = prepare_tree_commit(&merged.files, message, &parents, merged.legacy_path.as_deref(), &snapshot.encoded, &mut encoded)?;
            self.install_tree_objects(&encoded, std::slice::from_ref(&id))?;
            self.write_ref(&branch, &id)?;
            outcome.status = "merged".into();
            outcome.commit = Some(id);
            return Ok(outcome);
        }
        let mut report = wasm_git::merge::merge(
            snapshot_wasm(&snapshot, &base)?,
            snapshot_wasm(&snapshot, &ours)?,
            snapshot_wasm(&snapshot, &target)?,
        )?;
        outcome.base = Some(base);
        match report.status.as_str() {
            "conflict" => {
                outcome.status = "conflict".into();
                outcome.report = Some(report);
                Ok(outcome)
            }
            "clean" => {
                let bytes = report
                    .bytes
                    .take()
                    .ok_or("clean merge report contains no merged bytes")?;
                validate_wasm_header(&bytes)?;
                crate::porcelain::assert_worktree_revision_safe(
                    self,
                    &RevisionFiles {
                        commit: String::new(),
                        legacy: Some(bytes.clone()),
                        files: BTreeMap::new(),
                        legacy_path: None,
                    },
                )?;
                let wasm = self.store_object(WASM_KIND, &bytes)?;
                let commit = Commit {
                    format: 1,
                    tree: None,
                    legacy_path: None,
                    wasm,
                    parents: vec![ours, target],
                    message: message.to_owned(),
                };
                let id = self.store_object(COMMIT_KIND, &encode_commit(&commit)?)?;
                self.write_ref(&branch, &id)?;
                outcome.status = "merged".into();
                outcome.commit = Some(id);
                outcome.report = Some(report);
                Ok(outcome)
            }
            status => Err(format!("unexpected merge engine status: {status:?}")),
        }
    }

    /// Return all best common ancestors in stable object-ID order. Callers can
    /// inspect ambiguous/criss-cross ancestry without selecting a guessed base.
    pub fn merge_bases(&self, left: &str, right: &str) -> RepositoryResult<Vec<String>> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let left = snapshot_revision(&snapshot, left)?;
        let right = snapshot_revision(&snapshot, right)?;
        best_merge_bases(&left, &right, &snapshot.objects)
    }

    /// Record an explicitly supplied resolution with both verified parents.
    /// The immutable target and expected current tip bind the human's result to
    /// the history they reviewed; a concurrent advance cannot be overwritten.
    #[cfg(test)]
    pub fn merge_resolved(
        &self,
        expected_head: &str,
        target_id: &str,
        bytes: &[u8],
        message: &str,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        let state = self.state()?;
        self.merge_resolved_on_branch(&state.head, expected_head, target_id, bytes, message)
    }

    pub fn merge_resolved_on_branch(
        &self,
        expected_branch: &str,
        expected_head: &str,
        target_id: &str,
        bytes: &[u8],
        message: &str,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        validate_head_identity(expected_branch)?;
        require_id(expected_head)?;
        require_id(target_id)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        check_expected_branch(&snapshot.manifest.head, Some(expected_branch))?;
        let branch = snapshot.manifest.head.clone();
        let ours = snapshot
            .manifest
            .tip()
            .cloned()
            .ok_or("manual merge resolution requires an existing HEAD commit")?;
        if ours != expected_head {
            return Err(format!(
                "HEAD changed since resolution was reviewed: expected {expected_head}, actual {ours}; no merge published"
            ));
        }
        let target = snapshot_revision(&snapshot, target_id)?;
        if is_ancestor(&ours, &target, &snapshot.objects)?
            || is_ancestor(&target, &ours, &snapshot.objects)?
        {
            return Err("manual merge resolution requires divergent tips; refusing to ignore supplied bytes for a fast-forward or already-up-to-date history".into());
        }
        let base = unique_merge_base(&ours, &target, &snapshot.objects)?;
        for id in [&ours, &target, &base] {
            if let Some(Object::Commit(commit)) = snapshot.objects.get(id) {
                require_legacy_commit(commit)?;
            }
        }
        validate_wasm_header(bytes)?;
        // Explicit resolution has the same byte-preserving acceptance as commit:
        // unknown/future features and invalid bodies remain auditable history.
        // Its recorded diagnostics must never be presented as an automatic clean
        // merge or as proof of validation.
        let audit = wasm_git::audit::inspect(bytes)?;
        let wasm = self.store_object(WASM_KIND, bytes)?;
        let manual_resolution = ManualResolution {
            supplied_bytes: true,
            wasm: wasm.clone(),
            audit_validation: audit.validation,
            diagnostic_count: audit.diagnostics.len(),
        };
        let commit = Commit {
            format: 1,
            tree: None,
            legacy_path: None,
            wasm,
            parents: vec![ours.clone(), target.clone()],
            message: message.into(),
        };
        let id = self.store_object(COMMIT_KIND, &encode_commit(&commit)?)?;
        self.write_ref(&branch, &id)?;
        Ok(RepositoryMergeOutcome {
            schema_version: 1,
            status: "merged_resolved".into(),
            branch,
            old_head: Some(ours),
            target,
            base: Some(base),
            commit: Some(id),
            report: None,
            manual_resolution: Some(manual_resolution),
            file_reports: Vec::new(),
            tree_manual_resolution: None,
        })
    }

    /// Publish an explicit complete-tree resolution as a two-parent commit.
    /// This is metadata-only, like a staged commit: the supplied tree is stored
    /// without reading or rewriting the worktree. The caller serializes index
    /// access; this method holds the writer lock through validation/publication.
    pub fn merge_files_resolved_on_branch(
        &self,
        expected_branch: &str,
        expected_head: &str,
        target_id: &str,
        files: &BTreeMap<String, Vec<u8>>,
        legacy_path: Option<&str>,
        message: &str,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        validate_head_identity(expected_branch)?;
        require_id(expected_head)?;
        require_id(target_id)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        check_expected_branch(&snapshot.manifest.head, Some(expected_branch))?;
        check_expected(snapshot.manifest.tip(), Some(expected_head))?;
        // A complete hexadecimal ID is still required to name a commit, rather
        // than a similarly named ref that could redirect an explicit resolution.
        if !matches!(snapshot.objects.get(target_id), Some(Object::Commit(_))) {
            return Err(format!(
                "manual tree resolution target is not a stored commit: {target_id}"
            ));
        }
        if is_ancestor(expected_head, target_id, &snapshot.objects)?
            || is_ancestor(target_id, expected_head, &snapshot.objects)?
        {
            return Err("manual tree resolution requires divergent tips; refusing to ignore the supplied tree for a fast-forward or already-up-to-date history".into());
        }
        let base = unique_merge_base(expected_head, target_id, &snapshot.objects)?;
        let parents = vec![expected_head.to_owned(), target_id.to_owned()];
        check_tree_head_anchor(&snapshot, legacy_path)?;
        check_tree_parents(&snapshot, &parents, legacy_path)?;
        // Prepare every file, tree and commit in memory. All path, prefix,
        // header, anchor and collision failures precede object installation.
        let mut encoded = BTreeMap::new();
        let id = prepare_tree_commit(
            files,
            message,
            &parents,
            legacy_path,
            &snapshot.encoded,
            &mut encoded,
        )?;
        let revisions = [
            snapshot_files(&snapshot, &base)?,
            snapshot_files(&snapshot, expected_head)?,
            snapshot_files(&snapshot, target_id)?,
        ];
        let manual = manual_tree_resolution(revisions, files, legacy_path)?;
        self.install_tree_objects(&encoded, std::slice::from_ref(&id))?;
        self.write_named_ref("refs", expected_branch, &id, "merge-files-resolved")?;
        Ok(RepositoryMergeOutcome {
            schema_version: 1,
            status: "merged_resolved".into(),
            branch: expected_branch.into(),
            old_head: Some(expected_head.into()),
            target: target_id.into(),
            base: Some(base),
            commit: Some(id),
            report: None,
            manual_resolution: None,
            file_reports: Vec::new(),
            tree_manual_resolution: Some(manual),
        })
    }

    /// Resolve names and ancestry operators against one fully verified state.
    pub fn resolve(&self, revision: &str) -> RepositoryResult<String> {
        let _lock = self.lock()?;
        snapshot_revision(&self.snapshot()?, revision)
    }

    pub fn read_commit(&self, revision: &str) -> RepositoryResult<CommitInfo> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let id = snapshot_revision(&snapshot, revision)?;
        let Some(Object::Commit(commit)) = snapshot.objects.get(&id) else {
            return Err(format!("revision {id} is not a commit"));
        };
        Ok(CommitInfo {
            id,
            commit: commit.clone(),
        })
    }

    pub fn files_at(&self, revision: &str) -> RepositoryResult<RevisionFiles> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let id = snapshot_revision(&snapshot, revision)?;
        snapshot_files(&snapshot, &id)
    }

    pub fn commit_files_on_branch(
        &self,
        files: &BTreeMap<String, Vec<u8>>,
        message: &str,
        parents: &[String],
        expected_branch: &str,
        expected: Option<&str>,
        legacy_path: Option<&str>,
    ) -> RepositoryResult<String> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        validate_head_identity(expected_branch)?;
        check_expected_branch(&snapshot.manifest.head, Some(expected_branch))?;
        check_expected(snapshot.manifest.tip(), expected)?;
        check_tree_head_anchor(&snapshot, legacy_path)?;
        check_tree_parents(&snapshot, parents, legacy_path)?;
        let mut encoded = BTreeMap::new();
        let id = prepare_tree_commit(
            files,
            message,
            parents,
            legacy_path,
            &snapshot.encoded,
            &mut encoded,
        )?;
        self.install_tree_objects(&encoded, std::slice::from_ref(&id))?;
        self.write_named_ref("refs", expected_branch, &id, "commit-files")?;
        Ok(id)
    }

    /// Preflight every replayed tree and publish the chain's final tip once.
    pub fn replay_files_on_branch(
        &self,
        expected_branch: &str,
        expected: Option<&str>,
        base: &str,
        commits: &[(BTreeMap<String, Vec<u8>>, String)],
        legacy_path: Option<&str>,
    ) -> RepositoryResult<Vec<String>> {
        validate_head_identity(expected_branch)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        check_expected_branch(&snapshot.manifest.head, Some(expected_branch))?;
        check_expected(snapshot.manifest.tip(), expected)?;
        check_tree_head_anchor(&snapshot, legacy_path)?;
        let mut parent = snapshot_revision(&snapshot, base)?;
        check_tree_parents(&snapshot, std::slice::from_ref(&parent), legacy_path)?;
        let mut encoded = BTreeMap::new();
        let mut ids = Vec::new();
        for (files, message) in commits {
            let id = prepare_tree_commit(
                files,
                message,
                std::slice::from_ref(&parent),
                legacy_path,
                &snapshot.encoded,
                &mut encoded,
            )?;
            parent = id.clone();
            ids.push(id);
        }
        if ids.is_empty() {
            return Ok(ids);
        }
        self.install_tree_objects(&encoded, &ids)?;
        self.write_named_ref("refs", expected_branch, &parent, "replay-files")?;
        Ok(ids)
    }

    fn install_tree_objects(
        &self,
        encoded: &BTreeMap<String, Vec<u8>>,
        commits: &[String],
    ) -> RepositoryResult<()> {
        install_dependency_ordered(encoded, commits, |id, bytes| {
            self.install_encoded_object(id, bytes)
        })
    }

    /// Install the complete verified store, including unreachable histories.
    /// Dependencies must remain complete after every successful publication,
    /// so an interrupted import can be inspected and retried safely.
    fn install_snapshot_objects(&self, snapshot: &Snapshot) -> RepositoryResult<()> {
        let commits = validated_commit_order(&snapshot.objects)?;
        self.install_tree_objects(&snapshot.encoded, &commits)
    }

    pub fn wasm_bytes(&self, revision: &str) -> RepositoryResult<Vec<u8>> {
        self.resolved_revisions(&[revision])?
            .into_iter()
            .next()
            .map(|revision| revision.bytes)
            .ok_or_else(|| "revision snapshot returned no requested bytes".into())
    }

    fn resolved_revisions(&self, references: &[&str]) -> RepositoryResult<Vec<ResolvedRevision>> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        references
            .iter()
            .map(|reference| {
                let commit = snapshot_revision(&snapshot, reference)?;
                let bytes = snapshot_wasm(&snapshot, &commit)?.to_vec();
                Ok(ResolvedRevision { commit, bytes })
            })
            .collect()
    }

    /// The explicit output must not already exist, including a symbolic link.
    pub fn checkout(
        &self,
        revision: &str,
        destination: impl AsRef<Path>,
    ) -> RepositoryResult<String> {
        let info = self.read_commit(revision)?;
        require_legacy_commit(&info.commit)?;
        let bytes = match self.read_object(&info.commit.wasm)? {
            Object::Wasm(bytes) => bytes,
            Object::Commit(_) | Object::Tree(_) => {
                return Err("commit references a non-Wasm object".into())
            }
        };
        crate::output::write_export_file(destination.as_ref(), &bytes)?;
        Ok(info.id)
    }

    /// Traverse all ancestors once, with every child preceding its parents.
    pub fn log(&self, revision: Option<&str>) -> RepositoryResult<Vec<CommitInfo>> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let id = match revision {
            Some(rev) => snapshot_revision(&snapshot, rev)?,
            None => match snapshot.manifest.tip() {
                Some(id) => id.clone(),
                None => return Ok(Vec::new()),
            },
        };
        self.verify_history(&id)?;
        let mut commits = BTreeMap::new();
        let mut pending = vec![id];
        let mut children = BTreeMap::<String, usize>::new();
        while let Some(id) = pending.pop() {
            if commits.contains_key(&id) {
                continue;
            }
            let commit = self.read_commit_id(&id)?;
            children.entry(id.clone()).or_default();
            for parent in &commit.parents {
                *children.entry(parent.clone()).or_default() += 1;
                pending.push(parent.clone());
            }
            commits.insert(id, commit);
        }
        let mut ready: BTreeSet<_> = children
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(id, _)| id.clone())
            .collect();
        let mut result = Vec::with_capacity(commits.len());
        while let Some(id) = ready.pop_first() {
            let commit = commits.remove(&id).ok_or("invalid log graph")?;
            for parent in &commit.parents {
                let count = children.get_mut(parent).ok_or("invalid log parent")?;
                *count -= 1;
                if *count == 0 {
                    ready.insert(parent.clone());
                }
            }
            result.push(CommitInfo { id, commit });
        }
        Ok(result)
    }

    pub fn create_branch(&self, name: &str, revision: &str) -> RepositoryResult<String> {
        validate_ref_name(name)?;
        let _lock = self.lock()?;
        if self.read_ref_optional(name)?.is_some() {
            return Err(format!("branch {name} already exists"));
        }
        let snapshot = self.snapshot()?;
        let id = snapshot_revision(&snapshot, revision)?;
        self.write_ref(name, &id)?;
        Ok(id)
    }

    pub fn switch_branch(&self, name: &str) -> RepositoryResult<()> {
        validate_ref_name(name)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let id = snapshot
            .manifest
            .refs
            .get(name)
            .cloned()
            .ok_or_else(|| format!("unknown branch: {name}"))?;
        if snapshot.manifest.head == name {
            return Ok(());
        }
        let old = snapshot.manifest.tip().cloned();
        self.assert_branch_available(name)?;
        self.register_selected_branch(name)?;
        self.atomic_write(&self.metadata.join("HEAD"), format!("{name}\n").as_bytes())?;
        self.record_reflog(
            "HEAD",
            old.clone(),
            Some(id.clone()),
            &format!("switch {} -> {name}", snapshot.manifest.head),
        )?;
        self.record_head_event(old, Some(id), "switch")?;
        self.record_checkout(&snapshot.checkouts, &snapshot.manifest.head)
    }

    pub fn fsck(&self) -> RepositoryResult<FsckReport> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let reachable = reachable_objects(&snapshot.manifest, &snapshot.objects)?;
        let commits = snapshot
            .objects
            .values()
            .filter(|object| matches!(object, Object::Commit(_)))
            .count();
        Ok(FsckReport {
            format: 1,
            objects: snapshot.objects.len(),
            commits,
            wasm_blobs: snapshot
                .objects
                .values()
                .filter(|object| matches!(object, Object::Wasm(_)))
                .count(),
            trees: snapshot
                .objects
                .values()
                .filter(|object| matches!(object, Object::Tree(_)))
                .count(),
            branches: snapshot.manifest.refs.len(),
            tags: snapshot.manifest.tags.len(),
            unreachable_objects: snapshot.objects.len() - reachable.len(),
        })
    }

    pub fn export_bundle(&self, destination: impl AsRef<Path>) -> RepositoryResult<usize> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let bundle = encode_bundle(&snapshot)?;
        crate::output::write_export_file(destination.as_ref(), &bundle)?;
        Ok(snapshot.objects.len())
    }

    /// Import a verified self-contained bundle to one explicitly named branch.
    /// Existing branches can only advance to descendants of their current tip.
    pub fn import_bundle(
        &self,
        source: impl AsRef<Path>,
        branch: &str,
    ) -> RepositoryResult<String> {
        validate_ref_name(branch)?;
        // Validate *every* incoming object and all closures before any mutation.
        let incoming = decode_bundle(&read_regular(source.as_ref())?)?;
        let tip = incoming
            .manifest
            .tip()
            .cloned()
            .ok_or_else(|| "bundle has no commit at its HEAD branch".to_string())?;
        // Match receive's lock order so an add cannot create an index between
        // this check and ref publication. Importing another branch is safe;
        // integrating into a tracked current branch belongs to merge/pull.
        let _index_lock = self.lock_named("index.lock")?;
        let _lock = self.lock()?;
        // Existing corruption must not be hidden by newly imported objects.
        let current = self.snapshot()?;
        if current.manifest.head == branch {
            match fs::symlink_metadata(self.metadata.join("index")) {
                Ok(_) => return Err("cannot unbundle into the checked-out branch of a tracked worktree; import into another branch, then merge".into()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => return Err(io_error("inspect worktree index", &self.metadata.join("index"), e)),
            }
        }
        if let Some(old) = current.manifest.refs.get(branch) {
            if !is_ancestor(old, &tip, &incoming.objects)? {
                return Err(format!(
                    "refusing non-fast-forward update of {branch}; import into a new branch"
                ));
            }
        }
        for (id, bytes) in &incoming.encoded {
            if let Some(existing) = current.encoded.get(id) {
                if existing != bytes {
                    return Err(format!("object collision at {id}"));
                }
            }
        }
        self.install_snapshot_objects(&incoming)?;
        self.write_ref(branch, &tip)?;
        Ok(tip)
    }

    pub fn clone_local(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> RepositoryResult<Self> {
        let source = Self::open(source)?;
        let snapshot = {
            let _lock = source.lock()?;
            source.snapshot()?
        };
        let destination = destination.as_ref();
        // Requiring a new directory avoids overlaying any existing user files.
        fs::create_dir(destination)
            .map_err(|e| io_error("create clone destination", destination, e))?;
        let repo = Self::init(destination)?;
        {
            let _lock = repo.lock()?;
            repo.install_snapshot_objects(&snapshot)?;
            for (name, id) in &snapshot.manifest.refs {
                repo.write_ref(name, id)?;
            }
            for (name, id) in &snapshot.manifest.tags {
                repo.write_named_ref("tags", name, id, "clone")?;
            }
            if snapshot.manifest.head != "main" {
                repo.atomic_write(
                    &repo.metadata.join("HEAD"),
                    format!("{}\n", snapshot.manifest.head).as_bytes(),
                )?;
                repo.record_reflog(
                    "HEAD",
                    snapshot.manifest.refs.get("main").cloned(),
                    snapshot.manifest.tip().cloned(),
                    "clone-head",
                )?;
                repo.record_head_event(
                    snapshot.manifest.refs.get("main").cloned(),
                    snapshot.manifest.tip().cloned(),
                    "clone-head",
                )?;
            }
        }
        Ok(repo)
    }

    pub fn state(&self) -> RepositoryResult<RepositoryState> {
        let _lock = self.lock()?;
        Ok(manifest_state(&self.snapshot()?.manifest))
    }

    /// Pure history bisection. Only its local journal may change; no checkout,
    /// arbitrary test command, object, ref, index or pending update is made.
    pub fn bisect(&self, request: BisectRequest) -> RepositoryResult<BisectReport> {
        let _lock = self.lock()?;
        if matches!(&request, BisectRequest::Reset) {
            let path = self.metadata.join("bisect.json");
            let changed = match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(io_error("inspect bisect metadata", &path, error)),
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    fs::remove_file(&path).map_err(|error| io_error("remove bisect metadata", &path, error))?;
                    sync_directory(&self.metadata).map_err(|error| format!("bisect metadata was removed but its directory could not be synced: {error}; removal durability is uncertain"))?;
                    true
                }
                Ok(_) => return Err("bisect reset requires an existing regular journal, never a symlink or special file".into()),
            };
            return Ok(empty_bisect_report(
                "reset",
                "reset",
                changed,
                "not_requested",
            ));
        }
        let snapshot = self.snapshot()?;
        let saved = self.read_bisect()?;
        match request {
            BisectRequest::Start {
                bad,
                good,
                first_parent,
            } => {
                if saved.is_some() {
                    return Err("bisect metadata already exists; inspect or reset it before starting another session".into());
                }
                if good.is_empty() {
                    return Err("bisect start requires at least one known-good revision".into());
                }
                let bad = snapshot_revision(&snapshot, &bad)?;
                let good = good
                    .iter()
                    .map(|revision| snapshot_revision(&snapshot, revision))
                    .collect::<RepositoryResult<BTreeSet<_>>>()?
                    .into_iter()
                    .collect();
                let state = BisectState {
                    version: 1,
                    id: format!("{:x}", Sha256::digest(unique_name("bisect").as_bytes())),
                    original_bad: bad,
                    initial_good: good,
                    first_parent,
                    marks: Vec::new(),
                };
                let progress = replay_bisect(&snapshot, &state)?;
                let report = bisect_report(&snapshot, &state, &progress, "start", true)?;
                let encoded = encode_bisect(&state)?;
                self.publish_bisect(&encoded)?;
                Ok(report)
            }
            BisectRequest::Mark { kind, revisions } => {
                let mut state = saved.ok_or("no bisect session is active")?;
                let mut progress = replay_bisect(&snapshot, &state)?;
                let report =
                    bisect_report(&snapshot, &state, &progress, bisect_kind_name(kind), false)?;
                let revisions = if revisions.is_empty() {
                    vec![report.candidate.ok_or(
                        "bisect has no testable candidate; supply an explicit revision or reset",
                    )?]
                } else {
                    revisions
                        .iter()
                        .map(|revision| snapshot_revision(&snapshot, revision))
                        .collect::<RepositoryResult<BTreeSet<_>>>()?
                        .into_iter()
                        .collect()
                };
                if kind == BisectKind::Bad && revisions.len() != 1 {
                    return Err("bisect bad requires exactly one revision".into());
                }
                let domain =
                    describe_ancestors(&state.original_bad, &snapshot.objects, state.first_parent)?;
                let mark = apply_bisect_mark(
                    &snapshot,
                    state.first_parent,
                    &domain,
                    &mut progress,
                    kind,
                    &revisions,
                )?;
                let changed = !mark.revisions.is_empty();
                if changed {
                    if state.marks.len() >= MAX_BISECT_MARKS {
                        return Err("bisect journal exceeds the 4096 mark-event limit".into());
                    }
                    state.marks.push(mark);
                }
                let report = bisect_report(
                    &snapshot,
                    &state,
                    &progress,
                    bisect_kind_name(kind),
                    changed,
                )?;
                if changed {
                    self.publish_bisect(&encode_bisect(&state)?)?;
                }
                Ok(report)
            }
            BisectRequest::Status | BisectRequest::Log | BisectRequest::Next => {
                let operation = match &request {
                    BisectRequest::Log => "log",
                    BisectRequest::Next => "next",
                    _ => "status",
                };
                match saved {
                    None => Ok(empty_bisect_report(
                        operation,
                        "inactive",
                        false,
                        "full_snapshot",
                    )),
                    Some(state) => {
                        let progress = replay_bisect(&snapshot, &state)?;
                        bisect_report(&snapshot, &state, &progress, operation, false)
                    }
                }
            }
            BisectRequest::Reset => unreachable!(),
        }
    }

    /// Query local refs, including fetched branch tips and local upstream
    /// metadata, without consulting the index, worktree or pending journal.
    pub fn query_refs(&self) -> RepositoryResult<QueryRefs> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let mut refs = Vec::new();
        for (name, id) in &snapshot.manifest.refs {
            let object = query_object(&snapshot, id)?;
            refs.push(QueryRef {
                name: format!("refs/heads/{name}"),
                id: id.clone(),
                kind: object.kind,
                byte_len: object.byte_len,
                stored_byte_len: object.stored_byte_len,
                current: name == &snapshot.manifest.head,
                upstream: snapshot.upstreams.get(name).cloned(),
            });
        }
        for (prefix, names) in [
            ("refs/tags", &snapshot.manifest.tags),
            ("refs/remotes", &snapshot.tracking),
        ] {
            for (name, id) in names {
                let object = query_object(&snapshot, id)?;
                refs.push(QueryRef {
                    name: format!("{prefix}/{name}"),
                    id: id.clone(),
                    kind: object.kind,
                    byte_len: object.byte_len,
                    stored_byte_len: object.stored_byte_len,
                    current: false,
                    upstream: None,
                });
            }
        }
        refs.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(QueryRefs {
            schema_version: 1,
            head: snapshot.manifest.head.clone(),
            head_tip: snapshot.manifest.tip().cloned(),
            head_object: snapshot
                .manifest
                .tip()
                .map(|id| query_object(&snapshot, id))
                .transpose()?,
            refs,
        })
    }

    /// Resolve normal commit revision syntax, or an exact stored tree ID.
    /// Tree-ID prefixes are intentionally not resolved as revisions. A legacy
    /// blob is reported separately; no filename is guessed from the index.
    pub fn query_tree(&self, revision: &str) -> RepositoryResult<QueryTree> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        snapshot_query_tree(&snapshot, revision)
    }

    pub fn archive_files(&self, revision: &str) -> RepositoryResult<ArchiveSnapshot> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let selected = snapshot_query_tree(&snapshot, revision)?;
        let mut files = BTreeMap::new();
        for entry in selected.entries {
            let Some(Object::Wasm(bytes)) = snapshot.objects.get(&entry.object_id) else {
                return Err(format!("missing archive Wasm object {}", entry.object_id));
            };
            files.insert(entry.path, bytes.clone());
        }
        let legacy = selected
            .legacy
            .map(|object| match snapshot.objects.get(&object.object_id) {
                Some(Object::Wasm(bytes)) => Ok(bytes.clone()),
                _ => Err("missing archive legacy Wasm object".to_owned()),
            })
            .transpose()?;
        Ok(ArchiveSnapshot {
            object_id: selected.object_id,
            kind: selected.kind,
            commit: selected.commit,
            tree: selected.tree,
            legacy_path: selected.legacy_path,
            legacy,
            files,
        })
    }

    /// Select local lightweight tags from one verified snapshot. The caller's
    /// filter must not re-enter this repository while its writer lock is held.
    pub fn describe(
        &self,
        revision: &str,
        options: &DescribeOptions,
        mut accept_tag: impl FnMut(&str) -> RepositoryResult<bool>,
    ) -> RepositoryResult<DescribeResult> {
        if options.abbrev > 64 {
            return Err("describe abbreviation must be in 0..=64".into());
        }
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let commit = snapshot_revision(&snapshot, revision)?;
        let target = describe_ancestors(&commit, &snapshot.objects, options.first_parent)?;
        let mut evaluated_tags = 0;
        let mut selected: Option<(bool, usize, String, String)> = None;
        for (name, tip) in &snapshot.manifest.tags {
            if !accept_tag(name)? {
                continue;
            }
            evaluated_tags += 1;
            if !target.contains(tip) || (options.exact_match && tip != &commit) {
                continue;
            }
            let exact = tip == &commit;
            let distance = if exact {
                0
            } else {
                let tagged = describe_ancestors(tip, &snapshot.objects, options.first_parent)?;
                target.difference(&tagged).count()
            };
            let candidate = (!exact, distance, name.clone(), tip.clone());
            if selected.as_ref().is_none_or(|current| candidate < *current) {
                selected = Some(candidate);
            }
        }
        let (tag, tag_commit, distance, exact) = match selected {
            Some((not_exact, distance, name, tip)) => {
                (Some(name), Some(tip), Some(distance), !not_exact)
            }
            None => (None, None, None, false),
        };
        let abbreviation = unique_object_abbreviation(&commit, options.abbrev, &snapshot.objects)?;
        Ok(DescribeResult {
            schema_version: 1,
            commit,
            abbreviation,
            tag,
            tag_commit,
            distance,
            exact,
            first_parent: options.first_parent,
            evaluated_tags,
            selection_policy: "local_lightweight_tags; filtered_target_ancestors; exact_first; ancestor_set_difference_distance; ASCII_tag_name_tiebreak; no_dates; abbreviation_unique_across_all_objects".into(),
            requested_abbrev: options.abbrev,
        })
    }

    /// Count unique stored objects and retain roots from both current refs and
    /// recorded history. Unreachable is an observation, never permission to
    /// delete objects: an unpublished replay or index can still need them.
    pub fn query_objects(&self) -> RepositoryResult<QueryObjects> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let roots: BTreeSet<_> = snapshot
            .manifest
            .refs
            .values()
            .chain(snapshot.manifest.tags.values())
            .chain(snapshot.tracking.values())
            .chain(valid_id(&snapshot.manifest.head).then_some(&snapshot.manifest.head))
            .chain(
                snapshot
                    .reflog
                    .iter()
                    .chain(&snapshot.head_reflog)
                    .flat_map(|entry| entry.old.iter().chain(&entry.new)),
            )
            .cloned()
            .collect();
        let reachable = reachable_from_roots(roots.iter().cloned(), &snapshot.objects)?;
        let mut by_kind: BTreeMap<_, _> = ["commit", "tree", "wasm"]
            .into_iter()
            .map(|kind| (kind.to_owned(), QueryObjectCounts::default()))
            .collect();
        let mut payload_bytes = 0_u64;
        let mut stored_bytes = 0_u64;
        for id in snapshot.objects.keys() {
            let object = query_object(&snapshot, id)?;
            let counts = by_kind
                .get_mut(&object.kind)
                .ok_or("unknown stored object kind")?;
            counts.objects += 1;
            add_query_bytes(&mut counts.payload_bytes, object.byte_len)?;
            add_query_bytes(&mut counts.stored_bytes, object.stored_byte_len)?;
            add_query_bytes(&mut payload_bytes, object.byte_len)?;
            add_query_bytes(&mut stored_bytes, object.stored_byte_len)?;
            if reachable.contains(id) {
                counts.reachable_objects += 1;
            } else {
                counts.unreachable_objects += 1;
            }
        }
        Ok(QueryObjects {
            schema_version: 1,
            objects: snapshot.objects.len(),
            payload_bytes,
            stored_bytes,
            reachable_objects: reachable.len(),
            unreachable_objects: snapshot.objects.len() - reachable.len(),
            root_commits: roots.len(),
            root_policy: "local_branches+local_tags+detached_HEAD+fetched_tracking_branches+reflog_old_and_new+local_HEAD_reflog; remote_only_tags+pending+index_excluded; unlike_refs_only_fsck; unreachable_is_not_a_deletion_recommendation".into(),
            by_kind,
        })
    }

    /// Configuration and branch tips from one complete verified snapshot.
    /// Callers may already hold the remote configuration lock; these methods
    /// acquire only the repository writer lock, never a remote or index lock.
    pub fn state_with_upstreams(
        &self,
    ) -> RepositoryResult<(RepositoryState, BTreeMap<String, Upstream>)> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        Ok((manifest_state(&snapshot.manifest), snapshot.upstreams))
    }

    pub fn upstreams(&self) -> RepositoryResult<BTreeMap<String, Upstream>> {
        Ok(self.state_with_upstreams()?.1)
    }

    #[allow(dead_code)]
    pub fn upstream(&self, local: &str) -> RepositoryResult<Option<Upstream>> {
        validate_ref_name(local)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if !snapshot.manifest.refs.contains_key(local) && snapshot.manifest.head != local {
            return Err(format!("unknown branch: {local}"));
        }
        Ok(snapshot.upstreams.get(local).cloned())
    }

    /// Pin the named committed branch. This convenience API deliberately does
    /// not compare its previous association; network operations use the checked
    /// variant below to avoid replacing a concurrent user's configuration.
    #[allow(dead_code)]
    pub fn set_upstream_on_branch(
        &self,
        local: &str,
        remote: &str,
        target_branch: &str,
        expected_tip: &str,
    ) -> RepositoryResult<Upstream> {
        self.set_upstream_inner(local, remote, target_branch, expected_tip, None)
    }

    /// None requires an absent association, rather than omitting its lease.
    pub fn set_upstream_checked(
        &self,
        local: &str,
        remote: &str,
        target_branch: &str,
        expected_tip: &str,
        expected_upstream: Option<&Upstream>,
    ) -> RepositoryResult<Upstream> {
        self.set_upstream_inner(
            local,
            remote,
            target_branch,
            expected_tip,
            Some(expected_upstream),
        )
    }

    fn set_upstream_inner(
        &self,
        local: &str,
        remote: &str,
        target_branch: &str,
        expected_tip: &str,
        expected_upstream: Option<Option<&Upstream>>,
    ) -> RepositoryResult<Upstream> {
        validate_ref_name(local)?;
        validate_upstream_remote_name(remote)?;
        validate_ref_name(target_branch)?;
        require_id(expected_tip)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        check_upstream_tip(&snapshot, local, expected_tip)?;
        if expected_upstream.is_some_and(|expected| snapshot.upstreams.get(local) != expected) {
            return Err(format!(
                "upstream association for branch {local} changed; no configuration published"
            ));
        }
        let upstream = Upstream {
            remote: remote.into(),
            branch: target_branch.into(),
        };
        let mut associations = snapshot.upstreams;
        if associations.get(local) == Some(&upstream) {
            return Ok(upstream);
        }
        associations.insert(local.into(), upstream.clone());
        let bytes = encode_upstreams(&associations)?;
        self.publish_upstreams(&bytes, "set upstream")?;
        Ok(upstream)
    }

    #[allow(dead_code)]
    pub fn unset_upstream(&self, local: &str) -> RepositoryResult<Upstream> {
        self.unset_upstream_inner(local, None)
    }

    pub fn unset_upstream_checked(
        &self,
        local: &str,
        expected_tip: &str,
        expected_upstream: &Upstream,
    ) -> RepositoryResult<Upstream> {
        require_id(expected_tip)?;
        self.unset_upstream_inner(local, Some((expected_tip, expected_upstream)))
    }

    fn unset_upstream_inner(
        &self,
        local: &str,
        expected: Option<(&str, &Upstream)>,
    ) -> RepositoryResult<Upstream> {
        validate_ref_name(local)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if let Some((tip, upstream)) = expected {
            check_upstream_tip(&snapshot, local, tip)?;
            if snapshot.upstreams.get(local) != Some(upstream) {
                return Err(format!(
                    "upstream association for branch {local} changed; no configuration published"
                ));
            }
        }
        let mut associations = snapshot.upstreams;
        let old = associations
            .remove(local)
            .ok_or_else(|| format!("branch {local} has no upstream association"))?;
        let bytes = encode_upstreams(&associations)?;
        self.publish_upstreams(&bytes, "unset upstream")?;
        Ok(old)
    }

    /// Only the local association file changes. The caller coordinates the
    /// remote's separate configuration and reports any multi-file I/O failure.
    pub fn rename_upstream_remote(&self, old: &str, new: &str) -> RepositoryResult<usize> {
        validate_upstream_remote_name(old)?;
        validate_upstream_remote_name(new)?;
        if old == new {
            return Err("old and new remote names are identical".into());
        }
        let _lock = self.lock()?;
        let mut associations = self.snapshot()?.upstreams;
        let mut changed = 0;
        for upstream in associations.values_mut() {
            if upstream.remote == old {
                upstream.remote = new.into();
                changed += 1;
            }
        }
        if changed != 0 {
            let bytes = encode_upstreams(&associations)?;
            self.publish_upstreams(&bytes, "rename upstream remote")?;
        }
        Ok(changed)
    }

    pub fn remove_upstream_remote(&self, remote: &str) -> RepositoryResult<usize> {
        validate_upstream_remote_name(remote)?;
        let _lock = self.lock()?;
        let mut associations = self.snapshot()?.upstreams;
        let before = associations.len();
        associations.retain(|_, upstream| upstream.remote != remote);
        let changed = before - associations.len();
        if changed != 0 {
            let bytes = encode_upstreams(&associations)?;
            self.publish_upstreams(&bytes, "remove upstream remote")?;
        }
        Ok(changed)
    }

    /// Read local continuation metadata against a complete verified store.
    /// Stale branch pointers are reported by the caller, rather than making
    /// quit impossible after a separate writer has changed a branch.
    pub fn pending(&self) -> RepositoryResult<Option<PendingOperation>> {
        let _lock = self.lock()?;
        let Some(pending) = self.read_pending()? else {
            return Ok(None);
        };
        validate_pending_snapshot(&self.snapshot()?, &pending)?;
        Ok(Some(pending))
    }

    /// Record a conflict already computed for these immutable revisions. The
    /// caller holds the index lock from clean-index admission through here.
    pub fn record_pending(&self, request: PendingRequest) -> RepositoryResult<PendingOperation> {
        validate_head_identity(&request.branch)?;
        require_id(&request.head)?;
        require_id(&request.target)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if self.read_pending()?.is_some() {
            return Err(
                "a conflict operation is already pending; continue, abort or quit it first".into(),
            );
        }
        check_expected_branch(&snapshot.manifest.head, Some(&request.branch))?;
        check_expected(snapshot.manifest.tip(), Some(&request.head))?;
        let (base, selected_parent) = pending_identity(
            &snapshot,
            &request.operation,
            &request.head,
            &request.target,
            request.mainline,
        )?;
        let pending = PendingOperation {
            version: 1,
            id: format!("{:x}", Sha256::digest(unique_name("pending").as_bytes())),
            operation: request.operation,
            branch: request.branch,
            head: request.head,
            target: request.target,
            base,
            selected_parent,
            mainline: request.mainline,
            message: request.message,
            baseline_index: request.baseline_index,
            legacy_path: request.legacy_path,
            prepared: None,
            rebase: None,
        };
        validate_pending_snapshot(&snapshot, &pending)?;
        let bytes = encode_pending(&pending)?;
        self.publish_pending(&bytes, "record conflict")?;
        Ok(pending)
    }

    /// Publish the complete explicitly reviewed index without touching any
    /// working files or index bytes. The outer index lock precedes this writer
    /// lock. The prepared journal is durable before the ref update begins.
    pub fn continue_pending(
        &self,
        expected: &PendingOperation,
        index: Option<PendingIndex<'_>>,
    ) -> RepositoryResult<PendingResolutionOutcome> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let mut pending = self.checked_pending(&snapshot, expected)?;
        if pending.rebase.is_some() {
            return Err("use the rebase continuation API for its saved linear replay".into());
        }
        check_pending_head(&snapshot, &pending)?;
        let current = snapshot.manifest.tip();
        let already_published = pending
            .prepared
            .as_ref()
            .is_some_and(|prepared| current == Some(&prepared.commit));
        if !already_published {
            check_expected(current, Some(&pending.head))?;
        }
        let resumed_prepared = pending.prepared.is_some();
        let parents = pending_parents(&pending);
        let (commit, manual, index_matches_prepared) = if let Some(prepared) = &pending.prepared {
            let files = snapshot_files(&snapshot, &prepared.commit)?;
            let matches = index
                .as_ref()
                .map(|index| format!("{:x}", Sha256::digest(index.raw)) == prepared.index_sha256);
            if !already_published {
                let index = index.as_ref().ok_or(
                    "prepared continuation requires its existing reviewed index before publication",
                )?;
                crate::porcelain::validate_pending_resolution_index(
                    index.raw,
                    index.files,
                    index.legacy_path,
                )?;
                if index.legacy_path != pending.legacy_path.as_deref() || matches != Some(true) {
                    return Err("index changed after this continuation was prepared; no ref published; inspect the prepared commit or abort/quit the operation".into());
                }
                if index.files != &files.files {
                    return Err("prepared result differs from the reviewed index despite its recorded digest; no ref published".into());
                }
            }
            // Recovery always audits the committed tree, never a later index.
            let manual = pending_manual_resolution(&snapshot, &pending, &files.files)?;
            (prepared.commit.clone(), manual, matches)
        } else {
            let index = index
                .as_ref()
                .ok_or("continuation requires an existing explicitly reviewed index")?;
            crate::porcelain::validate_pending_resolution_index(
                index.raw,
                index.files,
                index.legacy_path,
            )?;
            if index.legacy_path != pending.legacy_path.as_deref() {
                return Err(
                    "resolved index changed the pending operation's legacy path anchor".into(),
                );
            }
            check_tree_parents(&snapshot, &parents, index.legacy_path)?;
            let mut encoded = BTreeMap::new();
            let commit = prepare_tree_commit(
                index.files,
                &pending.message,
                &parents,
                index.legacy_path,
                &snapshot.encoded,
                &mut encoded,
            )?;
            let manual = pending_manual_resolution(&snapshot, &pending, index.files)?;
            pending.prepared = Some(PendingPrepared {
                commit: commit.clone(),
                index_sha256: format!("{:x}", Sha256::digest(index.raw)),
            });
            // All logical checks, including the enlarged journal's limit,
            // precede installation of even an unreachable object.
            let bytes = encode_pending(&pending)?;
            self.install_tree_objects(&encoded, std::slice::from_ref(&commit))
                .map_err(|error| format!("continuation objects may be partly installed; branch and pending journal were not advanced: {error}"))?;
            self.publish_pending(&bytes, "prepare continuation")
                .map_err(|error| format!("commit {commit} is installed but its prepared journal may be published; inspect status and retry the same operation: {error}"))?;
            (commit, manual, Some(true))
        };
        let operation = format!("pending-continue-{}", pending.id);
        if !already_published {
            self.write_named_ref("refs", &pending.branch, &commit, &operation)
                .map_err(|error| format!("prepared continuation {commit} is durable; reference publication or its reflog may be incomplete: {error}; inspect status and retry --continue, never start another replay"))?;
        }
        self.ensure_pending_reflog(&pending, &commit, &operation)
            .map_err(|error| format!("continuation commit {commit} is published; pending state is retained because its reflog is incomplete: {error}; retry --continue after inspection"))?;
        self.remove_pending_checked(&pending)
            .map_err(|error| format!("continuation commit {commit} is published; clearing pending state failed or its durability is uncertain: {error}; inspect status before retrying"))?;
        Ok(PendingResolutionOutcome {
            schema_version: 1,
            status: "continued".into(),
            operation: pending.operation,
            pending_id: pending.id,
            branch: pending.branch,
            old_head: pending.head,
            target: pending.target,
            base: pending.base,
            selected_parent: pending.selected_parent,
            mainline: pending.mainline,
            commit,
            parents,
            already_published,
            resumed_prepared,
            index_matches_prepared,
            resolution_source: "index".into(),
            index_updated: false,
            worktree_updated: false,
            pending_cleared: true,
            tree_manual_resolution: manual,
        })
    }

    /// Begin an opt-in linear replay. Automatic prefixes are stored without
    /// publishing a branch; a conflicting source keeps its original baseline.
    pub fn begin_rebase_pending(&self, request: PendingRebaseRequest) -> RepositoryResult<Value> {
        validate_head_identity(&request.branch)?;
        for id in [&request.head, &request.upstream, &request.onto] {
            require_id(id)?;
        }
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if self.read_pending()?.is_some() {
            return Err(
                "a conflict operation is already pending; continue, abort or quit it first".into(),
            );
        }
        check_expected_branch(&snapshot.manifest.head, Some(&request.branch))?;
        check_expected(snapshot.manifest.tip(), Some(&request.head))?;
        let (fork_base, queue) = rebase_queue(&snapshot, &request.head, &request.upstream)?;
        let mut pending = PendingOperation {
            version: 1,
            id: format!(
                "{:x}",
                Sha256::digest(unique_name("pending-rebase").as_bytes())
            ),
            operation: "rebase".into(),
            branch: request.branch,
            head: request.head.clone(),
            target: request.head,
            base: None,
            selected_parent: None,
            mainline: None,
            message: String::new(),
            baseline_index: request.baseline_index,
            legacy_path: request.legacy_path,
            prepared: None,
            rebase: Some(PendingRebase {
                upstream: request.upstream,
                onto: request.onto.clone(),
                fork_base,
                queue,
                cursor: 0,
                progress_tip: request.onto,
                steps: Vec::new(),
                prepared_action: None,
            }),
        };
        bind_rebase_source(&snapshot, &mut pending)?;
        encode_pending(&pending)?;
        validate_rebase_anchors(&snapshot, &pending)?;
        self.advance_rebase_pending(snapshot, pending, "begin", None)
    }

    /// Treat this complete index as the current stopped source's result, then
    /// automatically replay subsequent sources until another conflict or end.
    pub fn continue_rebase_pending(
        &self,
        expected: &PendingOperation,
        index: Option<PendingIndex<'_>>,
    ) -> RepositoryResult<Value> {
        self.change_rebase_pending(expected, "continue", index)
    }

    /// Skip exactly the currently stopped source, without decoding the index.
    pub fn skip_rebase_pending(&self, expected: &PendingOperation) -> RepositoryResult<Value> {
        self.change_rebase_pending(expected, "skip", None)
    }

    fn change_rebase_pending(
        &self,
        expected: &PendingOperation,
        action: &str,
        index: Option<PendingIndex<'_>>,
    ) -> RepositoryResult<Value> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let pending = self.checked_pending(&snapshot, expected)?;
        if pending.operation != "rebase" || pending.rebase.is_none() {
            return Err("the saved operation is not a linear rebase".into());
        }
        check_pending_head(&snapshot, &pending)?;
        let already_published = pending
            .prepared
            .as_ref()
            .is_some_and(|prepared| snapshot.manifest.tip() == Some(&prepared.commit));
        if !already_published {
            check_expected(snapshot.manifest.tip(), Some(&pending.head))?;
        }
        if pending.prepared.is_some() {
            return self.finish_rebase_pending(
                &snapshot,
                &pending,
                index.as_ref(),
                already_published,
                true,
            );
        }
        self.advance_rebase_pending(snapshot, pending, action, index)
    }

    fn advance_rebase_pending(
        &self,
        mut snapshot: Snapshot,
        mut pending: PendingOperation,
        action: &str,
        index: Option<PendingIndex<'_>>,
    ) -> RepositoryResult<Value> {
        let mut encoded = BTreeMap::new();
        let mut commits = Vec::new();
        if action != "begin" {
            let rebase = pending
                .rebase
                .as_ref()
                .ok_or("missing linear replay state")?;
            let source = rebase
                .queue
                .get(rebase.cursor)
                .ok_or("no stopped rebase source")?
                .clone();
            let before = rebase.progress_tip.clone();
            let (commit, index_sha256) = if action == "continue" {
                let index = index.as_ref().ok_or(
                    "rebase continuation requires an existing explicitly reviewed complete index",
                )?;
                crate::porcelain::validate_pending_resolution_index(
                    index.raw,
                    index.files,
                    index.legacy_path,
                )?;
                if index.legacy_path != pending.legacy_path.as_deref() {
                    return Err(
                        "resolved index changed the rebase's original legacy path anchor".into(),
                    );
                }
                // Audit the exact supplied tree before installing any object.
                rebase_manual_resolution(&snapshot, &pending, &source, &before, index.files)?;
                let commit = stage_rebase_commit(
                    &mut snapshot,
                    &mut encoded,
                    &mut commits,
                    index.files,
                    &source,
                    &before,
                    pending.legacy_path.as_deref(),
                )?;
                (
                    Some(commit),
                    Some(format!("{:x}", Sha256::digest(index.raw))),
                )
            } else if action == "skip" {
                (None, None)
            } else {
                return Err("unsupported rebase continuation action".into());
            };
            let rebase = pending
                .rebase
                .as_mut()
                .ok_or("missing linear replay state")?;
            if let Some(commit) = &commit {
                rebase.progress_tip = commit.clone();
            }
            rebase.steps.push(PendingRebaseStep {
                source,
                before,
                commit,
                action: if action == "continue" {
                    "manual"
                } else {
                    "skipped"
                }
                .into(),
                index_sha256,
            });
            rebase.cursor += 1;
        }
        let mut reports = Vec::new();
        loop {
            let rebase = pending
                .rebase
                .as_ref()
                .ok_or("missing linear replay state")?;
            let Some(source) = rebase.queue.get(rebase.cursor).cloned() else {
                break;
            };
            let before = rebase.progress_tip.clone();
            let parent = rebase_source_parent(&snapshot, &source)?;
            let merged = merge_rebase_files(
                &snapshot,
                &parent,
                &before,
                &source,
                pending.legacy_path.as_deref(),
            )?;
            if merged
                .reports
                .iter()
                .any(|report| report.status == "conflict")
            {
                reports = merged.reports;
                break;
            }
            let commit = stage_rebase_commit(
                &mut snapshot,
                &mut encoded,
                &mut commits,
                &merged.files,
                &source,
                &before,
                pending.legacy_path.as_deref(),
            )?;
            let rebase = pending
                .rebase
                .as_mut()
                .ok_or("missing linear replay state")?;
            rebase.steps.push(PendingRebaseStep {
                source,
                before,
                commit: Some(commit.clone()),
                action: "automatic".into(),
                index_sha256: None,
            });
            rebase.cursor += 1;
            rebase.progress_tip = commit;
        }
        bind_rebase_source(&snapshot, &mut pending)?;
        let rebase = pending
            .rebase
            .as_mut()
            .ok_or("missing linear replay state")?;
        let complete = rebase.cursor == rebase.queue.len();
        if complete {
            rebase.prepared_action = Some(action.into());
            pending.prepared = Some(PendingPrepared {
                commit: rebase.progress_tip.clone(),
                index_sha256: if action == "continue" {
                    rebase
                        .steps
                        .iter()
                        .rev()
                        .find_map(|step| step.index_sha256.clone())
                        .ok_or("manual rebase finalization lacks its reviewed index digest")?
                } else {
                    // Begin/skip do not consume an index. prepared_action is
                    // explicit, so this sentinel can never become a lease.
                    format!("{:x}", Sha256::digest(b""))
                },
            });
        }
        validate_pending_snapshot(&snapshot, &pending)?;
        if action == "begin" && complete {
            // Ordinary begin will synchronize its successful checkout. Its
            // safety check must precede object, journal and ref publication;
            // explicit continue/skip intentionally preserve all working bytes.
            let tip = pending
                .rebase
                .as_ref()
                .ok_or("missing linear replay state")?;
            crate::porcelain::assert_worktree_revision_safe(
                self,
                &snapshot_files(&snapshot, &tip.progress_tip)?,
            )?;
        }
        let bytes = encode_pending(&pending)?;
        // All reports and journal bounds are checked before installing even
        // unreachable objects, and the branch remains its original tip.
        let report = rebase_pending_report(&snapshot, &pending, &reports, false, false, None)?;
        self.install_tree_objects(&encoded, &commits).map_err(|error| format!(
            "rebase objects may be partly installed; original branch and pending journal were not advanced: {error}"))?;
        self.publish_pending(&bytes, if complete { "prepare final rebase" } else { "record rebase conflict" })
            .map_err(|error| format!("rebase progress objects are installed; journal publication may have occurred, original branch is unchanged; inspect status before retrying: {error}"))?;
        if complete {
            self.finish_rebase_pending(&snapshot, &pending, index.as_ref(), false, false)
        } else {
            Ok(report)
        }
    }

    fn finish_rebase_pending(
        &self,
        snapshot: &Snapshot,
        pending: &PendingOperation,
        index: Option<&PendingIndex<'_>>,
        already_published: bool,
        resumed_prepared: bool,
    ) -> RepositoryResult<Value> {
        let prepared = pending
            .prepared
            .as_ref()
            .ok_or("final rebase is not prepared")?;
        let rebase = pending
            .rebase
            .as_ref()
            .ok_or("missing linear replay state")?;
        let uses_index = rebase.prepared_action.as_deref() == Some("continue");
        let matches = if uses_index {
            index.map(|index| format!("{:x}", Sha256::digest(index.raw)) == prepared.index_sha256)
        } else {
            None
        };
        if uses_index && !already_published {
            let index = index.ok_or("prepared rebase requires its reviewed index; retry --continue --resolved-index rather than --skip")?;
            crate::porcelain::validate_pending_resolution_index(
                index.raw,
                index.files,
                index.legacy_path,
            )?;
            let manual = rebase
                .steps
                .iter()
                .rev()
                .find(|step| step.action == "manual")
                .ok_or("prepared rebase lacks its manual resolution")?;
            let commit = manual
                .commit
                .as_deref()
                .ok_or("manual replay lacks its immutable result")?;
            let files = snapshot_files(snapshot, commit)?;
            if matches != Some(true)
                || index.legacy_path != pending.legacy_path.as_deref()
                || index.files != &files.files
            {
                return Err("index changed after final rebase preparation; no reference published; inspect its saved manual result or abort/quit".into());
            }
        }
        let report = rebase_pending_report(
            snapshot,
            pending,
            &[],
            already_published,
            resumed_prepared,
            matches,
        )?;
        let operation = format!("pending-continue-{}", pending.id);
        if !already_published {
            self.write_named_ref("refs", &pending.branch, &prepared.commit, &operation)
                .map_err(|error| format!("final rebase {} is durable; reference publication or reflog may be incomplete: {error}; inspect status and retry the saved operation", prepared.commit))?;
        }
        self.ensure_pending_reflog(pending, &prepared.commit, &operation)
            .map_err(|error| format!("final rebase {} is published; pending state is retained because reflog repair failed: {error}; inspect and retry continuation", prepared.commit))?;
        self.remove_pending_checked(pending)
            .map_err(|error| format!("final rebase {} is published; clearing pending state failed or durability is uncertain: {error}; inspect before retrying", prepared.commit))?;
        Ok(report)
    }

    /// Restore only the saved index and original tracked working files. The
    /// callback cannot reenter repository methods: the writer lock is held from
    /// binding checks through restoration and final journal removal.
    pub fn abort_pending(
        &self,
        expected: &PendingOperation,
        restore: impl FnOnce(&PendingOperation, &RevisionFiles) -> RepositoryResult<()>,
    ) -> RepositoryResult<()> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let pending = self.checked_pending(&snapshot, expected)?;
        check_pending_head(&snapshot, &pending)?;
        check_expected(snapshot.manifest.tip(), Some(&pending.head))?;
        let head = snapshot_files(&snapshot, &pending.head)?;
        restore(&pending, &head).map_err(|error| {
            format!("pending state retained; abort restoration may be partly completed: {error}")
        })?;
        self.remove_pending_checked(&pending)
            .map_err(|error| format!("original tracked files and index were restored; pending removal failed or its durability is uncertain: {error}"))
    }

    /// Forget a local operation without touching refs, index or working files.
    /// A stale branch binding is allowed; the exact journal still has a lease.
    pub fn quit_pending(&self, expected: &PendingOperation) -> RepositoryResult<()> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let pending = self.checked_pending(&snapshot, expected)?;
        self.remove_pending_checked(&pending)
    }

    pub fn tags(&self) -> RepositoryResult<BTreeMap<String, String>> {
        Ok(self.state()?.tags)
    }

    pub fn create_tag(&self, name: &str, revision: &str) -> RepositoryResult<String> {
        validate_ref_name(name)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if snapshot.manifest.tags.contains_key(name) {
            return Err(format!("tag {name} already exists"));
        }
        let id = snapshot_revision(&snapshot, revision)?;
        self.write_named_ref("tags", name, &id, "tag")?;
        Ok(id)
    }

    pub fn delete_tag(&self, name: &str) -> RepositoryResult<String> {
        validate_ref_name(name)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let id = snapshot
            .manifest
            .tags
            .get(name)
            .ok_or_else(|| format!("unknown tag: {name}"))?
            .clone();
        self.remove_named_ref("tags", name, &id, "delete-tag")?;
        Ok(id)
    }

    pub fn delete_branch(&self, name: &str, force: bool) -> RepositoryResult<String> {
        validate_ref_name(name)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if snapshot.manifest.head == name {
            return Err(format!("cannot delete the checked-out branch {name}"));
        }
        let id = snapshot
            .manifest
            .refs
            .get(name)
            .ok_or_else(|| format!("unknown branch: {name}"))?
            .clone();
        if !force {
            let head = snapshot
                .upstream_tips
                .get(name)
                .and_then(|result| result.as_ref().ok())
                .or_else(|| snapshot.manifest.tip())
                .ok_or(
                    "cannot establish merged ancestry from an unborn HEAD; use force explicitly",
                )?;
            if !is_ancestor(&id, head, &snapshot.objects)? {
                return Err(format!(
                    "branch {name} is not fully merged into HEAD; use force explicitly"
                ));
            }
        }
        self.remove_named_ref("refs", name, &id, "delete-branch")?;
        Ok(id)
    }

    /// Rename under the writer lock. Publish the replacement branch first,
    /// atomically move its local association, then update HEAD and remove the old
    /// branch. I/O errors can leave both names; messages identify completed steps.
    pub fn rename_branch(&self, old: &str, new: &str) -> RepositoryResult<()> {
        self.rename_branch_mode(old, new, false, false)
    }

    pub fn rename_branch_mode(
        &self,
        old: &str,
        new: &str,
        force: bool,
        copy: bool,
    ) -> RepositoryResult<()> {
        validate_ref_name(old)?;
        validate_ref_name(new)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if !copy {
            self.assert_branch_available(old)?;
        }
        self.assert_branch_available(new)?;
        if old == new {
            return Err("old and new branch names are identical".into());
        }
        if (!force && snapshot.manifest.refs.contains_key(new)) || snapshot.manifest.head == new {
            return Err(format!("branch {new} already exists"));
        }
        let id = snapshot.manifest.refs.get(old).cloned();
        if copy && id.is_none() {
            return Err("copy requires a committed source branch".into());
        }
        if id.is_none() && snapshot.manifest.head != old {
            return Err(format!("unknown branch: {old}"));
        }
        let original = snapshot.upstreams.clone();
        let mut upstreams = original.clone();
        let binding = if copy {
            upstreams.get(old).cloned()
        } else {
            upstreams.remove(old)
        };
        if force {
            upstreams.remove(new);
        }
        if let Some(upstream) = binding {
            upstreams.insert(new.into(), upstream);
        }
        let moved_upstream = upstreams != original;
        // Size and naming failures must precede the first replacement ref.
        let upstream_bytes = if moved_upstream {
            Some(encode_upstreams(&upstreams)?)
        } else {
            None
        };
        if let Some(id) = &id {
            self.write_named_ref("refs", new, id, "rename-branch-create")
                .map_err(|error| format!("rename branch {old} -> {new}: the replacement reference may have been published; the original branch and its upstream association have not been removed: {error}"))?;
        }
        if let Some(bytes) = &upstream_bytes {
            self.publish_upstreams(bytes, "rename branch upstream association")
                .map_err(|error| format!("replacement branch {new} is present and original branch {old} is retained; moving its upstream association did not complete durably: {error}"))?;
        }
        if !copy && snapshot.manifest.head == old {
            self.register_selected_branch(new)?;
            self.atomic_write(&self.metadata.join("HEAD"), format!("{new}\n").as_bytes())
                .map_err(|error| format!("rename branch {old} -> {new}: replacement branch and any upstream move were published, but HEAD publication is uncertain; the original branch has not been removed: {error}"))?;
            self.record_reflog(
                "HEAD",
                id.clone(),
                id.clone(),
                &format!("rename {old} -> {new}"),
            ).map_err(|error| format!("rename branch {old} -> {new}: HEAD and any upstream move were published; the original branch has not been removed: {error}"))?;
            self.record_head_event(id.clone(), id.clone(), &format!("rename {old} -> {new}"))?;
        }
        if let Some(id) = &id.filter(|_| !copy) {
            self.remove_named_ref("refs", old, id, "rename-branch-remove")
                .map_err(|error| format!("rename branch {old} -> {new}: replacement branch and any upstream move were published; removal of the original branch or its reflog may be incomplete: {error}"))?;
        }
        Ok(())
    }

    pub fn force_branch(&self, name: &str, revision: &str) -> RepositoryResult<String> {
        validate_ref_name(name)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        if snapshot.manifest.head == name {
            return Err("cannot force-update the current branch".into());
        }
        self.assert_branch_available(name)?;
        let id = snapshot_revision(&snapshot, revision)?;
        self.write_named_ref("refs", name, &id, "branch-force")?;
        Ok(id)
    }

    /// Explicit history rewrite guarded by an exact current-HEAD comparison.
    /// None requires an unborn branch; it is never an unchecked overwrite.
    #[cfg(test)]
    pub fn reset_head(&self, revision: &str, expected: Option<&str>) -> RepositoryResult<String> {
        self.reset_checked(revision, None, expected)
    }

    pub fn reset_on_branch(
        &self,
        revision: &str,
        expected_branch: &str,
        expected: Option<&str>,
    ) -> RepositoryResult<String> {
        validate_head_identity(expected_branch)?;
        self.reset_checked(revision, Some(expected_branch), expected)
    }

    fn reset_checked(
        &self,
        revision: &str,
        expected_branch: Option<&str>,
        expected: Option<&str>,
    ) -> RepositoryResult<String> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        check_expected_branch(&snapshot.manifest.head, expected_branch)?;
        check_expected(snapshot.manifest.tip(), expected)?;
        let id = snapshot_revision(&snapshot, revision)?;
        self.write_named_ref("refs", &snapshot.manifest.head, &id, "reset")?;
        Ok(id)
    }

    /// Record supplied bytes with explicitly selected parents, guarded against a
    /// concurrent HEAD update. Commit encoding and existing object IDs stay v1.
    #[cfg(test)]
    pub fn commit_explicit(
        &self,
        bytes: &[u8],
        message: &str,
        parents: &[String],
        expected: Option<&str>,
    ) -> RepositoryResult<String> {
        self.commit_checked(bytes, message, parents, None, expected)
    }

    pub fn commit_on_branch(
        &self,
        bytes: &[u8],
        message: &str,
        parents: &[String],
        expected_branch: &str,
        expected: Option<&str>,
    ) -> RepositoryResult<String> {
        validate_head_identity(expected_branch)?;
        self.commit_checked(bytes, message, parents, Some(expected_branch), expected)
    }

    fn commit_checked(
        &self,
        bytes: &[u8],
        message: &str,
        parents: &[String],
        expected_branch: Option<&str>,
        expected: Option<&str>,
    ) -> RepositoryResult<String> {
        validate_wasm_header(bytes)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        check_expected_branch(&snapshot.manifest.head, expected_branch)?;
        check_expected(snapshot.manifest.tip(), expected)?;
        require_legacy_head(&snapshot)?;
        let mut seen = BTreeSet::new();
        for parent in parents {
            require_id(parent)?;
            if !seen.insert(parent) {
                return Err("duplicate explicit commit parent".into());
            }
            match snapshot.objects.get(parent) {
                Some(Object::Commit(commit)) => require_legacy_commit(commit)?,
                _ => return Err(format!("missing explicit parent commit {parent}")),
            }
        }
        let wasm = self.store_object(WASM_KIND, bytes)?;
        let commit = Commit {
            format: 1,
            tree: None,
            legacy_path: None,
            wasm,
            parents: parents.to_vec(),
            message: message.into(),
        };
        let id = self.store_object(COMMIT_KIND, &encode_commit(&commit)?)?;
        self.write_named_ref("refs", &snapshot.manifest.head, &id, "commit-explicit")?;
        Ok(id)
    }

    /// Install a complete replay chain and publish its final tip once. Semantic
    /// rejection is side-effect free; an I/O failure can leave valid dangling
    /// objects, but never publishes an intermediate replay commit as HEAD.
    #[cfg(test)]
    pub fn replay_commits(
        &self,
        expected: Option<&str>,
        base: &str,
        commits: &[(Vec<u8>, String)],
    ) -> RepositoryResult<Vec<String>> {
        self.replay_checked(None, expected, base, commits)
    }

    pub fn replay_on_branch(
        &self,
        expected_branch: &str,
        expected: Option<&str>,
        base: &str,
        commits: &[(Vec<u8>, String)],
    ) -> RepositoryResult<Vec<String>> {
        validate_head_identity(expected_branch)?;
        self.replay_checked(Some(expected_branch), expected, base, commits)
    }

    fn replay_checked(
        &self,
        expected_branch: Option<&str>,
        expected: Option<&str>,
        base: &str,
        commits: &[(Vec<u8>, String)],
    ) -> RepositoryResult<Vec<String>> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        check_expected_branch(&snapshot.manifest.head, expected_branch)?;
        check_expected(snapshot.manifest.tip(), expected)?;
        require_legacy_head(&snapshot)?;
        let mut parent = snapshot_revision(&snapshot, base)?;
        if let Some(Object::Commit(commit)) = snapshot.objects.get(&parent) {
            require_legacy_commit(commit)?;
        }
        let mut encoded = BTreeMap::new();
        let mut ids = Vec::with_capacity(commits.len());
        for (bytes, message) in commits {
            validate_wasm_header(bytes)?;
            let blob = encode_object(WASM_KIND, bytes)?;
            let wasm = object_id(&blob);
            encoded.insert(wasm.clone(), blob);
            let commit = Commit {
                format: 1,
                tree: None,
                legacy_path: None,
                wasm,
                parents: vec![parent],
                message: message.clone(),
            };
            let object = encode_object(COMMIT_KIND, &encode_commit(&commit)?)?;
            parent = object_id(&object);
            encoded.insert(parent.clone(), object);
            ids.push(parent.clone());
        }
        for (id, bytes) in &encoded {
            if snapshot
                .encoded
                .get(id)
                .is_some_and(|existing| existing != bytes)
            {
                return Err(format!("object collision at {id}"));
            }
        }
        if ids.is_empty() {
            return Ok(ids);
        }
        self.install_tree_objects(&encoded, &ids)?;
        self.write_named_ref("refs", &snapshot.manifest.head, &parent, "replay")?;
        Ok(ids)
    }

    pub fn reflog(&self) -> RepositoryResult<Vec<ReflogEntry>> {
        let _lock = self.lock()?;
        self.snapshot()?;
        self.read_reflog()
    }

    /// None transfers the entire verified store and all refs, including unborn
    /// HEAD. A selected revision transfers exactly its ancestor/blob closure;
    /// transfer HEAD is a synthetic branch and only tags in that closure remain.
    pub fn bundle_bytes(
        &self,
        revision: Option<&str>,
    ) -> RepositoryResult<(RepositoryState, Vec<u8>)> {
        let _lock = self.lock()?;
        let mut snapshot = self.snapshot()?;
        if let Some(revision) = revision {
            let tip = snapshot_revision(&snapshot, revision)?;
            let commits = ancestors(&tip, &snapshot.objects)?;
            let mut closure = commits.clone();
            for id in &commits {
                let Some(Object::Commit(commit)) = snapshot.objects.get(id) else {
                    return Err(format!("missing transfer commit {id}"));
                };
                let content = commit.tree.as_ref().unwrap_or(&commit.wasm);
                closure.insert(content.clone());
                if let Some(Object::Tree(tree)) = snapshot.objects.get(content) {
                    closure.extend(tree.entries.values().cloned());
                }
            }
            snapshot.encoded.retain(|id, _| closure.contains(id));
            snapshot.objects.retain(|id, _| closure.contains(id));
            snapshot.manifest.head = "transfer".into();
            snapshot.manifest.refs = BTreeMap::from([("transfer".into(), tip)]);
            snapshot.manifest.tags.retain(|_, id| commits.contains(id));
            snapshot.manifest.format = manifest_format(
                &snapshot.manifest.head,
                &snapshot.manifest.tags,
                &snapshot.objects,
            );
        }
        Ok((
            manifest_state(&snapshot.manifest),
            encode_bundle(&snapshot)?,
        ))
    }

    /// Inspect a complete transfer before trusting its separately advertised state.
    pub fn bundle_state(bytes: &[u8]) -> RepositoryResult<RepositoryState> {
        Ok(manifest_state(&decode_bundle(bytes)?.manifest))
    }

    /// Fetch installation deliberately does not change branches, tags or HEAD.
    /// Every incoming and local object is checked before the first installation.
    pub fn install_bundle_bytes(&self, bytes: &[u8]) -> RepositoryResult<RepositoryState> {
        let incoming = decode_bundle(bytes)?;
        let _lock = self.lock()?;
        let current = self.snapshot()?;
        check_collisions(&current, &incoming)?;
        self.install_snapshot_objects(&incoming)?;
        Ok(manifest_state(&incoming.manifest))
    }

    /// String-error compatibility API; services use the typed checked variant.
    #[allow(dead_code)]
    pub fn receive_bundle(
        &self,
        bytes: &[u8],
        branch: &str,
        expected: Option<&str>,
        force: bool,
    ) -> RepositoryResult<String> {
        self.receive_bundle_checked(bytes, branch, expected, force)
            .map_err(|error| error.message)
    }

    pub fn receive_bundle_checked(
        &self,
        bytes: &[u8],
        branch: &str,
        expected: Option<&str>,
        force: bool,
    ) -> Result<String, ReceiveError> {
        let tip = receive_result(
            (|| {
                let incoming = decode_bundle(bytes)?;
                incoming
                    .manifest
                    .tip()
                    .cloned()
                    .ok_or("bundle has no commit at its HEAD branch".into())
            })(),
            false,
        )?;
        self.receive_ref_bundle_checked(bytes, "branch", branch, expected, Some(&tip), force)?
            .ok_or_else(|| ReceiveError {
                message: "receive unexpectedly deleted its branch".into(),
                publication_unknown: true,
            })
    }

    /// Publish one explicitly leased branch or lightweight tag. This is a
    /// single-ref transaction; callers updating several refs must report each
    /// outcome rather than claim the entire batch is atomic. Deletions carry no
    /// bundle and never delete objects. Tag replacement requires explicit force.
    #[allow(dead_code)]
    pub fn receive_ref_bundle(
        &self,
        bytes: &[u8],
        namespace: &str,
        name: &str,
        expected: Option<&str>,
        new: Option<&str>,
        force: bool,
    ) -> RepositoryResult<Option<String>> {
        self.receive_ref_bundle_checked(bytes, namespace, name, expected, new, force)
            .map_err(|error| error.message)
    }

    pub fn receive_ref_bundle_checked(
        &self,
        bytes: &[u8],
        namespace: &str,
        name: &str,
        expected: Option<&str>,
        new: Option<&str>,
        force: bool,
    ) -> Result<Option<String>, ReceiveError> {
        let mut publishing = false;
        let result: RepositoryResult<Option<String>> = (|| {
            validate_ref_name(name)?;
            let directory = match namespace {
                "branch" => "refs",
                "tag" => "tags",
                _ => return Err("unknown receive reference namespace".into()),
            };
            let incoming = if let Some(new) = new {
                require_id(new)?;
                let incoming = decode_bundle(bytes)?;
                if !matches!(incoming.objects.get(new), Some(Object::Commit(_))) {
                    return Err(format!("incoming bundle lacks requested commit {new}"));
                }
                Some(incoming)
            } else {
                if !bytes.is_empty() {
                    return Err("reference deletion requires an empty payload".into());
                }
                None
            };
            let _index_lock = self.lock_named("index.lock")?;
            let _lock = self.lock()?;
            let current = self.snapshot()?;
            if namespace == "branch" && current.manifest.head == name {
                match fs::symlink_metadata(self.metadata.join("index")) {
                Ok(_) => return Err("cannot receive into the checked-out branch of a tracked worktree; use a separate server repository".into()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => return Err(io_error("inspect worktree index", &self.metadata.join("index"), e)),
            }
            }
            let refs = if namespace == "branch" {
                &current.manifest.refs
            } else {
                &current.manifest.tags
            };
            let old = refs.get(name);
            check_expected(old, expected)?;
            if let Some(incoming) = incoming {
                check_collisions(&current, &incoming)?;
                let new = new.ok_or("missing receive target")?;
                if let Some(old) = old {
                    if !force && namespace == "branch" && !is_ancestor(old, new, &incoming.objects)?
                    {
                        return Err(format!("refusing non-fast-forward update of {name}"));
                    }
                    if !force && namespace == "tag" && old != new {
                        return Err(format!(
                            "refusing to replace tag {name} without an explicit force lease"
                        ));
                    }
                }
                self.install_snapshot_objects(&incoming)?;
                publishing = true;
                self.write_named_ref(
                    directory,
                    name,
                    new,
                    if force { "receive-force" } else { "receive" },
                )?;
                Ok(Some(new.into()))
            } else {
                if namespace == "branch" && current.manifest.head == name {
                    return Err(format!("cannot delete the checked-out branch {name}"));
                }
                let old = old.ok_or_else(|| format!("cannot delete missing {namespace} {name}"))?;
                publishing = true;
                self.remove_named_ref(directory, name, old, "receive-delete")?;
                Ok(None)
            }
        })();
        receive_result(result, publishing)
    }

    pub fn clone_bundle_bytes(
        bytes: &[u8],
        destination: impl AsRef<Path>,
    ) -> RepositoryResult<Self> {
        // Reject malformed input before even reserving the destination directory.
        let snapshot = decode_bundle(bytes)?;
        let destination = destination.as_ref();
        fs::create_dir(destination)
            .map_err(|e| io_error("create clone destination", destination, e))?;
        let repo = Self::init(destination)?;
        {
            let _lock = repo.lock()?;
            repo.install_snapshot_objects(&snapshot)?;
            for (name, id) in &snapshot.manifest.refs {
                repo.write_named_ref("refs", name, id, "clone")?;
            }
            for (name, id) in &snapshot.manifest.tags {
                repo.write_named_ref("tags", name, id, "clone")?;
            }
            if snapshot.manifest.head != "main" {
                repo.atomic_write(
                    &repo.metadata.join("HEAD"),
                    format!("{}\n", snapshot.manifest.head).as_bytes(),
                )?;
                repo.record_reflog(
                    "HEAD",
                    snapshot.manifest.refs.get("main").cloned(),
                    snapshot.manifest.tip().cloned(),
                    "clone-head",
                )?;
                repo.record_head_event(
                    snapshot.manifest.refs.get("main").cloned(),
                    snapshot.manifest.tip().cloned(),
                    "clone-head",
                )?;
            }
        }
        Ok(repo)
    }

    fn lock(&self) -> RepositoryResult<WriteLock> {
        self.lock_named("write.lock")
    }

    fn lock_named(&self, name: &str) -> RepositoryResult<WriteLock> {
        let directory = if name == "write.lock" {
            &self.common_metadata
        } else {
            &self.metadata
        };
        let path = directory.join(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "repository is locked: {}; if a writer crashed, inspect and remove this lock manually",
                        path.display()
                    )
                } else {
                    io_error("lock repository", &path, e)
                }
            })?;
        let mut lock = WriteLock { path, _file: file };
        writeln!(lock._file, "{}", std::process::id())
            .map_err(|e| format!("write repository lock: {e}"))?;
        lock._file
            .sync_all()
            .map_err(|e| format!("sync repository lock: {e}"))?;
        Ok(lock)
    }

    /// Return the exact stored payload after full-store verification.
    pub fn cat_object(&self, id: &str) -> RepositoryResult<(String, Vec<u8>)> {
        require_id(id)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let kind = match snapshot.objects.get(id) {
            Some(Object::Wasm(_)) => "wasm",
            Some(Object::Commit(_)) => "commit",
            Some(Object::Tree(_)) => "tree",
            None => return Err(format!("unknown object: {id}")),
        };
        let encoded = snapshot.encoded.get(id).ok_or("missing encoded object")?;
        Ok((kind.into(), encoded[OBJECT_HEADER_LENGTH..].to_vec()))
    }

    fn read_bisect(&self) -> RepositoryResult<Option<BisectState>> {
        let path = self.metadata.join("bisect.json");
        let metadata = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("inspect bisect metadata", &path, error)),
            Ok(metadata) => metadata,
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("bisect journal must be a regular file".into());
        }
        if metadata.len() > MAX_BISECT_BYTES {
            return Err("bisect journal exceeds the 1 MiB encoded limit".into());
        }
        let file =
            File::open(&path).map_err(|error| io_error("open bisect metadata", &path, error))?;
        if !file
            .metadata()
            .map_err(|error| io_error("inspect opened bisect metadata", &path, error))?
            .is_file()
        {
            return Err("opened bisect journal is not a regular file".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BISECT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read bisect metadata", &path, error))?;
        if bytes.len() as u64 > MAX_BISECT_BYTES {
            return Err("bisect journal exceeds the 1 MiB encoded limit".into());
        }
        let state: BisectState = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid bisect journal: {error}"))?;
        if encode_bisect(&state)? != bytes {
            return Err("non-canonical or duplicate-key bisect journal".into());
        }
        Ok(Some(state))
    }

    fn publish_bisect(&self, bytes: &[u8]) -> RepositoryResult<()> {
        if bytes.len() as u64 > MAX_BISECT_BYTES {
            return Err("bisect journal exceeds the 1 MiB encoded limit".into());
        }
        self.atomic_write(&self.metadata.join("bisect.json"), bytes)
            .map_err(|error| format!("bisect metadata may already have been published: {error}; inspect bisect status before retrying"))
    }

    fn read_pending(&self) -> RepositoryResult<Option<PendingOperation>> {
        let path = self.metadata.join("pending.json");
        let metadata = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("inspect pending operation", &path, error)),
            Ok(metadata) => metadata,
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("pending operation must be a regular file".into());
        }
        if metadata.len() > MAX_PENDING_BYTES {
            return Err("pending operation exceeds the 64 MiB encoded journal limit".into());
        }
        let file =
            File::open(&path).map_err(|error| io_error("open pending operation", &path, error))?;
        if !file
            .metadata()
            .map_err(|error| io_error("inspect opened pending operation", &path, error))?
            .is_file()
        {
            return Err("opened pending operation is not a regular file".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_PENDING_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read pending operation", &path, error))?;
        if bytes.len() as u64 > MAX_PENDING_BYTES {
            return Err("pending operation exceeds the 64 MiB encoded journal limit".into());
        }
        let pending: PendingOperation = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid pending operation: {error}"))?;
        if encode_pending(&pending)? != bytes {
            return Err("non-canonical or duplicate-key pending operation".into());
        }
        Ok(Some(pending))
    }

    fn checked_pending(
        &self,
        snapshot: &Snapshot,
        expected: &PendingOperation,
    ) -> RepositoryResult<PendingOperation> {
        let pending = self
            .read_pending()?
            .ok_or("no conflict operation is pending")?;
        if &pending != expected {
            return Err(
                "pending operation changed; no continuation or restoration published".into(),
            );
        }
        validate_pending_snapshot(snapshot, &pending)?;
        Ok(pending)
    }

    fn publish_pending(&self, bytes: &[u8], operation: &str) -> RepositoryResult<()> {
        self.atomic_write(&self.metadata.join("pending.json"), bytes)
            .map_err(|error| format!("{operation}: pending metadata may already have been published: {error}; inspect status before retrying"))
    }

    fn remove_pending_checked(&self, expected: &PendingOperation) -> RepositoryResult<()> {
        if self.read_pending()?.as_ref() != Some(expected) {
            return Err("pending operation changed before removal; no state removed".into());
        }
        let path = self.metadata.join("pending.json");
        fs::remove_file(&path)
            .map_err(|error| io_error("remove pending operation", &path, error))?;
        sync_directory(&self.metadata)
            .map_err(|error| format!("pending operation was removed but its directory could not be synced: {error}; removal durability is uncertain"))
    }

    fn ensure_pending_reflog(
        &self,
        pending: &PendingOperation,
        commit: &str,
        operation: &str,
    ) -> RepositoryResult<()> {
        let reference = if valid_id(&pending.branch) {
            "HEAD".into()
        } else {
            format!("refs/heads/{}", pending.branch)
        };
        let entries = self.read_reflog()?;
        let matches: Vec<_> = entries
            .iter()
            .filter(|entry| entry.operation == operation)
            .collect();
        match matches.as_slice() {
            [] => self.record_reflog(
                &reference,
                Some(pending.head.clone()),
                Some(commit.to_owned()),
                operation,
            ),
            [entry]
                if entry.reference == reference
                    && entry.old.as_deref() == Some(pending.head.as_str())
                    && entry.new.as_deref() == Some(commit) =>
            {
                Ok(())
            }
            _ => Err("the pending generation has conflicting or duplicate reflog entries".into()),
        }
        .and_then(|()| {
            self.record_head_event(Some(pending.head.clone()), Some(commit.into()), operation)
        })
    }

    fn read_upstreams(
        &self,
        branches: &BTreeMap<String, String>,
    ) -> RepositoryResult<BTreeMap<String, Upstream>> {
        let path = self.common_metadata.join("upstreams.json");
        let metadata = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(io_error("inspect upstream configuration", &path, error)),
            Ok(metadata) => metadata,
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "expected a regular upstream configuration file: {}",
                path.display()
            ));
        }
        if metadata.len() > MAX_UPSTREAM_BYTES {
            return Err("upstream configuration exceeds the 1 MiB limit".into());
        }
        let file =
            File::open(&path).map_err(|e| io_error("open upstream configuration", &path, e))?;
        if !file
            .metadata()
            .map_err(|e| io_error("inspect opened upstream configuration", &path, e))?
            .is_file()
        {
            return Err("opened upstream configuration is not a regular file".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_UPSTREAM_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error("read upstream configuration", &path, e))?;
        if bytes.len() as u64 > MAX_UPSTREAM_BYTES {
            return Err("upstream configuration exceeds the 1 MiB limit".into());
        }
        let record: UpstreamFile = serde_json::from_slice(&bytes)
            .map_err(|e| format!("invalid upstream configuration: {e}"))?;
        if record.version != 1 {
            return Err("unsupported upstream configuration version".into());
        }
        if encode_upstreams(&record.branches)? != bytes {
            return Err("non-canonical or duplicate-key upstream configuration".into());
        }
        for local in record.branches.keys() {
            if !branches.contains_key(local) {
                return Err(format!(
                    "upstream association refers to missing or unborn local branch {local}"
                ));
            }
        }
        Ok(record.branches)
    }

    /// A failed atomic write can have reached rename or directory sync. Never
    /// describe such an I/O outcome as a rolled-back association change.
    fn publish_upstreams(&self, bytes: &[u8], operation: &str) -> RepositoryResult<()> {
        self.atomic_write(&self.common_metadata.join("upstreams.json"), bytes)
            .map_err(|error| format!("{operation}: upstream metadata publication may have occurred: {error}; inspect .uwgit/upstreams.json before retrying"))
    }

    fn read_tracking(
        &self,
        objects: &BTreeMap<String, Object>,
    ) -> RepositoryResult<BTreeMap<String, String>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Tracking {
            version: u32,
            remote: String,
            url: String,
            state: RepositoryState,
        }
        let path = self.common_metadata.join("remotes");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(io_error("inspect remote tracking", &path, e)),
            Ok(_) => require_directory(&path)?,
        }
        let mut result = BTreeMap::new();
        for entry in fs::read_dir(&path).map_err(|e| io_error("read remote tracking", &path, e))? {
            let entry = entry.map_err(|e| format!("read remote tracking entry: {e}"))?;
            let filename = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 remote tracking filename".to_string())?;
            let Some(name) = filename.strip_suffix(".tracking.json") else {
                continue;
            };
            validate_ref_name(name)?;
            let record: Tracking = serde_json::from_slice(&read_regular(&entry.path())?)
                .map_err(|e| format!("invalid remote tracking {name}: {e}"))?;
            if record.version != 1
                || record.remote != name
                || record.url.is_empty()
                || record.state.format != 1
            {
                return Err(format!("invalid remote tracking schema for {name}"));
            }
            validate_head_identity(&record.state.head)?;
            if record.state.detached()
                && !matches!(objects.get(&record.state.head), Some(Object::Commit(_)))
            {
                return Err("remote detached HEAD is missing or is not a commit".into());
            }
            for (branch, id) in &record.state.branches {
                validate_ref_name(branch)?;
                require_id(id)?;
                if !matches!(objects.get(id), Some(Object::Commit(_))) {
                    return Err(format!("remote tracking {name}/{branch} references missing or non-commit object {id}"));
                }
                result.insert(format!("{name}/{branch}"), id.clone());
            }
            for (tag, id) in &record.state.tags {
                validate_ref_name(tag)?;
                require_id(id)?;
                if !matches!(objects.get(id), Some(Object::Commit(_))) {
                    return Err(format!("remote tracking tag {name}/{tag} references missing or non-commit object {id}"));
                }
            }
        }
        Ok(result)
    }

    fn read_refs(&self) -> RepositoryResult<BTreeMap<String, String>> {
        self.read_named_refs("refs", false)
    }

    fn read_named_refs(
        &self,
        namespace: &str,
        optional: bool,
    ) -> RepositoryResult<BTreeMap<String, String>> {
        let mut refs = BTreeMap::new();
        let path = self.common_metadata.join(namespace);
        match fs::symlink_metadata(&path) {
            Err(e) if optional && e.kind() == std::io::ErrorKind::NotFound => return Ok(refs),
            Err(e) => return Err(io_error("inspect refs directory", &path, e)),
            Ok(_) => require_directory(&path)?,
        }
        let mut pending = vec![(String::new(), path)];
        while let Some((prefix, directory)) = pending.pop() {
            require_directory(&directory)?;
            for entry in
                fs::read_dir(&directory).map_err(|e| io_error("read refs", &directory, e))?
            {
                let entry = entry.map_err(|e| format!("read reference entry: {e}"))?;
                let component = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "non-UTF-8 reference name")?;
                let name = if prefix.is_empty() {
                    component
                } else {
                    format!("{prefix}/{component}")
                };
                validate_ref_name(&name)?;
                let kind = entry.file_type().map_err(|e| e.to_string())?;
                if kind.is_dir() {
                    pending.push((name, entry.path()));
                } else {
                    let id = parse_ref_file(&read_regular(&entry.path())?, true)?;
                    refs.insert(name, id);
                }
            }
        }
        Ok(refs)
    }

    fn read_ref_optional(&self, name: &str) -> RepositoryResult<Option<String>> {
        validate_ref_name(name)?;
        let path = self.common_metadata.join("refs").join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(Some(parse_ref_file(&read_regular(&path)?, true)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error("read branch", &path, e)),
        }
    }

    fn write_ref(&self, name: &str, id: &str) -> RepositoryResult<()> {
        self.write_named_ref("refs", name, id, "update")
    }

    fn write_named_ref(
        &self,
        namespace: &str,
        name: &str,
        id: &str,
        operation: &str,
    ) -> RepositoryResult<()> {
        if namespace == "refs" && valid_id(name) {
            return self.write_detached_tip(name, id, operation);
        }
        validate_ref_name(name)?;
        require_id(id)?;
        if namespace == "refs" {
            self.assert_branch_available(name)?;
        }
        self.read_reflog()?;
        let directory = self.common_metadata.join(namespace);
        match fs::symlink_metadata(&directory) {
            Err(e) if namespace == "tags" && e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&directory)
                    .map_err(|e| io_error("create tag directory", &directory, e))?;
                sync_directory(&self.common_metadata)?;
            }
            Err(e) => return Err(io_error("inspect reference directory", &directory, e)),
            Ok(_) => require_directory(&directory)?,
        }
        let mut parent = directory.clone();
        let components: Vec<_> = name.split('/').collect();
        for component in &components[..components.len() - 1] {
            parent.push(component);
            match fs::create_dir(&parent) {
                Ok(()) => {
                    sync_directory(parent.parent().ok_or("reference directory has no parent")?)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    require_directory(&parent)?
                }
                Err(error) => return Err(io_error("create reference directory", &parent, error)),
            }
        }
        let path = directory.join(name);
        let old = match fs::symlink_metadata(&path) {
            Ok(_) => Some(parse_ref_file(&read_regular(&path)?, true)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error("inspect reference", &path, e)),
        };
        if old.as_deref() == Some(id) {
            return Ok(());
        }
        self.atomic_write(&path, format!("{id}\n").as_bytes())?;
        let reference = format!(
            "refs/{}/{name}",
            if namespace == "tags" { "tags" } else { "heads" }
        );
        self.record_reflog(&reference, old.clone(), Some(id.into()), operation)?;
        if namespace == "refs" && self.current_branch()? == name {
            self.record_head_event(old, Some(id.into()), operation)?;
        }
        Ok(())
    }

    fn remove_named_ref(
        &self,
        namespace: &str,
        name: &str,
        id: &str,
        operation: &str,
    ) -> RepositoryResult<()> {
        if namespace == "refs" {
            self.assert_branch_available(name)?;
        }
        self.read_reflog()?;
        let path = self.common_metadata.join(namespace).join(name);
        if parse_ref_file(&read_regular(&path)?, true)? != id {
            return Err(format!("reference {name} changed before deletion"));
        }
        // This shared path also handles server receive deletion. Clear the local
        // association before deleting its branch, so a reused name never inherits
        // another branch's upstream and successful deletion cannot orphan a map.
        let cleared_upstream = if namespace == "refs" {
            let mut upstreams = self.read_upstreams(&self.read_refs()?)?;
            if upstreams.remove(name).is_some() {
                let bytes = encode_upstreams(&upstreams)?;
                self.publish_upstreams(&bytes, "clear upstream before branch deletion")
                    .map_err(|error| format!("branch {name} has not been deleted; clearing its upstream association may be incomplete: {error}"))?;
                true
            } else {
                false
            }
        } else {
            false
        };
        let result = (|| {
            fs::remove_file(&path).map_err(|e| io_error("delete reference", &path, e))?;
            sync_directory(path.parent().ok_or("reference has no parent")?)
                .map_err(|error| format!("reference {name} was deleted but its directory could not be synced: {error}; deletion durability is uncertain"))?;
            let namespace_root = self.common_metadata.join(namespace);
            let mut parent = path
                .parent()
                .ok_or("reference has no parent")?
                .to_path_buf();
            while parent != namespace_root {
                match fs::remove_dir(&parent) {
                    Ok(()) => {
                        parent = parent
                            .parent()
                            .ok_or("reference cleanup escaped namespace")?
                            .to_path_buf();
                        sync_directory(&parent)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => break,
                    Err(error) => {
                        return Err(format!(
                        "reference {name} was deleted, but empty-directory cleanup failed: {error}"
                    ))
                    }
                }
            }
            let reference = format!(
                "refs/{}/{name}",
                if namespace == "tags" { "tags" } else { "heads" }
            );
            self.record_reflog(&reference, Some(id.into()), None, operation)
        })();
        result.map_err(|error| if cleared_upstream {
            format!("upstream association for branch {name} was cleared; branch deletion or its reflog may be incomplete: {error}; inspect the ref before retrying")
        } else { error })
    }

    fn read_reflog(&self) -> RepositoryResult<Vec<ReflogEntry>> {
        let path = self.common_metadata.join("reflog");
        let bytes = match fs::symlink_metadata(&path) {
            Ok(_) => read_regular(&path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_error("inspect reflog", &path, e)),
        };
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let body = bytes
            .strip_suffix(b"\n")
            .ok_or("reflog has an incomplete trailing entry")?;
        let mut entries = Vec::new();
        for line in body.split(|byte| *byte == b'\n') {
            let entry: ReflogEntry =
                serde_json::from_slice(line).map_err(|e| format!("invalid reflog entry: {e}"))?;
            if serde_json::to_vec(&entry).map_err(|e| format!("encode reflog entry: {e}"))? != line
            {
                return Err("non-canonical or duplicate-key reflog entry".into());
            }
            let sequence = u64::try_from(entries.len())
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or("reflog sequence overflow")?;
            if entry.sequence != sequence || entry.operation.is_empty() {
                return Err("invalid reflog sequence or operation".into());
            }
            if entry.reference != "HEAD" {
                let name = entry
                    .reference
                    .strip_prefix("refs/heads/")
                    .or_else(|| entry.reference.strip_prefix("refs/tags/"))
                    .ok_or("invalid reflog reference namespace")?;
                validate_ref_name(name)?;
            }
            for id in entry.old.iter().chain(entry.new.iter()) {
                require_id(id)?;
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    fn record_reflog(
        &self,
        reference: &str,
        old: Option<String>,
        new: Option<String>,
        operation: &str,
    ) -> RepositoryResult<()> {
        let result = (|| {
            let mut entries = self.read_reflog()?;
            let sequence = u64::try_from(entries.len())
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or("reflog sequence overflow")?;
            entries.push(ReflogEntry {
                sequence,
                reference: reference.into(),
                old,
                new,
                operation: operation.into(),
            });
            let mut bytes = Vec::new();
            for entry in entries {
                serde_json::to_writer(&mut bytes, &entry)
                    .map_err(|e| format!("encode reflog entry: {e}"))?;
                bytes.push(b'\n');
            }
            self.atomic_write(&self.common_metadata.join("reflog"), &bytes)
        })();
        result.map_err(|error| format!("reference {reference} was published, but reflog recording failed: {error}; inspect the ref before retrying"))
    }

    fn atomic_write(&self, destination: &Path, bytes: &[u8]) -> RepositoryResult<()> {
        // Refuse symbolic-link destinations even though rename would replace the
        // link itself: a repository containing links is not a valid store.
        match fs::symlink_metadata(destination) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(format!(
                    "refusing non-regular destination: {}",
                    destination.display()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error("inspect destination", destination, e)),
        }
        let staging = if destination.starts_with(&self.common_metadata) {
            &self.common_metadata
        } else {
            &self.metadata
        };
        let temp = staging.join("tmp").join(unique_name("ref"));
        write_new_file(&temp, bytes)?;
        let result = fs::rename(&temp, destination)
            .map_err(|e| io_error("publish reference", destination, e));
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result?;
        sync_directory(
            destination
                .parent()
                .ok_or("reference has no parent directory")?,
        ).map_err(|error| format!("published {} but could not sync its directory: {error}; publication durability is uncertain", destination.display()))
    }

    fn store_object(&self, kind: u8, payload: &[u8]) -> RepositoryResult<String> {
        let bytes = encode_object(kind, payload)?;
        let id = object_id(&bytes);
        self.install_encoded_object(&id, &bytes)?;
        Ok(id)
    }

    fn install_encoded_object(&self, id: &str, bytes: &[u8]) -> RepositoryResult<()> {
        require_id(id)?;
        decode_object(id, bytes)?;
        let destination = self.common_metadata.join("objects").join(id);
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                if read_regular(&destination)? != bytes {
                    return Err(format!("object collision or corruption at {id}"));
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error("inspect object", &destination, e)),
        }
        let temp = self.common_metadata.join("tmp").join(unique_name("object"));
        write_new_file(&temp, bytes)?;
        // hard_link publishes a complete object and never replaces an existing
        // object, unlike rename. Both directories are in this repository.
        let result = match fs::hard_link(&temp, &destination) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_regular(&destination)? == bytes {
                    Ok(())
                } else {
                    Err(format!("object collision or corruption at {id}"))
                }
            }
            Err(e) => Err(io_error("publish object", &destination, e)),
        };
        let _ = fs::remove_file(&temp);
        result?;
        sync_directory(&self.common_metadata.join("objects"))
    }

    fn read_object(&self, id: &str) -> RepositoryResult<Object> {
        require_id(id)?;
        let bytes = read_regular(&self.common_metadata.join("objects").join(id))?;
        decode_object(id, &bytes)
    }

    fn read_commit_id(&self, id: &str) -> RepositoryResult<Commit> {
        match self.read_object(id)? {
            Object::Commit(commit) => Ok(commit),
            Object::Wasm(_) | Object::Tree(_) => Err(format!("revision {id} is not a commit")),
        }
    }

    fn verify_history(&self, tip: &str) -> RepositoryResult<()> {
        let mut pending = vec![tip.to_owned()];
        let mut objects = BTreeMap::new();
        while let Some(id) = pending.pop() {
            if objects.contains_key(&id) {
                continue;
            }
            let object = self.read_object(&id)?;
            if let Object::Commit(commit) = &object {
                pending.push(commit.tree.as_ref().unwrap_or(&commit.wasm).clone());
                pending.extend(commit.parents.iter().cloned());
            }
            if let Object::Tree(tree) = &object {
                pending.extend(tree.entries.values().cloned());
            }
            objects.insert(id, object);
        }
        validate_object_graph(&objects)?;
        if !matches!(objects.get(tip), Some(Object::Commit(_))) {
            return Err(format!("revision {tip} is not a commit"));
        }
        Ok(())
    }

    fn snapshot(&self) -> RepositoryResult<Snapshot> {
        let tags = self.read_named_refs("tags", true)?;
        let manifest = Manifest {
            format: if tags.is_empty() { 1 } else { 2 },
            head: self.current_branch()?,
            refs: self.read_refs()?,
            tags,
        };
        let mut encoded = BTreeMap::new();
        let mut objects = BTreeMap::new();
        let path = self.common_metadata.join("objects");
        for entry in fs::read_dir(&path).map_err(|e| io_error("list objects", &path, e))? {
            let entry = entry.map_err(|e| format!("read object entry: {e}"))?;
            let id = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 object filename".to_string())?;
            require_id(&id)?;
            let bytes = read_regular(&entry.path())?;
            objects.insert(id.clone(), decode_object(&id, &bytes)?);
            encoded.insert(id, bytes);
        }
        let mut manifest = manifest;
        manifest.format = manifest_format(&manifest.head, &manifest.tags, &objects);
        validate_snapshot(&manifest, &objects)?;
        let reflog = self.read_reflog()?;
        let head_reflog = self.read_head_reflog()?;
        for entry in reflog.iter().chain(&head_reflog) {
            for id in entry.old.iter().chain(entry.new.iter()) {
                if !matches!(objects.get(id), Some(Object::Commit(_))) {
                    return Err(format!(
                        "reflog references missing or non-commit object {id}"
                    ));
                }
            }
        }
        let tracking = self.read_tracking(&objects)?;
        let upstreams = self.read_upstreams(&manifest.refs)?;
        let upstream_tips = revision_syntax::upstream_tips(self, &upstreams, &tracking);
        let checkouts = self.checkout_history()?;
        Ok(Snapshot {
            manifest,
            upstreams,
            upstream_tips,
            checkouts,
            head_reflog,
            tracking,
            reflog,
            encoded,
            objects,
        })
    }
}

fn validate_wasm_header(bytes: &[u8]) -> RepositoryResult<()> {
    if !bytes.starts_with(WASM_HEADER) {
        return Err("expected the WebAssembly core-module magic and version-1 header; component binaries are outside this repository format".into());
    }
    Ok(())
}

fn object_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut id = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(id, "{byte:02x}");
    }
    id
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn require_id(id: &str) -> RepositoryResult<()> {
    if !valid_id(id) {
        return Err(format!("invalid object ID: {id:?}"));
    }
    Ok(())
}

fn check_upstream_tip(
    snapshot: &Snapshot,
    local: &str,
    expected_tip: &str,
) -> RepositoryResult<()> {
    let actual = snapshot.manifest.refs.get(local).ok_or_else(|| {
        format!("upstream configuration requires an existing committed branch: {local}")
    })?;
    if actual != expected_tip {
        return Err(format!("branch {local} changed from expected tip {expected_tip} to {actual}; no upstream configuration published"));
    }
    Ok(())
}

fn encode_pending(pending: &PendingOperation) -> RepositoryResult<Vec<u8>> {
    if pending.version != 1 {
        return Err("unsupported pending operation version".into());
    }
    for id in [&pending.id, &pending.head, &pending.target] {
        require_id(id)?;
    }
    validate_head_identity(&pending.branch)?;
    if !matches!(
        pending.operation.as_str(),
        "merge" | "cherry-pick" | "revert" | "rebase"
    ) {
        return Err("unsupported pending operation kind".into());
    }
    if (pending.operation == "rebase") != pending.rebase.is_some() {
        return Err("pending rebase state does not match its operation kind".into());
    }
    if pending.mainline == Some(0) {
        return Err("pending mainline must be a positive parent number".into());
    }
    for id in pending.base.iter().chain(&pending.selected_parent) {
        require_id(id)?;
    }
    if let Some(path) = &pending.legacy_path {
        validate_tree_path(path)?;
    }
    if let Some(prepared) = &pending.prepared {
        require_id(&prepared.commit)?;
        require_id(&prepared.index_sha256)?;
    }
    if let Some(rebase) = &pending.rebase {
        if pending.mainline.is_some()
            || rebase.cursor > rebase.queue.len()
            || rebase.steps.len() != rebase.cursor
        {
            return Err("invalid linear rebase cursor or mainline".into());
        }
        for id in [
            &rebase.upstream,
            &rebase.onto,
            &rebase.fork_base,
            &rebase.progress_tip,
        ]
        .into_iter()
        .chain(rebase.queue.iter())
        {
            require_id(id)?;
        }
        for step in &rebase.steps {
            require_id(&step.source)?;
            require_id(&step.before)?;
            for id in step.commit.iter().chain(&step.index_sha256) {
                require_id(id)?;
            }
            if !matches!(step.action.as_str(), "automatic" | "manual" | "skipped")
                || (step.action == "skipped") != step.commit.is_none()
                || (step.action == "manual") != step.index_sha256.is_some()
            {
                return Err("invalid linear rebase step action or result".into());
            }
        }
        if pending.prepared.is_some() != rebase.prepared_action.is_some()
            || rebase
                .prepared_action
                .as_deref()
                .is_some_and(|action| !matches!(action, "begin" | "continue" | "skip"))
        {
            return Err("invalid final rebase preparation action".into());
        }
    }
    if pending
        .baseline_index
        .as_ref()
        .is_some_and(|bytes| bytes.len() as u64 > MAX_PENDING_BYTES)
    {
        return Err("pending baseline index exceeds the 64 MiB encoded journal limit".into());
    }
    let mut bytes = serde_json::to_vec(pending)
        .map_err(|error| format!("encode pending operation: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_PENDING_BYTES {
        return Err("pending operation exceeds the 64 MiB encoded journal limit".into());
    }
    Ok(bytes)
}

fn pending_identity(
    snapshot: &Snapshot,
    operation: &str,
    head: &str,
    target: &str,
    mainline: Option<usize>,
) -> RepositoryResult<(Option<String>, Option<String>)> {
    require_id(head)?;
    require_id(target)?;
    if !matches!(snapshot.objects.get(head), Some(Object::Commit(_))) {
        return Err("pending HEAD must name that exact stored commit".into());
    }
    let Some(Object::Commit(selected)) = snapshot.objects.get(target) else {
        return Err("pending target must name that exact stored commit".into());
    };
    if operation == "merge" {
        if mainline.is_some() {
            return Err("pending merge does not accept a mainline".into());
        }
        if is_ancestor(head, target, &snapshot.objects)?
            || is_ancestor(target, head, &snapshot.objects)?
        {
            return Err("pending merge requires divergent tips".into());
        }
        return Ok((
            Some(unique_merge_base(head, target, &snapshot.objects)?),
            None,
        ));
    }
    if !matches!(operation, "cherry-pick" | "revert") {
        return Err("unsupported pending operation kind".into());
    }
    let parent = match (selected.parents.len(), mainline) {
        (0, None) => None,
        (1, None) => selected.parents.first().cloned(),
        (count, Some(parent)) if parent > 0 && parent <= count => {
            selected.parents.get(parent - 1).cloned()
        }
        (_, Some(_)) => return Err("pending mainline parent number is out of range".into()),
        _ => return Err("pending replay of a merge commit requires --mainline N".into()),
    };
    let base = if operation == "revert" {
        Some(target.to_owned())
    } else {
        parent.clone()
    };
    Ok((base, parent))
}

fn pending_parents(pending: &PendingOperation) -> Vec<String> {
    if pending.operation == "merge" {
        vec![pending.head.clone(), pending.target.clone()]
    } else {
        vec![pending.head.clone()]
    }
}

fn pending_revisions(
    snapshot: &Snapshot,
    pending: &PendingOperation,
) -> RepositoryResult<[RevisionFiles; 3]> {
    let ours = snapshot_files(snapshot, &pending.head)?;
    let selected = snapshot_files(snapshot, &pending.target)?;
    if pending.operation == "merge" {
        let base = snapshot_files(
            snapshot,
            pending
                .base
                .as_deref()
                .ok_or("pending merge lacks its base")?,
        )?;
        return Ok([base, ours, selected]);
    }
    let parent = pending
        .selected_parent
        .as_deref()
        .map(|id| snapshot_files(snapshot, id))
        .transpose()?
        .unwrap_or_else(|| RevisionFiles {
            commit: String::new(),
            legacy: None,
            files: BTreeMap::new(),
            legacy_path: pending.legacy_path.clone(),
        });
    if pending.operation == "revert" {
        Ok([selected, ours, parent])
    } else {
        Ok([parent, ours, selected])
    }
}

fn validate_pending_snapshot(
    snapshot: &Snapshot,
    pending: &PendingOperation,
) -> RepositoryResult<()> {
    encode_pending(pending)?;
    if pending.rebase.is_some() {
        return validate_pending_rebase(snapshot, pending);
    }
    let (base, parent) = pending_identity(
        snapshot,
        &pending.operation,
        &pending.head,
        &pending.target,
        pending.mainline,
    )?;
    if pending.base != base || pending.selected_parent != parent {
        return Err(
            "pending base or selected parent does not match its immutable revisions".into(),
        );
    }
    let head = snapshot_files(snapshot, &pending.head)?;
    crate::porcelain::validate_pending_baseline(
        pending.baseline_index.as_deref(),
        &head,
        pending.legacy_path.as_deref(),
    )?;
    let parents = pending_parents(pending);
    check_tree_parents(snapshot, &parents, pending.legacy_path.as_deref())?;
    for revision in pending_revisions(snapshot, pending)? {
        if revision
            .legacy_path
            .as_deref()
            .is_some_and(|anchor| Some(anchor) != pending.legacy_path.as_deref())
        {
            return Err("pending revisions have conflicting legacy path anchors".into());
        }
        if revision.legacy.is_some() && pending.legacy_path.is_none() {
            return Err("pending legacy history requires an explicit original index path".into());
        }
    }
    if let Some(prepared) = &pending.prepared {
        let Some(Object::Commit(commit)) = snapshot.objects.get(&prepared.commit) else {
            return Err("prepared pending result is not a stored commit".into());
        };
        if commit.format != 2
            || commit.parents != parents
            || commit.message != pending.message
            || commit.legacy_path != pending.legacy_path
        {
            return Err("prepared pending result does not match its operation identity".into());
        }
    }
    Ok(())
}

fn pending_manual_resolution(
    snapshot: &Snapshot,
    pending: &PendingOperation,
    files: &BTreeMap<String, Vec<u8>>,
) -> RepositoryResult<TreeManualResolution> {
    let mut report = manual_tree_resolution(
        pending_revisions(snapshot, pending)?,
        files,
        pending.legacy_path.as_deref(),
    )?;
    report.provenance =
        "user_supplied_complete_tree; metadata_only; no_automatic_replay_claim".into();
    Ok(report)
}

fn rebase_source_parent(snapshot: &Snapshot, source: &str) -> RepositoryResult<String> {
    let Some(Object::Commit(commit)) = snapshot.objects.get(source) else {
        return Err("rebase source is not an exact stored commit".into());
    };
    if commit.parents.len() != 1 {
        return Err("linear rebase cannot replay a root or merge commit".into());
    }
    Ok(commit.parents[0].clone())
}

fn rebase_queue(
    snapshot: &Snapshot,
    head: &str,
    upstream: &str,
) -> RepositoryResult<(String, Vec<String>)> {
    for id in [head, upstream] {
        require_id(id)?;
        if !matches!(snapshot.objects.get(id), Some(Object::Commit(_))) {
            return Err("rebase revisions must be exact stored commit IDs".into());
        }
    }
    let fork_base = unique_merge_base(head, upstream, &snapshot.objects)?;
    let mut queue = Vec::new();
    let mut cursor = head.to_owned();
    while cursor != fork_base {
        let parent = rebase_source_parent(snapshot, &cursor)?;
        queue.push(cursor);
        cursor = parent;
    }
    queue.reverse();
    Ok((fork_base, queue))
}

fn bind_rebase_source(snapshot: &Snapshot, pending: &mut PendingOperation) -> RepositoryResult<()> {
    let rebase = pending
        .rebase
        .as_ref()
        .ok_or("missing linear rebase state")?;
    if let Some(source) = rebase.queue.get(rebase.cursor).or(rebase.queue.last()) {
        let parent = rebase_source_parent(snapshot, source)?;
        let Some(Object::Commit(commit)) = snapshot.objects.get(source) else {
            return Err("missing linear rebase source".into());
        };
        pending.target = source.clone();
        pending.base = Some(parent.clone());
        pending.selected_parent = Some(parent);
        pending.message = commit.message.clone();
    } else {
        pending.target = pending.head.clone();
        pending.base = Some(rebase.fork_base.clone());
        pending.selected_parent = None;
        pending.message.clear();
    }
    Ok(())
}

fn validate_rebase_anchors(
    snapshot: &Snapshot,
    pending: &PendingOperation,
) -> RepositoryResult<()> {
    let rebase = pending
        .rebase
        .as_ref()
        .ok_or("missing linear rebase state")?;
    let head = snapshot_files(snapshot, &pending.head)?;
    crate::porcelain::validate_pending_baseline(
        pending.baseline_index.as_deref(),
        &head,
        pending.legacy_path.as_deref(),
    )?;
    let ids = [
        &pending.head,
        &rebase.upstream,
        &rebase.onto,
        &rebase.fork_base,
    ]
    .into_iter()
    .chain(rebase.queue.iter());
    for id in ids {
        let revision = snapshot_files(snapshot, id)?;
        if revision
            .legacy_path
            .as_deref()
            .is_some_and(|anchor| Some(anchor) != pending.legacy_path.as_deref())
        {
            return Err("rebase histories have conflicting legacy path anchors".into());
        }
        if revision.legacy.is_some() && pending.legacy_path.is_none() {
            return Err(
                "rebase of unnamed legacy history requires an explicit original index path".into(),
            );
        }
    }
    check_tree_parents(
        snapshot,
        std::slice::from_ref(&rebase.onto),
        pending.legacy_path.as_deref(),
    )
}

fn merge_rebase_files(
    snapshot: &Snapshot,
    base: &str,
    ours: &str,
    theirs: &str,
    anchor: Option<&str>,
) -> RepositoryResult<MergedFiles> {
    merge_file_revisions(
        [
            snapshot_files(snapshot, base)?,
            snapshot_files(snapshot, ours)?,
            snapshot_files(snapshot, theirs)?,
        ],
        anchor,
    )
}

fn stage_rebase_commit(
    snapshot: &mut Snapshot,
    encoded: &mut BTreeMap<String, Vec<u8>>,
    commits: &mut Vec<String>,
    files: &BTreeMap<String, Vec<u8>>,
    source: &str,
    parent: &str,
    anchor: Option<&str>,
) -> RepositoryResult<String> {
    let Some(Object::Commit(original)) = snapshot.objects.get(source) else {
        return Err("missing original rebase source".into());
    };
    let message = original.message.clone();
    check_tree_parents(snapshot, &[parent.into()], anchor)?;
    let mut staged = BTreeMap::new();
    let id = prepare_tree_commit(
        files,
        &message,
        &[parent.into()],
        anchor,
        &snapshot.encoded,
        &mut staged,
    )?;
    for (key, bytes) in staged {
        snapshot
            .objects
            .insert(key.clone(), decode_object(&key, &bytes)?);
        snapshot.encoded.insert(key.clone(), bytes.clone());
        encoded.insert(key, bytes);
    }
    commits.push(id.clone());
    Ok(id)
}

fn validate_pending_rebase(
    snapshot: &Snapshot,
    pending: &PendingOperation,
) -> RepositoryResult<()> {
    let rebase = pending
        .rebase
        .as_ref()
        .ok_or("missing linear rebase state")?;
    let (fork_base, queue) = rebase_queue(snapshot, &pending.head, &rebase.upstream)?;
    if rebase.fork_base != fork_base || rebase.queue != queue {
        return Err(
            "pending rebase queue differs from its original linear history or upstream".into(),
        );
    }
    validate_rebase_anchors(snapshot, pending)?;
    let mut identity = pending.clone();
    bind_rebase_source(snapshot, &mut identity)?;
    if pending.target != identity.target
        || pending.base != identity.base
        || pending.selected_parent != identity.selected_parent
        || pending.message != identity.message
    {
        return Err("pending rebase source metadata differs from its frozen queue".into());
    }
    let mut progress = rebase.onto.clone();
    for (index, step) in rebase.steps.iter().enumerate() {
        if rebase.queue.get(index) != Some(&step.source) || step.before != progress {
            return Err("pending rebase step order or input tip differs from its queue".into());
        }
        let parent = rebase_source_parent(snapshot, &step.source)?;
        let merged = merge_rebase_files(
            snapshot,
            &parent,
            &progress,
            &step.source,
            pending.legacy_path.as_deref(),
        )?;
        let conflict = merged
            .reports
            .iter()
            .any(|report| report.status == "conflict");
        if step.action != "automatic" && !conflict {
            return Err("manual or skipped rebase step did not stop at an actual conflict".into());
        }
        if step.action == "skipped" {
            continue;
        }
        let result = step
            .commit
            .as_deref()
            .ok_or("replayed source lacks its result commit")?;
        let Some(Object::Commit(original)) = snapshot.objects.get(&step.source) else {
            return Err("missing original rebase source".into());
        };
        let Some(Object::Commit(commit)) = snapshot.objects.get(result) else {
            return Err("pending replay result is not a stored commit".into());
        };
        if commit.format != 2
            || commit.parents != [progress.clone()]
            || commit.message != original.message
            || commit.legacy_path != pending.legacy_path
        {
            return Err(
                "pending replay result has different parents, message or path anchor".into(),
            );
        }
        if step.action == "automatic"
            && (conflict || snapshot_files(snapshot, result)?.files != merged.files)
        {
            return Err("automatic rebase result differs from the exact original replay".into());
        }
        progress = result.into();
    }
    if progress != rebase.progress_tip {
        return Err("pending rebase progress tip differs from its step chain".into());
    }
    if let Some(prepared) = &pending.prepared {
        if rebase.cursor != rebase.queue.len() || prepared.commit != progress {
            return Err("final rebase preparation does not name its complete replay chain".into());
        }
        match rebase.prepared_action.as_deref() {
            Some("continue") => {
                let last = rebase
                    .steps
                    .iter()
                    .rev()
                    .find(|step| step.action != "automatic")
                    .ok_or("prepared continuation has no explicit resolution step")?;
                if last.action != "manual"
                    || last.index_sha256.as_deref() != Some(prepared.index_sha256.as_str())
                {
                    return Err(
                        "prepared continuation is not bound to its last manually supplied index"
                            .into(),
                    );
                }
            }
            Some("skip") => {
                if rebase
                    .steps
                    .iter()
                    .rev()
                    .find(|step| step.action != "automatic")
                    .is_none_or(|step| step.action != "skipped")
                {
                    return Err("prepared skip does not follow its explicit skipped source".into());
                }
                if prepared.index_sha256 != format!("{:x}", Sha256::digest(b"")) {
                    return Err("prepared skip has an unexpected index lease".into());
                }
            }
            Some("begin") => {
                if rebase.steps.iter().any(|step| step.action != "automatic")
                    || prepared.index_sha256 != format!("{:x}", Sha256::digest(b""))
                {
                    return Err(
                        "prepared automatic begin contains an explicit manual action".into(),
                    );
                }
            }
            _ => return Err("missing final rebase preparation action".into()),
        }
    } else {
        let source = rebase
            .queue
            .get(rebase.cursor)
            .ok_or("unprepared rebase has no stopped source")?;
        let parent = rebase_source_parent(snapshot, source)?;
        let merged = merge_rebase_files(
            snapshot,
            &parent,
            &progress,
            source,
            pending.legacy_path.as_deref(),
        )?;
        if !merged
            .reports
            .iter()
            .any(|report| report.status == "conflict")
        {
            return Err("pending rebase claims a conflict at an automatically clean source".into());
        }
    }
    Ok(())
}

fn rebase_manual_resolution(
    snapshot: &Snapshot,
    pending: &PendingOperation,
    source: &str,
    before: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> RepositoryResult<TreeManualResolution> {
    let parent = rebase_source_parent(snapshot, source)?;
    let mut report = manual_tree_resolution(
        [
            snapshot_files(snapshot, &parent)?,
            snapshot_files(snapshot, before)?,
            snapshot_files(snapshot, source)?,
        ],
        files,
        pending.legacy_path.as_deref(),
    )?;
    report.provenance = "user_supplied_complete_tree_for_one_rebase_source; no_automatic_completion_of_supplied_index; later_sources_replayed_separately".into();
    Ok(report)
}

fn rebase_pending_report(
    snapshot: &Snapshot,
    pending: &PendingOperation,
    file_reports: &[FileMergeReport],
    already_published: bool,
    resumed_prepared: bool,
    index_matches_prepared: Option<bool>,
) -> RepositoryResult<Value> {
    let rebase = pending
        .rebase
        .as_ref()
        .ok_or("missing linear replay state")?;
    let complete = pending.prepared.is_some();
    let mut manual = Vec::new();
    for step in rebase.steps.iter().filter(|step| step.action == "manual") {
        let commit = step
            .commit
            .as_deref()
            .ok_or("manual rebase step has no result")?;
        let files = snapshot_files(snapshot, commit)?;
        manual.push(json!({"source":step.source,"before":step.before,"commit":commit,
            "tree_manual_resolution":rebase_manual_resolution(snapshot,pending,&step.source,&step.before,&files.files)?}));
    }
    let parents = pending
        .prepared
        .as_ref()
        .map(|prepared| match snapshot.objects.get(&prepared.commit) {
            Some(Object::Commit(commit)) => Ok(commit.parents.clone()),
            _ => Err("final rebase result is not a stored commit".to_owned()),
        })
        .transpose()?;
    let recorded = if complete {
        Value::Null
    } else {
        json!({
        "id":pending.id,"operation":"rebase","branch":pending.branch,"head":pending.head,
        "old_head":pending.head,"target":pending.target,"base":pending.base,
        "selected_parent":pending.selected_parent,"mainline":pending.mainline,
        "phase":"conflict","rebase":rebase,"index_updated":false,"worktree_updated":false,
        "complete_index_required":true})
    };
    Ok(
        json!({"schema_version":1,"status":if complete {"rebased"} else {"conflict"},
        "operation":"rebase","pending_id":pending.id,"branch":pending.branch,
        "old_head":pending.head,"target":pending.target,"upstream":rebase.upstream,
        "onto":rebase.onto,"fork_base":rebase.fork_base,"queue":rebase.queue,
        "cursor":rebase.cursor,"progress_tip":rebase.progress_tip,
        "stopped_at":rebase.queue.get(rebase.cursor),
        "commit":pending.prepared.as_ref().map(|prepared| &prepared.commit),"parents":parents,
        "commits":rebase.steps.iter().filter_map(|step| step.commit.as_ref()).collect::<Vec<_>>(),
        "steps":rebase.steps,"skipped":rebase.steps.iter().filter(|step|step.action=="skipped").map(|step|&step.source).collect::<Vec<_>>(),
        "manual_resolutions":manual,"file_reports":file_reports,"pending":recorded,
        "resolution_source":if manual.is_empty() {"automatic_replay_or_skip"} else {"index"},
        "resolution_note":"Each supplied complete index resolves exactly one stopped source; nonconflicting paths are not filled in automatically. Later sources are replayed separately. A subsequent conflict requires another explicit --resolved-index review.",
        "index_updated":false,"worktree_updated":false,"pending_cleared":complete,
        "already_published":already_published,"resumed_prepared":resumed_prepared,
        "index_matches_prepared":index_matches_prepared}),
    )
}

fn validate_upstream_remote_name(name: &str) -> RepositoryResult<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(format!("invalid upstream remote name {name:?}: use 1-64 ASCII letters, digits, '_' or '-', starting with a letter or digit"));
    }
    Ok(())
}

fn encode_upstreams(branches: &BTreeMap<String, Upstream>) -> RepositoryResult<Vec<u8>> {
    for (local, upstream) in branches {
        validate_ref_name(local)?;
        validate_upstream_remote_name(&upstream.remote)?;
        validate_ref_name(&upstream.branch)?;
    }
    let bytes = serde_json::to_vec(&UpstreamFile {
        version: 1,
        branches: branches.clone(),
    })
    .map_err(|error| format!("encode upstream configuration: {error}"))?;
    if bytes.len() as u64 > MAX_UPSTREAM_BYTES {
        return Err("upstream configuration exceeds the 1 MiB limit".into());
    }
    Ok(bytes)
}

pub(crate) fn validate_ref_name(name: &str) -> RepositoryResult<()> {
    if name.is_empty()
        || name.len() > 128
        || name == "HEAD"
        || name.starts_with("refs/")
        || valid_id(name)
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.ends_with(".lock"))
    {
        return Err(format!(
            "invalid branch name {name:?}: use 1-128 ASCII letters, digits, '.', '_', '-', or '/' with nonempty normal path components, starting with a letter or digit; HEAD, object IDs and .lock suffixes are reserved"
        ));
    }
    Ok(())
}

fn parse_ref_file(bytes: &[u8], object: bool) -> RepositoryResult<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "non-UTF-8 reference".to_string())?;
    let value = text
        .strip_suffix('\n')
        .ok_or("reference must end with exactly one newline")?;
    if object {
        require_id(value)?;
    } else {
        validate_head_identity(value)?;
    }
    Ok(value.to_owned())
}

/// Validate a portable repository-relative UTF-8 path. File/directory prefix
/// collisions are checked across the complete tree, not guessed during checkout.
pub fn validate_tree_path(path: &str) -> RepositoryResult<()> {
    if path.is_empty()
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| {
            part.is_empty() || part == "." || part == ".." || part.eq_ignore_ascii_case(".uwgit")
        })
    {
        return Err(format!(
            "invalid tree path {path:?}: expected a normal relative path outside .uwgit"
        ));
    }
    Ok(())
}

fn validate_tree_paths<'a>(paths: impl Iterator<Item = &'a str>) -> RepositoryResult<()> {
    let mut seen = BTreeSet::new();
    for path in paths {
        validate_tree_path(path)?;
        seen.insert(path);
    }
    for path in &seen {
        for (offset, _) in path.match_indices('/') {
            if seen.contains(&path[..offset]) {
                return Err(format!("tree file/directory prefix conflict at {path:?}"));
            }
        }
    }
    Ok(())
}

fn manifest_format(
    head: &str,
    tags: &BTreeMap<String, String>,
    objects: &BTreeMap<String, Object>,
) -> u32 {
    if valid_id(head) {
        4
    } else if objects.values().any(|object| {
        matches!(object, Object::Tree(_))
            || matches!(object, Object::Commit(commit) if commit.format == 2)
    }) {
        3
    } else if tags.is_empty() {
        1
    } else {
        2
    }
}

fn require_legacy_commit(commit: &Commit) -> RepositoryResult<()> {
    if commit.format != 1 {
        return Err("revision contains a file tree; select an explicit file or use add/commit for the complete tree".into());
    }
    Ok(())
}

fn require_legacy_head(snapshot: &Snapshot) -> RepositoryResult<()> {
    if let Some(Object::Commit(commit)) = snapshot
        .manifest
        .tip()
        .and_then(|id| snapshot.objects.get(id))
    {
        require_legacy_commit(commit)?;
    }
    Ok(())
}

fn check_tree_head_anchor(snapshot: &Snapshot, legacy_path: Option<&str>) -> RepositoryResult<()> {
    if let Some(Object::Commit(commit)) = snapshot
        .manifest
        .tip()
        .and_then(|id| snapshot.objects.get(id))
    {
        if let Some(anchor) = &commit.legacy_path {
            if Some(anchor.as_str()) != legacy_path {
                return Err(
                    "cannot change or discard the current tree's legacy path anchor".into(),
                );
            }
        }
    }
    Ok(())
}

fn check_tree_parents(
    snapshot: &Snapshot,
    parents: &[String],
    legacy_path: Option<&str>,
) -> RepositoryResult<()> {
    if let Some(path) = legacy_path {
        validate_tree_path(path)?;
    }
    let mut seen = BTreeSet::new();
    for id in parents {
        require_id(id)?;
        if !seen.insert(id) {
            return Err("duplicate tree commit parent".into());
        }
        let Some(Object::Commit(commit)) = snapshot.objects.get(id) else {
            return Err(format!("missing tree parent commit {id}"));
        };
        if commit.format == 1 && legacy_path.is_none() {
            return Err(
                "legacy history requires an explicit legacy path when upgrading to a file tree"
                    .into(),
            );
        }
        if commit
            .legacy_path
            .as_deref()
            .is_some_and(|anchor| Some(anchor) != legacy_path)
        {
            return Err("tree parent histories have conflicting legacy path anchors".into());
        }
    }
    Ok(())
}

fn stage_tree_object(
    kind: u8,
    payload: &[u8],
    current: &BTreeMap<String, Vec<u8>>,
    staged: &mut BTreeMap<String, Vec<u8>>,
) -> RepositoryResult<String> {
    let encoded = encode_object(kind, payload)?;
    let id = object_id(&encoded);
    if current
        .get(&id)
        .or_else(|| staged.get(&id))
        .is_some_and(|previous| previous != &encoded)
    {
        return Err(format!("object collision at {id}"));
    }
    staged.insert(id.clone(), encoded);
    Ok(id)
}

/// Keep every successfully installed prefix a valid graph, including after an
/// I/O interruption: blobs first, then trees, then parent-before-child commits.
/// Both legacy replay and tree publication share this dependency contract.
fn install_dependency_ordered(
    encoded: &BTreeMap<String, Vec<u8>>,
    commits: &[String],
    mut install: impl FnMut(&str, &[u8]) -> RepositoryResult<()>,
) -> RepositoryResult<()> {
    for kind in [WASM_KIND, TREE_KIND] {
        for (id, bytes) in encoded {
            if bytes.get(8) == Some(&kind) {
                install(id, bytes)?;
            }
        }
    }
    for id in commits {
        install(id, encoded.get(id).ok_or("missing prepared commit")?)?;
    }
    Ok(())
}

fn prepare_tree_commit(
    files: &BTreeMap<String, Vec<u8>>,
    message: &str,
    parents: &[String],
    legacy_path: Option<&str>,
    current: &BTreeMap<String, Vec<u8>>,
    staged: &mut BTreeMap<String, Vec<u8>>,
) -> RepositoryResult<String> {
    validate_tree_paths(files.keys().map(String::as_str))?;
    if let Some(path) = legacy_path {
        validate_tree_path(path)?;
    }
    let mut entries = BTreeMap::new();
    for (path, bytes) in files {
        validate_wasm_header(bytes)?;
        entries.insert(
            path.clone(),
            stage_tree_object(WASM_KIND, bytes, current, staged)?,
        );
    }
    let tree = Tree { format: 1, entries };
    let payload = serde_json::to_vec(&tree).map_err(|e| format!("encode tree: {e}"))?;
    let tree = stage_tree_object(TREE_KIND, &payload, current, staged)?;
    let commit = Commit {
        format: 2,
        wasm: String::new(),
        parents: parents.to_vec(),
        message: message.into(),
        tree: Some(tree),
        legacy_path: legacy_path.map(str::to_owned),
    };
    stage_tree_object(COMMIT_KIND, &encode_commit(&commit)?, current, staged)
}

struct MergedFiles {
    files: BTreeMap<String, Vec<u8>>,
    legacy_path: Option<String>,
    reports: Vec<FileMergeReport>,
}

fn manual_tree_witness(bytes: &[u8]) -> RepositoryResult<ManualTreeByteWitness> {
    Ok(ManualTreeByteWitness {
        byte_len: bytes.len(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        hex: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        audit: wasm_git::audit::inspect(bytes)?,
    })
}

fn manual_tree_delta(
    old: Option<&[u8]>,
    resolved: Option<&[u8]>,
) -> RepositoryResult<ManualTreeFileDelta> {
    let status = match (old, resolved) {
        (None, None) => "absent",
        (None, Some(_)) => "added",
        (Some(_), None) => "deleted",
        (Some(old), Some(new)) if old == new => "unchanged",
        (Some(_), Some(_)) => "modified",
    };
    let audit = if status == "modified" {
        Some(wasm_git::audit::compare(
            old.ok_or("modified tree file lacks original bytes")?,
            resolved.ok_or("modified tree file lacks resolved bytes")?,
        )?)
    } else {
        None
    };
    Ok(ManualTreeFileDelta {
        status: status.into(),
        audit,
    })
}

fn manual_tree_resolution(
    mut revisions: [RevisionFiles; 3],
    files: &BTreeMap<String, Vec<u8>>,
    legacy_path: Option<&str>,
) -> RepositoryResult<TreeManualResolution> {
    for revision in &mut revisions {
        if revision
            .legacy_path
            .as_deref()
            .is_some_and(|anchor| Some(anchor) != legacy_path)
        {
            return Err(
                "manual tree resolution histories have conflicting legacy path anchors".into(),
            );
        }
        if let Some(bytes) = revision.legacy.take() {
            let path = legacy_path.ok_or(
                "manual tree resolution requires an explicit path for unnamed legacy history",
            )?;
            revision.files.insert(path.into(), bytes);
        }
    }
    let paths: BTreeSet<_> = revisions
        .iter()
        .flat_map(|revision| revision.files.keys())
        .chain(files.keys())
        .cloned()
        .collect();
    let mut reports = Vec::new();
    for path in paths {
        let base = revisions[0].files.get(&path).map(Vec::as_slice);
        let ours = revisions[1].files.get(&path).map(Vec::as_slice);
        let theirs = revisions[2].files.get(&path).map(Vec::as_slice);
        let resolved = files.get(&path).map(Vec::as_slice);
        reports.push(ManualTreeFile {
            path,
            base: base.map(manual_tree_witness).transpose()?,
            ours: ours.map(manual_tree_witness).transpose()?,
            theirs: theirs.map(manual_tree_witness).transpose()?,
            resolved: resolved.map(manual_tree_witness).transpose()?,
            from_ours: manual_tree_delta(ours, resolved)?,
            from_theirs: manual_tree_delta(theirs, resolved)?,
        });
    }
    Ok(TreeManualResolution {
        supplied_complete_tree: true,
        provenance: "user_supplied_complete_tree; metadata_only; no_automatic_merge_claim".into(),
        legacy_path: legacy_path.map(str::to_owned),
        files: reports,
    })
}

fn merge_file_trees(
    snapshot: &Snapshot,
    base: &str,
    ours: &str,
    theirs: &str,
) -> RepositoryResult<MergedFiles> {
    merge_file_revisions(
        [
            snapshot_files(snapshot, base)?,
            snapshot_files(snapshot, ours)?,
            snapshot_files(snapshot, theirs)?,
        ],
        None,
    )
}

fn merge_file_revisions(
    mut revisions: [RevisionFiles; 3],
    explicit_anchor: Option<&str>,
) -> RepositoryResult<MergedFiles> {
    let mut anchors: BTreeSet<_> = revisions
        .iter()
        .filter_map(|revision| revision.legacy_path.clone())
        .collect();
    if let Some(anchor) = explicit_anchor {
        validate_tree_path(anchor)?;
        anchors.insert(anchor.into());
    }
    let anchor = anchors.first().cloned();
    let mut result = MergedFiles {
        files: BTreeMap::new(),
        legacy_path: anchor.clone(),
        reports: Vec::new(),
    };
    if anchors.len() > 1
        || (anchor.is_none() && revisions.iter().any(|revision| revision.legacy.is_some()))
    {
        result.reports.push(FileMergeReport {
            path: String::new(),
            status: "conflict".into(),
            reason: Some(format!(
                "legacy path mapping is missing or conflicting; no filename guessed: {anchors:?}"
            )),
            report: None,
        });
        return Ok(result);
    }
    for revision in &mut revisions {
        if let Some(bytes) = revision.legacy.take() {
            revision
                .files
                .insert(anchor.clone().ok_or("missing explicit legacy path")?, bytes);
        }
    }
    let paths: BTreeSet<_> = revisions
        .iter()
        .flat_map(|revision| revision.files.keys().cloned())
        .collect();
    for path in paths {
        let base = revisions[0].files.get(&path);
        let ours = revisions[1].files.get(&path);
        let theirs = revisions[2].files.get(&path);
        if base == ours && base == theirs {
            if let Some(bytes) = base {
                result.files.insert(path, bytes.clone());
            }
            continue;
        }
        let mut report = None;
        let mut reason = None;
        let merged = if ours == theirs {
            Some(ours.cloned())
        } else if ours == base {
            Some(theirs.cloned())
        } else if theirs == base {
            Some(ours.cloned())
        } else if let (Some(base), Some(ours), Some(theirs)) = (base, ours, theirs) {
            let mut merge = wasm_git::merge::merge(base, ours, theirs)?;
            let bytes = if merge.status == "clean" {
                Some(Some(
                    merge.bytes.take().ok_or("clean file merge lacks bytes")?,
                ))
            } else {
                None
            };
            report = Some(merge);
            bytes
        } else {
            reason = Some(
                if base.is_none() {
                    "different bytes added at the same path"
                } else {
                    "delete/modify conflict"
                }
                .into(),
            );
            None
        };
        let status = if let Some(merged) = merged {
            let status = match (base, &merged) {
                (None, Some(_)) => "added",
                (Some(_), None) => "deleted",
                _ => "modified",
            };
            if let Some(bytes) = merged {
                result.files.insert(path.clone(), bytes);
            }
            status
        } else {
            "conflict"
        };
        result.reports.push(FileMergeReport {
            path,
            status: status.into(),
            reason,
            report,
        });
    }
    if let Err(error) = validate_tree_paths(result.files.keys().map(String::as_str)) {
        result.reports.push(FileMergeReport {
            path: String::new(),
            status: "conflict".into(),
            reason: Some(error),
            report: None,
        });
    }
    Ok(result)
}

fn snapshot_files(snapshot: &Snapshot, id: &str) -> RepositoryResult<RevisionFiles> {
    let Some(Object::Commit(commit)) = snapshot.objects.get(id) else {
        return Err(format!("missing commit {id}"));
    };
    if commit.format == 1 {
        return Ok(RevisionFiles {
            commit: id.into(),
            legacy: Some(snapshot_wasm(snapshot, id)?.to_vec()),
            files: BTreeMap::new(),
            legacy_path: None,
        });
    }
    let Some(Object::Tree(tree)) = commit
        .tree
        .as_ref()
        .and_then(|tree| snapshot.objects.get(tree))
    else {
        return Err(format!("missing tree for commit {id}"));
    };
    let files = tree
        .entries
        .iter()
        .map(|(path, blob)| {
            let Some(Object::Wasm(bytes)) = snapshot.objects.get(blob) else {
                return Err(format!("missing Wasm for tree path {path:?}"));
            };
            Ok((path.clone(), bytes.clone()))
        })
        .collect::<RepositoryResult<BTreeMap<_, _>>>()?;
    Ok(RevisionFiles {
        commit: id.into(),
        legacy: None,
        files,
        legacy_path: commit.legacy_path.clone(),
    })
}

fn snapshot_query_tree(snapshot: &Snapshot, revision: &str) -> RepositoryResult<QueryTree> {
    let id = if valid_id(revision) {
        match snapshot.objects.get(revision) {
                Some(Object::Tree(_)) | Some(Object::Commit(_)) => revision.to_owned(),
                Some(Object::Wasm(_)) => return Err("a Wasm blob has no named tree; query a commit revision or a complete tree object ID".into()),
                None => return Err(format!("unknown object: {revision}")),
            }
    } else {
        snapshot_revision(snapshot, revision)?
    };
    let selected = query_object(snapshot, &id)?;
    let (commit, tree, legacy_path, legacy) = match snapshot.objects.get(&id) {
        Some(Object::Tree(_)) => (None, Some(id.clone()), None, None),
        Some(Object::Commit(commit)) if commit.format == 1 => (
            Some(id.clone()),
            None,
            commit.legacy_path.clone(),
            Some(query_object(snapshot, &commit.wasm)?),
        ),
        Some(Object::Commit(commit)) => (
            Some(id.clone()),
            Some(
                commit
                    .tree
                    .clone()
                    .ok_or("tree commit is missing its stored tree ID")?,
            ),
            commit.legacy_path.clone(),
            None,
        ),
        _ => return Err("tree query requires a stored commit or tree".into()),
    };
    let entries = tree
        .as_deref()
        .map(|id| query_tree_entries(snapshot, id))
        .transpose()?
        .unwrap_or_default();
    Ok(QueryTree {
        schema_version: 1,
        object_id: id,
        kind: selected.kind,
        commit,
        named: tree.is_some(),
        tree,
        legacy_path,
        legacy,
        entries,
    })
}

fn query_object(snapshot: &Snapshot, id: &str) -> RepositoryResult<QueryObject> {
    let kind = match snapshot.objects.get(id) {
        Some(Object::Commit(_)) => "commit",
        Some(Object::Tree(_)) => "tree",
        Some(Object::Wasm(_)) => "wasm",
        None => return Err(format!("unknown stored object: {id}")),
    };
    let encoded = snapshot
        .encoded
        .get(id)
        .ok_or("stored object has no encoded bytes")?;
    let payload_len = encoded
        .len()
        .checked_sub(OBJECT_HEADER_LENGTH)
        .ok_or("stored object lacks its versioned envelope")?;
    Ok(QueryObject {
        object_id: id.into(),
        kind: kind.into(),
        byte_len: u64::try_from(payload_len)
            .map_err(|_| "object payload exceeds query size range")?,
        stored_byte_len: u64::try_from(encoded.len())
            .map_err(|_| "encoded object exceeds query size range")?,
    })
}

fn query_tree_entries(snapshot: &Snapshot, id: &str) -> RepositoryResult<Vec<QueryTreeEntry>> {
    let Some(Object::Tree(tree)) = snapshot.objects.get(id) else {
        return Err("tree query did not name a stored tree object".into());
    };
    tree.entries
        .iter()
        .map(|(path, id)| {
            let object = query_object(snapshot, id)?;
            if object.kind != "wasm" {
                return Err("stored tree entry is not a Wasm object".into());
            }
            Ok(QueryTreeEntry {
                path: path.clone(),
                object_id: object.object_id,
                kind: object.kind,
                byte_len: object.byte_len,
                stored_byte_len: object.stored_byte_len,
            })
        })
        .collect()
}

fn add_query_bytes(total: &mut u64, value: u64) -> RepositoryResult<()> {
    *total = total
        .checked_add(value)
        .ok_or("object query byte totals exceed u64")?;
    Ok(())
}

fn encode_commit(commit: &Commit) -> RepositoryResult<Vec<u8>> {
    serde_json::to_vec(commit).map_err(|e| format!("encode commit: {e}"))
}

fn encode_object(kind: u8, payload: &[u8]) -> RepositoryResult<Vec<u8>> {
    if ![WASM_KIND, COMMIT_KIND, TREE_KIND].contains(&kind) {
        return Err(format!("unsupported object type {kind}"));
    }
    let len = u64::try_from(payload.len()).map_err(|_| "object exceeds format size".to_string())?;
    let mut bytes = Vec::with_capacity(OBJECT_HEADER_LENGTH.saturating_add(payload.len()));
    bytes.extend_from_slice(OBJECT_MAGIC);
    bytes.push(kind);
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn decode_object(id: &str, bytes: &[u8]) -> RepositoryResult<Object> {
    require_id(id)?;
    if object_id(bytes) != id {
        return Err(format!("object hash mismatch: {id}"));
    }
    if bytes.len() < OBJECT_HEADER_LENGTH || &bytes[..8] != OBJECT_MAGIC {
        return Err(format!("invalid object envelope: {id}"));
    }
    let payload = &bytes[OBJECT_HEADER_LENGTH..];
    let length = u64::from_be_bytes(
        bytes[9..17]
            .try_into()
            .map_err(|_| "invalid object length")?,
    );
    if usize::try_from(length).ok() != Some(payload.len()) {
        return Err(format!("object payload length mismatch: {id}"));
    }
    match bytes[8] {
        WASM_KIND => {
            validate_wasm_header(payload)?;
            Ok(Object::Wasm(payload.to_vec()))
        }
        COMMIT_KIND => {
            let commit: Commit =
                serde_json::from_slice(payload).map_err(|e| format!("invalid commit {id}: {e}"))?;
            if encode_commit(&commit)? != payload {
                return Err(format!("non-canonical commit: {id}"));
            }
            match commit.format {
                1 if commit.tree.is_none() && commit.legacy_path.is_none() => {
                    require_id(&commit.wasm)?
                }
                2 if commit.wasm.is_empty() && commit.tree.is_some() => {
                    require_id(commit.tree.as_deref().ok_or("missing tree ID")?)?;
                    if let Some(path) = &commit.legacy_path {
                        validate_tree_path(path)?;
                    }
                }
                _ => return Err(format!("unsupported or inconsistent commit format: {id}")),
            }
            let mut parents = BTreeSet::new();
            for parent in &commit.parents {
                require_id(parent)?;
                if !parents.insert(parent) {
                    return Err(format!("duplicate parent in commit {id}"));
                }
            }
            Ok(Object::Commit(commit))
        }
        TREE_KIND => {
            let tree: Tree =
                serde_json::from_slice(payload).map_err(|e| format!("invalid tree {id}: {e}"))?;
            if tree.format != 1
                || serde_json::to_vec(&tree).map_err(|e| format!("encode tree: {e}"))? != payload
            {
                return Err(format!("unsupported or non-canonical tree: {id}"));
            }
            validate_tree_paths(tree.entries.keys().map(String::as_str))?;
            for blob in tree.entries.values() {
                require_id(blob)?;
            }
            Ok(Object::Tree(tree))
        }
        kind => Err(format!("unknown repository object type {kind} at {id}")),
    }
}

fn validate_object_graph(objects: &BTreeMap<String, Object>) -> RepositoryResult<()> {
    validated_commit_order(objects).map(|_| ())
}

fn validated_commit_order(objects: &BTreeMap<String, Object>) -> RepositoryResult<Vec<String>> {
    let mut remaining = BTreeMap::<String, usize>::new();
    let mut children = BTreeMap::<String, Vec<String>>::new();
    for (id, object) in objects {
        if let Object::Commit(commit) = object {
            if let Some(tree) = &commit.tree {
                if !matches!(objects.get(tree), Some(Object::Tree(_))) {
                    return Err(format!(
                        "commit {id} has a missing or non-tree object {tree}"
                    ));
                }
            } else if !matches!(objects.get(&commit.wasm), Some(Object::Wasm(_))) {
                return Err(format!(
                    "commit {id} has a missing or non-Wasm blob {}",
                    commit.wasm
                ));
            }
            remaining.insert(id.clone(), commit.parents.len());
            for parent in &commit.parents {
                if !matches!(objects.get(parent), Some(Object::Commit(_))) {
                    return Err(format!(
                        "commit {id} has a missing or non-commit parent {parent}"
                    ));
                }
                let Some(Object::Commit(parent_commit)) = objects.get(parent) else {
                    return Err("missing parent".into());
                };
                if commit.format == 1 && parent_commit.format == 2 {
                    return Err(format!(
                        "legacy commit {id} cannot discard parent file tree {parent}"
                    ));
                }
                if commit.format == 2 && parent_commit.format == 1 && commit.legacy_path.is_none() {
                    return Err(format!(
                        "tree commit {id} requires an explicit legacy path for parent {parent}"
                    ));
                }
                if let Some(anchor) = &parent_commit.legacy_path {
                    if commit.legacy_path.as_ref() != Some(anchor) {
                        return Err(format!(
                            "commit {id} changes or loses inherited legacy path {anchor:?}"
                        ));
                    }
                }
                children.entry(parent.clone()).or_default().push(id.clone());
            }
        }
        if let Object::Tree(tree) = object {
            for (path, blob) in &tree.entries {
                if !matches!(objects.get(blob), Some(Object::Wasm(_))) {
                    return Err(format!(
                        "tree {id} path {path:?} has a missing or non-Wasm blob {blob}"
                    ));
                }
            }
        }
    }
    // Iterative topological validation has no recursion limit for long histories.
    let mut ready: VecDeque<String> = remaining
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order = Vec::with_capacity(remaining.len());
    while let Some(id) = ready.pop_front() {
        order.push(id.clone());
        for child in children.get(&id).into_iter().flatten() {
            let count = remaining.get_mut(child).ok_or("invalid commit graph")?;
            *count -= 1;
            if *count == 0 {
                ready.push_back(child.clone());
            }
        }
    }
    if order.len() != remaining.len() {
        return Err("cyclic commit history".into());
    }
    Ok(order)
}

fn validate_snapshot(
    manifest: &Manifest,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<()> {
    if manifest.format != manifest_format(&manifest.head, &manifest.tags, objects) {
        return Err("unsupported or inconsistent bundle manifest format".into());
    }
    validate_head_identity(&manifest.head)?;
    if valid_id(&manifest.head) && !matches!(objects.get(&manifest.head), Some(Object::Commit(_))) {
        return Err("detached HEAD references a missing or non-commit object".into());
    }
    for (name, id) in &manifest.refs {
        validate_ref_name(name)?;
        require_id(id)?;
        if !matches!(objects.get(id), Some(Object::Commit(_))) {
            return Err(format!(
                "branch {name} references a missing or non-commit object {id}"
            ));
        }
    }
    for (name, id) in &manifest.tags {
        validate_ref_name(name)?;
        require_id(id)?;
        if !matches!(objects.get(id), Some(Object::Commit(_))) {
            return Err(format!(
                "tag {name} references a missing or non-commit object {id}"
            ));
        }
    }
    // HEAD may name an unborn branch even when other branches have been imported.
    validate_object_graph(objects)
}

fn reachable_objects(
    manifest: &Manifest,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<BTreeSet<String>> {
    reachable_from_roots(
        manifest
            .refs
            .values()
            .chain(manifest.tags.values())
            .chain(valid_id(&manifest.head).then_some(&manifest.head))
            .cloned(),
        objects,
    )
}

fn reachable_from_roots(
    roots: impl IntoIterator<Item = String>,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    let mut pending: Vec<String> = roots.into_iter().collect();
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        match objects.get(&id) {
            Some(Object::Commit(commit)) => {
                pending.push(commit.tree.as_ref().unwrap_or(&commit.wasm).clone());
                pending.extend(commit.parents.iter().cloned());
            }
            Some(Object::Tree(tree)) => pending.extend(tree.entries.values().cloned()),
            Some(Object::Wasm(_)) => {}
            None => return Err(format!("missing reachable object {id}")),
        }
    }
    Ok(seen)
}

fn is_ancestor(
    ancestor: &str,
    tip: &str,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<bool> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![tip.to_owned()];
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if id == ancestor {
            return Ok(true);
        }
        match objects.get(&id) {
            Some(Object::Commit(commit)) => pending.extend(commit.parents.iter().cloned()),
            _ => return Err(format!("missing commit {id} during ancestry check")),
        }
    }
    Ok(false)
}

fn deserialize_unique_refs<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueRefs;
    impl<'de> serde::de::Visitor<'de> for UniqueRefs {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a reference map without duplicate names")
        }
        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut result = BTreeMap::new();
            while let Some((name, id)) = map.next_entry::<String, String>()? {
                if result.insert(name.clone(), id).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate reference name {name:?}"
                    )));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(UniqueRefs)
}

fn manifest_state(manifest: &Manifest) -> RepositoryState {
    RepositoryState {
        format: 1,
        head: manifest.head.clone(),
        branches: manifest.refs.clone(),
        tags: manifest.tags.clone(),
    }
}

fn receive_result<T>(result: RepositoryResult<T>, publishing: bool) -> Result<T, ReceiveError> {
    result.map_err(|message| ReceiveError {
        message,
        publication_unknown: publishing,
    })
}

fn check_expected_branch(current: &str, expected: Option<&str>) -> RepositoryResult<()> {
    if expected.is_some_and(|expected| expected != current) {
        return Err(format!(
            "HEAD branch changed: expected {}, actual {current}; no update published",
            expected.unwrap_or("<unspecified>")
        ));
    }
    Ok(())
}

fn check_expected(current: Option<&String>, expected: Option<&str>) -> RepositoryResult<()> {
    if let Some(expected) = expected {
        require_id(expected)?;
    }
    if current.map(String::as_str) != expected {
        return Err(format!(
            "reference changed: expected {}, actual {}; no update published",
            expected.unwrap_or("<unborn>"),
            current.map_or("<unborn>", String::as_str)
        ));
    }
    Ok(())
}

fn check_collisions(current: &Snapshot, incoming: &Snapshot) -> RepositoryResult<()> {
    for (id, encoded) in &incoming.encoded {
        if current
            .encoded
            .get(id)
            .is_some_and(|existing| existing != encoded)
        {
            return Err(format!("object collision at {id}"));
        }
    }
    Ok(())
}

fn snapshot_revision(snapshot: &Snapshot, revision: &str) -> RepositoryResult<String> {
    let split = revision.find(['~', '^']).unwrap_or(revision.len());
    let (base, mut suffix) = revision.split_at(split);
    let mut id = snapshot_base_revision(snapshot, base)?;
    while !suffix.is_empty() {
        let operator = suffix.as_bytes()[0];
        suffix = &suffix[1..];
        if operator == b'^' && suffix.starts_with('{') {
            let (kind, rest) = suffix[1..]
                .split_once('}')
                .ok_or("unterminated revision peel")?;
            if !matches!(kind, "" | "commit" | "object") {
                return Err(format!(
                    "expected a commit revision, unsupported peel: {kind:?}"
                ));
            }
            suffix = rest;
            if !suffix.is_empty() && !suffix.starts_with(['~', '^']) {
                return Err("invalid suffix after revision peel".into());
            }
            continue;
        }
        let digits = suffix.bytes().take_while(u8::is_ascii_digit).count();
        let count = if digits == 0 {
            1
        } else {
            suffix[..digits]
                .parse::<usize>()
                .map_err(|_| "revision ancestry count exceeds host size")?
        };
        suffix = &suffix[digits..];
        if !suffix.is_empty() && !suffix.starts_with('~') && !suffix.starts_with('^') {
            return Err(format!("invalid revision ancestry suffix: {revision:?}"));
        }
        if operator == b'^' {
            if count == 0 {
                continue;
            }
            let Some(Object::Commit(commit)) = snapshot.objects.get(&id) else {
                return Err(format!("missing commit {id}"));
            };
            id = commit
                .parents
                .get(count - 1)
                .cloned()
                .ok_or_else(|| format!("revision {revision:?} has no parent {count}"))?;
        } else {
            // Every step consumes an existing DAG edge; impossible huge counts
            // stop at a root without iterating an attacker-supplied full count.
            for _ in 0..count {
                let Some(Object::Commit(commit)) = snapshot.objects.get(&id) else {
                    return Err(format!("missing commit {id}"));
                };
                id = commit.parents.first().cloned().ok_or_else(|| {
                    format!("revision {revision:?} reaches a root before its requested ancestor")
                })?;
            }
        }
    }
    Ok(id)
}

fn snapshot_base_revision(snapshot: &Snapshot, revision: &str) -> RepositoryResult<String> {
    if let Some(id) = revision_syntax::special_revision(snapshot, revision)? {
        return Ok(id);
    }
    let mut candidates = Vec::new();
    if revision == "HEAD" {
        candidates.push(
            snapshot
                .manifest
                .tip()
                .cloned()
                .ok_or_else(|| format!("branch {} has no commits", snapshot.manifest.head))?,
        );
    } else if let Some(name) = revision.strip_prefix("refs/heads/") {
        validate_ref_name(name)?;
        if let Some(id) = snapshot.manifest.refs.get(name) {
            candidates.push(id.clone());
        }
    } else if let Some(name) = revision.strip_prefix("refs/tags/") {
        validate_ref_name(name)?;
        if let Some(id) = snapshot.manifest.tags.get(name) {
            candidates.push(id.clone());
        }
    } else if let Some(name) = revision.strip_prefix("refs/remotes/") {
        if let Some(id) = snapshot.tracking.get(name) {
            candidates.push(id.clone());
        }
    } else if valid_id(revision) {
        candidates.push(revision.into());
    } else {
        let ref_name = validate_ref_name(revision);
        if let Some(id) = snapshot.manifest.refs.get(revision) {
            candidates.push(id.clone());
        }
        if let Some(id) = snapshot.manifest.tags.get(revision) {
            candidates.push(id.clone());
        }
        if let Some(id) = snapshot.tracking.get(revision) {
            candidates.push(id.clone());
        }
        if (4..64).contains(&revision.len())
            && revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            for (id, object) in &snapshot.objects {
                if id.starts_with(revision) && matches!(object, Object::Commit(_)) {
                    candidates.push(id.clone());
                }
            }
        }
        // Exact stored names and the pre-existing bare commit-prefix
        // rules retain priority. A generated description may exceed the
        // ref-name length limit; its label and decimal distance are only
        // hints, while its suffix must identify one actual commit.
        if candidates.is_empty() {
            if let Some(prefix) = description_commit_prefix(revision) {
                return described_commit(snapshot, revision, &prefix);
            }
        }
        ref_name?;
    }
    let id = match candidates.as_slice() {
        [] => return Err(format!("unknown revision: {revision}")),
        [id] => id.clone(),
        _ => {
            return Err(format!(
                "ambiguous revision: {revision}; use a full object ID or qualified ref"
            ))
        }
    };
    if !matches!(snapshot.objects.get(&id), Some(Object::Commit(_))) {
        return Err(format!("revision {id} is a missing or non-commit object"));
    }
    Ok(id)
}

fn description_commit_prefix(revision: &str) -> Option<String> {
    let (head, prefix) = revision.rsplit_once("-g")?;
    if !(4..=64).contains(&prefix.len()) || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let (label, distance) = head.rsplit_once('-')?;
    if label.is_empty()
        || label.len() > 128
        || !label.as_bytes()[0].is_ascii_alphanumeric()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte))
        || label
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || distance.is_empty()
        || !distance.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(prefix.to_ascii_lowercase())
}

fn described_commit(snapshot: &Snapshot, revision: &str, prefix: &str) -> RepositoryResult<String> {
    let matches: Vec<_> = snapshot
        .objects
        .keys()
        .filter(|id| id.starts_with(prefix))
        .take(2)
        .collect();
    match matches.as_slice() {
        [] => Err(format!("unknown described revision: {revision}")),
        [id] if matches!(snapshot.objects.get(*id), Some(Object::Commit(_))) => Ok((*id).clone()),
        [_] => Err(format!("described revision {revision:?} identifies a non-commit object")),
        _ => Err(format!("ambiguous described revision: {revision}; suffix must be unique across all stored objects")),
    }
}

fn snapshot_wasm<'a>(snapshot: &'a Snapshot, commit_id: &str) -> RepositoryResult<&'a [u8]> {
    let Some(Object::Commit(commit)) = snapshot.objects.get(commit_id) else {
        return Err(format!("missing merge commit {commit_id}"));
    };
    require_legacy_commit(commit)?;
    match snapshot.objects.get(&commit.wasm) {
        Some(Object::Wasm(bytes)) => Ok(bytes),
        _ => Err(format!(
            "merge commit {commit_id} has a missing or non-Wasm blob"
        )),
    }
}

fn ancestors(tip: &str, objects: &BTreeMap<String, Object>) -> RepositoryResult<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![tip.to_owned()];
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        match objects.get(&id) {
            Some(Object::Commit(commit)) => pending.extend(commit.parents.iter().cloned()),
            _ => return Err(format!("missing commit {id} during merge-base traversal")),
        }
    }
    Ok(seen)
}

fn bisect_kind_name(kind: BisectKind) -> &'static str {
    match kind {
        BisectKind::Good => "good",
        BisectKind::Bad => "bad",
        BisectKind::Skip => "skip",
    }
}

fn validate_bisect_shape(state: &BisectState) -> RepositoryResult<()> {
    if state.version != 1 {
        return Err("unsupported bisect journal version".into());
    }
    require_id(&state.id)?;
    require_id(&state.original_bad)?;
    if state.initial_good.is_empty() {
        return Err("bisect journal requires initial good commits".into());
    }
    if state.marks.len() > MAX_BISECT_MARKS {
        return Err("bisect journal exceeds the 4096 mark-event limit".into());
    }
    let check_ids = |ids: &[String]| -> RepositoryResult<()> {
        if ids.is_empty() || ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("bisect revision arrays must be nonempty, sorted and unique".into());
        }
        for id in ids {
            require_id(id)?;
        }
        Ok(())
    };
    check_ids(&state.initial_good)?;
    for mark in &state.marks {
        check_ids(&mark.revisions)?;
        if mark.kind == BisectKind::Bad && mark.revisions.len() != 1 {
            return Err("bisect bad event requires exactly one commit".into());
        }
    }
    Ok(())
}

fn encode_bisect(state: &BisectState) -> RepositoryResult<Vec<u8>> {
    validate_bisect_shape(state)?;
    // Bound serialization itself, not just the completed allocation.
    struct BoundedJournal(Vec<u8>);
    impl Write for BoundedJournal {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > (MAX_BISECT_BYTES as usize).saturating_sub(self.0.len()) {
                return Err(std::io::Error::other(
                    "bisect journal exceeds the 1 MiB encoded limit",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = BoundedJournal(Vec::new());
    serde_json::to_writer(&mut output, state)
        .map_err(|error| format!("encode bisect journal: {error}"))?;
    output
        .write_all(b"\n")
        .map_err(|error| format!("encode bisect journal: {error}"))?;
    if output.0.len() as u64 > MAX_BISECT_BYTES {
        return Err("bisect journal exceeds the 1 MiB encoded limit".into());
    }
    Ok(output.0)
}

fn bisect_region(
    snapshot: &Snapshot,
    first_parent: bool,
    progress: &BisectProgress,
) -> RepositoryResult<(BTreeSet<String>, BTreeSet<String>)> {
    let mut known_good = BTreeSet::new();
    for good in &progress.good {
        known_good.extend(describe_ancestors(good, &snapshot.objects, first_parent)?);
    }
    if known_good.contains(&progress.bad) {
        return Err("bisect good history contains the known-bad commit".into());
    }
    let region = describe_ancestors(&progress.bad, &snapshot.objects, first_parent)?
        .difference(&known_good)
        .cloned()
        .collect();
    Ok((region, known_good))
}

fn apply_bisect_mark(
    snapshot: &Snapshot,
    first_parent: bool,
    domain: &BTreeSet<String>,
    progress: &mut BisectProgress,
    kind: BisectKind,
    revisions: &[String],
) -> RepositoryResult<BisectMark> {
    if revisions.is_empty() || revisions.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("bisect marks require nonempty sorted unique commits".into());
    }
    if kind == BisectKind::Bad && revisions.len() != 1 {
        return Err("bisect bad requires exactly one revision".into());
    }
    let (region, known_good) = bisect_region(snapshot, first_parent, progress)?;
    let mut effective = Vec::new();
    // Admit the entire batch against the same before-state, then mutate it.
    for id in revisions {
        require_id(id)?;
        if !domain.contains(id) || !matches!(snapshot.objects.get(id), Some(Object::Commit(_))) {
            return Err(format!(
                "bisect revision {id} is outside the frozen original history domain"
            ));
        }
        match kind {
            BisectKind::Good => {
                if known_good.contains(id) {
                    continue;
                }
                if describe_ancestors(id, &snapshot.objects, first_parent)?.contains(&progress.bad)
                {
                    return Err(format!(
                        "bisect good {id} would classify the current bad commit as good"
                    ));
                }
            }
            BisectKind::Bad => {
                if id == &progress.bad {
                    continue;
                }
                if !region.contains(id) {
                    return Err(format!(
                        "bisect bad {id} cannot expand or contradict the current uncertain history"
                    ));
                }
            }
            BisectKind::Skip => {
                if known_good.contains(id)
                    || describe_ancestors(id, &snapshot.objects, first_parent)?
                        .contains(&progress.bad)
                {
                    return Err(format!(
                        "bisect cannot skip the already classified commit {id}"
                    ));
                }
                if progress.skip.contains(id) {
                    continue;
                }
            }
        }
        effective.push(id.clone());
    }
    for id in &effective {
        match kind {
            BisectKind::Good => {
                progress.good.insert(id.clone());
                progress.skip.remove(id);
            }
            BisectKind::Bad => {
                progress.bad = id.clone();
                progress.skip.remove(id);
            }
            BisectKind::Skip => {
                progress.skip.insert(id.clone());
            }
        }
    }
    Ok(BisectMark {
        kind,
        revisions: effective,
    })
}

fn replay_bisect(snapshot: &Snapshot, state: &BisectState) -> RepositoryResult<BisectProgress> {
    validate_bisect_shape(state)?;
    let domain = describe_ancestors(&state.original_bad, &snapshot.objects, state.first_parent)?;
    for good in &state.initial_good {
        if good == &state.original_bad || !domain.contains(good) {
            return Err("bisect initial good must be a strict ancestor of the original bad under the selected parent policy".into());
        }
    }
    let mut progress = BisectProgress {
        bad: state.original_bad.clone(),
        good: state.initial_good.iter().cloned().collect(),
        skip: BTreeSet::new(),
    };
    for mark in &state.marks {
        let effective = apply_bisect_mark(
            snapshot,
            state.first_parent,
            &domain,
            &mut progress,
            mark.kind,
            &mark.revisions,
        )?;
        if effective != *mark || effective.revisions.is_empty() {
            return Err("bisect journal contains a redundant or invalid transition".into());
        }
    }
    Ok(progress)
}

fn empty_bisect_report(
    operation: &str,
    status: &str,
    changed: bool,
    verification: &str,
) -> BisectReport {
    BisectReport { schema_version: 1, operation: operation.into(), status: status.into(), active: false, changed,
        generation: None, first_parent: false, original_bad: None, initial_good: Vec::new(), bad: None,
        good: Vec::new(), skip: Vec::new(), candidate: None, remaining: Vec::new(), testable: Vec::new(),
        suspects: Vec::new(), first_bad: None, marks: Vec::new(), object_verification: verification.into(),
        no_checkout: true, head_updated: false, index_updated: false, worktree_updated: false, pending_updated: false,
        selection_policy: "minimize max(|ancestors(candidate) intersect remaining|, |remaining| minus that weight); include skipped commits in weights; exclude current bad and active skips from testing; tie by ASCII full commit ID".into() }
}

fn bisect_report(
    snapshot: &Snapshot,
    state: &BisectState,
    progress: &BisectProgress,
    operation: &str,
    changed: bool,
) -> RepositoryResult<BisectReport> {
    let (region, _) = bisect_region(snapshot, state.first_parent, progress)?;
    if !region.contains(&progress.bad) {
        return Err("bisect uncertain history lost its known-bad commit".into());
    }
    let skip: BTreeSet<_> = progress
        .skip
        .intersection(&region)
        .filter(|id| *id != &progress.bad)
        .cloned()
        .collect();
    let testable: BTreeSet<_> = region
        .iter()
        .filter(|id| *id != &progress.bad && !skip.contains(*id))
        .cloned()
        .collect();
    let mut report = empty_bisect_report(operation, "testing", changed, "full_snapshot");
    report.active = true;
    report.generation = Some(state.id.clone());
    report.first_parent = state.first_parent;
    report.original_bad = Some(state.original_bad.clone());
    report.initial_good = state.initial_good.clone();
    report.bad = Some(progress.bad.clone());
    report.good = progress.good.iter().cloned().collect();
    report.skip = skip.into_iter().collect();
    report.remaining = region.iter().cloned().collect();
    report.suspects = report.remaining.clone();
    report.testable = testable.iter().cloned().collect();
    report.marks = state.marks.clone();
    if region.len() == 1 {
        report.status = "found".into();
        report.first_bad = Some(progress.bad.clone());
    } else if testable.is_empty() {
        report.status = "ambiguous_skipped".into();
    } else {
        let mut best: Option<(usize, String)> = None;
        for id in testable {
            let weight = describe_ancestors(&id, &snapshot.objects, state.first_parent)?
                .intersection(&region)
                .count();
            let scored = (weight.max(region.len() - weight), id);
            if best.as_ref().is_none_or(|previous| &scored < previous) {
                best = Some(scored);
            }
        }
        report.candidate = best.map(|(_, id)| id);
    }
    Ok(report)
}

fn describe_ancestors(
    tip: &str,
    objects: &BTreeMap<String, Object>,
    first_parent: bool,
) -> RepositoryResult<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![tip.to_owned()];
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let Some(Object::Commit(commit)) = objects.get(&id) else {
            return Err(format!("missing commit {id} during ancestry traversal"));
        };
        if first_parent {
            pending.extend(commit.parents.first().cloned());
        } else {
            pending.extend(commit.parents.iter().cloned());
        }
    }
    Ok(seen)
}

fn unique_object_abbreviation(
    id: &str,
    requested: usize,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<String> {
    require_id(id)?;
    if requested > 64 {
        return Err("describe abbreviation must be in 0..=64".into());
    }
    if !objects.contains_key(id) {
        return Err(format!("unknown describe object: {id}"));
    }
    if requested == 0 {
        return Ok(id.into());
    }
    for length in requested.max(4)..=64 {
        let prefix = &id[..length];
        if !objects
            .keys()
            .any(|other| other != id && other.starts_with(prefix))
        {
            return Ok(prefix.into());
        }
    }
    Err("stored object IDs do not have a unique complete abbreviation".into())
}

fn best_merge_bases(
    left: &str,
    right: &str,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<Vec<String>> {
    let left = ancestors(left, objects)?;
    let right = ancestors(right, objects)?;
    let common: BTreeSet<_> = left.intersection(&right).cloned().collect();
    let mut dominated = BTreeSet::new();
    // The common ancestor set is closed under parent edges. Consequently a
    // common ancestor is best precisely when it has no common descendant; any
    // non-best one has a direct child in this set, so no quadratic searches or
    // traversal-order tie breaks are needed.
    for id in &common {
        let Some(Object::Commit(commit)) = objects.get(id) else {
            return Err(format!("missing common ancestor {id}"));
        };
        dominated.extend(commit.parents.iter().cloned());
    }
    Ok(common.difference(&dominated).cloned().collect())
}

fn unique_merge_base(
    left: &str,
    right: &str,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<String> {
    let bases = best_merge_bases(left, right, objects)?;
    match bases.as_slice() {
        [] => Err("cannot merge unrelated histories: no common merge base".into()),
        [base] => Ok(base.clone()),
        _ => Err(format!(
            "cannot merge histories with multiple best merge bases; no base guessed: {}",
            bases.join(", ")
        )),
    }
}

fn encode_bundle(snapshot: &Snapshot) -> RepositoryResult<Vec<u8>> {
    let manifest = serde_json::to_vec(&snapshot.manifest)
        .map_err(|e| format!("encode bundle manifest: {e}"))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BUNDLE_MAGIC);
    bytes.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&manifest);
    bytes.extend_from_slice(&(snapshot.encoded.len() as u64).to_be_bytes());
    for (id, encoded) in &snapshot.encoded {
        // ASCII hex is deliberately retained for straightforward offline auditing.
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        bytes.extend_from_slice(encoded);
    }
    Ok(bytes)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> RepositoryResult<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or("bundle length overflow")?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or("truncated bundle")?;
        self.position = end;
        Ok(result)
    }

    fn number(&mut self) -> RepositoryResult<usize> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| "invalid bundle integer")?;
        usize::try_from(u64::from_be_bytes(bytes))
            .map_err(|_| "bundle length exceeds host size".into())
    }
}

fn decode_bundle(bytes: &[u8]) -> RepositoryResult<Snapshot> {
    let mut cursor = Cursor { bytes, position: 0 };
    if cursor.take(8)? != BUNDLE_MAGIC {
        return Err("unsupported bundle format".into());
    }
    let manifest_length = cursor.number()?;
    let manifest_bytes = cursor.take(manifest_length)?;
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| format!("invalid bundle manifest: {e}"))?;
    if serde_json::to_vec(&manifest).map_err(|e| format!("encode manifest: {e}"))? != manifest_bytes
    {
        return Err("non-canonical or duplicate-key bundle manifest".into());
    }
    let count = cursor.number()?;
    if count > bytes.len().saturating_sub(cursor.position) / (64 + 8 + OBJECT_HEADER_LENGTH) {
        return Err("bundle object count exceeds available bytes".into());
    }
    let mut encoded = BTreeMap::new();
    let mut objects = BTreeMap::new();
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let id = std::str::from_utf8(cursor.take(64)?)
            .map_err(|_| "non-ASCII bundle object ID".to_string())?
            .to_owned();
        require_id(&id)?;
        if previous.as_ref().is_some_and(|value| value >= &id) {
            return Err("bundle object IDs are duplicated or out of canonical order".into());
        }
        let length = cursor.number()?;
        let object_bytes = cursor.take(length)?;
        let object = decode_object(&id, object_bytes)?;
        previous = Some(id.clone());
        objects.insert(id.clone(), object);
        encoded.insert(id, object_bytes.to_vec());
    }
    if cursor.position != bytes.len() {
        return Err("unexpected trailing bytes in bundle".into());
    }
    validate_snapshot(&manifest, &objects)?;
    Ok(Snapshot {
        manifest,
        upstreams: BTreeMap::new(),
        upstream_tips: BTreeMap::new(),
        checkouts: Vec::new(),
        head_reflog: Vec::new(),
        tracking: BTreeMap::new(),
        reflog: Vec::new(),
        encoded,
        objects,
    })
}

fn require_directory(path: &Path) -> RepositoryResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| io_error("inspect directory", path, e))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("expected a real directory: {}", path.display()));
    }
    Ok(())
}

fn read_regular(path: &Path) -> RepositoryResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io_error("inspect file", path, e))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("expected a regular file: {}", path.display()));
    }
    let mut file = File::open(path).map_err(|e| io_error("open file", path, e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| io_error("read file", path, e))?;
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> RepositoryResult<()> {
    crate::output::write_new_file(path, bytes)
}

fn sync_directory(path: &Path) -> RepositoryResult<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| io_error("sync directory", path, e))
}

fn unique_name(kind: &str) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(
        "{kind}-{}-{timestamp}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn io_error(action: &str, path: &Path, error: std::io::Error) -> String {
    format!("cannot {action} {}: {error}", path.display())
}

/// Repository command dispatch. The first argument is the command, not argv[0].
pub fn run(args: &[String]) -> RepositoryResult<String> {
    // Handle help before interpreting paths or performing any filesystem action.
    // Prefix a literal path named --help/-h with ./ to disambiguate it.
    if crate::command_args::help_requested(args) {
        return Ok(REPOSITORY_USAGE.into());
    }
    let command = args.first().map(String::as_str).unwrap_or("");
    let ff_only = if command == "merge" {
        crate::command_args::option_indices(args, "--ff-only")
    } else {
        Vec::new()
    };
    let no_ff = if command == "merge" {
        crate::command_args::option_indices(args, "--no-ff")
    } else {
        Vec::new()
    };
    if !ff_only.is_empty() && !no_ff.is_empty() {
        return Err("merge --ff-only and --no-ff are mutually exclusive".into());
    }
    if no_ff.len() > 1 {
        return Err("merge --no-ff may be supplied only once".into());
    }
    match command {
        "init" if args.len() == 2 => {
            let repo = Repository::init(&args[1])?;
            Ok(format!("initialized {}", repo.metadata.display()))
        }
        "commit" if args.len() == 5 && matches!(args[3].as_str(), "-m" | "--message") => {
            let repo = Repository::open(&args[1])?;
            let bytes = read_regular(Path::new(&args[2]))?;
            let id = repo.commit(&bytes, &args[4])?;
            Ok(format!("{} {id}", repo.current_branch()?))
        }
        "merge" if !ff_only.is_empty() || !no_ff.is_empty() => {
            if ff_only.len() > 1 {
                return Err("merge --ff-only may be supplied only once".into());
            }
            if ["--resolved", "--resolved-index", "--expect-head", "--expect-branch"]
                .iter()
                .any(|option| !crate::command_args::option_indices(args, option).is_empty())
            {
                return Err("merge --ff-only cannot be combined with manual resolution or --expect-* options".into());
            }
            let normalized: Vec<_> = args
                .iter()
                .enumerate()
                .filter_map(|(index, value)| (!ff_only.contains(&index) && !no_ff.contains(&index)).then_some(value.as_str()))
                .collect();
            let (root, target, message) = match normalized.as_slice() {
                [_, root, target] if no_ff.is_empty() => (*root, *target, ""),
                [_, root, target, message_flag, message]
                    if matches!(*message_flag, "-m" | "--message") =>
                {
                    (*root, *target, *message)
                }
                _ => return Err("fast-forward-only merge requires merge <DIR> <REF_OR_ID> [-m <MESSAGE>] --ff-only".into()),
            };
            let repo = Repository::open(root)?;
            let state = repo.state()?;
            let outcome = if no_ff.is_empty() { repo.merge_ff_only_on_branch(target,message,&state.head,state.tip().map(String::as_str))? }
            else { repo.merge_no_ff_on_branch(target,message,&state.head,state.tip().map(String::as_str))? };
            serde_json::to_string_pretty(&outcome)
                .map_err(|e| format!("encode merge outcome: {e}"))
        }
        "merge" if args.len() == 5 && matches!(args[3].as_str(), "-m" | "--message") => {
            let repo = Repository::open(&args[1])?;
            let state = repo.state()?;
            let outcome = repo.merge_on_branch(&args[2], &args[4], &state.head, state.tip().map(String::as_str))?;
            serde_json::to_string_pretty(&outcome)
                .map_err(|e| format!("encode merge outcome: {e}"))
        }
        "merge"
            if args.len() == 9
                && matches!(args[3].as_str(), "-m" | "--message")
                && args[5] == "--resolved"
                && args[7] == "--expect-head" =>
        {
            let bytes = read_regular(Path::new(&args[6]))?;
            let repo = Repository::open(&args[1])?;
            let state = repo.state()?;
            let outcome = repo.merge_resolved_on_branch(&state.head, &args[8], &args[2], &bytes, &args[4])?;
            serde_json::to_string_pretty(&outcome)
                .map_err(|e| format!("encode manual merge outcome: {e}"))
        }
        "merge" if args.iter().any(|arg| arg == "--resolved") => Err(
            "manual resolution requires merge <DIR> <IMMUTABLE_TARGET_ID> -m <MESSAGE> --resolved <WASM> --expect-head <REVIEWED_HEAD_ID>".into(),
        ),
        "merge-base" if args.len() == 4 => {
            let bases = Repository::open(&args[1])?.merge_bases(&args[2], &args[3])?;
            serde_json::to_string_pretty(&bases).map_err(|e| format!("encode merge bases: {e}"))
        }
        "log" if (2..=3).contains(&args.len()) => {
            let repo = Repository::open(&args[1])?;
            let entries = repo.log(args.get(2).map(String::as_str))?;
            serde_json::to_string_pretty(&entries).map_err(|e| format!("encode log: {e}"))
        }
        "show" if args.len() == 3 => {
            let repo = Repository::open(&args[1])?;
            serde_json::to_string_pretty(&repo.read_commit(&args[2])?)
                .map_err(|e| format!("encode commit: {e}"))
        }
        "show" if args.len() == 5 && args[3] == "--output" => {
            let repo = Repository::open(&args[1])?;
            let id = repo.checkout(&args[2], &args[4])?;
            Ok(format!("wrote {id} to {}", args[4]))
        }
        "checkout" if args.len() == 4 => {
            let repo = Repository::open(&args[1])?;
            let id = repo.checkout(&args[2], &args[3])?;
            Ok(format!("wrote {id} to {}", args[3]))
        }
        "branch" if args.len() == 2 => {
            let repo = Repository::open(&args[1])?;
            let head = repo.current_branch()?;
            let refs = repo.branches()?;
            let lines: Vec<_> = refs
                .iter()
                .map(|(name, id)| format!("{} {name} {id}", if name == &head { "*" } else { " " }))
                .collect();
            Ok(if lines.is_empty() {
                format!("* {head} (no commits)")
            } else {
                lines.join("\n")
            })
        }
        "branch" if (3..=4).contains(&args.len()) => {
            let repo = Repository::open(&args[1])?;
            let id = repo.create_branch(&args[2], args.get(3).map_or("HEAD", String::as_str))?;
            Ok(format!("{} {id}", args[2]))
        }
        "switch" if args.len() == 3 => {
            Repository::open(&args[1])?.switch_branch(&args[2])?;
            Ok(format!("HEAD -> {}", args[2]))
        }
        "clone" if args.len() == 3 => {
            let repo = Repository::clone_local(&args[1], &args[2])?;
            Ok(format!("cloned {} into {}", args[1], repo.root.display()))
        }
        "bundle" if args.len() == 3 => {
            let count = Repository::open(&args[1])?.export_bundle(&args[2])?;
            Ok(format!("wrote {count} verified objects to {}", args[2]))
        }
        "unbundle" if args.len() == 4 => {
            let id = Repository::open(&args[1])?.import_bundle(&args[2], &args[3])?;
            Ok(format!("{} {id}", args[3]))
        }
        "fsck" if args.len() == 2 => {
            let report = Repository::open(&args[1])?.fsck()?;
            serde_json::to_string_pretty(&report).map_err(|e| format!("encode fsck report: {e}"))
        }
        _ => Err(REPOSITORY_USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            // All test artifacts are explicitly confined to /tmp on every host.
            let path = PathBuf::from("/tmp").join(unique_name("uwgit-repository-test"));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn repo(&self, name: &str) -> Repository {
            Repository::init(self.path(name)).unwrap()
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn wasm(extra: &[u8]) -> Vec<u8> {
        [WASM_HEADER.as_slice(), extra].concat()
    }

    fn files(entries: &[(&str, Vec<u8>)]) -> BTreeMap<String, Vec<u8>> {
        entries
            .iter()
            .map(|(path, bytes)| ((*path).into(), bytes.clone()))
            .collect()
    }

    fn commit_tree(
        repo: &Repository,
        files: &BTreeMap<String, Vec<u8>>,
        message: &str,
        anchor: Option<&str>,
    ) -> String {
        let state = repo.state().unwrap();
        let parent = state.tip();
        let parents: Vec<_> = parent.cloned().into_iter().collect();
        repo.commit_files_on_branch(
            files,
            message,
            &parents,
            &state.head,
            parent.map(String::as_str),
            anchor,
        )
        .unwrap()
    }

    fn pending_index_bytes(files: &BTreeMap<String, Vec<u8>>, anchor: Option<&str>) -> Vec<u8> {
        #[derive(Serialize)]
        struct TestIndex<'a> {
            format: u32,
            files: &'a BTreeMap<String, Vec<u8>>,
            legacy_path: Option<&'a str>,
        }
        let mut raw = b"UWGITIDX\x02".to_vec();
        serde_json::to_writer(
            &mut raw,
            &TestIndex {
                format: 2,
                files,
                legacy_path: anchor,
            },
        )
        .unwrap();
        raw.push(b'\n');
        raw
    }

    fn pending_fixture(temp: &TempDirectory, name: &str) -> (Repository, String, String) {
        let repo = temp.repo(name);
        let base = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[0, 2, 0, 10]))]),
            "base",
            None,
        );
        repo.create_branch("incoming", &base).unwrap();
        repo.switch_branch("incoming").unwrap();
        let target = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[0, 2, 0, 20]))]),
            "incoming",
            None,
        );
        repo.switch_branch("main").unwrap();
        let head = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[0, 2, 0, 30]))]),
            "ours",
            None,
        );
        (repo, head, target)
    }

    fn pending_request(
        repo: &Repository,
        operation: &str,
        head: &str,
        target: &str,
    ) -> PendingRequest {
        let original = repo.files_at(head).unwrap();
        PendingRequest {
            operation: operation.into(),
            branch: "main".into(),
            head: head.into(),
            target: target.into(),
            mainline: None,
            message: "reviewed complete index".into(),
            baseline_index: Some(pending_index_bytes(
                &original.files,
                original.legacy_path.as_deref(),
            )),
            legacy_path: original.legacy_path,
        }
    }

    fn prepare_pending_fixture(
        repo: &Repository,
        pending: &PendingOperation,
        files: &BTreeMap<String, Vec<u8>>,
        raw: &[u8],
    ) -> PendingOperation {
        let snapshot = repo.snapshot().unwrap();
        let mut encoded = BTreeMap::new();
        let commit = prepare_tree_commit(
            files,
            &pending.message,
            &pending_parents(pending),
            pending.legacy_path.as_deref(),
            &snapshot.encoded,
            &mut encoded,
        )
        .unwrap();
        repo.install_tree_objects(&encoded, std::slice::from_ref(&commit))
            .unwrap();
        let mut prepared = pending.clone();
        prepared.prepared = Some(PendingPrepared {
            commit,
            index_sha256: format!("{:x}", Sha256::digest(raw)),
        });
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&prepared).unwrap(),
        )
        .unwrap();
        prepared
    }

    #[test]
    fn detached_prepared_continuation_recovers_publication_and_local_reflog_exactly_once() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "detached-recovery");
        repo.detach_head(&head).unwrap();
        let mut request = pending_request(&repo, "merge", &head, &target);
        request.branch = head.clone();
        let pending = repo.record_pending(request).unwrap();
        let result = files(&[("a.wasm", wasm(&[0, 2, 0, 40]))]);
        let raw = pending_index_bytes(&result, None);
        let prepared = prepare_pending_fixture(&repo, &pending, &result, &raw);
        let commit = prepared.prepared.as_ref().unwrap().commit.clone();
        let objects = repo.snapshot().unwrap().encoded;
        // Simulate interruption immediately after the true HEAD file was
        // published, before either completion log or journal cleanup.
        fs::write(repo.metadata.join("HEAD"), format!("{commit}\n")).unwrap();
        fs::remove_file(repo.metadata.join("head-reflog.json")).unwrap();
        let old_log = repo.reflog().unwrap().len();
        let outcome = repo.continue_pending(&prepared, None).unwrap();
        assert!(outcome.already_published && outcome.resumed_prepared);
        assert_eq!(outcome.commit, commit);
        assert_eq!(repo.state().unwrap().head, commit);
        assert_eq!(repo.resolve("main").unwrap(), head);
        assert_eq!(repo.snapshot().unwrap().encoded, objects);
        assert_eq!(repo.reflog().unwrap().len(), old_log + 1);
        let local_log = repo.read_head_reflog().unwrap();
        assert_eq!(local_log.len(), 1);
        assert_eq!(local_log[0].old.as_ref(), Some(&head));
        assert_eq!(local_log[0].new.as_ref(), Some(&commit));
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&prepared).unwrap(),
        )
        .unwrap();
        assert!(
            repo.continue_pending(&prepared, None)
                .unwrap()
                .already_published
        );
        assert_eq!(repo.read_head_reflog().unwrap(), local_log);
        assert_eq!(repo.reflog().unwrap().len(), old_log + 1);
    }

    #[test]
    fn pending_record_is_local_canonical_and_does_not_change_objects_refs_or_bundle() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "local");
        let before = stored_state(&repo);
        let bundle_before = repo.bundle_bytes(None).unwrap();
        let request = pending_request(&repo, "merge", &head, &target);
        let original_index = request.baseline_index.clone();
        let pending = repo.record_pending(request).unwrap();
        assert_eq!(pending.baseline_index, original_index);
        assert_eq!(pending.version, 1);
        require_id(&pending.id).unwrap();
        assert_eq!(repo.pending().unwrap(), Some(pending.clone()));
        assert_eq!(
            fs::read(repo.metadata.join("pending.json")).unwrap(),
            encode_pending(&pending).unwrap()
        );
        assert_eq!(stored_state(&repo), before);
        assert_eq!(repo.bundle_bytes(None).unwrap(), bundle_before);
        assert!(!repo.metadata.join("index").exists());
        let clone = Repository::clone_local(&repo.root, temp.path("clone")).unwrap();
        assert!(clone.pending().unwrap().is_none());
        assert_eq!(clone.state().unwrap(), repo.state().unwrap());
        assert!(repo
            .record_pending(pending_request(&repo, "merge", &head, &target))
            .is_err());
        repo.quit_pending(&pending).unwrap();
        let next = repo
            .record_pending(pending_request(&repo, "merge", &head, &target))
            .unwrap();
        assert_ne!(pending.id, next.id);
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn pending_continue_publishes_reviewed_parents_and_four_sides_without_touching_index_or_work() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "continue");
        let pending = repo
            .record_pending(pending_request(&repo, "merge", &head, &target))
            .unwrap();
        let result = files(&[("a.wasm", wasm(&[0, 2, 0, 40])), ("extra.wasm", wasm(&[]))]);
        let raw = pending_index_bytes(&result, None);
        fs::write(repo.metadata.join("index"), &raw).unwrap();
        fs::write(repo.root.join("a.wasm"), b"dirty non-Wasm user edits").unwrap();
        let outcome = repo
            .continue_pending(
                &pending,
                Some(PendingIndex {
                    files: &result,
                    legacy_path: None,
                    raw: &raw,
                }),
            )
            .unwrap();
        assert_eq!(outcome.status, "continued");
        assert_eq!(outcome.parents, vec![head.clone(), target.clone()]);
        assert_eq!(
            repo.read_commit(&outcome.commit).unwrap().commit.parents,
            outcome.parents
        );
        assert_eq!(repo.files_at(&outcome.commit).unwrap().files, result);
        assert_eq!(fs::read(repo.metadata.join("index")).unwrap(), raw);
        assert_eq!(
            fs::read(repo.root.join("a.wasm")).unwrap(),
            b"dirty non-Wasm user edits"
        );
        assert!(!outcome.already_published && !outcome.resumed_prepared);
        assert_eq!(outcome.index_matches_prepared, Some(true));
        assert!(!outcome.index_updated && !outcome.worktree_updated);
        assert!(outcome.pending_cleared && repo.pending().unwrap().is_none());
        let a = outcome
            .tree_manual_resolution
            .files
            .iter()
            .find(|file| file.path == "a.wasm")
            .unwrap();
        assert_eq!(
            a.base.as_ref().unwrap().hex,
            wasm(&[0, 2, 0, 10])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(
            a.ours.as_ref().unwrap().byte_len,
            wasm(&[0, 2, 0, 30]).len()
        );
        assert_eq!(
            a.theirs.as_ref().unwrap().sha256,
            format!("{:x}", Sha256::digest(wasm(&[0, 2, 0, 20])))
        );
        assert_eq!(
            a.resolved.as_ref().unwrap().sha256,
            format!("{:x}", Sha256::digest(&result["a.wasm"]))
        );
        assert_eq!(
            repo.reflog()
                .unwrap()
                .iter()
                .filter(|entry| entry.operation == format!("pending-continue-{}", pending.id))
                .count(),
            1
        );
    }

    #[test]
    fn pending_prepared_before_ref_requires_exact_index_and_reuses_installed_commit() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "prepared-before");
        let pending = repo
            .record_pending(pending_request(&repo, "cherry-pick", &head, &target))
            .unwrap();
        let result = files(&[("a.wasm", wasm(&[0, 2, 0, 40]))]);
        let raw = pending_index_bytes(&result, None);
        let prepared = prepare_pending_fixture(&repo, &pending, &result, &raw);
        let before = stored_state(&repo);
        let wrong = files(&[("a.wasm", wasm(&[0, 2, 0, 50]))]);
        let wrong_raw = pending_index_bytes(&wrong, None);
        assert!(repo
            .continue_pending(
                &prepared,
                Some(PendingIndex {
                    files: &wrong,
                    legacy_path: None,
                    raw: &wrong_raw
                })
            )
            .unwrap_err()
            .contains("index changed"));
        assert_eq!(stored_state(&repo), before);
        assert_eq!(repo.pending().unwrap(), Some(prepared.clone()));
        assert!(repo.continue_pending(&prepared, None).is_err());
        let mut mismatched = prepared.clone();
        mismatched.prepared.as_mut().unwrap().index_sha256 =
            format!("{:x}", Sha256::digest(&wrong_raw));
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&mismatched).unwrap(),
        )
        .unwrap();
        assert!(repo
            .continue_pending(
                &mismatched,
                Some(PendingIndex {
                    files: &wrong,
                    legacy_path: None,
                    raw: &wrong_raw
                })
            )
            .unwrap_err()
            .contains("prepared result differs"));
        assert_eq!(stored_state(&repo), before);
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&prepared).unwrap(),
        )
        .unwrap();
        let outcome = repo
            .continue_pending(
                &prepared,
                Some(PendingIndex {
                    files: &result,
                    legacy_path: None,
                    raw: &raw,
                }),
            )
            .unwrap();
        assert_eq!(outcome.commit, prepared.prepared.as_ref().unwrap().commit);
        assert!(outcome.resumed_prepared && !outcome.already_published);
        assert_eq!(outcome.parents, vec![head]);
        assert_eq!(repo.snapshot().unwrap().encoded.len(), before.objects.len());
    }

    #[test]
    fn pending_published_recovery_repairs_missing_reflog_and_never_duplicates_commit_or_log() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "prepared-after");
        let pending = repo
            .record_pending(pending_request(&repo, "merge", &head, &target))
            .unwrap();
        let result = files(&[("a.wasm", wasm(&[0, 2, 0, 40]))]);
        let raw = pending_index_bytes(&result, None);
        let prepared = prepare_pending_fixture(&repo, &pending, &result, &raw);
        let commit = prepared.prepared.as_ref().unwrap().commit.clone();
        let objects = repo.snapshot().unwrap().encoded;
        let old_log = repo.reflog().unwrap().len();
        // Fixed interrupted state: ref rename completed, reflog not recorded.
        repo.atomic_write(
            &repo.metadata.join("refs/main"),
            format!("{commit}\n").as_bytes(),
        )
        .unwrap();
        let outcome = repo.continue_pending(&prepared, None).unwrap();
        assert!(outcome.already_published && outcome.resumed_prepared);
        assert_eq!(outcome.index_matches_prepared, None);
        assert_eq!(outcome.commit, commit);
        assert_eq!(repo.reflog().unwrap().len(), old_log + 1);
        assert_eq!(repo.snapshot().unwrap().encoded, objects);
        assert_eq!(
            outcome.tree_manual_resolution.files[0]
                .resolved
                .as_ref()
                .unwrap()
                .sha256,
            format!("{:x}", Sha256::digest(&result["a.wasm"]))
        );
        // Recovered old journal after cleanup must only clean it again.
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&prepared).unwrap(),
        )
        .unwrap();
        let second = repo.continue_pending(&prepared, None).unwrap();
        assert!(second.already_published);
        assert_eq!(repo.reflog().unwrap().len(), old_log + 1);
        assert_eq!(repo.snapshot().unwrap().encoded, objects);
    }

    #[test]
    fn pending_abort_holds_writer_guard_and_retains_journal_on_restoration_failure() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "abort");
        let pending = repo
            .record_pending(pending_request(&repo, "revert", &head, &target))
            .unwrap();
        let before = stored_state(&repo);
        let error = repo
            .abort_pending(&pending, |state, original| {
                assert!(repo.lock().is_err());
                assert_eq!(state, &pending);
                assert_eq!(original.commit, head);
                Err("fixed worktree restoration interruption".into())
            })
            .unwrap_err();
        assert!(error.contains("pending state retained") && error.contains("partly completed"));
        assert_eq!(repo.pending().unwrap(), Some(pending.clone()));
        assert_eq!(stored_state(&repo), before);
        repo.abort_pending(&pending, |state, original| {
            fs::write(
                repo.metadata.join("index"),
                state.baseline_index.as_ref().unwrap(),
            )
            .unwrap();
            fs::write(repo.root.join("a.wasm"), &original.files["a.wasm"]).unwrap();
            Ok(())
        })
        .unwrap();
        assert!(repo.pending().unwrap().is_none());
        assert_eq!(stored_state(&repo), before);
        assert_eq!(
            fs::read(repo.metadata.join("index")).unwrap(),
            pending.baseline_index.unwrap()
        );
    }

    #[test]
    fn pending_continue_and_abort_refuse_stale_tip_or_same_tip_other_branch_but_quit_preserves_it()
    {
        let temp = TempDirectory::new();
        for mode in ["tip", "branch"] {
            let (repo, head, target) = pending_fixture(&temp, mode);
            let pending = repo
                .record_pending(pending_request(&repo, "merge", &head, &target))
                .unwrap();
            if mode == "tip" {
                repo.reset_on_branch(&target, "main", Some(&head)).unwrap();
            } else {
                repo.create_branch("other", &head).unwrap();
                repo.switch_branch("other").unwrap();
            }
            let before = stored_state(&repo);
            let result = files(&[("a.wasm", wasm(&[]))]);
            let raw = pending_index_bytes(&result, None);
            assert!(repo
                .continue_pending(
                    &pending,
                    Some(PendingIndex {
                        files: &result,
                        legacy_path: None,
                        raw: &raw
                    })
                )
                .is_err());
            let called = std::cell::Cell::new(false);
            assert!(repo
                .abort_pending(&pending, |_, _| {
                    called.set(true);
                    Ok(())
                })
                .is_err());
            assert!(!called.get());
            assert_eq!(stored_state(&repo), before);
            repo.quit_pending(&pending).unwrap();
            assert_eq!(stored_state(&repo), before);
            assert!(repo.pending().unwrap().is_none());
        }
    }

    #[test]
    fn pending_invalid_baseline_or_resolution_dto_and_changed_generation_reject_before_storage() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "leases");
        let before = stored_state(&repo);
        let mut request = pending_request(&repo, "merge", &head, &target);
        request.baseline_index = Some(pending_index_bytes(&BTreeMap::new(), None));
        assert!(repo.record_pending(request).is_err());
        assert_eq!(stored_state(&repo), before);
        assert!(repo.pending().unwrap().is_none());
        let pending = repo
            .record_pending(pending_request(&repo, "merge", &head, &target))
            .unwrap();
        let result = files(&[("a.wasm", wasm(&[]))]);
        let wrong_raw = pending_index_bytes(&BTreeMap::new(), None);
        assert!(repo
            .continue_pending(
                &pending,
                Some(PendingIndex {
                    files: &result,
                    legacy_path: None,
                    raw: &wrong_raw
                })
            )
            .is_err());
        assert_eq!(stored_state(&repo), before);
        repo.quit_pending(&pending).unwrap();
        let next = repo
            .record_pending(pending_request(&repo, "merge", &head, &target))
            .unwrap();
        assert_ne!(pending.id, next.id);
        assert!(repo.quit_pending(&pending).unwrap_err().contains("changed"));
        assert!(repo.abort_pending(&pending, |_, _| Ok(())).is_err());
        assert_eq!(repo.pending().unwrap(), Some(next));
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn pending_canonical_schema_and_immutable_parent_binding_reject_malformed_state() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "invalid-state");
        let pending = repo
            .record_pending(pending_request(&repo, "merge", &head, &target))
            .unwrap();
        let original = encode_pending(&pending).unwrap();
        let before = stored_state(&repo);
        let mut wrong_base = pending.clone();
        wrong_base.base = Some(target.clone());
        let mut wrong_result = pending.clone();
        wrong_result.prepared = Some(PendingPrepared {
            commit: head,
            index_sha256: "a".repeat(64),
        });
        let mut extra = original.clone();
        extra.pop();
        extra.pop();
        extra.extend_from_slice(b",\"unknown\":true}\n");
        let mut duplicate = original.clone();
        duplicate.pop();
        duplicate.pop();
        duplicate.extend_from_slice(b",\"version\":1}\n");
        for bytes in [
            serde_json::to_vec_pretty(&pending).unwrap(),
            extra,
            duplicate,
            encode_pending(&wrong_base).unwrap(),
            encode_pending(&wrong_result).unwrap(),
        ] {
            fs::write(repo.metadata.join("pending.json"), bytes).unwrap();
            assert!(repo.pending().is_err());
            assert_eq!(stored_state(&repo), before);
        }
        fs::write(repo.metadata.join("pending.json"), &original).unwrap();
        assert_eq!(repo.pending().unwrap(), Some(pending));
    }

    #[test]
    fn pending_journal_limit_and_nonregular_files_fail_without_unbounded_read() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "bounds");
        let path = repo.metadata.join("pending.json");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_PENDING_BYTES + 1).unwrap();
        drop(file);
        assert!(repo.pending().unwrap_err().contains("64 MiB"));
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(repo.pending().unwrap_err().contains("regular file"));
        fs::remove_dir(&path).unwrap();
        #[cfg(unix)]
        {
            let external = temp.path("external");
            fs::write(&external, b"unchanged").unwrap();
            std::os::unix::fs::symlink(&external, &path).unwrap();
            assert!(repo.pending().unwrap_err().contains("regular file"));
            assert_eq!(fs::read(&external).unwrap(), b"unchanged");
            fs::remove_file(&path).unwrap();
        }
        let mut request = pending_request(&repo, "merge", &head, &target);
        request.message = "x".repeat(MAX_PENDING_BYTES as usize);
        let before = stored_state(&repo);
        assert!(repo.record_pending(request).unwrap_err().contains("64 MiB"));
        assert_eq!(stored_state(&repo), before);
        assert!(!path.exists());
    }

    #[test]
    fn pending_root_replays_and_selected_merge_mainline_keep_exact_single_parent_semantics() {
        let temp = TempDirectory::new();
        for operation in ["cherry-pick", "revert"] {
            let (repo, head, target) = pending_fixture(&temp, operation);
            let root = repo.read_commit(&target).unwrap().commit.parents[0].clone();
            let pending = repo
                .record_pending(pending_request(&repo, operation, &head, &root))
                .unwrap();
            assert!(pending.selected_parent.is_none());
            assert_eq!(pending.base, (operation == "revert").then_some(root));
            let result = BTreeMap::new();
            let raw = pending_index_bytes(&result, None);
            let outcome = repo
                .continue_pending(
                    &pending,
                    Some(PendingIndex {
                        files: &result,
                        legacy_path: None,
                        raw: &raw,
                    }),
                )
                .unwrap();
            assert_eq!(outcome.parents, vec![head]);
            assert!(repo.files_at(&outcome.commit).unwrap().files.is_empty());
        }
        let (repo, head, target) = pending_fixture(&temp, "mainline");
        let merge = repo
            .commit_files_on_branch(
                &repo.files_at(&head).unwrap().files,
                "merge target",
                &[target.clone(), head.clone()],
                "main",
                Some(&head),
                None,
            )
            .unwrap();
        repo.reset_on_branch(&head, "main", Some(&merge)).unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .record_pending(pending_request(&repo, "cherry-pick", &head, &merge))
            .unwrap_err()
            .contains("mainline"));
        assert_eq!(stored_state(&repo), before);
        let mut request = pending_request(&repo, "cherry-pick", &head, &merge);
        request.mainline = Some(1);
        let pending = repo.record_pending(request).unwrap();
        assert_eq!(pending.selected_parent, Some(target));
        assert_eq!(pending.mainline, Some(1));
        repo.quit_pending(&pending).unwrap();
    }

    #[test]
    fn pending_legacy_raw_index_retains_explicit_anchor_for_continue_and_abort() {
        let temp = TempDirectory::new();
        let repo = temp.repo("legacy-pending");
        let base = repo.commit(&wasm(&[0, 2, 0, 10]), "base").unwrap();
        repo.create_branch("incoming", &base).unwrap();
        repo.switch_branch("incoming").unwrap();
        let target = repo.commit(&wasm(&[0, 2, 0, 20]), "incoming").unwrap();
        repo.switch_branch("main").unwrap();
        let head = repo.commit(&wasm(&[0, 2, 0, 30]), "ours").unwrap();
        let old_index = |bytes: &[u8]| {
            let path = b"old.wasm";
            let mut raw = b"UWGITIDX\x01".to_vec();
            raw.extend_from_slice(&(path.len() as u64).to_le_bytes());
            raw.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            raw.extend_from_slice(path);
            raw.extend_from_slice(bytes);
            raw
        };
        let baseline = old_index(&repo.wasm_bytes(&head).unwrap());
        let request = || PendingRequest {
            operation: "merge".into(),
            branch: "main".into(),
            head: head.clone(),
            target: target.clone(),
            mainline: None,
            message: "legacy reviewed".into(),
            baseline_index: Some(baseline.clone()),
            legacy_path: Some("old.wasm".into()),
        };
        let pending = repo.record_pending(request()).unwrap();
        repo.abort_pending(&pending, |record, _| {
            fs::write(
                repo.metadata.join("index"),
                record.baseline_index.as_ref().unwrap(),
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(repo.metadata.join("index")).unwrap(), baseline);
        let pending = repo.record_pending(request()).unwrap();
        let result = files(&[("old.wasm", wasm(&[0, 2, 0, 40]))]);
        let raw = old_index(&result["old.wasm"]);
        let outcome = repo
            .continue_pending(
                &pending,
                Some(PendingIndex {
                    files: &result,
                    legacy_path: Some("old.wasm"),
                    raw: &raw,
                }),
            )
            .unwrap();
        let commit = repo.read_commit(&outcome.commit).unwrap();
        assert_eq!(commit.commit.parents, vec![head, target]);
        assert_eq!(commit.commit.legacy_path.as_deref(), Some("old.wasm"));
        assert_eq!(repo.files_at(&outcome.commit).unwrap().files, result);
        assert_eq!(fs::read(repo.metadata.join("index")).unwrap(), baseline);
    }

    fn rebase_fixture(temp: &TempDirectory, name: &str) -> (Repository, String, Vec<String>) {
        let repo = temp.repo(name);
        let base = commit_tree(
            &repo,
            &files(&[
                ("a.wasm", wasm(&[0, 2, 0, 10])),
                ("b.wasm", wasm(&[0, 2, 0, 20])),
            ]),
            "base",
            None,
        );
        repo.create_branch("upstream", &base).unwrap();
        let first = commit_tree(
            &repo,
            &files(&[("b.wasm", wasm(&[0, 2, 0, 20]))]),
            "remove a",
            None,
        );
        let second = commit_tree(&repo, &BTreeMap::new(), "remove b", None);
        let third = commit_tree(
            &repo,
            &files(&[("c.wasm", wasm(&[0, 2, 0, 30]))]),
            "add c",
            None,
        );
        repo.switch_branch("upstream").unwrap();
        let upstream = commit_tree(
            &repo,
            &files(&[
                ("a.wasm", wasm(&[0, 2, 0, 11])),
                ("b.wasm", wasm(&[0, 2, 0, 21])),
            ]),
            "upstream modifications",
            None,
        );
        repo.switch_branch("main").unwrap();
        (repo, upstream, vec![first, second, third])
    }

    fn rebase_request(repo: &Repository, upstream: &str) -> PendingRebaseRequest {
        let original = repo.files_at("HEAD").unwrap();
        PendingRebaseRequest {
            branch: "main".into(),
            head: original.commit,
            upstream: upstream.into(),
            onto: upstream.into(),
            baseline_index: Some(pending_index_bytes(
                &original.files,
                original.legacy_path.as_deref(),
            )),
            legacy_path: original.legacy_path,
        }
    }

    fn resolve_first_rebase(repo: &Repository, pending: &PendingOperation) -> PendingOperation {
        let result = files(&[("b.wasm", wasm(&[0, 2, 0, 21]))]);
        let raw = pending_index_bytes(&result, None);
        let report = repo
            .continue_rebase_pending(
                pending,
                Some(PendingIndex {
                    files: &result,
                    legacy_path: None,
                    raw: &raw,
                }),
            )
            .unwrap();
        assert_eq!(report["status"], "conflict");
        assert_eq!(report["cursor"], 1);
        repo.pending().unwrap().unwrap()
    }

    fn rebase_prepared_by_ref_failure(
        repo: &Repository,
        pending: &PendingOperation,
        index: Option<PendingIndex<'_>>,
        skip: bool,
    ) -> PendingOperation {
        let lock = repo.lock().unwrap();
        let snapshot = repo.snapshot().unwrap();
        let admitted = repo.checked_pending(&snapshot, pending).unwrap();
        let path = repo.metadata.join("reflog");
        let original = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        // Inject failure only after the public API's snapshot/lease admission,
        // while retaining its real writer guard through final preparation.
        let error = repo
            .advance_rebase_pending(
                snapshot,
                admitted,
                if skip { "skip" } else { "continue" },
                index,
            )
            .unwrap_err();
        fs::remove_dir(&path).unwrap();
        fs::write(&path, original).unwrap();
        drop(lock);
        assert!(error.contains("durable"), "{error}");
        assert_eq!(repo.resolve("HEAD").unwrap(), pending.head);
        let prepared = repo.pending().unwrap().unwrap();
        assert!(prepared.prepared.is_some());
        prepared
    }

    #[test]
    fn pending_rebase_two_conflicts_keep_original_head_and_audit_each_complete_index() {
        let temp = TempDirectory::new();
        let (repo, upstream, queue) = rebase_fixture(&temp, "rebase-two-conflicts");
        let original = stored_state(&repo);
        let baseline = pending_index_bytes(&repo.files_at("HEAD").unwrap().files, None);
        fs::write(repo.metadata.join("index"), &baseline).unwrap();
        fs::write(repo.root.join("private.txt"), b"unfinished editor bytes\0").unwrap();
        let start = repo
            .begin_rebase_pending(rebase_request(&repo, &upstream))
            .unwrap();
        assert_eq!(start["status"], "conflict");
        assert_eq!(start["queue"], json!(queue));
        assert_eq!(start["cursor"], 0);
        assert_eq!(stored_state(&repo), original);
        let first = repo.pending().unwrap().unwrap();
        assert!(repo
            .continue_pending(&first, None)
            .unwrap_err()
            .contains("rebase"));
        let second = resolve_first_rebase(&repo, &first);
        assert_eq!(repo.resolve("HEAD").unwrap(), queue[2]);
        assert_eq!(second.target, queue[1]);
        let after_first = stored_state(&repo);
        assert!(repo
            .skip_rebase_pending(&first)
            .unwrap_err()
            .contains("changed"));
        assert_eq!(stored_state(&repo), after_first);
        let result = BTreeMap::new();
        let raw = pending_index_bytes(&result, None);
        let report = repo
            .continue_rebase_pending(
                &second,
                Some(PendingIndex {
                    files: &result,
                    legacy_path: None,
                    raw: &raw,
                }),
            )
            .unwrap();
        assert_eq!(report["status"], "rebased");
        assert_eq!(report["cursor"], 3);
        assert_eq!(report["manual_resolutions"].as_array().unwrap().len(), 2);
        assert_eq!(report["steps"][2]["action"], "automatic");
        assert_eq!(report["steps"][0]["before"], upstream);
        assert_eq!(report["steps"][1]["before"], report["steps"][0]["commit"]);
        assert_eq!(
            repo.files_at("HEAD").unwrap().files,
            files(&[("c.wasm", wasm(&[0, 2, 0, 30]))])
        );
        assert_ne!(repo.files_at("HEAD").unwrap().files, result);
        assert_eq!(fs::read(repo.metadata.join("index")).unwrap(), baseline);
        assert_eq!(
            fs::read(repo.root.join("private.txt")).unwrap(),
            b"unfinished editor bytes\0"
        );
        assert!(repo.pending().unwrap().is_none());
        let logs = repo.reflog().unwrap();
        assert_eq!(
            logs.iter()
                .filter(|entry| entry.operation == format!("pending-continue-{}", first.id))
                .count(),
            1
        );
        let audit = &report["manual_resolutions"][0]["tree_manual_resolution"]["files"];
        let a = audit
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == "a.wasm")
            .unwrap();
        assert_eq!(
            a["base"]["sha256"],
            format!("{:x}", Sha256::digest(wasm(&[0, 2, 0, 10])))
        );
        assert_eq!(
            a["ours"]["sha256"],
            format!("{:x}", Sha256::digest(wasm(&[0, 2, 0, 11])))
        );
        assert!(a["theirs"].is_null() && a["resolved"].is_null());
    }

    #[test]
    fn pending_rebase_skip_advances_to_next_conflict_and_prepared_skip_recovers_without_index() {
        let temp = TempDirectory::new();
        let (repo, upstream, queue) = rebase_fixture(&temp, "rebase-skip");
        repo.begin_rebase_pending(rebase_request(&repo, &upstream))
            .unwrap();
        let first = repo.pending().unwrap().unwrap();
        let report = repo.skip_rebase_pending(&first).unwrap();
        assert_eq!(report["status"], "conflict");
        assert_eq!(report["cursor"], 1);
        assert_eq!(report["progress_tip"], upstream);
        assert_eq!(repo.resolve("HEAD").unwrap(), queue[2]);
        let second = repo.pending().unwrap().unwrap();
        let prepared = rebase_prepared_by_ref_failure(&repo, &second, None, true);
        let objects = repo.snapshot().unwrap().encoded;
        let report = repo.continue_rebase_pending(&prepared, None).unwrap();
        assert_eq!(report["status"], "rebased");
        assert_eq!(report["skipped"], json!([queue[0], queue[1]]));
        assert_eq!(report["resumed_prepared"], true);
        assert!(report["index_matches_prepared"].is_null());
        assert_eq!(repo.snapshot().unwrap().encoded, objects);
        assert_eq!(repo.files_at("HEAD").unwrap().files.len(), 3);
    }

    #[test]
    fn pending_rebase_prepared_manual_lease_uses_last_manual_tree_not_automatic_final_tree() {
        let temp = TempDirectory::new();
        let (repo, upstream, _) = rebase_fixture(&temp, "rebase-prepared-manual");
        repo.begin_rebase_pending(rebase_request(&repo, &upstream))
            .unwrap();
        let first = repo.pending().unwrap().unwrap();
        let second = resolve_first_rebase(&repo, &first);
        let files = BTreeMap::new();
        let raw = pending_index_bytes(&files, None);
        let prepared = rebase_prepared_by_ref_failure(
            &repo,
            &second,
            Some(PendingIndex {
                files: &files,
                legacy_path: None,
                raw: &raw,
            }),
            false,
        );
        let before = stored_state(&repo);
        assert!(repo.continue_rebase_pending(&prepared, None).is_err());
        assert!(repo.skip_rebase_pending(&prepared).is_err());
        let final_files = repo
            .files_at(&prepared.prepared.as_ref().unwrap().commit)
            .unwrap()
            .files;
        let final_raw = pending_index_bytes(&final_files, None);
        assert!(repo
            .continue_rebase_pending(
                &prepared,
                Some(PendingIndex {
                    files: &final_files,
                    legacy_path: None,
                    raw: &final_raw
                })
            )
            .is_err());
        // A caller cannot claim decoded files unrelated to its authentic raw
        // index. That also leaves the final prepared object graph unchanged.
        assert!(repo
            .continue_rebase_pending(
                &prepared,
                Some(PendingIndex {
                    files: &final_files,
                    legacy_path: None,
                    raw: &raw
                })
            )
            .is_err());
        assert_eq!(stored_state(&repo), before);
        let report = repo
            .continue_rebase_pending(
                &prepared,
                Some(PendingIndex {
                    files: &files,
                    legacy_path: None,
                    raw: &raw,
                }),
            )
            .unwrap();
        assert_eq!(report["resumed_prepared"], true);
        assert_eq!(report["index_matches_prepared"], true);
        assert_eq!(repo.snapshot().unwrap().encoded, before.objects);
    }

    #[test]
    fn pending_rebase_published_recovery_uses_saved_audits_and_repairs_reflog_once() {
        let temp = TempDirectory::new();
        let (repo, upstream, _) = rebase_fixture(&temp, "rebase-published");
        repo.begin_rebase_pending(rebase_request(&repo, &upstream))
            .unwrap();
        let first = repo.pending().unwrap().unwrap();
        let second = resolve_first_rebase(&repo, &first);
        let files = BTreeMap::new();
        let raw = pending_index_bytes(&files, None);
        let prepared = rebase_prepared_by_ref_failure(
            &repo,
            &second,
            Some(PendingIndex {
                files: &files,
                legacy_path: None,
                raw: &raw,
            }),
            false,
        );
        let commit = &prepared.prepared.as_ref().unwrap().commit;
        repo.atomic_write(
            &repo.metadata.join("refs/main"),
            format!("{commit}\n").as_bytes(),
        )
        .unwrap();
        let before = repo.snapshot().unwrap().encoded;
        let logs = repo.reflog().unwrap().len();
        assert!(repo
            .abort_pending(&prepared, |_, _| panic!(
                "published result must not restore"
            ))
            .is_err());
        let result = repo.continue_rebase_pending(&prepared, None).unwrap();
        assert_eq!(result["already_published"], true);
        assert_eq!(result["manual_resolutions"].as_array().unwrap().len(), 2);
        assert_eq!(repo.reflog().unwrap().len(), logs + 1);
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&prepared).unwrap(),
        )
        .unwrap();
        let again = repo.skip_rebase_pending(&prepared).unwrap();
        assert_eq!(again["commit"], result["commit"]);
        assert_eq!(repo.reflog().unwrap().len(), logs + 1);
        assert_eq!(repo.snapshot().unwrap().encoded, before);
    }

    #[test]
    fn pending_rebase_empty_queue_moves_onto_without_synthetic_commit_and_old_journal_bytes_stay_compatible(
    ) {
        let temp = TempDirectory::new();
        let repo = temp.repo("rebase-empty");
        let base = commit_tree(&repo, &files(&[("a.wasm", wasm(&[]))]), "base", None);
        repo.create_branch("upstream", &base).unwrap();
        repo.switch_branch("upstream").unwrap();
        let upstream = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[])), ("b.wasm", wasm(&[]))]),
            "upstream",
            None,
        );
        repo.switch_branch("main").unwrap();
        let objects = repo.snapshot().unwrap().encoded;
        let report = repo
            .begin_rebase_pending(rebase_request(&repo, &upstream))
            .unwrap();
        assert_eq!(report["status"], "rebased");
        assert_eq!(report["queue"], json!([]));
        assert_eq!(report["commit"], upstream);
        assert_eq!(repo.snapshot().unwrap().encoded, objects);
        assert!(repo.pending().unwrap().is_none());
        let (normal, head, target) = pending_fixture(&temp, "old-pending-encoding");
        let pending = normal
            .record_pending(pending_request(&normal, "merge", &head, &target))
            .unwrap();
        let bytes = encode_pending(&pending).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("\"rebase\""));
        let old: PendingOperation = serde_json::from_slice(&bytes).unwrap();
        assert!(old.rebase.is_none());
        assert_eq!(encode_pending(&old).unwrap(), bytes);
    }

    #[test]
    fn pending_rebase_canonical_queue_and_step_forgery_are_rejected_without_writes() {
        let temp = TempDirectory::new();
        let (repo, upstream, _) = rebase_fixture(&temp, "rebase-invalid-record");
        repo.begin_rebase_pending(rebase_request(&repo, &upstream))
            .unwrap();
        let first = repo.pending().unwrap().unwrap();
        let second = resolve_first_rebase(&repo, &first);
        let mut forgeries = Vec::new();
        let mut wrong = second.clone();
        wrong.rebase.as_mut().unwrap().queue.swap(0, 1);
        forgeries.push(wrong);
        let mut wrong = second.clone();
        wrong.rebase.as_mut().unwrap().progress_tip = upstream.clone();
        forgeries.push(wrong);
        let mut wrong = second.clone();
        wrong.rebase.as_mut().unwrap().steps[0].action = "automatic".into();
        wrong.rebase.as_mut().unwrap().steps[0].index_sha256 = None;
        forgeries.push(wrong);
        let before = stored_state(&repo);
        for wrong in forgeries {
            fs::write(
                repo.metadata.join("pending.json"),
                encode_pending(&wrong).unwrap(),
            )
            .unwrap();
            assert!(repo.pending().is_err());
            assert!(repo.skip_rebase_pending(&wrong).is_err());
            assert_eq!(stored_state(&repo), before);
        }
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&second).unwrap(),
        )
        .unwrap();
        assert_eq!(repo.pending().unwrap(), Some(second));
    }

    #[test]
    fn pending_rebase_automatic_begin_recovers_without_index_and_cannot_forge_clean_manual_or_skip()
    {
        let temp = TempDirectory::new();
        let repo = temp.repo("rebase-auto-begin");
        let base = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[0, 2, 0, 10]))]),
            "base",
            None,
        );
        repo.create_branch("upstream", &base).unwrap();
        let head = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[0, 2, 0, 10])), ("c.wasm", wasm(&[]))]),
            "clean add c",
            None,
        );
        repo.switch_branch("upstream").unwrap();
        let upstream = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[0, 2, 0, 11]))]),
            "upstream",
            None,
        );
        repo.switch_branch("main").unwrap();
        let log = fs::read(repo.metadata.join("reflog")).unwrap();
        let request = rebase_request(&repo, &upstream);
        let baseline = request.baseline_index.clone();
        let report = repo.begin_rebase_pending(request).unwrap();
        // Reconstruct one fixed durable-preparation state from an actual
        // automatic result, before its reference/reflog publication.
        repo.atomic_write(
            &repo.metadata.join("refs/main"),
            format!("{head}\n").as_bytes(),
        )
        .unwrap();
        fs::write(repo.metadata.join("reflog"), log).unwrap();
        let prepared = PendingOperation {
            version: 1,
            id: report["pending_id"].as_str().unwrap().into(),
            operation: "rebase".into(),
            branch: "main".into(),
            head: head.clone(),
            target: head.clone(),
            base: Some(base.clone()),
            selected_parent: Some(base.clone()),
            mainline: None,
            message: "clean add c".into(),
            baseline_index: baseline,
            legacy_path: None,
            prepared: Some(PendingPrepared {
                commit: report["commit"].as_str().unwrap().into(),
                index_sha256: format!("{:x}", Sha256::digest(b"")),
            }),
            rebase: Some(PendingRebase {
                upstream: upstream.clone(),
                onto: upstream.clone(),
                fork_base: base,
                queue: vec![head],
                cursor: 1,
                progress_tip: report["commit"].as_str().unwrap().into(),
                steps: serde_json::from_value(report["steps"].clone()).unwrap(),
                prepared_action: Some("begin".into()),
            }),
        };
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&prepared).unwrap(),
        )
        .unwrap();
        assert_eq!(repo.pending().unwrap(), Some(prepared.clone()));
        let before = stored_state(&repo);
        let mut manual = prepared.clone();
        manual.rebase.as_mut().unwrap().steps[0].action = "manual".into();
        manual.rebase.as_mut().unwrap().steps[0].index_sha256 =
            Some(format!("{:x}", Sha256::digest(b"supplied index")));
        manual.rebase.as_mut().unwrap().prepared_action = Some("continue".into());
        manual.prepared.as_mut().unwrap().index_sha256 = manual.rebase.as_ref().unwrap().steps[0]
            .index_sha256
            .clone()
            .unwrap();
        let mut skipped = prepared.clone();
        skipped.rebase.as_mut().unwrap().steps[0].action = "skipped".into();
        skipped.rebase.as_mut().unwrap().steps[0].commit = None;
        skipped.rebase.as_mut().unwrap().progress_tip = upstream.clone();
        skipped.rebase.as_mut().unwrap().prepared_action = Some("skip".into());
        skipped.prepared.as_mut().unwrap().commit = upstream;
        for forged in [manual, skipped] {
            fs::write(
                repo.metadata.join("pending.json"),
                encode_pending(&forged).unwrap(),
            )
            .unwrap();
            assert!(repo.pending().unwrap_err().contains("actual conflict"));
            assert_eq!(stored_state(&repo), before);
        }
        fs::write(
            repo.metadata.join("pending.json"),
            encode_pending(&prepared).unwrap(),
        )
        .unwrap();
        let report = repo.continue_rebase_pending(&prepared, None).unwrap();
        assert_eq!(report["status"], "rebased");
        assert!(report["index_matches_prepared"].is_null());
        assert_eq!(
            repo.files_at("HEAD").unwrap().files,
            files(&[("a.wasm", wasm(&[0, 2, 0, 11])), ("c.wasm", wasm(&[]))])
        );
        assert_eq!(repo.snapshot().unwrap().encoded, before.objects);
    }

    #[test]
    fn pending_rebase_legacy_anchor_is_explicit_and_abort_restores_original_baseline() {
        let temp = TempDirectory::new();
        let repo = temp.repo("rebase-legacy");
        let base = repo.commit(&wasm(&[0, 2, 0, 10]), "legacy base").unwrap();
        repo.create_branch("upstream", &base).unwrap();
        let head = commit_tree(
            &repo,
            &BTreeMap::new(),
            "delete legacy module",
            Some("old.wasm"),
        );
        repo.switch_branch("upstream").unwrap();
        let upstream = repo
            .commit(&wasm(&[0, 2, 0, 11]), "legacy changed")
            .unwrap();
        repo.switch_branch("main").unwrap();
        let original = stored_state(&repo);
        let mut bad = rebase_request(&repo, &upstream);
        bad.legacy_path = None;
        assert!(repo.begin_rebase_pending(bad).is_err());
        assert_eq!(stored_state(&repo), original);
        repo.begin_rebase_pending(rebase_request(&repo, &upstream))
            .unwrap();
        let pending = repo.pending().unwrap().unwrap();
        assert_eq!(pending.head, head);
        let baseline = pending.baseline_index.clone();
        let error = repo
            .abort_pending(&pending, |record, original| {
                assert_eq!(record.baseline_index, baseline);
                assert_eq!(original.commit, head);
                assert_eq!(original.legacy_path.as_deref(), Some("old.wasm"));
                Err("injected original-index restore failure".into())
            })
            .unwrap_err();
        assert!(error.contains("retained"));
        assert_eq!(repo.pending().unwrap(), Some(pending.clone()));
        repo.abort_pending(&pending, |_, _| Ok(())).unwrap();
        assert_eq!(stored_state(&repo), original);
        repo.begin_rebase_pending(rebase_request(&repo, &upstream))
            .unwrap();
        let pending = repo.pending().unwrap().unwrap();
        let result = files(&[("old.wasm", wasm(&[0, 2, 0, 12]))]);
        let raw = pending_index_bytes(&result, Some("old.wasm"));
        let report = repo
            .continue_rebase_pending(
                &pending,
                Some(PendingIndex {
                    files: &result,
                    legacy_path: Some("old.wasm"),
                    raw: &raw,
                }),
            )
            .unwrap();
        assert_eq!(report["status"], "rebased");
        assert_eq!(
            repo.files_at("HEAD").unwrap().legacy_path.as_deref(),
            Some("old.wasm")
        );
    }

    #[test]
    fn describe_linear_ancestors_exact_tags_and_revision_syntax_use_one_snapshot() {
        let temp = TempDirectory::new();
        let repo = temp.repo("describe-linear");
        let first = repo.commit(&wasm(&[]), "first").unwrap();
        repo.create_tag("v1", &first).unwrap();
        let second = repo.commit(&wasm(&[99, 1, 1]), "second").unwrap();
        repo.create_tag("v2", &second).unwrap();
        let tip = repo.commit(&wasm(&[99, 1, 2]), "third").unwrap();
        let before = stored_state(&repo);
        let options = DescribeOptions::default();
        let report = repo.describe("HEAD", &options, |_| Ok(true)).unwrap();
        assert_eq!(report.commit, tip);
        assert_eq!(report.tag.as_deref(), Some("v2"));
        assert_eq!(report.tag_commit.as_deref(), Some(second.as_str()));
        assert_eq!(report.distance, Some(1));
        assert!(!report.exact && !report.first_parent);
        assert_eq!(report.evaluated_tags, 2);
        assert_eq!(report.requested_abbrev, 12);
        assert!(tip.starts_with(&report.abbreviation) && report.abbreviation.len() >= 12);
        let exact = repo.describe("HEAD^", &options, |_| Ok(true)).unwrap();
        assert_eq!(exact.commit, second);
        assert_eq!(exact.tag.as_deref(), Some("v2"));
        assert_eq!(exact.distance, Some(0));
        assert!(exact.exact);
        assert_eq!(
            repo.describe("HEAD~2", &options, |_| Ok(true))
                .unwrap()
                .tag_commit,
            Some(first)
        );
        assert_eq!(stored_state(&repo), before);
    }

    fn describe_merge_fixture(temp: &TempDirectory, name: &str) -> (Repository, [String; 4]) {
        let repo = temp.repo(name);
        let blob = repo.store_object(WASM_KIND, &wasm(&[255, 1, 254])).unwrap();
        let root = store_history_commit(&repo, &blob, &[], "root");
        let left1 = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "left one");
        let left2 = store_history_commit(&repo, &blob, &[left1], "left two");
        let left3 = store_history_commit(&repo, &blob, std::slice::from_ref(&left2), "left three");
        let side = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "side one");
        let merge = store_history_commit(&repo, &blob, &[left3, side.clone()], "merge");
        repo.atomic_write(
            &repo.metadata.join("refs/main"),
            format!("{merge}\n").as_bytes(),
        )
        .unwrap();
        (repo, [root, left2, side, merge])
    }

    #[test]
    fn describe_merge_distance_is_ancestor_set_difference_not_nearest_parent_edges() {
        let temp = TempDirectory::new();
        let (repo, [_, left, side, merge]) =
            describe_merge_fixture(&temp, "describe-merge-distance");
        repo.create_tag("a-one-edge-side", &side).unwrap();
        repo.create_tag("z-two-edge-main", &left).unwrap();
        let before = stored_state(&repo);
        let report = repo
            .describe(&merge, &DescribeOptions::default(), |_| Ok(true))
            .unwrap();
        // The merge has six ancestors including itself. The left tag covers
        // three, while the side tag covers two, despite its shorter edge path.
        assert_eq!(report.tag.as_deref(), Some("z-two-edge-main"));
        assert_eq!(report.tag_commit, Some(left));
        assert_eq!(report.distance, Some(3));
        assert_eq!(
            repo.describe("HEAD", &DescribeOptions::default(), |name| Ok(
                name.starts_with('a')
            ))
            .unwrap()
            .distance,
            Some(4)
        );
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn describe_first_parent_filters_both_target_and_tag_ancestor_closures() {
        let temp = TempDirectory::new();
        let (repo, [_, left, side, _]) = describe_merge_fixture(&temp, "describe-first-parent");
        repo.create_tag("main-tag", &left).unwrap();
        repo.create_tag("side-tag", &side).unwrap();
        let options = DescribeOptions {
            first_parent: true,
            ..DescribeOptions::default()
        };
        let before = stored_state(&repo);
        let report = repo.describe("HEAD", &options, |_| Ok(true)).unwrap();
        assert_eq!(report.tag.as_deref(), Some("main-tag"));
        assert_eq!(report.distance, Some(2));
        assert!(report.first_parent);
        assert_eq!(report.evaluated_tags, 2);
        let missing = repo
            .describe("HEAD", &options, |name| Ok(name == "side-tag"))
            .unwrap();
        assert!(
            missing.tag.is_none()
                && missing.tag_commit.is_none()
                && missing.distance.is_none()
                && !missing.exact
        );
        assert_eq!(missing.evaluated_tags, 1);
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn describe_tied_tags_use_ascii_names_and_exact_matches_precede_ancestors() {
        let temp = TempDirectory::new();
        let repo = temp.repo("describe-ties");
        let first = repo.commit(&wasm(&[]), "base").unwrap();
        repo.create_tag("a-base", &first).unwrap();
        repo.create_tag("B-base", &first).unwrap();
        let tip = repo.commit(&wasm(&[99, 1, 1]), "tip").unwrap();
        assert_eq!(
            repo.describe("HEAD", &DescribeOptions::default(), |_| Ok(true))
                .unwrap()
                .tag
                .as_deref(),
            Some("B-base")
        );
        repo.create_tag("z-exact", &tip).unwrap();
        repo.create_tag("C-exact", &tip).unwrap();
        let before = stored_state(&repo);
        let report = repo
            .describe("HEAD", &DescribeOptions::default(), |_| Ok(true))
            .unwrap();
        assert_eq!(report.tag.as_deref(), Some("C-exact"));
        assert_eq!(report.distance, Some(0));
        assert!(report.exact);
        assert!(report.selection_policy.contains("ASCII_tag_name_tiebreak"));
        assert!(report.selection_policy.contains("no_dates"));
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn describe_predicate_exact_only_and_local_tag_scope_are_explicit_and_read_only() {
        let temp = TempDirectory::new();
        let repo = temp.repo("describe-predicate");
        let first = repo.commit(&wasm(&[]), "base").unwrap();
        repo.create_tag("keep-base", &first).unwrap();
        repo.create_tag("omit-base", &first).unwrap();
        repo.commit(&wasm(&[99, 1, 1]), "tip").unwrap();
        let blob = repo.store_object(WASM_KIND, &wasm(&[99, 1, 2])).unwrap();
        let unrelated = store_history_commit(&repo, &blob, &[], "unrelated");
        repo.create_tag("unrelated", &unrelated).unwrap();
        query_tracking(
            &repo,
            "origin",
            BTreeMap::new(),
            BTreeMap::from([("remote-only".into(), unrelated)]),
        );
        let before = stored_state(&repo);
        let mut seen = Vec::new();
        let report = repo
            .describe("HEAD", &DescribeOptions::default(), |name| {
                assert!(repo.metadata.join("write.lock").is_file());
                seen.push(name.to_owned());
                Ok(name != "omit-base")
            })
            .unwrap();
        assert_eq!(seen, ["keep-base", "omit-base", "unrelated"]);
        assert_eq!(report.evaluated_tags, 2);
        assert_eq!(report.tag.as_deref(), Some("keep-base"));
        let options = DescribeOptions {
            exact_match: true,
            ..DescribeOptions::default()
        };
        let exact = repo.describe("HEAD", &options, |_| Ok(true)).unwrap();
        assert!(exact.tag.is_none() && exact.distance.is_none() && !exact.exact);
        assert_eq!(exact.evaluated_tags, 3);
        assert_eq!(
            repo.describe("HEAD", &options, |_| Ok(false))
                .unwrap()
                .evaluated_tags,
            0
        );
        assert_eq!(
            repo.describe("HEAD", &options, |_| Err("fixed predicate error".into()))
                .unwrap_err(),
            "fixed predicate error"
        );
        assert_eq!(stored_state(&repo), before);
        assert!(!repo.metadata.join("write.lock").exists());
    }

    #[test]
    fn describe_abbreviations_extend_across_all_kinds_and_preserve_requested_lengths() {
        // Fixed artificial IDs exercise only prefix selection, not object
        // verification. No collision search or generated mutation is used.
        let target = format!("1234a{}", "0".repeat(59));
        let blob = format!("1234b{}", "0".repeat(59));
        let tree = format!("1234ac{}", "0".repeat(58));
        let objects = BTreeMap::from([
            (target.clone(), Object::Wasm(Vec::new())),
            (blob, Object::Wasm(Vec::new())),
            (
                tree,
                Object::Tree(Tree {
                    format: 1,
                    entries: BTreeMap::new(),
                }),
            ),
        ]);
        for requested in 1..=4 {
            assert_eq!(
                unique_object_abbreviation(&target, requested, &objects).unwrap(),
                "1234a0"
            );
        }
        assert_eq!(
            unique_object_abbreviation(&target, 7, &objects).unwrap(),
            target[..7]
        );
        assert_eq!(
            unique_object_abbreviation(&target, 0, &objects).unwrap(),
            target
        );
        assert!(unique_object_abbreviation(&target, 65, &objects).is_err());
        let temp = TempDirectory::new();
        let repo = temp.repo("describe-abbrev");
        let tip = repo.commit(&wasm(&[]), "without tags").unwrap();
        let before = stored_state(&repo);
        for requested in [0, 1, 2, 3, 4, 12, 64] {
            let options = DescribeOptions {
                abbrev: requested,
                ..DescribeOptions::default()
            };
            let report = repo.describe("HEAD", &options, |_| Ok(true)).unwrap();
            assert_eq!(report.requested_abbrev, requested);
            assert!(
                report.tag.is_none() && report.tag_commit.is_none() && report.distance.is_none()
            );
            if requested == 0 || requested == 64 {
                assert_eq!(report.abbreviation, tip);
            } else {
                assert!(
                    report.abbreviation.len() >= requested.max(4)
                        && tip.starts_with(&report.abbreviation)
                );
            }
        }
        assert!(repo
            .describe(
                "HEAD",
                &DescribeOptions {
                    abbrev: 65,
                    ..DescribeOptions::default()
                },
                |_| Ok(true)
            )
            .is_err());
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn describe_rejects_unborn_locked_and_corrupt_authorities_but_ignores_unrelated_work_state() {
        let temp = TempDirectory::new();
        let repo = temp.repo("describe-errors");
        let options = DescribeOptions::default();
        assert!(repo
            .describe("HEAD", &options, |_| Ok(true))
            .unwrap_err()
            .contains("no commits"));
        let tip = repo
            .commit(&wasm(&[255, 1, 254]), "unknown original bytes")
            .unwrap();
        fs::write(repo.metadata.join("index"), b"bad index\0").unwrap();
        fs::write(repo.metadata.join("pending.json"), b"bad pending\xff").unwrap();
        fs::write(repo.root.join("unfinished.txt"), b"unfinished user bytes").unwrap();
        let before = stored_state(&repo);
        assert_eq!(
            repo.describe("HEAD", &options, |_| Ok(true))
                .unwrap()
                .commit,
            tip
        );
        assert_eq!(
            fs::read(repo.metadata.join("index")).unwrap(),
            b"bad index\0"
        );
        assert_eq!(
            fs::read(repo.metadata.join("pending.json")).unwrap(),
            b"bad pending\xff"
        );
        assert_eq!(
            fs::read(repo.root.join("unfinished.txt")).unwrap(),
            b"unfinished user bytes"
        );
        assert_eq!(stored_state(&repo), before);
        let lock = repo.lock().unwrap();
        assert!(repo
            .describe("HEAD", &options, |_| Ok(true))
            .unwrap_err()
            .contains("locked"));
        drop(lock);
        let blob = repo.store_object(WASM_KIND, &wasm(&[99, 1, 9])).unwrap();
        assert!(repo
            .describe(&blob, &options, |_| Ok(true))
            .unwrap_err()
            .contains("non-commit"));
        let path = repo.metadata.join("objects").join(blob);
        fs::write(&path, b"corrupt even though unreachable").unwrap();
        let corrupt = stored_state(&repo);
        assert!(repo.describe("HEAD", &options, |_| Ok(true)).is_err());
        assert_eq!(stored_state(&repo), corrupt);
        assert!(!repo.metadata.join("write.lock").exists());
    }

    #[test]
    fn archive_snapshot_preserves_named_commit_and_direct_tree_provenance_and_original_bytes() {
        let temp = TempDirectory::new();
        let repo = temp.repo("archive-named");
        let bytes = wasm(&[255, 1, 254]);
        let expected = files(&[("one.wasm", bytes.clone()), ("nested/模块.wasm", bytes)]);
        let commit = commit_tree(&repo, &expected, "original modules", Some("one.wasm"));
        let tree = repo.read_commit("HEAD").unwrap().commit.tree.unwrap();
        commit_tree(&repo, &BTreeMap::new(), "empty tree", Some("one.wasm"));
        fs::write(repo.metadata.join("index"), b"unrelated bad index").unwrap();
        fs::write(repo.metadata.join("pending.json"), b"unrelated bad pending").unwrap();
        fs::write(repo.root.join("one.wasm"), b"unfinished bytes").unwrap();
        let before = stored_state(&repo);
        let snapshot = repo.archive_files("HEAD^").unwrap();
        assert_eq!(snapshot.object_id, commit);
        assert_eq!(snapshot.kind, "commit");
        assert_eq!(snapshot.commit.as_deref(), Some(commit.as_str()));
        assert_eq!(snapshot.tree.as_deref(), Some(tree.as_str()));
        assert_eq!(snapshot.legacy_path.as_deref(), Some("one.wasm"));
        assert!(snapshot.legacy.is_none());
        assert_eq!(snapshot.files, expected);
        let direct = repo.archive_files(&tree).unwrap();
        assert_eq!(direct.object_id, tree);
        assert_eq!(direct.kind, "tree");
        assert!(direct.commit.is_none() && direct.legacy_path.is_none() && direct.legacy.is_none());
        assert_eq!(direct.tree, snapshot.tree);
        assert_eq!(direct.files, expected);
        assert!(repo.archive_files(&tree[..63]).is_err());
        let empty = repo.archive_files("HEAD").unwrap();
        assert!(empty.tree.is_some() && empty.files.is_empty() && empty.legacy.is_none());
        assert_eq!(stored_state(&repo), before);
        assert_eq!(
            fs::read(repo.metadata.join("index")).unwrap(),
            b"unrelated bad index"
        );
        assert_eq!(
            fs::read(repo.metadata.join("pending.json")).unwrap(),
            b"unrelated bad pending"
        );
        assert_eq!(
            fs::read(repo.root.join("one.wasm")).unwrap(),
            b"unfinished bytes"
        );
    }

    #[test]
    fn archive_snapshot_keeps_legacy_unnamed_and_rejects_noncommit_corruption_and_locks() {
        let temp = TempDirectory::new();
        let repo = temp.repo("archive-legacy");
        let bytes = wasm(&[255, 1, 254]);
        let commit = repo.commit(&bytes, "unnamed original module").unwrap();
        let blob = repo.read_commit("HEAD").unwrap().commit.wasm;
        fs::write(
            repo.metadata.join("index"),
            pending_index_bytes(
                &files(&[("guessed.wasm", bytes.clone())]),
                Some("guessed.wasm"),
            ),
        )
        .unwrap();
        let before = stored_state(&repo);
        let legacy = repo.archive_files("HEAD").unwrap();
        assert_eq!(legacy.object_id, commit);
        assert_eq!(legacy.kind, "commit");
        assert_eq!(legacy.commit, Some(commit));
        assert!(legacy.tree.is_none() && legacy.legacy_path.is_none() && legacy.files.is_empty());
        assert_eq!(legacy.legacy, Some(bytes));
        assert!(repo.archive_files(&blob).unwrap_err().contains("Wasm blob"));
        let lock = repo.lock().unwrap();
        assert!(repo.archive_files("HEAD").unwrap_err().contains("locked"));
        drop(lock);
        assert_eq!(stored_state(&repo), before);
        let orphan = repo.store_object(WASM_KIND, &wasm(&[99, 1, 9])).unwrap();
        fs::write(
            repo.metadata.join("objects").join(orphan),
            b"corrupt orphan",
        )
        .unwrap();
        let corrupt = stored_state(&repo);
        assert!(repo.archive_files("HEAD").is_err());
        assert_eq!(stored_state(&repo), corrupt);
        assert!(!repo.metadata.join("write.lock").exists());
    }

    #[test]
    fn described_revision_roundtrips_long_labels_hint_counts_hex_case_and_ancestry() {
        let temp = TempDirectory::new();
        let repo = temp.repo("describe-revision-roundtrip");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let label = "t".repeat(128);
        repo.create_tag(&label, &root).unwrap();
        let tip = repo.commit(&wasm(&[99, 1, 1]), "tip").unwrap();
        let before = stored_state(&repo);
        let report = repo
            .describe("HEAD", &DescribeOptions::default(), |_| Ok(true))
            .unwrap();
        let description = format!(
            "{}-{}-g{}",
            report.tag.unwrap(),
            report.distance.unwrap(),
            report.abbreviation
        );
        assert!(description.len() > 128);
        assert_eq!(repo.resolve(&description).unwrap(), tip);
        assert_eq!(repo.resolve(&format!("{description}^1")).unwrap(), root);
        assert_eq!(repo.resolve(&format!("{description}~1")).unwrap(), root);
        assert_eq!(
            repo.archive_files(&description).unwrap(),
            repo.archive_files("HEAD").unwrap()
        );
        assert_eq!(
            repo.query_tree(&description).unwrap(),
            repo.query_tree("HEAD").unwrap()
        );
        let hinted = format!(
            "absent-label-{}-g{}",
            "9".repeat(200),
            tip.to_ascii_uppercase()
        );
        assert_eq!(repo.resolve(&hinted).unwrap(), tip);
        assert_eq!(repo.resolve(&format!("{hinted}^0")).unwrap(), tip);
        for malformed in [
            format!("-999-g{tip}"),
            format!("label-x-g{tip}"),
            format!("label--g{tip}"),
            format!("label-g{tip}"),
            "label-1-g".into(),
            format!("bad/../label-1-g{tip}"),
            format!("{}-1-g{tip}", "t".repeat(129)),
            format!("label-1-g{}", &tip[..3]),
        ] {
            assert!(repo.resolve(&malformed).is_err(), "{malformed}");
        }
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn described_revision_keeps_real_ref_priority_and_requires_unique_commit_objects() {
        let temp = TempDirectory::new();
        let repo = temp.repo("describe-revision-priority");
        let first = repo.commit(&wasm(&[]), "first").unwrap();
        let tip = repo.commit(&wasm(&[99, 1, 1]), "tip").unwrap();
        let description = format!("hint-999-g{tip}");
        repo.create_branch(&description, &first).unwrap();
        let before = stored_state(&repo);
        assert_eq!(repo.resolve(&description).unwrap(), first);
        repo.create_tag(&description, &tip).unwrap();
        let both = stored_state(&repo);
        assert!(repo
            .resolve(&description)
            .unwrap_err()
            .contains("ambiguous"));
        assert_eq!(stored_state(&repo), both);
        let blob = repo.read_commit(&tip).unwrap().commit.wasm;
        assert!(repo
            .resolve(&format!("hint-1-g{blob}"))
            .unwrap_err()
            .contains("non-commit"));
        assert!(repo
            .resolve(&format!("hint-1-g{}", "0".repeat(64)))
            .unwrap_err()
            .contains("unknown"));
        // A fixed internal ID table distinguishes description suffixes, which
        // cover every object kind, from the existing bare commit-only prefix.
        let mut snapshot = repo.snapshot().unwrap();
        let commit_id = format!("1234{}", "a".repeat(60));
        let blob_id = format!("1234{}", "b".repeat(60));
        let commit = match snapshot.objects.get(&tip).unwrap() {
            Object::Commit(value) => value.clone(),
            _ => unreachable!(),
        };
        snapshot
            .objects
            .insert(commit_id.clone(), Object::Commit(commit));
        snapshot.objects.insert(blob_id, Object::Wasm(Vec::new()));
        assert!(snapshot_base_revision(&snapshot, "hint-1-g1234")
            .unwrap_err()
            .contains("ambiguous"));
        assert_eq!(
            snapshot_base_revision(&snapshot, "hint-1-g1234A").unwrap(),
            commit_id
        );
        assert_eq!(before.objects, both.objects);
        assert!(!repo.metadata.join("write.lock").exists());
    }

    fn query_tracking(
        repo: &Repository,
        remote: &str,
        branches: BTreeMap<String, String>,
        tags: BTreeMap<String, String>,
    ) {
        let path = repo.metadata.join("remotes");
        fs::create_dir_all(&path).unwrap();
        let value = json!({"version":1,"remote":remote,"url":"local-query-fixture",
            "state":{"format":1,"head":"main","branches":branches,"tags":tags}});
        fs::write(
            path.join(format!("{remote}.tracking.json")),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn query_unborn_repository_ignores_bad_index_pending_and_work_bytes_without_writes() {
        let temp = TempDirectory::new();
        let repo = temp.repo("query-unborn");
        let pending = b"not a pending journal\0";
        let index = b"not an index\xff";
        let work = b"unfinished text, not a Wasm module";
        fs::write(repo.metadata.join("pending.json"), pending).unwrap();
        fs::write(repo.metadata.join("index"), index).unwrap();
        fs::write(repo.root.join("editor.txt"), work).unwrap();
        let before = stored_state(&repo);
        let refs = repo.query_refs().unwrap();
        assert_eq!(refs.head, "main");
        assert!(refs.head_tip.is_none() && refs.refs.is_empty());
        let objects = repo.query_objects().unwrap();
        assert_eq!(
            (
                objects.objects,
                objects.payload_bytes,
                objects.stored_bytes,
                objects.reachable_objects,
                objects.unreachable_objects,
                objects.root_commits
            ),
            (0, 0, 0, 0, 0, 0)
        );
        assert_eq!(objects.by_kind.len(), 3);
        assert!(objects
            .by_kind
            .values()
            .all(|value| value == &QueryObjectCounts::default()));
        assert!(repo.query_tree("HEAD").is_err());
        assert_eq!(stored_state(&repo), before);
        assert_eq!(
            fs::read(repo.metadata.join("pending.json")).unwrap(),
            pending
        );
        assert_eq!(fs::read(repo.metadata.join("index")).unwrap(), index);
        assert_eq!(fs::read(repo.root.join("editor.txt")).unwrap(), work);
        assert!(!repo.metadata.join("write.lock").exists());
    }

    #[test]
    fn query_refs_reports_real_names_commit_sizes_current_and_upstream_in_one_snapshot() {
        let temp = TempDirectory::new();
        let repo = temp.repo("query-refs");
        let head = repo.commit(&wasm(&[]), "local").unwrap();
        repo.create_branch("other", &head).unwrap();
        repo.create_tag("release", &head).unwrap();
        repo.set_upstream_on_branch("main", "origin", "main", &head)
            .unwrap();
        let blob = repo.store_object(WASM_KIND, &wasm(&[99, 1, 9])).unwrap();
        let remote = store_history_commit(&repo, &blob, &[], "remote branch only");
        query_tracking(
            &repo,
            "origin",
            BTreeMap::from([("main".into(), remote.clone())]),
            BTreeMap::from([("not-a-local-tag".into(), remote.clone())]),
        );
        let before = stored_state(&repo);
        let refs = repo.query_refs().unwrap();
        assert_eq!(refs.head, "main");
        assert_eq!(refs.head_tip, Some(head.clone()));
        assert_eq!(
            refs.refs
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            [
                "refs/heads/main",
                "refs/heads/other",
                "refs/remotes/origin/main",
                "refs/tags/release"
            ]
        );
        for row in &refs.refs {
            let raw = fs::read(repo.metadata.join("objects").join(&row.id)).unwrap();
            assert_eq!(row.kind, "commit");
            assert_eq!(row.byte_len, (raw.len() - OBJECT_HEADER_LENGTH) as u64);
            assert_eq!(row.stored_byte_len, raw.len() as u64);
        }
        assert!(refs.refs[0].current);
        assert_eq!(
            refs.refs[0].upstream,
            Some(Upstream {
                remote: "origin".into(),
                branch: "main".into()
            })
        );
        assert!(refs.refs[1..]
            .iter()
            .all(|row| !row.current && row.upstream.is_none()));
        assert_eq!(refs.refs[2].id, remote);
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn query_tree_reports_flat_shared_paths_full_tree_ids_and_commit_revision_syntax() {
        let temp = TempDirectory::new();
        let repo = temp.repo("query-flat-tree");
        let payload = wasm(&[99, 1, 9]);
        let initial = files(&[
            ("a.wasm", payload.clone()),
            ("nested/b.wasm", payload.clone()),
            ("目录/space name.wasm", wasm(&[])),
        ]);
        let first = commit_tree(&repo, &initial, "named modules", None);
        let second = commit_tree(&repo, &BTreeMap::new(), "empty tree", None);
        let before = stored_state(&repo);
        let report = repo.query_tree("HEAD^").unwrap();
        assert_eq!(report.object_id, first);
        assert_eq!(report.kind, "commit");
        assert_eq!(report.commit.as_deref(), Some(first.as_str()));
        assert!(report.named && report.legacy.is_none());
        assert_eq!(
            report
                .entries
                .iter()
                .map(|row| row.path.as_str())
                .collect::<Vec<_>>(),
            ["a.wasm", "nested/b.wasm", "目录/space name.wasm"]
        );
        assert_eq!(report.entries[0].object_id, report.entries[1].object_id);
        assert_eq!(report.entries[0].byte_len, payload.len() as u64);
        assert_eq!(
            report.entries[0].stored_byte_len,
            (payload.len() + OBJECT_HEADER_LENGTH) as u64
        );
        assert!(report.entries.iter().all(|row| row.kind == "wasm"));
        let tree = report.tree.as_ref().unwrap();
        let direct = repo.query_tree(tree).unwrap();
        assert_eq!(direct.entries, report.entries);
        assert_eq!(direct.kind, "tree");
        assert!(direct.commit.is_none() && direct.legacy_path.is_none());
        assert!(repo.query_tree(&tree[..63]).is_err());
        assert_eq!(repo.query_tree(&first[..63]).unwrap(), report);
        assert!(repo
            .query_tree(&report.entries[0].object_id)
            .unwrap_err()
            .contains("Wasm blob"));
        let empty = repo.query_tree("HEAD").unwrap();
        assert_eq!(empty.commit.as_deref(), Some(second.as_str()));
        assert!(empty.named && empty.entries.is_empty() && empty.tree.is_some());
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn query_legacy_commit_preserves_unnamed_blob_identity_without_index_name_guessing() {
        let temp = TempDirectory::new();
        let repo = temp.repo("query-legacy");
        let payload = wasm(&[255, 1, 254]);
        let head = repo.commit(&payload, "unknown core data").unwrap();
        let blob = repo.read_commit(&head).unwrap().commit.wasm;
        let raw_index = pending_index_bytes(
            &files(&[("guessed.wasm", payload.clone())]),
            Some("guessed.wasm"),
        );
        fs::write(repo.metadata.join("index"), &raw_index).unwrap();
        let before = stored_state(&repo);
        let report = repo.query_tree("HEAD").unwrap();
        assert_eq!(report.kind, "commit");
        assert_eq!(report.commit, Some(head));
        assert!(!report.named && report.entries.is_empty() && report.tree.is_none());
        assert!(report.legacy_path.is_none());
        assert_eq!(
            report.legacy,
            Some(QueryObject {
                object_id: blob,
                kind: "wasm".into(),
                byte_len: payload.len() as u64,
                stored_byte_len: (payload.len() + OBJECT_HEADER_LENGTH) as u64
            })
        );
        assert_eq!(fs::read(repo.metadata.join("index")).unwrap(), raw_index);
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn query_object_counts_use_raw_unique_objects_and_branch_tag_tracking_reflog_roots() {
        let temp = TempDirectory::new();
        let repo = temp.repo("query-object-roots");
        let base = repo.commit(&wasm(&[]), "base").unwrap();
        let held = repo.commit(&wasm(&[99, 1, 1]), "held by reflog").unwrap();
        repo.atomic_write(
            &repo.metadata.join("refs/main"),
            format!("{base}\n").as_bytes(),
        )
        .unwrap();
        let mut isolated = Vec::new();
        for (byte, message) in [
            (2, "local tag only"),
            (3, "remote branch only"),
            (4, "remote tag excluded"),
        ] {
            let blob = repo.store_object(WASM_KIND, &wasm(&[99, 1, byte])).unwrap();
            isolated.push(store_history_commit(&repo, &blob, &[], message));
        }
        fs::write(
            repo.metadata.join("tags/kept"),
            format!("{}\n", isolated[0]),
        )
        .unwrap();
        query_tracking(
            &repo,
            "origin",
            BTreeMap::from([("main".into(), isolated[1].clone())]),
            BTreeMap::from([("cached-only".into(), isolated[2].clone())]),
        );
        repo.store_object(WASM_KIND, &wasm(&[99, 1, 5])).unwrap();
        let before = stored_state(&repo);
        let report = repo.query_objects().unwrap();
        assert_eq!(
            (
                report.objects,
                report.reachable_objects,
                report.unreachable_objects,
                report.root_commits
            ),
            (11, 8, 3, 4)
        );
        assert_eq!(
            (
                report.by_kind["commit"].objects,
                report.by_kind["commit"].reachable_objects,
                report.by_kind["commit"].unreachable_objects
            ),
            (5, 4, 1)
        );
        assert_eq!(
            (
                report.by_kind["wasm"].objects,
                report.by_kind["wasm"].reachable_objects,
                report.by_kind["wasm"].unreachable_objects
            ),
            (6, 4, 2)
        );
        assert_eq!(report.by_kind["tree"], QueryObjectCounts::default());
        let stored: u64 = before
            .objects
            .values()
            .map(|bytes| bytes.len() as u64)
            .sum();
        assert_eq!(report.stored_bytes, stored);
        assert_eq!(
            report.payload_bytes,
            stored - report.objects as u64 * OBJECT_HEADER_LENGTH as u64
        );
        assert_eq!(
            report
                .by_kind
                .values()
                .map(|value| value.stored_bytes)
                .sum::<u64>(),
            stored
        );
        assert_eq!(
            report
                .by_kind
                .values()
                .map(|value| value.payload_bytes)
                .sum::<u64>(),
            report.payload_bytes
        );
        assert_eq!(repo.fsck().unwrap().unreachable_objects, 7);
        assert!(report.root_policy.contains("fetched_tracking_branches"));
        assert!(report
            .root_policy
            .contains("unreachable_is_not_a_deletion_recommendation"));
        assert_eq!(stored_state(&repo), before);
        let log = fs::read(repo.metadata.join("reflog")).unwrap();
        fs::remove_file(repo.metadata.join("reflog")).unwrap();
        assert_eq!(
            repo.query_objects().unwrap().root_commits,
            report.root_commits
        );
        let head_log = fs::read(repo.metadata.join("head-reflog.json")).unwrap();
        fs::remove_file(repo.metadata.join("head-reflog.json")).unwrap();
        let without_log = repo.query_objects().unwrap();
        assert_eq!(
            (without_log.root_commits, without_log.unreachable_objects),
            (3, 5)
        );
        assert!(!repo
            .query_refs()
            .unwrap()
            .refs
            .iter()
            .any(|row| row.id == held));
        fs::write(repo.metadata.join("reflog"), log).unwrap();
        fs::write(repo.metadata.join("head-reflog.json"), head_log).unwrap();
        let mut maximum = u64::MAX;
        assert!(add_query_bytes(&mut maximum, 1).is_err());
        assert_eq!(maximum, u64::MAX);
    }

    #[test]
    fn queries_reject_held_writer_and_corruption_even_in_unreachable_store_without_writes() {
        let temp = TempDirectory::new();
        let repo = temp.repo("query-errors");
        repo.commit(&wasm(&[]), "base").unwrap();
        let assert_rejected = || {
            let before = stored_state(&repo);
            assert!(repo.query_refs().is_err());
            assert!(repo.query_tree("HEAD").is_err());
            assert!(repo.query_objects().is_err());
            assert_eq!(stored_state(&repo), before);
        };
        fs::write(repo.metadata.join("write.lock"), b"external owner").unwrap();
        assert_rejected();
        assert_eq!(
            fs::read(repo.metadata.join("write.lock")).unwrap(),
            b"external owner"
        );
        fs::remove_file(repo.metadata.join("write.lock")).unwrap();
        let id = repo.store_object(WASM_KIND, &wasm(&[99, 1, 9])).unwrap();
        let path = repo.metadata.join("objects").join(&id);
        let original = fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&path, corrupt).unwrap();
        assert_rejected();
        fs::write(&path, original).unwrap();
        let log = fs::read(repo.metadata.join("reflog")).unwrap();
        fs::write(repo.metadata.join("reflog"), b"bad reflog").unwrap();
        assert_rejected();
        fs::write(repo.metadata.join("reflog"), log).unwrap();
        query_tracking(
            &repo,
            "origin",
            BTreeMap::from([("main".into(), "0".repeat(64))]),
            BTreeMap::new(),
        );
        assert_rejected();
    }

    #[test]
    fn query_counts_do_not_treat_unpublished_pending_progress_or_index_as_retention_roots() {
        let temp = TempDirectory::new();
        let (repo, head, target) = pending_fixture(&temp, "query-pending-roots");
        let pending = repo
            .record_pending(pending_request(&repo, "merge", &head, &target))
            .unwrap();
        let files = files(&[("a.wasm", wasm(&[0, 2, 0, 40]))]);
        let raw = pending_index_bytes(&files, None);
        let prepared = prepare_pending_fixture(&repo, &pending, &files, &raw);
        fs::write(repo.metadata.join("index"), &raw).unwrap();
        let report = repo.query_objects().unwrap();
        assert_eq!(report.unreachable_objects, 3);
        let before = stored_state(&repo);
        let broken = b"broken pending journal ignored by read-only queries";
        fs::write(repo.metadata.join("pending.json"), broken).unwrap();
        assert_eq!(repo.query_objects().unwrap(), report);
        assert_eq!(repo.query_tree("HEAD").unwrap().commit, Some(head));
        assert_eq!(
            repo.query_refs().unwrap().head_tip.as_deref(),
            Some(prepared.head.as_str())
        );
        assert_eq!(stored_state(&repo), before);
        assert_eq!(
            fs::read(repo.metadata.join("pending.json")).unwrap(),
            broken
        );
        assert_eq!(fs::read(repo.metadata.join("index")).unwrap(), raw);
    }

    #[test]
    fn tree_commit_roundtrip_empty_deletion_and_legacy_bytes_remain_exact() {
        let temp = TempDirectory::new();
        let repo = temp.repo("tree");
        let original = files(&[
            ("one.wasm", wasm(&[])),
            ("目录/two.wasm", wasm(&[99, 1, 0x42])),
        ]);
        let first = commit_tree(&repo, &original, "two modules", None);
        let revision = repo.files_at("HEAD").unwrap();
        assert_eq!(revision.commit, first);
        assert!(revision.legacy.is_none());
        assert_eq!(revision.files, original);
        let info = repo.read_commit("HEAD").unwrap();
        assert_eq!(info.commit.format, 2);
        assert!(info.commit.wasm.is_empty());
        let tree = info.commit.tree.unwrap();
        assert_eq!(repo.cat_object(&tree).unwrap().0, "tree");
        assert!(repo.wasm_bytes("HEAD").unwrap_err().contains("file tree"));
        assert!(repo
            .checkout("HEAD", temp.path("must-not-exist.wasm"))
            .is_err());
        assert!(!temp.path("must-not-exist.wasm").exists());
        let report = repo.fsck().unwrap();
        assert_eq!((report.commits, report.trees, report.wasm_blobs), (1, 1, 2));
        let empty = commit_tree(&repo, &BTreeMap::new(), "delete all modules", None);
        assert!(repo.files_at(&empty).unwrap().files.is_empty());
        assert_eq!(
            repo.read_commit(&empty).unwrap().commit.parents,
            vec![first]
        );
        assert_eq!(repo.fsck().unwrap().unreachable_objects, 0);
    }

    #[test]
    fn tree_paths_and_invalid_wasm_are_rejected_before_any_storage() {
        let temp = TempDirectory::new();
        let repo = temp.repo("tree");
        let before = stored_state(&repo);
        for path in [
            "",
            "/x",
            "../x",
            "a/../x",
            "a//x",
            "a/./x",
            "a/.uwgit/x",
            ".UWGIT/x",
            "a\\x",
            "C:x",
            "a\nx",
            "a/",
        ] {
            let input = files(&[(path, wasm(&[]))]);
            assert!(
                repo.commit_files_on_branch(&input, "invalid path", &[], "main", None, None)
                    .is_err(),
                "{path:?}"
            );
            assert_eq!(stored_state(&repo), before);
        }
        for input in [
            files(&[("a", wasm(&[])), ("a/b", wasm(&[]))]),
            files(&[("a.wasm", b"not Wasm".to_vec())]),
        ] {
            assert!(repo
                .commit_files_on_branch(&input, "invalid tree", &[], "main", None, None)
                .is_err());
            assert_eq!(stored_state(&repo), before);
        }
    }

    #[test]
    fn legacy_promotion_requires_a_persistent_explicit_anchor_and_old_writers_cannot_drop_tree() {
        let temp = TempDirectory::new();
        let repo = temp.repo("legacy");
        let root = repo.commit(&wasm(&[]), "old root").unwrap();
        let old_payload = repo.cat_object(&root).unwrap().1;
        let input = files(&[("old.wasm", wasm(&[])), ("second.wasm", wasm(&[0, 1, 0]))]);
        let before = stored_state(&repo);
        assert!(repo
            .commit_files_on_branch(
                &input,
                "needs mapping",
                std::slice::from_ref(&root),
                "main",
                Some(&root),
                None
            )
            .is_err());
        assert_eq!(stored_state(&repo), before);
        let tree = commit_tree(&repo, &input, "upgrade", Some("old.wasm"));
        assert_eq!(repo.cat_object(&root).unwrap().1, old_payload);
        assert_eq!(
            repo.files_at("HEAD").unwrap().legacy_path.as_deref(),
            Some("old.wasm")
        );
        let before = stored_state(&repo);
        assert!(repo.commit(&wasm(&[]), "must not lose files").is_err());
        assert!(repo
            .commit_on_branch(
                &wasm(&[]),
                "must not lose files",
                std::slice::from_ref(&tree),
                "main",
                Some(&tree)
            )
            .is_err());
        assert!(repo
            .commit_files_on_branch(
                &input,
                "changed anchor",
                std::slice::from_ref(&tree),
                "main",
                Some(&tree),
                Some("renamed.wasm")
            )
            .is_err());
        assert_eq!(stored_state(&repo), before);
        commit_tree(
            &repo,
            &BTreeMap::new(),
            "delete legacy path too",
            Some("old.wasm"),
        );
        assert_eq!(
            repo.files_at("HEAD").unwrap().legacy_path.as_deref(),
            Some("old.wasm")
        );
    }

    #[test]
    fn tree_bundle_uses_explicit_v3_and_preserves_all_shared_file_closures() {
        let temp = TempDirectory::new();
        let repo = temp.repo("source");
        let root = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[])), ("b.wasm", wasm(&[]))]),
            "shared blob",
            None,
        );
        repo.create_tag("v1", "HEAD").unwrap();
        let tip = commit_tree(
            &repo,
            &files(&[("a.wasm", wasm(&[0, 1, 0]))]),
            "remove b",
            None,
        );
        let (state, bundle) = repo.bundle_bytes(Some("HEAD")).unwrap();
        let snapshot = decode_bundle(&bundle).unwrap();
        assert_eq!(snapshot.manifest.format, 3);
        assert_eq!(snapshot.objects.len(), 6);
        assert_eq!(state.tags["v1"], root);
        let clone = Repository::clone_bundle_bytes(&bundle, temp.path("clone")).unwrap();
        assert_eq!(
            clone.files_at(&tip).unwrap().files,
            repo.files_at(&tip).unwrap().files
        );
        assert_eq!(clone.files_at("v1").unwrap().files.len(), 2);
        assert_eq!(clone.fsck().unwrap().unreachable_objects, 0);
        let mut wrong = snapshot;
        wrong.manifest.format = 2;
        assert!(decode_bundle(&encode_bundle(&wrong).unwrap())
            .unwrap_err()
            .contains("manifest format"));
        let legacy = temp.repo("legacy");
        legacy.commit(&wasm(&[]), "old").unwrap();
        assert_eq!(
            decode_bundle(&legacy.bundle_bytes(None).unwrap().1)
                .unwrap()
                .manifest
                .format,
            1
        );
        legacy.create_tag("old", "HEAD").unwrap();
        assert_eq!(
            decode_bundle(&legacy.bundle_bytes(None).unwrap().1)
                .unwrap()
                .manifest
                .format,
            2
        );
    }

    fn complete_repository_bytes(repo: &Repository) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if metadata.is_dir() {
                entries.insert(relative, None);
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), entries);
                }
            } else {
                assert!(metadata.is_file());
                entries.insert(relative, Some(fs::read(path).unwrap()));
            }
        }
        let mut entries = BTreeMap::new();
        visit(&repo.root, &repo.root, &mut entries);
        entries
    }

    #[test]
    fn tree_unbundle_rejects_tracked_head_without_changing_any_repository_or_worktree_bytes() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let base = commit_tree(&source, &files(&[("owned.wasm", wasm(&[]))]), "base", None);
        let target = Repository::clone_local(&source.root, temp.path("tracked")).unwrap();
        let bare = Repository::clone_local(&source.root, temp.path("bare")).unwrap();
        let staged = wasm(&[0, 1, 0]);
        let unstaged = wasm(&[0, 2, 0, 1]);
        let untracked = wasm(&[0, 2, 0, 2]);
        fs::write(target.root.join("owned.wasm"), &staged).unwrap();
        crate::porcelain::run(&[
            "add".into(),
            target.root.to_str().unwrap().into(),
            "owned.wasm".into(),
        ])
        .unwrap();
        fs::write(target.root.join("owned.wasm"), &unstaged).unwrap();
        fs::write(target.root.join("incoming.wasm"), &untracked).unwrap();
        let index = fs::read(target.metadata.join("index")).unwrap();
        let descendant_files = files(&[
            ("owned.wasm", wasm(&[0, 2, 0, 3])),
            ("incoming.wasm", wasm(&[0, 2, 0, 4])),
        ]);
        let descendant = commit_tree(&source, &descendant_files, "descendant", None);
        let bundle = temp.path("descendant.bundle");
        source.export_bundle(&bundle).unwrap();

        let before = complete_repository_bytes(&target);
        assert!(target
            .import_bundle(&bundle, "main")
            .unwrap_err()
            .contains("import into another branch, then merge"));
        assert_eq!(complete_repository_bytes(&target), before);
        assert_eq!(target.resolve("HEAD").unwrap(), base);

        assert_eq!(
            target.import_bundle(&bundle, "incoming").unwrap(),
            descendant
        );
        assert_eq!(target.resolve("HEAD").unwrap(), base);
        assert_eq!(target.resolve("incoming").unwrap(), descendant);
        assert_eq!(fs::read(target.metadata.join("index")).unwrap(), index);
        assert_eq!(fs::read(target.root.join("owned.wasm")).unwrap(), unstaged);
        assert_eq!(
            fs::read(target.root.join("incoming.wasm")).unwrap(),
            untracked
        );
        assert_eq!(target.files_at("incoming").unwrap().files, descendant_files);

        assert!(!bare.metadata.join("index").exists());
        assert_eq!(bare.import_bundle(&bundle, "main").unwrap(), descendant);
        assert_eq!(bare.resolve("HEAD").unwrap(), descendant);
        assert_eq!(bare.files_at("HEAD").unwrap().files, descendant_files);
        assert!(!bare.metadata.join("index").exists());
        assert!(!target.metadata.join("index.lock").exists());
        assert!(!target.metadata.join("write.lock").exists());
    }

    #[test]
    fn tree_unbundle_obeys_index_and_writer_locks_without_partial_installation() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        commit_tree(&source, &files(&[("new.wasm", wasm(&[]))]), "root", None);
        let target = temp.repo("target");
        let bundle = temp.path("incoming.bundle");
        source.export_bundle(&bundle).unwrap();

        let index_lock = target.lock_named("index.lock").unwrap();
        let before = complete_repository_bytes(&target);
        assert!(target
            .import_bundle(&bundle, "incoming")
            .unwrap_err()
            .contains("index.lock"));
        assert_eq!(complete_repository_bytes(&target), before);
        drop(index_lock);

        let writer_lock = target.lock().unwrap();
        let before = complete_repository_bytes(&target);
        assert!(target
            .import_bundle(&bundle, "incoming")
            .unwrap_err()
            .contains("write.lock"));
        assert_eq!(complete_repository_bytes(&target), before);
        drop(writer_lock);
        assert!(!target.metadata.join("index.lock").exists());
        assert!(!target.metadata.join("write.lock").exists());
    }

    #[test]
    fn tree_decoder_and_graph_validation_reject_invalid_paths_prefixes_and_missing_or_wrong_blobs()
    {
        let temp = TempDirectory::new();
        let repo = temp.repo("source");
        commit_tree(&repo, &files(&[("a.wasm", wasm(&[]))]), "root", None);
        let snapshot = repo.snapshot().unwrap();
        let blob = snapshot
            .objects
            .iter()
            .find_map(|(id, object)| matches!(object, Object::Wasm(_)).then_some(id.clone()))
            .unwrap();
        for entries in [
            BTreeMap::from([("../bad".into(), blob.clone())]),
            BTreeMap::from([("a".into(), blob.clone()), ("a/b".into(), blob.clone())]),
        ] {
            let payload = serde_json::to_vec(&Tree { format: 1, entries }).unwrap();
            let encoded = encode_object(TREE_KIND, &payload).unwrap();
            assert!(decode_object(&object_id(&encoded), &encoded).is_err());
        }
        for missing in ["a".repeat(64), repo.resolve("HEAD").unwrap()] {
            let mut objects = snapshot.objects.clone();
            let tree = Tree {
                format: 1,
                entries: BTreeMap::from([("bad.wasm".into(), missing)]),
            };
            objects.insert("b".repeat(64), Object::Tree(tree));
            assert!(validate_object_graph(&objects)
                .unwrap_err()
                .contains("non-Wasm"));
        }
    }

    #[test]
    fn tree_commit_transactions_bind_branch_and_tip_and_reject_invalid_ancestry() {
        let temp = TempDirectory::new();
        let repo = temp.repo("cas-tree");
        let root = commit_tree(&repo, &BTreeMap::new(), "root", None);
        repo.create_branch("same-tip", "HEAD").unwrap();
        repo.switch_branch("same-tip").unwrap();
        let input = files(&[("a.wasm", wasm(&[]))]);
        let before = stored_state(&repo);
        for (branch, expected, parents) in [
            ("main", Some(root.as_str()), vec![root.clone()]),
            ("same-tip", None, vec![root.clone()]),
            ("same-tip", Some(root.as_str()), vec!["a".repeat(64)]),
            (
                "same-tip",
                Some(root.as_str()),
                vec![root.clone(), root.clone()],
            ),
        ] {
            assert!(repo
                .commit_files_on_branch(&input, "must reject", &parents, branch, expected, None)
                .is_err());
            assert_eq!(stored_state(&repo), before);
        }
        let mut objects = repo.snapshot().unwrap().objects;
        let encoded = encode_object(WASM_KIND, &wasm(&[])).unwrap();
        let wasm_id = object_id(&encoded);
        objects.insert(wasm_id.clone(), Object::Wasm(wasm(&[])));
        objects.insert(
            "f".repeat(64),
            Object::Commit(Commit {
                format: 1,
                wasm: wasm_id,
                parents: vec![root],
                message: "illegal downgrade".into(),
                tree: None,
                legacy_path: None,
            }),
        );
        assert!(validate_object_graph(&objects)
            .unwrap_err()
            .contains("cannot discard"));
    }

    #[test]
    fn tree_merge_combines_independent_additions_modifications_and_exact_deletion() {
        let temp = TempDirectory::new();
        let repo = temp.repo("merge");
        let base = files(&[
            ("main.wasm", function_wasm(1, 2)),
            ("delete.wasm", wasm(&[])),
        ]);
        commit_tree(&repo, &base, "base", None);
        repo.create_branch("theirs", "HEAD").unwrap();
        let ours = files(&[
            ("main.wasm", function_wasm(11, 2)),
            ("ours.wasm", wasm(&[99, 1, 0x42])),
        ]);
        let ours_id = commit_tree(&repo, &ours, "ours", None);
        repo.switch_branch("theirs").unwrap();
        let theirs = files(&[
            ("main.wasm", function_wasm(1, 22)),
            ("delete.wasm", wasm(&[])),
            ("theirs.wasm", wasm(&[99, 1, 0x43])),
        ]);
        let theirs_id = commit_tree(&repo, &theirs, "theirs", None);
        repo.switch_branch("main").unwrap();
        let outcome = repo
            .merge_on_branch(&theirs_id, "combine", "main", Some(&ours_id))
            .unwrap();
        assert_eq!(outcome.status, "merged");
        assert_eq!(
            repo.files_at("HEAD").unwrap().files,
            files(&[
                ("main.wasm", function_wasm(11, 22)),
                ("ours.wasm", wasm(&[99, 1, 0x42])),
                ("theirs.wasm", wasm(&[99, 1, 0x43]))
            ])
        );
        assert!(outcome
            .file_reports
            .iter()
            .any(|report| report.path == "delete.wasm" && report.status == "deleted"));
        assert_eq!(
            repo.read_commit("HEAD").unwrap().commit.parents,
            vec![ours_id, theirs_id]
        );
        repo.fsck().unwrap();
    }

    fn manual_tree_fixture(
        temp: &TempDirectory,
        name: &str,
    ) -> (Repository, String, String, String) {
        let repo = temp.repo(name);
        let base = commit_tree(
            &repo,
            &files(&[
                ("main.wasm", function_wasm(1, 2)),
                ("delete.wasm", wasm(&[])),
            ]),
            "base",
            None,
        );
        repo.create_branch("theirs", "HEAD").unwrap();
        let ours = commit_tree(
            &repo,
            &files(&[
                ("main.wasm", function_wasm(11, 2)),
                ("ours.wasm", wasm(&[])),
            ]),
            "ours",
            None,
        );
        repo.switch_branch("theirs").unwrap();
        let target = commit_tree(
            &repo,
            &files(&[
                ("main.wasm", function_wasm(1, 22)),
                ("delete.wasm", wasm(&[])),
                ("theirs.wasm", wasm(&[0, 1, 0])),
            ]),
            "theirs",
            None,
        );
        repo.switch_branch("main").unwrap();
        (repo, base, ours, target)
    }

    #[test]
    fn manual_tree_resolution_audits_both_parents_and_preserves_dirty_index_and_worktree() {
        let temp = TempDirectory::new();
        let (repo, base, ours, target) = manual_tree_fixture(&temp, "resolved");
        fs::write(repo.root.join("main.wasm"), function_wasm(101, 202)).unwrap();
        crate::porcelain::run(&[
            "add".into(),
            repo.root.to_str().unwrap().into(),
            "main.wasm".into(),
        ])
        .unwrap();
        let index = fs::read(repo.metadata.join("index")).unwrap();
        fs::write(repo.root.join("main.wasm"), b"unstaged invalid bytes").unwrap();
        fs::create_dir(repo.root.join("new.wasm")).unwrap();
        let worktree: BTreeMap<_, _> = complete_repository_bytes(&repo)
            .into_iter()
            .filter(|(path, _)| !path.starts_with(".uwgit"))
            .collect();
        let unknown = wasm(&[99, 1, 0x42]);
        let resolved = files(&[
            ("main.wasm", function_wasm(111, 222)),
            ("ours.wasm", wasm(&[])),
            ("new.wasm", unknown.clone()),
        ]);
        let index_lock = repo.lock_named("index.lock").unwrap();
        let outcome = repo
            .merge_files_resolved_on_branch(
                "main",
                &ours,
                &target,
                &resolved,
                None,
                "explicit complete resolution",
            )
            .unwrap();
        drop(index_lock);
        assert_eq!(outcome.status, "merged_resolved");
        assert_eq!(outcome.base.as_deref(), Some(base.as_str()));
        assert!(outcome.manual_resolution.is_none() && outcome.report.is_none());
        let id = outcome.commit.as_ref().unwrap();
        assert_eq!(
            repo.read_commit(id).unwrap().commit.parents,
            vec![ours, target]
        );
        assert_eq!(repo.files_at(id).unwrap().files, resolved);
        assert_eq!(fs::read(repo.metadata.join("index")).unwrap(), index);
        assert_eq!(
            complete_repository_bytes(&repo)
                .into_iter()
                .filter(|(path, _)| !path.starts_with(".uwgit"))
                .collect::<BTreeMap<_, _>>(),
            worktree
        );
        let report = outcome.tree_manual_resolution.unwrap();
        assert!(report.supplied_complete_tree);
        assert!(report.provenance.contains("no_automatic_merge_claim"));
        assert_eq!(report.files.len(), 5);
        let changed = report
            .files
            .iter()
            .find(|file| file.path == "main.wasm")
            .unwrap();
        for delta in [&changed.from_ours, &changed.from_theirs] {
            assert_eq!(delta.status, "modified");
            let audit = delta.audit.as_ref().unwrap();
            assert!(audit.changed && !audit.edits.is_empty());
        }
        let added = report
            .files
            .iter()
            .find(|file| file.path == "new.wasm")
            .unwrap();
        assert!(added.base.is_none() && added.ours.is_none() && added.theirs.is_none());
        assert_eq!(added.from_ours.status, "added");
        let witness = added.resolved.as_ref().unwrap();
        assert_eq!(witness.byte_len, unknown.len());
        assert_eq!(witness.sha256, format!("{:x}", Sha256::digest(&unknown)));
        assert_eq!(
            witness.hex,
            unknown
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        assert!(!witness.audit.diagnostics.is_empty());
        let deleted = report
            .files
            .iter()
            .find(|file| file.path == "theirs.wasm")
            .unwrap();
        assert!(deleted.resolved.is_none() && deleted.theirs.is_some());
        assert_eq!(deleted.from_ours.status, "absent");
        assert_eq!(deleted.from_theirs.status, "deleted");
        assert!(!deleted.theirs.as_ref().unwrap().hex.is_empty());
        repo.fsck().unwrap();
    }

    #[test]
    fn manual_tree_resolution_preflight_refuses_stale_or_nonimmutable_inputs_and_bad_files() {
        let temp = TempDirectory::new();
        let (repo, base, ours, target) = manual_tree_fixture(&temp, "rejected");
        let valid = files(&[("resolved.wasm", wasm(&[]))]);
        let wrong_kind = repo.read_commit(&target).unwrap().commit.tree.unwrap();
        let missing = "e".repeat(64);
        let descendant = commit_tree(&repo, &valid, "descendant of ours", None);
        repo.reset_on_branch(&ours, "main", Some(&descendant))
            .unwrap();
        let before = complete_repository_bytes(&repo);
        for (expected, target) in [
            (base.as_str(), target.as_str()),
            (ours.as_str(), base.as_str()),
            (ours.as_str(), ours.as_str()),
            (ours.as_str(), descendant.as_str()),
            (ours.as_str(), "theirs"),
            (ours.as_str(), &target[..12]),
            (ours.as_str(), wrong_kind.as_str()),
            (ours.as_str(), missing.as_str()),
        ] {
            assert!(repo
                .merge_files_resolved_on_branch(
                    "main",
                    expected,
                    target,
                    &valid,
                    None,
                    "must reject",
                )
                .is_err());
            assert_eq!(complete_repository_bytes(&repo), before);
        }
        for invalid in [
            files(&[("../escape.wasm", wasm(&[]))]),
            files(&[("a/.uwgit/b", wasm(&[]))]),
            files(&[("a", wasm(&[])), ("a/b", wasm(&[]))]),
            files(&[("valid.wasm", b"invalid header".to_vec())]),
            files(&[("empty.wasm", Vec::new())]),
        ] {
            assert!(repo
                .merge_files_resolved_on_branch(
                    "main",
                    &ours,
                    &target,
                    &invalid,
                    None,
                    "invalid tree",
                )
                .is_err());
            assert_eq!(complete_repository_bytes(&repo), before);
        }
        repo.create_branch("same-tip", &ours).unwrap();
        repo.switch_branch("same-tip").unwrap();
        let before = complete_repository_bytes(&repo);
        assert!(repo
            .merge_files_resolved_on_branch("main", &ours, &target, &valid, None, "wrong branch",)
            .unwrap_err()
            .contains("branch changed"));
        assert_eq!(complete_repository_bytes(&repo), before);
    }

    #[test]
    fn manual_tree_resolution_requires_one_common_base_and_verifies_dangling_history() {
        let temp = TempDirectory::new();
        let (repo, _, ours, target) = manual_tree_fixture(&temp, "unrelated");
        repo.switch_branch("theirs").unwrap();
        let unrelated = repo
            .commit_files_on_branch(
                &BTreeMap::new(),
                "unrelated root",
                &[],
                "theirs",
                Some(&target),
                None,
            )
            .unwrap();
        repo.switch_branch("main").unwrap();
        let before = complete_repository_bytes(&repo);
        assert!(repo
            .merge_files_resolved_on_branch(
                "main",
                &ours,
                &unrelated,
                &BTreeMap::new(),
                None,
                "no base",
            )
            .unwrap_err()
            .contains("no common merge base"));
        assert_eq!(complete_repository_bytes(&repo), before);

        let (repo, _, ours, target) = manual_tree_fixture(&temp, "criss-cross");
        let left = repo
            .commit_files_on_branch(
                &BTreeMap::new(),
                "left merge",
                &[ours.clone(), target.clone()],
                "main",
                Some(&ours),
                None,
            )
            .unwrap();
        repo.switch_branch("theirs").unwrap();
        let right = repo
            .commit_files_on_branch(
                &BTreeMap::new(),
                "right merge",
                &[target.clone(), ours],
                "theirs",
                Some(&target),
                None,
            )
            .unwrap();
        repo.switch_branch("main").unwrap();
        let before = complete_repository_bytes(&repo);
        assert!(repo
            .merge_files_resolved_on_branch(
                "main",
                &left,
                &right,
                &BTreeMap::new(),
                None,
                "ambiguous base",
            )
            .unwrap_err()
            .contains("multiple best merge bases"));
        assert_eq!(complete_repository_bytes(&repo), before);

        let (repo, _, ours, target) = manual_tree_fixture(&temp, "corrupt-dangling");
        let blob = repo.store_object(WASM_KIND, &wasm(&[])).unwrap();
        store_history_commit(&repo, &blob, &["a".repeat(64)], "missing parent");
        let before = complete_repository_bytes(&repo);
        assert!(repo
            .merge_files_resolved_on_branch(
                "main",
                &ours,
                &target,
                &BTreeMap::new(),
                None,
                "corrupt store",
            )
            .unwrap_err()
            .contains("parent"));
        assert_eq!(complete_repository_bytes(&repo), before);
    }

    #[test]
    fn manual_tree_resolution_legacy_mapping_is_explicit_and_empty_tree_is_real_deletion() {
        let temp = TempDirectory::new();
        let repo = temp.repo("mixed-resolution");
        let base = repo.commit(&function_wasm(1, 2), "legacy root").unwrap();
        let original_payload = repo.cat_object(&base).unwrap().1;
        repo.create_branch("theirs", "HEAD").unwrap();
        let ours = repo.commit(&function_wasm(11, 2), "legacy edit").unwrap();
        repo.switch_branch("theirs").unwrap();
        let target = commit_tree(
            &repo,
            &files(&[
                ("saved.wasm", function_wasm(1, 22)),
                ("added.wasm", wasm(&[])),
            ]),
            "upgrade",
            Some("saved.wasm"),
        );
        repo.switch_branch("main").unwrap();
        let before = complete_repository_bytes(&repo);
        for anchor in [None, Some("wrong.wasm"), Some("../invalid")] {
            assert!(repo
                .merge_files_resolved_on_branch(
                    "main",
                    &ours,
                    &target,
                    &BTreeMap::new(),
                    anchor,
                    "must not guess",
                )
                .is_err());
            assert_eq!(complete_repository_bytes(&repo), before);
        }
        let count = repo.fsck().unwrap().wasm_blobs;
        let outcome = repo
            .merge_files_resolved_on_branch(
                "main",
                &ours,
                &target,
                &BTreeMap::new(),
                Some("saved.wasm"),
                "delete every module",
            )
            .unwrap();
        let resolved = repo.files_at("HEAD").unwrap();
        assert!(resolved.files.is_empty() && resolved.legacy.is_none());
        assert_eq!(resolved.legacy_path.as_deref(), Some("saved.wasm"));
        assert_eq!(repo.fsck().unwrap().wasm_blobs, count);
        assert_eq!(repo.cat_object(&base).unwrap().1, original_payload);
        let report = outcome.tree_manual_resolution.unwrap();
        assert_eq!(report.files.len(), 2);
        assert!(report.files.iter().all(|file| file.resolved.is_none()));
        let saved = report
            .files
            .iter()
            .find(|file| file.path == "saved.wasm")
            .unwrap();
        assert!(saved.base.is_some() && saved.ours.is_some() && saved.theirs.is_some());
        assert_eq!(saved.from_ours.status, "deleted");
        assert_eq!(saved.from_theirs.status, "deleted");

        repo.create_branch("different-anchor", &base).unwrap();
        repo.switch_branch("different-anchor").unwrap();
        let different = commit_tree(
            &repo,
            &files(&[("other.wasm", wasm(&[]))]),
            "other anchor",
            Some("other.wasm"),
        );
        repo.switch_branch("main").unwrap();
        let ours = repo.resolve("HEAD").unwrap();
        let before = complete_repository_bytes(&repo);
        assert!(repo
            .merge_files_resolved_on_branch(
                "main",
                &ours,
                &different,
                &BTreeMap::new(),
                Some("saved.wasm"),
                "anchor conflict",
            )
            .is_err());
        assert_eq!(complete_repository_bytes(&repo), before);
    }

    #[test]
    fn tree_merge_conflicts_never_install_partial_clean_file_results() {
        let temp = TempDirectory::new();
        for mode in ["add-add", "delete-modify", "prefix"] {
            let repo = temp.repo(mode);
            let base = if mode == "delete-modify" {
                files(&[("same.wasm", wasm(&[]))])
            } else {
                BTreeMap::new()
            };
            commit_tree(&repo, &base, "base", None);
            repo.create_branch("theirs", "HEAD").unwrap();
            let ours = if mode == "delete-modify" {
                BTreeMap::new()
            } else if mode == "prefix" {
                files(&[("path", wasm(&[]))])
            } else {
                files(&[("same.wasm", wasm(&[99, 1, 0x42]))])
            };
            let ours_id = commit_tree(&repo, &ours, "ours", None);
            repo.switch_branch("theirs").unwrap();
            let theirs = if mode == "prefix" {
                files(&[("path/nested.wasm", wasm(&[]))])
            } else {
                files(&[
                    ("same.wasm", wasm(&[99, 1, 0x43])),
                    ("clean.wasm", wasm(&[])),
                ])
            };
            let target = commit_tree(&repo, &theirs, "theirs", None);
            repo.switch_branch("main").unwrap();
            let before = stored_state(&repo);
            let outcome = repo
                .merge_on_branch(&target, "must not publish", "main", Some(&ours_id))
                .unwrap();
            assert_eq!(outcome.status, "conflict", "{mode}");
            assert!(outcome
                .file_reports
                .iter()
                .any(|report| report.status == "conflict"));
            assert_eq!(stored_state(&repo), before);
        }
    }

    #[test]
    fn mixed_legacy_tree_merge_uses_only_saved_anchor_and_rejects_conflicting_anchors() {
        let temp = TempDirectory::new();
        let repo = temp.repo("mixed");
        let root = repo.commit(&function_wasm(1, 2), "legacy").unwrap();
        repo.create_branch("theirs", "HEAD").unwrap();
        let ours = repo.commit(&function_wasm(11, 2), "legacy edit").unwrap();
        repo.switch_branch("theirs").unwrap();
        let target = commit_tree(
            &repo,
            &files(&[
                ("saved.wasm", function_wasm(1, 22)),
                ("added.wasm", wasm(&[])),
            ]),
            "upgrade",
            Some("saved.wasm"),
        );
        repo.switch_branch("main").unwrap();
        assert_eq!(
            repo.merge_on_branch(&target, "mixed merge", "main", Some(&ours))
                .unwrap()
                .status,
            "merged"
        );
        assert_eq!(
            repo.files_at("HEAD").unwrap().files["saved.wasm"],
            function_wasm(11, 22)
        );
        assert_eq!(
            repo.files_at("HEAD").unwrap().legacy_path.as_deref(),
            Some("saved.wasm")
        );
        repo.create_branch("different-anchor", &root).unwrap();
        repo.switch_branch("different-anchor").unwrap();
        let different = commit_tree(
            &repo,
            &files(&[("other.wasm", function_wasm(1, 2))]),
            "different mapping",
            Some("other.wasm"),
        );
        repo.switch_branch("main").unwrap();
        let state = repo.state().unwrap();
        let before = stored_state(&repo);
        let outcome = repo
            .merge_on_branch(
                &different,
                "must not guess",
                "main",
                state.branches.get("main").map(String::as_str),
            )
            .unwrap();
        assert_eq!(outcome.status, "conflict");
        assert!(outcome.file_reports[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("legacy path"));
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn tree_replay_preflights_all_files_and_only_publishes_final_head() {
        let temp = TempDirectory::new();
        let repo = temp.repo("replay");
        let root = commit_tree(&repo, &BTreeMap::new(), "root", None);
        let before = stored_state(&repo);
        let valid = files(&[("one.wasm", wasm(&[]))]);
        let bad = files(&[("two.wasm", b"bad".to_vec())]);
        assert!(repo
            .replay_files_on_branch(
                "main",
                Some(&root),
                &root,
                &[(valid.clone(), "first".into()), (bad, "bad second".into())],
                None
            )
            .is_err());
        assert_eq!(stored_state(&repo), before);
        assert!(repo
            .replay_files_on_branch("main", Some(&root), &root, &[], None)
            .unwrap()
            .is_empty());
        assert_eq!(stored_state(&repo), before);
        let logs = repo.reflog().unwrap().len();
        let ids = repo
            .replay_files_on_branch(
                "main",
                Some(&root),
                &root,
                &[(valid, "first".into()), (BTreeMap::new(), "delete".into())],
                None,
            )
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(repo.resolve("HEAD").unwrap(), ids[1]);
        assert_eq!(
            repo.read_commit(&ids[1]).unwrap().commit.parents,
            vec![ids[0].clone()]
        );
        assert!(repo.files_at("HEAD").unwrap().files.is_empty());
        assert_eq!(repo.reflog().unwrap().len(), logs + 1);
    }

    #[test]
    fn selected_file_history_preserves_real_absence_boundaries_without_fake_blobs() {
        let temp = TempDirectory::new();
        let repo = temp.repo("history");
        let root = repo.commit(&wasm(&[]), "legacy").unwrap();
        let added = commit_tree(
            &repo,
            &files(&[("legacy.wasm", wasm(&[])), ("new.wasm", wasm(&[0, 1, 0]))]),
            "add new",
            Some("legacy.wasm"),
        );
        let deleted = commit_tree(
            &repo,
            &files(&[("legacy.wasm", wasm(&[]))]),
            "delete new",
            Some("legacy.wasm"),
        );
        let readded = commit_tree(
            &repo,
            &files(&[
                ("legacy.wasm", wasm(&[])),
                ("new.wasm", wasm(&[99, 1, 0x42])),
            ]),
            "re-add new",
            Some("legacy.wasm"),
        );
        let trace = read_file_history(&repo.root, "HEAD", "new.wasm").unwrap();
        assert_eq!(trace.history.tip, readded);
        assert_eq!(
            trace.absent,
            BTreeSet::from([root.clone(), deleted.clone()])
        );
        assert_eq!(trace.history.commits.len(), 4);
        assert!(trace.history.commits[&deleted].wasm.is_empty());
        assert_eq!(trace.history.commits[&deleted].parents, vec![added]);
        assert_eq!(trace.history.blobs.len(), 2);
        assert!(read_file_history(&repo.root, &deleted, "new.wasm").is_err());
        assert!(read_history(&repo.root, "HEAD").is_err());
        let selected = read_file_revisions(&repo.root, &[&root, "HEAD"]).unwrap();
        assert!(selected[0].legacy.is_some());
        assert_eq!(selected[1].files.len(), 2);
    }

    #[test]
    fn legacy_empty_tags_keep_manifest_encoding_and_object_ids_unchanged() {
        let temp = TempDirectory::new();
        let repo = temp.repo("legacy");
        fs::remove_dir(repo.metadata.join("tags")).unwrap();
        let reopened = Repository::open(&repo.root).unwrap();
        let empty = reopened.state().unwrap();
        assert_eq!(empty.format, 1);
        assert_eq!(empty.head, "main");
        assert!(empty.branches.is_empty());
        assert!(empty.tags.is_empty());
        let (_, bytes) = reopened.bundle_bytes(None).unwrap();
        let snapshot = decode_bundle(&bytes).unwrap();
        assert_eq!(snapshot.manifest.format, 1);
        assert_eq!(
            serde_json::to_vec(&snapshot.manifest).unwrap(),
            br#"{"format":1,"head":"main","refs":{}}"#
        );
        let id = reopened.commit(&wasm(&[]), "legacy root").unwrap();
        let commit = reopened.read_commit(&id).unwrap().commit;
        let expected = format!(
            r#"{{"format":1,"wasm":"{}","parents":[],"message":"legacy root"}}"#,
            commit.wasm
        );
        assert_eq!(
            reopened.cat_object(&id).unwrap(),
            ("commit".into(), expected.as_bytes().to_vec())
        );
        assert_eq!(
            reopened.cat_object(&commit.wasm).unwrap(),
            ("wasm".into(), wasm(&[]))
        );
        let expected_object = encode_object(COMMIT_KIND, expected.as_bytes()).unwrap();
        assert_eq!(id, object_id(&expected_object));
        assert!(!repo.metadata.join("tags").exists());
    }

    #[test]
    fn tags_preserve_otherwise_unreachable_history_in_bundles_clones_and_fsck() {
        let temp = TempDirectory::new();
        let repo = temp.repo("source");
        let main = repo.commit(&wasm(&[]), "main root").unwrap();
        let blob = repo.store_object(WASM_KIND, &wasm(&[99, 1, 0x42])).unwrap();
        let orphan = store_history_commit(&repo, &blob, &[], "tag-only root");
        assert_eq!(repo.fsck().unwrap().unreachable_objects, 2);
        assert_eq!(repo.create_tag("release", &orphan).unwrap(), orphan);
        assert_eq!(repo.fsck().unwrap().unreachable_objects, 0);
        assert_eq!(repo.fsck().unwrap().tags, 1);
        let (state, bytes) = repo.bundle_bytes(None).unwrap();
        assert_eq!(state.tags["release"], orphan);
        assert_eq!(decode_bundle(&bytes).unwrap().manifest.format, 2);
        assert_eq!(Repository::bundle_state(&bytes).unwrap(), state);
        for clone in [
            Repository::clone_local(&repo.root, temp.path("local-clone")).unwrap(),
            Repository::clone_bundle_bytes(&bytes, temp.path("bundle-clone")).unwrap(),
        ] {
            assert_eq!(clone.state().unwrap(), state);
            assert_eq!(clone.resolve("refs/tags/release").unwrap(), orphan);
            assert_eq!(clone.wasm_bytes("release").unwrap(), wasm(&[99, 1, 0x42]));
            assert_eq!(clone.resolve("HEAD").unwrap(), main);
            assert_eq!(clone.fsck().unwrap().unreachable_objects, 0);
        }
        assert_eq!(repo.delete_tag("release").unwrap(), orphan);
        assert_eq!(repo.fsck().unwrap().unreachable_objects, 2);
        let (_, no_tags) = repo.bundle_bytes(None).unwrap();
        assert_eq!(decode_bundle(&no_tags).unwrap().manifest.format, 1);
    }

    #[test]
    fn selected_transfer_has_exact_ancestor_closure_and_matching_tags() {
        let temp = TempDirectory::new();
        let repo = temp.repo("source");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let tip = repo.commit(&wasm(&[0, 1, 0]), "tip").unwrap();
        repo.create_branch("other", &root).unwrap();
        repo.switch_branch("other").unwrap();
        let other = repo.commit(&wasm(&[99, 1, 0x43]), "unselected").unwrap();
        repo.create_tag("selected", &root).unwrap();
        repo.create_tag("unselected", &other).unwrap();
        let (state, bytes) = repo.bundle_bytes(Some(&tip)).unwrap();
        assert_eq!(state.head, "transfer");
        assert_eq!(
            state.branches,
            BTreeMap::from([("transfer".into(), tip.clone())])
        );
        assert_eq!(
            state.tags,
            BTreeMap::from([("selected".into(), root.clone())])
        );
        let selected = decode_bundle(&bytes).unwrap();
        assert_eq!(selected.objects.len(), 4);
        assert!(selected.objects.contains_key(&root));
        assert!(selected.objects.contains_key(&tip));
        assert!(!selected.objects.contains_key(&other));
        let destination = temp.repo("fetch");
        let before = destination.state().unwrap();
        let log_before = destination.reflog().unwrap();
        assert_eq!(destination.install_bundle_bytes(&bytes).unwrap(), state);
        assert_eq!(destination.state().unwrap(), before);
        assert_eq!(destination.reflog().unwrap(), log_before);
        assert_eq!(destination.resolve(&tip).unwrap(), tip);
        assert!(destination.resolve("selected").is_err());
        assert_eq!(destination.fsck().unwrap().objects, 4);
    }

    #[test]
    fn receive_requires_exact_cas_and_fast_forward_before_any_installation() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let root = source.commit(&wasm(&[]), "root").unwrap();
        let (_, first) = source.bundle_bytes(Some("HEAD")).unwrap();
        let target = temp.repo("target");
        assert_eq!(
            target.receive_bundle(&first, "main", None, false).unwrap(),
            root
        );
        let tip = source.commit(&wasm(&[0, 1, 0]), "tip").unwrap();
        let (_, next) = source.bundle_bytes(Some("HEAD")).unwrap();
        let before = target.bundle_bytes(None).unwrap();
        let log_before = target.reflog().unwrap();
        assert!(target
            .receive_bundle(&next, "main", None, false)
            .unwrap_err()
            .contains("reference changed"));
        assert_eq!(target.bundle_bytes(None).unwrap(), before);
        assert_eq!(target.reflog().unwrap(), log_before);
        assert_eq!(
            target
                .receive_bundle(&next, "main", Some(&root), false)
                .unwrap(),
            tip
        );
        let before = target.bundle_bytes(None).unwrap();
        let log_before = target.reflog().unwrap();
        assert!(target
            .receive_bundle(&first, "main", Some(&tip), false)
            .unwrap_err()
            .contains("non-fast-forward"));
        assert_eq!(target.bundle_bytes(None).unwrap(), before);
        assert_eq!(target.reflog().unwrap(), log_before);
        assert_eq!(
            target
                .receive_bundle(&first, "main", Some(&tip), true)
                .unwrap(),
            root
        );
        let entry = target.reflog().unwrap().pop().unwrap();
        assert_eq!(entry.old.as_deref(), Some(tip.as_str()));
        assert_eq!(entry.new.as_deref(), Some(root.as_str()));
        assert_eq!(entry.operation, "receive-force");
    }

    #[test]
    fn checked_receive_rejections_are_known_before_ref_publication() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let root = source.commit(&wasm(&[]), "root").unwrap();
        let (_, bundle) = source.bundle_bytes(Some("HEAD")).unwrap();
        let target = temp.repo("target");
        let before = stored_state(&target);
        let malformed = target
            .receive_bundle_checked(b"not a bundle", "main", None, false)
            .unwrap_err();
        assert!(!malformed.publication_unknown);
        assert_eq!(stored_state(&target), before);
        let missing = target
            .receive_ref_bundle_checked(&bundle, "tag", "v1", Some(&root), Some(&root), false)
            .unwrap_err();
        assert!(!missing.publication_unknown);
        assert!(missing.message.contains("reference changed"));
        assert_eq!(stored_state(&target), before);
        target
            .receive_bundle_checked(&bundle, "main", None, false)
            .unwrap();
        let before = stored_state(&target);
        let stale = target
            .receive_bundle_checked(&bundle, "main", None, false)
            .unwrap_err();
        assert!(!stale.publication_unknown);
        assert_eq!(stored_state(&target), before);
        let delete_head = target
            .receive_ref_bundle_checked(&[], "branch", "main", Some(&root), None, false)
            .unwrap_err();
        assert!(!delete_head.publication_unknown);
        assert_eq!(stored_state(&target), before);
    }

    #[test]
    fn receive_phase_mapping_marks_injected_error_after_real_publication_unknown() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let child = repo.commit(&wasm(&[0, 1, 0]), "child").unwrap();
        let _lock = repo.lock().unwrap();
        // This is a phase-mapping fixture, not a claim that an fsync fault was
        // reproduced. It publishes the real ref before injecting a later error.
        let result: RepositoryResult<()> = (|| {
            repo.write_named_ref("refs", "main", &root, "phase fixture")?;
            assert_eq!(
                repo.read_ref_optional("main").unwrap().as_deref(),
                Some(root.as_str())
            );
            Err("injected error after publication".into())
        })();
        let error = receive_result(result, true).unwrap_err();
        assert!(error.publication_unknown);
        assert_eq!(error.message, "injected error after publication");
        assert_eq!(
            repo.read_ref_optional("main").unwrap().as_deref(),
            Some(root.as_str())
        );
        assert_ne!(
            repo.read_ref_optional("main").unwrap().as_deref(),
            Some(child.as_str())
        );
        let preflight =
            receive_result::<()>(Err("published is only human text here".into()), false)
                .unwrap_err();
        assert!(!preflight.publication_unknown);
    }

    #[test]
    fn remote_tag_replacement_and_ref_deletion_require_exact_leases() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let root = source.commit(&wasm(&[]), "root").unwrap();
        let (_, first) = source.bundle_bytes(Some("HEAD")).unwrap();
        let tip = source.commit(&wasm(&[0, 1, 0]), "tip").unwrap();
        let (_, next) = source.bundle_bytes(Some("HEAD")).unwrap();
        let target = temp.repo("target");
        assert_eq!(
            target
                .receive_ref_bundle(&first, "tag", "v1", None, Some(&root), false)
                .unwrap(),
            Some(root.clone())
        );
        let before = stored_state(&target);
        assert!(target
            .receive_ref_bundle(&next, "tag", "v1", Some(&root), Some(&tip), false)
            .unwrap_err()
            .contains("replace tag"));
        assert!(target
            .receive_ref_bundle(&next, "tag", "v1", None, Some(&tip), true)
            .is_err());
        assert!(target
            .receive_ref_bundle(&[], "tag", "v1", Some(&tip), None, false)
            .is_err());
        assert!(target
            .receive_ref_bundle(&first, "tag", "v1", Some(&root), None, false)
            .is_err());
        assert_eq!(stored_state(&target), before);
        assert_eq!(
            target
                .receive_ref_bundle(&next, "tag", "v1", Some(&root), Some(&tip), true)
                .unwrap(),
            Some(tip.clone())
        );
        assert_eq!(target.resolve("refs/tags/v1").unwrap(), tip);
        let objects = target.fsck().unwrap().objects;
        assert_eq!(
            target
                .receive_ref_bundle(&[], "tag", "v1", Some(&tip), None, false)
                .unwrap(),
            None
        );
        assert_eq!(target.fsck().unwrap().objects, objects);
        target.receive_bundle(&first, "main", None, false).unwrap();
        target.receive_bundle(&first, "topic", None, false).unwrap();
        let before = stored_state(&target);
        assert!(target
            .receive_ref_bundle(&[], "branch", "main", Some(&root), None, true)
            .unwrap_err()
            .contains("checked-out"));
        assert_eq!(stored_state(&target), before);
        target
            .receive_ref_bundle(&[], "branch", "topic", Some(&root), None, false)
            .unwrap();
        assert!(!target.branches().unwrap().contains_key("topic"));
        assert_eq!(target.resolve(&tip).unwrap(), tip);
    }

    #[test]
    fn transfer_rejects_bad_input_before_clone_or_local_store_mutation() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        source.commit(&wasm(&[]), "root").unwrap();
        let (_, bytes) = source.bundle_bytes(None).unwrap();
        let mut bad = bytes.clone();
        bad.push(0);
        let destination = temp.path("must-not-exist");
        assert!(Repository::clone_bundle_bytes(&bad, &destination).is_err());
        assert!(!destination.exists());
        let target = temp.repo("target");
        let before = stored_state(&target);
        assert!(Repository::bundle_state(&bad).is_err());
        assert!(target.install_bundle_bytes(&bad).is_err());
        assert!(target.receive_bundle(&bad, "main", None, false).is_err());
        assert_eq!(stored_state(&target), before);
        let dangling = target.store_object(WASM_KIND, &wasm(&[0, 1, 0])).unwrap();
        fs::write(
            target.metadata.join("objects").join(&dangling),
            b"corrupted",
        )
        .unwrap();
        let before = stored_state(&target);
        assert!(target.install_bundle_bytes(&bytes).is_err());
        assert!(target.receive_bundle(&bytes, "main", None, false).is_err());
        assert_eq!(stored_state(&target), before);
    }

    #[test]
    fn revision_syntax_follows_ordered_parents_and_ref_ambiguity_is_explicit() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let blob = repo.read_commit_id(&root).unwrap().wasm;
        let left = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "left");
        let right = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "right");
        let merged = repo
            .commit_explicit(
                &wasm(&[]),
                "merge",
                &[left.clone(), right.clone()],
                Some(&root),
            )
            .unwrap();
        for (revision, expected) in [
            ("HEAD^0", &merged),
            ("HEAD~0", &merged),
            ("HEAD^", &left),
            ("HEAD^2", &right),
            ("HEAD~2", &root),
            ("HEAD^2~", &root),
            ("HEAD^1^1", &root),
        ] {
            assert_eq!(repo.resolve(revision).unwrap(), *expected);
        }
        for revision in [
            "HEAD^3",
            "HEAD~3",
            "HEAD~-1",
            "HEAD^1x",
            "HEAD~184467440737095516160",
        ] {
            assert!(repo.resolve(revision).is_err(), "{revision}");
        }
        assert_eq!(repo.resolve(&merged[..4]).unwrap(), merged);
        repo.create_branch("shared", &root).unwrap();
        repo.create_tag("shared", &root).unwrap();
        assert!(repo.resolve("shared").unwrap_err().contains("ambiguous"));
        assert_eq!(repo.resolve("refs/heads/shared").unwrap(), root);
        assert_eq!(repo.resolve("refs/tags/shared").unwrap(), root);
        repo.create_branch(&merged[..4], "HEAD").unwrap();
        assert!(repo
            .resolve(&merged[..4])
            .unwrap_err()
            .contains("ambiguous"));
    }

    #[test]
    fn explicit_commits_and_resets_compare_head_and_keep_selected_parents() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit_explicit(&wasm(&[]), "root", &[], None).unwrap();
        let child = repo.commit(&wasm(&[0, 1, 0]), "child").unwrap();
        let before = repo.bundle_bytes(None).unwrap();
        let log_before = repo.reflog().unwrap();
        assert!(repo.reset_head(&root, None).is_err());
        assert!(repo.reset_head(&root, Some(&root)).is_err());
        assert!(repo
            .commit_explicit(&wasm(&[99, 1, 0x42]), "stale", &[], Some(&root))
            .is_err());
        assert!(repo
            .commit_explicit(&wasm(&[]), "missing", &["a".repeat(64)], Some(&child))
            .is_err());
        assert!(repo
            .commit_explicit(
                &wasm(&[]),
                "duplicate",
                &[root.clone(), root.clone()],
                Some(&child)
            )
            .is_err());
        assert_eq!(repo.bundle_bytes(None).unwrap(), before);
        assert_eq!(repo.reflog().unwrap(), log_before);
        let rewritten = repo
            .commit_explicit(
                &wasm(&[99, 1, 0x42]),
                "amend",
                std::slice::from_ref(&root),
                Some(&child),
            )
            .unwrap();
        assert_eq!(
            repo.read_commit(&rewritten).unwrap().commit.parents,
            vec![root.clone()]
        );
        assert_eq!(repo.wasm_bytes(&rewritten).unwrap(), wasm(&[99, 1, 0x42]));
        assert_eq!(repo.reset_head(&root, Some(&rewritten)).unwrap(), root);
        assert_eq!(repo.resolve("HEAD").unwrap(), root);
        assert_eq!(repo.resolve(&child).unwrap(), child);
    }

    #[test]
    fn branch_and_tip_cas_rejects_switch_to_another_branch_with_the_same_commit() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_branch("same-tip", "HEAD").unwrap();
        repo.switch_branch("same-tip").unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .reset_on_branch(&root, "main", Some(&root))
            .unwrap_err()
            .contains("branch changed"));
        assert!(repo
            .commit_on_branch(
                &wasm(&[0, 1, 0]),
                "must reject",
                std::slice::from_ref(&root),
                "main",
                Some(&root)
            )
            .unwrap_err()
            .contains("branch changed"));
        assert!(repo
            .replay_on_branch(
                "main",
                Some(&root),
                &root,
                &[(wasm(&[0, 1, 0]), "must reject".into())]
            )
            .unwrap_err()
            .contains("branch changed"));
        assert_eq!(stored_state(&repo), before);
        let child = repo
            .commit_on_branch(
                &wasm(&[0, 1, 0]),
                "correct branch",
                std::slice::from_ref(&root),
                "same-tip",
                Some(&root),
            )
            .unwrap();
        assert_eq!(repo.resolve("refs/heads/main").unwrap(), root);
        assert_eq!(repo.resolve("HEAD").unwrap(), child);
        assert_eq!(
            repo.reset_on_branch(&root, "same-tip", Some(&child))
                .unwrap(),
            root
        );
    }

    #[test]
    fn receive_holds_worktree_lock_and_refuses_to_move_a_tracked_current_branch() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let root = source.commit(&wasm(&[]), "root").unwrap();
        let (_, bundle) = source.bundle_bytes(Some("HEAD")).unwrap();
        let target = temp.repo("target");
        fs::write(target.metadata.join("index"), b"tracked worktree marker").unwrap();
        let before = stored_state(&target);
        assert!(target
            .receive_bundle(&bundle, "main", None, false)
            .unwrap_err()
            .contains("tracked worktree"));
        assert_eq!(stored_state(&target), before);
        assert_eq!(
            target
                .receive_bundle(&bundle, "other", None, false)
                .unwrap(),
            root
        );
        assert!(!target.state().unwrap().branches.contains_key("main"));
        let index_lock = target.lock_named("index.lock").unwrap();
        let before = stored_state(&target);
        assert!(target
            .receive_ref_bundle(&bundle, "tag", "v1", None, Some(&root), false)
            .unwrap_err()
            .contains("locked"));
        assert_eq!(stored_state(&target), before);
        drop(index_lock);
        assert!(!target.metadata.join("index.lock").exists());
    }

    #[test]
    fn replay_preflights_the_whole_chain_then_publishes_only_its_final_tip() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let old_tip = repo.commit(&wasm(&[0, 1, 0]), "old tip").unwrap();
        let before = stored_state(&repo);
        assert!(repo.replay_commits(Some(&root), &root, &[]).is_err());
        assert!(repo.replay_commits(Some(&old_tip), "unknown", &[]).is_err());
        assert!(repo
            .replay_commits(
                Some(&old_tip),
                &root,
                &[
                    (wasm(&[99, 1, 0x42]), "valid first".into()),
                    (b"bad header".to_vec(), "invalid second".into())
                ]
            )
            .is_err());
        assert_eq!(stored_state(&repo), before);
        assert!(repo
            .replay_commits(Some(&old_tip), &root, &[])
            .unwrap()
            .is_empty());
        assert_eq!(stored_state(&repo), before);
        let logs_before = repo.reflog().unwrap().len();
        let replay = repo
            .replay_commits(
                Some(&old_tip),
                &root,
                &[
                    (wasm(&[99, 1, 0x42]), "first".into()),
                    (wasm(&[99, 1, 0x43]), "second".into()),
                ],
            )
            .unwrap();
        assert_eq!(replay.len(), 2);
        assert_eq!(
            repo.read_commit(&replay[0]).unwrap().commit.parents,
            vec![root]
        );
        assert_eq!(
            repo.read_commit(&replay[1]).unwrap().commit.parents,
            vec![replay[0].clone()]
        );
        assert_eq!(repo.resolve("HEAD").unwrap(), replay[1]);
        assert_eq!(repo.resolve(&old_tip).unwrap(), old_tip);
        let logs = repo.reflog().unwrap();
        assert_eq!(logs.len(), logs_before + 1);
        assert_eq!(logs.last().unwrap().operation, "replay");
        assert_eq!(logs.last().unwrap().old.as_deref(), Some(old_tip.as_str()));
        assert_eq!(
            logs.last().unwrap().new.as_deref(),
            Some(replay[1].as_str())
        );
    }

    #[test]
    fn legacy_replay_interruption_at_every_install_prefix_leaves_a_valid_unpublished_graph() {
        let temp = TempDirectory::new();
        let fixture = temp.repo("fixture");
        let root = fixture.commit(&wasm(&[]), "root").unwrap();
        let replay: Vec<(Vec<u8>, String)> = vec![
            (wasm(&[99, 1, 0x42]), "first replay step".into()),
            (wasm(&[99, 1, 0x43]), "second replay step".into()),
        ];
        let mut encoded = BTreeMap::new();
        let mut ids = Vec::new();
        let mut parent = root.clone();
        for (bytes, message) in &replay {
            let blob = encode_object(WASM_KIND, bytes).unwrap();
            let wasm = object_id(&blob);
            encoded.insert(wasm.clone(), blob);
            let commit = Commit {
                format: 1,
                wasm,
                parents: vec![parent],
                message: message.clone(),
                tree: None,
                legacy_path: None,
            };
            let commit = encode_object(COMMIT_KIND, &encode_commit(&commit).unwrap()).unwrap();
            parent = object_id(&commit);
            encoded.insert(parent.clone(), commit);
            ids.push(parent.clone());
        }
        // This fixed chain must expose the original bug: at least one prefix
        // of plain hash order has an incomplete closure, despite valid inputs.
        let mut hash_prefix = fixture.snapshot().unwrap().objects;
        assert!(encoded.iter().any(|(id, bytes)| {
            hash_prefix.insert(id.clone(), decode_object(id, bytes).unwrap());
            validate_object_graph(&hash_prefix).is_err()
        }));

        // Interrupt each real-store installation boundary. Inspecting the full
        // verified snapshot, rather than checking an ordering list, proves
        // dangling objects are readable complete closures at every prefix.
        for interrupt_after in 1..=encoded.len() {
            let repo = temp.repo(&format!("interrupted-{interrupt_after}"));
            assert_eq!(repo.commit(&wasm(&[]), "root").unwrap(), root);
            let reflog = fs::read(repo.metadata.join("reflog")).unwrap();
            let mut installed = 0;
            let failure = install_dependency_ordered(&encoded, &ids, |id, bytes| {
                repo.install_encoded_object(id, bytes)?;
                installed += 1;
                let snapshot = repo.snapshot().unwrap();
                assert_eq!(snapshot.manifest.head, "main");
                assert_eq!(snapshot.manifest.refs["main"], root);
                assert_eq!(fs::read(repo.metadata.join("reflog")).unwrap(), reflog);
                if installed == interrupt_after {
                    Err("fixed I/O interruption after object installation".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(failure, "fixed I/O interruption after object installation");
            assert_eq!(installed, interrupt_after);
            assert_eq!(repo.resolve("HEAD").unwrap(), root);
            assert_eq!(repo.fsck().unwrap().unreachable_objects, interrupt_after);
            assert_eq!(fs::read(repo.metadata.join("reflog")).unwrap(), reflog);
        }

        let repo = temp.repo("complete");
        assert_eq!(repo.commit(&wasm(&[]), "root").unwrap(), root);
        let reflog_entries = repo.reflog().unwrap().len();
        assert_eq!(
            repo.replay_on_branch("main", Some(&root), &root, &replay)
                .unwrap(),
            ids
        );
        assert_eq!(repo.resolve("HEAD").unwrap(), parent);
        assert_eq!(repo.fsck().unwrap().unreachable_objects, 0);
        assert_eq!(repo.reflog().unwrap().len(), reflog_entries + 1);
    }

    #[test]
    fn complete_snapshot_install_prefixes_are_valid_and_public_import_retries_preserve_all_objects()
    {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let root = source.commit(&wasm(&[]), "root").unwrap();
        let legacy = source
            .commit(&wasm(&[99, 1, 0x42]), "first replay step")
            .unwrap();
        let tip = commit_tree(
            &source,
            &files(&[
                ("legacy.wasm", wasm(&[99, 1, 0x42])),
                ("dir/extra.wasm", wasm(&[99, 1, 0x43])),
            ]),
            "tree upgrade",
            Some("legacy.wasm"),
        );
        source.create_branch("temporary", &legacy).unwrap();
        source.switch_branch("temporary").unwrap();
        let dangling = commit_tree(
            &source,
            &files(&[
                ("legacy.wasm", wasm(&[99, 1, 0x44])),
                ("orphan.wasm", wasm(&[99, 1, 0x45])),
            ]),
            "unreachable complete tree",
            Some("legacy.wasm"),
        );
        source.switch_branch("main").unwrap();
        source.delete_branch("temporary", true).unwrap();
        let (advertised, bundle) = source.bundle_bytes(None).unwrap();
        let incoming = decode_bundle(&bundle).unwrap();
        let order = validated_commit_order(&incoming.objects).unwrap();
        assert!(order.contains(&dangling));
        assert!(!reachable_objects(&incoming.manifest, &incoming.objects)
            .unwrap()
            .contains(&dangling));
        let bundle_path = temp.path("complete.bundle");
        source.export_bundle(&bundle_path).unwrap();
        assert_eq!(fs::read(&bundle_path).unwrap(), bundle);

        // This fixed full bundle includes the same hash-order counterexample
        // as legacy replay, plus tree dependencies and an unreferenced history.
        let initial = temp.repo("initial");
        assert_eq!(initial.commit(&wasm(&[]), "root").unwrap(), root);
        let mut hash_prefix = initial.snapshot().unwrap().objects;
        assert!(incoming.encoded.iter().any(|(id, bytes)| {
            hash_prefix.insert(id.clone(), decode_object(id, bytes).unwrap());
            validate_object_graph(&hash_prefix).is_err()
        }));

        for mode in ["unbundle", "fetch-install", "receive"] {
            for interrupt_after in 1..=incoming.encoded.len() {
                let repo = temp.repo(&format!("{mode}-{interrupt_after}"));
                assert_eq!(repo.commit(&wasm(&[]), "root").unwrap(), root);
                let before = repo.state().unwrap();
                let reflog = fs::read(repo.metadata.join("reflog")).unwrap();
                let mut installed = 0;
                let failure = install_dependency_ordered(&incoming.encoded, &order, |id, bytes| {
                    repo.install_encoded_object(id, bytes)?;
                    installed += 1;
                    // This is the actual store after each complete object
                    // publication, not an assertion about a generated order.
                    assert_eq!(repo.state().unwrap(), before);
                    assert_eq!(fs::read(repo.metadata.join("reflog")).unwrap(), reflog);
                    repo.fsck().unwrap();
                    if installed == interrupt_after {
                        Err("fixed snapshot-install I/O interruption".into())
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
                assert_eq!(failure, "fixed snapshot-install I/O interruption");
                assert_eq!(installed, interrupt_after);
                assert_eq!(repo.resolve("HEAD").unwrap(), root);
                assert_eq!(fs::read(repo.metadata.join("reflog")).unwrap(), reflog);

                // Retrying through the real public operation must get past
                // full local validation and install every object, including
                // the dangling branch that no advertised ref can reach.
                match mode {
                    "unbundle" => {
                        assert_eq!(repo.import_bundle(&bundle_path, "main").unwrap(), tip)
                    }
                    "fetch-install" => {
                        assert_eq!(repo.install_bundle_bytes(&bundle).unwrap(), advertised)
                    }
                    "receive" => assert_eq!(
                        repo.receive_bundle_checked(&bundle, "main", Some(&root), false)
                            .unwrap(),
                        tip
                    ),
                    _ => unreachable!(),
                }
                assert_eq!(repo.snapshot().unwrap().encoded, incoming.encoded);
                assert_eq!(
                    repo.fsck().unwrap().unreachable_objects,
                    if mode == "fetch-install" {
                        incoming.objects.len() - 2
                    } else {
                        source.fsck().unwrap().unreachable_objects
                    }
                );
                if mode == "fetch-install" {
                    assert_eq!(repo.state().unwrap(), before);
                    assert_eq!(fs::read(repo.metadata.join("reflog")).unwrap(), reflog);
                } else {
                    assert_eq!(repo.resolve("HEAD").unwrap(), tip);
                    let log = repo.reflog().unwrap();
                    assert_eq!(log.len(), 2);
                    assert_eq!(log[1].old.as_deref(), Some(root.as_str()));
                    assert_eq!(log[1].new.as_deref(), Some(tip.as_str()));
                }
            }
        }
        for clone in [
            Repository::clone_local(&source.root, temp.path("local-clone")).unwrap(),
            Repository::clone_bundle_bytes(&bundle, temp.path("bundle-clone")).unwrap(),
        ] {
            assert_eq!(clone.snapshot().unwrap().encoded, incoming.encoded);
            assert_eq!(clone.state().unwrap(), advertised);
            assert_eq!(
                clone.fsck().unwrap().unreachable_objects,
                source.fsck().unwrap().unreachable_objects
            );
        }
    }

    #[test]
    fn upstream_configuration_is_canonical_local_only_and_excluded_from_both_clone_routes() {
        let temp = TempDirectory::new();
        let repo = temp.repo("upstream-source");
        let tip = repo.commit(&wasm(&[]), "root").unwrap();
        let before_bundle = repo.bundle_bytes(None).unwrap();
        let before_log = repo.reflog().unwrap();
        let before_ids = repo.snapshot().unwrap().encoded;
        assert!(repo.upstreams().unwrap().is_empty());
        let binding = repo
            .set_upstream_checked("main", "origin", "trunk", &tip, None)
            .unwrap();
        assert_eq!(
            binding,
            Upstream {
                remote: "origin".into(),
                branch: "trunk".into()
            }
        );
        assert_eq!(
            fs::read(repo.metadata.join("upstreams.json")).unwrap(),
            br#"{"version":1,"branches":{"main":{"remote":"origin","branch":"trunk"}}}"#
        );
        let (state, associations) = repo.state_with_upstreams().unwrap();
        assert_eq!(state.branches["main"], tip);
        assert_eq!(associations["main"], binding);
        assert_eq!(repo.upstream("main").unwrap(), Some(binding.clone()));
        assert_eq!(repo.bundle_bytes(None).unwrap(), before_bundle);
        assert_eq!(repo.reflog().unwrap(), before_log);
        assert_eq!(repo.snapshot().unwrap().encoded, before_ids);
        let clone = Repository::clone_local(&repo.root, temp.path("upstream-local-clone")).unwrap();
        let bundle_clone =
            Repository::clone_bundle_bytes(&before_bundle.1, temp.path("upstream-bundle-clone"))
                .unwrap();
        for cloned in [&clone, &bundle_clone] {
            assert_eq!(cloned.resolve("HEAD").unwrap(), tip);
            assert!(cloned.upstreams().unwrap().is_empty());
            assert!(!cloned.metadata.join("upstreams.json").exists());
        }
        assert_eq!(
            repo.unset_upstream_checked("main", &tip, &binding).unwrap(),
            binding
        );
        assert!(repo.upstreams().unwrap().is_empty());
        assert_eq!(
            fs::read(repo.metadata.join("upstreams.json")).unwrap(),
            br#"{"version":1,"branches":{}}"#
        );
        assert_eq!(repo.bundle_bytes(None).unwrap(), before_bundle);
    }

    #[test]
    fn upstream_leases_check_named_tip_and_original_binding_without_requiring_current_head() {
        let temp = TempDirectory::new();
        let repo = temp.repo("upstream-leases");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_branch("topic", "HEAD").unwrap();
        let first = repo
            .set_upstream_checked("topic", "origin", "main", &root, None)
            .unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .set_upstream_checked("topic", "other", "trunk", &root, None)
            .is_err());
        assert_eq!(stored_state(&repo), before);
        let changed = repo
            .set_upstream_checked("topic", "other", "trunk", &root, Some(&first))
            .unwrap();
        assert_eq!(repo.current_branch().unwrap(), "main");
        let before = stored_state(&repo);
        assert!(repo
            .set_upstream_checked("topic", "origin", "main", &root, Some(&first))
            .is_err());
        assert!(repo.unset_upstream_checked("topic", &root, &first).is_err());
        assert_eq!(stored_state(&repo), before);
        repo.switch_branch("topic").unwrap();
        let next = repo.commit(&wasm(&[0, 1, 0]), "next").unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .set_upstream_checked("topic", "origin", "main", &root, Some(&changed))
            .is_err());
        assert!(repo
            .unset_upstream_checked("topic", &root, &changed)
            .is_err());
        assert_eq!(stored_state(&repo), before);
        assert_eq!(
            repo.unset_upstream_checked("topic", &next, &changed)
                .unwrap(),
            changed
        );
        let before = stored_state(&repo);
        assert!(repo.unset_upstream("topic").is_err());
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn upstream_rejects_unborn_unknown_and_invalid_names_before_publication() {
        let temp = TempDirectory::new();
        let unborn = temp.repo("upstream-unborn");
        let before = stored_state(&unborn);
        assert_eq!(unborn.upstream("main").unwrap(), None);
        assert!(unborn
            .set_upstream_on_branch("main", "origin", "main", &"a".repeat(64))
            .is_err());
        assert_eq!(stored_state(&unborn), before);
        let repo = temp.repo("upstream-names");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let before = stored_state(&repo);
        for (local, remote, branch, tip) in [
            ("missing", "origin", "main", root.as_str()),
            ("main", "bad.remote", "main", root.as_str()),
            ("main", "../origin", "main", root.as_str()),
            ("main", "origin", "HEAD", root.as_str()),
            ("main", "origin", "topic/../nested", root.as_str()),
            ("main", "origin", "topic.lock", root.as_str()),
            ("main", "origin", "main", "HEAD"),
        ] {
            assert!(repo
                .set_upstream_on_branch(local, remote, branch, tip)
                .is_err());
            assert_eq!(stored_state(&repo), before);
        }
        assert!(repo.upstream("missing").is_err());
        assert!(repo
            .set_upstream_on_branch("main", &"x".repeat(65), "main", &root)
            .is_err());
        assert!(repo
            .set_upstream_on_branch("main", "origin", &"x".repeat(129), &root)
            .is_err());
        assert!(repo
            .set_upstream_on_branch("main", "origin", &"a".repeat(64), &root)
            .is_err());
        assert_eq!(stored_state(&repo), before);
        let _lock = repo.lock().unwrap();
        assert!(repo
            .set_upstream_checked("main", "origin", "main", &root, None)
            .unwrap_err()
            .contains("locked"));
        assert!(!repo.metadata.join("upstreams.json").exists());
    }

    #[test]
    fn upstream_branch_lifecycle_moves_bindings_and_clears_them_before_name_reuse() {
        let temp = TempDirectory::new();
        let repo = temp.repo("upstream-lifecycle");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_branch("topic", "HEAD").unwrap();
        let main = repo
            .set_upstream_on_branch("main", "origin", "main", &root)
            .unwrap();
        let topic = repo
            .set_upstream_on_branch("topic", "backup", "trunk", &root)
            .unwrap();
        let before = stored_state(&repo);
        assert!(repo.delete_branch("main", true).is_err());
        assert!(repo.rename_branch("main", "topic").is_err());
        assert_eq!(stored_state(&repo), before);
        repo.rename_branch("main", "trunk").unwrap();
        assert_eq!(repo.current_branch().unwrap(), "trunk");
        assert_eq!(repo.upstream("trunk").unwrap(), Some(main));
        assert!(!repo.upstreams().unwrap().contains_key("main"));
        repo.rename_branch("topic", "renamed").unwrap();
        assert_eq!(repo.upstream("renamed").unwrap(), Some(topic));
        assert!(!repo.upstreams().unwrap().contains_key("topic"));
        repo.delete_branch("renamed", false).unwrap();
        repo.create_branch("renamed", &root).unwrap();
        assert_eq!(repo.upstream("renamed").unwrap(), None);
        assert_eq!(repo.upstreams().unwrap().len(), 1);
        repo.fsck().unwrap();
    }

    #[test]
    fn server_branch_deletion_also_clears_local_upstream_and_leaves_a_valid_store() {
        let temp = TempDirectory::new();
        let repo = temp.repo("upstream-receive-delete");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_branch("topic", "HEAD").unwrap();
        repo.set_upstream_on_branch("topic", "origin", "main", &root)
            .unwrap();
        assert_eq!(
            repo.receive_ref_bundle_checked(&[], "branch", "topic", Some(&root), None, false)
                .unwrap(),
            None
        );
        assert!(!repo.state().unwrap().branches.contains_key("topic"));
        assert!(repo.upstreams().unwrap().is_empty());
        repo.fsck().unwrap();
        repo.create_branch("topic", &root).unwrap();
        assert_eq!(repo.upstream("topic").unwrap(), None);
    }

    #[test]
    fn upstream_remote_lifecycle_changes_only_matching_local_configuration() {
        let temp = TempDirectory::new();
        let repo = temp.repo("upstream-remotes");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_branch("topic", "HEAD").unwrap();
        repo.create_branch("other", "HEAD").unwrap();
        repo.set_upstream_on_branch("main", "origin", "main", &root)
            .unwrap();
        repo.set_upstream_on_branch("topic", "origin", "trunk", &root)
            .unwrap();
        let unrelated = repo
            .set_upstream_on_branch("other", "backup", "main", &root)
            .unwrap();
        let bundle = repo.bundle_bytes(None).unwrap();
        let logs = repo.reflog().unwrap();
        assert_eq!(
            repo.rename_upstream_remote("origin", "upstream").unwrap(),
            2
        );
        let associations = repo.upstreams().unwrap();
        assert_eq!(associations["main"].remote, "upstream");
        assert_eq!(associations["topic"].branch, "trunk");
        assert_eq!(associations["other"], unrelated);
        let before = stored_state(&repo);
        assert_eq!(
            repo.rename_upstream_remote("missing", "elsewhere").unwrap(),
            0
        );
        assert_eq!(repo.remove_upstream_remote("missing").unwrap(), 0);
        assert!(repo.rename_upstream_remote("upstream", "upstream").is_err());
        assert!(repo.remove_upstream_remote("bad.remote").is_err());
        assert_eq!(stored_state(&repo), before);
        assert_eq!(repo.remove_upstream_remote("upstream").unwrap(), 2);
        assert_eq!(
            repo.upstreams().unwrap(),
            BTreeMap::from([("other".into(), unrelated)])
        );
        assert_eq!(repo.bundle_bytes(None).unwrap(), bundle);
        assert_eq!(repo.reflog().unwrap(), logs);
    }

    #[test]
    fn corrupt_or_noncanonical_upstreams_reject_mutations_and_receive_before_objects_are_installed()
    {
        let temp = TempDirectory::new();
        let repo = temp.repo("upstream-corrupt");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_branch("topic", "HEAD").unwrap();
        let producer = temp.repo("upstream-producer");
        let incoming_tip = producer.commit(&wasm(&[0, 1, 0]), "incoming").unwrap();
        let incoming = producer.bundle_bytes(None).unwrap().1;
        let path = repo.metadata.join("upstreams.json");
        let cases = [
            br#"{"version":2,"branches":{}}"#.as_slice(),
            br#"{"version":1,"branches":{},"extra":true}"#.as_slice(),
            br#"{ "version":1,"branches":{}}"#.as_slice(),
            br#"{"version":1,"branches":{"main":{"remote":"origin","branch":"main","extra":true}}}"#.as_slice(),
            br#"{"version":1,"branches":{"main":{"remote":"origin","branch":"main"},"main":{"remote":"other","branch":"main"}}}"#.as_slice(),
            br#"{"version":1,"branches":{"missing":{"remote":"origin","branch":"main"}}}"#.as_slice(),
            br#"{"version":1,"branches":{"main":{"remote":"bad.remote","branch":"main"}}}"#.as_slice(),
            br#"{"version":1,"branches":{"main":{"remote":"origin","branch":"HEAD"}}}"#.as_slice(),
        ];
        for bytes in cases {
            fs::write(&path, bytes).unwrap();
            let before = stored_state(&repo);
            assert!(repo.state().is_err());
            assert!(repo.commit(&wasm(&[0, 1, 1]), "must not publish").is_err());
            assert!(repo.rename_branch("main", "trunk").is_err());
            assert!(repo.delete_branch("topic", true).is_err());
            assert!(repo
                .set_upstream_on_branch("main", "origin", "main", &root)
                .is_err());
            let error = repo
                .receive_ref_bundle_checked(
                    &incoming,
                    "branch",
                    "new",
                    None,
                    Some(&incoming_tip),
                    false,
                )
                .unwrap_err();
            assert!(!error.publication_unknown);
            assert_eq!(stored_state(&repo), before);
        }
        fs::write(&path, vec![b' '; MAX_UPSTREAM_BYTES as usize + 1]).unwrap();
        let before = stored_state(&repo);
        assert!(repo.upstreams().unwrap_err().contains("1 MiB"));
        assert!(repo.commit(&wasm(&[0, 1, 1]), "must not publish").is_err());
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn upstream_atomic_write_io_failure_does_not_claim_rollback_or_modify_refs() {
        let temp = TempDirectory::new();
        let repo = temp.repo("upstream-io");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let first = repo
            .set_upstream_on_branch("main", "origin", "main", &root)
            .unwrap();
        fs::remove_dir(repo.metadata.join("tmp")).unwrap();
        fs::write(repo.metadata.join("tmp"), b"fixed temporary-file blocker").unwrap();
        let before = stored_state(&repo);
        let error = repo
            .set_upstream_checked("main", "backup", "main", &root, Some(&first))
            .unwrap_err();
        assert!(error.contains("publication may have occurred"));
        assert_eq!(stored_state(&repo), before);
        let error = repo.rename_branch("main", "trunk").unwrap_err();
        assert!(
            error.contains("original branch and its upstream association have not been removed")
        );
        assert_eq!(stored_state(&repo), before);
        assert_eq!(
            fs::read(repo.metadata.join("tmp")).unwrap(),
            b"fixed temporary-file blocker"
        );
    }

    #[cfg(unix)]
    #[test]
    fn upstream_configuration_refuses_directories_and_symlinks_without_touching_the_target() {
        use std::os::unix::fs::symlink;
        let temp = TempDirectory::new();
        let repo = temp.repo("upstream-nonregular");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let path = repo.metadata.join("upstreams.json");
        fs::create_dir(&path).unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .set_upstream_on_branch("main", "origin", "main", &root)
            .unwrap_err()
            .contains("regular"));
        assert_eq!(stored_state(&repo), before);
        assert!(path.is_dir());
        fs::remove_dir(&path).unwrap();
        let outside = temp.path("private-upstreams.json");
        let original = br#"{"version":1,"branches":{}}"#;
        fs::write(&outside, original).unwrap();
        symlink(&outside, &path).unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .set_upstream_on_branch("main", "origin", "main", &root)
            .unwrap_err()
            .contains("regular"));
        assert_eq!(stored_state(&repo), before);
        assert!(path.is_symlink());
        assert_eq!(fs::read(outside).unwrap(), original);
    }

    #[test]
    fn branch_deletion_and_rename_protect_head_and_unmerged_commits() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        repo.rename_branch("main", "unborn").unwrap();
        assert_eq!(repo.current_branch().unwrap(), "unborn");
        assert!(repo.state().unwrap().branches.is_empty());
        repo.rename_branch("unborn", "main").unwrap();
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_branch("topic", "HEAD").unwrap();
        repo.switch_branch("topic").unwrap();
        let topic = repo.commit(&wasm(&[0, 1, 0]), "topic").unwrap();
        repo.switch_branch("main").unwrap();
        let before = repo.bundle_bytes(None).unwrap();
        let logs = repo.reflog().unwrap();
        assert!(repo.delete_branch("main", true).is_err());
        assert!(repo
            .delete_branch("topic", false)
            .unwrap_err()
            .contains("not fully merged"));
        assert!(repo.rename_branch("topic", "main").is_err());
        assert_eq!(repo.bundle_bytes(None).unwrap(), before);
        assert_eq!(repo.reflog().unwrap(), logs);
        repo.rename_branch("topic", "renamed").unwrap();
        assert!(!repo.branches().unwrap().contains_key("topic"));
        assert_eq!(repo.resolve("renamed").unwrap(), topic);
        assert_eq!(repo.delete_branch("renamed", true).unwrap(), topic);
        repo.create_branch("merged", &root).unwrap();
        assert_eq!(repo.delete_branch("merged", false).unwrap(), root);
        repo.rename_branch("main", "trunk").unwrap();
        assert_eq!(repo.current_branch().unwrap(), "trunk");
        assert_eq!(repo.resolve("HEAD").unwrap(), root);
    }

    #[test]
    fn reflog_records_ref_publication_and_rejects_corrupt_log_before_writes() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        assert!(repo.reflog().unwrap().is_empty());
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_tag("release", "HEAD").unwrap();
        repo.delete_tag("release").unwrap();
        let entries = repo.reflog().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].reference, "refs/heads/main");
        assert_eq!(entries[0].old, None);
        assert_eq!(entries[0].new.as_deref(), Some(root.as_str()));
        assert_eq!(entries[1].reference, "refs/tags/release");
        assert_eq!(entries[2].old.as_deref(), Some(root.as_str()));
        assert_eq!(entries[2].new, None);
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry.sequence, index as u64 + 1);
        }
        let log_before = fs::read(repo.metadata.join("reflog")).unwrap();
        repo.reset_head("HEAD", Some(&root)).unwrap();
        assert_eq!(fs::read(repo.metadata.join("reflog")).unwrap(), log_before);
        fs::write(repo.metadata.join("reflog"), b"incomplete").unwrap();
        let before = stored_state(&repo);
        assert!(repo.commit(&wasm(&[0, 1, 0]), "must reject").is_err());
        assert!(repo.create_branch("new", "HEAD").is_err());
        assert!(repo.create_tag("new", "HEAD").is_err());
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn remote_tracking_is_strict_and_never_substitutes_for_local_object_validation() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let root = source.commit(&wasm(&[]), "remote root").unwrap();
        let (state, bundle) = source.bundle_bytes(None).unwrap();
        let target = temp.repo("target");
        target.install_bundle_bytes(&bundle).unwrap();
        let directory = target.metadata.join("remotes");
        fs::create_dir(&directory).unwrap();
        let tracking = directory.join("origin.tracking.json");
        let valid = serde_json::json!({"version":1,"remote":"origin","url":"http://localhost:8080","state":state});
        fs::write(&tracking, serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(target.resolve("origin/main").unwrap(), root);
        assert_eq!(target.resolve("refs/remotes/origin/main").unwrap(), root);
        let mut bad = valid.clone();
        bad["state"]["branches"]["main"] = serde_json::Value::String("a".repeat(64));
        fs::write(&tracking, serde_json::to_vec(&bad).unwrap()).unwrap();
        let before = stored_state(&target);
        assert!(target
            .resolve("origin/main")
            .unwrap_err()
            .contains("missing or non-commit"));
        assert!(target
            .commit(&wasm(&[]), "must reject invalid tracking")
            .is_err());
        assert_eq!(stored_state(&target), before);
        let duplicate = format!(
            r#"{{"version":1,"remote":"origin","url":"http://localhost:8080","state":{{"format":1,"head":"main","branches":{{"main":"{root}","main":"{root}"}},"tags":{{}}}}}}"#
        );
        fs::write(&tracking, duplicate).unwrap();
        assert!(target
            .resolve("origin/main")
            .unwrap_err()
            .contains("duplicate reference"));
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("remote", serde_json::json!("other")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            fs::write(&tracking, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(target.resolve("origin/main").is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn tag_reflog_and_tracking_links_cannot_redirect_metadata_reads_or_writes() {
        use std::os::unix::fs::symlink;
        let temp = TempDirectory::new();
        for mode in ["tags", "reflog", "tracking"] {
            let repo = temp.repo(mode);
            repo.commit(&wasm(&[]), "root").unwrap();
            let outside = temp.path(&format!("outside-{mode}"));
            fs::write(&outside, b"preserve outside").unwrap();
            match mode {
                "tags" => symlink(&outside, repo.metadata.join("tags").join("redirect")).unwrap(),
                "reflog" => {
                    fs::remove_file(repo.metadata.join("reflog")).unwrap();
                    symlink(&outside, repo.metadata.join("reflog")).unwrap();
                }
                "tracking" => {
                    fs::create_dir(repo.metadata.join("remotes")).unwrap();
                    symlink(
                        &outside,
                        repo.metadata.join("remotes").join("origin.tracking.json"),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let before = stored_state(&repo);
            assert!(repo.state().is_err());
            assert!(repo
                .commit(&wasm(&[0, 1, 0]), "must refuse metadata link")
                .is_err());
            assert_eq!(stored_state(&repo), before);
            assert_eq!(fs::read(outside).unwrap(), b"preserve outside");
        }
    }

    #[test]
    fn repository_subcommand_help_returns_before_any_filesystem_action() {
        let temp = TempDirectory::new();
        let prospective_repo = temp.path("must-not-be-created");
        for flag in ["--help", "-h"] {
            // Do not change the process-wide cwd or assume a help-named path is
            // absent. This assertion also works in an existing user's checkout.
            let help_path = std::env::current_dir().unwrap().join(flag);
            let before = fs::symlink_metadata(&help_path)
                .map(|m| (m.file_type(), m.len(), m.modified().ok()))
                .ok();
            for command in [
                "init",
                "commit",
                "merge",
                "merge-base",
                "log",
                "show",
                "checkout",
                "branch",
                "switch",
                "clone",
                "bundle",
                "unbundle",
                "fsck",
            ] {
                let only_help = vec![command.to_string(), flag.to_string()];
                assert_eq!(run(&only_help).unwrap(), REPOSITORY_USAGE);
                let with_path = vec![
                    command.to_string(),
                    prospective_repo.to_str().unwrap().to_string(),
                    flag.to_string(),
                ];
                assert_eq!(run(&with_path).unwrap(), REPOSITORY_USAGE);
                assert!(!prospective_repo.exists());
            }
            let after = fs::symlink_metadata(&help_path)
                .map(|m| (m.file_type(), m.len(), m.modified().ok()))
                .ok();
            assert_eq!(before, after);
        }
    }

    #[test]
    fn repository_dispatch_preserves_literal_help_flags_as_commit_messages() {
        let temp = TempDirectory::new();
        let input = temp.path("input.wasm");
        fs::write(&input, wasm(&[])).unwrap();
        for (name, option, message) in [("short", "-m", "--help"), ("long", "--message", "-h")] {
            let repo = temp.repo(name);
            let output = run(&[
                "commit".into(),
                repo.root.to_str().unwrap().into(),
                input.to_str().unwrap().into(),
                option.into(),
                message.into(),
            ])
            .unwrap();
            assert_ne!(output, REPOSITORY_USAGE);
            assert_eq!(repo.read_commit("HEAD").unwrap().commit.message, message);
            assert_eq!(repo.wasm_bytes("HEAD").unwrap(), wasm(&[]));
        }
    }

    #[test]
    fn exact_bytes_unknown_features_and_immutable_dag_round_trip() {
        let temp = TempDirectory::new();
        let repo = temp.repo("source");
        // Raw future/unknown section bytes and non-normalized encodings survive.
        let before = wasm(&[0, 5, 0x81, 0, b'x', 0xff, 0, 99, 2, 0xfe, 0xff]);
        let first = repo.commit(&before, "initial bytes").unwrap();
        let after = wasm(&[99, 4, 0xfb, 0x80, 0x80, 0]);
        let second = repo.commit(&after, "future instruction bytes").unwrap();
        assert_ne!(first, second);
        assert_eq!(repo.wasm_bytes(&first).unwrap(), before);
        assert_eq!(repo.wasm_bytes("HEAD").unwrap(), after);
        let history = repo.log(None).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].commit.parents, vec![first.clone()]);
        assert_eq!(history[1].commit.parents, Vec::<String>::new());
        let destination = temp.path("checked-out.wasm");
        repo.checkout(&first, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), before);
        assert!(repo.checkout(&second, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), before);
        let report = repo.fsck().unwrap();
        assert_eq!(report.objects, 4);
        assert_eq!(report.commits, 2);
        assert_eq!(report.unreachable_objects, 0);
    }

    #[test]
    fn revision_batch_binds_repeated_head_and_other_refs_to_one_verified_snapshot() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let original_bytes = wasm(&[0, 1, 0]);
        let original = repo.commit(&original_bytes, "original").unwrap();
        repo.create_branch("review", "HEAD").unwrap();
        let current_bytes = wasm(&[99, 2, 0xff, 0xfe]);
        let current = repo.commit(&current_bytes, "current").unwrap();
        let batch = read_revisions(&repo.root, &["HEAD", "HEAD", "review", &original]).unwrap();
        assert_eq!(batch.len(), 4);
        assert_eq!(batch[0].commit, current);
        assert_eq!(batch[1].commit, current);
        assert_eq!(batch[0].bytes, current_bytes);
        assert_eq!(batch[1].bytes, current_bytes);
        assert_eq!(batch[2].commit, original);
        assert_eq!(batch[3].commit, original);
        assert_eq!(batch[2].bytes, original_bytes);
        assert_eq!(batch[3].bytes, original_bytes);
        assert!(!repo.metadata.join("write.lock").exists());
        repo.commit(&wasm(&[]), "advance after snapshot").unwrap();
        // Both IDs and copies remain an immutable description of the state read.
        assert_eq!(batch[0].commit, current);
        assert_eq!(batch[0].bytes, current_bytes);
        assert_eq!(repo.wasm_bytes("review").unwrap(), original_bytes);
    }

    #[test]
    fn revision_batch_refuses_locked_or_incomplete_requests_without_partial_results() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        repo.commit(&wasm(&[]), "root").unwrap();
        let lock = repo.lock().unwrap();
        assert!(read_revisions(&repo.root, &["HEAD", "HEAD"])
            .unwrap_err()
            .contains("locked"));
        assert!(repo.wasm_bytes("HEAD").unwrap_err().contains("locked"));
        assert!(repo.metadata.join("write.lock").exists());
        drop(lock);
        assert!(read_revisions(&repo.root, &["HEAD", "unknown"])
            .unwrap_err()
            .contains("unknown revision"));
        assert!(!repo.metadata.join("write.lock").exists());
        assert_eq!(
            read_revisions(&repo.root, &["HEAD", "HEAD"]).unwrap().len(),
            2
        );
    }

    #[test]
    fn revision_batch_verifies_dangling_objects_and_parent_closure_before_reading() {
        let temp = TempDirectory::new();
        for corrupt in ["dangling_blob", "missing_parent"] {
            let repo = temp.repo(corrupt);
            let root = repo.commit(&wasm(&[]), "root").unwrap();
            let expected_error = if corrupt == "dangling_blob" {
                let dangling = repo.store_object(WASM_KIND, &wasm(&[0, 1, 0])).unwrap();
                let path = repo.metadata.join("objects").join(dangling);
                let mut bytes = fs::read(&path).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                fs::write(path, bytes).unwrap();
                "hash mismatch"
            } else {
                let blob = repo.read_commit_id(&root).unwrap().wasm;
                store_history_commit(&repo, &blob, &["a".repeat(64)], "dangling broken history");
                "parent"
            };
            let before = stored_state(&repo);
            assert!(read_revisions(&repo.root, &["HEAD", "HEAD"])
                .unwrap_err()
                .contains(expected_error));
            assert!(repo
                .wasm_bytes("HEAD")
                .unwrap_err()
                .contains(expected_error));
            assert_eq!(stored_state(&repo), before);
            assert!(!repo.metadata.join("write.lock").exists());
        }
    }

    #[test]
    fn history_snapshot_contains_all_parents_deduplicates_blobs_and_keeps_fixed_tip() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let raw = wasm(&[]);
        let root = repo.commit(&raw, "root").unwrap();
        let blob = repo.read_commit_id(&root).unwrap().wasm;
        let left = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "left message");
        let right =
            store_history_commit(&repo, &blob, std::slice::from_ref(&root), "right message");
        let parents = vec![right.clone(), left.clone()];
        let merged = store_history_commit(&repo, &blob, &parents, "merge message");
        repo.write_ref("main", &merged).unwrap();
        let other_blob = repo.store_object(WASM_KIND, &wasm(&[0, 1, 0])).unwrap();
        let other = store_history_commit(
            &repo,
            &other_blob,
            std::slice::from_ref(&root),
            "other branch",
        );
        repo.write_ref("other", &other).unwrap();
        let dangling_blob = repo.store_object(WASM_KIND, &wasm(&[99, 1, 0xff])).unwrap();
        let dangling = store_history_commit(&repo, &dangling_blob, &[], "unrelated dangling root");
        let before = stored_state(&repo);
        let history = read_history(&repo.root, "HEAD").unwrap();
        assert_eq!(stored_state(&repo), before);
        assert!(!repo.metadata.join("write.lock").exists());
        assert_eq!(history.tip, merged);
        assert_eq!(history.commits.len(), 4);
        assert_eq!(history.blobs.len(), 1);
        assert_eq!(history.blobs[&blob], raw);
        assert_eq!(history.commits[&merged].parents, parents);
        assert_eq!(history.commits[&merged].message, "merge message");
        assert_eq!(history.commits[&left].message, "left message");
        assert_eq!(history.commits[&right].message, "right message");
        assert_eq!(history.commits[&left].parents, vec![root.clone()]);
        assert_eq!(history.commits[&right].parents, vec![root.clone()]);
        assert!(history.commits[&root].parents.is_empty());
        for (id, commit) in &history.commits {
            assert_eq!(id, &commit.id);
            assert_eq!(commit.wasm, blob);
        }
        assert!(!history.commits.contains_key(&other));
        assert!(!history.commits.contains_key(&dangling));
        assert!(!history.blobs.contains_key(&other_blob));
        assert!(!history.blobs.contains_key(&dangling_blob));
        let advanced = repo
            .commit(&wasm(&[99, 1, 0xfe]), "advance after snapshot")
            .unwrap();
        assert_eq!(history.tip, merged);
        assert!(!history.commits.contains_key(&advanced));
        assert_eq!(history.blobs[&blob], raw);
        assert_eq!(read_history(&repo.root, "HEAD").unwrap().tip, advanced);
    }

    #[test]
    fn history_snapshot_refuses_locked_unknown_or_non_commit_revisions() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let blob = repo.read_commit_id(&root).unwrap().wasm;
        let before = stored_state(&repo);
        let lock = repo.lock().unwrap();
        assert!(read_history(&repo.root, "HEAD")
            .unwrap_err()
            .contains("locked"));
        assert!(repo.metadata.join("write.lock").exists());
        drop(lock);
        assert!(read_history(&repo.root, "unknown")
            .unwrap_err()
            .contains("unknown revision"));
        assert!(read_history(&repo.root, &blob)
            .unwrap_err()
            .contains("non-commit"));
        assert_eq!(stored_state(&repo), before);
        assert!(!repo.metadata.join("write.lock").exists());
        assert_eq!(read_history(&repo.root, &root).unwrap().tip, root);
    }

    #[test]
    fn history_snapshot_verifies_missing_parents_and_unrelated_dangling_corruption() {
        let temp = TempDirectory::new();
        for corrupt in [
            "missing_reachable_parent",
            "dangling_blob",
            "dangling_parent",
        ] {
            let repo = temp.repo(corrupt);
            let root = repo.commit(&wasm(&[]), "root").unwrap();
            let blob = repo.read_commit_id(&root).unwrap().wasm;
            let expected_error = match corrupt {
                "missing_reachable_parent" => {
                    repo.commit(&wasm(&[0, 1, 0]), "child").unwrap();
                    fs::remove_file(repo.metadata.join("objects").join(&root)).unwrap();
                    "parent"
                }
                "dangling_blob" => {
                    let dangling = repo.store_object(WASM_KIND, &wasm(&[0, 1, 0])).unwrap();
                    let path = repo.metadata.join("objects").join(dangling);
                    let mut bytes = fs::read(&path).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(path, bytes).unwrap();
                    "hash mismatch"
                }
                "dangling_parent" => {
                    store_history_commit(
                        &repo,
                        &blob,
                        &["a".repeat(64)],
                        "broken dangling history",
                    );
                    "parent"
                }
                _ => unreachable!(),
            };
            let before = stored_state(&repo);
            assert!(read_history(&repo.root, "HEAD")
                .unwrap_err()
                .contains(expected_error));
            assert_eq!(stored_state(&repo), before);
            assert!(!repo.metadata.join("write.lock").exists());
        }
    }

    #[test]
    fn deterministic_ids_and_component_rejection() {
        let temp = TempDirectory::new();
        let a = temp.repo("a");
        let b = temp.repo("b");
        let bytes = wasm(&[]);
        assert_eq!(
            a.commit(&bytes, "same").unwrap(),
            b.commit(&bytes, "same").unwrap()
        );
        assert!(a.commit(b"\0asm\x0d\0\x01\0", "component").is_err());
        assert!(a.commit(b"\0asm", "truncated").is_err());
        assert_eq!(a.fsck().unwrap().commits, 1);
    }

    #[test]
    fn importing_a_new_branch_preserves_an_unborn_head() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let id = source.commit(&wasm(&[]), "first").unwrap();
        let bundle = temp.path("source.bundle");
        source.export_bundle(&bundle).unwrap();
        let target = temp.repo("target");
        target.import_bundle(&bundle, "incoming").unwrap();
        assert_eq!(target.current_branch().unwrap(), "main");
        assert!(target.resolve("HEAD").is_err());
        assert_eq!(target.resolve("incoming").unwrap(), id);
        assert_eq!(target.fsck().unwrap().branches, 1);
        target.switch_branch("incoming").unwrap();
        assert_eq!(target.resolve("HEAD").unwrap(), id);
    }

    #[test]
    fn imported_multi_parent_histories_log_children_before_every_parent() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let common = repo.commit(&wasm(&[0, 1, 0]), "common").unwrap();
        let long_parent = repo.commit(&wasm(&[0, 2, 1, b'x']), "long parent").unwrap();
        let wasm_id = repo.read_commit_id(&root).unwrap().wasm;
        let short_parent = repo
            .store_object(
                COMMIT_KIND,
                &encode_commit(&Commit {
                    format: 1,
                    tree: None,
                    legacy_path: None,
                    wasm: wasm_id.clone(),
                    parents: vec![root.clone()],
                    message: "short parent".into(),
                })
                .unwrap(),
            )
            .unwrap();
        let merge = repo
            .store_object(
                COMMIT_KIND,
                &encode_commit(&Commit {
                    format: 1,
                    tree: None,
                    legacy_path: None,
                    wasm: wasm_id,
                    parents: vec![short_parent.clone(), long_parent.clone()],
                    message: "imported merge".into(),
                })
                .unwrap(),
            )
            .unwrap();
        repo.write_ref("main", &merge).unwrap();
        let log = repo.log(None).unwrap();
        let positions: BTreeMap<_, _> = log
            .iter()
            .enumerate()
            .map(|(position, info)| (info.id.clone(), position))
            .collect();
        for entry in &log {
            for parent in &entry.commit.parents {
                assert!(positions[&entry.id] < positions[parent]);
            }
        }
        assert_eq!(log.len(), 5);
        assert!(positions[&common] < positions[&root]);
        assert_eq!(log.first().unwrap().id, merge);
        assert_eq!(log.last().unwrap().id, root);
        repo.fsck().unwrap();
    }

    #[test]
    fn branches_clone_and_bundle_fast_forward_without_history_loss() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let first = source.commit(&wasm(&[]), "first").unwrap();
        source.create_branch("review", "HEAD").unwrap();
        let clone = Repository::clone_local(&source.root, temp.path("clone")).unwrap();
        assert_eq!(clone.branches().unwrap(), source.branches().unwrap());
        let second = source.commit(&wasm(&[0, 1, 0]), "second").unwrap();
        let bundle = temp.path("source.bundle");
        source.export_bundle(&bundle).unwrap();
        assert_eq!(clone.import_bundle(&bundle, "main").unwrap(), second);
        assert_eq!(clone.resolve("review").unwrap(), first);
        clone.switch_branch("review").unwrap();
        let divergent = clone.commit(&wasm(&[0, 2, 1, b'x']), "divergent").unwrap();
        let objects_before = clone.fsck().unwrap().objects;
        assert!(clone
            .import_bundle(&bundle, "review")
            .unwrap_err()
            .contains("non-fast-forward"));
        assert_eq!(clone.resolve("review").unwrap(), divergent);
        assert_eq!(clone.fsck().unwrap().objects, objects_before);
        assert_eq!(clone.import_bundle(&bundle, "incoming").unwrap(), second);
        assert_eq!(clone.resolve("HEAD").unwrap(), divergent);
        assert!(Repository::clone_local(&source.root, &clone.root).is_err());
    }

    #[test]
    fn tampered_bundle_is_rejected_before_any_object_or_reference_write() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        source.commit(&wasm(&[]), "first").unwrap();
        let bundle = temp.path("tampered.bundle");
        source.export_bundle(&bundle).unwrap();
        let mut bytes = fs::read(&bundle).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&bundle, bytes).unwrap();
        let destination = temp.repo("destination");
        assert!(destination.import_bundle(&bundle, "main").is_err());
        assert_eq!(destination.fsck().unwrap().objects, 0);
        assert!(destination.branches().unwrap().is_empty());
    }

    #[test]
    fn incomplete_parent_closure_is_rejected_even_for_unreferenced_objects() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let first = source.commit(&wasm(&[]), "first").unwrap();
        let mut snapshot = source.snapshot().unwrap();
        let mut commit = source.read_commit_id(&first).unwrap();
        commit.parents = vec!["a".repeat(64)];
        let encoded = encode_object(COMMIT_KIND, &encode_commit(&commit).unwrap()).unwrap();
        let id = object_id(&encoded);
        // The invalid object is deliberately dangling; it still must be checked.
        snapshot.encoded.insert(id.clone(), encoded);
        snapshot.objects.insert(id, Object::Commit(commit));
        let bundle = temp.path("missing-parent.bundle");
        fs::write(&bundle, encode_bundle(&snapshot).unwrap()).unwrap();
        let destination = temp.repo("destination");
        assert!(destination
            .import_bundle(&bundle, "main")
            .unwrap_err()
            .contains("parent"));
        assert_eq!(destination.fsck().unwrap().objects, 0);
    }

    #[test]
    fn all_objects_and_refs_are_verified_and_path_traversal_is_rejected() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let first = repo.commit(&wasm(&[]), "first").unwrap();
        for bad in [
            "../outside",
            "/tmp/escape",
            "a/../b",
            ".",
            "..",
            "HEAD",
            "a.lock",
            "",
        ] {
            assert!(repo.create_branch(bad, "HEAD").is_err(), "accepted {bad:?}");
        }
        assert!(repo.create_branch(&"a".repeat(64), "HEAD").is_err());
        let info = repo.read_commit(&first).unwrap();
        let blob = repo.metadata.join("objects").join(info.commit.wasm);
        let mut bytes = fs::read(&blob).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&blob, bytes).unwrap();
        assert!(repo.fsck().unwrap_err().contains("hash mismatch"));
        assert!(repo
            .commit(&wasm(&[]), "do not extend corrupt history")
            .is_err());
        assert!(repo.wasm_bytes("HEAD").is_err());
        assert!(repo.export_bundle(temp.path("bad.bundle")).is_err());
    }

    #[test]
    fn repository_lock_prevents_concurrent_ref_writes() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let lock = repo.lock().unwrap();
        assert!(repo
            .commit(&wasm(&[]), "blocked")
            .unwrap_err()
            .contains("locked"));
        assert!(repo.metadata.join("write.lock").exists());
        drop(lock);
        repo.commit(&wasm(&[]), "allowed").unwrap();
        assert!(!repo.metadata.join("write.lock").exists());
    }

    fn function_wasm(left: i32, right: i32) -> Vec<u8> {
        wat::parse_str(format!(
            "(module (func (export \"left\") (result i32) i32.const {left}) \
             (func (export \"right\") (result i32) i32.const {right}))"
        ))
        .unwrap()
    }

    fn store_history_commit(
        repo: &Repository,
        wasm: &str,
        parents: &[String],
        message: &str,
    ) -> String {
        repo.store_object(
            COMMIT_KIND,
            &encode_commit(&Commit {
                format: 1,
                tree: None,
                legacy_path: None,
                wasm: wasm.into(),
                parents: parents.to_vec(),
                message: message.into(),
            })
            .unwrap(),
        )
        .unwrap()
    }

    #[derive(Debug, PartialEq, Eq)]
    struct StoredState {
        objects: BTreeMap<String, Vec<u8>>,
        refs: BTreeMap<String, Vec<u8>>,
        tags: BTreeMap<String, Vec<u8>>,
        tracking: BTreeMap<String, Vec<u8>>,
        upstreams: Option<Vec<u8>>,
        reflog: Option<Vec<u8>>,
        head: Vec<u8>,
    }

    fn stored_state(repo: &Repository) -> StoredState {
        fn files(path: &Path) -> BTreeMap<String, Vec<u8>> {
            fs::read_dir(path)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (
                        entry.file_name().into_string().unwrap(),
                        fs::read(entry.path()).unwrap(),
                    )
                })
                .collect()
        }
        StoredState {
            objects: files(&repo.metadata.join("objects")),
            refs: files(&repo.metadata.join("refs")),
            tags: if repo.metadata.join("tags").exists() {
                files(&repo.metadata.join("tags"))
            } else {
                BTreeMap::new()
            },
            tracking: if repo.metadata.join("remotes").exists() {
                files(&repo.metadata.join("remotes"))
            } else {
                BTreeMap::new()
            },
            reflog: fs::read(repo.metadata.join("reflog")).ok(),
            upstreams: fs::read(repo.metadata.join("upstreams.json")).ok(),
            head: fs::read(repo.metadata.join("HEAD")).unwrap(),
        }
    }

    #[test]
    fn ff_only_keeps_branch_tip_cas_and_full_store_validation_for_fast_forwards_and_noops() {
        let temp = TempDirectory::new();
        let repo = temp.repo("ff-only");
        let root = repo.commit(&function_wasm(1, 2), "root").unwrap();
        repo.create_branch("target", "HEAD").unwrap();
        repo.switch_branch("target").unwrap();
        let target = repo.commit(&function_wasm(11, 2), "target").unwrap();
        repo.switch_branch("main").unwrap();
        repo.create_branch("same-tip", "HEAD").unwrap();
        repo.switch_branch("same-tip").unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .merge_ff_only_on_branch(&target, "wrong branch", "main", Some(&root))
            .unwrap_err()
            .contains("branch changed"));
        assert_eq!(stored_state(&repo), before);
        let outcome = repo
            .merge_ff_only_on_branch(&target, "fast-forward", "same-tip", Some(&root))
            .unwrap();
        assert_eq!(outcome.status, "fast_forward");
        assert_eq!(repo.resolve("HEAD").unwrap(), target);
        assert_eq!(repo.resolve("main").unwrap(), root);
        let before = stored_state(&repo);
        assert!(repo
            .merge_ff_only_on_branch("HEAD", "stale tip", "same-tip", Some(&root))
            .unwrap_err()
            .contains("reference changed"));
        assert_eq!(stored_state(&repo), before);
        assert_eq!(
            repo.merge_ff_only_on_branch(&root, "included", "same-tip", Some(&target))
                .unwrap()
                .status,
            "already_up_to_date"
        );
        assert_eq!(stored_state(&repo), before);
        let corrupt = repo.metadata.join("objects").join("f".repeat(64));
        assert!(!corrupt.exists());
        fs::write(&corrupt, b"invalid dangling object").unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .merge_ff_only_on_branch("HEAD", "cannot hide corruption", "same-tip", Some(&target))
            .is_err());
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn ff_only_rejects_unrelated_and_criss_cross_histories_before_base_selection() {
        let temp = TempDirectory::new();
        let repo = temp.repo("ff-only-bases");
        let root = repo.commit(&function_wasm(1, 2), "root").unwrap();
        let wasm = repo.read_commit(&root).unwrap().commit.wasm;
        let unrelated = store_history_commit(&repo, &wasm, &[], "unrelated");
        let before = stored_state(&repo);
        assert!(repo
            .merge_ff_only_on_branch(&unrelated, "unrelated", "main", Some(&root))
            .unwrap_err()
            .contains("fast-forward-only merge refused"));
        assert_eq!(stored_state(&repo), before);
        let left = store_history_commit(&repo, &wasm, std::slice::from_ref(&root), "left");
        let right = store_history_commit(&repo, &wasm, std::slice::from_ref(&root), "right");
        let ours = store_history_commit(&repo, &wasm, &[left.clone(), right.clone()], "ours");
        let target = store_history_commit(&repo, &wasm, &[right, left], "target");
        repo.reset_on_branch(&ours, "main", Some(&root)).unwrap();
        assert_eq!(repo.merge_bases(&ours, &target).unwrap().len(), 2);
        let before = stored_state(&repo);
        assert!(repo
            .merge_ff_only_on_branch(&target, "ambiguous ancestry", "main", Some(&ours))
            .unwrap_err()
            .contains("fast-forward-only merge refused"));
        assert_eq!(stored_state(&repo), before);
        assert!(repo
            .merge_on_branch(
                &target,
                "default still diagnoses bases",
                "main",
                Some(&ours)
            )
            .unwrap_err()
            .contains("multiple best merge bases"));
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn guarded_merge_rejects_same_tip_branch_switch_and_stale_tip_without_publication() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit(&function_wasm(1, 2), "root").unwrap();
        repo.create_branch("target", "HEAD").unwrap();
        repo.switch_branch("target").unwrap();
        let target = repo.commit(&function_wasm(11, 2), "target").unwrap();
        repo.switch_branch("main").unwrap();
        repo.create_branch("same-tip", "HEAD").unwrap();
        repo.switch_branch("same-tip").unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .merge_on_branch(&target, "wrong branch", "main", Some(&root))
            .unwrap_err()
            .contains("branch changed"));
        assert_eq!(stored_state(&repo), before);
        let child = repo.commit(&function_wasm(1, 22), "advance").unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .merge_on_branch(&target, "stale", "same-tip", Some(&root))
            .unwrap_err()
            .contains("reference changed"));
        assert_eq!(stored_state(&repo), before);
        let outcome = repo
            .merge_on_branch(&target, "correct review", "same-tip", Some(&child))
            .unwrap();
        assert_eq!(outcome.status, "merged");
        assert_eq!(repo.resolve("refs/heads/main").unwrap(), root);
        assert_eq!(
            repo.read_commit("HEAD").unwrap().commit.parents,
            vec![child, target]
        );
    }

    #[test]
    fn guarded_manual_merge_rejects_same_tip_switch_and_preserves_reviewed_bytes() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        repo.commit(&function_wasm(1, 2), "root").unwrap();
        repo.create_branch("target", "HEAD").unwrap();
        let ours = repo.commit(&function_wasm(11, 2), "ours").unwrap();
        repo.switch_branch("target").unwrap();
        let target = repo.commit(&function_wasm(22, 2), "target").unwrap();
        repo.switch_branch("main").unwrap();
        repo.create_branch("same-tip", "HEAD").unwrap();
        repo.switch_branch("same-tip").unwrap();
        let resolved = wasm(&[99, 1, 0x42]);
        let before = stored_state(&repo);
        assert!(repo
            .merge_resolved_on_branch("main", &ours, &target, &resolved, "wrong branch")
            .unwrap_err()
            .contains("branch changed"));
        assert_eq!(stored_state(&repo), before);
        let outcome = repo
            .merge_resolved_on_branch("same-tip", &ours, &target, &resolved, "correct branch")
            .unwrap();
        assert_eq!(outcome.status, "merged_resolved");
        assert_eq!(repo.resolve("refs/heads/main").unwrap(), ours);
        assert_eq!(repo.wasm_bytes("HEAD").unwrap(), resolved);
        assert_eq!(
            repo.read_commit("HEAD").unwrap().commit.parents,
            vec![ours, target]
        );
    }

    #[test]
    fn merge_fast_forward_and_ancestor_noop_create_no_objects() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let first = repo.commit(&wasm(&[]), "root").unwrap();
        repo.create_branch("incoming", "HEAD").unwrap();
        repo.switch_branch("incoming").unwrap();
        let second = repo.commit(&wasm(&[0, 1, 0]), "second").unwrap();
        repo.switch_branch("main").unwrap();
        let objects = repo.fsck().unwrap().objects;
        let outcome = repo.merge("incoming", "unused for fast-forward").unwrap();
        assert_eq!(outcome.status, "fast_forward");
        assert_eq!(outcome.old_head.as_deref(), Some(first.as_str()));
        assert_eq!(outcome.commit.as_deref(), Some(second.as_str()));
        assert!(outcome.report.is_none());
        assert_eq!(repo.resolve("HEAD").unwrap(), second);
        assert_eq!(repo.current_branch().unwrap(), "main");
        assert_eq!(repo.fsck().unwrap().objects, objects);
        let unchanged = stored_state(&repo);
        for target in [&first, &second] {
            let outcome = repo.merge(target, "unused for ancestor").unwrap();
            assert_eq!(outcome.status, "already_up_to_date");
            assert_eq!(outcome.commit.as_deref(), Some(second.as_str()));
            assert_eq!(stored_state(&repo), unchanged);
        }
        assert_eq!(repo.merge_bases("main", "incoming").unwrap(), vec![second]);
    }

    #[test]
    fn merge_can_fast_forward_an_unborn_head_to_an_imported_branch() {
        let temp = TempDirectory::new();
        let source = temp.repo("source");
        let tip = source.commit(&wasm(&[]), "root").unwrap();
        let bundle = temp.path("source.bundle");
        source.export_bundle(&bundle).unwrap();
        let repo = temp.repo("repo");
        repo.import_bundle(&bundle, "incoming").unwrap();
        let objects = repo.fsck().unwrap().objects;
        let outcome = repo.merge("incoming", "adopt imported history").unwrap();
        assert_eq!(outcome.status, "fast_forward");
        assert!(outcome.old_head.is_none());
        assert!(outcome.base.is_none());
        assert_eq!(outcome.commit.as_deref(), Some(tip.as_str()));
        assert_eq!(repo.resolve("HEAD").unwrap(), tip);
        assert_eq!(repo.fsck().unwrap().objects, objects);
    }

    #[test]
    fn divergent_function_edits_create_two_parent_commit_and_bundle_round_trip() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let base = repo.commit(&function_wasm(1, 2), "base").unwrap();
        repo.create_branch("incoming", "HEAD").unwrap();
        let ours = repo.commit(&function_wasm(11, 2), "ours").unwrap();
        repo.switch_branch("incoming").unwrap();
        let theirs = repo.commit(&function_wasm(1, 22), "theirs").unwrap();
        repo.switch_branch("main").unwrap();
        assert_eq!(
            repo.merge_bases("HEAD", "incoming").unwrap(),
            vec![base.clone()]
        );
        let outcome = repo.merge("incoming", "combine function changes").unwrap();
        assert_eq!(outcome.status, "merged");
        assert_eq!(outcome.base.as_deref(), Some(base.as_str()));
        assert_eq!(outcome.report.as_ref().unwrap().status, "clean");
        let id = outcome.commit.unwrap();
        let commit = repo.read_commit(&id).unwrap();
        assert_eq!(commit.commit.parents, vec![ours, theirs.clone()]);
        assert_eq!(commit.commit.message, "combine function changes");
        assert_eq!(repo.resolve("HEAD").unwrap(), id);
        assert_eq!(repo.resolve("incoming").unwrap(), theirs);
        assert_eq!(repo.wasm_bytes("HEAD").unwrap(), function_wasm(11, 22));
        let bundle = temp.path("merged.bundle");
        repo.export_bundle(&bundle).unwrap();
        let destination = temp.repo("destination");
        destination.import_bundle(&bundle, "merged").unwrap();
        assert_eq!(
            destination.read_commit("merged").unwrap().commit,
            commit.commit
        );
        assert_eq!(
            destination.wasm_bytes("merged").unwrap(),
            function_wasm(11, 22)
        );
        assert_eq!(destination.fsck().unwrap().commits, 4);
        let positions: BTreeMap<_, _> = destination
            .log(Some("merged"))
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, info)| (info.id.clone(), index))
            .collect();
        assert_eq!(positions[&id], 0);
        assert_eq!(positions[&base], 3);
    }

    #[test]
    fn conflicting_merge_leaves_every_object_reference_and_head_unchanged() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        repo.commit(&function_wasm(1, 2), "base").unwrap();
        repo.create_branch("incoming", "HEAD").unwrap();
        repo.commit(&function_wasm(11, 2), "ours").unwrap();
        repo.switch_branch("incoming").unwrap();
        repo.commit(&function_wasm(22, 2), "theirs").unwrap();
        repo.switch_branch("main").unwrap();
        let before = stored_state(&repo);
        let outcome = repo.merge("incoming", "must remain uncommitted").unwrap();
        assert_eq!(outcome.status, "conflict");
        assert!(outcome.commit.is_none());
        assert_eq!(outcome.report.as_ref().unwrap().status, "conflict");
        assert_eq!(stored_state(&repo), before);
        assert_eq!(repo.fsck().unwrap().commits, 3);
        assert!(!repo.metadata.join("write.lock").exists());
    }

    #[test]
    fn explicit_resolution_preserves_exact_unknown_bytes_and_both_parents() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let base = repo.commit(&function_wasm(1, 2), "base").unwrap();
        repo.create_branch("incoming", "HEAD").unwrap();
        let ours = repo.commit(&function_wasm(11, 2), "ours").unwrap();
        repo.switch_branch("incoming").unwrap();
        let theirs = repo.commit(&function_wasm(22, 2), "theirs").unwrap();
        repo.switch_branch("main").unwrap();
        let resolved = wasm(&[99, 3, 0xff, 0xfe, 0xfd]);
        let outcome = repo
            .merge_resolved(&ours, &theirs, &resolved, "explicit unknown bytes")
            .unwrap();
        assert_eq!(outcome.status, "merged_resolved");
        assert_eq!(outcome.old_head.as_deref(), Some(ours.as_str()));
        assert_eq!(outcome.target, theirs);
        assert_eq!(outcome.base.as_deref(), Some(base.as_str()));
        assert!(outcome.report.is_none());
        let id = outcome.commit.unwrap();
        let commit = repo.read_commit(&id).unwrap().commit;
        assert_eq!(commit.parents, vec![ours, theirs]);
        assert_eq!(repo.wasm_bytes("HEAD").unwrap(), resolved);
        let manual = outcome.manual_resolution.unwrap();
        assert!(manual.supplied_bytes);
        assert_eq!(manual.wasm, commit.wasm);
        assert_eq!(manual.audit_validation, "failed_or_unsupported");
        assert!(manual.diagnostic_count > 0);
        repo.fsck().unwrap();
    }

    #[test]
    fn explicit_resolution_requires_immutable_reviewed_tips_and_divergent_history() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let base = repo.commit(&function_wasm(1, 2), "base").unwrap();
        repo.create_branch("incoming", "HEAD").unwrap();
        let ours = repo.commit(&function_wasm(11, 2), "ours").unwrap();
        repo.switch_branch("incoming").unwrap();
        let theirs = repo.commit(&function_wasm(22, 2), "theirs").unwrap();
        repo.switch_branch("main").unwrap();
        let before = stored_state(&repo);
        assert!(repo
            .merge_resolved(&base, &theirs, &function_wasm(33, 2), "stale")
            .unwrap_err()
            .contains("HEAD changed"));
        assert!(repo
            .merge_resolved(&ours, "incoming", &function_wasm(33, 2), "mutable target")
            .unwrap_err()
            .contains("invalid object ID"));
        assert!(repo
            .merge_resolved(&ours, &theirs, b"not a wasm", "bad header")
            .is_err());
        for target in [&ours, &base] {
            assert!(repo
                .merge_resolved(&ours, target, &function_wasm(33, 2), "not divergent")
                .unwrap_err()
                .contains("divergent"));
        }
        assert_eq!(stored_state(&repo), before);
        let fast_forward_repo = temp.repo("ff");
        let first = fast_forward_repo.commit(&wasm(&[]), "first").unwrap();
        let last = fast_forward_repo.commit(&wasm(&[0, 1, 0]), "last").unwrap();
        fast_forward_repo.create_branch("old", &first).unwrap();
        fast_forward_repo.switch_branch("old").unwrap();
        let before = stored_state(&fast_forward_repo);
        assert!(fast_forward_repo
            .merge_resolved(&first, &last, &wasm(&[]), "must not ignore bytes")
            .unwrap_err()
            .contains("divergent"));
        assert_eq!(stored_state(&fast_forward_repo), before);
    }

    #[test]
    fn unrelated_and_criss_cross_merges_refuse_to_guess_a_base() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let blob = repo.read_commit_id(&root).unwrap().wasm;
        let unrelated = store_history_commit(&repo, &blob, &[], "unrelated");
        repo.write_ref("unrelated", &unrelated).unwrap();
        let before = stored_state(&repo);
        assert!(repo.merge_bases("HEAD", "unrelated").unwrap().is_empty());
        assert!(repo
            .merge("unrelated", "no base")
            .unwrap_err()
            .contains("unrelated"));
        assert!(repo
            .merge_resolved(&root, &unrelated, &wasm(&[]), "manual no base")
            .unwrap_err()
            .contains("unrelated"));
        assert_eq!(stored_state(&repo), before);
        let a = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "a");
        let b = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "b");
        let left = store_history_commit(&repo, &blob, &[a.clone(), b.clone()], "left merge");
        let right = store_history_commit(&repo, &blob, &[b.clone(), a.clone()], "right merge");
        repo.write_ref("main", &left).unwrap();
        repo.write_ref("incoming", &right).unwrap();
        let before = stored_state(&repo);
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(repo.merge_bases("HEAD", "incoming").unwrap(), expected);
        let error = repo.merge("incoming", "ambiguous base").unwrap_err();
        assert!(error.contains("multiple best merge bases"));
        assert!(repo
            .merge_resolved(&left, &right, &wasm(&[]), "manual ambiguous base")
            .unwrap_err()
            .contains("multiple best merge bases"));
        for id in expected {
            assert!(error.contains(&id));
        }
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn merge_verifies_all_history_before_fast_forward_or_noop_and_holds_writer_lock() {
        let temp = TempDirectory::new();
        for mode in ["missing_parent", "tampered_blob", "dangling_history"] {
            let repo = temp.repo(mode);
            let root = repo.commit(&wasm(&[]), "root").unwrap();
            repo.create_branch("incoming", "HEAD").unwrap();
            repo.switch_branch("incoming").unwrap();
            repo.commit(&wasm(&[0, 1, 0]), "child").unwrap();
            repo.switch_branch("main").unwrap();
            match mode {
                "missing_parent" => {
                    fs::remove_file(repo.metadata.join("objects").join(&root)).unwrap()
                }
                "tampered_blob" => {
                    let blob = repo.read_commit_id(&root).unwrap().wasm;
                    let path = repo.metadata.join("objects").join(blob);
                    let mut bytes = fs::read(&path).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    fs::write(path, bytes).unwrap();
                }
                "dangling_history" => {
                    let blob = repo.read_commit_id(&root).unwrap().wasm;
                    store_history_commit(&repo, &blob, &["a".repeat(64)], "missing parent");
                }
                _ => unreachable!(),
            }
            let before = stored_state(&repo);
            for target in ["incoming", "HEAD"] {
                assert!(repo.merge(target, "must refuse corrupt store").is_err());
                assert_eq!(stored_state(&repo), before);
            }
            assert!(repo.merge_bases("HEAD", "incoming").is_err());
        }
        let repo = temp.repo("locked");
        let root = repo.commit(&wasm(&[]), "root").unwrap();
        let before = stored_state(&repo);
        let lock = repo.lock().unwrap();
        assert!(repo.merge("HEAD", "locked").unwrap_err().contains("locked"));
        assert!(repo
            .merge_bases("HEAD", "HEAD")
            .unwrap_err()
            .contains("locked"));
        assert!(repo
            .merge_resolved(&root, &root, &wasm(&[]), "locked")
            .unwrap_err()
            .contains("locked"));
        assert_eq!(stored_state(&repo), before);
        drop(lock);
        assert_eq!(
            repo.merge("HEAD", "noop").unwrap().status,
            "already_up_to_date"
        );
    }

    fn bisect_linear_fixture(
        temp: &TempDirectory,
        name: &str,
        count: usize,
    ) -> (Repository, Vec<String>) {
        let repo = temp.repo(name);
        let ids = (0..count)
            .map(|index| repo.commit(&wasm(&[]), &format!("linear {index}")).unwrap())
            .collect();
        (repo, ids)
    }

    fn bisect_start(repo: &Repository, bad: &str, good: &str, first_parent: bool) -> BisectReport {
        repo.bisect(BisectRequest::Start {
            bad: bad.into(),
            good: vec![good.into()],
            first_parent,
        })
        .unwrap()
    }

    #[test]
    fn bisect_linear_balancing_and_no_checkout_preserve_every_other_authority() {
        let temp = TempDirectory::new();
        let (repo, ids) = bisect_linear_fixture(&temp, "bisect-linear", 7);
        fs::write(repo.metadata.join("index"), b"intentionally invalid index").unwrap();
        fs::write(
            repo.metadata.join("pending.json"),
            b"intentionally invalid pending",
        )
        .unwrap();
        let work = repo.metadata.parent().unwrap().join("dirty.wasm");
        fs::write(&work, b"dirty unknown bytes").unwrap();
        let before = stored_state(&repo);
        let bundle = repo.bundle_bytes(None).unwrap();
        let start = bisect_start(&repo, &ids[6], &ids[0], false);
        assert_eq!(start.status, "testing");
        assert_eq!(start.candidate.as_ref(), Some(&ids[3]));
        assert_eq!(start.remaining.len(), 6);
        assert_eq!(start.testable.len(), 5);
        assert_eq!(start.suspects, start.remaining);
        assert!(start.active && start.changed && start.no_checkout);
        assert!(
            !start.head_updated
                && !start.index_updated
                && !start.worktree_updated
                && !start.pending_updated
        );
        assert_eq!(start.object_verification, "full_snapshot");
        assert_eq!(start.generation.as_ref().unwrap().len(), 64);
        let journal = fs::read(repo.metadata.join("bisect.json")).unwrap();
        for request in [
            BisectRequest::Status,
            BisectRequest::Next,
            BisectRequest::Log,
        ] {
            let report = repo.bisect(request).unwrap();
            assert_eq!(report.candidate, start.candidate);
            assert_eq!(report.generation, start.generation);
            assert!(!report.changed);
            assert_eq!(
                fs::read(repo.metadata.join("bisect.json")).unwrap(),
                journal
            );
        }
        assert_eq!(repo.bundle_bytes(None).unwrap(), bundle);
        assert_eq!(stored_state(&repo), before);
        assert_eq!(
            fs::read(repo.metadata.join("index")).unwrap(),
            b"intentionally invalid index"
        );
        assert_eq!(
            fs::read(repo.metadata.join("pending.json")).unwrap(),
            b"intentionally invalid pending"
        );
        assert_eq!(fs::read(work).unwrap(), b"dirty unknown bytes");
    }

    #[test]
    fn bisect_merge_scores_use_remaining_ancestor_sets_and_first_parent_edges() {
        let temp = TempDirectory::new();
        let repo = temp.repo("bisect-dag");
        let blob = repo.store_object(WASM_KIND, &wasm(&[])).unwrap();
        let root = store_history_commit(&repo, &blob, &[], "root");
        let a1 = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "a1");
        let a2 = store_history_commit(&repo, &blob, std::slice::from_ref(&a1), "a2");
        let a3 = store_history_commit(&repo, &blob, std::slice::from_ref(&a2), "a3");
        let s1 = store_history_commit(&repo, &blob, std::slice::from_ref(&root), "s1");
        let s2 = store_history_commit(&repo, &blob, std::slice::from_ref(&s1), "s2");
        let merge = store_history_commit(&repo, &blob, &[a3.clone(), s2.clone()], "merge");
        let all = bisect_start(&repo, &merge, &root, false);
        assert_eq!(all.candidate.as_ref(), Some(&a3));
        assert_eq!(all.remaining.len(), 6);
        repo.bisect(BisectRequest::Mark {
            kind: BisectKind::Bad,
            revisions: vec![a3.clone()],
        })
        .unwrap();
        let outside_current = repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: vec![s2.clone()],
            })
            .unwrap();
        assert!(outside_current.good.contains(&s2));
        assert_eq!(outside_current.remaining.len(), 3);
        let raw = fs::read(repo.metadata.join("bisect.json")).unwrap();
        assert!(repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: vec![merge.clone()]
            })
            .is_err());
        assert_eq!(fs::read(repo.metadata.join("bisect.json")).unwrap(), raw);
        repo.bisect(BisectRequest::Reset).unwrap();
        let fp = bisect_start(&repo, &merge, &root, true);
        assert_eq!(fp.candidate.as_ref(), Some(&a2));
        assert_eq!(fp.remaining.len(), 4);
        repo.bisect(BisectRequest::Reset).unwrap();
        assert!(repo
            .bisect(BisectRequest::Start {
                bad: merge,
                good: vec![s2],
                first_parent: true
            })
            .is_err());
        assert!(!repo.metadata.join("bisect.json").exists());
    }

    #[test]
    fn bisect_skips_preserve_ambiguity_and_explicit_classification_can_unskip() {
        let temp = TempDirectory::new();
        let (repo, ids) = bisect_linear_fixture(&temp, "bisect-skip", 3);
        assert_eq!(
            bisect_start(&repo, &ids[2], &ids[0], false)
                .candidate
                .as_ref(),
            Some(&ids[1])
        );
        let skipped = repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Skip,
                revisions: Vec::new(),
            })
            .unwrap();
        assert_eq!(skipped.status, "ambiguous_skipped");
        assert!(skipped.candidate.is_none() && skipped.first_bad.is_none());
        assert_eq!(
            skipped.suspects.iter().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([ids[1].clone(), ids[2].clone()])
        );
        assert!(repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: Vec::new()
            })
            .is_err());
        let raw = fs::read(repo.metadata.join("bisect.json")).unwrap();
        let noop = repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Skip,
                revisions: vec![ids[1].clone()],
            })
            .unwrap();
        assert!(!noop.changed);
        assert_eq!(fs::read(repo.metadata.join("bisect.json")).unwrap(), raw);
        let found = repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: vec![ids[1].clone()],
            })
            .unwrap();
        assert_eq!(found.status, "found");
        assert_eq!(found.first_bad.as_ref(), Some(&ids[2]));
        assert_eq!(found.suspects, vec![ids[2].clone()]);
        assert!(found.skip.is_empty());
        assert_eq!(found.marks.len(), 2);
        assert!(repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Bad,
                revisions: vec![ids[1].clone()]
            })
            .is_err());
        repo.bisect(BisectRequest::Reset).unwrap();
        bisect_start(&repo, &ids[2], &ids[0], false);
        repo.bisect(BisectRequest::Mark {
            kind: BisectKind::Skip,
            revisions: vec![ids[1].clone()],
        })
        .unwrap();
        let found = repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Bad,
                revisions: vec![ids[1].clone()],
            })
            .unwrap();
        assert_eq!(found.first_bad.as_ref(), Some(&ids[1]));
        assert!(found.skip.is_empty());
    }

    #[test]
    fn bisect_batches_are_atomic_sorted_idempotent_and_contradictions_never_publish() {
        let temp = TempDirectory::new();
        let (repo, ids) = bisect_linear_fixture(&temp, "bisect-batch", 7);
        bisect_start(&repo, &ids[6], &ids[0], false);
        let marked = repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: vec![ids[2].clone(), ids[1].clone(), ids[2].clone()],
            })
            .unwrap();
        assert_eq!(marked.marks.len(), 1);
        assert_eq!(marked.marks[0].revisions.len(), 2);
        assert!(marked.marks[0].revisions[0] < marked.marks[0].revisions[1]);
        let raw = fs::read(repo.metadata.join("bisect.json")).unwrap();
        let before = stored_state(&repo);
        let noop = repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: vec![ids[0].clone(), ids[1].clone(), ids[2].clone()],
            })
            .unwrap();
        assert!(!noop.changed);
        for request in [
            BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: vec![ids[3].clone(), ids[6].clone()],
            },
            BisectRequest::Mark {
                kind: BisectKind::Skip,
                revisions: vec![ids[3].clone(), ids[1].clone()],
            },
            BisectRequest::Mark {
                kind: BisectKind::Bad,
                revisions: vec![ids[3].clone(), ids[4].clone()],
            },
        ] {
            assert!(repo.bisect(request).is_err());
        }
        assert_eq!(fs::read(repo.metadata.join("bisect.json")).unwrap(), raw);
        assert_eq!(stored_state(&repo), before);
        let old_bad = ids[6].clone();
        repo.bisect(BisectRequest::Mark {
            kind: BisectKind::Bad,
            revisions: vec![ids[4].clone()],
        })
        .unwrap();
        assert!(repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Bad,
                revisions: vec![old_bad.clone()]
            })
            .is_err());
        assert!(repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Skip,
                revisions: vec![old_bad]
            })
            .is_err());
    }

    #[test]
    fn bisect_frozen_ids_survive_reference_and_head_moves_and_default_uses_candidate() {
        let temp = TempDirectory::new();
        let (repo, ids) = bisect_linear_fixture(&temp, "bisect-refmove", 7);
        let start = bisect_start(&repo, "HEAD", "HEAD~6", false);
        repo.create_branch("elsewhere", &ids[0]).unwrap();
        repo.switch_branch("elsewhere").unwrap();
        let unrelated = repo
            .commit(&wasm(&[]), "unrelated sibling after session")
            .unwrap();
        let before = stored_state(&repo);
        let current = repo.bisect(BisectRequest::Status).unwrap();
        assert_eq!(current.original_bad.as_ref(), Some(&ids[6]));
        assert_eq!(current.candidate, start.candidate);
        assert_eq!(current.generation, start.generation);
        assert!(repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: vec!["HEAD".into()]
            })
            .is_err());
        let marked = repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Bad,
                revisions: Vec::new(),
            })
            .unwrap();
        assert_eq!(marked.bad, start.candidate);
        assert_eq!(repo.resolve("HEAD").unwrap(), unrelated);
        assert_eq!(stored_state(&repo), before);
    }

    #[test]
    fn bisect_canonical_journal_replay_rejects_forged_and_redundant_events() {
        let temp = TempDirectory::new();
        let (repo, ids) = bisect_linear_fixture(&temp, "bisect-forged", 4);
        bisect_start(&repo, &ids[3], &ids[0], false);
        let state = repo.read_bisect().unwrap().unwrap();
        let original = encode_bisect(&state).unwrap();
        let mut unknown = serde_json::to_value(&state).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("candidate".into(), json!(ids[1]));
        let mut redundant = state.clone();
        redundant.marks.push(BisectMark {
            kind: BisectKind::Good,
            revisions: vec![ids[0].clone()],
        });
        let mut bad_initial = state.clone();
        bad_initial.initial_good = vec![ids[3].clone()];
        let duplicate = String::from_utf8(original.clone())
            .unwrap()
            .replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
            .into_bytes();
        let mut no_lf = original.clone();
        no_lf.pop();
        for bytes in [
            b"{broken".to_vec(),
            serde_json::to_vec(&unknown).unwrap(),
            duplicate,
            no_lf,
            encode_bisect(&redundant).unwrap(),
            encode_bisect(&bad_initial).unwrap(),
        ] {
            fs::write(repo.metadata.join("bisect.json"), &bytes).unwrap();
            let before = stored_state(&repo);
            assert!(repo.bisect(BisectRequest::Status).is_err());
            assert!(repo
                .bisect(BisectRequest::Start {
                    bad: ids[3].clone(),
                    good: vec![ids[0].clone()],
                    first_parent: false
                })
                .is_err());
            assert_eq!(fs::read(repo.metadata.join("bisect.json")).unwrap(), bytes);
            assert_eq!(stored_state(&repo), before);
            assert!(repo.bisect(BisectRequest::Reset).unwrap().changed);
        }
        fs::write(repo.metadata.join("bisect.json"), original).unwrap();
        assert_eq!(
            repo.bisect(BisectRequest::Status)
                .unwrap()
                .original_bad
                .as_ref(),
            Some(&ids[3])
        );
    }

    #[test]
    fn bisect_journal_encoding_and_decoding_enforce_byte_and_event_limits() {
        let temp = TempDirectory::new();
        let (repo, ids) = bisect_linear_fixture(&temp, "bisect-bounds", 3);
        bisect_start(&repo, &ids[2], &ids[0], false);
        let mut state = repo.read_bisect().unwrap().unwrap();
        let event = BisectMark {
            kind: BisectKind::Skip,
            revisions: vec![ids[1].clone()],
        };
        state.marks = vec![event.clone(); MAX_BISECT_MARKS];
        let valid_shape = encode_bisect(&state).unwrap();
        assert!(valid_shape.len() as u64 <= MAX_BISECT_BYTES);
        fs::write(repo.metadata.join("bisect.json"), &valid_shape).unwrap();
        assert_eq!(
            repo.read_bisect().unwrap().unwrap().marks.len(),
            MAX_BISECT_MARKS
        );
        // Syntactically bounded is separate from semantic replay: repeated skip
        // events must not masquerade as effective user actions.
        assert!(repo.bisect(BisectRequest::Status).is_err());
        state.marks.push(event);
        assert!(encode_bisect(&state).unwrap_err().contains("4096"));
        let mut unchecked = serde_json::to_vec(&state).unwrap();
        unchecked.push(b'\n');
        fs::write(repo.metadata.join("bisect.json"), unchecked).unwrap();
        assert!(repo.read_bisect().unwrap_err().contains("4096"));
        state.marks.clear();
        state.initial_good = (0..16384usize)
            .map(|index| format!("{index:064x}"))
            .collect();
        assert!(encode_bisect(&state).unwrap_err().contains("1 MiB"));
        fs::write(
            repo.metadata.join("bisect.json"),
            vec![b' '; MAX_BISECT_BYTES as usize + 1],
        )
        .unwrap();
        assert!(repo.read_bisect().unwrap_err().contains("1 MiB"));
        let reset = repo.bisect(BisectRequest::Reset).unwrap();
        assert!(reset.changed && !reset.active);
        assert_eq!(reset.object_verification, "not_requested");
    }

    #[test]
    fn bisect_inactive_and_reset_respect_locks_and_reset_can_recover_a_corrupt_store() {
        let temp = TempDirectory::new();
        let repo = temp.repo("bisect-inactive");
        for request in [
            BisectRequest::Status,
            BisectRequest::Log,
            BisectRequest::Next,
        ] {
            let report = repo.bisect(request).unwrap();
            assert_eq!(report.status, "inactive");
            assert!(!report.active && !report.changed);
            assert_eq!(report.object_verification, "full_snapshot");
        }
        assert!(repo
            .bisect(BisectRequest::Mark {
                kind: BisectKind::Good,
                revisions: Vec::new()
            })
            .is_err());
        assert!(!repo.bisect(BisectRequest::Reset).unwrap().changed);
        let first = repo.commit(&wasm(&[]), "first").unwrap();
        let last = repo.commit(&wasm(&[]), "last").unwrap();
        bisect_start(&repo, &last, &first, false);
        let lock = repo.lock().unwrap();
        assert!(repo
            .bisect(BisectRequest::Status)
            .unwrap_err()
            .contains("locked"));
        assert!(repo
            .bisect(BisectRequest::Reset)
            .unwrap_err()
            .contains("locked"));
        drop(lock);
        fs::write(
            repo.metadata.join("objects").join("f".repeat(64)),
            b"invalid unrelated object",
        )
        .unwrap();
        let before = stored_state(&repo);
        assert!(repo.bisect(BisectRequest::Status).is_err());
        assert!(repo.bisect(BisectRequest::Reset).unwrap().changed);
        assert_eq!(stored_state(&repo), before);
        assert!(!repo.metadata.join("bisect.json").exists());
        fs::create_dir(repo.metadata.join("bisect.json")).unwrap();
        assert!(repo.bisect(BisectRequest::Reset).is_err());
        assert!(repo.metadata.join("bisect.json").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn bisect_never_follows_a_journal_symlink_even_for_reset() {
        use std::os::unix::fs::symlink;
        let temp = TempDirectory::new();
        let repo = temp.repo("bisect-symlink");
        let outside = temp.path("outside");
        fs::write(&outside, b"preserve").unwrap();
        symlink(&outside, repo.metadata.join("bisect.json")).unwrap();
        assert!(repo.bisect(BisectRequest::Status).is_err());
        assert!(repo.bisect(BisectRequest::Reset).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"preserve");
        assert!(fs::symlink_metadata(repo.metadata.join("bisect.json"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn bundle_rejects_trailing_data_unknown_types_and_duplicate_objects() {
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        repo.commit(&wasm(&[]), "first").unwrap();
        let mut snapshot = repo.snapshot().unwrap();
        let canonical = encode_bundle(&snapshot).unwrap();
        let mut extra = canonical.clone();
        extra.push(0);
        assert!(decode_bundle(&extra).unwrap_err().contains("trailing"));
        let encoded = [OBJECT_MAGIC.as_slice(), &[99], &0u64.to_be_bytes()].concat();
        snapshot.encoded.insert(object_id(&encoded), encoded);
        assert!(decode_bundle(&encode_bundle(&snapshot).unwrap())
            .unwrap_err()
            .contains("unknown repository object type"));
        for length in [0, 7, 8, 15, canonical.len() - 1] {
            assert!(decode_bundle(&canonical[..length]).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_cannot_redirect_objects_refs_or_checkout() {
        use std::os::unix::fs::symlink;
        let temp = TempDirectory::new();
        let repo = temp.repo("repo");
        repo.commit(&wasm(&[]), "first").unwrap();
        let outside = temp.path("outside");
        fs::write(&outside, b"preserve").unwrap();
        let output = temp.path("output.wasm");
        symlink(&outside, &output).unwrap();
        assert!(repo.checkout("HEAD", &output).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"preserve");
        let reference = repo.metadata.join("refs").join("redirect");
        symlink(&outside, &reference).unwrap();
        assert!(repo.create_branch("redirect", "HEAD").is_err());
        assert!(repo.fsck().is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"preserve");
    }
}
