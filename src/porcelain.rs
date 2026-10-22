//! Multi-module index and worktree commands. File paths are stored in tree
//! commits; unnamed v1 history receives a path only from an explicit anchor.
//! Raw module bytes are never normalized or gated by a feature validator.

use crate::repository::{
    validate_tree_path, PendingIndex, PendingOperation, Repository, RevisionFiles,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "worktree_tools.rs"]
mod worktree_tools;
pub use worktree_tools::clean;
pub use worktree_tools::mergetool;
pub use worktree_tools::squash_merge;
#[path = "index_plumbing.rs"]
mod index_plumbing;
pub use index_plumbing::{index_command, index_command_handles};
#[path = "index_flags.rs"]
mod index_flags;
#[path = "index_resolve_undo.rs"]
mod index_resolve_undo;
#[path = "porcelain_replay.rs"]
mod replay_worktree;
pub use replay_worktree::{replay_control, replay_start, try_replay_control};

const OLD_MAGIC: &[u8; 9] = b"UWGITIDX\x01";
const MAGIC: &[u8; 9] = b"UWGITIDX\x02";
const STAGED_MAGIC: &[u8; 9] = b"UWGITIDX\x03";
const FLAGS_MAGIC: &[u8; 9] = b"UWGITIDX\x04";
const RESOLVE_MAGIC: &[u8; 9] = b"UWGITIDX\x05";
const WASM: &[u8; 8] = b"\0asm\x01\0\0\0";
const USAGE: &str = "tree commands: add DIR [-A|-u] [-f] [-n] [-N|--intent-to-add] [--sparse] [--] PATHSPEC...; status DIR; commit DIR [-a|--all] [--amend] [--allow-empty] [-m MESSAGE]; rm DIR [--cached] [-f] [--] [FILE...]; mv DIR [--] OLD NEW; restore DIR [--source REV] [--staged] [--worktree] [--overlay] [--ignore-skip-worktree-bits] [--output NEW_FILE] [--] [PATH...]; reset DIR [--soft|--mixed|--hard] [REV]; reset DIR [REV] -- PATH...; branch DIR [NAME [REV]|-d NAME|-D NAME|-m [OLD] NEW|-M [OLD] NEW|-c [OLD] NEW|-C [OLD] NEW|-f NAME [REV]|-r|-a|-vv|-u REMOTE/BRANCH [LOCAL_BRANCH]|--set-upstream-to REMOTE/BRANCH [LOCAL_BRANCH]|--unset-upstream [LOCAL_BRANCH]]; switch DIR NAME|-; switch DIR -c NAME [REV]; switch DIR --detach [REV]; switch DIR --orphan NAME; ls-files DIR; stash DIR [push [-m MESSAGE]|list|apply ID|pop ID|drop ID]; config DIR [KEY [VALUE]|--unset KEY]; tag DIR [NAME [REV]|-d NAME]; reflog DIR; rev-parse DIR REV (including @{upstream}, @{u}, NAME@{upstream}, NAME@{u}); cat-file DIR REV";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
type Files = BTreeMap<String, Vec<u8>>;
type Worktree = BTreeMap<String, Option<Vec<u8>>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    format: u32,
    files: Files,
    legacy_path: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    conflicts: BTreeMap<String, ConflictStages>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    flags: BTreeMap<String, IndexFlags>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    intents: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    resolve_undo: BTreeMap<String, ConflictStages>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexFlags {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    assume_unchanged: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    skip_worktree: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fsmonitor_valid: Option<String>,
}
impl IndexFlags {
    fn hidden(&self) -> bool {
        self.assume_unchanged || self.skip_worktree
    }
    fn empty(&self) -> bool {
        !self.hidden() && self.fsmonitor_valid.is_none()
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConflictStages {
    base: Option<Vec<u8>>,
    ours: Option<Vec<u8>>,
    theirs: Option<Vec<u8>>,
}
impl ConflictStages {
    fn image(&self, stage: u8) -> Option<&Vec<u8>> {
        match stage {
            1 => self.base.as_ref(),
            2 => self.ours.as_ref(),
            3 => self.theirs.as_ref(),
            _ => None,
        }
    }
}
impl Index {
    /// Keep the complete original sides when an explicit resolution removes
    /// unmerged entries. Ordinary edits of stage zero leave this record alone.
    fn resolve_path(&mut self, path: &str) {
        if let Some(stages) = self.conflicts.remove(path) {
            self.resolve_undo.insert(path.to_owned(), stages);
            self.format = self.format.max(5);
        }
    }
    fn hidden(&self, path: &str) -> bool {
        self.flags.get(path).is_some_and(IndexFlags::hidden)
    }
    fn skipped(&self, path: &str) -> bool {
        self.flags.get(path).is_some_and(|flag| flag.skip_worktree)
    }
    fn tidy(&mut self) {
        self.intents
            .retain(|path| !self.files.contains_key(path) && !self.conflicts.contains_key(path));
        self.flags.retain(|path, flag| {
            (self.files.contains_key(path) || self.intents.contains(path)) && !flag.empty()
        });
    }
    fn empty() -> Self {
        Self {
            format: 2,
            files: BTreeMap::new(),
            legacy_path: None,
            conflicts: BTreeMap::new(),
            flags: BTreeMap::new(),
            intents: BTreeSet::new(),
            resolve_undo: BTreeMap::new(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    format: u32,
    values: BTreeMap<String, String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stashes {
    format: u32,
    next_id: u64,
    entries: Vec<Stash>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stash {
    id: u64,
    message: String,
    base: String,
    index: Index,
    worktree: Worktree,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OldIndex {
    path: String,
    bytes: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OldStash {
    id: u64,
    message: String,
    base: String,
    index: OldIndex,
    worktree: Option<Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OldStashes {
    format: u32,
    next_id: u64,
    entries: Vec<OldStash>,
}

struct State {
    repo: Repository,
    metadata: PathBuf,
}

struct Lock(PathBuf, File);

impl Drop for Lock {
    fn drop(&mut self) {
        // Keep the descriptor alive until cleanup finishes.
        let _ = self.1.sync_all();
        let _ = fs::remove_file(&self.0);
    }
}

fn error(action: &str, path: &Path, error: std::io::Error) -> String {
    format!("cannot {action} {}: {error}", path.display())
}

fn regular(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(error("inspect file", path, e)),
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => fs::read(path)
            .map(Some)
            .map_err(|e| error("read file", path, e)),
        Ok(_) => Err(format!("expected a regular file: {}", path.display())),
    }
}

fn validate_wasm(bytes: &[u8]) -> Result<(), String> {
    if !bytes.starts_with(WASM) {
        return Err("expected a Core Wasm version-one binary header".into());
    }
    Ok(())
}

fn relative_path(path: &str) -> Result<(), String> {
    validate_tree_path(path)
}
fn validate_files(files: &Files) -> Result<(), String> {
    for (path, bytes) in files {
        validate_tree_path(path)?;
        validate_wasm(bytes)?;
        for (offset, _) in path.match_indices('/') {
            if files.contains_key(&path[..offset]) {
                return Err("tree contains a file/directory prefix collision".into());
            }
        }
    }
    Ok(())
}
fn validate_index(index: &Index) -> Result<(), String> {
    if !matches!(index.format, 2..=5)
        || (index.format == 2 && !index.conflicts.is_empty())
        || (index.format < 4 && (!index.flags.is_empty() || !index.intents.is_empty()))
        || (index.format < 5 && !index.resolve_undo.is_empty())
    {
        return Err("unsupported index format".into());
    }
    validate_files(&index.files)?;
    for path in &index.intents {
        validate_tree_path(path)?;
        if index.files.contains_key(path) || index.conflicts.contains_key(path) {
            return Err("intent-to-add cannot overlap a stored index image".into());
        }
    }
    for (path, flag) in &index.flags {
        validate_tree_path(path)?;
        if flag.empty() || (!index.files.contains_key(path) && !index.intents.contains(path)) {
            return Err("index flags require a resolved entry or intent-to-add path".into());
        }
        if flag.fsmonitor_valid.as_ref().is_some_and(|id| {
            id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err("invalid native fsmonitor image digest".into());
        }
        if flag.fsmonitor_valid.as_ref().is_some_and(|id| {
            index
                .files
                .get(path)
                .is_none_or(|bytes| index_flags::digest(bytes) != *id)
        }) {
            return Err("native fsmonitor digest must identify its stored index image".into());
        }
    }
    for (path, stages) in &index.conflicts {
        validate_tree_path(path)?;
        if index.files.contains_key(path)
            || (stages.base.is_none() && stages.ours.is_none() && stages.theirs.is_none())
        {
            return Err(
                "index stage zero overlaps unmerged stages, or all stages are absent".into(),
            );
        }
        for bytes in stages.base.iter().chain(&stages.ours).chain(&stages.theirs) {
            validate_wasm(bytes)?;
        }
    }
    // Undo records can describe resolutions from different steps, so their
    // paths need not form a single tree. Reinstating a selection validates the
    // resulting complete index before publication, including D/F conflicts.
    for (path, stages) in &index.resolve_undo {
        validate_tree_path(path)?;
        if stages.base.is_none() && stages.ours.is_none() && stages.theirs.is_none() {
            return Err("resolve-undo record must retain at least one original stage".into());
        }
        for bytes in stages.base.iter().chain(&stages.ours).chain(&stages.theirs) {
            validate_wasm(bytes)?;
        }
    }
    // A directory/file conflict may span different stages, but each original
    // side together with the resolved entries must still be a valid tree.
    for stage in 1..=3 {
        let paths: BTreeSet<_> = index
            .files
            .keys()
            .chain(index.intents.iter())
            .chain(
                index
                    .conflicts
                    .iter()
                    .filter_map(|(path, images)| images.image(stage).map(|_| path)),
            )
            .map(String::as_str)
            .collect();
        for path in &paths {
            if path
                .match_indices('/')
                .any(|(offset, _)| paths.contains(&path[..offset]))
            {
                return Err(format!(
                    "index stage {stage} has a file/directory prefix collision"
                ));
            }
        }
    }
    if let Some(path) = &index.legacy_path {
        validate_tree_path(path)?;
    }
    Ok(())
}
fn index_bytes(index: &Index) -> Result<Vec<u8>, String> {
    let mut normalized = index.clone();
    normalized.tidy();
    if !normalized.resolve_undo.is_empty() {
        normalized.format = normalized.format.max(5);
    } else if !normalized.flags.is_empty() || !normalized.intents.is_empty() {
        normalized.format = normalized.format.max(4);
    } else if !normalized.conflicts.is_empty() && normalized.format < 3 {
        normalized.format = 3;
    }
    validate_index(&normalized)?;
    let mut bytes = if normalized.format == 5 {
        RESOLVE_MAGIC
    } else if normalized.format == 4 {
        FLAGS_MAGIC
    } else if normalized.format == 3 {
        STAGED_MAGIC
    } else {
        MAGIC
    }
    .to_vec();
    bytes.extend_from_slice(&canonical(&normalized)?);
    Ok(bytes)
}
fn decode_index(bytes: &[u8]) -> Result<Index, String> {
    if let Some(payload) = bytes.strip_prefix(RESOLVE_MAGIC) {
        let index: Index = decode_canonical(payload)?;
        if index.format != 5 {
            return Err("resolve-undo index magic/format mismatch".into());
        }
        validate_index(&index)?;
        return Ok(index);
    }
    if let Some(payload) = bytes.strip_prefix(FLAGS_MAGIC) {
        let index: Index = decode_canonical(payload)?;
        if index.format != 4 {
            return Err("flag index magic/format mismatch".into());
        }
        validate_index(&index)?;
        return Ok(index);
    }
    if let Some(payload) = bytes.strip_prefix(STAGED_MAGIC) {
        let index: Index = decode_canonical(payload)?;
        if index.format != 3 {
            return Err("extended index magic/format mismatch".into());
        }
        validate_index(&index)?;
        return Ok(index);
    }
    if let Some(payload) = bytes.strip_prefix(MAGIC) {
        let index: Index = decode_canonical(payload)?;
        if index.format != 2 {
            return Err("index magic/format mismatch".into());
        }
        validate_index(&index)?;
        return Ok(index);
    }
    if bytes.len() < 25 || !bytes.starts_with(OLD_MAGIC) {
        return Err("invalid index header".into());
    }
    let path_len = usize::try_from(u64::from_le_bytes(bytes[9..17].try_into().unwrap()))
        .map_err(|_| "index path length exceeds this host")?;
    let wasm_len = usize::try_from(u64::from_le_bytes(bytes[17..25].try_into().unwrap()))
        .map_err(|_| "index module length exceeds this host")?;
    let split = 25usize
        .checked_add(path_len)
        .ok_or("invalid index length")?;
    if split.checked_add(wasm_len) != Some(bytes.len()) {
        return Err("index lengths do not match payload".into());
    }
    let path = std::str::from_utf8(&bytes[25..split])
        .map_err(|_| "index path is not UTF-8")?
        .to_owned();
    let index = Index {
        format: 2,
        files: BTreeMap::from([(path.clone(), bytes[split..].to_vec())]),
        legacy_path: Some(path),
        conflicts: BTreeMap::new(),
        flags: BTreeMap::new(),
        intents: BTreeSet::new(),
        resolve_undo: BTreeMap::new(),
    };
    validate_index(&index)?;
    Ok(index)
}

fn require_resolved_index(index: &Index) -> Result<(), String> {
    if index.conflicts.is_empty() {
        Ok(())
    } else {
        Err("index has unresolved native Wasm stages; resolve them with add/rm or update-index before publishing a tree".into())
    }
}

pub fn replay_baseline_files(
    raw: Option<&[u8]>,
    head: &RevisionFiles,
    anchor: Option<&str>,
    allow_staged: bool,
) -> Result<Files, String> {
    let files = if let Some(raw) = raw {
        let index = decode_index(raw)?;
        require_resolved_index(&index)?;
        if !index.intents.is_empty() {
            return Err(
                "replay requires complete images; stage or remove intent-to-add paths first".into(),
            );
        }
        if index.legacy_path.as_deref() != anchor {
            return Err("replay baseline changed its path anchor".into());
        }
        index.files
    } else {
        head.files.clone()
    };
    if !allow_staged && files != head.files {
        return Err("committing replay requires the complete unchanged HEAD index".into());
    }
    validate_files(&files)?;
    Ok(files)
}
pub fn validate_replay_initial_worktree(
    raw: Option<&[u8]>,
    work: &Worktree,
    allow_dirty: bool,
) -> Result<(), String> {
    let index = raw
        .map(decode_index)
        .transpose()?
        .unwrap_or_else(Index::empty);
    if work.keys().cloned().collect::<BTreeSet<_>>() != controlled_paths(&index) {
        return Err("replay baseline work scope differs from its original index".into());
    }
    if !allow_dirty {
        for (path, image) in work {
            if image.as_ref() != index.files.get(path) && !(image.is_none() && index.skipped(path))
            {
                return Err("committing replay baseline contains dirty work bytes".into());
            }
        }
    }
    Ok(())
}
pub fn validate_replay_checkpoint(
    checkpoint: &crate::repository::ReplayCheckpoint,
    images: &crate::repository::ReplayImages,
    anchor: Option<&str>,
    original_work: Option<&Worktree>,
) -> Result<(), String> {
    let after = decode_index(&checkpoint.index_after)?;
    let conflicts: BTreeMap<_, _> = images
        .conflicts
        .iter()
        .map(|(path, sides)| {
            (
                path.clone(),
                ConflictStages {
                    base: sides[0].clone(),
                    ours: sides[1].clone(),
                    theirs: sides[2].clone(),
                },
            )
        })
        .collect();
    if after.files != images.files
        || after.conflicts != conflicts
        || !after.intents.is_empty()
        || after.legacy_path.as_deref() != anchor
    {
        return Err("replay checkpoint differs from its exact native images".into());
    }
    let before = checkpoint
        .index_before
        .as_deref()
        .map(decode_index)
        .transpose();
    let before = match before {
        Ok(index) => index.unwrap_or_else(Index::empty),
        Err(_) if checkpoint.action == "skip" => Index::empty(),
        Err(e) => return Err(e),
    };
    if after.resolve_undo != before.resolve_undo {
        return Err("replay checkpoint changed its saved resolve-undo images".into());
    }
    let scope: BTreeSet<_> = checkpoint
        .owned_before
        .iter()
        .cloned()
        .chain(controlled_paths(&after))
        .collect();
    if checkpoint
        .work_after
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != scope
    {
        return Err("replay checkpoint changed its controlled work scope".into());
    }
    for (path, value) in &checkpoint.work_after {
        let expected = after.files.get(path).or_else(|| {
            after
                .conflicts
                .get(path)
                .and_then(|side| side.ours.as_ref())
        });
        let original = checkpoint.work_before.get(path).and_then(Option::as_ref);
        let old = before.files.get(path).or_else(|| {
            before
                .conflicts
                .get(path)
                .and_then(|side| side.ours.as_ref())
        });
        let preserved =
            (checkpoint.action == "skip" || old == expected) && value.as_ref() == original;
        let restored = checkpoint.action == "skip"
            && original_work.and_then(|work| work.get(path)) == Some(value);
        let sparse = after.skipped(path) && value.is_none() && (original.is_none() || restored);
        if value.as_ref() != expected && !preserved && !sparse && !restored {
            return Err(format!(
                "replay checkpoint work image is unrelated to its result: {path}"
            ));
        }
    }
    Ok(())
}
fn controlled_paths(index: &Index) -> BTreeSet<String> {
    index
        .files
        .keys()
        .chain(index.conflicts.keys())
        .chain(index.intents.iter())
        .cloned()
        .collect()
}

/// Validate an immutable operation backup without consulting mutable repository
/// metadata. Callers may hold the repository writer lock.
pub fn validate_pending_baseline(
    raw: Option<&[u8]>,
    head: &RevisionFiles,
    legacy_path: Option<&str>,
) -> Result<(), String> {
    if let Some(path) = legacy_path {
        validate_tree_path(path)?;
    }
    if head.legacy.is_none() && head.legacy_path.as_deref() != legacy_path {
        return Err("pending baseline must retain the committed legacy path".into());
    }
    if head
        .legacy_path
        .as_deref()
        .is_some_and(|path| Some(path) != legacy_path)
    {
        return Err("pending baseline changed the history's legacy path".into());
    }
    let Some(raw) = raw else {
        if head.legacy.is_some() {
            return Err("pending operation on unnamed legacy history requires an existing index with an explicit path".into());
        }
        return Ok(());
    };
    let index = decode_index(raw)?;
    require_resolved_index(&index)?;
    if index.legacy_path.as_deref() != legacy_path {
        return Err("pending baseline index has a different legacy path".into());
    }
    let mut files = head.files.clone();
    if let Some(bytes) = &head.legacy {
        files.insert(
            legacy_path
                .ok_or("pending legacy baseline requires an explicit path")?
                .to_owned(),
            bytes.clone(),
        );
    }
    validate_files(&files)?;
    if index.files != files {
        return Err("pending baseline index must contain the complete unchanged HEAD tree".into());
    }
    Ok(())
}

/// The publisher receives both decoded files and their original encoding; they
/// must describe precisely the same complete index.
pub fn validate_pending_resolution_index(
    raw: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    legacy_path: Option<&str>,
) -> Result<(), String> {
    let index = decode_index(raw)?;
    require_resolved_index(&index)?;
    if index.files != *files || index.legacy_path.as_deref() != legacy_path {
        return Err(
            "pending resolution index bytes do not match its supplied files or legacy path".into(),
        );
    }
    Ok(())
}
fn decode_canonical<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let value: T = serde_json::from_slice(bytes).map_err(|e| format!("invalid metadata: {e}"))?;
    if canonical(&value)? != bytes {
        return Err("noncanonical metadata".into());
    }
    Ok(value)
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| format!("encode metadata: {e}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_json<T: Serialize + DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    let Some(bytes) = regular(path)? else {
        return Ok(None);
    };
    let value: T =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid {}: {e}", path.display()))?;
    if canonical(&value)? != bytes {
        return Err(format!("noncanonical metadata: {}", path.display()));
    }
    Ok(Some(value))
}

impl State {
    fn open(root: &str) -> Result<Self, String> {
        let repo = Repository::open(root)?;
        let metadata = repo.root.join(".uwgit");
        Ok(Self { repo, metadata })
    }

    fn metadata_directories(&self) -> Result<(), String> {
        let temporary = self.metadata.join("tmp");
        for path in [&self.repo.root, &self.metadata, &temporary] {
            let metadata = fs::symlink_metadata(path)
                .map_err(|e| error("inspect metadata directory", path, e))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("repository metadata directories must be real directories".into());
            }
        }
        Ok(())
    }

    fn lock(&self) -> Result<Lock, String> {
        self.metadata_directories()?;
        let path = self.metadata.join("index.lock");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| error("lock worktree metadata", &path, e))?;
        Ok(Lock(path, file))
    }

    fn index(&self) -> Result<Option<Index>, String> {
        self.metadata_directories()?;
        regular(&self.metadata.join("index"))?
            .map(|bytes| decode_index(&bytes))
            .transpose()
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.metadata_directories()?;
        let path = self.metadata.join(name);
        regular(&path)?;
        let temporary = self.metadata.join("tmp").join(format!(
            "porcelain-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| error("create metadata staging file", &temporary, e))?;
        let result = file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| error("write metadata staging file", &temporary, e));
        drop(file);
        if let Err(e) = result {
            let _ = fs::remove_file(&temporary);
            return Err(e);
        }
        // Refuse a symlink installed since the initial read as well.
        let result = regular(&path).and_then(|_| {
            fs::rename(&temporary, &path).map_err(|e| error("publish metadata", &path, e))
        });
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        File::open(&self.metadata)
            .and_then(|file| file.sync_all())
            .map_err(|e| error("sync metadata directory", &self.metadata, e))
    }

    fn worktree(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        regular(&self.worktree_path(path)?)
    }

    fn worktree_path(&self, path: &str) -> Result<PathBuf, String> {
        relative_path(path)?;
        let mut result = self.repo.root.clone();
        let parts: Vec<_> = Path::new(path).components().collect();
        for (position, part) in parts.iter().enumerate() {
            result.push(part.as_os_str());
            if position + 1 < parts.len() {
                match fs::symlink_metadata(&result) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(error("inspect tracked directory", &result, e)),
                    Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                    Ok(_) => return Err("tracked path contains a non-directory or symlink".into()),
                }
            }
        }
        Ok(result)
    }

    fn create_parents(&self, value: &str) -> Result<(), String> {
        let path = self.worktree_path(value)?;
        let relative = path
            .parent()
            .ok_or("tracked file has no parent")?
            .strip_prefix(&self.repo.root)
            .map_err(|_| "tracked path escaped repository")?;
        let mut cursor = self.repo.root.clone();
        for component in relative.components() {
            cursor.push(component.as_os_str());
            match fs::create_dir(&cursor) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(&cursor)
                        .map_err(|e| error("inspect tracked directory", &cursor, e))?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err("tracked parent is not a real directory".into());
                    }
                }
                Err(e) => return Err(error("create tracked directory", &cursor, e)),
            }
        }
        Ok(())
    }

    /// Replace only the explicitly tracked regular file. The caller holds the
    /// index lock, and both reads detect ordinary concurrent editor changes.
    /// External directory renames are outside this process-local lock's scope.
    fn replace_worktree(
        &self,
        path: &str,
        expected: &Option<Vec<u8>>,
        replacement: Option<&[u8]>,
    ) -> Result<(), String> {
        let destination = self.worktree_path(path)?;
        if &regular(&destination)? != expected {
            return Err("tracked file changed concurrently".into());
        }
        let parent = destination.parent().ok_or("tracked file has no parent")?;
        if let Some(bytes) = replacement {
            self.create_parents(path)?;
            let temporary = parent.join(format!(
                ".uwgit-worktree-{}-{}.tmp",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|e| error("create worktree staging file", &temporary, e))?;
            let written = file
                .write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| error("write worktree staging file", &temporary, e));
            drop(file);
            let result = written.and_then(|()| {
                if &self.worktree(path)? != expected {
                    return Err("tracked file changed concurrently".into());
                }
                if expected.is_none() {
                    fs::hard_link(&temporary, &destination)
                        .map_err(|e| error("publish new tracked file", &destination, e))?;
                    fs::remove_file(&temporary)
                        .map_err(|e| error("remove worktree staging file", &temporary, e))
                } else {
                    fs::rename(&temporary, &destination)
                        .map_err(|e| error("publish tracked file", &destination, e))
                }
            });
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result?;
        } else if expected.is_some() {
            fs::remove_file(&destination)
                .map_err(|e| error("remove tracked file", &destination, e))?;
        }
        if parent.exists() {
            File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|e| error("sync tracked directory", parent, e))?;
        }
        Ok(())
    }

    fn output(&self, destination: &str, bytes: &[u8]) -> Result<(), String> {
        crate::output::write_export_file(Path::new(destination), bytes)
    }

    fn head(&self) -> Result<Option<String>, String> {
        let state = self.repo.state()?;
        Ok(state.tip().cloned())
    }

    fn save_index(&self, index: &Index) -> Result<(), String> {
        self.write("index", &index_bytes(index)?)
    }
    fn revision_index(&self, revision: &str, anchor: Option<&str>) -> Result<Index, String> {
        let value = self.repo.files_at(revision)?;
        let legacy_path = value.legacy_path.or_else(|| {
            if value.legacy.is_some() {
                anchor.map(str::to_owned)
            } else {
                None
            }
        });
        let mut files = value.files;
        if let Some(bytes) = value.legacy {
            let path = legacy_path.as_ref().ok_or(
                "unnamed v1 revision requires an explicit legacy path; use add DIR PATH first",
            )?;
            files.insert(path.clone(), bytes);
        }
        let index = Index {
            format: 2,
            files,
            legacy_path,
            conflicts: BTreeMap::new(),
            flags: BTreeMap::new(),
            intents: BTreeSet::new(),
            resolve_undo: BTreeMap::new(),
        };
        validate_index(&index)?;
        Ok(index)
    }
    fn starting_index(&self, chosen_path: Option<&str>) -> Result<Index, String> {
        if let Some(mut index) = self.index()? {
            if let Some(path) = chosen_path.filter(|_| index.legacy_path.is_none()) {
                let legacy_head = self
                    .head()?
                    .map(|id| self.repo.files_at(&id))
                    .transpose()?
                    .is_some_and(|head| head.legacy.is_some());
                if legacy_head {
                    validate_tree_path(path)?;
                    index.legacy_path = Some(path.to_owned());
                }
            }
            return Ok(index);
        }
        match self.head()? {
            Some(id) => self.revision_index(&id, chosen_path),
            None => Ok(Index::empty()),
        }
    }
    fn snapshot_worktree(
        &self,
        paths: impl IntoIterator<Item = String>,
    ) -> Result<Worktree, String> {
        paths
            .into_iter()
            .map(|p| Ok((p.clone(), self.worktree_module(&p)?)))
            .collect()
    }
    // A directory, or a path below a regular file, is absent as a module at
    // this exact name. Mutations still use strict observations and ownership
    // checks; this read cannot authorize overwriting either obstruction.
    fn worktree_module(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        validate_tree_path(path)?;
        let mut cursor = self.repo.root.clone();
        let mut relative = String::new();
        let components: Vec<_> = path.split('/').collect();
        for (position, component) in components.iter().enumerate() {
            if !relative.is_empty() {
                relative.push('/');
            }
            relative.push_str(component);
            cursor.push(component);
            match fs::symlink_metadata(&cursor) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(error("inspect tracked path", &cursor, e)),
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(format!("tracked path contains a symlink: {relative}"));
                }
                Ok(metadata) if position + 1 < components.len() => {
                    if metadata.is_file() {
                        return Ok(None);
                    }
                    if !metadata.is_dir() {
                        return Err(format!(
                            "tracked parent is not a real directory: {relative}"
                        ));
                    }
                }
                Ok(metadata) if metadata.is_dir() => {
                    return Ok(None);
                }
                Ok(_) => return regular(&cursor),
            }
        }
        unreachable!("validated paths have at least one component")
    }
    fn stashes(&self) -> Result<Stashes, String> {
        self.metadata_directories()?;
        let Some(bytes) = regular(&self.metadata.join("stash"))? else {
            return Ok(Stashes {
                format: 2,
                next_id: 0,
                entries: Vec::new(),
            });
        };
        let version = serde_json::from_slice::<Value>(&bytes)
            .map_err(|e| format!("invalid stash metadata: {e}"))?["format"]
            .as_u64();
        let value = if version == Some(1) {
            let old: OldStashes = decode_canonical(&bytes)?;
            Stashes {
                format: 2,
                next_id: old.next_id,
                entries: old
                    .entries
                    .into_iter()
                    .map(|e| {
                        let p = e.index.path;
                        Stash {
                            id: e.id,
                            message: e.message,
                            base: e.base,
                            index: Index {
                                format: 2,
                                files: BTreeMap::from([(p.clone(), e.index.bytes)]),
                                legacy_path: Some(p.clone()),
                                conflicts: BTreeMap::new(),
                                flags: BTreeMap::new(),
                                intents: BTreeSet::new(),
                                resolve_undo: BTreeMap::new(),
                            },
                            worktree: BTreeMap::from([(p, e.worktree)]),
                        }
                    })
                    .collect(),
            }
        } else {
            decode_canonical::<Stashes>(&bytes)?
        };
        if value.format != 2 {
            return Err("unsupported stash format".into());
        }
        let mut previous = None;
        for e in &value.entries {
            validate_index(&e.index)?;
            require_resolved_index(&e.index)?;
            if !e.index.intents.is_empty() {
                return Err("stash index contains intent-to-add without a saved image".into());
            }
            if e.base.len() != 64
                || !e
                    .base
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid stash base commit".into());
            }
            if e.id >= value.next_id || previous.is_some_and(|p| p >= e.id) {
                return Err("invalid stash sequence".into());
            }
            for p in e.worktree.keys() {
                validate_tree_path(p)?;
            }
            previous = Some(e.id);
        }
        Ok(value)
    }

    fn config(&self) -> Result<Config, String> {
        self.metadata_directories()?;
        let config = read_json::<Config>(&self.metadata.join("config"))?.unwrap_or(Config {
            format: 1,
            values: BTreeMap::new(),
        });
        if config.format != 1 {
            return Err("unsupported config format".into());
        }
        for (name, value) in &config.values {
            config_value(name, value)?;
        }
        Ok(config)
    }
}

fn config_value(name: &str, value: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name.contains('.')
        || name.split('.').any(str::is_empty)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        || value.len() > 4096
        || value.chars().any(char::is_control)
    {
        return Err("invalid config key or value".into());
    }
    Ok(())
}

fn json_text(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|e| format!("encode command output: {e}"))
}

/// The first argument is the command name. Existing file-based commit and
/// checkout remain in repository::run; this dispatcher handles staged commit.
pub fn run(args: &[String]) -> Result<String, String> {
    if crate::command_args::help_requested(args) {
        return Ok(USAGE.into());
    }
    if args.len() < 2 {
        return Err(USAGE.into());
    }
    let state = State::open(&args[1])?;
    let _lock = state.lock()?;
    guard_pending_command(&state, args)?;
    match args[0].as_str() {
        "add" if args.len() > 2 => add(&state, &args[2..]),
        "status" if args.len() == 2 => status(&state),
        "commit" => commit(&state, args),
        "rm" => remove(&state, args),
        "mv" => match path_operands(&args[2..]).as_slice() {
            [old, new] => move_tracked(&state, old, new),
            _ => Err(USAGE.into()),
        },
        "restore" => restore(&state, args),
        "reset" => reset(&state, args),
        "branch" => branch(&state, args),
        "switch" => switch(&state, args),
        "stash" => stash(&state, args),
        "config" => config(&state, args),
        "ls-files" if args.len() == 2 => Ok(state
            .index()?
            .map(|i| i.files.keys().cloned().collect::<Vec<_>>().join("\n"))
            .unwrap_or_default()),
        "rev-parse" if args.len() == 3 => resolve_revision(&state.repo, &args[2]),
        "cat-file" if args.len() == 3 => json_text(&state.repo.read_commit(&args[2])?),
        "cat-file" if args.len() == 4 && matches!(args[2].as_str(), "-t" | "-s" | "-p") => {
            let (_, kind, bytes) = state.repo.resolve_object(&args[3])?;
            match args[2].as_str() {
                "-t" => Ok(kind),
                "-s" => Ok(bytes.len().to_string()),
                _ if kind != "wasm" => {
                    String::from_utf8(bytes).map_err(|_| "object metadata is not UTF-8".into())
                }
                _ => Err("binary Wasm requires --output NEW_FILE".into()),
            }
        }
        "cat-file" if args.len() == 5 && args[3] == "--output" => {
            let (_, bytes) = state.repo.cat_object(&args[2])?;
            state.output(&args[4], &bytes)?;
            Ok(format!("wrote object {}", args[2]))
        }
        "tag" if args.len() == 2 => json_text(&state.repo.tags()?),
        "tag" if args.len() == 4 && args[2] == "-d" => state.repo.delete_tag(&args[3]),
        "tag" if (3..=4).contains(&args.len()) => state
            .repo
            .create_tag(&args[2], args.get(3).map_or("HEAD", String::as_str)),
        "reflog" if args.len() == 2 => json_text(&state.repo.reflog()?),
        _ => Err(USAGE.into()),
    }
}

/// Plumbing publishes immutable tree objects without moving HEAD or index.
pub fn write_tree(root: &str, prefix: Option<&str>) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let index = state
        .index()?
        .ok_or("write-tree requires an existing index")?;
    require_resolved_index(&index)?;
    let Some(prefix) = prefix else {
        return state.repo.create_files_tree(&index.files);
    };
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    validate_tree_path(prefix)?;
    let prefix = format!("{prefix}/");
    let files: Files = index
        .files
        .iter()
        .filter_map(|(path, bytes)| {
            path.strip_prefix(&prefix)
                .map(|relative| (relative.to_owned(), bytes.clone()))
        })
        .collect();
    if files.is_empty() {
        return Err("write-tree prefix does not name an indexed directory".into());
    }
    state.repo.create_files_tree(&files)
}

pub fn encode_worktree_index(files: &Files, legacy_path: Option<&str>) -> Result<Vec<u8>, String> {
    index_bytes(&Index {
        format: 2,
        files: files.clone(),
        legacy_path: legacy_path.map(str::to_owned),
        conflicts: BTreeMap::new(),
        flags: BTreeMap::new(),
        intents: BTreeSet::new(),
        resolve_undo: BTreeMap::new(),
    })
}

pub fn remove_linked_worktree(source: &str, target: &str, force: bool) -> Result<String, String> {
    let state = State::open(target)?;
    let _lock = state.lock()?;
    require_no_pending(&state.repo)?;
    if state.repo.root.join(".git").symlink_metadata().is_ok() {
        return Err(
            "worktree root also contains native Git metadata; remove refuses it even with --force"
                .into(),
        );
    }
    let source = Repository::open(source)?;
    if fs::canonicalize(source.common_metadata()).map_err(|error| error.to_string())?
        != fs::canonicalize(state.repo.common_metadata()).map_err(|error| error.to_string())?
    {
        return Err("worktree belongs to a different repository".into());
    }
    let index = state.index()?.ok_or("linked worktree has no index")?;
    if !force {
        clean_index(&state)?;
        if !state.stashes()?.entries.is_empty() {
            return Err("worktree contains local stash entries; use --force explicitly".into());
        }
    }
    let mut directories = vec![state.repo.root.clone()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let full = entry.path();
            if full == state.metadata {
                continue;
            }
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_symlink() || (!kind.is_dir() && !kind.is_file()) {
                return Err("worktree remove refuses symbolic links or special files".into());
            }
            if kind.is_dir() {
                if full.join(".uwgit").exists() || full.join(".git").exists() {
                    return Err("worktree contains a nested repository".into());
                }
                directories.push(full);
            } else if !force {
                let path = full
                    .strip_prefix(&state.repo.root)
                    .map_err(|_| "worktree file escaped root")?
                    .to_str()
                    .ok_or("worktree removal requires UTF-8 paths")?;
                if !index.files.contains_key(path) {
                    return Err(format!(
                        "worktree contains untracked file {path:?}; use --force explicitly"
                    ));
                }
            }
        }
    }
    json_text(&source.remove_linked_worktree(&state.repo.root)?)
}

pub fn move_linked_worktree(source: &str, target: &str, new_path: &str) -> Result<String, String> {
    let state = State::open(target)?;
    let mut lock = state.lock()?;
    let source = Repository::open(source)?;
    if fs::canonicalize(source.common_metadata()).map_err(|error| error.to_string())?
        != fs::canonicalize(state.repo.common_metadata()).map_err(|error| error.to_string())?
    {
        return Err("worktree belongs to a different repository".into());
    }
    let result = source.move_linked_worktree(&state.repo.root, Path::new(new_path));
    if !state.repo.root.exists() {
        if let Ok(moved) = fs::canonicalize(new_path) {
            lock.0 = moved.join(".uwgit/index.lock");
        }
    }
    json_text(&result?)
}

/// Replace only the index with a complete immutable tree. Existing work bytes
/// and pending conflict state remain available for explicit review.
pub fn read_tree(root: &str, revision: Option<&str>) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let index = if let Some(revision) = revision {
        let snapshot = state.repo.archive_files(revision)?;
        if snapshot.legacy.is_some() {
            return Err(
                "read-tree requires a named tree; use restore with an explicit legacy path".into(),
            );
        }
        Index {
            format: 2,
            files: snapshot.files,
            legacy_path: snapshot.legacy_path,
            conflicts: BTreeMap::new(),
            flags: BTreeMap::new(),
            intents: BTreeSet::new(),
            resolve_undo: BTreeMap::new(),
        }
    } else {
        Index::empty()
    };
    state.save_index(&index)?;
    json_text(
        &json!({"status":"read_tree","paths":index.files.keys().collect::<Vec<_>>(),"worktree_updated":false,"head_updated":false}),
    )
}

pub fn garbage_collect(root: &str, prune: bool) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let roots: Vec<_> = state
        .stashes()?
        .entries
        .into_iter()
        .map(|stash| stash.base)
        .collect();
    json_text(&state.repo.garbage_collect(&roots, prune)?)
}

/// Ordinary history writes cannot accidentally replace a recorded resolution.
/// Preparation commands remain available while the user edits the full index.
fn guard_pending_command(state: &State, args: &[String]) -> Result<(), String> {
    let command = args[0].as_str();
    let blocked = match command {
        "commit" | "switch" => true,
        "reset" => crate::command_args::separator_index(args).is_none(),
        "stash" => matches!(
            args.get(2).map_or("push", String::as_str),
            "push" | "apply" | "pop"
        ),
        _ => false,
    };
    if blocked {
        require_no_pending(&state.repo)?;
    }
    if command == "branch" {
        let affected = match &args[2..] {
            [option, branch] if matches!(option.as_str(), "-d" | "-D") => Some(branch.clone()),
            [option, _] if option == "-m" => Some(state.repo.current_branch()?),
            [option, old, _] if option == "-m" => Some(old.clone()),
            _ => None,
        };
        if let Some(affected) = affected {
            if let Some(pending) = state.repo.pending()? {
                if pending.branch == affected {
                    return Err(format!(
                        "branch {affected} belongs to pending {}; finish it with --continue, --abort or --quit before renaming or deleting it",
                        pending.operation
                    ));
                }
            }
        }
    }
    Ok(())
}

fn require_no_pending(repo: &Repository) -> Result<(), String> {
    if let Some(pending) = repo.pending()? {
        return Err(format!(
            "pending {} on branch {}; finish it with --continue, --abort or --quit before starting another history operation",
            pending.operation, pending.branch
        ));
    }
    Ok(())
}
fn path_operands(args: &[String]) -> Vec<String> {
    let mut literal = false;
    let mut paths = Vec::new();
    for arg in args {
        if !literal && arg == "--" {
            literal = true;
        } else {
            paths.push(arg.clone());
        }
    }
    paths
}
fn add(state: &State, paths: &[String]) -> Result<String, String> {
    let (mut all, mut update, mut force, mut dry_run, mut literal) =
        (false, false, false, false, false);
    let (mut intent, mut sparse) = (false, false);
    let mut selectors = Vec::new();
    for arg in paths {
        if literal {
            selectors.push(arg.clone());
            continue;
        }
        match arg.as_str() {
            "--" => literal = true,
            "-A" | "--all" => all = true,
            "-u" | "--update" => update = true,
            "-f" | "--force" => force = true,
            "-n" | "--dry-run" => dry_run = true,
            "-N" | "--intent-to-add" => intent = true,
            "--sparse" => sparse = true,
            option if option.starts_with('-') => {
                return Err(format!("unsupported add option: {option}"))
            }
            _ => selectors.push(arg.clone()),
        }
    }
    if all && update {
        return Err("add --all and --update are mutually exclusive".into());
    }
    if selectors.is_empty() && !all && !update {
        return Err(USAGE.into());
    }
    let anchor = selectors
        .first()
        .filter(|path| {
            selectors.len() == 1
                && !path.contains(['*', '?', '[', ':'])
                && validate_tree_path(path).is_ok()
        })
        .map(String::as_str);
    let mut index = state.starting_index(anchor)?;
    let mut candidates = controlled_paths(&index);
    if !update {
        for path in worktree_tools::visible_paths(&state.repo.root, !force)? {
            let full = state.worktree_path(&path)?;
            if full.is_file() && has_wasm_header(&full)? {
                candidates.insert(path);
            }
        }
    }
    let selected = select_paths(&candidates, &selectors)?;
    if !sparse
        && !selectors.is_empty()
        && selected.iter().all(|path| index.skipped(path))
        && !selected.is_empty()
    {
        return Err(
            "selected paths are skip-worktree; use --sparse to stage them explicitly".into(),
        );
    }
    let mut count = 0;
    for path in &selected {
        if intent && index.conflicts.contains_key(path) {
            return Err("intent-to-add cannot resolve unmerged images; stage actual bytes or remove the path".into());
        }
        if index.skipped(path) && !sparse {
            continue;
        }
        if index
            .flags
            .get(path)
            .is_some_and(|flag| flag.assume_unchanged)
        {
            continue;
        }
        if intent && index.files.contains_key(path) {
            continue;
        }
        index.resolve_path(path);
        match state.worktree_module(path)? {
            Some(bytes) => {
                validate_wasm(&bytes)?;
                if intent {
                    index.intents.insert(path.clone());
                    index.format = index.format.max(4);
                } else {
                    index.files.insert(path.clone(), bytes);
                    index.intents.remove(path);
                    if let Some(flag) = index.flags.get_mut(path) {
                        flag.fsmonitor_valid = None;
                    }
                }
            }
            None => {
                index.files.remove(path);
                index.intents.remove(path);
            }
        }
        count += 1;
    }
    index.tidy();
    validate_index(&index)?;
    if !dry_run && !selected.is_empty() {
        state.save_index(&index)?;
    }
    Ok(format!(
        "{} {} paths; {} paths in index",
        if dry_run { "would stage" } else { "staged" },
        count,
        index.files.len()
    ))
}
fn has_wasm_header(path: &Path) -> Result<bool, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| error("inspect untracked file", path, e))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("untracked file changed type during scan".into());
    }
    let mut file = File::open(path).map_err(|e| error("open untracked file", path, e))?;
    let mut header = [0u8; 8];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(&header == WASM),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(error("read untracked header", path, e)),
    }
}
fn scan_untracked(state: &State, tracked: &BTreeSet<String>) -> Result<Vec<String>, String> {
    let mut pending = vec![state.repo.root.clone()];
    let mut result = Vec::new();
    while let Some(directory) = pending.pop() {
        let m = fs::symlink_metadata(&directory)
            .map_err(|e| error("inspect worktree directory", &directory, e))?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err("worktree scan encountered redirected directory".into());
        }
        for e in fs::read_dir(&directory).map_err(|e| error("scan worktree", &directory, e))? {
            let e = e.map_err(|e| format!("scan worktree entry: {e}"))?;
            let path = e.path();
            let p = path
                .strip_prefix(&state.repo.root)
                .map_err(|_| "worktree scan escaped repository")?
                .to_str()
                .ok_or("non-UTF-8 worktree path")?
                .to_owned();
            if p.split('/').any(|v| v.eq_ignore_ascii_case(".uwgit")) {
                continue;
            }
            let kind = e
                .file_type()
                .map_err(|e| error("inspect worktree entry", &path, e))?;
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() && !tracked.contains(&p) && has_wasm_header(&path)? {
                validate_tree_path(&p)?;
                result.push(p);
            }
        }
    }
    result.sort();
    Ok(result)
}

fn pending_status(
    pending: &PendingOperation,
    current_branch: &str,
    current_head: Option<&String>,
) -> Value {
    let already_published = pending.prepared.as_ref().is_some_and(|prepared| {
        pending.matches_head_identity(current_branch) && current_head == Some(&prepared.commit)
    });
    let matches_original = current_branch == pending.branch && current_head == Some(&pending.head);
    let mut report = json!({
        "id":pending.id,
        "operation":pending.operation,
        "branch":pending.branch,
        "head":pending.head,
        "target":pending.target,
        "base":pending.base,
        "selected_parent":pending.selected_parent,
        "mainline":pending.mainline,
        "phase":if already_published { "published" } else if pending.prepared.is_some() { "prepared" } else { "conflict" },
        "prepared_commit":pending.prepared.as_ref().map(|prepared| &prepared.commit),
        "stale":!matches_original && !already_published,
        "index_before_present":pending.baseline_index.is_some(),
        "complete_index_required":true
    });
    if let Some(rebase) = &pending.rebase {
        report["rebase"] = json!({
            "upstream":rebase.upstream,
            "onto":rebase.onto,
            "fork_base":rebase.fork_base,
            "queue_length":rebase.queue.len(),
            "cursor":rebase.cursor,
            "current_source":rebase.queue.get(rebase.cursor),
            "progress_tip":rebase.progress_tip,
            "completed_steps":rebase.steps.len(),
            "skipped_steps":rebase.steps.iter().filter(|step| step.action == "skipped").count()
        });
        report["complete_index_required"] = json!(
            !already_published
                && (pending.prepared.is_none()
                    || rebase.prepared_action.as_deref() == Some("continue"))
        );
        report["rebase"]["prepared_action"] = json!(rebase.prepared_action);
    }
    if let Some(replay) = &pending.replay {
        report["replay"] = json!({"queue":replay.queue,"cursor":replay.cursor,"progress":replay.progress,"progress_kind":if replay.options.no_commit{"tree"}else{"commit"},"no_commit":replay.options.no_commit,"steps":replay.steps,"checkpoint_pending":replay.checkpoint.is_some()});
        report["phase"] = json!(if replay.checkpoint.is_some() {
            "worktree-checkpoint"
        } else if already_published {
            "published"
        } else {
            &replay.stop
        });
        report["complete_index_required"] =
            json!(replay.checkpoint.is_none() && replay.stop != "complete");
        if let Some(rebase) = &replay.rebase {
            report["rebase"] = json!({"upstream":rebase.upstream,"onto":rebase.onto,"fork_base":rebase.fork_base,"queue_length":replay.queue.len(),"cursor":replay.cursor,"current_source":replay.queue.get(replay.cursor),"progress_tip":replay.progress,"completed_steps":replay.steps.len(),"skipped_steps":replay.steps.iter().filter(|step|step.action=="skipped").count()});
        }
    }
    report
}

fn status(state: &State) -> Result<String, String> {
    let actual = state.index();
    let pending = state.repo.pending()?;
    let actual = match actual {
        Ok(actual) => actual,
        Err(error) => {
            let Some(pending) = &pending else {
                return Err(error);
            };
            let snapshot = state.repo.state()?;
            let head = snapshot.tip();
            return json_text(&json!({
                "format":2,
                "branch":snapshot.head,
                "head":head,
                "index_available":false,
                "index_error":error,
                "index_present":null,
                "files":null,
                "untracked":null,
                "tracked":null,
                "staged":null,
                "worktree":"unavailable",
                "pending":pending_status(pending, &snapshot.head, head)
            }));
        }
    };
    let snapshot = state.repo.state()?;
    let head_id = snapshot.tip();
    let anchor = actual.as_ref().and_then(|i| i.legacy_path.as_deref());
    let raw = head_id.map(|id| state.repo.files_at(id)).transpose()?;
    let unmapped = raw
        .as_ref()
        .is_some_and(|r| r.legacy.is_some() && anchor.is_none() && r.legacy_path.is_none());
    let head = if unmapped {
        Index::empty()
    } else {
        head_id
            .map(|id| state.revision_index(id, anchor))
            .transpose()?
            .unwrap_or_else(Index::empty)
    };
    let index = actual.as_ref().unwrap_or(&head);
    let paths: BTreeSet<_> = head
        .files
        .keys()
        .cloned()
        .chain(index.files.keys().cloned())
        .chain(index.conflicts.keys().cloned())
        .chain(index.intents.iter().cloned())
        .collect();
    let mut rows = Vec::new();
    let mut staged_any = false;
    let mut modified = false;
    let mut deleted = false;
    let worktree = state.snapshot_worktree(paths.iter().cloned())?;
    for p in paths {
        let old = head.files.get(&p);
        let staged = index.files.get(&p);
        let current = if index.hidden(&p) {
            staged.cloned()
        } else {
            worktree.get(&p).cloned().flatten()
        };
        let change = if index.conflicts.contains_key(&p) {
            "unmerged"
        } else {
            match (old, staged) {
                (None, Some(_)) => "added",
                (Some(_), None) => "deleted",
                _ if old != staged => "modified",
                _ => "clean",
            }
        };
        let work = if index.conflicts.contains_key(&p) {
            "unmerged"
        } else {
            match (staged, current.as_ref()) {
                (None, Some(_)) if index.intents.contains(&p) => "added",
                (None, Some(_)) => "untracked",
                (Some(_), None) => "deleted",
                _ if current.as_ref() != staged => "modified",
                _ => "clean",
            }
        };
        staged_any |= change != "clean";
        modified |= matches!(work, "modified" | "added");
        deleted |= work == "deleted";
        let mut row = json!({"path":p,"staged":change,"worktree":work});
        if index.format >= 4 {
            row["intent_to_add"] = json!(index.intents.contains(&p));
            row["assume_unchanged"] =
                json!(index.flags.get(&p).is_some_and(|f| f.assume_unchanged));
            row["skip_worktree"] = json!(index.skipped(&p));
            row["fsmonitor_valid"] = json!(index_flags::monitor_valid(state, index, &p)?);
        }
        rows.push(row);
    }
    let untracked = scan_untracked(state, &controlled_paths(index))?;
    let singleton = if index.files.len() == 1 {
        index.files.keys().next().cloned()
    } else {
        None
    };
    let mut report = json!({"format":2,"branch":snapshot.head,"detached":snapshot.detached(),"head":head_id,"index_present":actual.is_some(),"legacy_head_unmapped":unmapped,"legacy_head_byte_len":raw.as_ref().and_then(|r|r.legacy.as_ref().map(Vec::len)),"files":rows,"untracked":untracked,"tracked":singleton,"staged":staged_any,"worktree":if modified{"modified"}else if deleted{"deleted"}else if actual.is_none()&&index.files.is_empty(){"untracked"}else{"clean"}});
    if let Some(pending) = pending {
        report["pending"] = pending_status(&pending, &snapshot.head, head_id);
    }
    report["unmerged"] = json!(index.conflicts.iter().map(|(path,stages)|json!({"path":path,"stages":(1..=3).filter(|stage|stages.image(*stage).is_some()).collect::<Vec<_>>()})).collect::<Vec<_>>());
    if !index.conflicts.is_empty() {
        report["worktree"] = json!("unmerged");
    }
    json_text(&report)
}
fn commit(state: &State, args: &[String]) -> Result<String, String> {
    let mut amend = false;
    let mut allow_empty = false;
    let mut message = None;
    let mut all = false;
    let mut cursor = 2;
    while cursor < args.len() {
        match args[cursor].as_str() {
            "--amend" if !amend => amend = true,
            "--allow-empty" if !allow_empty => allow_empty = true,
            "-a" | "--all" if !all => all = true,
            "-m" | "--message" if message.is_none() => {
                cursor += 1;
                message = Some(
                    args.get(cursor)
                        .ok_or("commit message is missing")?
                        .as_str(),
                );
            }
            _ => return Err(USAGE.into()),
        }
        cursor += 1;
    }
    let snapshot = state.repo.state()?;
    let head = snapshot.tip();
    let previous = head.map(|id| state.repo.read_commit(id)).transpose()?;
    if amend && previous.is_none() {
        return Err("cannot amend an unborn branch".into());
    }
    let message = message
        .or_else(|| {
            if amend {
                previous.as_ref().map(|p| p.commit.message.as_str())
            } else {
                None
            }
        })
        .ok_or("commit requires -m MESSAGE")?;
    let mut index = match state.index()? {
        Some(i) => i,
        None if allow_empty && head.is_none() => Index::empty(),
        None if amend || allow_empty => state.starting_index(None)?,
        None => return Err("nothing staged; use add DIR FILE...".into()),
    };
    if all {
        require_resolved_index(&index)?;
        for path in controlled_paths(&index) {
            if index.hidden(&path) {
                continue;
            }
            match state.worktree_module(&path)? {
                Some(bytes) => {
                    validate_wasm(&bytes)?;
                    index.files.insert(path.clone(), bytes);
                    index.intents.remove(&path);
                    index.flags.remove(&path);
                }
                None => {
                    index.files.remove(&path);
                    index.intents.remove(&path);
                }
            }
        }
        index.tidy();
        validate_index(&index)?;
    }
    let old = head
        .map(|id| state.revision_index(id, index.legacy_path.as_deref()))
        .transpose()?
        .unwrap_or_else(Index::empty);
    require_resolved_index(&index)?;
    if !amend
        && !allow_empty
        && head
            .map(|id| state.repo.files_at(id))
            .transpose()?
            .is_none_or(|r| r.legacy.is_none())
        && index.files == old.files
        && (head.is_some() || index.files.is_empty())
    {
        return Err("nothing staged; use --allow-empty for unchanged tree".into());
    }
    let parents = if amend {
        previous
            .as_ref()
            .ok_or("no commit to amend")?
            .commit
            .parents
            .clone()
    } else {
        head.into_iter().cloned().collect()
    };
    let id = state.repo.commit_files_on_branch(
        &index.files,
        message,
        &parents,
        &snapshot.head,
        head.map(String::as_str),
        index.legacy_path.as_deref(),
    )?;
    state
        .save_index(&index)
        .map_err(|e| format!("commit {id} published, but index publication failed: {e}"))?;
    Ok(format!("{} {id}", snapshot.head))
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Change {
    path: String,
    current: Option<Vec<u8>>,
    replacement: Option<Vec<u8>>,
}
fn keys(files: &Files) -> BTreeSet<String> {
    files.keys().cloned().collect()
}
fn has_descendant(paths: &BTreeSet<String>, path: &str) -> bool {
    let prefix = format!("{path}/");
    paths
        .range(prefix.clone()..)
        .next()
        .is_some_and(|candidate| candidate.starts_with(&prefix))
}
fn files_worktree(files: &Files) -> Worktree {
    files
        .iter()
        .map(|(p, b)| (p.clone(), Some(b.clone())))
        .collect()
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Observed {
    Absent,
    File(Vec<u8>),
    Directory,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct WorktreePlan {
    owned: BTreeSet<String>,
    target: Worktree,
    observed: BTreeMap<String, Observed>,
    changes: Vec<Change>,
    // true means a directory must be removed to publish a target file. false
    // means remove it only when empty after deleting an owned child.
    directories: BTreeMap<String, bool>,
}
fn observe(state: &State, path: &str) -> Result<Observed, String> {
    let full = state.repo.root.join(path);
    match fs::symlink_metadata(&full) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Observed::Absent),
        Err(e) => Err(error("inspect worktree path", &full, e)),
        Ok(m) if m.file_type().is_symlink() => Err(format!("worktree path is a symlink: {path}")),
        Ok(m) if m.is_dir() => Ok(Observed::Directory),
        Ok(m) if m.is_file() => fs::read(&full)
            .map(Observed::File)
            .map_err(|e| error("read worktree path", &full, e)),
        Ok(_) => Err(format!(
            "worktree path is not a regular file or directory: {path}"
        )),
    }
}
fn record_observation(
    state: &State,
    path: &str,
    observed: &mut BTreeMap<String, Observed>,
) -> Result<Observed, String> {
    let value = observe(state, path)?;
    if observed.get(path).is_some_and(|old| old != &value) {
        return Err(format!("worktree changed during preflight: {path}"));
    }
    observed.insert(path.into(), value.clone());
    Ok(value)
}
fn scan_removable_directory(
    state: &State,
    path: &str,
    owned: &BTreeSet<String>,
    target: &Worktree,
    observed: &mut BTreeMap<String, Observed>,
    directories: &mut BTreeMap<String, bool>,
) -> Result<(), String> {
    // Empty directories have no tracked identity. Refuse to erase them unless
    // an owned descendant establishes that this is a tracked container.
    if !has_descendant(owned, path) {
        return Err(format!("untracked directory would be replaced: {path}"));
    }
    let full = state.repo.root.join(path);
    for entry in fs::read_dir(&full).map_err(|e| error("scan replaced directory", &full, e))? {
        let entry = entry.map_err(|e| format!("scan replaced directory entry: {e}"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or("non-UTF-8 path in replaced directory")?;
        let child = format!("{path}/{name}");
        match record_observation(state, &child, observed)? {
            Observed::Directory => {
                scan_removable_directory(state, &child, owned, target, observed, directories)?;
            }
            Observed::File(_)
                if owned.contains(&child) && !target.get(&child).is_some_and(Option::is_some) => {}
            Observed::File(_) => {
                return Err(format!("untracked file would be removed: {child}"));
            }
            Observed::Absent => return Err(format!("worktree changed during preflight: {child}")),
        }
    }
    directories.insert(path.into(), true);
    Ok(())
}
fn plan(
    state: &State,
    owned: &BTreeSet<String>,
    target: &Worktree,
) -> Result<WorktreePlan, String> {
    let present: BTreeSet<_> = target
        .iter()
        .filter_map(|(path, bytes)| bytes.as_ref().map(|_| path.clone()))
        .collect();
    for path in owned.iter().chain(target.keys()) {
        validate_tree_path(path)?;
    }
    for path in &present {
        if has_descendant(&present, path) {
            return Err(format!(
                "worktree target contains a file/directory prefix collision: {path}"
            ));
        }
    }
    let paths: BTreeSet<_> = owned
        .iter()
        .cloned()
        .chain(target.keys().cloned())
        .collect();
    let mut changes = Vec::new();
    let mut observed = BTreeMap::new();
    let mut directories = BTreeMap::new();
    for p in paths {
        let replacement = target.get(&p).cloned().flatten();
        let mut prefix = String::new();
        let mut current = None;
        let components: Vec<_> = p.split('/').collect();
        for (position, component) in components.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let value = record_observation(state, &prefix, &mut observed)?;
            if position + 1 < components.len() {
                match value {
                    Observed::Absent => break,
                    Observed::Directory => {}
                    // A missing child beneath a retained regular file needs
                    // no filesystem update. This occurs in staged D/F sides.
                    Observed::File(_) if replacement.is_none() => break,
                    Observed::File(_) if owned.contains(&prefix) && !present.contains(&prefix) => {
                        break
                    }
                    Observed::File(_) => {
                        return Err(format!(
                            "untracked or retained file blocks target directory: {prefix}"
                        ));
                    }
                }
            } else {
                match value {
                    Observed::Absent => {}
                    Observed::File(bytes) => current = Some(bytes),
                    Observed::Directory if replacement.is_some() => {
                        scan_removable_directory(
                            state,
                            &p,
                            owned,
                            target,
                            &mut observed,
                            &mut directories,
                        )?;
                    }
                    Observed::Directory
                        if owned.contains(&p)
                            && !has_descendant(&present, &p)
                            && !has_descendant(owned, &p) =>
                    {
                        return Err(format!("tracked file was replaced by a directory: {p}"));
                    }
                    Observed::Directory => {}
                }
            }
        }
        if !owned.contains(&p) && current.is_some() {
            return Err(format!("untracked file would be overwritten: {p}"));
        }
        if current.is_some() && replacement.is_none() {
            for (offset, _) in p.match_indices('/') {
                let parent = &p[..offset];
                if observed.get(parent) == Some(&Observed::Directory) {
                    directories.entry(parent.into()).or_insert(false);
                }
            }
        }
        if current != replacement {
            changes.push(Change {
                path: p,
                current,
                replacement,
            });
        }
    }
    Ok(WorktreePlan {
        owned: owned.clone(),
        target: target.clone(),
        observed,
        changes,
        directories,
    })
}
fn apply_plan(state: &State, prepared: &WorktreePlan) -> Result<(), String> {
    if plan(state, &prepared.owned, &prepared.target)? != *prepared {
        return Err("worktree changed before publication; no files updated".into());
    }
    let mut completed = 0;
    let mut removed_directories = 0;
    let mut phase = "preflight";
    let mut failed_path = String::new();
    let result = (|| {
        for c in &prepared.changes {
            if c.replacement.is_none() {
                phase = "remove file";
                failed_path = c.path.clone();
                state.replace_worktree(&c.path, &c.current, None)?;
                completed += 1;
            }
        }
        let mut directories: Vec<_> = prepared.directories.iter().collect();
        directories.sort_by(|(a, _), (b, _)| {
            b.split('/')
                .count()
                .cmp(&a.split('/').count())
                .then_with(|| b.cmp(a))
        });
        for (path, required) in directories {
            phase = "remove directory";
            failed_path = path.clone();
            let full = state.repo.root.join(path);
            if observe(state, path)? != Observed::Directory {
                return Err(format!("worktree directory changed before removal: {path}"));
            }
            match fs::remove_dir(&full) {
                Ok(()) => {
                    removed_directories += 1;
                    let parent = full.parent().ok_or("removed directory has no parent")?;
                    File::open(parent)
                        .and_then(|file| file.sync_all())
                        .map_err(|e| error("sync removed directory parent", parent, e))?;
                }
                Err(e) if !required && e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(e) => return Err(error("remove tracked directory", &full, e)),
            }
        }
        for c in &prepared.changes {
            if let Some(bytes) = &c.replacement {
                phase = "write file";
                failed_path = c.path.clone();
                state.replace_worktree(&c.path, &c.current, Some(bytes))?;
                completed += 1;
            }
        }
        Ok(())
    })();
    result.map_err(|e| format!(
        "worktree I/O failed after {completed} completed file updates and {removed_directories} directory removals; failed phase {phase} at {failed_path}; that failed operation may already have changed the worktree: {e}"
    ))
}
fn clean_index(state: &State) -> Result<Option<Index>, String> {
    let index = state.index()?;
    if let Some(i) = &index {
        require_resolved_index(i)?;
        if !i.intents.is_empty() {
            return Err("index has intent-to-add paths; stage or remove them first".into());
        }
        let h = state
            .head()?
            .map(|id| state.revision_index(&id, i.legacy_path.as_deref()))
            .transpose()?
            .unwrap_or_else(Index::empty);
        if i.files != h.files {
            return Err("index has staged changes; commit or stash them first".into());
        }
        for (p, b) in &i.files {
            let actual = state.worktree_module(p)?;
            if actual.is_none() && i.skipped(p) {
                continue;
            }
            if actual.as_ref() != Some(b) {
                return Err(format!("tracked file has worktree changes: {p}"));
            }
        }
    }
    Ok(index)
}
fn plan_index_transition(
    state: &State,
    old: &Index,
    target: &Index,
    discard: bool,
) -> Result<WorktreePlan, String> {
    let mut target = target.clone();
    index_flags::inherit(&mut target, old);
    let work = index_flags::transition_worktree(state, old, &target, discard)?;
    plan(state, &controlled_paths(old), &work)
}
pub fn assert_worktree_target_safe(
    repo: &Repository,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    validate_files(files)?;
    let state = State {
        repo: repo.clone(),
        metadata: repo.root.join(".uwgit"),
    };
    if let Some(i) = state.index()? {
        require_resolved_index(&i)?;
        let mut target = Index::empty();
        target.files = files.clone();
        index_flags::inherit(&mut target, &i);
        let work = index_flags::transition_worktree(&state, &i, &target, false)?;
        plan(&state, &controlled_paths(&i), &work)?;
    }
    Ok(())
}
pub fn worktree_legacy_path(repo: &Repository) -> Result<Option<String>, String> {
    let state = State {
        repo: repo.clone(),
        metadata: repo.root.join(".uwgit"),
    };
    Ok(state.index()?.and_then(|index| index.legacy_path))
}
pub fn assert_worktree_revision_safe(
    repo: &Repository,
    revision: &crate::repository::RevisionFiles,
) -> Result<(), String> {
    let state = State {
        repo: repo.clone(),
        metadata: repo.root.join(".uwgit"),
    };
    let Some(index) = state.index()? else {
        return Ok(());
    };
    require_resolved_index(&index)?;
    let mut files = revision.files.clone();
    if let Some(bytes) = &revision.legacy {
        let path = revision
            .legacy_path
            .as_ref()
            .or(index.legacy_path.as_ref())
            .ok_or("unnamed v1 target needs an explicit legacy path before worktree update")?;
        files.insert(path.clone(), bytes.clone());
    }
    validate_files(&files)?;
    let mut target = Index::empty();
    target.files = files;
    index_flags::inherit(&mut target, &index);
    let work = index_flags::transition_worktree(&state, &index, &target, false)?;
    plan(&state, &controlled_paths(&index), &work)?;
    Ok(())
}
fn change_and_sync(
    state: &State,
    allow_branch_change: bool,
    operation: impl FnOnce(&Repository) -> Result<String, String>,
) -> Result<String, String> {
    let branch = state.repo.current_branch()?;
    let index = clean_index(state)?;
    let old = state.head()?;
    let result = operation(&state.repo)?;
    let current = state.repo.current_branch()?;
    if !allow_branch_change
        && current != branch
        && !(crate::repository::is_detached_identity(&branch)
            && crate::repository::is_detached_identity(&current))
    {
        return Err("operation completed, but branch changed; index/worktree not updated".into());
    }
    let new = state
        .head()
        .map_err(|e| format!("operation completed, but HEAD inspection failed: {e}"))?;
    if new == old {
        return Ok(result);
    }
    if let Some(i) = index {
        let mut target = state
            .revision_index(
                new.as_deref()
                    .ok_or("HEAD changed to unborn; index/worktree not updated")?,
                i.legacy_path.as_deref(),
            )
            .map_err(|e| format!("HEAD changed, target tree read failed: {e}"))?;
        index_flags::inherit(&mut target, &i);
        let work = index_flags::transition_worktree(state, &i, &target, false)
            .map_err(|e| format!("HEAD changed; worktree planning failed: {e}"))?;
        let changes = plan(state, &controlled_paths(&i), &work)
            .map_err(|e| format!("HEAD changed, worktree preflight failed: {e}"))?;
        apply_plan(state, &changes).map_err(|e| format!("HEAD changed; index not updated: {e}"))?;
        state
            .save_index(&target)
            .map_err(|e| format!("HEAD/worktree changed, index update failed: {e}"))?;
    }
    Ok(result)
}
pub fn with_clean_history(
    root: &str,
    operation: impl FnOnce(&Repository) -> Result<String, String>,
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    require_no_pending(&state.repo)?;
    change_and_sync(&state, false, operation)
}

/// Guard older file-based writers with the same index-to-writer lock order as
/// the staged commands, without requiring a clean worktree.
pub fn with_no_pending(
    root: &str,
    operation: impl FnOnce(&Repository) -> Result<String, String>,
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    require_no_pending(&state.repo)?;
    if let Some(index) = state.index()? {
        require_resolved_index(&index)?;
    }
    operation(&state.repo)
}

/// Capture the original index while normal clean-history semantics still
/// apply. Only the callback's actual conflict path records this backup.
pub fn with_recorded_begin(
    root: &str,
    kind: &str,
    revisions: Vec<String>,
    options: crate::repository::ReplayOptions,
    onto: Option<String>,
    operation: impl FnOnce(&Repository, Option<&[u8]>, Option<&str>) -> Result<String, String>,
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    require_no_pending(&state.repo)?;
    let raw = regular(&state.metadata.join("index"))?;
    if raw.is_some() {
        return replay_worktree::start_in_state(&state, kind, revisions, options, onto);
    }
    let decoded = raw.as_deref().map(decode_index).transpose()?;
    if clean_index(&state)? != decoded {
        return Err("index changed while capturing the pending baseline".into());
    }
    let head = state
        .head()?
        .map(|id| state.repo.files_at(&id))
        .transpose()?;
    let anchor = decoded
        .as_ref()
        .and_then(|index| index.legacy_path.clone())
        .or_else(|| head.as_ref().and_then(|head| head.legacy_path.clone()));
    if let Some(head) = &head {
        validate_pending_baseline(raw.as_deref(), head, anchor.as_deref())?;
    }
    change_and_sync(&state, false, |repo| {
        if regular(&state.metadata.join("index"))? != raw {
            return Err("index changed before the pending operation started".into());
        }
        operation(repo, raw.as_deref(), anchor.as_deref())
    })
}

/// Continue from the complete staged tree without reading any worktree file.
/// A published result, or a rebase result prepared without consuming an index,
/// can finish its metadata even after the user removed or damaged the index.
pub fn with_pending_index(
    root: &str,
    operation: impl FnOnce(&Repository, Option<PendingIndex<'_>>) -> Result<String, String>,
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let pending = state.repo.pending()?.ok_or("no pending operation")?;
    let snapshot = state.repo.state()?;
    let published = pending.prepared.as_ref().is_some_and(|prepared| {
        pending.matches_head_identity(&snapshot.head) && snapshot.tip() == Some(&prepared.commit)
    });
    let without_resolution_index = pending.prepared.is_some()
        && pending.rebase.as_ref().is_some_and(|rebase| {
            matches!(rebase.prepared_action.as_deref(), Some("begin" | "skip"))
        });
    if published || without_resolution_index {
        return operation(&state.repo, None);
    }
    let raw = regular(&state.metadata.join("index"))?.ok_or(
        "pending --continue requires an existing complete index; stage the full resolution first",
    )?;
    let index = decode_index(&raw)?;
    require_resolved_index(&index)?;
    operation(
        &state.repo,
        Some(PendingIndex {
            files: &index.files,
            legacy_path: index.legacy_path.as_deref(),
            raw: &raw,
        }),
    )
}

/// Hold the index lock for a journal control that does not consume a staged
/// resolution. In particular, rebase --skip can advance its immutable queue
/// even when the current index is absent or damaged.
pub fn with_pending_control(
    root: &str,
    operation: impl FnOnce(&Repository) -> Result<String, String>,
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    operation(&state.repo)
}

fn selected_pending(repo: &Repository, operation: &str) -> Result<PendingOperation, String> {
    let pending = repo.pending()?.ok_or("no pending operation")?;
    if pending.operation != operation {
        return Err(format!(
            "pending operation is {}, not {operation}; no state changed",
            pending.operation
        ));
    }
    Ok(pending)
}

fn restore_pending_baseline(
    state: &State,
    pending: &PendingOperation,
    head: &RevisionFiles,
) -> Result<(), String> {
    validate_pending_baseline(
        pending.baseline_index.as_deref(),
        head,
        pending.legacy_path.as_deref(),
    )?;
    let original = pending
        .baseline_index
        .as_deref()
        .map(decode_index)
        .transpose()?;
    // An index type error must reject before restoring the first work file.
    // Its content need not decode: abort deliberately restores the exact backup.
    let current_index = regular(&state.metadata.join("index"))?;
    let changes = original
        .as_ref()
        .map(|index| plan(state, &keys(&index.files), &files_worktree(&index.files)))
        .transpose()?;
    if regular(&state.metadata.join("index"))? != current_index {
        return Err("index changed during pending abort preflight; no files restored".into());
    }
    if let Some(changes) = changes {
        apply_plan(state, &changes)
            .map_err(|error| format!("pending operation retained; original tracked files may be partly restored: {error}"))?;
    }
    if regular(&state.metadata.join("index"))? != current_index {
        return Err("original tracked files restored, but index changed before restoration; pending operation retained".into());
    }
    if let Some(raw) = &pending.baseline_index {
        state.write("index", raw).map_err(|error| {
            format!("original tracked files restored; original index restoration failed or its durability is uncertain; pending operation retained: {error}")
        })?;
    } else if current_index.is_some() {
        fs::remove_file(state.metadata.join("index"))
            .and_then(|()| File::open(&state.metadata)?.sync_all())
            .map_err(|error| format!("work files preserved; restoring the original absent index failed or its durability is uncertain; pending operation retained: {error}"))?;
    }
    Ok(())
}

pub fn pending_abort(root: &str, operation: &str, skip: bool) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    if skip && operation == "merge" {
        return Err("merge has no --skip operation".into());
    }
    let pending = selected_pending(&state.repo, operation)?;
    state.repo.abort_pending(&pending, |pending, head| {
        restore_pending_baseline(&state, pending, head)
    })?;
    json_text(&json!({
        "schema_version":1,
        "status":if skip { "skipped" } else { "aborted" },
        "operation":pending.operation,
        "pending_id":pending.id,
        "branch":pending.branch,
        "old_head":pending.head,
        "target":pending.target,
        "head_updated":false,
        "index_restored":true,
        "original_tracked_worktree_restored":pending.baseline_index.is_some(),
        "new_work_files_preserved":true,
        "pending_cleared":true
    }))
}

pub fn pending_quit(root: &str, operation: &str) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let pending = selected_pending(&state.repo, operation)?;
    state.repo.quit_pending(&pending)?;
    json_text(&json!({
        "schema_version":1,
        "status":"quit",
        "operation":pending.operation,
        "pending_id":pending.id,
        "branch":pending.branch,
        "old_head":pending.head,
        "target":pending.target,
        "head_updated":false,
        "index_updated":false,
        "worktree_updated":false,
        "pending_cleared":true
    }))
}
/// Commit an explicitly resolved index while preserving all worktree bytes,
/// including unstaged changes and deleted files. The operation receives the
/// exact validated index and runs under the ordinary index lock.
pub fn with_index_resolution(
    root: &str,
    operation: impl FnOnce(
        &Repository,
        &BTreeMap<String, Vec<u8>>,
        Option<&str>,
    ) -> Result<String, String>,
) -> Result<String, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    require_no_pending(&state.repo)?;
    let index = state
        .index()?
        .ok_or("resolved-index operation requires an existing index")?;
    validate_index(&index)?;
    require_resolved_index(&index)?;
    operation(&state.repo, &index.files, index.legacy_path.as_deref())
}
pub struct FileDiffSnapshot {
    pub path: String,
    pub old: Option<Vec<u8>>,
    pub new: Option<Vec<u8>>,
    pub old_origin: Value,
    pub new_origin: Value,
}
pub fn diff_snapshot(root: &str, cached: bool) -> Result<Vec<FileDiffSnapshot>, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let index = state.starting_index(None)?;
    require_resolved_index(&index)?;
    let snapshot = state.repo.state()?;
    let head = snapshot.tip();
    let (old, new, old_kind, new_kind) = if cached {
        let h = head
            .map(|id| state.revision_index(id, index.legacy_path.as_deref()))
            .transpose()?
            .unwrap_or_else(Index::empty);
        (
            files_worktree(&h.files),
            files_worktree(&index.files),
            "commit",
            "index",
        )
    } else {
        (
            files_worktree(&index.files),
            index_flags::query_worktree(&state, &index)?,
            "index",
            "worktree",
        )
    };
    let paths: BTreeSet<_> = old.keys().cloned().chain(new.keys().cloned()).collect();
    Ok(paths
        .into_iter()
        .map(|p| FileDiffSnapshot {
            old: old.get(&p).cloned().flatten(),
            new: new.get(&p).cloned().flatten(),
            old_origin: json!({"kind":old_kind,"path":p,"commit":if cached{head}else{None}}),
            new_origin: json!({"kind":new_kind,"path":p}),
            path: p,
        })
        .collect())
}

pub fn diff_index_snapshot(
    root: &str,
    revision: &str,
    cached: bool,
) -> Result<Vec<FileDiffSnapshot>, String> {
    let state = State::open(root)?;
    let _lock = state.lock()?;
    let index = state.starting_index(None)?;
    require_resolved_index(&index)?;
    let old = state.revision_index(revision, index.legacy_path.as_deref())?;
    let new = if cached {
        files_worktree(&index.files)
    } else {
        index_flags::query_worktree(&state, &index)?
    };
    let paths: BTreeSet<_> = old.files.keys().chain(new.keys()).cloned().collect();
    Ok(paths
        .into_iter()
        .map(|path| FileDiffSnapshot {
            old: old.files.get(&path).cloned(),
            new: new.get(&path).cloned().flatten(),
            old_origin: json!({"kind":"commit","revision":revision,"path":path}),
            new_origin: json!({"kind":if cached {"index"} else {"worktree"},"path":path}),
            path,
        })
        .collect())
}

fn resolve_revision(repo: &Repository, revision: &str) -> Result<String, String> {
    let local = ["@{upstream}", "@{u}"]
        .into_iter()
        .find_map(|suffix| revision.strip_suffix(suffix));
    let Some(local) = local else {
        return repo.resolve(revision);
    };
    let current;
    let local = if local.is_empty() || local == "HEAD" {
        current = repo.current_branch()?;
        &current
    } else {
        local
    };
    let upstream = crate::remote::upstream_status(repo, local)?
        .ok_or_else(|| format!("branch {local:?} has no upstream"))?;
    upstream.tip.ok_or_else(|| {
        format!(
            "upstream {}/{} has no fetched branch; fetch {} and inspect branch -vv",
            upstream.remote, upstream.branch, upstream.remote
        )
    })
}

fn branch_verbose(state: &State) -> Result<String, String> {
    let snapshot = state.repo.state()?;
    let mut names: BTreeSet<_> = snapshot.branches.keys().cloned().collect();
    if !snapshot.detached() {
        names.insert(snapshot.head.clone());
    }
    let mut branches = Vec::new();
    for name in names {
        let upstream = crate::remote::upstream_status(&state.repo, &name)?.map(|upstream| {
            json!({
                "tracking":format!("{}/{}", upstream.remote, upstream.branch),
                "status":if upstream.tip.is_some() { "available" } else { "gone" },
                "remote":upstream.remote,
                "branch":upstream.branch,
                "tip":upstream.tip
            })
        });
        branches.push(json!({
            "name":name,
            "current":name == snapshot.head,
            "commit":snapshot.branches.get(&name),
            "upstream":upstream
        }));
    }
    json_text(
        &json!({"format":1,"head":snapshot.head,"detached":snapshot.detached(),"branches":branches}),
    )
}

fn configure_branch_upstream(
    state: &State,
    spec: &str,
    local: Option<&str>,
) -> Result<String, String> {
    let current;
    let local = if let Some(local) = local {
        local
    } else {
        current = state.repo.current_branch()?;
        &current
    };
    crate::remote::configure_upstream(&state.repo, local, spec)?;
    Ok(format!("branch {local} upstream -> {spec}"))
}

fn branch(state: &State, args: &[String]) -> Result<String, String> {
    match &args[2..] {
        [] => {
            let snapshot = state.repo.state()?;
            if snapshot.detached() {
                let mut lines = vec![format!("* (HEAD detached at {})", snapshot.head)];
                lines.extend(
                    snapshot
                        .branches
                        .iter()
                        .map(|(name, id)| format!("  {name} {id}")),
                );
                return Ok(lines.join("\n"));
            }
            if snapshot.branches.is_empty() {
                return Ok(format!("* {} (no commits)", snapshot.head));
            }
            Ok(snapshot
                .branches
                .iter()
                .map(|(name, id)| {
                    format!(
                        "{} {name} {id}",
                        if name == &snapshot.head { "*" } else { " " }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        [option] if option == "-vv" => branch_verbose(state),
        [option, spec] if matches!(option.as_str(), "-u" | "--set-upstream-to") => {
            configure_branch_upstream(state, spec, None)
        }
        [option, spec, local] if matches!(option.as_str(), "-u" | "--set-upstream-to") => {
            configure_branch_upstream(state, spec, Some(local))
        }
        [option] | [option, _] if option.starts_with("--set-upstream-to=") => {
            configure_branch_upstream(
                state,
                option.strip_prefix("--set-upstream-to=").ok_or(USAGE)?,
                args.get(3).map(String::as_str),
            )
        }
        [option] | [option, _] if option == "--unset-upstream" => {
            let local = args.get(3).cloned().unwrap_or(state.repo.current_branch()?);
            crate::remote::unset_upstream(&state.repo, &local)?;
            Ok(format!("unset upstream for branch {local}"))
        }
        [option, name] if matches!(option.as_str(), "-d" | "-D") => {
            state.repo.delete_branch(name, option == "-D")
        }
        [option, name] if option == "-m" => {
            state
                .repo
                .rename_branch(&state.repo.current_branch()?, name)?;
            Ok(format!("renamed current branch to {name}"))
        }
        [option, old, new] if option == "-m" => {
            state.repo.rename_branch(old, new)?;
            Ok(format!("renamed {old} to {new}"))
        }
        [option, name] if matches!(option.as_str(), "-M" | "-c" | "-C") => {
            require_no_pending(&state.repo)?;
            state.repo.rename_branch_mode(
                &state.repo.current_branch()?,
                name,
                option != "-c",
                option != "-M",
            )?;
            Ok(format!("branch {option} -> {name}"))
        }
        [option, old, new] if matches!(option.as_str(), "-M" | "-c" | "-C") => {
            require_no_pending(&state.repo)?;
            state
                .repo
                .rename_branch_mode(old, new, option != "-c", option != "-M")?;
            Ok(format!("branch {option} {old} -> {new}"))
        }
        [option, name] | [option, name, _] if matches!(option.as_str(), "-f" | "--force") => {
            require_no_pending(&state.repo)?;
            state
                .repo
                .force_branch(name, args.get(4).map_or("HEAD", String::as_str))
        }
        [option] if matches!(option.as_str(), "-r" | "--remotes" | "-a" | "--all") => {
            let report = state.repo.query_refs()?;
            Ok(report
                .refs
                .into_iter()
                .filter(|reference| {
                    option == "-a"
                        || option == "--all"
                        || reference.name.starts_with("refs/remotes/")
                })
                .filter(|reference| !reference.name.starts_with("refs/tags/"))
                .map(|reference| {
                    format!(
                        "{} {} {}",
                        if reference.current { "*" } else { " " },
                        reference
                            .name
                            .strip_prefix("refs/heads/")
                            .unwrap_or(&reference.name),
                        reference.id
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        [name] if !name.starts_with('-') => state.repo.create_branch(name, "HEAD"),
        [name, revision] if !name.starts_with('-') => state.repo.create_branch(name, revision),
        _ => Err(USAGE.into()),
    }
}

fn switch(state: &State, args: &[String]) -> Result<String, String> {
    if args.get(2).is_some_and(|value| value == "-") && args.len() == 3 {
        let previous = state.repo.previous_checkout_branch(1)?;
        if crate::repository::is_detached_identity(&previous) {
            return switch(
                state,
                &[
                    "switch".into(),
                    args[1].clone(),
                    "--detach".into(),
                    previous,
                ],
            );
        }
        return switch(state, &["switch".into(), args[1].clone(), previous]);
    }
    if matches!(args.get(2).map(String::as_str), Some("--detach" | "-d"))
        && (3..=4).contains(&args.len())
    {
        let revision = args.get(3).map_or("HEAD", String::as_str);
        let id = state.repo.resolve(revision)?;
        if let Some(index) = clean_index(state)? {
            let target = state.revision_index(&id, index.legacy_path.as_deref())?;
            plan_index_transition(state, &index, &target, false)?;
        }
        return change_and_sync(state, true, |repo| {
            repo.detach_head(&id)
                .map(|id| format!("HEAD detached at {id}"))
        });
    }
    if args.get(2).is_some_and(|value| value == "--orphan") && args.len() == 4 {
        let index = clean_index(state)?;
        let target = Index::empty();
        let changes = plan(
            state,
            &index
                .as_ref()
                .map(|index| keys(&index.files))
                .unwrap_or_default(),
            &files_worktree(&target.files),
        )?;
        state.repo.orphan_head(&args[3])?;
        apply_plan(state, &changes).map_err(|error| {
            format!("orphan HEAD was published; worktree restoration incomplete: {error}")
        })?;
        state.save_index(&target).map_err(|error| {
            format!("orphan HEAD and worktree published; index update failed: {error}")
        })?;
        return Ok(format!("HEAD -> {} (orphan)", args[3]));
    }
    let (name, revision, create) = match &args[2..] {
        [name] if !name.starts_with('-') => (name, "HEAD", false),
        [op, name] if op == "-c" => (name, "HEAD", true),
        [op, name, rev] if op == "-c" => (name, rev.as_str(), true),
        _ => return Err(USAGE.into()),
    };
    if let Some(i) = clean_index(state)? {
        if state.head()?.is_some() || revision != "HEAD" {
            let target = state.revision_index(
                if create { revision } else { name },
                i.legacy_path.as_deref(),
            )?;
            plan_index_transition(state, &i, &target, false)?;
        }
    }
    change_and_sync(state, true, |repo| {
        if create {
            if state.head()?.is_none() && revision == "HEAD" {
                repo.rename_branch(&repo.current_branch()?, name)?;
                return Ok(format!("HEAD -> {name} (unborn)"));
            }
            repo.create_branch(name, revision)?;
            repo.switch_branch(name)
                .map_err(|e| format!("branch {name} created, switch failed: {e}"))?;
        } else {
            repo.switch_branch(name)?;
        }
        Ok(format!("HEAD -> {name}"))
    })
}
fn chosen_paths(index: &Index, paths: Vec<String>) -> Result<Vec<String>, String> {
    let paths = if paths.is_empty() {
        if controlled_paths(index).len() == 1 {
            controlled_paths(index).into_iter().collect()
        } else {
            return Err(
                "specify tracked paths when index does not contain exactly one file".into(),
            );
        }
    } else {
        paths
    };
    let mut unique = BTreeSet::new();
    for p in &paths {
        validate_tree_path(p)?;
        if !index.files.contains_key(p)
            && !index.conflicts.contains_key(p)
            && !index.intents.contains(p)
        {
            return Err(format!("path is not tracked: {p}"));
        }
        if !unique.insert(p.clone()) {
            return Err("duplicate path argument".into());
        }
    }
    Ok(paths)
}
fn remove(state: &State, args: &[String]) -> Result<String, String> {
    let mut cached = false;
    let mut force = false;
    let mut paths = Vec::new();
    let mut literal = false;
    for a in &args[2..] {
        if literal {
            paths.push(a.clone());
            continue;
        }
        match a.as_str() {
            "--" => literal = true,
            "--cached" if !cached => cached = true,
            "-f" | "--force" if !force => force = true,
            v if !v.starts_with('-') => paths.push(a.clone()),
            _ => return Err(USAGE.into()),
        }
    }
    let mut index = state.index()?.ok_or("no index")?;
    let paths = chosen_paths(&index, paths)?;
    let head = state
        .head()?
        .map(|id| state.revision_index(&id, index.legacy_path.as_deref()))
        .transpose()?
        .unwrap_or_else(Index::empty);
    for p in &paths {
        if index.intents.contains(p) {
            if !cached && !force && state.worktree_module(p)?.is_some() {
                return Err("intent-to-add removal requires --cached or --force".into());
            }
            continue;
        }
        if index.conflicts.contains_key(p) {
            if !force {
                return Err("unmerged removal requires explicit --force".into());
            }
            continue;
        }
        let b = index.files.get(p).ok_or("missing tracked path")?;
        let current = state.worktree(p)?;
        if !force
            && ((cached && head.files.get(p) != Some(b) && current.as_ref() != Some(b))
                || (!cached
                    && (head.files.get(p) != Some(b) || current.as_ref().is_some_and(|v| v != b))))
        {
            return Err(format!(
                "path has unsaved changes: {p}; commit/stash or --force"
            ));
        }
    }
    let changes = if cached {
        None
    } else {
        Some(plan(
            state,
            &paths.iter().cloned().collect(),
            &paths.iter().map(|p| (p.clone(), None)).collect(),
        )?)
    };
    for p in &paths {
        index.files.remove(p);
        index.resolve_path(p);
        index.intents.remove(p);
        index.flags.remove(p);
    }
    index.tidy();
    validate_index(&index)?;
    if let Some(changes) = changes {
        apply_plan(state, &changes)?;
    }
    state
        .save_index(&index)
        .map_err(|e| format!("worktree removals completed, index update failed: {e}"))?;
    Ok(format!(
        "removed {} paths{}",
        paths.len(),
        if cached {
            "; worktree preserved"
        } else {
            " and tracked files"
        }
    ))
}
fn move_tracked(state: &State, old: &str, new: &str) -> Result<String, String> {
    let mut index = state.index()?.ok_or("no index")?;
    validate_tree_path(new)?;
    let staged = index.files.get(old).cloned();
    let intent = index.intents.contains(old);
    if staged.is_none() && !intent {
        return Err("mv source is not tracked".into());
    }
    if controlled_paths(&index).contains(new) {
        return Err("mv destination already exists".into());
    }
    let bytes = state.worktree(old)?.ok_or("mv source is deleted")?;
    let owned = controlled_paths(&index);
    let mut target = state.snapshot_worktree(owned.iter().cloned())?;
    index.files.remove(old);
    index.intents.remove(old);
    if let Some(bytes) = staged {
        index.files.insert(new.into(), bytes);
    }
    if intent {
        index.intents.insert(new.into());
    }
    if let Some(mut flag) = index.flags.remove(old) {
        flag.fsmonitor_valid = None;
        if !flag.empty() {
            index.flags.insert(new.into(), flag);
        }
    }
    index.tidy();
    validate_index(&index)?;
    target.insert(old.into(), None);
    target.insert(new.into(), Some(bytes));
    let changes = plan(state, &owned, &target)?;
    apply_plan(state, &changes)?;
    state
        .save_index(&index)
        .map_err(|e| format!("file moved, index path update failed: {e}"))?;
    Ok(format!("moved {old} to {new}"))
}
fn select_paths(
    candidates: &BTreeSet<String>,
    selectors: &[String],
) -> Result<BTreeSet<String>, String> {
    wasm_git::pathspec::select(candidates, selectors)
}
fn restore(state: &State, args: &[String]) -> Result<String, String> {
    if args
        .iter()
        .skip(2)
        .take_while(|value| value.as_str() != "--")
        .any(|value| matches!(value.as_str(), "--ours" | "--theirs"))
    {
        return index_plumbing::restore_side(state, args);
    }
    let mut source = None;
    let mut staged = false;
    let mut work = false;
    let mut overlay = false;
    let mut ignore_skip = false;
    let mut output = None;
    let mut explicit_file = false;
    let mut paths = Vec::new();
    let mut literal = false;
    let mut cursor = 2;
    while cursor < args.len() {
        if literal {
            paths.push(args[cursor].clone());
            cursor += 1;
            continue;
        }
        match args[cursor].as_str() {
            "--" => {
                literal = true;
                explicit_file = true;
            }
            "--source" if source.is_none() => {
                cursor += 1;
                source = Some(args.get(cursor).ok_or(USAGE)?.clone());
            }
            "--staged" if !staged => staged = true,
            "--worktree" if !work => work = true,
            "--overlay" if !overlay => overlay = true,
            "--ignore-skip-worktree-bits" if !ignore_skip => ignore_skip = true,
            "--output" if output.is_none() => {
                cursor += 1;
                output = Some(args.get(cursor).ok_or(USAGE)?.as_str());
            }
            "--file" => {
                cursor += 1;
                paths.push(args.get(cursor).ok_or(USAGE)?.clone());
                explicit_file = true;
            }
            v if !v.starts_with('-') => paths.push(args[cursor].clone()),
            _ => return Err(USAGE.into()),
        }
        cursor += 1;
    }
    if literal && paths.is_empty() {
        return Err("restore requires at least one path after --".into());
    }
    let old = state.index()?;
    let mut legacy_export = false;
    if output.is_some()
        && source.is_none()
        && !explicit_file
        && paths.len() == 1
        && state.repo.resolve(&paths[0]).is_ok()
    {
        source = Some(paths.remove(0));
        legacy_export = true;
    }
    if let (Some(output), Some(revision)) = (output, source.as_ref()) {
        if !staged && !work && paths.is_empty() {
            if let Some(bytes) = state.repo.files_at(revision)?.legacy {
                state.output(output, &bytes)?;
                return Ok(format!(
                    "exported unnamed v1 bytes to {output}; no path mapping created"
                ));
            }
        }
    }
    let target = match source {
        Some(rev) => {
            state.revision_index(&rev, old.as_ref().and_then(|i| i.legacy_path.as_deref()))?
        }
        None if staged => {
            let id = state.head()?.ok_or("staged restore requires HEAD")?;
            state.revision_index(&id, old.as_ref().and_then(|i| i.legacy_path.as_deref()))?
        }
        None => old.clone().ok_or("no index; specify --source REV")?,
    };
    if let Some(output) = output {
        if staged || work {
            return Err("--output cannot combine with staged/worktree".into());
        }
        let p = if paths.is_empty() || legacy_export {
            if target.files.len() != 1 {
                return Err("tree export requires --file PATH".into());
            }
            target
                .files
                .keys()
                .next()
                .cloned()
                .ok_or("empty tree has no module")?
        } else if paths.len() == 1 {
            paths[0].clone()
        } else {
            return Err("one output requires one selected path".into());
        };
        state.output(
            output,
            target.files.get(&p).ok_or("path absent from source tree")?,
        )?;
        return Ok(format!("wrote {p} to {output}"));
    }
    if !staged {
        work = true;
    }
    // Restore changes content/index, never the identity used to interpret an
    // unnamed ancestor of the current HEAD. A source without an anchor cannot
    // erase an earlier explicit choice, and two choices must not be conflated.
    let head_revision = state
        .head()?
        .map(|id| state.repo.files_at(&id))
        .transpose()?;
    let anchors: BTreeSet<_> = old
        .as_ref()
        .and_then(|index| index.legacy_path.clone())
        .into_iter()
        .chain(target.legacy_path.clone())
        .chain(
            head_revision
                .as_ref()
                .and_then(|head| head.legacy_path.clone()),
        )
        .collect();
    if anchors.len() > 1 {
        return Err(format!(
            "restore source has conflicting legacy path anchors; no files or index changed: {anchors:?}"
        ));
    }
    let legacy_path = anchors.into_iter().next();
    if staged
        && legacy_path.is_none()
        && head_revision
            .as_ref()
            .is_some_and(|head| head.legacy.is_some())
    {
        return Err(
            "staged restore of an unnamed v1 HEAD requires an explicit legacy path; use add DIR PATH first"
                .into(),
        );
    }
    let mut replacement = old.clone().unwrap_or_else(Index::empty);
    let candidates = if overlay {
        keys(&target.files)
    } else {
        replacement
            .files
            .keys()
            .cloned()
            .chain(replacement.conflicts.keys().cloned())
            .chain(replacement.intents.iter().cloned())
            .chain(target.files.keys().cloned())
            .collect()
    };
    let mut selected = select_paths(&candidates, &paths)?;
    if overlay && selected.is_empty() {
        return Ok("restored 0 paths; index/worktree preserved".into());
    }
    if overlay {
        // Overlay preserves source-absent entries except owned ancestors or
        // descendants that must be removed to install a selected source path.
        // Match every selector first; only those source paths authorize this
        // structural expansion. The complete index and worktree plan are still
        // validated before publication, including every untracked obstruction.
        let removals: Vec<_> = replacement
            .files
            .keys()
            .chain(replacement.conflicts.keys())
            .chain(replacement.intents.iter())
            .filter(|path| {
                has_descendant(&selected, path)
                    || path
                        .match_indices('/')
                        .any(|(offset, _)| selected.contains(&path[..offset]))
            })
            .cloned()
            .collect();
        selected.extend(removals);
    }
    let mut desired = if work {
        state.snapshot_worktree(controlled_paths(&replacement))?
    } else {
        Worktree::new()
    };
    for p in &selected {
        validate_tree_path(p)?;
        if work && !staged && !ignore_skip && replacement.skipped(p) {
            continue;
        }
        if target.intents.contains(p) {
            return Err("intent-to-add has no image to restore; stage its content first".into());
        }
        if target.conflicts.contains_key(p) {
            return Err("restore of unmerged paths requires --ours or --theirs".into());
        }
        replacement.resolve_path(p);
        replacement.intents.remove(p);
        let write_work = work && (ignore_skip || !replacement.skipped(p));
        if replacement.files.get(p) != target.files.get(p) {
            if let Some(flag) = replacement.flags.get_mut(p) {
                flag.fsmonitor_valid = None;
            }
        }
        match target.files.get(p) {
            Some(b) => {
                replacement.files.insert(p.clone(), b.clone());
                if write_work {
                    desired.insert(p.clone(), Some(b.clone()));
                }
            }
            None => {
                replacement.files.remove(p);
                if write_work {
                    desired.insert(p.clone(), None);
                }
            }
        }
    }
    replacement.legacy_path = legacy_path;
    replacement.tidy();
    validate_index(&replacement)?;
    if work {
        let owned = old.as_ref().map(controlled_paths).unwrap_or_default();
        let changes = plan(state, &owned, &desired)?;
        apply_plan(state, &changes)?;
    }
    if staged {
        state
            .save_index(&replacement)
            .map_err(|e| format!("worktree restored, index update failed: {e}"))?;
    }
    Ok(format!(
        "restored {} paths{}",
        selected.len(),
        if staged {
            " and index"
        } else {
            "; index preserved"
        }
    ))
}
fn reset(state: &State, args: &[String]) -> Result<String, String> {
    if let Some(separator) = args[2..].iter().position(|arg| arg == "--") {
        let (prefix, paths) = args[2..].split_at(separator);
        let paths = &paths[1..];
        if paths.is_empty() {
            return Err("path reset requires at least one path after --".into());
        }
        let revision = match prefix {
            [] => "HEAD",
            [revision] if !revision.starts_with('-') => revision.as_str(),
            _ => return Err(
                "path reset accepts only [REV] before --; reset modes cannot combine with paths"
                    .into(),
            ),
        };
        if revision == "HEAD" && state.head()?.is_none() {
            return Err("path reset requires a committed HEAD; before the first commit, use rm DIR --cached -- PATH... to unstage".into());
        }
        let mut restore_args = vec![
            "restore".into(),
            args[1].clone(),
            "--source".into(),
            revision.into(),
            "--staged".into(),
            "--".into(),
        ];
        restore_args.extend_from_slice(paths);
        return restore(state, &restore_args)
            .map(|result| format!("{result}; HEAD and worktree preserved"));
    }
    let (mode, rev) = match &args[2..] {
        [] => ("--mixed", "HEAD"),
        [r] if !r.starts_with('-') => ("--mixed", r.as_str()),
        [m] if matches!(m.as_str(), "--soft" | "--mixed" | "--hard") => (m.as_str(), "HEAD"),
        [m, r] if matches!(m.as_str(), "--soft" | "--mixed" | "--hard") => (m.as_str(), r.as_str()),
        _ => return Err(USAGE.into()),
    };
    let old = state.index()?;
    let s = state.repo.state()?;
    let head = s.tip();
    let id = state.repo.resolve(rev)?;
    let mut target = if mode == "--soft" {
        None
    } else {
        Some(state.revision_index(&id, old.as_ref().and_then(|i| i.legacy_path.as_deref()))?)
    };
    if let (Some(target), Some(old)) = (&mut target, &old) {
        index_flags::inherit(target, old);
    }
    let changes = if mode == "--hard" {
        let empty = Index::empty();
        let before = old.as_ref().unwrap_or(&empty);
        let work = index_flags::transition_worktree(
            state,
            before,
            target.as_ref().ok_or("missing reset tree")?,
            true,
        )?;
        Some(plan(
            state,
            &old.as_ref().map(controlled_paths).unwrap_or_default(),
            &work,
        )?)
    } else {
        None
    };
    state
        .repo
        .reset_on_branch(&id, &s.head, head.map(String::as_str))?;
    if let Some(c) = changes {
        apply_plan(state, &c).map_err(|e| format!("HEAD moved to {id}; index not updated: {e}"))?;
    }
    if let Some(t) = target {
        state
            .save_index(&t)
            .map_err(|e| format!("HEAD moved to {id}, index update failed: {e}"))?;
    }
    Ok(format!("HEAD {id}; {mode}"))
}

fn config(state: &State, args: &[String]) -> Result<String, String> {
    let mut config = state.config()?;
    match &args[2..] {
        [] => json_text(&config.values),
        [name] => {
            config_value(name, "")?;
            config
                .values
                .get(name)
                .cloned()
                .ok_or_else(|| format!("unset config: {name}"))
        }
        [option, name] if option == "--unset" => {
            config_value(name, "")?;
            config
                .values
                .remove(name)
                .ok_or_else(|| format!("unset config: {name}"))?;
            state.write("config", &canonical(&config)?)?;
            Ok(format!("unset {name}"))
        }
        [name, value] => {
            config_value(name, value)?;
            config.values.insert(name.clone(), value.clone());
            state.write("config", &canonical(&config)?)?;
            Ok(format!("set {name}"))
        }
        _ => Err(USAGE.into()),
    }
}

fn merge_file(
    base: Option<&Vec<u8>>,
    ours: Option<&Vec<u8>>,
    theirs: Option<&Vec<u8>>,
    path: &str,
) -> Result<Option<Vec<u8>>, String> {
    if ours == base {
        return Ok(theirs.cloned());
    }
    if theirs == base || ours == theirs {
        return Ok(ours.cloned());
    }
    match (base, ours, theirs) {
        (Some(b), Some(o), Some(t)) => wasm_git::merge::merge(b, o, t)
            .map_err(|e| format!("Wasm merge unavailable for {path}: {e}"))?
            .bytes
            .map(Some)
            .ok_or_else(|| format!("Wasm conflict at {path}")),
        _ => Err(format!("Wasm add/delete conflict at {path}")),
    }
}
fn merge_trees(base: &Files, ours: &Files, theirs: &Worktree) -> Result<Worktree, String> {
    let paths: BTreeSet<_> = base
        .keys()
        .cloned()
        .chain(ours.keys().cloned())
        .chain(theirs.keys().cloned())
        .collect();
    paths
        .into_iter()
        .map(|p| {
            let b = merge_file(
                base.get(&p),
                ours.get(&p),
                theirs.get(&p).and_then(Option::as_ref),
                &p,
            )?;
            Ok((p, b))
        })
        .collect()
}
fn stash(state: &State, args: &[String]) -> Result<String, String> {
    let mut all = state.stashes()?;
    let op = args.get(2).map_or("push", String::as_str);
    match op {
        "list" if args.len() == 3 => json_text(
            &all.entries
                .iter()
                .rev()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "message": e.message,
                        "paths": e.index.files.keys().collect::<Vec<_>>(),
                        "index_bytes": e.index.files.values().map(Vec::len).sum::<usize>(),
                        "worktree_bytes": e.worktree.values().filter_map(Option::as_ref).map(Vec::len).sum::<usize>()
                    })
                })
                .collect::<Vec<_>>(),
        ),
        "push"
            if args.len() == 2
                || args.len() == 3
                || (args.len() == 5 && args[3] == "-m") =>
        {
            let index = state.index()?.ok_or("no index to stash")?;
            require_resolved_index(&index)?;
            if !index.intents.is_empty() { return Err("stage or remove intent-to-add paths before stashing".into()); }
            let base = state.head()?.ok_or("cannot stash before first commit")?;
            let mut target = state.revision_index(&base, index.legacy_path.as_deref())?;
            index_flags::inherit(&mut target,&index);
            let paths: BTreeSet<_> = index
                .files
                .keys()
                .cloned()
                .chain(target.files.keys().cloned())
                .collect();
            let worktree = state.snapshot_worktree(paths)?;
            if index.files == target.files && worktree == files_worktree(&target.files) {
                return Ok("no local changes to save".into());
            }
            let changes = plan_index_transition(state,&index,&target,true)?;
            let id = all.next_id;
            all.next_id = id.checked_add(1).ok_or("stash sequence exhausted")?;
            all.entries.push(Stash {
                id,
                message: args.get(4).cloned().unwrap_or_default(),
                base: base.clone(),
                index,
                worktree,
            });
            state.write("stash", &canonical(&all)?)?;
            if state.head()?.as_ref() != Some(&base) {
                return Err(format!(
                    "saved stash {id}; HEAD changed, index/worktree not reset"
                ));
            }
            apply_plan(state, &changes)
                .map_err(|e| format!("saved stash {id}; index not reset: {e}"))?;
            state.save_index(&target).map_err(|e| {
                format!("saved stash {id}, worktree reset, index reset failed: {e}")
            })?;
            Ok(format!("saved stash {id}"))
        }
        "apply" | "pop" | "drop" => {
            let id: u64 = args
                .get(3)
                .ok_or(USAGE)?
                .parse()
                .map_err(|_| "stash ID must be unsigned integer")?;
            let pos = all
                .entries
                .iter()
                .position(|e| e.id == id)
                .ok_or("unknown stash ID")?;
            if op == "drop" {
                if args.len() != 4 {
                    return Err(USAGE.into());
                }
                all.entries.remove(pos);
                state.write("stash", &canonical(&all)?)?;
                return Ok(format!("dropped stash {id}"));
            }
            let e = &all.entries[pos];
            if args.len() == 6 && op == "apply" && args[4] == "--output" {
                let present: Vec<_> = e.worktree.values().filter_map(Option::as_ref).collect();
                if present.len() != 1 {
                    return Err("stash export requires exactly one present worktree file".into());
                }
                state.output(&args[5], present[0])?;
                return Ok(format!("exported stash {id}; index/worktree unchanged"));
            }
            if args.len() != 4 {
                return Err(USAGE.into());
            }
            let current = clean_index(state)?.unwrap_or_else(Index::empty);
            let head = state.head()?.ok_or("stash apply requires HEAD")?;
            let ours = state.revision_index(
                &head,
                current
                    .legacy_path
                    .as_deref()
                    .or(e.index.legacy_path.as_deref()),
            )?;
            let base = state.revision_index(&e.base, e.index.legacy_path.as_deref())?;
            let staged = merge_trees(&base.files, &ours.files, &files_worktree(&e.index.files))?;
            let worktree = merge_trees(&base.files, &ours.files, &e.worktree)?;
            let mut target = Index {
                format: 2,
                files: staged
                    .into_iter()
                    .filter_map(|(p, b)| b.map(|b| (p, b)))
                    .collect(),
                legacy_path: ours.legacy_path.or_else(|| e.index.legacy_path.clone()),
                conflicts: BTreeMap::new(),
            flags: BTreeMap::new(),
            intents: BTreeSet::new(),
            resolve_undo: BTreeMap::new(),
            };
            index_flags::inherit(&mut target,&e.index);
            target.resolve_undo = e.index.resolve_undo.clone();
            if !target.resolve_undo.is_empty() {
                target.format = target.format.max(5);
            }
            validate_index(&target)?;
            let changes = plan(state, &keys(&current.files), &worktree)?;
            apply_plan(state, &changes)?;
            state.save_index(&target).map_err(|er| {
                format!(
                    "stash {id} worktree applied, index update failed; saved entry retained: {er}"
                )
            })?;
            if op == "pop" {
                all.entries.remove(pos);
                state.write("stash", &canonical(&all)?).map_err(|er| {
                    format!("stash {id} applied, saved entry removal failed: {er}")
                })?;
            }
            Ok(format!("applied stash {id}"))
        }
        _ => Err(USAGE.into()),
    }
}
