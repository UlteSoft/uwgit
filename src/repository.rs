//! A lossless, local, content-addressed Wasm repository.
//!
//! Objects contain the original bytes, never a normalized representation. The
//! versioned object envelope (including its type and payload length) is hashed
//! with SHA-256. Commits form an immutable DAG; branch files are the only mutable
//! history pointers. Bundles are self-contained and verified before publication.
//! Mutations and consistent snapshots use `.uwgit/write.lock`; a crashed writer's
//! lock requires manual inspection and removal before another writer proceeds.
//!
//! This initial format has no signatures, network authentication,
//! compression, or garbage collection. Object verification currently reads the
//! complete store into memory. Hashes establish integrity, not an author's identity.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub type RepositoryResult<T> = Result<T, String>;

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

const FORMAT: &[u8] = b"uwgit-repository-v1\n";
const OBJECT_MAGIC: &[u8; 8] = b"UWGO\0\0\0\x01";
const BUNDLE_MAGIC: &[u8; 8] = b"UWGB\0\0\0\x01";
const WASM_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";
const OBJECT_HEADER_LENGTH: usize = 17;
const WASM_KIND: u8 = 1;
const COMMIT_KIND: u8 = 2;
const REPOSITORY_USAGE: &str = "repository commands: init <DIR>; commit <DIR> <WASM> -m <MESSAGE>; merge <DIR> <REF_OR_ID> -m <MESSAGE>; merge <DIR> <TARGET_ID> -m <MESSAGE> --resolved <WASM> --expect-head <HEAD_ID>; merge-base <DIR> <LEFT> <RIGHT>; log <DIR> [REF_OR_ID]; show <DIR> <REF_OR_ID> [--output <NEW_FILE>]; checkout <DIR> <REF_OR_ID> <NEW_FILE>; branch <DIR> [NAME [REF_OR_ID]]; switch <DIR> <BRANCH>; clone <SOURCE_DIR> <NEW_DIR>; bundle <DIR> <NEW_BUNDLE_FILE>; unbundle <DIR> <BUNDLE> <BRANCH>; fsck <DIR>";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct Repository {
    pub root: PathBuf,
    metadata: PathBuf,
}

/// Field order is part of the version-one canonical commit encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub format: u32,
    pub wasm: String,
    pub parents: Vec<String>,
    pub message: String,
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
    pub branches: usize,
    pub unreachable_objects: usize,
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
}

#[derive(Debug, Serialize)]
pub struct ManualResolution {
    pub supplied_bytes: bool,
    pub wasm: String,
    pub audit_validation: String,
    pub diagnostic_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    head: String,
    refs: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
enum Object {
    Wasm(Vec<u8>),
    Commit(Commit),
}

#[derive(Debug)]
struct Snapshot {
    manifest: Manifest,
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
        for child in ["objects", "refs", "tmp"] {
            let path = metadata.join(child);
            fs::create_dir(&path).map_err(|e| io_error("create repository directory", &path, e))?;
        }
        write_new_file(&metadata.join("HEAD"), b"main\n")?;
        // Write the format marker last; incomplete initialization cannot be opened.
        write_new_file(&metadata.join("format"), FORMAT)?;
        sync_directory(&metadata)?;
        Ok(Self { root, metadata })
    }

    pub fn open(root: impl AsRef<Path>) -> RepositoryResult<Self> {
        let root = root.as_ref().to_path_buf();
        require_directory(&root)?;
        let metadata = root.join(".uwgit");
        require_directory(&metadata)?;
        for child in ["objects", "refs", "tmp"] {
            require_directory(&metadata.join(child))?;
        }
        if read_regular(&metadata.join("format"))? != FORMAT {
            return Err("unsupported or incomplete uwgit repository format".into());
        }
        let repo = Self { root, metadata };
        repo.current_branch()?;
        Ok(repo)
    }

    pub fn current_branch(&self) -> RepositoryResult<String> {
        parse_ref_file(&read_regular(&self.metadata.join("HEAD"))?, false)
    }

    pub fn branches(&self) -> RepositoryResult<BTreeMap<String, String>> {
        let _lock = self.lock()?;
        self.read_refs()
    }

    /// Store any core Wasm byte stream, including unknown or future features.
    /// Header validation intentionally does not impose an instruction validator.
    pub fn commit(&self, bytes: &[u8], message: &str) -> RepositoryResult<String> {
        validate_wasm_header(bytes)?;
        let _lock = self.lock()?;
        let branch = self.current_branch()?;
        let mut parents = Vec::new();
        if let Some(parent) = self.read_ref_optional(&branch)? {
            // Never extend a broken history, even if its immediate commit exists.
            self.verify_history(&parent)?;
            parents.push(parent);
        }
        let wasm = self.store_object(WASM_KIND, bytes)?;
        let commit = Commit {
            format: 1,
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
    pub fn merge(
        &self,
        target_revision: &str,
        message: &str,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        let _lock = self.lock()?;
        // Verify the whole store, including dangling histories, before treating
        // ancestry as evidence or allowing a fast-forward to hide corruption.
        let snapshot = self.snapshot()?;
        let branch = snapshot.manifest.head.clone();
        let target = snapshot_revision(&snapshot, target_revision)?;
        let old_head = snapshot.manifest.refs.get(&branch).cloned();
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
        };
        let Some(ours) = old_head else {
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
        if is_ancestor(&ours, &target, &snapshot.objects)? {
            self.write_ref(&branch, &target)?;
            outcome.status = "fast_forward".into();
            outcome.base = Some(ours);
            outcome.commit = Some(target);
            return Ok(outcome);
        }
        let base = unique_merge_base(&ours, &target, &snapshot.objects)?;
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
                let wasm = self.store_object(WASM_KIND, &bytes)?;
                let commit = Commit {
                    format: 1,
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
    pub fn merge_resolved(
        &self,
        expected_head: &str,
        target_id: &str,
        bytes: &[u8],
        message: &str,
    ) -> RepositoryResult<RepositoryMergeOutcome> {
        require_id(expected_head)?;
        require_id(target_id)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let branch = snapshot.manifest.head.clone();
        let ours = snapshot
            .manifest
            .refs
            .get(&branch)
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
        })
    }

    pub fn resolve(&self, revision: &str) -> RepositoryResult<String> {
        let id = if revision == "HEAD" {
            let branch = self.current_branch()?;
            self.read_ref_optional(&branch)?
                .ok_or_else(|| format!("branch {branch} has no commits"))?
        } else if valid_id(revision) {
            revision.to_owned()
        } else {
            validate_ref_name(revision)?;
            self.read_ref_optional(revision)?
                .ok_or_else(|| format!("unknown revision: {revision}"))?
        };
        self.read_commit_id(&id)?;
        Ok(id)
    }

    pub fn read_commit(&self, revision: &str) -> RepositoryResult<CommitInfo> {
        let id = self.resolve(revision)?;
        self.verify_history(&id)?;
        let commit = self.read_commit_id(&id)?;
        Ok(CommitInfo { id, commit })
    }

    #[cfg(test)]
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
        let bytes = match self.read_object(&info.commit.wasm)? {
            Object::Wasm(bytes) => bytes,
            Object::Commit(_) => return Err("commit references a non-Wasm object".into()),
        };
        write_new_file(destination.as_ref(), &bytes)?;
        Ok(info.id)
    }

    /// Traverse all ancestors once, with every child preceding its parents.
    pub fn log(&self, revision: Option<&str>) -> RepositoryResult<Vec<CommitInfo>> {
        let _lock = self.lock()?;
        let id = match revision {
            Some(rev) => self.resolve(rev)?,
            None => {
                let branch = self.current_branch()?;
                match self.read_ref_optional(&branch)? {
                    Some(id) => id,
                    None => return Ok(Vec::new()),
                }
            }
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
        let id = self.resolve(revision)?;
        self.verify_history(&id)?;
        self.write_ref(name, &id)?;
        Ok(id)
    }

    pub fn switch_branch(&self, name: &str) -> RepositoryResult<()> {
        validate_ref_name(name)?;
        let _lock = self.lock()?;
        let id = self
            .read_ref_optional(name)?
            .ok_or_else(|| format!("unknown branch: {name}"))?;
        self.verify_history(&id)?;
        self.atomic_write(&self.metadata.join("HEAD"), format!("{name}\n").as_bytes())
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
            wasm_blobs: snapshot.objects.len() - commits,
            branches: snapshot.manifest.refs.len(),
            unreachable_objects: snapshot.objects.len() - reachable.len(),
        })
    }

    pub fn export_bundle(&self, destination: impl AsRef<Path>) -> RepositoryResult<usize> {
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let bundle = encode_bundle(&snapshot)?;
        write_new_file(destination.as_ref(), &bundle)?;
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
            .refs
            .get(&incoming.manifest.head)
            .cloned()
            .ok_or_else(|| "bundle has no commit at its HEAD branch".to_string())?;
        let _lock = self.lock()?;
        // Existing corruption must not be hidden by newly imported objects.
        let current = self.snapshot()?;
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
        for (id, bytes) in &incoming.encoded {
            self.install_encoded_object(id, bytes)?;
        }
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
            for (id, bytes) in &snapshot.encoded {
                repo.install_encoded_object(id, bytes)?;
            }
            for (name, id) in &snapshot.manifest.refs {
                repo.write_ref(name, id)?;
            }
            repo.atomic_write(
                &repo.metadata.join("HEAD"),
                format!("{}\n", snapshot.manifest.head).as_bytes(),
            )?;
        }
        Ok(repo)
    }

    fn lock(&self) -> RepositoryResult<WriteLock> {
        let path = self.metadata.join("write.lock");
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

    fn read_refs(&self) -> RepositoryResult<BTreeMap<String, String>> {
        let mut refs = BTreeMap::new();
        let path = self.metadata.join("refs");
        for entry in fs::read_dir(&path).map_err(|e| io_error("read refs", &path, e))? {
            let entry = entry.map_err(|e| format!("read branch entry: {e}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 branch name".to_string())?;
            validate_ref_name(&name)?;
            let id = parse_ref_file(&read_regular(&entry.path())?, true)?;
            refs.insert(name, id);
        }
        Ok(refs)
    }

    fn read_ref_optional(&self, name: &str) -> RepositoryResult<Option<String>> {
        validate_ref_name(name)?;
        let path = self.metadata.join("refs").join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(Some(parse_ref_file(&read_regular(&path)?, true)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error("read branch", &path, e)),
        }
    }

    fn write_ref(&self, name: &str, id: &str) -> RepositoryResult<()> {
        validate_ref_name(name)?;
        require_id(id)?;
        self.atomic_write(
            &self.metadata.join("refs").join(name),
            format!("{id}\n").as_bytes(),
        )
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
        let temp = self.metadata.join("tmp").join(unique_name("ref"));
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
        )
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
        let destination = self.metadata.join("objects").join(id);
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
        let temp = self.metadata.join("tmp").join(unique_name("object"));
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
        sync_directory(&self.metadata.join("objects"))
    }

    fn read_object(&self, id: &str) -> RepositoryResult<Object> {
        require_id(id)?;
        let bytes = read_regular(&self.metadata.join("objects").join(id))?;
        decode_object(id, &bytes)
    }

    fn read_commit_id(&self, id: &str) -> RepositoryResult<Commit> {
        match self.read_object(id)? {
            Object::Commit(commit) => Ok(commit),
            Object::Wasm(_) => Err(format!("revision {id} is a Wasm blob, not a commit")),
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
                pending.push(commit.wasm.clone());
                pending.extend(commit.parents.iter().cloned());
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
        let manifest = Manifest {
            format: 1,
            head: self.current_branch()?,
            refs: self.read_refs()?,
        };
        let mut encoded = BTreeMap::new();
        let mut objects = BTreeMap::new();
        let path = self.metadata.join("objects");
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
        validate_snapshot(&manifest, &objects)?;
        Ok(Snapshot {
            manifest,
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

fn validate_ref_name(name: &str) -> RepositoryResult<()> {
    if name.is_empty()
        || name.len() > 128
        || name == "HEAD"
        || valid_id(name)
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || name.ends_with(".lock")
    {
        return Err(format!(
            "invalid branch name {name:?}: use 1-128 ASCII letters, digits, '.', '_' or '-', starting with a letter or digit; HEAD, object IDs and .lock suffixes are reserved"
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
        validate_ref_name(value)?;
    }
    Ok(value.to_owned())
}

fn encode_commit(commit: &Commit) -> RepositoryResult<Vec<u8>> {
    serde_json::to_vec(commit).map_err(|e| format!("encode commit: {e}"))
}

fn encode_object(kind: u8, payload: &[u8]) -> RepositoryResult<Vec<u8>> {
    if ![WASM_KIND, COMMIT_KIND].contains(&kind) {
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
            if commit.format != 1 || encode_commit(&commit)? != payload {
                return Err(format!("unsupported or non-canonical commit: {id}"));
            }
            require_id(&commit.wasm)?;
            let mut parents = BTreeSet::new();
            for parent in &commit.parents {
                require_id(parent)?;
                if !parents.insert(parent) {
                    return Err(format!("duplicate parent in commit {id}"));
                }
            }
            Ok(Object::Commit(commit))
        }
        kind => Err(format!("unknown repository object type {kind} at {id}")),
    }
}

fn validate_object_graph(objects: &BTreeMap<String, Object>) -> RepositoryResult<()> {
    let mut remaining = BTreeMap::<String, usize>::new();
    let mut children = BTreeMap::<String, Vec<String>>::new();
    for (id, object) in objects {
        if let Object::Commit(commit) = object {
            if !matches!(objects.get(&commit.wasm), Some(Object::Wasm(_))) {
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
                children.entry(parent.clone()).or_default().push(id.clone());
            }
        }
    }
    // Iterative topological validation has no recursion limit for long histories.
    let mut ready: VecDeque<String> = remaining
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut visited = 0;
    while let Some(id) = ready.pop_front() {
        visited += 1;
        for child in children.get(&id).into_iter().flatten() {
            let count = remaining.get_mut(child).ok_or("invalid commit graph")?;
            *count -= 1;
            if *count == 0 {
                ready.push_back(child.clone());
            }
        }
    }
    if visited != remaining.len() {
        return Err("cyclic commit history".into());
    }
    Ok(())
}

fn validate_snapshot(
    manifest: &Manifest,
    objects: &BTreeMap<String, Object>,
) -> RepositoryResult<()> {
    if manifest.format != 1 {
        return Err("unsupported bundle manifest format".into());
    }
    validate_ref_name(&manifest.head)?;
    for (name, id) in &manifest.refs {
        validate_ref_name(name)?;
        require_id(id)?;
        if !matches!(objects.get(id), Some(Object::Commit(_))) {
            return Err(format!(
                "branch {name} references a missing or non-commit object {id}"
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
    let mut seen = BTreeSet::new();
    let mut pending: Vec<String> = manifest.refs.values().cloned().collect();
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        match objects.get(&id) {
            Some(Object::Commit(commit)) => {
                pending.push(commit.wasm.clone());
                pending.extend(commit.parents.iter().cloned());
            }
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

fn snapshot_revision(snapshot: &Snapshot, revision: &str) -> RepositoryResult<String> {
    let id = if revision == "HEAD" {
        snapshot
            .manifest
            .refs
            .get(&snapshot.manifest.head)
            .cloned()
            .ok_or_else(|| format!("branch {} has no commits", snapshot.manifest.head))?
    } else if valid_id(revision) {
        revision.to_owned()
    } else {
        validate_ref_name(revision)?;
        snapshot
            .manifest
            .refs
            .get(revision)
            .cloned()
            .ok_or_else(|| format!("unknown revision: {revision}"))?
    };
    if !matches!(snapshot.objects.get(&id), Some(Object::Commit(_))) {
        return Err(format!("revision {id} is a missing or non-commit object"));
    }
    Ok(id)
}

fn snapshot_wasm<'a>(snapshot: &'a Snapshot, commit_id: &str) -> RepositoryResult<&'a [u8]> {
    let Some(Object::Commit(commit)) = snapshot.objects.get(commit_id) else {
        return Err(format!("missing merge commit {commit_id}"));
    };
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
    if args
        .iter()
        .skip(1)
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Ok(REPOSITORY_USAGE.into());
    }
    let command = args.first().map(String::as_str).unwrap_or("");
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
        "merge" if args.len() == 5 && matches!(args[3].as_str(), "-m" | "--message") => {
            let outcome = Repository::open(&args[1])?.merge(&args[2], &args[4])?;
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
            let outcome = Repository::open(&args[1])?
                .merge_resolved(&args[8], &args[2], &bytes, &args[4])?;
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
            "a/b",
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
            head: fs::read(repo.metadata.join("HEAD")).unwrap(),
        }
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
