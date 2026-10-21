//! Publish complete new files without replacing an existing destination.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn io_error(action: &str, path: &Path, error: std::io::Error) -> String {
    format!("cannot {action} {}: {error}", path.display())
}

fn unique_name() -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(
        ".uwgit-output-{}-{timestamp}-{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

struct StagedOutput {
    path: PathBuf,
    cleanup: bool,
}

impl Drop for StagedOutput {
    fn drop(&mut self) {
        // Only the exclusively created staging path belongs to this operation.
        // Never remove the final path, even when publishing or syncing fails.
        if self.cleanup {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl StagedOutput {
    fn new(parent: &Path, bytes: &[u8]) -> Result<Self, String> {
        let path = parent.join(unique_name());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| io_error("create output staging file", &path, error))?;
        let staged = Self {
            path,
            cleanup: true,
        };
        let written = file
            .write_all(bytes)
            .map_err(|error| io_error("write output staging file", &staged.path, error))
            .and_then(|()| {
                file.sync_all()
                    .map_err(|error| io_error("sync output staging file", &staged.path, error))
            });
        // Close the file before cleanup on error, including on platforms which
        // cannot unlink an open file.
        drop(file);
        written?;
        Ok(staged)
    }

    fn publish(mut self, destination: &Path) -> Result<(), String> {
        // Linking is an atomic create-if-absent operation. A competing writer,
        // regular file, directory, or symlink cannot be replaced by this call.
        fs::hard_link(&self.path, destination)
            .map_err(|error| io_error("publish new output file", destination, error))?;
        fs::remove_file(&self.path)
            .map_err(|error| io_error("remove output staging file", &self.path, error))?;
        self.cleanup = false;
        let parent = parent_directory(destination);
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("sync output directory", parent, error))
    }
}

/// Write and sync an exclusive sibling temporary file, then atomically publish
/// the complete bytes without replacing any existing destination. Failures
/// clean this operation's temporary file; interruption can leave a unique temp.
/// A failure after publication can leave a complete final file, never a partial
/// final file. Filesystems without hard-link support are rejected.
pub fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.file_name().is_none() {
        return Err(format!(
            "output path must name a new file: {}",
            path.display()
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(format!(
                "refusing to replace existing output: {}",
                path.display()
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("inspect output destination", path, error)),
    }
    StagedOutput::new(parent_directory(path), bytes)?.publish(path)
}

/// Export through an existing resolved directory outside repository metadata.
/// Resolve parent aliases once and use that same directory for publication.
pub fn write_export_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    // file_name normalizes trailing separators and `.` components. Preserve
    // the requested directory semantics before selecting a destination name.
    let final_component = path
        .as_os_str()
        .as_encoded_bytes()
        .rsplit(|byte| std::path::is_separator(*byte as char))
        .next()
        .unwrap_or_default();
    if final_component.is_empty() || final_component == b"." || final_component == b".." {
        return Err(format!(
            "output path must name a new file: {}",
            path.display()
        ));
    }
    let filename = path
        .file_name()
        .ok_or_else(|| format!("output path must name a new file: {}", path.display()))?;
    let parent = parent_directory(path);
    let parent = fs::canonicalize(parent)
        .map_err(|error| io_error("resolve output parent", parent, error))?;
    if parent.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|part| part.eq_ignore_ascii_case(".uwgit"))
    }) {
        return Err("output must be outside repository metadata".into());
    }
    write_new_file(&parent.join(filename), bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let path = Path::new("/tmp").join(unique_name());
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn entries(&self) -> Vec<PathBuf> {
            let mut entries: Vec<_> = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            entries
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn complete_outputs_are_published_without_staging_files() {
        let temp = TempDirectory::new();
        let destination = temp.path("result.wasm");
        let bytes: Vec<_> = (0..1_000_000).map(|index| (index % 251) as u8).collect();
        write_new_file(&destination, &bytes).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(temp.entries(), vec![destination.clone()]);
        assert!(write_new_file(&destination, b"replacement").is_err());
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(temp.entries(), vec![destination]);
    }

    #[test]
    fn bare_relative_filenames_use_the_current_directory_without_changing_cwd() {
        assert_eq!(parent_directory(Path::new("result.wasm")), Path::new("."));
        assert_eq!(parent_directory(Path::new("./result.wasm")), Path::new("."));
        assert_eq!(parent_directory(Path::new("a/result.wasm")), Path::new("a"));
    }

    #[test]
    fn exports_reject_metadata_components_and_preserve_internal_publication() {
        let temp = TempDirectory::new();
        for (case, name) in [("lower", ".uwgit"), ("mixed", ".UwGiT")] {
            let container = temp.path(case);
            fs::create_dir(&container).unwrap();
            let metadata = container.join(name);
            fs::create_dir(&metadata).unwrap();
            let nested = metadata.join("tmp");
            fs::create_dir(&nested).unwrap();
            for parent in [&metadata, &nested] {
                let destination = parent.join("export.wasm");
                assert!(write_export_file(&destination, b"export").is_err());
                assert!(!destination.exists());
                assert!(fs::read_dir(parent).unwrap().all(|entry| {
                    !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".uwgit-output-")
                }));
            }
            let internal = metadata.join("internal");
            write_new_file(&internal, b"metadata").unwrap();
            assert_eq!(fs::read(internal).unwrap(), b"metadata");
        }
        let ordinary = temp.path(".uwgit-exports");
        fs::create_dir(&ordinary).unwrap();
        let destination = ordinary.join("result.wasm");
        write_export_file(&destination, b"complete export").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"complete export");
        assert!(write_export_file(&destination, b"replacement").is_err());
        assert_eq!(fs::read(destination).unwrap(), b"complete export");
        let missing = temp.path("missing").join("result.wasm");
        assert!(write_export_file(&missing, b"unpublished").is_err());
        assert!(!temp.path("missing").exists());
    }

    #[test]
    fn exports_preserve_lexical_directory_requests_and_invalid_parents() {
        let temp = TempDirectory::new();
        for name in ["missing/", "missing/.", "missing/.//"] {
            assert!(write_export_file(&temp.path(name), b"unpublished").is_err());
            assert!(temp.entries().is_empty());
        }
        let directory = temp.path("existing");
        fs::create_dir(&directory).unwrap();
        let parent_file = temp.path("parent-file");
        fs::write(&parent_file, b"preserve parent bytes").unwrap();
        let before = temp.entries();
        for name in [
            "existing/",
            "existing/.",
            "existing/.//",
            "parent-file/child",
        ] {
            assert!(write_export_file(&temp.path(name), b"unpublished").is_err());
            assert_eq!(temp.entries(), before);
            assert!(fs::read_dir(&directory).unwrap().next().is_none());
            assert_eq!(fs::read(&parent_file).unwrap(), b"preserve parent bytes");
        }
        let ordinary = temp.path("ordinary.wasm");
        write_export_file(&ordinary, b"complete export").unwrap();
        assert_eq!(fs::read(ordinary).unwrap(), b"complete export");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let non_utf8 = temp.0.join(std::ffi::OsStr::from_bytes(b"non-utf8-\xff"));
            write_export_file(&non_utf8, b"non-UTF-8 filename").unwrap();
            assert_eq!(fs::read(non_utf8).unwrap(), b"non-UTF-8 filename");
        }
    }

    #[cfg(unix)]
    #[test]
    fn exports_resolve_parent_aliases_before_metadata_check_and_publication() {
        use std::os::unix::fs::symlink;
        let temp = TempDirectory::new();
        let metadata = temp.path(".uwgit");
        fs::create_dir(&metadata).unwrap();
        let blocked_alias = temp.path("metadata-alias");
        symlink(&metadata, &blocked_alias).unwrap();
        assert!(write_export_file(&blocked_alias.join("index.lock"), b"blocked").is_err());
        assert!(fs::read_dir(&metadata).unwrap().next().is_none());
        let ordinary = temp.path("exports");
        fs::create_dir(&ordinary).unwrap();
        let ordinary_alias = temp.path("export-alias");
        symlink(&ordinary, &ordinary_alias).unwrap();
        write_export_file(&ordinary_alias.join("result.wasm"), b"exported").unwrap();
        assert_eq!(fs::read(ordinary.join("result.wasm")).unwrap(), b"exported");
        let target = ordinary.join("preserve");
        fs::write(&target, b"existing bytes").unwrap();
        symlink(&target, ordinary.join("existing-link")).unwrap();
        assert!(write_export_file(&ordinary_alias.join("existing-link"), b"replacement").is_err());
        assert_eq!(fs::read(target).unwrap(), b"existing bytes");
    }

    #[test]
    fn a_competing_publication_is_preserved_and_only_our_temp_is_cleaned() {
        let temp = TempDirectory::new();
        let unrelated_temp = temp.path("unrelated.tmp");
        fs::write(&unrelated_temp, b"keep").unwrap();
        let destination = temp.path("result.wasm");
        // Pause at the real publication boundary to reproduce a losing writer
        // deterministically, without timing a thread against filesystem I/O.
        let staged = StagedOutput::new(&temp.0, b"our complete bytes").unwrap();
        let staged_path = staged.path.clone();
        assert!(staged_path.exists());
        assert!(!destination.exists());
        fs::write(&destination, b"winning writer").unwrap();
        assert!(staged.publish(&destination).is_err());
        assert!(!staged_path.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"winning writer");
        assert_eq!(fs::read(&unrelated_temp).unwrap(), b"keep");
        assert_eq!(temp.entries().len(), 2);
    }

    #[test]
    fn publication_failure_cleans_staging_and_missing_parent_creates_nothing() {
        let temp = TempDirectory::new();
        let staged = StagedOutput::new(&temp.0, b"complete").unwrap();
        let staged_path = staged.path.clone();
        let destination = temp.path("missing").join("result.wasm");
        assert!(staged.publish(&destination).is_err());
        assert!(!staged_path.exists());
        assert!(temp.entries().is_empty());
        assert!(write_new_file(&destination, b"never published").is_err());
        assert!(temp.entries().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn existing_and_competing_symlinks_are_preserved() {
        use std::os::unix::fs::symlink;
        let temp = TempDirectory::new();
        let outside = temp.path("outside");
        fs::write(&outside, b"preserve target").unwrap();
        let destination = temp.path("result.wasm");
        symlink(&outside, &destination).unwrap();
        assert!(write_new_file(&destination, b"must not replace").is_err());
        assert!(fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&outside).unwrap(), b"preserve target");
        fs::remove_file(&destination).unwrap();
        let staged = StagedOutput::new(&temp.0, b"staged").unwrap();
        let staged_path = staged.path.clone();
        symlink(&outside, &destination).unwrap();
        assert!(staged.publish(&destination).is_err());
        assert!(!staged_path.exists());
        assert!(fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&outside).unwrap(), b"preserve target");
    }
}
