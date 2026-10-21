# uwgit local reader bounds patch

This directory retains all 72 regular files from the wasmparser 0.249.0 crate.
The canonical crate SHA-256 is `30538cae9a794215f490b532df01c557e2e2bfac92569482554acd0992a102ea`.
The upstream VCS revision is `efeee7cafa5a3dcdddb5aab27bc0c05f279929ed`.
The original licenses, Cargo metadata and VCS record are retained.
File hashes and the sole code delta are recorded in `../wasmparser-upstream.json`.

Only `BinaryReader::ensure_has_bytes` differs from upstream. Given the reader
invariant `position <= buffer.len()`, `len <= buffer.len() - position` tests the
same bound without adding an untrusted length. On EOF, `len - remaining` is the
same mathematical needed hint without overflowing. Messages and offsets are
unchanged. No byte is projected or replaced, and validation is still executed.

This fixes 32-bit overflows reached by code/data length-prefixed reads, custom
name re-reading during merge, and other readers using this common bound.
It does not change Core grammar, selected feature flags or resource limits.
The crate version remains 0.249.0; this is explicitly a local patch, not an
unmodified upstream release. Root and fuzz manifests resolve registry users to
this directory. Keeping the fuzz manifest consistent does not run fuzz.
