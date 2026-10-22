#!/usr/bin/env bash
# Source is edited in the checkout; all staging and execution use /tmp.
set -euo pipefail
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
remote_host=${UWGIT_SSH_HOST:-linux}
container=${UWGIT_CONTAINER:-uwvm-debug-core3-v48-20261011}
remote_root=${UWGIT_REMOTE_ROOT:-/tmp/uwgit-20261019}
run_spec=${UWGIT_RUN_SPEC:-0}
run_fuzz=${UWGIT_RUN_FUZZ:-0}
skip_fuzz=${UWGIT_SKIP_FUZZ:-0}
run_doctest=${UWGIT_RUN_DOCTEST:-0}
expected_swap_max=${UWGIT_EXPECTED_CGROUP_SWAP_MAX:-0}
[[ $expected_swap_max == max || $expected_swap_max =~ ^(0|[1-9][0-9]*)$ ]] || { echo 'invalid expected cgroup swap limit' >&2; exit 2; }
[[ $skip_fuzz == 0 || $skip_fuzz == 1 ]] || { echo 'UWGIT_SKIP_FUZZ must be 0 or 1' >&2; exit 2; }
[[ $skip_fuzz != 1 || $run_fuzz == 0 ]] || { echo 'UWGIT_SKIP_FUZZ=1 conflicts with UWGIT_RUN_FUZZ=1' >&2; exit 2; }
[[ $run_spec == 0 || $run_spec == 1 ]] || { echo 'UWGIT_RUN_SPEC must be 0 or 1' >&2; exit 2; }
[[ $run_fuzz == 0 || $run_fuzz == 1 ]] || { echo 'UWGIT_RUN_FUZZ must be 0 or 1' >&2; exit 2; }
[[ $run_doctest == 0 || $run_doctest == 1 ]] || { echo 'UWGIT_RUN_DOCTEST must be 0 or 1' >&2; exit 2; }
if [[ ${UWGIT_CORPUS_MODE+x} ]]; then
    corpus_mode=$UWGIT_CORPUS_MODE
elif [[ $skip_fuzz == 1 ]]; then
    corpus_mode=originals-only
else
    corpus_mode=fixed-mutations
fi
[[ $corpus_mode == originals-only || $corpus_mode == fixed-mutations ]] || { echo 'UWGIT_CORPUS_MODE must be originals-only or fixed-mutations' >&2; exit 2; }
[[ $skip_fuzz != 1 || $corpus_mode == originals-only ]] || { echo 'UWGIT_SKIP_FUZZ=1 requires UWGIT_CORPUS_MODE=originals-only' >&2; exit 2; }
[[ $container =~ ^[A-Za-z0-9_.-]+$ ]] || { echo 'invalid container name' >&2; exit 2; }
[[ $remote_root =~ ^/tmp/[A-Za-z0-9_./-]+$ && $remote_root != *..* ]] || { echo 'remote root must be a simple /tmp path' >&2; exit 2; }
staging=$(mktemp -d /tmp/uwgit-source.XXXXXXXX)
trap 'rm -rf "$staging"' EXIT
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='._*' -cf "$staging/source.tar" -C "$repo_dir" \
    Cargo.toml Cargo.lock src tests tools vendor fuzz/Cargo.toml fuzz/Cargo.lock fuzz/generate_seeds.rs fuzz/fuzz_targets
python3 "$repo_dir/tools/source-manifest.py" create "$staging/source.tar" "$staging/source-inputs.json"
COPYFILE_DISABLE=1 tar --no-xattrs -rf "$staging/source.tar" -C "$staging" source-inputs.json
incoming="/tmp/uwgit-source-$(id -u)-$$.tar"
scp -q "$staging/source.tar" "$remote_host:$incoming"
ssh "$remote_host" "docker exec -i '$container' chroot /host /bin/bash -s -- '$remote_root' '$incoming' '$run_spec' '$run_fuzz' '$skip_fuzz' '$corpus_mode' '$run_doctest' '$expected_swap_max'" < "$repo_dir/tools/test-linux-remote.sh"
python3 "$repo_dir/tools/source-manifest.py" compare "$staging/source-inputs.json" "$repo_dir"
