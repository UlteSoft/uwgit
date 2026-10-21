#!/usr/bin/env bash
# All compilation/execution runs inside the existing Linux cgroup. The local
# side only reads reference inputs and stages/compares them under /tmp.
set -euo pipefail
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
reference_dir=${UWGIT_UWVM_SOURCE:-"$repo_dir/../uwvm2-ros"}
remote_host=${UWGIT_SSH_HOST:-linux}
container=${UWGIT_CONTAINER:-uwvm-debug-core3-v48-20261011}
remote_root=${UWGIT_REMOTE_ROOT:-/tmp/uwgit-20261019}
skip_fuzz=${UWGIT_SKIP_FUZZ:-0}
[[ $skip_fuzz == 0 || $skip_fuzz == 1 ]] || { echo 'UWGIT_SKIP_FUZZ must be 0 or 1' >&2; exit 2; }
if [[ ${UWGIT_CORPUS_MODE+x} ]]; then
    corpus_mode=$UWGIT_CORPUS_MODE
elif [[ $skip_fuzz == 1 ]]; then
    corpus_mode=originals-only
else
    corpus_mode=fixed-mutations
fi
[[ $corpus_mode == originals-only || $corpus_mode == fixed-mutations ]] || { echo 'invalid UWGIT_CORPUS_MODE' >&2; exit 2; }
[[ $skip_fuzz != 1 || $corpus_mode == originals-only ]] || { echo 'UWGIT_SKIP_FUZZ=1 requires UWGIT_CORPUS_MODE=originals-only' >&2; exit 2; }
[[ $container =~ ^[A-Za-z0-9_.-]+$ ]] || { echo 'invalid container' >&2; exit 2; }
[[ $remote_root =~ ^/tmp/[A-Za-z0-9_./-]+$ && $remote_root != *..* ]] || { echo 'invalid /tmp root' >&2; exit 2; }
staging=$(mktemp -d /tmp/uwgit-uwvm-source.XXXXXXXX)
receipt=$(mktemp -d /tmp/uwgit-uwvm-receipt.XXXXXXXX)
cleanup() { rm -rf "$staging"; }
trap cleanup EXIT
python3 "$repo_dir/tools/uwvm-examples-inputs.py" snapshot "$reference_dir" "$staging/inputs.json"
cp "$staging/inputs.json" "$receipt/inputs.before.json"
python3 "$repo_dir/tools/uwvm-examples-inputs.py" archive "$reference_dir" "$staging/inputs.json" \
    --output "$staging/reference.tar"
python3 "$repo_dir/tools/uwvm-examples-inputs.py" compare "$reference_dir" "$staging/inputs.json"
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='._*' -cf "$staging/source.tar" -C "$repo_dir" \
    Cargo.toml Cargo.lock src tests tools vendor fuzz/Cargo.toml fuzz/Cargo.lock fuzz/generate_seeds.rs fuzz/fuzz_targets
incoming="/tmp/uwgit-uwvm-source-$(id -u)-$$"
scp -q "$staging/reference.tar" "$remote_host:$incoming-reference.tar"
scp -q "$staging/inputs.json" "$remote_host:$incoming-inputs.json"
scp -q "$staging/source.tar" "$remote_host:$incoming-source.tar"
set +e
ssh "$remote_host" "docker exec -i '$container' chroot /host /bin/bash -s -- '$remote_root' '$incoming' '$skip_fuzz' '$corpus_mode'" < "$repo_dir/tools/test-uwvm-examples-remote.sh"
run_status=$?
# Always recheck the original checkout, including after a failed remote test.
python3 "$repo_dir/tools/uwvm-examples-inputs.py" compare "$reference_dir" "$staging/inputs.json" > "$receipt/reference.after.json" 2> "$receipt/reference.after.log"
reference_status=$?
set -e
cat "$receipt/reference.after.json" "$receipt/reference.after.log"
printf '{"remote_status":%s,"reference_status":%s}\n' "$run_status" "$reference_status" > "$receipt/status.json"
printf 'Local reference receipt: %s\n' "$receipt"
[[ $run_status == 0 && $reference_status == 0 ]]
