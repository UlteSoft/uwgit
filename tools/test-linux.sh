#!/usr/bin/env bash
# Source is edited in the checkout; all staging and execution use /tmp.
set -euo pipefail
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
remote_host=${UWGIT_SSH_HOST:-linux}
container=${UWGIT_CONTAINER:-uwvm-debug-core3-v48-20261011}
remote_root=${UWGIT_REMOTE_ROOT:-/tmp/uwgit-20261019}
run_spec=${UWGIT_RUN_SPEC:-0}
[[ $run_spec == 0 || $run_spec == 1 ]] || { echo 'UWGIT_RUN_SPEC must be 0 or 1' >&2; exit 2; }
[[ $container =~ ^[A-Za-z0-9_.-]+$ ]] || { echo 'invalid container name' >&2; exit 2; }
[[ $remote_root =~ ^/tmp/[A-Za-z0-9_./-]+$ && $remote_root != *..* ]] || { echo 'remote root must be a simple /tmp path' >&2; exit 2; }
staging=$(mktemp -d /tmp/uwgit-source.XXXXXXXX)
trap 'rm -rf "$staging"' EXIT
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='._*' -cf "$staging/source.tar" -C "$repo_dir" Cargo.toml Cargo.lock src tests tools
incoming="/tmp/uwgit-source-$(id -u)-$$.tar"
scp -q "$staging/source.tar" "$remote_host:$incoming"
ssh "$remote_host" "docker exec -i '$container' chroot /host /bin/bash -s -- '$remote_root' '$incoming' '$run_spec'" < "$repo_dir/tools/test-linux-remote.sh"
