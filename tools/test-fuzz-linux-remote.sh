#!/usr/bin/env bash
set -euo pipefail
root=$1
incoming=$2
runs=$3
nightly=nightly-2026-10-18
cg_path=$(awk -F: '$1 == "0" && $2 == "" {print $3}' /proc/self/cgroup)
cg="/sys/fs/cgroup$cg_path"
[[ $(uname -s) == Linux && $cg_path == /system.slice/docker-*.scope ]]
[[ $(cat "$cg/memory.max") == 68719476736 && $(cat "$cg/memory.swap.max") == 0 ]]
grep -Fxq "$$" "$cg/cgroup.procs"
umask 077
run="$root/libfuzzer-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$run/source" "$run/evidence" "$run/tmp" "$run/artifacts" "$run/corpus"
printf '%s\n' "$run" > "$root/libfuzzer-latest.txt"
tar -xf "$incoming" -C "$run/source"
rm "$incoming"
export CARGO_HOME="$root/toolchain/cargo" RUSTUP_HOME="$root/toolchain/rustup"
export PATH="$root/fuzz-tools/bin:$CARGO_HOME/bin:$PATH"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 TMPDIR="$run/tmp"
export CC=/usr/lib/llvm-22/bin/clang CXX=/usr/lib/llvm-22/bin/clang++
export CARGO_TARGET_DIR="$run/seed-target"
cd "$run/source"
{
    cat /proc/sys/kernel/random/boot_id /proc/self/cgroup
    cat "$cg/memory.max" "$cg/memory.swap.max" "$cg/memory.current" "$cg/cpuset.cpus.effective"
    rustc +stable --version
    rustc +"$nightly" -vV
    cargo fuzz --version
    "$CXX" --version
} > "$run/evidence/environment.txt"
sha256sum Cargo.toml Cargo.lock src/*.rs tests/*.rs tests/fixtures/*.wasm tests/fixtures/c/*.c tools/* \
    fuzz/Cargo.toml fuzz/Cargo.lock fuzz/generate_seeds.rs fuzz/fuzz_targets/*.rs > "$run/evidence/source.sha256"
find vendor -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >> "$run/evidence/source.sha256"
sha256sum "$root/fuzz-tools/bin/cargo-fuzz" "$CC" "$CXX" > "$run/evidence/compiler-tools.sha256"
cp "$cg/memory.events" "$run/evidence/memory.events.before"
set +e
cargo +stable fmt --manifest-path fuzz/Cargo.toml --check > "$run/evidence/fmt.log" 2>&1
fmt_status=$?
cargo +stable run --locked --manifest-path fuzz/Cargo.toml --features seed-generator --bin generate_seeds -- \
    "$run/seeds" "$run/evidence/seeds.json" > "$run/evidence/seeds.log" 2>&1
seeds_status=$?
build_status=1
fuzz_status=1
replay_status=1
if [[ $fmt_status == 0 && $seeds_status == 0 ]]; then
    cp "$run/seeds/"* "$run/corpus/"
    cargo +"$nightly" fuzz build raw_audit --fuzz-dir fuzz --target-dir "$run/fuzz-target" \
        --sanitizer address --codegen-units 16 > "$run/evidence/build.log" 2>&1
    build_status=$?
    if [[ $build_status == 0 ]]; then
        binary="$run/fuzz-target/x86_64-unknown-linux-gnu/release/raw_audit"
        sha256sum "$binary" > "$run/evidence/binary.sha256"
        python3 - "$binary" "$run" "$runs" <<'PY'
import json, pathlib, sys
binary, root, runs = sys.argv[1:]
run = pathlib.Path(root)
args = [binary, str(run/'corpus'), '-seed=757767697', '-runs='+runs,
        '-max_len=4096', '-timeout=10', '-rss_limit_mb=2048', '-print_final_stats=1',
        '-artifact_prefix='+str(run/'artifacts')+'/']
(run/'evidence/command.json').write_text(json.dumps(args, indent=2)+'\n')
PY
        python3 - "$run" <<'PY'
import json, pathlib, subprocess, sys
run = pathlib.Path(sys.argv[1])
args = json.loads((run/'evidence/command.json').read_text())
with (run/'evidence/fuzz.log').open('wb') as log:
    try:
        result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, timeout=900)
        outcome = {'returncode': result.returncode}
    except subprocess.TimeoutExpired:
        outcome = {'returncode': None, 'wall_timeout_seconds': 900}
(run/'evidence/fuzz-exit.json').write_text(json.dumps(outcome)+'\n')
sys.exit(0 if outcome['returncode'] == 0 else 1)
PY
        fuzz_status=$?
        if [[ $fuzz_status == 0 ]]; then
            # Re-run every retained coverage input once with the same ASan binary.
            python3 - "$run" <<'PY'
import json, pathlib, subprocess, sys
run = pathlib.Path(sys.argv[1])
args = json.loads((run/'evidence/command.json').read_text())
args = [arg if not arg.startswith('-runs=') else '-runs=0' for arg in args]
(run/'evidence/replay-command.json').write_text(json.dumps(args, indent=2)+'\n')
with (run/'evidence/replay.log').open('wb') as log:
    try:
        result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, timeout=900)
        outcome = {'returncode': result.returncode}
    except subprocess.TimeoutExpired:
        outcome = {'returncode': None, 'wall_timeout_seconds': 900}
(run/'evidence/replay-exit.json').write_text(json.dumps(outcome)+'\n')
sys.exit(0 if outcome['returncode'] == 0 else 1)
PY
            replay_status=$?
        fi
    fi
fi
sha256sum -c "$run/evidence/compiler-tools.sha256" > "$run/evidence/compiler-tools.after.txt" 2>&1
tools_status=$?
cp "$cg/memory.events" "$run/evidence/memory.events.after"
cat "$cg/memory.current" > "$run/evidence/memory.current.after"
printf '{"fmt":%s,"seeds":%s,"build":%s,"fuzz":%s,"replay":%s,"tools":%s}\n' \
    "$fmt_status" "$seeds_status" "$build_status" "$fuzz_status" "$replay_status" "$tools_status" > "$run/evidence/status.json"
python3 tools/check-libfuzzer.py "$run" > "$run/evidence/verification.json" 2> "$run/evidence/verification.log"
verification_status=$?
set -e
cat "$run/evidence/status.json"
printf 'Evidence: %s\n' "$run/evidence"
tail -n 15 "$run/evidence/seeds.log" "$run/evidence/build.log" "$run/evidence/fuzz.log" \
    "$run/evidence/replay.log" "$run/evidence/verification.log" 2>/dev/null || true
[[ $fmt_status == 0 && $seeds_status == 0 && $build_status == 0 && $fuzz_status == 0 \
    && $replay_status == 0 && $tools_status == 0 && $verification_status == 0 ]]
