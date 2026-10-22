#!/usr/bin/env bash
# Invoked through test-linux.sh in an EXISTING container/cgroup; never creates one.
set -euo pipefail
root=$1
incoming=$2
run_spec=${3:-0}
run_fuzz=${4:-0}
skip_fuzz=${5:-0}
run_doctest=${7:-0}
expected_swap_max=${8:-0}
[[ $expected_swap_max == max || $expected_swap_max =~ ^(0|[1-9][0-9]*)$ ]] || exit 2
[[ $skip_fuzz == 0 || $skip_fuzz == 1 ]] || exit 2
[[ $skip_fuzz != 1 || $run_fuzz == 0 ]] || exit 2
[[ $run_spec == 0 || $run_spec == 1 ]] || exit 2
[[ $run_fuzz == 0 || $run_fuzz == 1 ]] || exit 2
[[ $run_doctest == 0 || $run_doctest == 1 ]] || exit 2
# Direct invocations receive the same mode checks as the staging wrapper.
if [[ $# -ge 6 ]]; then
    corpus_mode=$6
elif [[ ${UWGIT_CORPUS_MODE+x} ]]; then
    corpus_mode=$UWGIT_CORPUS_MODE
elif [[ $skip_fuzz == 1 ]]; then
    corpus_mode=originals-only
else
    corpus_mode=fixed-mutations
fi
[[ $corpus_mode == originals-only || $corpus_mode == fixed-mutations ]] || exit 2
[[ $skip_fuzz != 1 || $corpus_mode == originals-only ]] || exit 2
export UWGIT_CORPUS_MODE=$corpus_mode
cg_path=$(awk -F: '$1 == "0" && $2 == "" {print $3}' /proc/self/cgroup)
cg="/sys/fs/cgroup$cg_path"
initial_boot=$(cat /proc/sys/kernel/random/boot_id)
[[ $(uname -s) == Linux && $cg_path == /system.slice/docker-*.scope ]]
[[ $(cat "$cg/memory.max") == 68719476736 && $(cat "$cg/memory.swap.max") == "$expected_swap_max" ]]
grep -Fxq "$$" "$cg/cgroup.procs"
umask 077
run="$root/standards-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$run/source" "$run/evidence" "$root/bin" "$run/tmp"
printf '%s\n' "$run" > "$root/standards-latest.txt"
export CARGO_HOME="$root/toolchain/cargo" RUSTUP_HOME="$root/toolchain/rustup"
export CARGO_TARGET_DIR="$run/target" CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export TMPDIR="$run/tmp"
export PATH="$CARGO_HOME/bin:$PATH"
[[ -x $CARGO_HOME/bin/cargo ]] || { echo "Install Rust with rustfmt and clippy in $root/toolchain before running." >&2; exit 2; }
tar -xf "$incoming" -C "$run/source"
rm "$incoming"
python3 "$run/source/tools/source-manifest.py" verify "$run/source" > "$run/evidence/source-input-verification.json"
{
    cat /proc/sys/kernel/random/boot_id
    cat /proc/self/cgroup
    cat "$cg/memory.max" "$cg/memory.swap.max" "$cg/memory.current" "$cg/cpuset.cpus.effective"
    rustc --version
    cargo --version
} > "$run/evidence/environment.txt"
cp "$cg/memory.events" "$run/evidence/memory.events.before"
cat "$cg/memory.swap.current" > "$run/evidence/memory.swap.current.before"
cd "$run/source"
source tools/regular-test-targets.sh
sha256sum Cargo.toml Cargo.lock src/*.rs tests/*.rs tests/fixtures/*.wasm tests/fixtures/c/*.c tools/* \
    fuzz/Cargo.toml fuzz/Cargo.lock fuzz/generate_seeds.rs fuzz/fuzz_targets/*.rs > "$run/evidence/source.sha256"
find vendor -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >> "$run/evidence/source.sha256"
# Use the existing LLVM compiler and Rust's wasm-capable LLD. These wrappers
# live only in this task's /tmp tree and make C integration mandatory.
rust_lld="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
[[ -x /usr/lib/llvm-22/bin/clang && -x $rust_lld ]]
printf '#!/bin/sh\nexec "%s" -flavor wasm "$@"\n' "$rust_lld" > "$root/bin/wasm-ld"
printf '#!/bin/sh\nexec /usr/lib/llvm-22/bin/clang "$@"\n' > "$root/bin/clang-wasm"
chmod 700 "$root/bin/wasm-ld" "$root/bin/clang-wasm"
ln -sf wasm-ld "$root/bin/wasm-ld-22"
export PATH="$root/bin:$PATH"
export WASM_GIT_CC="$root/bin/clang-wasm"
set +e
cargo fmt --check > "$run/evidence/fmt.log" 2>&1
fmt_status=$?
python3 tools/test-example-inputs.py > "$run/evidence/sdk-input-tests.log" 2>&1
sdk_input_status=$?
python3 tools/test-source-manifest.py > "$run/evidence/source-transfer-tests.log" 2>&1
source_transfer_status=$?
cargo clippy --locked --all-targets -- -D warnings > "$run/evidence/clippy.log" 2>&1
clippy_status=$?
cargo test --locked "${regular_targets[@]}" -- "${regular_filters[@]}" --nocapture > "$run/evidence/tests.log" 2>&1
test_status=$?
doctest_status=0
if [[ $run_doctest == 1 && $test_status == 0 ]]; then
    cargo test --locked --doc -- --nocapture > "$run/evidence/doctests.log" 2>&1
    doctest_status=$?
elif [[ $run_doctest == 1 ]]; then
    printf '%s\n' 'Separate doctests were requested but not run because regular tests failed.' > "$run/evidence/doctests.log"
    doctest_status=1
fi
spec_status=0
if [[ $run_spec == 1 && $test_status == 0 ]]; then
    python3 tools/fetch-spec-corpus.py "$root/corpus-verified" > "$run/evidence/spec-inputs.json"
    spec_status=$?
    if [[ $spec_status == 0 ]]; then
        while IFS=$'\t' read -r version corpus_root; do
            UWGIT_SPEC_ROOT="$corpus_root" UWGIT_SPEC_VERSION="$version" UWGIT_SPEC_REPORT="$run/evidence/spec-core$version.json" \
                cargo test --locked --test spec_corpus official_core_wast_corpus_audit -- --ignored --exact --nocapture --test-threads=1 > "$run/evidence/spec-core$version.log" 2>&1
            if [[ $? != 0 ]]; then spec_status=1; fi
        done < <(python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); [print(str(c["version"])+"\t"+c["root"]) for c in data["corpora"]]' "$run/evidence/spec-inputs.json")
        python3 tools/check-spec-reports.py "$run/evidence/spec-inputs.json" "$run/evidence" --corpus-mode "$corpus_mode" > "$run/evidence/spec-verification.json" 2> "$run/evidence/spec-verification.log"
        if [[ $? != 0 ]]; then spec_status=1; fi
        if [[ $corpus_mode == originals-only ]]; then
            python3 tools/check-spec-inputs.py "$run/evidence/spec-inputs.json" "$run/evidence" --archive-root "$root/corpus-verified" > "$run/evidence/spec-input-verification.json" 2> "$run/evidence/spec-input-verification.log"
            if [[ $? != 0 ]]; then spec_status=1; fi
        fi
    fi
elif [[ $run_spec == 1 ]]; then
    spec_status=1
fi
fuzz_status=0
if [[ $run_fuzz == 1 && $test_status == 0 ]]; then
    UWGIT_AUDIT_FUZZ_REPORT_DIR="$run/evidence/audit-fuzz" \
        cargo test --locked --test audit_fuzz deterministic_extended_byte_fuzz_with_replay_receipts -- \
        --ignored --exact --nocapture --test-threads=1 > "$run/evidence/fuzz.log" 2>&1
    fuzz_status=$?
    if [[ $fuzz_status == 0 ]]; then
        python3 tools/check-audit-fuzz.py "$run/evidence/audit-fuzz" \
            > "$run/evidence/fuzz-verification.json" 2> "$run/evidence/fuzz-verification.log"
        fuzz_status=$?
    fi
elif [[ $run_fuzz == 1 ]]; then
    fuzz_status=1
fi
set -e
cp "$cg/memory.events" "$run/evidence/memory.events.after"
cat "$cg/memory.current" > "$run/evidence/memory.current.after"
cat "$cg/memory.swap.current" > "$run/evidence/memory.swap.current.after"
resource_status=0
[[ $(cat "$cg/memory.max") == 68719476736 && $(cat "$cg/memory.swap.max") == "$expected_swap_max" ]] || resource_status=1
[[ $(cat "$cg/cpuset.cpus.effective") == 0-31 && $(cat /proc/sys/kernel/random/boot_id) == "$initial_boot" ]] || resource_status=1
[[ $(awk -F: '$1 == "0" && $2 == "" {print $3}' /proc/self/cgroup) == "$cg_path" ]] || resource_status=1
grep -Fxq "$$" "$cg/cgroup.procs" || resource_status=1
for counter in oom oom_kill oom_group_kill; do
    before=$(awk -v counter="$counter" '$1 == counter {print $2}' "$run/evidence/memory.events.before")
    after=$(awk -v counter="$counter" '$1 == counter {print $2}' "$run/evidence/memory.events.after")
    [[ -n $before && $before == "$after" ]] || resource_status=1
done
printf '{"fmt":%s,"sdk_inputs":%s,"source_transfer":%s,"clippy":%s,"tests":%s,"doctests_requested":%s,"doctests":%s,"spec_requested":%s,"spec":%s,"fuzz_requested":%s,"fuzz":%s,"skip_fuzz":%s,"corpus_mode":"%s","resources":%s,"expected_cgroup_swap_max":"%s"}\n' "$fmt_status" "$sdk_input_status" "$source_transfer_status" "$clippy_status" "$test_status" "$run_doctest" "$doctest_status" "$run_spec" "$spec_status" "$run_fuzz" "$fuzz_status" "$skip_fuzz" "$corpus_mode" "$resource_status" "$expected_swap_max" > "$run/evidence/status.json"
cat "$run/evidence/status.json"
printf 'Evidence: %s\n' "$run/evidence"
cat "$run/evidence/fmt.log" "$run/evidence/clippy.log"
tail -5 "$run/evidence/sdk-input-tests.log"
tail -5 "$run/evidence/source-transfer-tests.log"
tail -45 "$run/evidence/tests.log"
if [[ $run_doctest == 1 ]]; then tail -20 "$run/evidence/doctests.log"; fi
if [[ $run_spec == 1 ]]; then
    for version in 1 2 3; do
        if [[ -f $run/evidence/spec-core$version.log ]]; then tail -15 "$run/evidence/spec-core$version.log"; fi
    done
fi
if [[ $run_fuzz == 1 && -f $run/evidence/fuzz.log ]]; then tail -20 "$run/evidence/fuzz.log"; fi
[[ $fmt_status == 0 && $sdk_input_status == 0 && $source_transfer_status == 0 && $clippy_status == 0 && $test_status == 0 && $doctest_status == 0 && $spec_status == 0 && $fuzz_status == 0 && $resource_status == 0 ]]
