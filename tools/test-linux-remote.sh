#!/usr/bin/env bash
# Invoked through test-linux.sh in an EXISTING container/cgroup; never creates one.
set -euo pipefail
root=$1
incoming=$2
run_spec=${3:-0}
cg_path=$(awk -F: '$1 == "0" && $2 == "" {print $3}' /proc/self/cgroup)
cg="/sys/fs/cgroup$cg_path"
[[ $(uname -s) == Linux && $cg_path == /system.slice/docker-*.scope ]]
[[ $(cat "$cg/memory.max") == 68719476736 && $(cat "$cg/memory.swap.max") == 0 ]]
grep -Fxq "$$" "$cg/cgroup.procs"
umask 077
if [[ -d $root/evidence ]]; then
    mv "$root/evidence" "$root/evidence-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
mkdir -p "$root/source" "$root/evidence" "$root/bin"
export CARGO_HOME="$root/toolchain/cargo" RUSTUP_HOME="$root/toolchain/rustup"
export CARGO_TARGET_DIR="$root/target" CARGO_BUILD_JOBS=2
export PATH="$CARGO_HOME/bin:$PATH"
[[ -x $CARGO_HOME/bin/cargo ]] || { echo "Install Rust with rustfmt and clippy in $root/toolchain before running." >&2; exit 2; }
tar -xf "$incoming" -C "$root/source"
rm "$incoming"
{
    cat /proc/sys/kernel/random/boot_id
    cat /proc/self/cgroup
    cat "$cg/memory.max" "$cg/memory.swap.max" "$cg/memory.current" "$cg/cpuset.cpus.effective"
    rustc --version
    cargo --version
} > "$root/evidence/environment.txt"
cp "$cg/memory.events" "$root/evidence/memory.events.before"
cd "$root/source"
sha256sum Cargo.toml Cargo.lock src/*.rs tests/*.rs tests/fixtures/*.wasm tests/fixtures/c/*.c tools/* > "$root/evidence/source.sha256"
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
cargo fmt --check > "$root/evidence/fmt.log" 2>&1
fmt_status=$?
cargo clippy --locked --all-targets -- -D warnings > "$root/evidence/clippy.log" 2>&1
clippy_status=$?
cargo test --locked -- --nocapture > "$root/evidence/tests.log" 2>&1
test_status=$?
spec_status=0
if [[ $run_spec == 1 && $test_status == 0 ]]; then
    python3 tools/fetch-spec-corpus.py "$root/corpus-verified" > "$root/evidence/spec-inputs.json"
    spec_status=$?
    if [[ $spec_status == 0 ]]; then
        while IFS=$'\t' read -r version corpus_root; do
            UWGIT_SPEC_ROOT="$corpus_root" UWGIT_SPEC_VERSION="$version" UWGIT_SPEC_REPORT="$root/evidence/spec-core$version.json" \
                cargo test --locked --test spec_corpus -- --ignored --nocapture --test-threads=1 > "$root/evidence/spec-core$version.log" 2>&1
            if [[ $? != 0 ]]; then spec_status=1; fi
        done < <(python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); [print(str(c["version"])+"\t"+c["root"]) for c in data["corpora"]]' "$root/evidence/spec-inputs.json")
        python3 tools/check-spec-reports.py "$root/evidence/spec-inputs.json" "$root/evidence" > "$root/evidence/spec-verification.json" 2> "$root/evidence/spec-verification.log"
        if [[ $? != 0 ]]; then spec_status=1; fi
    fi
elif [[ $run_spec == 1 ]]; then
    spec_status=1
fi
set -e
cp "$cg/memory.events" "$root/evidence/memory.events.after"
cat "$cg/memory.current" > "$root/evidence/memory.current.after"
printf '{"fmt":%s,"clippy":%s,"tests":%s,"spec_requested":%s,"spec":%s}\n' "$fmt_status" "$clippy_status" "$test_status" "$run_spec" "$spec_status" > "$root/evidence/status.json"
cat "$root/evidence/status.json"
cat "$root/evidence/fmt.log" "$root/evidence/clippy.log"
tail -45 "$root/evidence/tests.log"
if [[ $run_spec == 1 ]]; then
    for version in 1 2 3; do
        if [[ -f $root/evidence/spec-core$version.log ]]; then tail -15 "$root/evidence/spec-core$version.log"; fi
    done
fi
[[ $fmt_status == 0 && $clippy_status == 0 && $test_status == 0 && $spec_status == 0 ]]
