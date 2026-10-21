#!/usr/bin/env bash
# Invoked by test-uwvm-examples.sh in an existing container, never creates one.
set -euo pipefail
root=$1
incoming=$2
skip_fuzz=${3:-0}
[[ $skip_fuzz == 0 || $skip_fuzz == 1 ]] || exit 2
if [[ $# -ge 4 ]]; then
    corpus_mode=$4
elif [[ ${UWGIT_CORPUS_MODE+x} ]]; then
    corpus_mode=$UWGIT_CORPUS_MODE
elif [[ $skip_fuzz == 1 ]]; then
    corpus_mode=originals-only
else
    corpus_mode=fixed-mutations
fi
[[ $corpus_mode == originals-only || $corpus_mode == fixed-mutations ]] || exit 2
[[ $skip_fuzz != 1 || $corpus_mode == originals-only ]] || exit 2
export UWGIT_CORPUS_MODE="$corpus_mode"
cg_path=$(awk -F: '$1 == "0" && $2 == "" {print $3}' /proc/self/cgroup)
cg="/sys/fs/cgroup$cg_path"
[[ $(uname -s) == Linux && $cg_path == /system.slice/docker-*.scope ]]
[[ $(cat "$cg/memory.max") == 68719476736 && $(cat "$cg/memory.swap.max") == 0 ]]
grep -Fxq "$$" "$cg/cgroup.procs"
umask 077
run="$root/uwvm-examples-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$run/reference" "$run/build" "$run/evidence" "$run/bin" "$run/workflow" "$run/tmp" "$run/source"
tar -xf "$incoming-reference.tar" -C "$run/reference"
cp "$incoming-inputs.json" "$run/evidence/inputs.json"
tar -xf "$incoming-source.tar" -C "$run/source"
rm "$incoming-reference.tar" "$incoming-inputs.json" "$incoming-source.tar"
export CARGO_HOME="$root/toolchain/cargo" RUSTUP_HOME="$root/toolchain/rustup"
export CARGO_TARGET_DIR="$run/target" CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
export PATH="$root/bin:$CARGO_HOME/bin:$PATH"
export TMPDIR="$run/tmp"
[[ -x $CARGO_HOME/bin/cargo && -x $root/bin/wasm-ld && -x /usr/lib/llvm-22/bin/clang ]]
cd "$run/source"
source tools/regular-test-targets.sh
sha256sum Cargo.toml Cargo.lock src/*.rs tests/*.rs tests/fixtures/*.wasm tests/fixtures/c/*.c tools/* \
    fuzz/Cargo.toml fuzz/Cargo.lock fuzz/generate_seeds.rs fuzz/fuzz_targets/*.rs > "$run/evidence/source.sha256"
find vendor -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >> "$run/evidence/source.sha256"
{
    cat /proc/sys/kernel/random/boot_id /proc/self/cgroup
    cat "$cg/memory.max" "$cg/memory.swap.max" "$cg/memory.current" "$cg/cpuset.cpus.effective"
    rustc --version
    cargo --version
    python3 --version
    /usr/lib/llvm-22/bin/clang --version
    /usr/bin/wat2wasm --version
    /usr/bin/wasm-validate --version
} > "$run/evidence/environment.txt"
cp "$cg/memory.events" "$run/evidence/memory.events.before"
python3 tools/uwvm-examples-inputs.py verify "$run/reference" "$run/evidence/inputs.json" > "$run/evidence/inputs.before.json"
# Freeze an existing runtime product; neither its source nor its product path
# is a build/output directory for this task.
runtime_origin=/tmp/uwvm-pretty-20261018/products-r819-all3-O2-wset-r821-r1/uwvm2-ros/uwvm
[[ -x $runtime_origin ]]
runtime_sha=a43f92c52fc7f201027dbe84db0ad95c5a4580d980b35c8d1f034a6f0d745be1
printf '%s  %s\n' "$runtime_sha" "$runtime_origin" | sha256sum -c - > "$run/evidence/runtime-origin.before.txt"
cp "$runtime_origin" "$run/bin/uwvm"
chmod 700 "$run/bin/uwvm"
printf '%s  %s\n' "$runtime_sha" "$run/bin/uwvm" | sha256sum -c - > "$run/evidence/runtime-copy.txt"
ldd "$run/bin/uwvm" > "$run/evidence/runtime.ldd.txt"
python3 - "$run/evidence/runtime.ldd.txt" "$run/evidence/runtime-libraries.sha256" <<'PY'
import hashlib, pathlib, sys
paths = set()
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    words = line.split()
    for word in words:
        if word.startswith('/') and pathlib.Path(word).is_file(): paths.add(word)
with open(sys.argv[2], 'w') as output:
    for path in sorted(paths):
        output.write(hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()+'  '+path+'\n')
PY
sha256sum /usr/bin/wat2wasm /usr/bin/wasm-validate /usr/bin/wasm-objdump /usr/lib/llvm-22/bin/clang "$root/bin/wasm-ld" > "$run/evidence/compiler-tools.sha256"
export UWGIT_UWVM_EXAMPLES_ROOT="$run/reference"
export UWGIT_UWVM_BUILD_ROOT="$run/build"
export UWGIT_UWVM_CORPUS_REPORT="$run/evidence/corpus.json"
export UWGIT_UWVM_WORKFLOW_ROOT="$run/workflow"
export UWGIT_UWVM_WORKFLOW_REPORT_DIR="$run/evidence/workflows"
export UWGIT_UWVM_BIN="$run/bin/uwvm"
export UWGIT_UWVM_CC="$root/bin/clang-wasm"
export WASM_GIT_CC="$root/bin/clang-wasm"
set +e
cargo fmt --check > "$run/evidence/fmt.log" 2>&1
fmt_status=$?
cargo clippy --locked --all-targets -- -D warnings > "$run/evidence/clippy.log" 2>&1
clippy_status=$?
cargo test --locked "${regular_targets[@]}" -- "${regular_filters[@]}" --nocapture > "$run/evidence/tests.log" 2>&1
regular_status=$?
corpus_status=1
workflow_status=1
products_status=1
if [[ $fmt_status == 0 && $clippy_status == 0 && $regular_status == 0 ]]; then
    cargo test --locked --test uwvm_examples -- --ignored --nocapture --test-threads=1 > "$run/evidence/corpus.log" 2>&1
    corpus_status=$?
    cargo test --locked --test uwvm_example_workflows -- --ignored --nocapture --test-threads=1 > "$run/evidence/workflows.log" 2>&1
    workflow_status=$?
    if [[ $corpus_status == 0 ]]; then
        python3 tools/verify-uwvm-example-products.py --reference "$run/reference" --build-root "$run/build" \
            --evidence "$run/evidence/products" --uwgit "$CARGO_TARGET_DIR/debug/wasm-git" \
            --uwvm "$run/bin/uwvm" --cc "$root/bin/clang-wasm" > "$run/evidence/products.log" 2>&1
        products_status=$?
    fi
fi
python3 tools/uwvm-examples-inputs.py verify "$run/reference" "$run/evidence/inputs.json" > "$run/evidence/inputs.after.json" 2>&1
inputs_status=$?
sha256sum -c "$run/evidence/runtime-libraries.sha256" > "$run/evidence/runtime-libraries.after.txt" 2>&1
libraries_status=$?
sha256sum -c "$run/evidence/compiler-tools.sha256" > "$run/evidence/compiler-tools.after.txt" 2>&1
tools_status=$?
printf '%s  %s\n' "$runtime_sha" "$runtime_origin" | sha256sum -c - > "$run/evidence/runtime-origin.after.txt" 2>&1
runtime_status=$?
python3 tools/check-uwvm-examples.py "$run" > "$run/evidence/verification.json" 2> "$run/evidence/verification.log"
verification_status=$?
set -e
cp "$cg/memory.events" "$run/evidence/memory.events.after"
cat "$cg/memory.current" > "$run/evidence/memory.current.after"
printf '{"fmt":%s,"clippy":%s,"regular":%s,"corpus":%s,"workflows":%s,"products":%s,"inputs":%s,"runtime":%s,"libraries":%s,"tools":%s,"verification":%s,"corpus_mode":"%s"}\n' \
    "$fmt_status" "$clippy_status" "$regular_status" "$corpus_status" "$workflow_status" "$products_status" "$inputs_status" "$runtime_status" "$libraries_status" "$tools_status" "$verification_status" "$corpus_mode" > "$run/evidence/status.json"
printf '%s\n' "$run" > "$root/uwvm-examples-latest.txt"
cat "$run/evidence/status.json"
printf 'Evidence: %s\n' "$run/evidence"
cat "$run/evidence/fmt.log" "$run/evidence/clippy.log"
tail -n 20 "$run/evidence/tests.log" "$run/evidence/corpus.log" "$run/evidence/workflows.log" "$run/evidence/products.log" "$run/evidence/verification.log" 2>/dev/null || true
[[ $fmt_status == 0 && $clippy_status == 0 && $regular_status == 0 && $corpus_status == 0 && $workflow_status == 0 && $products_status == 0 && $inputs_status == 0 && $runtime_status == 0 && $libraries_status == 0 && $tools_status == 0 && $verification_status == 0 ]]
