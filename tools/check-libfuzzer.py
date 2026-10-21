#!/usr/bin/env python3
"""Check libFuzzer's finite campaign and raw seed/corpus receipts, not just exit 0."""

import hashlib
import json
import pathlib
import re
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text())


def main():
    run = pathlib.Path(sys.argv[1]).resolve()
    evidence = run / "evidence"
    status = load(evidence / "status.json")
    require(set(status) == {"fmt", "seeds", "build", "fuzz", "replay", "tools"}, "stage keys")
    require(all(value == 0 for value in status.values()), "a stage failed")
    require(load(evidence / "fuzz-exit.json") == {"returncode": 0}, "fuzzer exit")
    require(load(evidence / "replay-exit.json") == {"returncode": 0}, "replay exit")
    command = load(evidence / "command.json")
    require(command[0] == str(run / "fuzz-target/x86_64-unknown-linux-gnu/release/raw_audit"), "binary path")
    require(command[1] == str(run / "corpus"), "corpus path")
    require(len(command) == 9, "unexpected command")
    require(command[2] == "-seed=757767697", "random seed")
    requested = int(command[3].removeprefix("-runs="))
    require(1 <= requested <= 1_000_000, "run bound")
    require(command[4:8] == ["-max_len=4096", "-timeout=10", "-rss_limit_mb=2048", "-print_final_stats=1"], "resource bounds")
    require(command[8] == "-artifact_prefix=" + str(run / "artifacts") + "/", "artifact path")
    expected_replay = [arg if not arg.startswith("-runs=") else "-runs=0" for arg in command]
    require(load(evidence / "replay-command.json") == expected_replay, "replay command")
    binary_record = (evidence / "binary.sha256").read_text().strip().split(maxsplit=1)
    require(binary_record[1] == command[0], "binary receipt path")
    require(digest(pathlib.Path(command[0]).read_bytes()) == binary_record[0], "binary changed")
    require(not list((run / "artifacts").iterdir()), "crash/timeout/leak artifacts exist")

    source_count = 0
    for line in (evidence / "source.sha256").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        path = pathlib.PurePosixPath(relative)
        require(not path.is_absolute() and ".." not in path.parts, "unsafe source path")
        require(digest((run / "source" / path).read_bytes()) == expected, "source changed: " + relative)
        source_count += 1

    report = load(evidence / "seeds.json")
    require(report["format"] == 1 and report["max_input"] == 4096, "seed format")
    header = bytes.fromhex("0061736d01000000")
    seeds = report["seeds"]
    require(len(seeds) >= 100, "seed breadth shrank")
    seed_names = set()
    for seed in seeds:
        name = seed["file"]
        require(pathlib.PurePath(name).name == name and name not in seed_names, "unsafe/duplicate seed")
        seed_names.add(name)
        raw = (run / "seeds" / name).read_bytes()
        old, new = bytes.fromhex(seed["old_hex"]), bytes.fromhex(seed["new_hex"])
        require(old.startswith(header) and new.startswith(header), "seed header")
        require(len(raw) == seed["bytes"] <= 4096 and digest(raw) == seed["sha256"], "seed bytes")
        require(digest(old) == seed["old_sha256"] and digest(new) == seed["new_sha256"], "seed raw hashes")
        require(raw == (len(old) - 8).to_bytes(2, "little") + old[8:] + new[8:], "seed envelope")
        require((run / "corpus" / name).read_bytes() == raw, "initial seed changed")
    require({p.name for p in (run / "seeds").iterdir()} == seed_names, "extra seed files")

    receipts = []
    for path in sorted((run / "corpus").iterdir()):
        require(path.is_file() and not path.is_symlink(), "nonregular corpus entry")
        raw = path.read_bytes()
        require(len(raw) <= 4096, "oversized retained input")
        payload = raw[2:] if len(raw) >= 2 else b""
        split = int.from_bytes(raw[:2], "little") % (len(payload) + 1) if len(raw) >= 2 else 0
        old, new = header + payload[:split], header + payload[split:]
        receipts.append({"file": path.name, "bytes": len(raw), "sha256": digest(raw),
                         "old_sha256": digest(old), "new_sha256": digest(new)})
    require(len(receipts) >= len(seeds), "retained corpus lost seeds")
    corpus_manifest = json.dumps(receipts, sort_keys=True, indent=2) + "\n"
    (evidence / "corpus.json").write_text(corpus_manifest)

    log = (evidence / "fuzz.log").read_text()
    replay = (evidence / "replay.log").read_text()
    for name, text in [("fuzz", log), ("replay", replay)]:
        require(not re.search(r"ERROR:|SUMMARY: AddressSanitizer|runtime error:|panicked at", text), name + " failure diagnostic")
        require("inline 8-bit counters" in text and "PC tables" in text, name + " missing instrumentation")
        require("INITED cov:" in text and "DONE   cov:" in text, name + " incomplete run")
    initial = re.search(r"#(\d+)\s+INITED cov: (\d+) ft: (\d+)", log)
    final = re.search(r"#(\d+)\s+DONE\s+cov: (\d+) ft: (\d+)", log)
    require(initial is not None and final is not None, "coverage counters")
    init_runs, init_cov, init_features = map(int, initial.groups())
    final_runs, final_cov, final_features = map(int, final.groups())
    require(final_runs >= max(requested, init_runs), "fewer executions than requested")
    require(final_cov >= init_cov and final_features >= init_features, "coverage regressed")
    require(re.search(r"#\d+\s+NEW\s+cov:", log) is not None, "no coverage-guided discoveries")
    require(final_cov > init_cov or final_features > init_features, "no coverage growth")
    replay_done = re.search(r"#(\d+)\s+DONE\s+cov:", replay)
    require(replay_done is not None and int(replay_done[1]) >= len(receipts), "incomplete corpus replay")
    total = re.search(r"stat::number_of_executed_units:\s*(\d+)", log)
    require(total is not None and int(total[1]) == final_runs, "execution statistic")
    peak = re.search(r"stat::peak_rss_mb:\s*(\d+)", log)
    require(peak is not None, "missing observed peak RSS")
    def events(path):
        return {name: int(value) for name, value in
                (line.split() for line in path.read_text().splitlines())}
    before, after = events(evidence / "memory.events.before"), events(evidence / "memory.events.after")
    require(before.keys() == after.keys() and all(after[key] >= before[key] for key in before), "cgroup event counters")
    print(json.dumps({"verified": True, "source_files": source_count, "seeds": len(seeds),
                      "requested_executions": requested, "executed_units": final_runs,
                      "initial_cov": init_cov, "final_cov": final_cov,
                      "initial_features": init_features, "final_features": final_features,
                      "retained_inputs": len(receipts), "corpus_replay_units": int(replay_done[1]),
                      "observed_peak_rss_mb": int(peak[1]),
                      "shared_cgroup_event_delta": {key: after[key]-before[key] for key in before},
                      "corpus_manifest_sha256": digest(corpus_manifest.encode()),
                      "binary_sha256": binary_record[0],
                      "interpretation": "LLVM instrumented edge/features are search feedback, not a proof of exhaustive paths or normative conformance."}, indent=2))


if __name__ == "__main__":
    main()
