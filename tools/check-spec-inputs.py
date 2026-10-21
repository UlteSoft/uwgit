#!/usr/bin/env python3
"""Recompute official-corpus input bytes and report aggregates independently.

This checks fixed evidence and archive contents, never generates Wasm variants
or runs modules. The audit harness, rather than this checker, parses WAST.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


COUNTS = ("directive_counts", "encoding_counts", "module_category_counts",
          "outcome_counts", "runtime_actions_not_executed")
SHA = re.compile(r"[0-9a-f]{64}\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def counts(value, label):
    require(isinstance(value, dict), f"not a counter: {label}")
    require(all(isinstance(k, str) and type(v) is int and v > 0
                for k, v in value.items()), f"invalid counter: {label}")
    return Counter(value)


def verify(inputs, evidence, archive_root):
    manifest = json.loads(inputs.read_text())
    pins = json.loads(Path(__file__).with_name("spec-corpora.json").read_text())
    require(manifest["format"] == pins["format"] == 1, "unsupported manifest")
    require(manifest["upstream"] == pins["upstream"], "upstream mismatch")
    require(len(manifest["corpora"]) == len(pins["corpora"]) == 3, "wrong corpus count")
    totals = Counter()
    summaries = []
    for pinned, corpus in zip(pins["corpora"], manifest["corpora"]):
        version = pinned["version"]
        label = f"Core{version}"
        require(all(corpus.get(k) == v for k, v in pinned.items()), f"pin mismatch: {label}")
        archive = archive_root / f'{pinned["commit"]}.tar.gz'
        with archive.open("rb") as raw:
            actual_sha = hashlib.file_digest(raw, "sha256").hexdigest()
        require(actual_sha == pinned["archive_sha256"], f"archive hash mismatch: {label}")
        prefix = f'spec-{pinned["commit"]}/test/core/'
        originals = {}
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle:
                if not member.name.startswith(prefix) or not member.name.endswith(".wast"):
                    continue
                name = member.name[len(prefix):]
                relative = PurePosixPath(name)
                require(member.isfile() and not relative.is_absolute()
                        and ".." not in relative.parts and name not in originals,
                        f"unsafe/duplicate member: {member.name}")
                data = bundle.extractfile(member).read()
                originals[name] = {"sha256": digest(data), "byte_len": len(data)}
                source = Path(corpus["root"]) / name
                require(source.is_file() and not source.is_symlink()
                        and source.read_bytes() == data, f"materialized bytes mismatch: {label}/{name}")
        require(len(originals) == pinned["wast_files"], f"wrong archive member count: {label}")
        selected = {p.relative_to(corpus["root"]).as_posix()
                    for p in Path(corpus["root"]).rglob("*.wast")}
        require(selected == set(originals), f"materialized member set mismatch: {label}")
        source_manifest = [{"path": n, "sha256": originals[n]["sha256"]} for n in sorted(originals)]
        require(corpus["files"] == source_manifest, f"input manifest mismatch: {label}")
        report = json.loads((evidence / f"spec-core{version}.json").read_text())
        require(report["schema_version"] == 1 and report["corpus_mode"] == "originals-only"
                and report["generated_mutations"] == 0, f"not originals-only: {label}")
        require(report["runtime_conformance_tested"] is False, f"unjustified runtime claim: {label}")
        require(not report["failures"] and not report["excluded_symlinks"], f"failures/exclusions: {label}")
        require(report["corpus_root"] == corpus["root"], f"root mismatch: {label}")
        rows = report["files"]
        require([row["path"] for row in rows] == sorted(originals), f"report source set/order mismatch: {label}")
        canonical = b"".join(n.encode() + b"\0" + originals[n]["sha256"].encode() + b"\n"
                             for n in sorted(originals))
        require(digest(canonical) == report["source_manifest_sha256"], f"source manifest digest mismatch: {label}")
        aggregate = {key: Counter() for key in COUNTS}
        outcomes, profile_outcomes = Counter(), Counter()
        modules = auditable = 0
        for row in rows:
            name = row["path"]
            require(all(row[k] == v for k, v in originals[name].items()), f"report bytes mismatch: {label}/{name}")
            for key in COUNTS:
                aggregate[key].update(counts(row[key], f"{label}/{name}/{key}"))
            file_outcomes = Counter(module["outcome"] for module in row["modules"])
            require(dict(file_outcomes) == row["outcome_counts"], f"per-file outcomes mismatch: {label}/{name}")
            require(dict(Counter(m["encoding"] for m in row["modules"])) == row["encoding_counts"],
                    f"per-file encoding mismatch: {label}/{name}")
            require(dict(Counter(m["expectation"] for m in row["modules"])) == row["module_category_counts"],
                    f"per-file categories mismatch: {label}/{name}")
            locations = set()
            for module in row["modules"]:
                modules += 1
                outcomes[module["outcome"]] += 1
                loc = module["location"]
                key = (loc["directive"], loc["line"], loc["column"])
                require(key not in locations and type(loc["line"]) is int and loc["line"] > 0
                        and type(loc["column"]) is int and loc["column"] > 0,
                        f"invalid/duplicate module location: {label}/{name}")
                locations.add(key)
                require(module["mutation_offset"] is None and module["mutation_replayed"] is False
                        and module["patch_mutation_replayed"] is False
                        and module["mutation_skip_reason"] == "originals-only mode does not construct or audit generated byte variants",
                        f"generated variant evidence: {label}/{name}")
                binary_sha = module["sha256"]
                require((binary_sha is None) == (module["byte_len"] is None), f"partial byte identity: {label}/{name}")
                if binary_sha is not None:
                    require(SHA.fullmatch(binary_sha) and type(module["byte_len"]) is int and module["byte_len"] >= 0,
                            f"invalid binary identity: {label}/{name}")
                encoded = module["audit_validation"] is not None
                require(module["identity_checked"] is encoded and module["patch_identity_replayed"] is encoded,
                        f"identity closure mismatch: {label}/{name}")
                profiles = module["standard_profiles"]
                if not encoded:
                    require(not profiles and module["outcome"] in ("expected_text_encoding_rejection", "expected_core_header_rejection"),
                            f"unaccounted unauditable input: {label}/{name}")
                    continue
                auditable += 1
                require(binary_sha is not None and len(profiles) == 3
                        and {p["standard"] for p in profiles} == {"core1", "core2", "core3"},
                        f"missing profiles: {label}/{name}")
                require(len({p["physical_topology_sha256"] for p in profiles}) == 1
                        and all(SHA.fullmatch(p["physical_topology_sha256"]) for p in profiles),
                        f"inconsistent topology: {label}/{name}")
                for profile in profiles:
                    require(type(profile["validator_valid"]) is bool and type(profile["requirements_satisfied"]) is bool,
                            f"invalid profile status type: {label}/{name}")
                    require((profile["reported_validation"] == "valid") == (profile["validator_valid"] and profile["requirements_satisfied"]),
                            f"profile validity mismatch: {label}/{name}")
                    counts(profile["feature_status_counts"], f"{label}/{name}/features")
                    profile_outcomes[profile["standard"] + ":" + profile["reported_validation"]] += 1
        for key in COUNTS:
            require(dict(aggregate[key]) == report[key], f"aggregate mismatch: {label}/{key}")
        require(dict(outcomes) == report["outcome_counts"], f"outcome partition mismatch: {label}")
        limitations = report["known_profile_limitations"]
        require(len(limitations) == (1 if version == 1 else 0), f"unexpected historical discrepancies: {label}")
        for limitation in limitations:
            require(version == 1 and limitation["file"] == "unreached-invalid.wast"
                    and limitation["file_sha256"] == "572b32f9ed9b29385b9150a68115946049d79c85d4b5ac494237d23cba0fac3f"
                    and limitation["module_sha256"] == "90e51445cce7caf407bcd2486dee7f2455d6b32e1d21b983ccd3f62bbfa8ee1a",
                    f"unrecognized historical discrepancy: {label}")
            bound = [m for row in rows if row["path"] == limitation["file"] for m in row["modules"]
                     if m["sha256"] == limitation["module_sha256"] and m["location"] == limitation["location"]]
            require(len(bound) == 1 and bound[0]["outcome"] == "known_historical_validator_deviation_audited"
                    and next(p for p in bound[0]["standard_profiles"] if p["standard"] == "core1")["reported_validation"] == "invalid",
                    f"historical discrepancy not bound to rejected original: {label}")
        totals.update({"wast_files": len(rows), "module_forms": modules,
                       "auditable_originals": auditable, "cross_standard_inspections": auditable * 3})
        summaries.append({"version": version, "wast_files": len(rows), "module_forms": modules,
                          "auditable_originals": auditable, "outcomes": dict(outcomes),
                          "profile_outcomes": dict(profile_outcomes),
                          "source_manifest_sha256": digest(canonical), "archive_sha256": actual_sha})
    return {"format": 1, "verified": True, "corpus_mode": "originals-only", "generated_mutations": 0,
            "runtime_conformance_tested": False, "totals": dict(totals), "corpora": summaries}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--archive-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.inputs, args.evidence, args.archive_root), indent=2))
