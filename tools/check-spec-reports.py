#!/usr/bin/env python3
"""Verify corpus reports consumed exactly the hash-pinned official WAST files."""
import argparse
import json
from pathlib import Path


def verify(inputs: Path, evidence: Path) -> dict:
    data = json.loads(inputs.read_text())
    summaries = []
    for corpus in data["corpora"]:
        report_path = evidence / f'spec-core{corpus["version"]}.json'
        report = json.loads(report_path.read_text())
        expected = {item["path"]: item["sha256"] for item in corpus["files"]}
        actual = {item["path"]: item["sha256"] for item in report["files"]}
        if len(actual) != len(report["files"]) or actual != expected:
            raise ValueError(f'corpus source manifest mismatch for {corpus["tag"]}')
        if report["failures"] or report["excluded_symlinks"]:
            raise ValueError(f'corpus audit failures/exclusions for {corpus["tag"]}')
        if report["encoding_counts"].get("component_model_excluded", 0):
            raise ValueError(f'unexpected component exclusions in Core corpus {corpus["tag"]}')
        modules = [module for file in report["files"] for module in file["modules"]]
        encoded = [module for module in modules if module["audit_validation"] is not None]
        if any(not module["identity_checked"] or not module["mutation_replayed"] for module in encoded):
            raise ValueError(f'missing identity/replay evidence for {corpus["tag"]}')
        if any(not module["patch_identity_replayed"] or not module["patch_mutation_replayed"] for module in encoded):
            raise ValueError(f'missing serialized patch replay evidence for {corpus["tag"]}')
        summaries.append({
            "version": corpus["version"], "tag": corpus["tag"], "commit": corpus["commit"],
            "archive_sha256": corpus["archive_sha256"], "files": len(actual),
            "modules": len(modules), "auditable_binary_modules": len(encoded),
            "patch_identity_modules": len(encoded), "patch_mutation_modules": len(encoded),
            "outcomes": report["outcome_counts"],
            "known_profile_limitations": report.get("known_profile_limitations", []),
            "runtime_conformance_tested": report["runtime_conformance_tested"],
            "source_manifest_sha256": report["source_manifest_sha256"],
        })
    return {"format": 1, "verified": True, "corpora": summaries}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.inputs, args.evidence), indent=2))
