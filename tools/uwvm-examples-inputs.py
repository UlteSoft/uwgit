#!/usr/bin/env python3
"""Inventory the read-only external example inputs; never compile or edit them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

SDK_FILES = (
    "sdk/common/abi.h",
    "sdk/ros1/abi.h",
    "sdk/ros1/freestanding.hpp",
    "sdk/ros2/abi.h",
    "sdk/ros2/freestanding.hpp",
)


def inventory(root: Path) -> list[dict]:
    examples = root / "examples"
    if examples.is_symlink() or not examples.is_dir():
        raise ValueError("examples must be a real directory")
    paths = []
    pending = [examples]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            if path.is_symlink():
                raise ValueError(f"symlink in example inputs: {path}")
            if path.is_dir():
                pending.append(path)
            elif path.is_file():
                paths.append(path)
            else:
                raise ValueError(f"non-regular example input: {path}")
    for relative in SDK_FILES:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or non-regular SDK input: {path}")
        paths.append(path)
    result = []
    for path in sorted(paths):
        data = path.read_bytes()
        result.append({"path": path.relative_to(root).as_posix(), "byte_len": len(data),
                       "sha256": hashlib.sha256(data).hexdigest()})
    return result


def git_metadata(root: Path) -> dict:
    environment = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    def git(*arguments: str) -> str:
        return subprocess.run(["git", "-C", str(root), *arguments], env=environment,
                              check=True, text=True, capture_output=True).stdout.strip()
    return {"head": git("rev-parse", "HEAD"),
            "input_status": git("status", "--porcelain=v1", "--untracked-files=no", "--",
                                "examples", *SDK_FILES)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("snapshot", "verify", "compare"))
    parser.add_argument("root", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    if args.mode == "snapshot":
        result = {"format": 1, "source_root": str(args.root.resolve()),
                  "git": git_metadata(args.root), "files": inventory(args.root)}
        args.manifest.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"files": len(result["files"]), "snapshot": str(args.manifest)}))
        return
    expected = json.loads(args.manifest.read_text())
    actual = inventory(args.root)
    if expected["format"] != 1 or actual != expected["files"]:
        raise ValueError("external example input inventory/content changed")
    if args.mode == "compare" and git_metadata(args.root) != expected["git"]:
        raise ValueError("external source revision/input Git status changed")
    print(json.dumps({"verified": True, "files": len(actual), "mode": args.mode}))


if __name__ == "__main__":
    main()
