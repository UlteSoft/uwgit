#!/usr/bin/env python3
"""Bind an SCP source archive to exact file bytes; never write into its source."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def create(archive, destination):
    files = {}
    directories = set()
    with tarfile.open(archive, "r:") as source:
        for member in source:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("archive contains a non-relative path")
            if member.isdir():
                directories.add(member.name.rstrip("/"))
                continue
            if not member.isfile() or member.name in files or member.name == "source-inputs.json":
                raise ValueError("archive contains a link, special file, or duplicate path")
            data = source.extractfile(member).read()
            files[member.name] = {"byte_len": len(data), "sha256": digest(data)}
    roots = []
    for directory in sorted(directories, key=lambda name: (len(PurePosixPath(name).parts), name)):
        if not any(directory == root or directory.startswith(root + "/") for root in roots):
            roots.append(directory)
    roots.extend(name for name in files if not any(name.startswith(root + "/") for root in roots))
    Path(destination).write_text(json.dumps({"version": 1, "roots": sorted(roots), "files": files}, sort_keys=True) + "\n")


def verify(root):
    root = Path(root)
    manifest = root / "source-inputs.json"
    record = json.loads(manifest.read_text())
    if record.get("version") != 1 or not isinstance(record.get("files"), dict):
        raise ValueError("unsupported source manifest")
    actual = {}
    for path in root.rglob("*"):
        if path == manifest:
            continue
        if path.is_symlink():
            raise ValueError("source tree contains a symbolic link")
        if path.is_file():
            data = path.read_bytes()
            actual[path.relative_to(root).as_posix()] = {
                "byte_len": len(data), "sha256": digest(data)
            }
    if actual != record["files"]:
        differing = sorted(set(actual) ^ set(record["files"]) | {
            path for path in set(actual) & set(record["files"])
            if actual[path] != record["files"][path]
        })
        raise ValueError("source snapshot mismatch: " + ", ".join(differing))
    print(json.dumps({"verified_files": len(actual), "manifest_sha256": digest(manifest.read_bytes())}))


def compare(manifest, root):
    record = json.loads(Path(manifest).read_text())
    root = Path(root)
    if record.get("version") != 1 or not isinstance(record.get("roots"), list):
        raise ValueError("comparison requires a source manifest with explicit archive roots")
    actual = {}
    for name in record["roots"]:
        logical = PurePosixPath(name)
        if logical.is_absolute() or ".." in logical.parts:
            raise ValueError("invalid source root")
        path = root / name
        if path.is_symlink():
            raise ValueError("local source root became a symlink")
        candidates = path.rglob("*") if path.is_dir() else [path]
        for selected in candidates:
            if selected.name.startswith("._"):
                continue
            if selected.is_symlink():
                raise ValueError("local source contains a symlink")
            if selected.is_file():
                data = selected.read_bytes()
                actual[selected.relative_to(root).as_posix()] = {"byte_len": len(data), "sha256": digest(data)}
    if actual != record["files"]:
        raise ValueError("local source changed after the SCP snapshot; rerun tests from the local checkout")
    print(json.dumps({"local_source_unchanged": True, "verified_files": len(actual), "manifest_sha256": digest(Path(manifest).read_bytes())}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("create")
    make.add_argument("archive")
    make.add_argument("destination")
    check = commands.add_parser("verify")
    check.add_argument("root")
    same = commands.add_parser("compare")
    same.add_argument("manifest")
    same.add_argument("root")
    args = parser.parse_args()
    if args.command == "create":
        create(args.archive, args.destination)
    elif args.command == "verify":
        verify(args.root)
    else:
        compare(args.manifest, args.root)


if __name__ == "__main__":
    main()
