#!/usr/bin/env python3
"""Inventory the read-only external example inputs; never compile or edit them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

SDK_MEMBERS = (
    "common/abi.h",
    "ros1/abi.h",
    "ros1/freestanding.hpp",
    "ros2/abi.h",
    "ros2/freestanding.hpp",
)


def _sdk_input(root: Path, relative: str) -> Path:
    """Check every actual component; never canonicalize through a symlink."""
    path = root
    parts = Path(relative).parts
    for index, part in enumerate(parts):
        path = path / part
        if path.is_symlink():
            raise ValueError(f"symlink in SDK inputs: {path}")
        if index < len(parts) - 1:
            if not path.is_dir():
                raise ValueError(f"missing or non-directory SDK input: {path}")
        elif not path.is_file():
            raise ValueError(f"missing or non-regular SDK input: {path}")
    return path


def _include_text(data: str, path: Path) -> str:
    """Splice physical lines and blank comments without interpreting macros.

    Ordinary string/character literals protect their comment-looking bytes.
    C++ raw strings are blanked so their physical lines cannot become fake
    preprocessor directives. Every conditional branch is inventoried.
    """
    data = data.replace("\r\n", "\n").replace("\r", "\n")
    if re.search(r"\?\?[=/'()!<>-]", data) is not None:
        raise ValueError(f"unsupported trigraph in SDK include scan: {path}")
    if re.search(r"\\[ \t]+\n", data) is not None:
        raise ValueError(f"unsupported whitespace after SDK line-continuation backslash: {path}")
    data = data.replace("\\\n", "")
    result = []
    index = 0
    while index < len(data):
        if data.startswith("/*", index):
            end = data.find("*/", index + 2)
            if end < 0:
                raise ValueError(f"unterminated SDK block comment: {path}")
            end += 2
            result.append("".join("\n" if ch == "\n" else " " for ch in data[index:end]))
            index = end
        elif data.startswith("//", index):
            end = data.find("\n", index + 2)
            if end < 0:
                end = len(data)
            result.append(" " * (end - index))
            index = end
        elif data.startswith('R"', index):
            opening = data.find("(", index + 2, index + 19)
            delimiter = data[index + 2:opening] if opening >= 0 else None
            if delimiter is None or any(ch.isspace() or ch in "()\\" for ch in delimiter):
                raise ValueError(f"unsupported SDK raw string: {path}")
            closing = ")" + delimiter + '"'
            end = data.find(closing, opening + 1)
            if end < 0:
                raise ValueError(f"unterminated SDK raw string: {path}")
            end += len(closing)
            result.append("".join("\n" if ch == "\n" else " " for ch in data[index:end]))
            index = end
        elif data[index] in "\"'":
            quote = data[index]
            # A digit separator is not the start of a C++ character literal.
            if (quote == "'" and index + 1 < len(data) and data[index + 1].isalnum()
                    and re.search(r"\b[0-9][0-9A-Za-z]*$", data[:index]) is not None):
                result.append(quote)
                index += 1
                continue
            end = index + 1
            while end < len(data) and data[end] != "\n":
                if data[end] == "\\":
                    end += 2
                elif data[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            if end > len(data) or end == index + 1 or data[end - 1] != quote:
                raise ValueError(f"unterminated SDK quoted literal: {path}")
            result.append(data[index:end])
            index = end
        else:
            result.append(data[index])
            index += 1
    return "".join(result)


def _quoted_includes(path: Path) -> tuple[str, ...]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeError as error:
        raise ValueError(f"SDK header is not UTF-8: {path}") from error
    text = _include_text(text, path)
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        directive = re.match(r"^[ \t\v\f]*(?:#|%:)[ \t\v\f]*([A-Za-z_][A-Za-z_0-9]*)(.*)$", line)
        if directive is None:
            continue
        operation, argument = directive.groups()
        if operation in ("include_next", "import"):
            raise ValueError(f"unsupported SDK include directive at {path}:{number}: {operation}")
        if operation != "include":
            continue
        argument = argument.strip()
        local = re.fullmatch(r'"([^"\n]+)"', argument)
        if local is not None:
            result.append(local.group(1))
        elif re.fullmatch(r"<[^<>\n]+>", argument) is None:
            raise ValueError(f"non-literal or malformed SDK include at {path}:{number}: {argument!r}")
    return tuple(result)


def _sdk_include(root: Path, prefix: str, current: str, include: str) -> str:
    if (not include or include.startswith("/") or "\\" in include or ":" in include
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in include)):
        raise ValueError(f"unsafe SDK include path in {current}: {include!r}")
    components = include.split("/")
    if any(part in ("", ".") for part in components):
        raise ValueError(f"noncanonical SDK include path in {current}: {include!r}")
    selected = Path(prefix)
    parts = list(Path(current).relative_to(selected).parent.parts)
    for index, part in enumerate(components):
        if part == "..":
            if not parts:
                raise ValueError(f"SDK include escapes selected layout in {current}: {include!r}")
            parts.pop()
            continue
        candidate = selected.joinpath(*parts, part)
        path = root / candidate
        if path.is_symlink():
            raise ValueError(f"symlink in SDK includes: {path}")
        if index < len(components) - 1:
            if not path.is_dir():
                raise ValueError(f"missing or non-directory SDK include: {path}")
        elif not path.is_file():
            raise ValueError(f"missing or non-regular SDK include: {path}")
        parts.append(part)
    relative = selected.joinpath(*parts).as_posix()
    _sdk_input(root, relative)
    return relative


def select_sdk_files(root: Path) -> tuple[str, ...]:
    """Select five SDK roots and their literal local-include closure.

    Select one complete layout without concealing a partial SDK migration.
    Follow only explicit quoted includes, including inactive conditional
    branches; never enumerate unrelated SDK or vendor trees. Macro includes and
    unsupported include extensions fail explicitly instead of omitting input.
    """
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"SDK source root must be a real directory: {root}")
    sdk = root / "sdk"
    if sdk.is_symlink() or not sdk.is_dir():
        raise ValueError(f"SDK must be a real directory: {sdk}")
    origin = sdk / "origin"
    if origin.is_symlink():
        raise ValueError(f"symlink in SDK inputs: {origin}")
    prefix = "sdk/origin" if origin.exists() else "sdk"
    pending = [f"{prefix}/{name}" for name in SDK_MEMBERS]
    selected = set()
    while pending:
        relative = pending.pop()
        if relative in selected:
            continue
        path = _sdk_input(root, relative)
        selected.add(relative)
        for include in _quoted_includes(path):
            pending.append(_sdk_include(root, prefix, relative, include))
    return tuple(sorted(selected))


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
    for relative in select_sdk_files(root):
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
                                "examples", *select_sdk_files(root))}


def archive_inputs(root: Path, expected: dict, destination: Path) -> None:
    """Archive exactly the verified manifest files, with their actual names."""
    if not destination.resolve().is_relative_to(Path("/tmp").resolve()):
        raise ValueError("reference archive must be written under /tmp")
    if expected.get("format") != 1 or inventory(root) != expected.get("files"):
        raise ValueError("external example input inventory/content changed before archive")
    with tarfile.open(destination, "x", dereference=True) as archive:
        for record in expected["files"]:
            relative = record["path"]
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError(f"unsafe reference input path: {relative}")
            path = root / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"missing or non-regular archive input: {path}")
            with path.open("rb") as source:
                member = archive.gettarinfo(str(path), arcname=relative)
                if not member.isfile() or member.size != record["byte_len"]:
                    raise ValueError(f"archive input metadata changed: {path}")
                archive.addfile(member, source)
    # A concurrent edit must not become a successful frozen input archive.
    if inventory(root) != expected["files"]:
        raise ValueError("external example input inventory/content changed during archive")
    with tarfile.open(destination, "r") as archive:
        members = archive.getmembers()
        if [member.name for member in members] != [item["path"] for item in expected["files"]]:
            raise ValueError("reference archive file set differs from input manifest")
        for member, record in zip(members, expected["files"]):
            source = archive.extractfile(member) if member.isfile() else None
            if source is None:
                raise ValueError(f"non-regular reference archive member: {member.name}")
            with source:
                data = source.read()
            if len(data) != record["byte_len"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError(f"reference archive bytes differ from input manifest: {member.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("snapshot", "verify", "compare", "archive"))
    parser.add_argument("root", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if (args.mode == "archive") != (args.output is not None):
        parser.error("--output is required only for archive mode")
    if args.mode == "snapshot":
        result = {"format": 1, "source_root": str(args.root.resolve()),
                  "git": git_metadata(args.root), "files": inventory(args.root)}
        args.manifest.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"files": len(result["files"]), "snapshot": str(args.manifest)}))
        return
    expected = json.loads(args.manifest.read_text())
    if args.mode == "archive":
        archive_inputs(args.root, expected, args.output)
        print(json.dumps({"archived": True, "files": len(expected["files"]), "archive": str(args.output)}))
        return
    actual = inventory(args.root)
    if expected["format"] != 1 or actual != expected["files"]:
        raise ValueError("external example input inventory/content changed")
    if args.mode == "compare" and git_metadata(args.root) != expected["git"]:
        raise ValueError("external source revision/input Git status changed")
    print(json.dumps({"verified": True, "files": len(actual), "mode": args.mode}))


if __name__ == "__main__":
    main()
