#!/usr/bin/env python3
"""Fetch immutable official Core WAST inputs; this does not execute tests.

Run in the existing SSH Linux test cgroup. Materialized inputs and downloads are
kept under the explicitly chosen /tmp directory. Only regular .wast members of
verified archives are extracted; no archive path or link is trusted.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import urllib.request


def fetch(destination: Path) -> dict:
    destination = destination.absolute()
    if not destination.is_relative_to(Path("/tmp")) or ".." in destination.parts:
        raise ValueError("corpus destination must be under /tmp")
    destination.mkdir(parents=True, exist_ok=True)
    pins = json.loads(Path(__file__).with_name("spec-corpora.json").read_text())
    results = []
    for pin in pins["corpora"]:
        url = f'https://codeload.github.com/WebAssembly/spec/tar.gz/{pin["commit"]}'
        archive = destination / f'{pin["commit"]}.tar.gz'
        # Even a cached download must satisfy the pinned digest on every run.
        if not archive.exists():
            with urllib.request.urlopen(url, timeout=90) as response:
                with tempfile.NamedTemporaryFile(dir=destination, delete=False) as output:
                    temporary = Path(output.name)
                    try:
                        while chunk := response.read(1024 * 1024):
                            output.write(chunk)
                    except BaseException:
                        temporary.unlink(missing_ok=True)
                        raise
            temporary.replace(archive)
        with archive.open("rb") as downloaded:
            digest = hashlib.file_digest(downloaded, "sha256").hexdigest()
        if digest != pin["archive_sha256"]:
            raise ValueError(f'archive digest mismatch: {archive}: {digest}')
        target = Path(tempfile.mkdtemp(prefix=f'core{pin["version"]}-', dir=destination))
        prefix = f'spec-{pin["commit"]}/test/core/'
        files = []
        with tarfile.open(archive, "r:gz") as source:
            for member in source:
                if not member.name.startswith(prefix) or not member.name.endswith(".wast"):
                    continue
                relative = PurePosixPath(member.name[len(prefix):])
                if not member.isfile() or relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"unexpected corpus member {member.name!r}")
                path = target.joinpath(*relative.parts)
                path.parent.mkdir(parents=True, exist_ok=True)
                data = source.extractfile(member).read()
                with path.open("xb") as output:
                    output.write(data)
                files.append({"path": relative.as_posix(), "sha256": hashlib.sha256(data).hexdigest()})
        files.sort(key=lambda item: item["path"])
        if len(files) != pin["wast_files"]:
            raise ValueError(f'corpus file count mismatch for {pin["tag"]}: {len(files)}')
        result = dict(pin, root=str(target), url=url, files=files)
        (target / "provenance.json").write_text(json.dumps(result, indent=2) + "\n")
        results.append(result)
    return {"format": 1, "upstream": pins["upstream"], "corpora": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(fetch(arguments.destination), indent=2))
