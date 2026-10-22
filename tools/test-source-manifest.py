#!/usr/bin/env python3
"""Source transfer checks, including changed and added local source files."""
import io
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest

manifest = runpy.run_path(str(Path(__file__).with_name("source-manifest.py")))


class SourceManifestTests(unittest.TestCase):
    def test_roundtrip_and_local_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "src").mkdir()
            (source / "src" / "main.rs").write_text("fn main() {}\n")
            archive = root / "source.tar"
            with tarfile.open(archive, "w:") as output:
                output.add(source / "src", arcname="src")
            record = root / "inputs.json"
            manifest["create"](archive, record)
            manifest["compare"](record, source)
            frozen = root / "frozen"
            frozen.mkdir()
            with tarfile.open(archive, "r:") as saved:
                saved.extractall(frozen, filter="data")
            (frozen / "source-inputs.json").write_bytes(record.read_bytes())
            manifest["verify"](frozen)
            (source / "src" / "new.rs").write_text("new source")
            with self.assertRaises(ValueError):
                manifest["compare"](record, source)
            (source / "src" / "new.rs").unlink()
            (source / "src" / "main.rs").write_text("changed source")
            with self.assertRaises(ValueError):
                manifest["compare"](record, source)

    def test_rejects_links_duplicates_and_parent_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for case in ["../outside", "link", "duplicate"]:
                archive = root / "source.tar"
                with tarfile.open(archive, "w:") as output:
                    info = tarfile.TarInfo(case)
                    if case == "link":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/outside"
                        output.addfile(info)
                    else:
                        info.size = 1
                        output.addfile(info, io.BytesIO(b"x"))
                        if case == "duplicate":
                            output.addfile(info, io.BytesIO(b"x"))
                with self.assertRaises(ValueError):
                    manifest["create"](archive, root / "inputs.json")


if __name__ == "__main__":
    unittest.main()
