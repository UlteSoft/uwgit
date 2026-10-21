#!/usr/bin/env python3
"""Fixed SDK include-closure cases; run only in the SSH Linux test cgroup.

No compiler, guest, network, git command, fuzzer, random input or external ROS
checkout is used. Every fixture and archive is created in an isolated /tmp tree.
"""

import importlib.util
import hashlib
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "uwgit_example_inputs", Path(__file__).with_name("uwvm-examples-inputs.py"))
INPUTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INPUTS)


class SDKInputs(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="uwgit-sdk-inputs-", dir="/tmp")
        self.root = Path(self.temporary.name)
        (self.root / "examples").mkdir()
        (self.root / "examples/module.wasm").write_bytes(b"\0asm\x01\0\0\0")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, text: str = "#pragma once\n") -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def seed(self, prefix: str = "sdk/origin") -> tuple[str, ...]:
        roots = tuple(f"{prefix}/{member}" for member in INPUTS.SDK_MEMBERS)
        for relative in roots:
            self.write(relative)
        return roots

    def snapshot(self) -> dict:
        return {path.relative_to(self.root).as_posix(): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()}

    def test_legacy_layout_keeps_exact_original_five_roots(self) -> None:
        roots = self.seed("sdk")
        before = self.snapshot()
        self.assertEqual(INPUTS.select_sdk_files(self.root), tuple(sorted(roots)))
        self.assertEqual(self.snapshot(), before)

    def test_origin_layout_wins_without_mixing_legacy_headers(self) -> None:
        roots = self.seed()
        self.seed("sdk")
        self.write("sdk/common/abi.h", '#include UNKNOWN_LEGACY_MACRO\n')
        self.assertEqual(INPUTS.select_sdk_files(self.root), tuple(sorted(roots)))

    def test_partial_origin_layout_never_falls_back_to_complete_legacy(self) -> None:
        self.seed("sdk")
        self.write("sdk/origin/common/abi.h")
        with self.assertRaisesRegex(ValueError, "missing or non-directory"):
            INPUTS.select_sdk_files(self.root)

    def test_local_quote_closure_cycles_deduplicates_and_does_not_walk_vendor(self) -> None:
        roots = self.seed()
        self.write("sdk/origin/common/abi.h", '#include "c_portability.h"\n#include "c_portability.h"\n')
        self.write("sdk/origin/common/c_portability.h", '#include <stddef.h>\n#include <stdint.h>\n#include "abi.h"\n')
        self.write("sdk/origin/ros1/abi.h", '#include "../common/abi.h"\n')
        self.write("sdk/origin/ros2/abi.h", '#include "../common/abi.h"\n')
        self.write("sdk/origin/vendor/never-read.h", '#include UNKNOWN_VENDOR_MACRO\n')
        (self.root / "sdk/origin/vendor/dangling.h").symlink_to("missing.h")
        before = self.snapshot()
        self.assertEqual(INPUTS.select_sdk_files(self.root), tuple(sorted((*roots, "sdk/origin/common/c_portability.h"))))
        self.assertEqual(self.snapshot(), before)

    def test_recursive_profiles_and_raw_backend_headers_form_only_reachable_closure(self) -> None:
        roots = self.seed()
        self.write("sdk/origin/ros1/freestanding.hpp", '#include "../include/roswasm/cpp_profile.hpp"\n#if OLD_PROFILE\n#include "../include/roswasm/detail/raw_ros1.hpp"\n#else\n#include "abi.h"\n#endif\n')
        self.write("sdk/origin/ros2/freestanding.hpp", '#include "../include/roswasm/detail/raw_ros2.hpp"\n')
        leaves = {
            "include/roswasm/cpp_profile.hpp": '#include <cstddef>\n',
            "include/roswasm/detail/raw_ros1.hpp": '#include "../ros1.h"\n#include "raw_owner.hpp"\n',
            "include/roswasm/detail/raw_ros2.hpp": '#include "../ros2.h"\n#include "raw_owner.hpp"\n',
            "include/roswasm/detail/raw_owner.hpp": '#include "../cpp_profile.hpp"\n',
            "include/roswasm/ros1.h": '#include <stdint.h>\n',
            "include/roswasm/ros2.h": '#include <stdint.h>\n',
        }
        for relative, content in leaves.items():
            self.write(f"sdk/origin/{relative}", content)
        self.assertEqual(INPUTS.select_sdk_files(self.root), tuple(sorted((*roots, *(f"sdk/origin/{name}" for name in leaves)))))

    def test_comment_strings_raw_literals_continuations_and_bom_are_lexically_handled(self) -> None:
        roots = self.seed()
        self.write("sdk/origin/common/abi.h", '''\ufeff/* #include "missing-a.h" */
// #include "missing-b.h"
const char *s = "text // /* quoted */";
const char *raw = R"tag(
#include "missing-c.h"
)tag";
const char c = '/';
const auto d = u8'x';
const auto n = 1'000;
# /* visible comment */ inc\\
lude /* another comment */ "leaf.h" // accepted trailing comment
''')
        self.write("sdk/origin/common/leaf.h", '#include <stddef.h>\n')
        self.assertEqual(INPUTS.select_sdk_files(self.root), tuple(sorted((*roots, "sdk/origin/common/leaf.h"))))

    def test_digraph_directive_is_collected(self) -> None:
        roots = self.seed()
        self.write("sdk/origin/common/abi.h", '%: include "leaf.h"\n')
        self.write("sdk/origin/common/leaf.h")
        self.assertEqual(INPUTS.select_sdk_files(self.root), tuple(sorted((*roots, "sdk/origin/common/leaf.h"))))

    def test_unknown_macro_and_include_extensions_fail_instead_of_omitting_bytes(self) -> None:
        self.seed()
        cases = ('#include HEADER\n', '#include MAKE_HEADER(x)\n', '#include_next "leaf.h"\n',
                 '#import "leaf.h"\n', '#include "leaf.h" extra\n', '#include ""\n',
                 '#include <unterminated\n', '#if 0\n#include UNKNOWN\n#endif\n')
        for text in cases:
            with self.subTest(text=text):
                self.write("sdk/origin/common/abi.h", text)
                with self.assertRaisesRegex(ValueError, "include"):
                    INPUTS.select_sdk_files(self.root)

    def test_missing_or_non_regular_quoted_header_is_rejected(self) -> None:
        self.seed()
        self.write("sdk/origin/common/abi.h", '#include "missing.h"\n')
        with self.assertRaisesRegex(ValueError, "missing or non-regular"):
            INPUTS.select_sdk_files(self.root)
        (self.root / "sdk/origin/common/missing.h").mkdir()
        with self.assertRaisesRegex(ValueError, "missing or non-regular"):
            INPUTS.select_sdk_files(self.root)

    def test_escape_absolute_and_noncanonical_include_paths_are_rejected(self) -> None:
        self.seed()
        paths = ("../../outside.h", "/tmp/outside.h", "../common/../../../outside.h", "./abi.h",
                 "x//leaf.h", "x\\leaf.h", "C:leaf.h", "x/../abi.h")
        for path in paths:
            with self.subTest(path=path):
                self.write("sdk/origin/common/abi.h", f'#include "{path}"\n')
                with self.assertRaises(ValueError):
                    INPUTS.select_sdk_files(self.root)

    def test_existing_directory_parent_reference_is_allowed_but_symlink_parent_is_not(self) -> None:
        roots = self.seed()
        (self.root / "sdk/origin/common/ordinary").mkdir()
        self.write("sdk/origin/common/abi.h", '#include "ordinary/../leaf.h"\n')
        self.write("sdk/origin/common/leaf.h")
        self.assertEqual(INPUTS.select_sdk_files(self.root), tuple(sorted((*roots, "sdk/origin/common/leaf.h"))))
        (self.root / "sdk/origin/common/link").symlink_to("ordinary", target_is_directory=True)
        self.write("sdk/origin/common/abi.h", '#include "link/../leaf.h"\n')
        with self.assertRaisesRegex(ValueError, "symlink"):
            INPUTS.select_sdk_files(self.root)

    def test_root_layout_leaf_and_intermediate_symlinks_are_rejected(self) -> None:
        self.seed()
        self.write("outside.h")
        (self.root / "sdk/origin/common/leaf.h").symlink_to(self.root / "outside.h")
        self.write("sdk/origin/common/abi.h", '#include "leaf.h"\n')
        with self.assertRaisesRegex(ValueError, "symlink"):
            INPUTS.select_sdk_files(self.root)
        (self.root / "alias").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directory"):
            INPUTS.select_sdk_files(self.root / "alias")
        # A present origin symlink must never be treated as a missing layout.
        (self.root / "sdk/origin").rename(self.root / "sdk/real-origin")
        (self.root / "sdk/origin").symlink_to("real-origin", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            INPUTS.select_sdk_files(self.root)

    def test_malformed_comment_string_and_non_utf8_header_fail_explicitly(self) -> None:
        self.seed()
        for text in ('/* unclosed', 'const char *s = "unclosed\n', 'const char *s = R"tag(unclosed', '??/\n#include "x.h"\n'):
            with self.subTest(text=text):
                self.write("sdk/origin/common/abi.h", text)
                with self.assertRaises(ValueError):
                    INPUTS.select_sdk_files(self.root)
        (self.root / "sdk/origin/common/abi.h").write_bytes(b"\xff\xfe")
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            INPUTS.select_sdk_files(self.root)

    def test_inventory_and_archive_cover_closure_and_detect_later_header_change(self) -> None:
        self.seed()
        self.write("sdk/origin/common/abi.h", '#include "leaf.h"\n')
        self.write("sdk/origin/common/leaf.h", "#define LEAF 1\n")
        expected = {"format": 1, "files": INPUTS.inventory(self.root)}
        paths = [record["path"] for record in expected["files"]]
        self.assertIn("sdk/origin/common/leaf.h", paths)
        self.assertIn("examples/module.wasm", paths)
        leaf = next(record for record in expected["files"] if record["path"] == "sdk/origin/common/leaf.h")
        self.assertEqual(leaf["byte_len"], len(b"#define LEAF 1\n"))
        self.assertEqual(leaf["sha256"], hashlib.sha256(b"#define LEAF 1\n").hexdigest())
        archive = self.root / "inputs.tar"
        INPUTS.archive_inputs(self.root, expected, archive)
        with tarfile.open(archive, "r") as frozen:
            self.assertEqual([member.name for member in frozen.getmembers()], paths)
            with frozen.extractfile("sdk/origin/common/leaf.h") as source:
                self.assertEqual(source.read(), b"#define LEAF 1\n")
        frozen_bytes = archive.read_bytes()
        self.write("sdk/origin/common/leaf.h", "#define LEAF 2\n")
        with self.assertRaisesRegex(ValueError, "changed before archive"):
            INPUTS.archive_inputs(self.root, expected, self.root / "new-inputs.tar")
        self.assertFalse((self.root / "new-inputs.tar").exists())
        self.assertEqual(archive.read_bytes(), frozen_bytes)
        self.assertNotEqual(INPUTS.inventory(self.root), expected["files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
