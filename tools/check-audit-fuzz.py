#!/usr/bin/env python3
"""Check complete fixed-seed mutation receipts without trusting summary counts.

Run this inside the same SSH Linux cgroup as the Rust fuzz harness. This checks
evidence integrity and mutation coverage; the Rust harness performs auditing and
forward/reverse serialized patch replay, without executing guest modules.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def require(value, message):
    if not value:
        raise ValueError(message)


def verify(directory, random_cases=10_000):
    summary = json.loads((directory / "summary.json").read_text())
    raw = (directory / "cases.jsonl").read_bytes()
    require(summary["status"] == "PASS" and summary["schema_version"] == 1, "fuzz did not complete")
    require(summary["seed"] == "75776769742d7631", "unexpected seed")
    require(summary["profiles"] == ["core1", "core2", "core3", "all-known"], "missing profile")
    require(summary["receipts"] == "cases.jsonl" and hashlib.sha256(raw).hexdigest() == summary["receipts_sha256"], "receipt hash/path mismatch")
    seeds, mutations, counts, random_indices = {}, {}, Counter(), set()
    lines = raw.splitlines()
    for index, line in enumerate(lines):
        record = json.loads(line)
        require(record["case"] == index and record["seed"] == summary["seed"], "case order/seed mismatch")
        require(record["status"] == "PASS" and record["error"] is None, "failed case")
        old, new = (bytes.fromhex(record[side + "_hex"]) for side in ("old", "new"))
        for side, data in (("old", old), ("new", new)):
            require(data.hex() == record[side + "_hex"] and hashlib.sha256(data).hexdigest() == record[side + "_sha256"], "case raw bytes/hash differ")
            require(data.startswith(b"\0asm\x01\0\0\0"), "payload fuzz changed Core header")
        require(old != new, "identity counted as a mutation")
        label, mutation = record["fixture"], record["mutation"]
        require(label not in seeds or seeds[label] == old, "seed fixture changed")
        seeds[label] = old
        seen = mutations.setdefault(label, set())
        require(mutation not in seen, "duplicate mutation receipt")
        seen.add(mutation)
        kind, *args = mutation.split(":")
        counts[kind] += 1
        if kind == "random":
            number = int(args[0])
            require(number not in random_indices, "duplicate random iteration")
            random_indices.add(number)
            continue
        position = int(args[0])
        require(8 <= position <= len(old), "mutation position outside payload")
        expected = bytearray(old)
        if kind == "bit":
            require(position < len(old) and 0 <= int(args[1]) < 8, "bad bit mutation")
            expected[position] ^= 1 << int(args[1])
        elif kind == "delete":
            require(position < len(old), "bad deletion")
            del expected[position]
        elif kind == "insert":
            expected.insert(position, int(args[1], 16))
        else:
            raise ValueError("unknown mutation kind")
        require(bytes(expected) == new, "receipt does not match declared mutation")
    for label, old in seeds.items():
        expected = {f"bit:{position}:{bit}" for position in range(8, len(old)) for bit in range(8)}
        expected |= {f"delete:{position}" for position in range(8, len(old))}
        expected |= {f"insert:{position}:{value:02x}" for position in range(8, len(old) + 1) for value in (0, 1, 0x0b, 0x41, 0x7f, 0x80, 0xff)}
        require({value for value in mutations[label] if not value.startswith("random:")} == expected, "incomplete exhaustive mutations")
    require(len(seeds) == 9 and len(lines) == summary["cases"], "fixture/case count mismatch")
    require(0 <= random_cases <= 1_000_000 and random_indices == set(range(random_cases)), "fixed random campaign incomplete")
    return {"verified": True, "seed": summary["seed"], "cases": len(lines), "fixtures": len(seeds), "mutations": dict(counts), "receipts_sha256": summary["receipts_sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--random-cases", type=int, default=10_000)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.random_cases), indent=2))
