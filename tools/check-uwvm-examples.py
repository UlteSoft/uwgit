#!/usr/bin/env python3
"""Cross-check complete example inventories, producer outputs and command receipts."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def current_inputs(reference):
    """Reuse the snapshot traversal, including all files and symlink rejection."""
    source = Path(__file__).with_name("uwvm-examples-inputs.py")
    spec = importlib.util.spec_from_file_location("uwgit_uwvm_examples_inputs", source)
    require(spec is not None and spec.loader is not None, "cannot load input inventory helper")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module.inventory(reference)


def unique_records(records, key, description):
    indexed = {item[key]: item for item in records}
    require(len(indexed) == len(records), f"duplicate {description}")
    return indexed


def product_command(products, index, product, description):
    commands = products["commands"]
    require(type(index) is int and 0 <= index < len(commands), f"invalid command index: {description}")
    command = commands[index]
    require(command["index"] == index and product in command["argv"], f"command does not bind product: {description}")
    return command


def verify(run):
    reference, build, evidence = run / "reference", run / "build", run / "evidence"
    manifest = json.loads((evidence / "inputs.json").read_text())
    require(manifest["format"] == 1, "unsupported input manifest format")
    require(current_inputs(reference) == manifest["files"], "current complete reference inventory/content differs from frozen inputs")
    inputs = {item["path"]: item for item in manifest["files"]}
    require(len(inputs) == len(manifest["files"]), "duplicate source input")
    for phase in ("before", "after"):
        receipt = json.loads((evidence / f"inputs.{phase}.json").read_text())
        require(receipt["verified"] is True and receipt["files"] == len(inputs)
                and receipt["mode"] == "verify", f"missing/inconsistent {phase} input verification")
    selected = {name.removeprefix("examples/"): item for name, item in inputs.items()
                if name.startswith("examples/") and Path(name).suffix in (".wasm", ".wat")}
    corpus = json.loads((evidence / "corpus.json").read_text())
    require(corpus["complete"] and not corpus["failures"], "corpus failures")
    actual = {item["relative_path"]: item for item in corpus["files"]}
    require(len(actual) == len(corpus["files"]) and set(actual) == set(selected), "example corpus file set differs from frozen inputs")
    paired = 0
    for name, original in selected.items():
        item = actual[name]
        require(item["source_sha256"] == original["sha256"] and item["source_len"] == original["byte_len"], f"source mismatch: {name}")
        require(item["audit_validation"] == "valid_with_all_known_features" and item["audit_decoding_complete"], f"incomplete original decoding: {name}")
        for flag in ("identity_replay", "serialized_identity_patch_replay", "mutation_replay", "serialized_mutation_patch_replay"):
            require(item[flag] is True, f"missing {flag}: {name}")
        require(item["independent_inventory"] is not None, f"missing independent inventory: {name}")
        if Path(name).suffix == ".wat":
            product = build / (name + ".wasm")
            require(item["generated_path"] == str(product) and product.is_file(), f"wrong/missing compiled path: {name}")
            require(digest(product) == item["binary_sha256"] and product.stat().st_size == item["binary_len"], f"compiled bytes mismatch: {name}")
            pair_name = str(Path(name).with_suffix(".wasm"))
            if pair_name in selected:
                paired += 1
                pair = item["paired_binary"]
                require(pair is not None and pair["replay"] and pair["serialized_patch"]["replay"], f"missing binary/source pair replay: {name}")
                require(pair["source_sha256"] == selected[pair_name]["sha256"], f"wrong paired input: {name}")
        else:
            require(item["binary_sha256"] == original["sha256"], f"original binary changed: {name}")
    summary = corpus["summary"]
    require(summary["valid_core_modules"] == len(selected), "module count mismatch")
    require(summary["paired_binaries"] == paired == summary["paired_binary_replays"], "paired module count mismatch")

    expected_cases = {"preload-constant", "preload-bindings", "preload-index-shift",
                      "preload-name-opaque", "preload-real-merge", "real-proxy-tail-pair"}
    reports = sorted((evidence / "workflows").glob("*.json"))
    seen, commands, runtime_commands = set(), 0, 0
    expected_runtime_outcomes = {
        "preload-constant": (1, 1),
        "preload-bindings": (3, 2),
        "preload-index-shift": (2, 0),
        "preload-name-opaque": (2, 0),
        "preload-real-merge": (2, 1),
        "real-proxy-tail-pair": (0, 0),
    }
    runtime_outcomes = {}
    for path in reports:
        report = json.loads(path.read_text())
        label = next((label for label in expected_cases if path.name.startswith(label + "-")), None)
        require(label is not None and label not in seen, f"extra/duplicate workflow: {path}")
        seen.add(label)
        runtime_successes, runtime_failures = 0, 0
        require(report["status"] == "PASS", f"workflow failed/incomplete: {path}")
        require(report["sources"] and report["artifacts"] and report["commands"], f"empty workflow: {path}")
        for source in report["sources"]:
            relative = str(Path(source["path"]).relative_to(reference))
            require(source["sha256_before"] == source["sha256_after"] == inputs[relative]["sha256"], f"workflow reference changed: {relative}")
        for artifact in report["artifacts"]:
            product = Path(artifact["path"])
            require(product.is_relative_to(run) and digest(product) == artifact["sha256"] and product.stat().st_size == artifact["length"], f"workflow product changed: {product}")
        for command in report["commands"]:
            commands += 1
            require(command["status"] == "COMPLETED" and command["returncode"] not in (124, 137), f"incomplete/timeout command: {path}")
            expected, code = command["expected"], command["returncode"]
            if expected == "success":
                require(code == 0, f"positive workflow command failed: {path}")
            elif expected.startswith("exit "):
                require(code == int(expected[5:]), f"wrong expected exit: {path}")
            else:
                require(expected == "nonzero (excluding timeout)" and code != 0, f"negative workflow command did not fail: {path}")
            for stream in ("stdout", "stderr"):
                require(digest(Path(command[stream])) == command[stream + "_sha256"], f"workflow command receipt changed: {path}")
            if Path(command["program"]) == run / "bin" / "uwvm":
                runtime_commands += 1
                require(type(code) is int, f"runtime has no normal exit-code receipt: {path}")
                if code == 0:
                    runtime_successes += 1
                else:
                    runtime_failures += 1
        runtime_outcomes[label] = (runtime_successes, runtime_failures)
        require(runtime_outcomes[label] == expected_runtime_outcomes[label], f"runtime outcome set incomplete for {label}: {runtime_outcomes[label]}")
    require(seen == expected_cases, "workflow set incomplete")
    require(runtime_commands == 14, "expected exactly fourteen actual preload execution witnesses")
    require(sum(outcome[0] for outcome in runtime_outcomes.values()) == 10
            and sum(outcome[1] for outcome in runtime_outcomes.values()) == 4,
            "expected ten successful and four deliberately failing preload executions")

    products = json.loads((evidence / "products" / "products-report.json").read_text())
    require(products["passed"] and not products["failures"] and not products["validator_disagreements"], "independent validation or C/C++ producer failure")
    require(products["reference_unchanged"], "C/C++ validation reference changed")
    require(products["reference"] == str(reference) and products["build_root"] == str(build), "producer report belongs to another run")
    expected_modules = {str(reference / "examples" / name) for name in selected if Path(name).suffix == ".wasm"}
    expected_modules |= {str(build / (name + ".wasm")) for name in selected if Path(name).suffix == ".wat"}
    modules = products["modules"]
    external = [item for item in modules if item["category"] in ("reference_wasm", "compiled_wat")]
    require(len(external) == len(expected_modules) and {item["path"] for item in external} == expected_modules, "independent validator input set incomplete")
    counts = Counter(item["category"] for item in modules)
    require(counts["real_c_cpp"] == 6 and counts["real_c_threshold_variant"] == 1, "missing real C/C++ products")
    expected_products = {}
    for backend in ("ros1", "ros2"):
        for filename in ("talker.c", "listener.c", "talker.cpp"):
            source = f"examples/{backend}/{filename}"
            product = str(build / "c-compiled" / f"{backend}-{filename.replace('.', '-')}.wasm")
            expected_products[product] = {
                "source": str(build / "c-work-source" / source),
                "source_bytes": (reference / source).read_bytes(),
                "category": "real_c_cpp", "backend": backend,
            }
    variant_source = "examples/ros1/talker.c"
    original_source = (reference / variant_source).read_bytes()
    require(original_source.count(b"1000000000ULL") == 1, "unexpected threshold source contents")
    variant_product = str(build / "c-compiled" / "ros1-talker-c-threshold-plus-one.wasm")
    expected_products[variant_product] = {
        "source": str(build / "c-variant-source" / variant_source),
        "source_bytes": original_source.replace(b"1000000000ULL", b"1000000001ULL"),
        "category": "real_c_threshold_variant", "backend": "ros1",
    }
    real_modules = unique_records(
        [item for item in modules if item["category"] in ("real_c_cpp", "real_c_threshold_variant")],
        "path", "real C/C++ module path")
    require(set(real_modules) == set(expected_products), "real C/C++ module path set incomplete/extra")
    require(len(modules) == len(expected_modules) + len(expected_products), "unexpected producer module category or duplicate module")
    compilations = unique_records(products["compilations"], "output", "compilation output")
    require(set(compilations) == set(expected_products), "compilation output set incomplete/extra")
    require(len({item["source"]["path"] for item in compilations.values()}) == 7, "duplicate C/C++ compilation source")
    require(len({item["command"] for item in compilations.values()}) == 7, "reused compilation command receipt")
    import_checks = unique_records(products["compiled_import_checks"], "path", "compiled import-check path")
    require(set(import_checks) == set(expected_products), "compiled import-check product set incomplete/extra")
    inspection_commands = set()
    for product, expected in expected_products.items():
        require(real_modules[product]["category"] == expected["category"], f"wrong real-source product category: {product}")
        compilation = compilations[product]
        require(compilation["success"] is True, f"compilation did not succeed: {product}")
        source = compilation["source"]
        expected_bytes = expected["source_bytes"]
        require(source["path"] == expected["source"], f"wrong source/output binding: {product}")
        require(Path(source["path"]).read_bytes() == expected_bytes
                and source["sha256"] == hashlib.sha256(expected_bytes).hexdigest()
                and source["byte_len"] == len(expected_bytes), f"compiled source differs from frozen input/explicit variant: {product}")
        command = product_command(products, compilation["command"], product, f"compile {product}")
        argv = command["argv"]
        require(source["path"] in argv and "-o" in argv
                and argv.index("-o") + 1 < len(argv) and argv[argv.index("-o") + 1] == product,
                f"compilation command does not bind exact source/output: {product}")
        checked = import_checks[product]
        require(checked["matches_uwgit_projection"] is True and checked["unexpected_env_imports"] is False,
                f"missing successful independent import comparison: {product}")
        allowed_modules = {"wasi_snapshot_preview1", f"uwvm_{expected['backend']}_v1"}
        require({item["module"] for item in checked["imports"]} == allowed_modules,
                f"wrong backend or unexpected compiled import module: {product}")
        for key in ("objdump_details_command", "objdump_disassembly_command", "uwgit_inspect_command"):
            index = checked[key]
            product_command(products, index, product, f"{key} {product}")
            require(index not in inspection_commands, f"reused independent import inspection command: {product}")
            inspection_commands.add(index)
    variant = products["threshold_variant"]
    baseline_product = str(build / "c-compiled" / "ros1-talker-c.wasm")
    require(variant["source"] == compilations[variant_product]["source"], "threshold source receipt differs from compilation")
    for key, product in (("baseline", baseline_product), ("variant", variant_product)):
        receipt = variant[key]
        module = real_modules[product]
        require(receipt["path"] == product and receipt["sha256"] == module["sha256"]
                and receipt["byte_len"] == module["byte_len"], f"wrong threshold {key} product receipt")
    for item in modules:
        product = Path(item["path"])
        require(item["wabt_valid"] and item["uwvm_valid"] and digest(product) == item["sha256"], f"independent module validation missing: {product}")
    for command in products["commands"]:
        require(command["returncode"] == 0 and not command["timed_out"], "independent product command failure")
        for stream in ("stdout", "stderr"):
            require(digest(Path(command[stream])) == command[stream + "_record"]["sha256"], "independent command receipt changed")
    require(products["threshold_variant"]["exact_replay"] is True, "missing real C threshold patch replay")
    return {"format": 1, "verified": True, "reference_files": len(inputs), "corpus_modules": len(selected),
            "original_wasm": summary["discovered_wasm"], "wat_sources": summary["discovered_wat"],
            "paired_binary_replays": paired, "serialized_patch_replays": len(selected) * 2 + paired,
            "workflow_cases": len(seen), "workflow_commands": commands, "preload_runtime_commands": runtime_commands,
            "preload_runtime_successes": 10, "preload_runtime_expected_failures": 4,
            "preload_runtime_outcomes_by_case": {name: {"successes": value[0], "expected_failures": value[1]}
                                                  for name, value in sorted(runtime_outcomes.items())},
            "real_c_cpp_products": counts["real_c_cpp"], "real_c_variants": counts["real_c_threshold_variant"],
            "double_validator_modules": len(modules)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.run), indent=2))
