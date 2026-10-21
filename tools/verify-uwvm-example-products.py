#!/usr/bin/env python3
"""Compile and independently validate staged uwvm2-ros example products.

This is an opt-in Linux/cgroup harness. It never executes guest code, starts a
ROS gateway, or writes to the reference tree. Runtime workflows are a separate
test lane. Every subprocess has complete logs and an explicit timeout.
"""

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback


SOURCES = tuple(
    f"examples/{backend}/{name}"
    for backend in ("ros1", "ros2")
    for name in ("talker.c", "listener.c", "talker.cpp")
)


def selected_headers(reference):
    source = Path(__file__).with_name("uwvm-examples-inputs.py")
    spec = importlib.util.spec_from_file_location("uwgit_product_inputs", source)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load input SDK selection helper")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module.select_sdk_files(reference)


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def file_record(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular non-symlink file: {path}")
    return {"path": str(path), "byte_len": path.stat().st_size, "sha256": sha256(path)}


def require_tmp(path):
    resolved = path.resolve()
    if not resolved.is_relative_to(Path("/tmp").resolve()):
        raise ValueError(f"all harness output must be under /tmp: {path}")
    return resolved


def inventory(reference, headers=None):
    selected = selected_headers(reference)
    if headers is not None and selected != headers:
        raise ValueError("selected SDK layout changed during product verification")
    paths = {reference / name for name in selected + SOURCES}
    examples = reference / "examples"
    if not examples.is_dir():
        raise ValueError(f"reference root must contain examples/: {reference}")
    paths.update(examples.rglob("*.wasm"))
    paths.update(examples.rglob("*.wat"))
    return {
        str(path.relative_to(reference)): file_record(path)
        for path in sorted(paths)
    }


def expected_swap_max():
    value = os.environ.get("UWGIT_EXPECTED_CGROUP_SWAP_MAX", "0")
    if re.fullmatch(r"max|0|[1-9][0-9]*", value) is None:
        raise ValueError("UWGIT_EXPECTED_CGROUP_SWAP_MAX must be max or canonical nonnegative decimal")
    return value


def linux_admission():
    if platform.system() != "Linux":
        raise ValueError("this harness must run on SSH Linux inside the existing cgroup")
    text = Path("/proc/self/cgroup").read_text()
    paths = [line.split(":", 2)[2] for line in text.splitlines() if line.startswith("0::")]
    if len(paths) != 1 or not re.fullmatch(r"/system\.slice/docker-[0-9a-f]+\.scope", paths[0]):
        raise ValueError(f"expected the existing docker cgroup, got {text!r}")
    group = Path("/sys/fs/cgroup") / paths[0].lstrip("/")
    swap_max = expected_swap_max()
    expected_limits = {"memory.max": "68719476736", "memory.swap.max": swap_max, "cpuset.cpus.effective": "0-31"}
    limits = {field: (group / field).read_text().strip() for field in expected_limits}
    if limits != expected_limits:
        raise ValueError("existing cgroup limits must match 64 GiB, CPUs 0-31 and the explicit swap expectation")
    if str(os.getpid()) not in (group / "cgroup.procs").read_text().splitlines():
        raise ValueError("harness PID is absent from its reported existing cgroup")
    return {
        "cgroup": text,
        "cgroup_path": str(group),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "memory_max": limits["memory.max"],
        "memory_swap_max": limits["memory.swap.max"],
        "expected_cgroup_swap_max": swap_max,
        "cpuset_cpus_effective": limits["cpuset.cpus.effective"],
        "limits_before": limits,
        "swap_current_before": (group / "memory.swap.current").read_text().strip(),
        "memory_events_before": (group / "memory.events").read_text(),
        "resource_scope": "Existing shared cgroup; nonfatal memory.max events may reflect other load. Other tasks are not isolated.",
    }


class Harness:
    def __init__(self, args):
        self.args = args
        self.reference = args.reference.resolve(strict=True)
        self.headers = selected_headers(self.reference)
        self.build = require_tmp(args.build_root)
        self.evidence = require_tmp(args.evidence)
        if self.build.is_relative_to(self.reference) or self.evidence.is_relative_to(self.reference):
            raise ValueError("build/evidence directories must be outside the reference tree")
        self.build.mkdir(parents=True, exist_ok=True)
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.logs = self.evidence / "products-commands"
        self.logs.mkdir(exist_ok=False)
        self.report = {
            "schema_version": 1,
            "scope": "real staged ROS C/C++ compilation, independent WABT and UWVM validation, physical diff and patch replay; no guest execution or native ROS delivery",
            "guest_execution_tested": False,
            "native_ros_delivery_tested": False,
            "command_log_storage": "shared_sha256_payloads_v1",
            "reference": str(self.reference),
            "build_root": str(self.build),
            "commands": [],
            "compilations": [],
            "modules": [],
            "validator_disagreements": [],
            "failures": [],
        }
        self.environment = os.environ.copy()
        self.environment["TMPDIR"] = str(self.build / "compiler-tmp")
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"
        Path(self.environment["TMPDIR"]).mkdir(exist_ok=False)

    def fail(self, stage, message, **details):
        self.report["failures"].append({"stage": stage, "message": str(message), **details})

    def stream_record(self, data):
        # Successful validators usually emit two empty streams. Store identical
        # bytes once while retaining a separate stream receipt for every command.
        expected = hashlib.sha256(data).hexdigest()
        path = self.logs / f"{expected}.log"
        if not path.exists():
            path.write_bytes(data)
        record = file_record(path)
        if record["sha256"] != expected or record["byte_len"] != len(data):
            raise ValueError("shared command log content differs from its receipt")
        return record

    def command(self, label, argv, *, timeout=30, inputs=(), outputs=()):
        index = len(self.report["commands"])
        record = {
            "index": index, "label": label, "argv": [str(value) for value in argv],
            "cwd": str(self.build), "timeout_seconds": timeout,
            "inputs": [file_record(Path(path)) for path in inputs],
            "outputs": [], "returncode": None, "timed_out": False,
            "stdout": None, "stderr": None,
        }
        self.report["commands"].append(record)
        started = time.monotonic()
        stdout = stderr = b""
        process = None
        try:
            process = subprocess.Popen(
                record["argv"], cwd=self.build, env=self.environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
            record["returncode"] = process.returncode
        except OSError as error:
            record["error"] = str(error)
        except BaseException:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
            raise
        finally:
            record["elapsed_seconds"] = time.monotonic() - started
            for stream, data in (("stdout", stdout), ("stderr", stderr)):
                receipt = self.stream_record(data)
                record[stream] = receipt["path"]
                record[stream + "_record"] = receipt
            for path in outputs:
                path = Path(path)
                record["outputs"].append(file_record(path) if path.is_file() else {"path": str(path), "missing": True})
        return record

    @staticmethod
    def succeeded(record):
        return record["returncode"] == 0 and not record["timed_out"] and "error" not in record

    def require_command(self, label, argv, **kwargs):
        record = self.command(label, argv, **kwargs)
        if not self.succeeded(record):
            raise ValueError(f"{label} failed; command[{record['index']}], returncode={record['returncode']}, timeout={record['timed_out']}")
        return record

    @staticmethod
    def output(record, stream="stdout"):
        return Path(record[stream]).read_text(errors="replace")

    def prepare_tools(self):
        self.tools = {}
        for name, supplied in (
            ("uwgit", self.args.uwgit), ("uwvm", self.args.uwvm),
            ("cc", self.args.cc), ("wasm-validate", "wasm-validate"),
            ("wasm-objdump", "wasm-objdump"), ("cmp", "cmp"),
        ):
            found = shutil.which(str(supplied))
            if not found:
                raise ValueError(f"required executable is unavailable: {supplied}")
            self.tools[name] = str(Path(found).resolve(strict=True))
        self.report["tools"] = {name: file_record(Path(path)) for name, path in self.tools.items()}
        for name in ("cc", "uwvm", "wasm-validate", "wasm-objdump"):
            self.require_command(f"version-{name}", [self.tools[name], "--version"])
        help_record = self.require_command("uwvm-help-wasm", [self.tools["uwvm"], "--log-color", "disable", "--help", "wasm"])
        help_text = self.output(help_record) + self.output(help_record, "stderr")
        self.features = sorted(set(re.findall(r"--wasm-feature-enable-[a-z0-9-]+", help_text)))
        if not {"--wasm-feature-enable-memory64", "--wasm-feature-enable-multi-memory"}.issubset(self.features):
            raise ValueError("UWVM help does not expose the required memory64/multi-memory flags")
        self.report["uwvm_validation_feature_flags"] = self.features

    def copy_sources(self, destination):
        destination.mkdir(exist_ok=False)
        for name in self.headers + SOURCES:
            source = self.reference / name
            file_record(source)
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            if sha256(source) != sha256(target):
                raise ValueError(f"source copy differs: {name}")

    def compile(self, source, output, label):
        cpp = source.suffix == ".cpp"
        dependency = output.with_suffix(".d")
        argv = [self.tools["cc"], "--target=wasm32-unknown-unknown",
                "-std=c++20" if cpp else "-std=c11", "-O0", "-g", "-ffreestanding", "-nostdlib"]
        if cpp:
            argv += ["-nostdinc++", "-fno-exceptions", "-fno-rtti"]
        argv += ["-MD", "-MF", str(dependency), "-Wl,--no-entry", "-Wl,--export=_start",
                 "-Wl,--export-memory", "-Wl,--allow-undefined", str(source), "-o", str(output)]
        copied_root = source.parents[2]
        inputs = [source, *(copied_root / name for name in self.headers)]
        record = self.command(f"compile-{label}", argv, timeout=60, inputs=inputs, outputs=[output, dependency])
        self.report["compilations"].append({"source": file_record(source), "output": str(output), "command": record["index"], "success": self.succeeded(record)})
        if not self.succeeded(record):
            self.fail("compile", "C/C++ compilation failed", source=str(source), command=record["index"])
            return None
        return output

    def validate(self, path, category):
        identity = file_record(path)
        label = f"{category}-{len(self.report['modules']):04d}-{path.name}"
        wabt = self.command(f"validate-wabt-{label}", [self.tools["wasm-validate"], "--enable-all", str(path)], inputs=[path])
        uwvm = self.command(f"validate-uwvm-{label}", [self.tools["uwvm"], "--log-color", "disable", "--mode", "validation", *self.features, "--run", str(path)], inputs=[path])
        result = {**identity, "category": category, "wabt_command": wabt["index"], "uwvm_command": uwvm["index"],
                  "wabt_valid": self.succeeded(wabt), "uwvm_valid": self.succeeded(uwvm)}
        self.report["modules"].append(result)
        for tool, record in (("WABT", wabt), ("UWVM", uwvm)):
            if not self.succeeded(record):
                self.fail("validation", f"{tool} rejected or could not validate the product; no feature relaxation or skip applied", path=str(path), category=category, command=record["index"])
        if result["wabt_valid"] != result["uwvm_valid"]:
            self.report["validator_disagreements"].append(result.copy())
        return result

    def inspect_compiled(self, path, backend):
        details = self.require_command(f"objdump-x-{path.name}", [self.tools["wasm-objdump"], "-x", str(path)], inputs=[path])
        disassembly = self.require_command(f"objdump-d-{path.name}", [self.tools["wasm-objdump"], "-d", str(path)], inputs=[path])
        allowed = ("wasi_snapshot_preview1", f"uwvm_{backend}_v1")
        imports = []
        for line in self.output(details).splitlines():
            match = re.search(r"<-\s+(\S+)", line)
            if not match:
                continue
            target = match.group(1)
            module = next((name for name in allowed if target.startswith(name + ".")), None)
            if module is None:
                raise ValueError(f"unexpected independent WABT import in {path}: {target}")
            imports.append((module, target[len(module) + 1:]))
        if not imports or {module for module, _ in imports} != set(allowed):
            raise ValueError(f"expected real ROS and WASI imports in {path}, got {imports!r}")
        inspected = self.require_command(f"uwgit-inspect-{path.name}", [self.tools["uwgit"], "inspect", str(path), "--json"], inputs=[path])
        projection = json.loads(self.output(inspected))
        if projection.get("function_analysis", {}).get("available") is not True:
            raise ValueError(f"uwgit function projection unavailable for compiled real example: {path}")
        projected = [(item["module"], item["name"]) for item in projection["module"]["imports"]]
        if Counter(imports) != Counter(projected):
            raise ValueError(f"WABT/uwgit import lists differ for {path}")
        self.report.setdefault("compiled_import_checks", []).append({
            "path": str(path), "imports": [{"module": module, "name": name} for module, name in imports],
            "unexpected_env_imports": False, "matches_uwgit_projection": True,
            "objdump_details_command": details["index"], "objdump_disassembly_command": disassembly["index"],
            "uwgit_inspect_command": inspected["index"],
        })
        return disassembly

    def compile_examples(self):
        source_root = self.build / "c-work-source"
        self.copy_sources(source_root)
        output_root = self.build / "c-compiled"
        output_root.mkdir(exist_ok=False)
        compiled = {}
        disassemblies = {}
        for name in SOURCES:
            relative = Path(name)
            backend = relative.parts[1]
            label = f"{backend}-{relative.name.replace('.', '-')}"
            output = output_root / f"{label}.wasm"
            try:
                product = self.compile(source_root / name, output, label)
                if product is None:
                    continue
                compiled[name] = product
                self.validate(product, "real_c_cpp")
                disassemblies[name] = self.inspect_compiled(product, backend)
            except Exception as error:
                self.fail("compiled_product", error, source=name)
        if len(compiled) != len(SOURCES):
            self.fail("compile", "not all six real C/C++ examples produced outputs", expected=len(SOURCES), actual=len(compiled))
        return compiled, disassemblies

    def threshold_variant(self, compiled, disassemblies):
        source_name = "examples/ros1/talker.c"
        if source_name not in compiled or source_name not in disassemblies:
            raise ValueError("threshold workflow blocked because the baseline ROS1 C talker did not compile/inspect")
        variant_root = self.build / "c-variant-source"
        self.copy_sources(variant_root)
        source = variant_root / source_name
        original = source.read_text()
        if original.count("1000000000ULL") != 1:
            raise ValueError("ROS1 C talker does not contain exactly the expected original delay threshold")
        source.write_text(original.replace("1000000000ULL", "1000000001ULL"))
        target = self.build / "c-compiled" / "ros1-talker-c-threshold-plus-one.wasm"
        product = self.compile(source, target, "ros1-threshold-plus-one")
        if product is None:
            raise ValueError("independent threshold variant did not compile")
        self.validate(product, "real_c_threshold_variant")
        variant_disassembly = self.inspect_compiled(product, "ros1")
        old_text = self.output(disassemblies[source_name])
        new_text = self.output(variant_disassembly)
        constants = lambda text: Counter(int(value) for value in re.findall(r"\bi64\.const\s+(-?\d+)\b", text))
        if constants(old_text) - constants(new_text) != Counter({1000000000: 1}) or constants(new_text) - constants(old_text) != Counter({1000000001: 1}):
            raise ValueError("independent WABT disassembly did not isolate exactly one i64.const threshold change")
        baseline = compiled[source_name]
        difference = self.require_command("uwgit-threshold-diff", [self.tools["uwgit"], "diff", str(baseline), str(product), "--format", "json"], inputs=[baseline, product])
        diff = json.loads(self.output(difference))
        audit = diff["audit"]
        semantic = [change for change in audit["semantic_changes"]
                    if "/operator[" in change["path"] and change.get("old") and change.get("new")
                    and "I64Const" in change["old"]["description"] and "1000000000" in change["old"]["description"]
                    and "I64Const" in change["new"]["description"] and "1000000001" in change["new"]["description"]]
        edits = [edit for edit in audit["edits"] if edit["old_hex"] != edit["new_hex"]
                 and any("/operator[" in context["path"] for context in edit["old_context"] + edit["new_context"])]
        if not diff.get("binary_changed") or not audit.get("changed") or not semantic or not edits:
            raise ValueError("uwgit did not expose the real threshold operator change with physical edit context")
        patch = self.build / "c-compiled" / "threshold.uwgp"
        patch_command = self.require_command("uwgit-threshold-patch", [self.tools["uwgit"], "patch", str(baseline), str(product), "--output", str(patch)], inputs=[baseline, product], outputs=[patch])
        check_command = self.require_command("uwgit-threshold-apply-check", [self.tools["uwgit"], "apply", str(baseline), str(patch), "--check"], inputs=[baseline, patch])
        restored = self.build / "c-compiled" / "threshold-restored.wasm"
        apply_command = self.require_command("uwgit-threshold-apply", [self.tools["uwgit"], "apply", str(baseline), str(patch), "--output", str(restored)], inputs=[baseline, patch], outputs=[restored])
        cmp_command = self.require_command("cmp-threshold-replay", [self.tools["cmp"], "--silent", str(product), str(restored)], inputs=[product, restored])
        if product.read_bytes() != restored.read_bytes() or sha256(product) != sha256(restored):
            raise ValueError("patch replay differs from the separately compiled variant")
        locations = lambda text, value: [line for line in text.splitlines() if re.search(rf"\bi64\.const\s+{value}\b", line)]
        self.report["threshold_variant"] = {
            "source": file_record(source), "baseline": file_record(baseline), "variant": file_record(product),
            "old_constant": 1000000000, "new_constant": 1000000001,
            "old_wabt_locations": locations(old_text, 1000000000), "new_wabt_locations": locations(new_text, 1000000001),
            "operator_semantic_changes": semantic, "physical_operator_edits": edits,
            "diff_command": difference["index"], "patch_command": patch_command["index"],
            "apply_check_command": check_command["index"], "apply_command": apply_command["index"], "cmp_command": cmp_command["index"],
            "patch": file_record(patch), "restored": file_record(restored), "exact_replay": True,
            "runtime_delay_behavior_tested": False,
        }

    def validate_external_products(self):
        examples = self.reference / "examples"
        originals = sorted(examples.rglob("*.wasm"))
        expected_wat = {self.build / (str(path.relative_to(examples)) + ".wasm") for path in examples.rglob("*.wat")}
        found_wat = set(self.build.rglob("*.wat.wasm"))
        self.report["external_product_counts"] = {
            "reference_wasm": len(originals), "reference_wat": len(expected_wat), "generated_wat_products": len(found_wat),
        }
        self.report["expected_external_product_paths"] = {
            "reference_wasm": [str(path) for path in originals],
            "compiled_wat": [str(path) for path in sorted(expected_wat)],
        }
        if not originals or not expected_wat:
            self.fail("external_products", "expected nonempty real reference Wasm and WAT inventories")
        for path in sorted(expected_wat - found_wat):
            self.fail("external_products", "missing WAT compilation product; not skipped", path=str(path))
        for path in sorted(found_wat - expected_wat):
            self.fail("external_products", "unexpected WAT compilation product outside reference inventory", path=str(path))
        for category, paths in (("reference_wasm", originals), ("compiled_wat", sorted(found_wat))):
            for path in paths:
                try:
                    self.validate(path, category)
                except Exception as error:
                    self.fail("external_product", error, path=str(path), category=category)

    def check_environment(self):
        environment = self.report["environment"]
        environment["resource_integrity_preserved"] = False
        try:
            group = Path(environment["cgroup_path"])
            environment["cgroup_after"] = Path("/proc/self/cgroup").read_text()
            environment["boot_id_after"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            environment["limits_after"] = {field: (group / field).read_text().strip() for field in environment["limits_before"]}
            environment["swap_current_after"] = (group / "memory.swap.current").read_text().strip()
            environment["pid_in_admitted_cgroup_after"] = str(os.getpid()) in (group / "cgroup.procs").read_text().splitlines()
            environment["memory_events_after"] = (group / "memory.events").read_text()
            before = {key: int(value) for key, value in (line.split() for line in environment["memory_events_before"].splitlines())}
            after = {key: int(value) for key, value in (line.split() for line in environment["memory_events_after"].splitlines())}
            environment["memory_event_deltas"] = {key: after.get(key, 0) - before.get(key, 0) for key in sorted(before.keys() | after.keys())}
            environment["oom_counters_preserved"] = all(key in before and key in after and before[key] == after[key] for key in ("oom", "oom_kill", "oom_group_kill"))
            environment["resource_integrity_preserved"] = (
                environment["cgroup_after"] == environment["cgroup"]
                and environment["boot_id_after"] == environment["boot_id"]
                and environment["limits_after"] == environment["limits_before"]
                and environment["limits_after"]["memory.swap.max"] == environment["expected_cgroup_swap_max"]
                and environment["pid_in_admitted_cgroup_after"]
                and environment["oom_counters_preserved"]
            )
            if not environment["resource_integrity_preserved"]:
                self.fail("resource_integrity", "cgroup membership, boot, explicit limits or OOM counters changed")
        except Exception as error:
            environment["resource_integrity_error"] = repr(error)
            self.fail("resource_integrity", error)

    def run(self):
        self.report["environment"] = linux_admission()
        self.report["reference_before"] = inventory(self.reference, self.headers)
        try:
            self.prepare_tools()
            compiled, disassemblies = self.compile_examples()
            try:
                self.threshold_variant(compiled, disassemblies)
            except Exception as error:
                self.fail("threshold_variant", error)
            self.validate_external_products()
        finally:
            try:
                self.report["reference_after"] = inventory(self.reference, self.headers)
                self.report["reference_unchanged"] = self.report["reference_before"] == self.report["reference_after"]
                if not self.report["reference_unchanged"]:
                    self.fail("reference_integrity", "reference example/SDK inventory changed during verification")
            finally:
                self.check_environment()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("reference", "build-root", "evidence", "uwgit", "uwvm", "cc"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    harness = None
    report = {"schema_version": 1, "passed": False, "failures": []}
    try:
        harness = Harness(args)
        report = harness.report
        harness.run()
    except Exception as error:
        report["failures"].append({"stage": "harness_exception", "message": str(error), "traceback": traceback.format_exc()})
    report["passed"] = not report["failures"]
    report["command_count"] = len(report.get("commands", []))
    report["validated_module_count"] = len(report.get("modules", []))
    report["validated_module_counts_by_category"] = dict(Counter(item["category"] for item in report.get("modules", [])))
    evidence = require_tmp(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    destination = evidence / "products-report.json"
    temporary = evidence / f".products-report-{os.getpid()}.json"
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(destination)
    print(json.dumps({"passed": report["passed"], "report": str(destination), "commands": report["command_count"], "modules": report["validated_module_count"], "failures": len(report["failures"])}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
