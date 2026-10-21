//! External, ignored acceptance workflows using untouched uwvm2-ros examples.
//! Run only in the existing SSH Linux cgroup. All generated files and complete
//! command evidence are retained below the explicitly supplied /tmp roots.
//! WABT compiles the expected artifacts; no uwgit library is used as an oracle.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wasmparser::{BinaryReader, Operator, Parser, Payload, TypeRef, Validator, WasmFeatures};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static WORKFLOW_LOCK: Mutex<()> = Mutex::new(());

fn text(path: &Path) -> String {
    path.to_str()
        .expect("UTF-8 external fixture path")
        .to_owned()
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
fn digest(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}
fn sha(bytes: &[u8]) -> String {
    digest(&Sha256::digest(bytes))
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

#[derive(Clone, Copy)]
enum Expected {
    Success,
    Failure,
    Code(i32),
}

struct Case {
    _serial: MutexGuard<'static, ()>,
    directory: PathBuf,
    report: PathBuf,
    examples: PathBuf,
    runtime: PathBuf,
    commands: Vec<Value>,
    artifacts: Vec<Value>,
    sources: Vec<Value>,
    assertions: Vec<Value>,
    sequence: usize,
    finished: bool,
}

impl Case {
    fn new(label: &str) -> Self {
        let serial = WORKFLOW_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let required = |name| {
            PathBuf::from(
                std::env::var(name)
                    .unwrap_or_else(|_| panic!("external ignored workflow requires {name}")),
            )
        };
        let root = required("UWGIT_UWVM_WORKFLOW_ROOT");
        let reports = required("UWGIT_UWVM_WORKFLOW_REPORT_DIR");
        assert!(
            root.is_absolute()
                && root.starts_with("/tmp")
                && !root
                    .components()
                    .any(|part| part == std::path::Component::ParentDir)
        );
        assert!(
            reports.is_absolute()
                && reports.starts_with("/tmp")
                && !reports
                    .components()
                    .any(|part| part == std::path::Component::ParentDir)
        );
        let supplied = required("UWGIT_UWVM_EXAMPLES_ROOT");
        let examples = if supplied.join("examples").is_dir() {
            supplied.join("examples")
        } else {
            supplied
        };
        let runtime = required("UWGIT_UWVM_BIN");
        let token = format!(
            "{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&reports).unwrap();
        let directory = root.join(&token);
        std::fs::create_dir(&directory).unwrap();
        let mut case = Self {
            _serial: serial,
            directory,
            report: reports.join(format!("{token}.json")),
            examples,
            runtime,
            commands: Vec::new(),
            artifacts: Vec::new(),
            sources: Vec::new(),
            assertions: Vec::new(),
            sequence: 0,
            finished: false,
        };
        case.persist("RUNNING");
        case.run(
            "wabt-version",
            Path::new("/usr/bin/wat2wasm"),
            &args(&["--version"]),
            Expected::Success,
            20,
        );
        let runtime = case.runtime.clone();
        let fingerprint = case.run(
            "runtime-sha256",
            Path::new("/usr/bin/sha256sum"),
            &[text(&runtime)],
            Expected::Success,
            20,
        );
        let observed = String::from_utf8(fingerprint.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        case.artifacts.push(json!({"role":"frozen existing runtime binary; external sha256sum","path":runtime,"sha256":observed,"length":std::fs::metadata(&case.runtime).unwrap().len()}));
        case
    }

    fn persist(&self, status: &str) {
        let evidence = json!({
            "schema_version":1, "status":status, "workspace":self.directory,
            "examples_root":self.examples, "runtime":self.runtime,
            "scope":"Fresh WABT compilation and original-byte uwgit workflows, with explicitly recorded pure preload runtime probes. No ROS network execution or source-repository modification.",
            "sources":self.sources,"artifacts":self.artifacts,"commands":self.commands,"assertions":self.assertions,
        });
        std::fs::write(&self.report, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn source(&mut self, relative: &str) -> String {
        let path = self.examples.join(relative);
        let bytes = std::fs::read(&path).expect("read original example snapshot");
        self.sources
            .push(json!({"path":path,"sha256_before":sha(&bytes),"length":bytes.len()}));
        String::from_utf8(bytes).unwrap()
    }

    fn run(
        &mut self,
        label: &str,
        program: &Path,
        arguments: &[String],
        expected: Expected,
        seconds: u64,
    ) -> Output {
        self.sequence += 1;
        let prefix = format!("{:04}-{label}", self.sequence);
        let stdout = self.path(&format!("{prefix}.stdout"));
        let stderr = self.path(&format!("{prefix}.stderr"));
        let record = self.path(&format!("{prefix}.command.json"));
        let started = now();
        let expected_status = match expected {
            Expected::Success => "success".to_owned(),
            Expected::Failure => "nonzero exit or SIGILL=4 (excluding timeout/kill)".to_owned(),
            Expected::Code(code) => format!("exit {code}"),
        };
        let before = json!({"label":label,"program":program,"argv":arguments,"cwd":self.directory,"timeout_seconds":seconds,"expected":expected_status,"started_unix_ms":started,"status":"RUNNING","signal":null,"stdout":stdout,"stderr":stderr});
        std::fs::write(&record, serde_json::to_vec_pretty(&before).unwrap()).unwrap();
        self.commands.push(before);
        self.persist("RUNNING");
        let timer = Instant::now();
        let result = Command::new("/usr/bin/timeout")
            .args(["--signal=TERM", "--kill-after=3s", &format!("{seconds}s")])
            .arg(program)
            .args(arguments)
            .current_dir(&self.directory)
            .env("TMPDIR", &self.directory)
            .env("LC_ALL", "C")
            .output();
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                let failure = json!({"label":label,"program":program,"argv":arguments,"status":"SPAWN_FAILED","signal":null,"error":error.to_string(),"started_unix_ms":started,"elapsed_ms":timer.elapsed().as_millis()});
                std::fs::write(&record, serde_json::to_vec_pretty(&failure).unwrap()).unwrap();
                *self.commands.last_mut().unwrap() = failure;
                self.persist("FAILED");
                panic!("cannot launch {program:?}: {error}");
            }
        };
        std::fs::write(&stdout, &output.stdout).unwrap();
        std::fs::write(&stderr, &output.stderr).unwrap();
        let mut completed = self.commands.last().unwrap().clone();
        completed["status"] = json!("COMPLETED");
        completed["returncode"] = json!(output.status.code());
        completed["signal"] = json!(exit_signal(&output.status));
        completed["elapsed_ms"] = json!(timer.elapsed().as_millis());
        completed["stdout_sha256"] = json!(sha(&output.stdout));
        completed["stderr_sha256"] = json!(sha(&output.stderr));
        std::fs::write(&record, serde_json::to_vec_pretty(&completed).unwrap()).unwrap();
        *self.commands.last_mut().unwrap() = completed;
        self.persist("RUNNING");
        assert!(
            !matches!(output.status.code(), Some(124 | 137 | 143))
                && !matches!(exit_signal(&output.status), Some(9 | 15)),
            "{label}: timeout or forced termination is never an expected negative"
        );
        let accepted = match expected {
            Expected::Success => output.status.success(),
            Expected::Failure => match exit_signal(&output.status) {
                Some(4) => true,
                None => output.status.code().is_some_and(|code| code != 0),
                _ => false,
            },
            Expected::Code(code) => output.status.code() == Some(code),
        };
        assert!(
            accepted,
            "{label} {program:?} {arguments:?}: status={}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn cli(&mut self, label: &str, arguments: &[String]) -> Output {
        self.run(
            label,
            Path::new(env!("CARGO_BIN_EXE_wasm-git")),
            arguments,
            Expected::Success,
            20,
        )
    }

    fn cli_json(&mut self, label: &str, arguments: &[String]) -> Value {
        let output = self.cli(label, arguments);
        serde_json::from_slice(&output.stdout).expect("CLI JSON result")
    }

    fn save(&mut self, label: &str, value: Value) {
        let path = self.path(&format!("{label}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        self.assertions
            .push(json!({"label":label,"evidence":path,"result":value}));
        self.persist("RUNNING");
    }

    fn artifact(&mut self, role: &str, path: &Path) {
        let bytes = std::fs::read(path).unwrap();
        let output = self.run(
            "external-sha256",
            Path::new("/usr/bin/sha256sum"),
            &[text(path)],
            Expected::Success,
            20,
        );
        let observed = String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(observed, sha(&bytes));
        self.artifacts
            .push(json!({"role":role,"path":path,"sha256":observed,"length":bytes.len()}));
        self.persist("RUNNING");
    }

    fn compile(&mut self, label: &str, source: &str) -> PathBuf {
        let source_path = self.path(&format!("{label}.wat"));
        let binary = self.path(&format!("{label}.wasm"));
        std::fs::write(&source_path, source).unwrap();
        self.run(
            "wabt-compile",
            Path::new("/usr/bin/wat2wasm"),
            &args(&[
                "--enable-all",
                "--debug-names",
                &text(&source_path),
                "-o",
                &text(&binary),
            ]),
            Expected::Success,
            20,
        );
        self.run(
            "wabt-validate",
            Path::new("/usr/bin/wasm-validate"),
            &args(&["--enable-all", &text(&binary)]),
            Expected::Success,
            20,
        );
        self.run(
            "wabt-disassemble",
            Path::new("/usr/bin/wasm-objdump"),
            &args(&["-d", "-x", &text(&binary)]),
            Expected::Success,
            20,
        );
        let bytes = std::fs::read(&binary).unwrap();
        Validator::new_with_features(WasmFeatures::all())
            .validate_all(&bytes)
            .expect("separate wasmparser validation");
        self.artifact("actual source compiled by WABT", &source_path);
        self.artifact("fresh independently compiled expected Wasm", &binary);
        self.save(&format!("{label}.independent-parser"), oracle(&bytes));
        binary
    }

    fn runtime(
        &mut self,
        label: &str,
        library: &Path,
        binding: &str,
        main: &Path,
        expected: Expected,
    ) -> Output {
        let command = args(&[
            "--runtime-int",
            "--runtime-compile-threads",
            "1",
            "--wasip1-global-disable",
            "--wasip1-global-set-argv0",
            "global-entry",
            "--wasip1-single-create",
            binding,
            "--wasip1-single-enable",
            binding,
            "--wasip1-single-set-argv0",
            binding,
            "pre",
            "--wasm-preload-library",
            &text(library),
            binding,
            "--run",
            &text(main),
            "hello",
            "world",
        ]);
        let runtime = self.runtime.clone();
        self.run(label, &runtime, &command, expected, 30)
    }

    fn finish(mut self) {
        for source in &mut self.sources {
            let path = PathBuf::from(source["path"].as_str().unwrap());
            let after = sha(&std::fs::read(path).unwrap());
            source["sha256_after"] = json!(after);
            assert_eq!(
                source["sha256_before"], source["sha256_after"],
                "original example snapshot changed"
            );
        }
        self.finished = true;
        self.persist("PASS");
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        if !self.finished {
            // Keep evidence even after an assertion failure; never delete work.
            self.persist(if std::thread::panicking() {
                "FAILED"
            } else {
                "INCOMPLETE"
            });
        }
    }
}

fn replaced(source: &str, from: &str, to: &str) -> String {
    assert_eq!(
        source.matches(from).count(),
        1,
        "source pin: unique mutation anchor {from:?}"
    );
    source.replacen(from, to, 1)
}

fn leb(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = value as u8 & 127;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return bytes;
        }
    }
}

fn sections(bytes: &[u8]) -> Vec<(u8, std::ops::Range<usize>, std::ops::Range<usize>)> {
    assert_eq!(&bytes[..8], b"\0asm\x01\0\0\0");
    let mut reader = BinaryReader::new(&bytes[8..], 8);
    let mut result = Vec::new();
    while !reader.eof() {
        let start = reader.original_position();
        let id = reader.read_u8().unwrap();
        let length = reader.read_var_u32().unwrap() as usize;
        let payload = reader.original_position();
        reader.read_bytes(length).unwrap();
        result.push((
            id,
            start..reader.original_position(),
            payload..reader.original_position(),
        ));
    }
    result
}

fn oracle(bytes: &[u8]) -> Value {
    let mut imports = Vec::new();
    let mut exports = BTreeMap::new();
    let mut functions = Vec::new();
    let mut names = BTreeMap::new();
    let mut imported_functions = 0u32;
    let mut start = None;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.expect("independent parser accepts fresh valid artifact") {
            Payload::ImportSection(reader) => {
                for group in reader {
                    for item in group.unwrap().into_iter() {
                        let (_, import) = item.unwrap();
                        if matches!(import.ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
                            imported_functions += 1;
                        }
                        imports.push(json!({"module":import.module,"name":import.name,"type":format!("{:?}",import.ty)}));
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.unwrap();
                    exports.insert(
                        export.name.to_owned(),
                        json!({"index":export.index,"kind":format!("{:?}",export.kind)}),
                    );
                }
            }
            Payload::StartSection { func, .. } => start = Some(func),
            Payload::CodeSectionEntry(body) => {
                let mut reader = body.get_operators_reader().unwrap();
                let mut ops = Vec::new();
                while !reader.eof() {
                    let start = reader.original_position();
                    let operator = reader.read().unwrap();
                    let mut op = json!({"start":start,"end":reader.original_position(),"description":format!("{operator:?}")});
                    match operator {
                        Operator::Call { function_index } => {
                            op["code"] = json!("Call");
                            op["function_index"] = json!(function_index);
                        }
                        Operator::ReturnCall { function_index } => {
                            op["code"] = json!("ReturnCall");
                            op["function_index"] = json!(function_index);
                        }
                        Operator::I32Const { value } => {
                            op["code"] = json!("I32Const");
                            op["value"] = json!(value);
                        }
                        _ => {}
                    }
                    ops.push(op);
                }
                functions.push(json!({"global_index":imported_functions as usize+functions.len(),"body_start":body.range().start,"body_end":body.range().end,"operators":ops}));
            }
            Payload::CustomSection(custom) if custom.name() == "name" => {
                let mut reader = BinaryReader::new(custom.data(), custom.data_offset());
                while !reader.eof() {
                    let id = reader.read_u8().unwrap();
                    let length = reader.read_var_u32().unwrap() as usize;
                    let offset = reader.original_position();
                    let data = reader.read_bytes(length).unwrap();
                    if id == 1 {
                        let mut map = BinaryReader::new(data, offset);
                        for _ in 0..map.read_var_u32().unwrap() {
                            let index = map.read_var_u32().unwrap();
                            names.insert(index.to_string(), map.read_string().unwrap().to_owned());
                        }
                        assert!(map.eof());
                    }
                }
            }
            _ => {}
        }
    }
    json!({"raw_sha256":sha(bytes),"length":bytes.len(),"imports":imports,"exports":exports,"start":start,"functions":functions,"function_names":names})
}

fn instructions(oracle: &Value) -> Vec<&Value> {
    oracle["functions"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|function| function["operators"].as_array().unwrap())
        .collect()
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                output.insert(relative, None);
                visit(root, &path, output);
            } else {
                output.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

fn store_evidence(state: &BTreeMap<PathBuf, Option<Vec<u8>>>) -> Vec<Value> {
    state
        .iter()
        .map(|(path, bytes)| match bytes {
            Some(bytes) => json!({"path":path,"directory":false,"length":bytes.len(),"sha256":sha(bytes),"hex":digest(bytes)}),
            None => json!({"path":path,"directory":true}),
        })
        .collect()
}

fn unchanged_store(
    case: &mut Case,
    label: &str,
    repo: &Path,
    before: &BTreeMap<PathBuf, Option<Vec<u8>>>,
) {
    let after = snapshot(&repo.join(".uwgit"));
    assert_eq!(
        &after, before,
        "{label}: no refs, objects, locks, or directories may change"
    );
    case.save(label, json!({"repository":repo,"full_bytes_equal":true,"before":store_evidence(before),"after":store_evidence(&after)}));
}

fn decode_hex(value: &Value) -> Vec<u8> {
    let value = value.as_str().unwrap();
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn replay_patch_independently(patch: &Value, old: &[u8], new: &[u8]) {
    assert_eq!(patch["format"], "uwgit-byte-patch-v1");
    assert_eq!(patch["old_sha256"], sha(old));
    assert_eq!(patch["new_sha256"], sha(new));
    assert_eq!(patch["old_len"], old.len());
    assert_eq!(patch["new_len"], new.len());
    let mut cursor = 0usize;
    let mut output = Vec::new();
    for edit in patch["edits"].as_array().unwrap() {
        let start = edit["old_span"]["start"].as_u64().unwrap() as usize;
        let end = edit["old_span"]["end"].as_u64().unwrap() as usize;
        assert!(cursor <= start && start <= end && end <= old.len());
        assert_eq!(&old[start..end], decode_hex(&edit["old_hex"]));
        output.extend_from_slice(&old[cursor..start]);
        assert_eq!(
            output.len(),
            edit["new_span"]["start"].as_u64().unwrap() as usize
        );
        output.extend(decode_hex(&edit["new_hex"]));
        assert_eq!(
            output.len(),
            edit["new_span"]["end"].as_u64().unwrap() as usize
        );
        cursor = end;
    }
    output.extend_from_slice(&old[cursor..]);
    assert_eq!(output, new);
}

fn commit(case: &mut Case, repo: &Path, input: &Path, message: &str) -> String {
    let output = case.cli(
        "commit",
        &args(&["commit", &text(repo), &text(input), "-m", message]),
    );
    let id = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_owned();
    assert_eq!(id.len(), 64);
    id
}

fn object(repo: &Path, id: &str, kind: u8) -> Vec<u8> {
    let bytes = std::fs::read(repo.join(".uwgit/objects").join(id)).unwrap();
    assert_eq!(sha(&bytes), id);
    assert_eq!(&bytes[..8], b"UWGO\0\0\0\x01");
    assert_eq!(bytes[8], kind);
    let length = u64::from_be_bytes(bytes[9..17].try_into().unwrap());
    assert_eq!(length, (bytes.len() - 17) as u64);
    bytes[17..].to_vec()
}

fn verify_commit(repo: &Path, id: &str, parents: &[String], expected: &[u8]) -> Value {
    let commit: Value = serde_json::from_slice(&object(repo, id, 2)).unwrap();
    assert_eq!(commit["parents"], json!(parents));
    let blob = commit["wasm"].as_str().unwrap();
    assert_eq!(object(repo, blob, 1), expected);
    json!({"commit":id,"parents":parents,"wasm_object":blob,"raw_sha256":sha(expected),"typed_object_envelopes_independently_verified":true})
}

fn transfer(case: &mut Case, label: &str, repo: &Path, revision: &str, expected: &[u8]) {
    let clone = case.path(&format!("{label}.clone"));
    case.cli("clone", &args(&["clone", &text(repo), &text(&clone)]));
    case.cli_json("clone-fsck", &args(&["fsck", &text(&clone)]));
    let checked = case.path(&format!("{label}.clone.wasm"));
    case.cli(
        "clone-checkout",
        &args(&["checkout", &text(&clone), revision, &text(&checked)]),
    );
    assert_eq!(std::fs::read(&checked).unwrap(), expected);
    case.artifact("clone preserved expected original bytes", &checked);
    let bundle = case.path(&format!("{label}.bundle"));
    case.cli("bundle", &args(&["bundle", &text(repo), &text(&bundle)]));
    case.artifact("offline bundle", &bundle);
    let receiver = case.path(&format!("{label}.receiver"));
    case.cli("receiver-init", &args(&["init", &text(&receiver)]));
    case.cli(
        "unbundle",
        &args(&["unbundle", &text(&receiver), &text(&bundle), "incoming"]),
    );
    case.cli_json("receiver-fsck", &args(&["fsck", &text(&receiver)]));
    let recovered = case.path(&format!("{label}.receiver.wasm"));
    case.cli(
        "receiver-checkout",
        &args(&["checkout", &text(&receiver), revision, &text(&recovered)]),
    );
    assert_eq!(std::fs::read(&recovered).unwrap(), expected);
    case.artifact("unbundled expected original bytes", &recovered);
}

fn verify_trace(report: &Value, revisions: &BTreeMap<String, Vec<u8>>) {
    assert_eq!(report["repository_verified"], true);
    assert_eq!(report["trace"]["identity_unproven"], true);
    assert_eq!(report["trace"]["complete"], true);
    for edge in report["trace"]["edges"].as_array().unwrap() {
        let old = &revisions[edge["parent"].as_str().unwrap()];
        let new = &revisions[edge["child"].as_str().unwrap()];
        for mapping in edge["gap_mappings"].as_array().unwrap() {
            let range = |value: &Value| {
                value["span"]["start"].as_u64().unwrap() as usize
                    ..value["span"]["end"].as_u64().unwrap() as usize
            };
            assert_eq!(
                old[range(&mapping["parent"])],
                new[range(&mapping["child"])]
            );
        }
        for event in edge["events"].as_array().unwrap() {
            let edit = &event["edit"];
            let range = |side: &str| {
                edit[side]["start"].as_u64().unwrap() as usize
                    ..edit[side]["end"].as_u64().unwrap() as usize
            };
            assert_eq!(&old[range("old_span")], decode_hex(&edit["old_hex"]));
            assert_eq!(&new[range("new_span")], decode_hex(&edit["new_hex"]));
        }
    }
}

fn lifecycle(case: &mut Case, label: &str, old_file: &Path, new_file: &Path) {
    let old = std::fs::read(old_file).unwrap();
    let new = std::fs::read(new_file).unwrap();
    let diff = case.cli_json(
        "diff",
        &args(&["diff", &text(old_file), &text(new_file), "--format", "json"]),
    );
    assert_eq!(diff["audit"]["changed"], old != new);
    case.save(&format!("{label}.diff"), diff);
    let patch = case.path(&format!("{label}.uwgp"));
    case.cli_json(
        "patch",
        &args(&[
            "patch",
            &text(old_file),
            &text(new_file),
            "--output",
            &text(&patch),
        ]),
    );
    let metadata: Value = serde_json::from_slice(&std::fs::read(&patch).unwrap()).unwrap();
    replay_patch_independently(&metadata, &old, &new);
    case.artifact("offline exact byte patch", &patch);
    case.cli_json(
        "apply-check",
        &args(&["apply", &text(old_file), &text(&patch), "--check"]),
    );
    let replay = case.path(&format!("{label}.replayed.wasm"));
    case.cli_json(
        "apply",
        &args(&[
            "apply",
            &text(old_file),
            &text(&patch),
            "--output",
            &text(&replay),
        ]),
    );
    assert_eq!(std::fs::read(&replay).unwrap(), new);
    case.artifact("CLI patch replay equals independent target", &replay);
    let repo = case.path(&format!("{label}.repo"));
    case.cli("init", &args(&["init", &text(&repo)]));
    let base = commit(case, &repo, old_file, "independent real source baseline");
    let tip = commit(case, &repo, new_file, "independent real source change");
    let shown = case.cli_json("show", &args(&["show", &text(&repo), &tip]));
    assert_eq!(shown["id"], tip);
    assert_eq!(shown["parents"], json!([base.clone()]));
    case.cli_json("fsck", &args(&["fsck", &text(&repo)]));
    let verified = verify_commit(&repo, &tip, std::slice::from_ref(&base), &new);
    case.save(&format!("{label}.typed-objects"), verified);
    let range = format!("0:{}", new.len());
    let before = snapshot(&repo.join(".uwgit"));
    let history = case.cli_json(
        "trace",
        &args(&["trace", &text(&repo), &tip, "--range", &range]),
    );
    verify_trace(
        &history,
        &BTreeMap::from([(base, old), (tip.clone(), new.clone())]),
    );
    assert_eq!(snapshot(&repo.join(".uwgit")), before);
    case.save(&format!("{label}.trace"), history);
    transfer(case, label, &repo, &tip, &new);
}

fn require_trap(output: &Output) {
    let signal = exit_signal(&output.status);
    let nonzero_exit = signal.is_none()
        && output
            .status
            .code()
            .is_some_and(|code| code != 0 && !matches!(code, 124 | 137 | 143));
    assert!(
        signal == Some(4) || nonzero_exit,
        "expected SIGILL=4 or an ordinary nonzero exit for guest assertion trap: {}",
        output.status
    );
    let diagnostics = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(
        diagnostics.contains("trap") || diagnostics.contains("unreachable"),
        "expected actual guest assertion trap: {diagnostics}"
    );
}

fn require_link_failure(output: &Output, binding: &str) {
    let diagnostics = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    assert!(
        diagnostics.contains(binding),
        "missing changed binding in link diagnostic: {diagnostics}"
    );
    assert!(
        diagnostics.contains("import")
            || diagnostics.contains("export")
            || diagnostics.contains("link")
            || diagnostics.contains("module")
            || diagnostics.contains("function")
            || diagnostics.contains("not found"),
        "expected initialization/link diagnostic: {diagnostics}"
    );
}

#[test]
#[ignore = "requires staged real uwvm2-ros examples, WABT, existing UWVM LLVM runtime, and SSH Linux cgroup"]
fn real_preload_constant_instruction_and_runtime_workflow() {
    let mut case = Case::new("preload-constant");
    let main = case.source("0004.preload_wasm/main.wat");
    let library = case.source("0004.preload_wasm/lib.wat");
    let changed = replaced(&main, "i32.const 3", "i32.const 4");
    let base = case.compile("main.base", &main);
    let variant = case.compile("main.const4", &changed);
    let lib = case.compile("library", &library);
    let old = oracle(&std::fs::read(&base).unwrap());
    let new = oracle(&std::fs::read(&variant).unwrap());
    assert_eq!(old["imports"], new["imports"]);
    assert_eq!(old["start"], new["start"]);
    assert_eq!(
        instructions(&old)
            .iter()
            .filter(|op| op["code"] == "I32Const" && op["value"] == 3)
            .count(),
        1
    );
    assert_eq!(
        instructions(&new)
            .iter()
            .filter(|op| op["code"] == "I32Const" && op["value"] == 4)
            .count(),
        1
    );
    case.runtime(
        "runtime-base-must-pass",
        &lib,
        "lib.test",
        &base,
        Expected::Success,
    );
    require_trap(&case.runtime(
        "runtime-const4-must-trap",
        &lib,
        "lib.test",
        &variant,
        Expected::Failure,
    ));
    lifecycle(&mut case, "const", &base, &variant);
    case.finish();
}

#[test]
#[ignore = "requires staged real uwvm2-ros examples, WABT, existing UWVM LLVM runtime, and SSH Linux cgroup"]
fn real_preload_import_export_rebinding_workflow() {
    let mut case = Case::new("preload-bindings");
    let main = case.source("0004.preload_wasm/main.wat");
    let library = case.source("0004.preload_wasm/lib.wat");
    assert_eq!(main.matches("\"lib.test\"").count(), 2);
    let renamed_imports = main.replace("\"lib.test\"", "\"lib.other\"");
    let renamed_export = replaced(&library, "\"get_argc\"", "\"get_argc_v2\"");
    let renamed_caller = replaced(&main, "\"get_argc\"", "\"get_argc_v2\"");
    let base = case.compile("main.base", &main);
    let imports = case.compile("main.lib-other", &renamed_imports);
    let lib = case.compile("lib.base", &library);
    let export = case.compile("lib.renamed-export", &renamed_export);
    let caller = case.compile("main.renamed-export", &renamed_caller);
    let parsed = oracle(&std::fs::read(&imports).unwrap());
    assert!(parsed["imports"]
        .as_array()
        .unwrap()
        .iter()
        .all(|import| import["module"] == "lib.other"));
    let original = oracle(&std::fs::read(&lib).unwrap());
    let changed = oracle(&std::fs::read(&export).unwrap());
    let function_bytes = |path: &Path| {
        let bytes = std::fs::read(path).unwrap();
        sections(&bytes)
            .into_iter()
            .filter(|(id, _, _)| *id == 10)
            .map(|(_, range, _)| bytes[range].to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(function_bytes(&lib), function_bytes(&export));
    assert_eq!(
        original["exports"]["get_argc"]["index"],
        changed["exports"]["get_argc_v2"]["index"]
    );
    case.runtime(
        "runtime-original-bindings",
        &lib,
        "lib.test",
        &base,
        Expected::Success,
    );
    require_link_failure(
        &case.runtime(
            "runtime-wrong-module-binding",
            &lib,
            "lib.test",
            &imports,
            Expected::Failure,
        ),
        "lib.other",
    );
    case.runtime(
        "runtime-matched-module-binding",
        &lib,
        "lib.other",
        &imports,
        Expected::Success,
    );
    require_link_failure(
        &case.runtime(
            "runtime-missing-old-export",
            &export,
            "lib.test",
            &base,
            Expected::Failure,
        ),
        "get_argc",
    );
    case.runtime(
        "runtime-matched-renamed-export",
        &export,
        "lib.test",
        &caller,
        Expected::Success,
    );
    lifecycle(&mut case, "import", &base, &imports);
    lifecycle(&mut case, "export", &lib, &export);
    case.finish();
}

#[test]
#[ignore = "requires staged real uwvm2-ros examples, WABT, existing UWVM LLVM runtime, and SSH Linux cgroup"]
fn real_preload_index_shift_is_explicit_and_context_merge_refuses_writes() {
    let mut case = Case::new("preload-index-shift");
    let main = case.source("0004.preload_wasm/main.wat");
    let library = case.source("0004.preload_wasm/lib.wat");
    let shifted = replaced(
        &main,
        "(module",
        "(module\n  (import \"lib.test\" \"get_argc\" (func $unused (result i32)))",
    );
    let other = replaced(&main, "i32.const 3", "i32.const 4");
    let base = case.compile("main.base", &main);
    let shift = case.compile("main.index-shift", &shifted);
    let concurrent = case.compile("main.concurrent", &other);
    let lib = case.compile("library", &library);
    let old = oracle(&std::fs::read(&base).unwrap());
    let new = oracle(&std::fs::read(&shift).unwrap());
    assert_eq!(
        new["imports"].as_array().unwrap().len(),
        old["imports"].as_array().unwrap().len() + 1
    );
    assert_eq!(
        new["start"].as_u64().unwrap(),
        old["start"].as_u64().unwrap() + 1
    );
    for (a, b) in old["functions"]
        .as_array()
        .unwrap()
        .iter()
        .zip(new["functions"].as_array().unwrap())
    {
        assert_eq!(
            b["global_index"].as_u64().unwrap(),
            a["global_index"].as_u64().unwrap() + 1
        );
        let a: Vec<_> = a["operators"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|op| op["code"] == "Call")
            .collect();
        let b: Vec<_> = b["operators"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|op| op["code"] == "Call")
            .collect();
        assert_eq!(a.len(), b.len());
        for (a, b) in a.into_iter().zip(b) {
            assert_eq!(
                b["function_index"].as_u64().unwrap(),
                a["function_index"].as_u64().unwrap() + 1
            );
        }
    }
    case.runtime(
        "runtime-index-base",
        &lib,
        "lib.test",
        &base,
        Expected::Success,
    );
    case.runtime(
        "runtime-index-shifted",
        &lib,
        "lib.test",
        &shift,
        Expected::Success,
    );
    lifecycle(&mut case, "shift", &base, &shift);
    let repo = case.path("conflict.repo");
    case.cli("conflict-init", &args(&["init", &text(&repo)]));
    let base_id = commit(&mut case, &repo, &base, "base");
    case.cli(
        "branch",
        &args(&["branch", &text(&repo), "right", &base_id]),
    );
    let left = commit(&mut case, &repo, &shift, "import index shift");
    case.cli("switch-right", &args(&["switch", &text(&repo), "right"]));
    let right = commit(&mut case, &repo, &concurrent, "concurrent const edit");
    case.cli("switch-main", &args(&["switch", &text(&repo), "main"]));
    let before = snapshot(&repo.join(".uwgit"));
    let output = case.run(
        "merge-must-conflict",
        Path::new(env!("CARGO_BIN_EXE_wasm-git")),
        &args(&[
            "merge",
            &text(&repo),
            &right,
            "-m",
            "refuse index rebinding",
        ]),
        Expected::Code(2),
        20,
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "conflict");
    assert_eq!(report["old_head"], left);
    assert!(report["report"]["conflicts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|conflict| conflict["reason"].as_str().unwrap().contains("context")));
    assert_eq!(snapshot(&repo.join(".uwgit")), before);
    case.save("context-conflict-no-writes", report);
    case.finish();
}

#[test]
#[ignore = "requires staged real uwvm2-ros examples, WABT, existing UWVM LLVM runtime, and SSH Linux cgroup"]
fn real_name_only_opaque_custom_and_unknown_opcode_preserve_every_byte() {
    let mut case = Case::new("preload-name-opaque");
    let main = case.source("0004.preload_wasm/main.wat");
    let library = case.source("0004.preload_wasm/lib.wat");
    assert!(main.matches("$assert_eq").count() > 1);
    let rename = main.replace("$assert_eq", "$check_equal");
    let base = case.compile("main.base", &main);
    let renamed = case.compile("main.renamed", &rename);
    let lib = case.compile("library", &library);
    let old = std::fs::read(&base).unwrap();
    let new = std::fs::read(&renamed).unwrap();
    let standard = |bytes: &[u8]| {
        sections(bytes)
            .into_iter()
            .filter(|(id, _, _)| *id != 0)
            .map(|(_, range, _)| bytes[range].to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(standard(&old), standard(&new));
    assert_ne!(sha(&old), sha(&new));
    let a = oracle(&old);
    let b = oracle(&new);
    assert!(a["function_names"]
        .as_object()
        .unwrap()
        .values()
        .any(|name| name == "assert_eq"));
    assert!(b["function_names"]
        .as_object()
        .unwrap()
        .values()
        .any(|name| name == "check_equal"));
    case.runtime(
        "runtime-name-baseline",
        &lib,
        "lib.test",
        &base,
        Expected::Success,
    );
    case.runtime(
        "runtime-name-only",
        &lib,
        "lib.test",
        &renamed,
        Expected::Success,
    );
    lifecycle(&mut case, "names", &base, &renamed);
    let mut malformed = old[..8].to_vec();
    let mut changed = 0;
    for (id, range, payload) in sections(&old) {
        if id == 0 {
            let mut reader = BinaryReader::new(&old[payload.clone()], payload.start);
            if reader.read_string().unwrap() == "name" {
                let body = b"\x04name\x01\x02\x80\x00";
                malformed.push(0);
                malformed.extend(leb(body.len()));
                malformed.extend(body);
                changed += 1;
                continue;
            }
        }
        malformed.extend_from_slice(&old[range]);
    }
    assert_eq!(changed, 1);
    assert_eq!(standard(&old), standard(&malformed));
    let opaque = case.path("main.noncanonical-name.wasm");
    std::fs::write(&opaque, &malformed).unwrap();
    case.artifact(
        "derived noncanonical name count: 80 00, fixed convention intentionally rejected",
        &opaque,
    );
    let inspect = case.cli_json(
        "inspect-malformed-name",
        &args(&["inspect", &text(&opaque), "--json"]),
    );
    assert!(inspect["audit"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|section| section["id"] == 0 && section["status"] == "opaque"));
    assert!(inspect["audit"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "custom_opaque"));
    case.save("malformed-name-opaque", inspect);
    lifecycle(&mut case, "opaque", &base, &opaque);
    let first = instructions(&a)
        .into_iter()
        .find(|op| op["code"] == "I32Const")
        .unwrap()["start"]
        .as_u64()
        .unwrap() as usize;
    let mut unknown = old.clone();
    unknown[first] = 0xff;
    let unknown_path = case.path("main.unknown-opcode.wasm");
    std::fs::write(&unknown_path, &unknown).unwrap();
    let rejection = Parser::new(0)
        .parse_all(&unknown)
        .find_map(|payload| {
            if let Payload::CodeSectionEntry(body) = payload.unwrap() {
                body.get_operators_reader()
                    .unwrap()
                    .into_iter_with_offsets()
                    .find_map(|op| op.err())
            } else {
                None
            }
        })
        .expect("independent parser rejects deliberately unknown opcode");
    assert_eq!(rejection.offset(), first);
    case.save(
        "unknown-opcode-independent-rejection",
        json!({"offset":first,"message":rejection.to_string(),"runtime_executed":false}),
    );
    case.run(
        "wabt-reject-unknown",
        Path::new("/usr/bin/wasm-validate"),
        &args(&["--enable-all", &text(&unknown_path)]),
        Expected::Failure,
        20,
    );
    let inspect = case.cli_json(
        "inspect-unknown",
        &args(&["inspect", &text(&unknown_path), "--json"]),
    );
    assert!(inspect["audit"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["code"] == "unknown_operator" && issue["offset"] == first));
    case.save("unknown-opcode-audit", inspect);
    lifecycle(&mut case, "unknown", &base, &unknown_path);
    case.artifact(
        "unknown instruction derivation; never executed",
        &unknown_path,
    );
    case.finish();
}

#[test]
#[ignore = "requires staged real uwvm2-ros examples, WABT, existing UWVM LLVM runtime, and SSH Linux cgroup"]
fn real_library_merge_matches_independently_compiled_combined_source() {
    let mut case = Case::new("preload-real-merge");
    let library = case.source("0004.preload_wasm/lib.wat");
    let main = case.source("0004.preload_wasm/main.wat");
    let left = replaced(
        &library,
        "i32.const 0\n    i32.load)",
        "i32.const 0\n    i32.load\n    i32.const 1\n    i32.add)",
    );
    let right = replaced(
        &library,
        "i32.const 4\n    i32.load)",
        "i32.const 4\n    i32.load\n    i32.const 2\n    i32.add)",
    );
    let combined = replaced(
        &left,
        "i32.const 4\n    i32.load)",
        "i32.const 4\n    i32.load\n    i32.const 2\n    i32.add)",
    );
    let expected_main = replaced(
        &replaced(&main, "i32.const 3", "i32.const 4"),
        "i32.const 16",
        "i32.const 18",
    );
    let base = case.compile("lib.base", &library);
    let left_file = case.compile("lib.left", &left);
    let right_file = case.compile("lib.right", &right);
    let expected = case.compile("lib.expected-combined", &combined);
    let caller = case.compile("main.expected-4-and-18", &expected_main);
    let repo = case.path("merge.repo");
    case.cli("init", &args(&["init", &text(&repo)]));
    let base_id = commit(&mut case, &repo, &base, "real library base");
    case.cli(
        "branch-right",
        &args(&["branch", &text(&repo), "right", &base_id]),
    );
    let left_id = commit(&mut case, &repo, &left_file, "argc plus one");
    case.cli("switch-right", &args(&["switch", &text(&repo), "right"]));
    let right_id = commit(&mut case, &repo, &right_file, "argv bytes plus two");
    case.cli("switch-main", &args(&["switch", &text(&repo), "main"]));
    let report = case.cli_json(
        "merge",
        &args(&[
            "merge",
            &text(&repo),
            &right_id,
            "-m",
            "independently compiled expected combination",
        ]),
    );
    assert_eq!(report["status"], "merged");
    let merged_id = report["commit"].as_str().unwrap().to_owned();
    case.save("merge-result", report);
    let merged = case.path("lib.actual-merged.wasm");
    case.cli(
        "checkout-merge",
        &args(&["checkout", &text(&repo), &merged_id, &text(&merged)]),
    );
    let expected_bytes = std::fs::read(&expected).unwrap();
    assert_eq!(std::fs::read(&merged).unwrap(), expected_bytes);
    case.artifact(
        "actual merge exactly equals fresh combined-source compilation",
        &merged,
    );
    let evidence = verify_commit(
        &repo,
        &merged_id,
        &[left_id.clone(), right_id.clone()],
        &expected_bytes,
    );
    case.save("independent-two-parent-object-verification", evidence);
    case.runtime(
        "runtime-expected-combined",
        &expected,
        "lib.test",
        &caller,
        Expected::Success,
    );
    case.runtime(
        "runtime-actual-merged",
        &merged,
        "lib.test",
        &caller,
        Expected::Success,
    );
    require_trap(&case.runtime(
        "runtime-baseline-cannot-satisfy-4-18",
        &base,
        "lib.test",
        &caller,
        Expected::Failure,
    ));
    let parsed = oracle(&expected_bytes);
    let first = instructions(&parsed)
        .into_iter()
        .find(|op| op["code"] == "I32Const" && op["value"] == 1)
        .unwrap();
    let selection = format!(
        "{}:{}",
        first["start"].as_u64().unwrap(),
        first["end"].as_u64().unwrap()
    );
    let history = case.cli_json(
        "trace-all-merge-parents",
        &args(&["trace", &text(&repo), &merged_id, "--range", &selection]),
    );
    verify_trace(
        &history,
        &BTreeMap::from([
            (base_id, std::fs::read(&base).unwrap()),
            (left_id.clone(), std::fs::read(&left_file).unwrap()),
            (right_id.clone(), std::fs::read(&right_file).unwrap()),
            (merged_id.clone(), expected_bytes.clone()),
        ]),
    );
    let incoming: Vec<_> = history["trace"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|edge| edge["child"] == merged_id)
        .map(|edge| edge["parent"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(incoming, vec![left_id, right_id]);
    case.save("merge-all-parent-trace", history);
    case.cli_json("merged-fsck", &args(&["fsck", &text(&repo)]));
    transfer(&mut case, "merged", &repo, &merged_id, &expected_bytes);
    lifecycle(&mut case, "combined-byte-patch", &base, &merged);
    case.finish();
}

#[test]
#[ignore = "requires staged real uwvm2-ros examples and independent WABT; does not run ROS or guest modules"]
fn real_ros_proxy_call_and_tail_call_pair_have_independent_opcode_oracles() {
    let mut case = Case::new("real-proxy-tail-pair");
    let caller = case.source("ros_dual/proxy_caller.wat");
    let tail = case.source("ros_dual/proxy_tail.wat");
    assert_eq!(
        replaced(&caller, "(call $probe)", "(return_call $probe)"),
        tail
    );
    let normal = case.compile("proxy-caller", &caller);
    let tail = case.compile("proxy-tail", &tail);
    let a = oracle(&std::fs::read(&normal).unwrap());
    let b = oracle(&std::fs::read(&tail).unwrap());
    assert_eq!(a["imports"], b["imports"]);
    assert_eq!(a["exports"], b["exports"]);
    assert_eq!(
        instructions(&a)
            .iter()
            .filter(|op| op["code"] == "Call" && op["function_index"] == 0)
            .count(),
        1
    );
    assert_eq!(
        instructions(&b)
            .iter()
            .filter(|op| op["code"] == "ReturnCall" && op["function_index"] == 0)
            .count(),
        1
    );
    case.save("tailcall-scope",json!({"real_existing_source_pair":true,"expected_call_target":0,"old_opcode":"Call","new_opcode":"ReturnCall","runtime_executed":false,"ros_network_executed":false}));
    lifecycle(&mut case, "tailcall", &normal, &tail);
    case.finish();
}

#[test]
#[ignore = "requires staged real uwvm2-ros examples, WABT, existing UWVM LLVM runtime, and SSH Linux cgroup"]
fn real_independent_peers_resolve_overlap_and_return_verified_two_parent_history() {
    let mut case = Case::new("preload-multi-peer-resolution");
    let main_source = case.source("0004.preload_wasm/main.wat");
    let library_source = case.source("0004.preload_wasm/lib.wat");
    let left_source = replaced(&main_source, "i32.const 3", "i32.const 4");
    let right_source = replaced(&main_source, "i32.const 3", "i32.const 5");
    let resolved_source = replaced(&main_source, "i32.const 3", "i32.const 6");
    let resolved_library_source = replaced(
        &library_source,
        "i32.const 0\n    i32.load)",
        "i32.const 0\n    i32.load\n    i32.const 3\n    i32.add)",
    );
    let base_file = case.compile("peer.main.base", &main_source);
    let left_file = case.compile("peer.main.left-const4", &left_source);
    let right_file = case.compile("peer.main.right-const5", &right_source);
    let resolved_file = case.compile("peer.main.resolved-const6", &resolved_source);
    let provider = case.compile("peer.lib.argc-plus3", &resolved_library_source);
    let base_bytes = std::fs::read(&base_file).unwrap();
    let left_bytes = std::fs::read(&left_file).unwrap();
    let right_bytes = std::fs::read(&right_file).unwrap();
    let resolved_bytes = std::fs::read(&resolved_file).unwrap();
    let parsed = [
        oracle(&base_bytes),
        oracle(&left_bytes),
        oracle(&right_bytes),
        oracle(&resolved_bytes),
    ];
    let operators: Vec<Value> = parsed
        .iter()
        .zip([3, 4, 5, 6])
        .map(|(module, value)| {
            let matching: Vec<_> = instructions(module)
                .into_iter()
                .filter(|op| op["code"] == "I32Const" && op["value"] == value)
                .collect();
            assert_eq!(matching.len(), 1);
            matching[0].clone()
        })
        .collect();
    for module in &parsed[1..] {
        assert_eq!(module["imports"], parsed[0]["imports"]);
        assert_eq!(module["start"], parsed[0]["start"]);
        assert_eq!(
            module["functions"].as_array().unwrap().len(),
            parsed[0]["functions"].as_array().unwrap().len()
        );
    }
    case.save("peer-independent-instruction-oracles", json!({
        "mutation":"same real $start argc assertion: base=3, peer_a=4, peer_b=5, manual_resolution=6",
        "base":operators[0],"peer_a":operators[1],"peer_b":operators[2],"resolved":operators[3],
        "expected_runtime_argc":6,"provider_operation":"original args_sizes_get argc 3 + i32.const 3 + i32.add",
    }));

    let origin = case.path("peer.origin");
    let peer_a = case.path("peer.a");
    let peer_b = case.path("peer.b");
    let peer_c = case.path("peer.c");
    case.cli("peer-origin-init", &args(&["init", &text(&origin)]));
    let base_id = commit(
        &mut case,
        &origin,
        &base_file,
        "shared real preload baseline",
    );
    let origin_state = snapshot(&origin.join(".uwgit"));
    case.cli(
        "peer-clone-a",
        &args(&["clone", &text(&origin), &text(&peer_a)]),
    );
    case.cli(
        "peer-clone-b",
        &args(&["clone", &text(&origin), &text(&peer_b)]),
    );
    let left_id = commit(
        &mut case,
        &peer_a,
        &left_file,
        "peer A independent argc assertion 4",
    );
    let left_state = snapshot(&peer_a.join(".uwgit"));
    let right_id = commit(
        &mut case,
        &peer_b,
        &right_file,
        "peer B independent argc assertion 5",
    );
    assert_ne!(left_id, right_id);
    unchanged_store(
        &mut case,
        "peer-a-independent-of-b-commit",
        &peer_a,
        &left_state,
    );
    unchanged_store(
        &mut case,
        "origin-independent-of-peer-commits",
        &origin,
        &origin_state,
    );
    let peer_b_state = snapshot(&peer_b.join(".uwgit"));
    let peer_bundle = case.path("peer.b-to-a.bundle");
    case.cli(
        "peer-b-bundle",
        &args(&["bundle", &text(&peer_b), &text(&peer_bundle)]),
    );
    case.artifact(
        "independent peer B history for offline exchange",
        &peer_bundle,
    );

    let before_non_ff = snapshot(&peer_a.join(".uwgit"));
    assert!(!peer_a.join(".uwgit/objects").join(&right_id).exists());
    let refused = case.run(
        "peer-non-fast-forward-refused",
        Path::new(env!("CARGO_BIN_EXE_wasm-git")),
        &args(&["unbundle", &text(&peer_a), &text(&peer_bundle), "main"]),
        Expected::Code(1),
        20,
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("non-fast-forward"));
    unchanged_store(
        &mut case,
        "peer-non-fast-forward-store-unchanged",
        &peer_a,
        &before_non_ff,
    );
    let corrupt_bundle = case.path("peer.b-corrupt.bundle");
    let mut corrupt = std::fs::read(&peer_bundle).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&corrupt_bundle, corrupt).unwrap();
    case.artifact(
        "deliberate final-byte bundle corruption; must never publish",
        &corrupt_bundle,
    );
    let before_corrupt = snapshot(&peer_a.join(".uwgit"));
    let refused = case.run(
        "peer-corrupt-bundle-refused",
        Path::new(env!("CARGO_BIN_EXE_wasm-git")),
        &args(&[
            "unbundle",
            &text(&peer_a),
            &text(&corrupt_bundle),
            "corrupt-must-not-exist",
        ]),
        Expected::Code(1),
        20,
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("hash mismatch"));
    unchanged_store(
        &mut case,
        "peer-corrupt-bundle-store-unchanged",
        &peer_a,
        &before_corrupt,
    );
    case.cli(
        "peer-import-incoming",
        &args(&["unbundle", &text(&peer_a), &text(&peer_bundle), "incoming"]),
    );
    let incoming = case.cli_json(
        "peer-show-incoming",
        &args(&["show", &text(&peer_a), "incoming"]),
    );
    assert_eq!(incoming["id"], right_id);
    let current = case.cli_json(
        "peer-show-local-head",
        &args(&["show", &text(&peer_a), "HEAD"]),
    );
    assert_eq!(current["id"], left_id);
    case.save(
        "peer-import-bindings",
        json!({"local_head":current,"incoming":incoming}),
    );

    let before_conflict = snapshot(&peer_a.join(".uwgit"));
    let conflict_output = case.run(
        "peer-overlap-must-conflict",
        Path::new(env!("CARGO_BIN_EXE_wasm-git")),
        &args(&[
            "merge",
            &text(&peer_a),
            &right_id,
            "-m",
            "independent peer overlap requires review",
        ]),
        Expected::Code(2),
        20,
    );
    let conflict: Value = serde_json::from_slice(&conflict_output.stdout).unwrap();
    assert_eq!(conflict["status"], "conflict");
    assert_eq!(conflict["base"], base_id);
    assert_eq!(conflict["old_head"], left_id);
    assert_eq!(conflict["target"], right_id);
    assert!(conflict["commit"].is_null());
    let conflicts = conflict["report"]["conflicts"].as_array().unwrap();
    assert_eq!(conflicts.len(), 1);
    assert!(conflicts[0]["path"]
        .as_str()
        .unwrap()
        .contains("/operator["));
    for ((side, bytes), operator) in [
        ("base", &base_bytes),
        ("ours", &left_bytes),
        ("theirs", &right_bytes),
    ]
    .into_iter()
    .zip(&operators)
    {
        let evidence = &conflicts[0][side];
        assert_eq!(evidence["span"]["start"], operator["start"]);
        assert_eq!(evidence["span"]["end"], operator["end"]);
        let start = operator["start"].as_u64().unwrap() as usize;
        let end = operator["end"].as_u64().unwrap() as usize;
        assert_eq!(decode_hex(&evidence["hex"]), bytes[start..end]);
    }
    case.save("peer-full-physical-instruction-conflict", conflict);
    unchanged_store(
        &mut case,
        "peer-conflict-store-unchanged",
        &peer_a,
        &before_conflict,
    );

    let resolved = case.cli_json(
        "peer-manual-resolution",
        &args(&[
            "merge",
            &text(&peer_a),
            &right_id,
            "-m",
            "explicit real-source resolution argc 6",
            "--resolved",
            &text(&resolved_file),
            "--expect-head",
            &left_id,
        ]),
    );
    assert_eq!(resolved["status"], "merged_resolved");
    assert_eq!(resolved["old_head"], left_id);
    assert_eq!(resolved["target"], right_id);
    assert_eq!(resolved["base"], base_id);
    assert_eq!(resolved["manual_resolution"]["supplied_bytes"], true);
    assert_eq!(
        resolved["manual_resolution"]["audit_validation"],
        "valid_with_all_known_features"
    );
    let resolved_id = resolved["commit"].as_str().unwrap().to_owned();
    assert_ne!(resolved_id, left_id);
    assert_ne!(resolved_id, right_id);
    case.save("peer-manual-resolution-result", resolved);
    let parents = [left_id.clone(), right_id.clone()];
    let evidence = verify_commit(&peer_a, &resolved_id, &parents, &resolved_bytes);
    case.save("peer-manual-two-parent-raw-object-verification", evidence);
    let before_stale = snapshot(&peer_a.join(".uwgit"));
    let stale = case.run(
        "peer-stale-resolution-refused",
        Path::new(env!("CARGO_BIN_EXE_wasm-git")),
        &args(&[
            "merge",
            &text(&peer_a),
            &right_id,
            "-m",
            "stale reviewed head must not publish",
            "--resolved",
            &text(&resolved_file),
            "--expect-head",
            &left_id,
        ]),
        Expected::Code(1),
        20,
    );
    assert!(String::from_utf8_lossy(&stale.stderr).contains("HEAD changed since resolution"));
    unchanged_store(
        &mut case,
        "peer-stale-resolution-store-unchanged",
        &peer_a,
        &before_stale,
    );
    let shown = case.cli_json(
        "peer-show-resolved-head",
        &args(&["show", &text(&peer_a), "HEAD"]),
    );
    assert_eq!(shown["id"], resolved_id);
    assert_eq!(shown["parents"], json!(parents));
    let checked = case.path("peer.a.resolved-checkout.wasm");
    case.cli(
        "peer-checkout-resolved",
        &args(&["checkout", &text(&peer_a), &resolved_id, &text(&checked)]),
    );
    assert_eq!(std::fs::read(&checked).unwrap(), resolved_bytes);
    case.artifact(
        "manual resolution checkout equals independently compiled source",
        &checked,
    );
    let checked_fsck = case.cli_json("peer-resolved-fsck", &args(&["fsck", &text(&peer_a)]));
    assert_eq!(checked_fsck["commits"], 4);
    assert_eq!(checked_fsck["wasm_blobs"], 4);
    case.save("peer-resolved-fsck-report", checked_fsck);

    let resolved_bundle = case.path("peer.a-resolved-to-c.bundle");
    case.cli(
        "peer-resolved-bundle",
        &args(&["bundle", &text(&peer_a), &text(&resolved_bundle)]),
    );
    case.artifact(
        "resolved original bytes and complete double-parent ancestry for third peer",
        &resolved_bundle,
    );
    case.cli("peer-c-init", &args(&["init", &text(&peer_c)]));
    case.cli(
        "peer-c-import-reviewed",
        &args(&[
            "unbundle",
            &text(&peer_c),
            &text(&resolved_bundle),
            "reviewed",
        ]),
    );
    let received = case.cli_json(
        "peer-c-show-reviewed",
        &args(&["show", &text(&peer_c), "reviewed"]),
    );
    assert_eq!(received["id"], resolved_id);
    assert_eq!(received["parents"], json!(parents));
    let third_fsck = case.cli_json("peer-c-fsck", &args(&["fsck", &text(&peer_c)]));
    assert_eq!(third_fsck["commits"], 4);
    assert_eq!(third_fsck["wasm_blobs"], 4);
    let third_checkout = case.path("peer.c.received-resolution.wasm");
    case.cli(
        "peer-c-checkout-reviewed",
        &args(&[
            "checkout",
            &text(&peer_c),
            "reviewed",
            &text(&third_checkout),
        ]),
    );
    assert_eq!(std::fs::read(&third_checkout).unwrap(), resolved_bytes);
    case.artifact(
        "third-peer received manual resolution exact original bytes",
        &third_checkout,
    );
    let ancestry = vec![
        verify_commit(&peer_c, &base_id, &[], &base_bytes),
        verify_commit(
            &peer_c,
            &left_id,
            std::slice::from_ref(&base_id),
            &left_bytes,
        ),
        verify_commit(
            &peer_c,
            &right_id,
            std::slice::from_ref(&base_id),
            &right_bytes,
        ),
        verify_commit(&peer_c, &resolved_id, &parents, &resolved_bytes),
    ];
    case.save(
        "peer-c-independent-complete-parent-chain",
        json!({"commits":ancestry,"fsck":third_fsck}),
    );
    let query = format!(
        "{}:{}",
        operators[3]["start"].as_u64().unwrap(),
        operators[3]["end"].as_u64().unwrap()
    );
    let before_trace = snapshot(&peer_c.join(".uwgit"));
    let traced = case.cli_json(
        "peer-c-trace-all-reviewed-parents",
        &args(&["trace", &text(&peer_c), "reviewed", "--range", &query]),
    );
    verify_trace(
        &traced,
        &BTreeMap::from([
            (base_id.clone(), base_bytes),
            (left_id.clone(), left_bytes),
            (right_id.clone(), right_bytes),
            (resolved_id.clone(), resolved_bytes.clone()),
        ]),
    );
    assert_eq!(traced["trace"]["tip"], resolved_id);
    let edges = traced["trace"]["edges"].as_array().unwrap();
    let incoming: Vec<_> = edges
        .iter()
        .filter(|edge| edge["child"] == resolved_id)
        .map(|edge| edge["parent"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(incoming, parents);
    assert_eq!(edges.len(), 4);
    assert_eq!(
        traced["trace"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|node| node["commit"] == base_id)
            .count(),
        1
    );
    case.save("peer-c-all-parent-physical-trace", traced);
    unchanged_store(
        &mut case,
        "peer-c-trace-store-unchanged",
        &peer_c,
        &before_trace,
    );
    unchanged_store(
        &mut case,
        "peer-b-unchanged-by-resolution-and-return",
        &peer_b,
        &peer_b_state,
    );
    unchanged_store(
        &mut case,
        "origin-unchanged-by-resolution-and-return",
        &origin,
        &origin_state,
    );
    case.runtime(
        "runtime-peer-independent-resolved-source",
        &provider,
        "lib.test",
        &resolved_file,
        Expected::Success,
    );
    case.runtime(
        "runtime-peer-third-checkout-same-result",
        &provider,
        "lib.test",
        &third_checkout,
        Expected::Success,
    );
    case.finish();
}

// Separate from the product's resolver: expand real function signatures and
// interpret each numeric call through this module's own import/declaration
// tables. Source-controlled variants establish this test's correspondence;
// these descriptors do not assert general historical function identity.
fn reference_oracle(bytes: &[u8]) -> Value {
    let mut signatures = Vec::new();
    let mut imports: Vec<Value> = Vec::new();
    let mut declarations = Vec::new();
    let mut calls = Vec::new();
    let mut defined_index = 0usize;
    let mut start = None;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.expect("independent reference oracle framing") {
            Payload::TypeSection(reader) => {
                for group in reader {
                    for (_, ty) in group.unwrap().into_types_and_offsets() {
                        let wasmparser::CompositeInnerType::Func(function) =
                            ty.composite_type.inner
                        else {
                            panic!("this real preload fixture must contain only ordinary function signatures");
                        };
                        signatures.push(json!({
                            "params":function.params().iter().map(|ty|format!("{ty:?}")).collect::<Vec<_>>(),
                            "results":function.results().iter().map(|ty|format!("{ty:?}")).collect::<Vec<_>>(),
                        }));
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for group in reader {
                    for item in group.unwrap().into_iter() {
                        let (_, import) = item.unwrap();
                        let (type_index, exact) = match import.ty {
                            TypeRef::Func(index) => (index, false),
                            TypeRef::FuncExact(index) => (index, true),
                            _ => panic!("the chosen real preload main has only function imports"),
                        };
                        imports.push(json!({
                            "function_index":imports.len(),"module":import.module,"name":import.name,
                            "type_index":type_index,"signature":signatures[type_index as usize],"exact":exact,
                        }));
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for type_index in reader {
                    declarations.push(type_index.unwrap());
                }
            }
            Payload::StartSection { func, .. } => start = Some(func),
            Payload::CodeSectionEntry(body) => {
                let mut reader = body.get_operators_reader().unwrap();
                let mut ordinal = 0usize;
                while !reader.eof() {
                    let offset = reader.original_position();
                    let op = reader.read().unwrap();
                    if let Operator::Call { function_index } = op {
                        let target_index = function_index as usize;
                        let target = if target_index < imports.len() {
                            let import = &imports[target_index];
                            json!({"kind":"import","module":import["module"],"name":import["name"],"signature":import["signature"],"exact":import["exact"]})
                        } else {
                            let target_defined = target_index - imports.len();
                            let type_index = declarations[target_defined];
                            json!({"kind":"defined","defined_index":target_defined,"signature":signatures[type_index as usize]})
                        };
                        calls.push(json!({
                            "defined_function_index":defined_index,"global_function_index":imports.len()+defined_index,
                            "operator_ordinal":ordinal,"span":{"start":offset,"end":reader.original_position()},
                            "opcode":"Call","operand_index":function_index,"resolved_target":target,
                        }));
                    }
                    ordinal += 1;
                }
                defined_index += 1;
            }
            _ => {}
        }
    }
    assert_eq!(defined_index, declarations.len());
    let section_hashes: Vec<_> = sections(bytes).into_iter().filter(|(id,_,_)|*id!=0).map(|(id,range,_)| {
        json!({"id":id,"raw_span":{"start":range.start,"end":range.end},"sha256":sha(&bytes[range])})
    }).collect();
    json!({"raw_sha256":sha(bytes),"signatures":signatures,"imports":imports,"declarations":declarations,"start":start,"call_sites":calls,"standard_sections":section_hashes})
}

// This workflow selects import bytes for physical history. In particular, it
// does not ask trace to turn unchanged numeric call bytes into semantic origin.
fn reference_roundtrip(case: &mut Case, label: &str, old_file: &Path, new_file: &Path) -> Value {
    let old = std::fs::read(old_file).unwrap();
    let new = std::fs::read(new_file).unwrap();
    let difference = case.cli_json(
        "bindings-diff",
        &args(&["diff", &text(old_file), &text(new_file), "--format", "json"]),
    );
    assert_eq!(difference["audit"]["changed"], true);
    let patch = case.path(&format!("{label}.uwgp"));
    case.cli_json(
        "bindings-patch",
        &args(&[
            "patch",
            &text(old_file),
            &text(new_file),
            "--output",
            &text(&patch),
        ]),
    );
    let patch_json: Value = serde_json::from_slice(&std::fs::read(&patch).unwrap()).unwrap();
    replay_patch_independently(&patch_json, &old, &new);
    case.artifact("reference-binding raw offline patch", &patch);
    case.cli_json(
        "bindings-apply-check",
        &args(&["apply", &text(old_file), &text(&patch), "--check"]),
    );
    let replayed = case.path(&format!("{label}.replayed.wasm"));
    case.cli_json(
        "bindings-apply",
        &args(&[
            "apply",
            &text(old_file),
            &text(&patch),
            "--output",
            &text(&replayed),
        ]),
    );
    assert_eq!(std::fs::read(&replayed).unwrap(), new);
    case.artifact(
        "reference-binding patch replay equals independent WABT target",
        &replayed,
    );
    let repo = case.path(&format!("{label}.repo"));
    case.cli("bindings-init", &args(&["init", &text(&repo)]));
    let base_id = commit(case, &repo, old_file, "independent numeric call baseline");
    let tip_id = commit(case, &repo, new_file, "independent import context variant");
    let verified = verify_commit(&repo, &tip_id, std::slice::from_ref(&base_id), &new);
    case.save(&format!("{label}.typed-objects"), verified);
    case.cli_json("bindings-fsck", &args(&["fsck", &text(&repo)]));
    let import_range = sections(&new)
        .into_iter()
        .find(|(id, _, _)| *id == 2)
        .unwrap()
        .1;
    let query = format!("{}:{}", import_range.start, import_range.end);
    let before = snapshot(&repo.join(".uwgit"));
    let traced = case.cli_json(
        "bindings-trace-physical-import-only",
        &args(&["trace", &text(&repo), &tip_id, "--range", &query]),
    );
    assert_eq!(
        traced["trace"]["query"],
        json!({"start":import_range.start,"end":import_range.end})
    );
    verify_trace(
        &traced,
        &BTreeMap::from([(base_id, old), (tip_id.clone(), new.clone())]),
    );
    assert!(traced["trace"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| !edge["events"].as_array().unwrap().is_empty()));
    unchanged_store(case, &format!("{label}.trace-read-only"), &repo, &before);
    case.save(&format!("{label}.physical-import-history"),json!({"meaning":"Only selected physical import bytes; unchanged call-byte gaps are not a semantic dependency trace","report":traced}));
    transfer(case, label, &repo, &tip_id, &new);
    difference
}

#[test]
#[ignore = "requires staged real uwvm2-ros examples, independent WABT, existing UWVM LLVM runtime, and SSH Linux cgroup"]
fn real_preload_call_indices_and_actual_import_targets_are_distinct_oracles() {
    let mut case = Case::new("preload-reference-bindings");
    let source = case.source("0004.preload_wasm/main.wat");
    let library_source = case.source("0004.preload_wasm/lib.wat");
    let numeric = replaced(
        &replaced(&source, "call $get_argc\n", "call 0\n"),
        "call $get_argv_buf_size\n",
        "call 1\n",
    );
    let shifted = replaced(
        &source,
        "(module",
        "(module\n  (import \"lib.test\" \"get_argc\" (func $unused (result i32)))",
    );
    let argc_import = "  (import \"lib.test\" \"get_argc\" (func $get_argc (result i32)))";
    let argv_import =
        "  (import \"lib.test\" \"get_argv_buf_size\" (func $get_argv_buf_size (result i32)))";
    let rebound = replaced(
        &numeric,
        &format!("{argc_import}\n{argv_import}"),
        &format!("{argv_import}\n{argc_import}"),
    );
    let confirmed = replaced(
        &replaced(
            &rebound,
            "call 0\n    i32.const 3",
            "call 0\n    i32.const 16",
        ),
        "call 1\n    i32.const 16",
        "call 1\n    i32.const 3",
    );
    let base = case.compile("bindings.main.numeric-baseline", &numeric);
    let relocated = case.compile("bindings.main.index-relocated-same-target", &shifted);
    let changed = case.compile("bindings.main.same-index-rebound", &rebound);
    let accepted = case.compile("bindings.main.rebound-confirmed-16-3", &confirmed);
    let library = case.compile("bindings.library", &library_source);
    let bytes = [
        std::fs::read(&base).unwrap(),
        std::fs::read(&relocated).unwrap(),
        std::fs::read(&changed).unwrap(),
        std::fs::read(&accepted).unwrap(),
    ];
    let oracle: Vec<_> = bytes.iter().map(|bytes| reference_oracle(bytes)).collect();
    for module in &oracle {
        for import in module["imports"].as_array().unwrap() {
            assert_eq!(import["signature"], json!({"params":[],"results":["I32"]}));
        }
    }
    let calls = |module: &Value| {
        module["call_sites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|call| call["operand_index"].as_u64().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(calls(&oracle[0]), vec![0, 2, 1, 2]);
    assert_eq!(calls(&oracle[1]), vec![1, 3, 2, 3]);
    assert_eq!(calls(&oracle[2]), vec![0, 2, 1, 2]);
    assert_eq!(calls(&oracle[3]), vec![0, 2, 1, 2]);
    assert_eq!(
        oracle[1]["start"].as_u64().unwrap(),
        oracle[0]["start"].as_u64().unwrap() + 1
    );
    assert_eq!(oracle[2]["start"], oracle[0]["start"]);
    let base_calls = oracle[0]["call_sites"].as_array().unwrap();
    for (before, after) in base_calls
        .iter()
        .zip(oracle[1]["call_sites"].as_array().unwrap())
    {
        assert_eq!(
            after["operand_index"].as_u64().unwrap(),
            before["operand_index"].as_u64().unwrap() + 1
        );
        assert_eq!(before["resolved_target"], after["resolved_target"]);
    }
    let rebound_calls = oracle[2]["call_sites"].as_array().unwrap();
    assert_eq!(base_calls[0]["resolved_target"]["name"], "get_argc");
    assert_eq!(
        rebound_calls[0]["resolved_target"]["name"],
        "get_argv_buf_size"
    );
    assert_eq!(
        base_calls[2]["resolved_target"]["name"],
        "get_argv_buf_size"
    );
    assert_eq!(rebound_calls[2]["resolved_target"]["name"], "get_argc");
    let code = |bytes: &[u8]| {
        sections(bytes)
            .into_iter()
            .filter(|(id, _, _)| *id == 10)
            .map(|(_, range, _)| bytes[range].to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        code(&bytes[0]),
        code(&bytes[2]),
        "same numeric calls despite changed import targets"
    );
    assert_ne!(
        code(&bytes[0]),
        code(&bytes[1]),
        "index relocation changes code encoding"
    );
    assert_ne!(
        code(&bytes[2]),
        code(&bytes[3]),
        "counterfactual checks must encode 16/3 instead of 3/16"
    );
    case.save("reference-independent-expanded-bindings",json!({
        "base":oracle[0],"index_relocated_same_target":oracle[1],"same_index_different_target":oracle[2],"rebound_results_confirmed":oracle[3],
        "base_and_rebound_raw_code_identical":true,
        "identity_scope":"Controlled source variants establish this oracle; no general historical identity claim. Duplicate unused imports are not asserted to have unique historical counterparts.",
    }));
    case.runtime(
        "runtime-bindings-baseline-pass",
        &library,
        "lib.test",
        &base,
        Expected::Success,
    );
    case.runtime(
        "runtime-bindings-relocated-same-target",
        &library,
        "lib.test",
        &relocated,
        Expected::Success,
    );
    require_trap(&case.runtime(
        "runtime-bindings-rebound-wrong-expectations",
        &library,
        "lib.test",
        &changed,
        Expected::Failure,
    ));
    case.runtime(
        "runtime-bindings-rebound-values-confirmed",
        &library,
        "lib.test",
        &accepted,
        Expected::Success,
    );
    let relocation_diff = reference_roundtrip(&mut case, "reference-shift", &base, &relocated);
    let mut relocation_bindings = Vec::new();
    for change in relocation_diff["changes"].as_array().unwrap() {
        if let Some(bindings) = change["function"]["call_bindings"].as_array() {
            relocation_bindings.extend(bindings);
        }
    }
    if let Some(notes) = relocation_diff["call_binding_notes"].as_array() {
        for note in notes {
            relocation_bindings.extend(note["call_bindings"].as_array().unwrap());
        }
    }
    assert!(
        !relocation_bindings
            .iter()
            .any(|binding| binding["relation"] == "different_target"),
        "a duplicate unused import must not invent an external target change"
    );
    assert!(relocation_bindings.iter().any(|binding| {
        binding["relation"] == "same_target_index_relocated"
            && binding["target_changed"] == false
            && binding["old"]["target"]["import"]["name"] == "get_argv_buf_size"
    }));
    assert!(relocation_bindings.iter().any(|binding| {
        binding["relation"] == "same_target_index_relocated"
            && binding["target_changed"] == false
            && binding["old"]["target"]["kind"] == "defined"
    }));
    case.save("reference-index-relocation-product-diff", relocation_diff);
    let difference = reference_roundtrip(&mut case, "reference-rebound", &base, &changed);
    assert_eq!(difference["function_analysis"]["available"], true);
    let callers: Vec<_> = difference["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["kind"] == "function_changed")
        .map(|change| &change["function"])
        .filter(|function| {
            function["call_bindings"]
                .as_array()
                .is_some_and(|bindings| {
                    bindings
                        .iter()
                        .any(|binding| binding["relation"] == "different_target")
                })
        })
        .collect();
    assert_eq!(
        callers.len(),
        1,
        "one real unchanged-byte caller must be reported as changed"
    );
    let caller = callers[0];
    assert_eq!(caller["direct_calls_changed"], false);
    assert!(
        caller["operators"].as_array().unwrap().is_empty(),
        "raw Call operators did not change"
    );
    let binding_changes: Vec<_> = caller["call_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|binding| binding["relation"] == "different_target")
        .collect();
    assert_eq!(binding_changes.len(), 2);
    for (operand, old_name, new_name) in [
        (0, "get_argc", "get_argv_buf_size"),
        (1, "get_argv_buf_size", "get_argc"),
    ] {
        let binding = binding_changes
            .iter()
            .find(|binding| binding["old"]["function_index"] == operand)
            .unwrap();
        assert_eq!(binding["pairing"], "opcode_alignment");
        assert_eq!(binding["target_changed"], true);
        assert_eq!(binding["identity_unproven"], true);
        let independent_old = base_calls
            .iter()
            .find(|call| call["operand_index"] == operand)
            .unwrap();
        let independent_new = rebound_calls
            .iter()
            .find(|call| call["operand_index"] == operand)
            .unwrap();
        for (side, name, independent) in [
            ("old", old_name, independent_old),
            ("new", new_name, independent_new),
        ] {
            assert_eq!(binding[side]["function_index"], operand);
            assert_eq!(binding[side]["opcode"], "Call");
            assert_eq!(
                binding[side]["operator_index"],
                independent["operator_ordinal"]
            );
            assert_eq!(binding[side]["offset"], independent["span"]["start"]);
            assert_eq!(binding[side]["target"]["kind"], "imported");
            assert_eq!(binding[side]["target"]["import"]["module"], "lib.test");
            assert_eq!(binding[side]["target"]["import"]["name"], name);
        }
        assert_eq!(
            binding["old"]["target"]["type_id"],
            binding["new"]["target"]["type_id"]
        );
        assert!(!binding["old"]["target"]["type_id"]
            .as_str()
            .unwrap()
            .is_empty());
    }
    assert!(difference["summary"]["functions_changed"].as_u64().unwrap() >= 1);
    case.save(
        "reference-rebound-product-reports-changed-caller",
        difference,
    );
    case.finish();
}
