//! Fixed custom metadata names stay in values, never in selectable paths.
use std::collections::{BTreeMap, BTreeSet};
use wasm_git::{
    audit::{self, AuditModule, ByteEdit, Region, Span},
    patch::BytePatch,
    standard::Standard,
    trace::{self, HistoryCommit, HistorySnapshot, TraceLimits},
};

const HEADER: &[u8] = b"\0asm\x01\0\0\0";
const PROFILES: [Standard; 4] = [
    Standard::Core1,
    Standard::Core2,
    Standard::Core3,
    Standard::AllKnown,
];

#[derive(Clone, Copy)]
struct CustomFrame {
    name: Span,
    data: Span,
}

fn unsigned(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let byte = value as u8 & 0x7f;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}

fn string(value: &str, output: &mut Vec<u8>) {
    unsigned(value.len(), output);
    output.extend_from_slice(value.as_bytes());
}

fn custom(output: &mut Vec<u8>, name: &str, data: &[u8]) -> CustomFrame {
    let mut encoded_name = Vec::new();
    string(name, &mut encoded_name);
    output.push(0);
    unsigned(encoded_name.len() + data.len(), output);
    let start = output.len();
    output.extend_from_slice(&encoded_name);
    let data_start = output.len();
    output.extend_from_slice(data);
    CustomFrame {
        name: Span {
            start,
            end: data_start,
        },
        data: Span {
            start: data_start,
            end: output.len(),
        },
    }
}

fn regions(module: &AuditModule) -> Vec<&Region> {
    fn visit<'a>(entries: &'a [Region], output: &mut Vec<&'a Region>) {
        for entry in entries {
            output.push(entry);
            visit(&entry.children, output);
        }
    }
    let mut output = Vec::new();
    for section in &module.sections {
        visit(&section.regions, &mut output);
    }
    output
}

fn region<'a>(module: &'a AuditModule, path: &str) -> &'a Region {
    regions(module)
        .into_iter()
        .find(|entry| entry.path == path)
        .unwrap_or_else(|| panic!("missing custom region {path}"))
}

fn paths_are_bounded(module: &AuditModule) {
    let mut paths = BTreeSet::new();
    for path in module
        .sections
        .iter()
        .map(|section| section.path.as_str())
        .chain(regions(module).into_iter().map(|entry| entry.path.as_str()))
    {
        assert!(path.is_ascii());
        assert!(!path.contains('\0'));
        assert!(path.len() < 128, "path must not grow with a metadata name");
        assert!(paths.insert(path), "duplicate physical path {path}");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn replay(old: &[u8], new: &[u8], edits: &[ByteEdit]) {
    let (mut old_cursor, mut new_cursor) = (0, 0);
    let mut output = Vec::new();
    for edit in edits {
        assert!(old_cursor <= edit.old_span.start && edit.old_span.start <= edit.old_span.end);
        assert!(new_cursor <= edit.new_span.start && edit.new_span.start <= edit.new_span.end);
        assert!(edit.old_span.end <= old.len() && edit.new_span.end <= new.len());
        assert_eq!(
            &old[old_cursor..edit.old_span.start],
            &new[new_cursor..edit.new_span.start]
        );
        assert_eq!(
            edit.old_hex,
            hex(&old[edit.old_span.start..edit.old_span.end])
        );
        assert_eq!(
            edit.new_hex,
            hex(&new[edit.new_span.start..edit.new_span.end])
        );
        for context in edit.old_context.iter().chain(&edit.new_context) {
            assert!(context.path.is_ascii() && !context.path.contains('\0'));
            assert!(context.path.len() < 128);
        }
        output.extend_from_slice(&old[old_cursor..edit.old_span.start]);
        output.extend_from_slice(&unhex(&edit.new_hex));
        old_cursor = edit.old_span.end;
        new_cursor = edit.new_span.end;
    }
    assert_eq!(&old[old_cursor..], &new[new_cursor..]);
    output.extend_from_slice(&old[old_cursor..]);
    assert_eq!(output, new);
}

fn physical_pair(old: &[u8], new: &[u8]) {
    let mut expected = None;
    for standard in PROFILES {
        let diff = audit::compare_with_standard(old, new, standard).unwrap();
        assert!(diff.changed);
        replay(old, new, &diff.edits);
        for (bytes, module) in [(old, &diff.old), (new, &diff.new)] {
            paths_are_bounded(module);
            for evidence in &module.standard.evidence {
                assert!(
                    evidence.span.start <= evidence.span.end && evidence.span.end <= bytes.len()
                );
                assert_eq!(
                    evidence.raw_hex,
                    hex(&bytes[evidence.span.start..evidence.span.end])
                );
            }
        }
        let edits = serde_json::to_vec(&diff.edits).unwrap();
        if let Some(previous) = &expected {
            assert_eq!(previous, &edits);
        } else {
            expected = Some(edits);
        }
    }
    for (before, after) in [(old, new), (new, old)] {
        let patch = wasm_git::patch::create(before, after).unwrap();
        assert_eq!(
            BytePatch::from_bytes(&patch.to_bytes().unwrap())
                .unwrap()
                .apply(before)
                .unwrap(),
            after
        );
    }
}

fn physical_trace(old: &[u8], new: &[u8], query: Span) {
    let history = HistorySnapshot {
        tip: "child".into(),
        commits: BTreeMap::from([
            (
                "parent".into(),
                HistoryCommit {
                    id: "parent".into(),
                    wasm: "old".into(),
                    parents: vec![],
                    message: "fixed parent".into(),
                },
            ),
            (
                "child".into(),
                HistoryCommit {
                    id: "child".into(),
                    wasm: "new".into(),
                    parents: vec!["parent".into()],
                    message: "fixed child".into(),
                },
            ),
        ]),
        blobs: BTreeMap::from([("old".into(), old.to_vec()), ("new".into(), new.to_vec())]),
    };
    let report = trace::trace(&history, query, TraceLimits::default()).unwrap();
    assert!(report.complete && report.identity_unproven);
    assert_eq!(report.query, query);
    assert_eq!(report.edges.len(), 1);
    let edge = &report.edges[0];
    assert_eq!(edge.exact_minimal, Some(true));
    assert!(!edge.events.is_empty());
    for gap in &edge.gap_mappings {
        assert_eq!(
            &old[gap.parent.span.start..gap.parent.span.end],
            &new[gap.child.span.start..gap.child.span.end]
        );
    }
    for event in &edge.events {
        let edit = &event.edit;
        assert_eq!(
            edit.old_hex,
            hex(&old[edit.old_span.start..edit.old_span.end])
        );
        assert_eq!(
            edit.new_hex,
            hex(&new[edit.new_span.start..edit.new_span.end])
        );
    }
}

#[test]
fn arbitrary_unknown_custom_names_have_one_bounded_ascii_payload_path() {
    let names = [
        "nul\0name".to_owned(),
        "a/b".to_owned(),
        "%2f%00".to_owned(),
        "名字".to_owned(),
        String::new(),
        "n".repeat(131_073),
    ];
    let mut bytes = HEADER.to_vec();
    let mut frames = Vec::new();
    for (index, name) in names.iter().enumerate() {
        frames.push(custom(&mut bytes, name, &[0xa5, index as u8, 0x5a]));
    }
    let module = audit::inspect(&bytes).unwrap();
    assert_eq!(module.sections.len(), names.len());
    paths_are_bounded(&module);
    for (index, (name, frame)) in names.iter().zip(frames).enumerate() {
        assert_eq!(module.sections[index].status, "opaque");
        let outer = region(&module, &format!("custom[{index}]/name"));
        assert_eq!(outer.span, frame.name);
        assert_eq!(outer.description, *name);
        let mut encoded_name = Vec::new();
        string(name, &mut encoded_name);
        assert_eq!(&bytes[outer.span.start..outer.span.end], encoded_name);
        let opaque = region(&module, &format!("custom[{index}]/payload/opaque"));
        assert_eq!(opaque.span, frame.data);
        assert_eq!(
            &bytes[opaque.span.start..opaque.span.end],
            &[0xa5, index as u8, 0x5a]
        );
        assert_eq!(module.sections[index].regions.len(), 2);
    }
    // The long outer name can trigger a pinned validator resource limit. The
    // physical path and payload checks do not assert a Core encoding failure.
}

#[test]
fn producer_value_ordinals_are_independent_of_tool_name_bytes_and_metadata_keys() {
    let names = [
        "nul\0tool".to_owned(),
        "a/b".to_owned(),
        "%2f".to_owned(),
        "生产者".to_owned(),
        String::new(),
        "count".to_owned(),
        "value[0]".to_owned(),
        "p".repeat(131_073),
    ];
    let version = "v\0/%版本";
    let mut payload = vec![3];
    let mut expected = Vec::new();
    for field in ["language", "processed-by", "sdk"] {
        string(field, &mut payload);
        unsigned(names.len(), &mut payload);
        for (index, name) in names.iter().enumerate() {
            let start = payload.len();
            string(name, &mut payload);
            string(version, &mut payload);
            expected.push((field, index, name, start, payload.len()));
        }
    }
    let mut bytes = HEADER.to_vec();
    let frame = custom(&mut bytes, "producers", &payload);
    let module = audit::inspect(&bytes).unwrap();
    assert_eq!(module.sections[0].status, "decoded");
    paths_are_bounded(&module);
    assert_eq!(
        region(&module, "custom[0]/producers/count").description,
        "3"
    );
    for (field, index, name, start, end) in expected {
        let value = region(
            &module,
            &format!("custom[0]/producers/{field}/value[{index}]"),
        );
        assert_eq!(
            value.span,
            Span {
                start: frame.data.start + start,
                end: frame.data.start + end
            }
        );
        assert_eq!(
            &bytes[value.span.start..value.span.end],
            &payload[start..end]
        );
        assert_eq!(
            value.description,
            format!("name={name:?} version={version:?}")
        );
        assert_eq!(
            region(&module, &format!("custom[0]/producers/{field}"))
                .children
                .len(),
            names.len()
        );
    }
}

#[test]
fn repeated_display_names_in_distinct_name_indices_keep_distinct_fixed_paths() {
    let display = "same\0/%名字";
    let mut payload = Vec::new();
    let mut module_name = Vec::new();
    string(display, &mut module_name);
    payload.push(0);
    unsigned(module_name.len(), &mut payload);
    payload.extend_from_slice(&module_name);
    for id in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] {
        let mut map = Vec::new();
        if matches!(id, 2 | 3 | 10) {
            map.extend_from_slice(&[1, 0]); // One primary index0.
        }
        map.push(2);
        for index in [0, 1] {
            map.push(index);
            string(display, &mut map);
        }
        payload.push(id);
        unsigned(map.len(), &mut payload);
        payload.extend_from_slice(&map);
    }
    let mut bytes = HEADER.to_vec();
    custom(&mut bytes, "name", &payload);
    let module = audit::inspect(&bytes).unwrap();
    assert_eq!(module.sections[0].status, "decoded");
    paths_are_bounded(&module);
    assert_eq!(
        region(&module, "custom[0]/name/subsection[0]/module").description,
        format!("module={display:?}")
    );
    for id in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] {
        let prefix = if matches!(id, 2 | 3 | 10) {
            format!("custom[0]/name/subsection[{id}]/index[0]")
        } else {
            format!("custom[0]/name/subsection[{id}]")
        };
        let a = region(&module, &format!("{prefix}/index[0]"));
        let b = region(&module, &format!("{prefix}/index[1]"));
        assert_eq!(a.description, format!("index=0 name={display:?}"));
        assert_eq!(b.description, format!("index=1 name={display:?}"));
        assert_ne!(a.span, b.span);
        for (index, entry) in [(0, a), (1, b)] {
            let mut raw = vec![index];
            string(display, &mut raw);
            assert_eq!(&bytes[entry.span.start..entry.span.end], raw);
        }
    }
}

#[test]
fn convention_failures_and_unimplemented_name_subsections_stay_wholly_opaque() {
    let mut duplicate_producer = vec![1];
    string("language", &mut duplicate_producer);
    duplicate_producer.push(2);
    for version in ["one", "two"] {
        string("same\0tool", &mut duplicate_producer);
        string(version, &mut duplicate_producer);
    }
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("name", vec![1, 7, 2, 0, 1, b'a', 0, 1, b'b']),
        ("name", vec![1, 1, 0, 0, 1, 0]),
        ("name", vec![1, 2, 0x80, 0]),
        ("name", vec![1, 2, 1, 0]),
        ("name", vec![12, 6, 1, 0, 1, 0, 1, b'p']),
        ("name", vec![13, 6, 1, 0, 1, 0, 1, b'p']),
        ("producers", duplicate_producer),
        ("producers", vec![0x80, 0]),
        ("target_features", vec![1, b'=', 1, b'x']),
        ("target_features", vec![2, b'+', 1, b'x', b'-', 1, b'x']),
    ];
    let mut bytes = HEADER.to_vec();
    let mut frames = Vec::new();
    for (name, payload) in &cases {
        frames.push(custom(&mut bytes, name, payload));
    }
    let module = audit::inspect(&bytes).unwrap();
    paths_are_bounded(&module);
    for (index, ((name, payload), frame)) in cases.iter().zip(frames).enumerate() {
        let section = &module.sections[index];
        assert_eq!(section.status, "opaque");
        assert_eq!(
            section.regions.len(),
            2,
            "no partial convention entries survive"
        );
        let opaque = region(&module, &format!("custom[{index}]/{name}/opaque"));
        assert_eq!(opaque.span, frame.data);
        assert_eq!(&bytes[opaque.span.start..opaque.span.end], payload);
        assert!(opaque.children.is_empty());
    }
    assert_eq!(
        module
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "custom_opaque")
            .count(),
        cases.len()
    );
    assert!(!module
        .standard
        .evidence
        .iter()
        .any(|evidence| evidence.status == "invalid_encoding"));
}

#[test]
fn canonical_custom_paths_keep_raw_diffs_patches_and_physical_trace_exact() {
    let mut old = HEADER.to_vec();
    let mut new = HEADER.to_vec();
    custom(&mut old, "unknown\0/%名字", &[0xa5, 0, 0x5a]);
    let frame = custom(&mut new, "unknown\0/%名字", &[0xa5, 1, 0x5a]);
    physical_pair(&old, &new);
    physical_trace(&old, &new, frame.data);

    let long = "x".repeat(131_073);
    let mut old = HEADER.to_vec();
    let mut new = HEADER.to_vec();
    custom(&mut old, &long, &[0x31]);
    custom(&mut new, &long, &[0x32]);
    physical_pair(&old, &new);

    let producer = |name: &str| {
        let mut payload = vec![1];
        string("processed-by", &mut payload);
        payload.push(2);
        string(name, &mut payload);
        string("v\0/%版本", &mut payload);
        string("count", &mut payload);
        string("one", &mut payload);
        let mut bytes = HEADER.to_vec();
        custom(&mut bytes, "producers", &payload);
        bytes
    };
    let old = producer("tool\0old/%名字");
    let new = producer("tool\0new/%名字");
    physical_pair(&old, &new);
    let audited = audit::inspect(&new).unwrap();
    let value = region(&audited, "custom[0]/producers/processed-by/value[0]");
    physical_trace(&old, &new, value.span);
}
