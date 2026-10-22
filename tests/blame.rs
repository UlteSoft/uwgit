use std::collections::{BTreeMap, BTreeSet};
use wasm_git::audit::Span;
use wasm_git::blame::blame;
use wasm_git::trace::{HistoryCommit, HistorySnapshot, TraceLimits};
fn wasm(a: u8, b: u8) -> Vec<u8> {
    [b"\0asm\x01\0\0\0".as_slice(), &[0, 4, 1, b'x', a, b]].concat()
}
fn graph(left: bool, right: bool) -> HistorySnapshot {
    let blobs: BTreeMap<_, _> = [
        ("root", wasm(20, 30)),
        ("left", wasm(if left { 25 } else { 20 }, 30)),
        ("right", wasm(20, if right { 35 } else { 30 })),
        (
            "merge",
            wasm(if left { 25 } else { 20 }, if right { 35 } else { 30 }),
        ),
    ]
    .into_iter()
    .map(|(id, bytes)| (id.into(), bytes))
    .collect();
    let commits = [
        ("root", vec![]),
        ("left", vec!["root"]),
        ("right", vec!["root"]),
        ("merge", vec!["left", "right"]),
    ]
    .into_iter()
    .map(|(id, parents)| {
        (
            id.into(),
            HistoryCommit {
                id: id.into(),
                wasm: id.into(),
                parents: parents.into_iter().map(str::to_owned).collect(),
                message: id.into(),
            },
        )
    })
    .collect();
    HistorySnapshot {
        tip: "merge".into(),
        commits,
        blobs,
    }
}
#[test]
fn merge_bytes_follow_any_unchanged_parent_instead_of_being_blindly_assigned_to_the_merge() {
    for left in [false, true] {
        for right in [false, true] {
            let history = graph(left, right);
            let report = blame(
                &history,
                &BTreeSet::new(),
                Span { start: 0, end: 14 },
                false,
                TraceLimits::default(),
            )
            .unwrap();
            assert!(report.complete);
            assert!(!report.historical_identity_proven);
            for byte in 0..14 {
                let owners: BTreeSet<_> = report
                    .origins
                    .iter()
                    .filter(|origin| origin.tip_span.start <= byte && byte < origin.tip_span.end)
                    .map(|origin| origin.commit.as_str())
                    .collect();
                let expected = if byte == 12 && left {
                    "left"
                } else if byte == 13 && right {
                    "right"
                } else {
                    "root"
                };
                assert_eq!(
                    owners,
                    BTreeSet::from([expected]),
                    "byte={byte}, left={left}, right={right}"
                );
            }
        }
    }
}
#[test]
fn selected_ranges_and_all_origin_bytes_are_independently_equal_to_the_tip() {
    let history = graph(true, true);
    let report = blame(
        &history,
        &BTreeSet::new(),
        Span { start: 12, end: 14 },
        false,
        TraceLimits::default(),
    )
    .unwrap();
    for origin in report.origins {
        assert!(origin.tip_span.start >= 12 && origin.tip_span.end <= 14);
        let bytes = &history.blobs[&history.commits[&origin.commit].wasm];
        assert_eq!(
            &bytes[origin.origin_span.start..origin.origin_span.end],
            &history.blobs["merge"][origin.tip_span.start..origin.tip_span.end]
        );
    }
}
#[test]
fn exhausted_budgets_return_frontiers_without_fabricated_attribution() {
    let history = graph(true, true);
    for limits in [
        TraceLimits {
            max_edges: 0,
            ..Default::default()
        },
        TraceLimits {
            max_compared_bytes: 0,
            ..Default::default()
        },
        TraceLimits {
            max_records: 0,
            ..Default::default()
        },
    ] {
        let report = blame(
            &history,
            &BTreeSet::new(),
            Span { start: 0, end: 14 },
            false,
            limits,
        )
        .unwrap();
        assert!(!report.complete);
        assert!(!report.frontier.is_empty());
        assert!(report.origins.is_empty());
    }
}
#[test]
fn absence_is_a_file_introduction_boundary_and_never_a_jump_over_deletion() {
    let mut history = graph(true, true);
    history.commits.get_mut("root").unwrap().wasm.clear();
    history.commits.get_mut("right").unwrap().wasm.clear();
    let absent = BTreeSet::from(["root".into(), "right".into()]);
    let report = blame(
        &history,
        &absent,
        Span { start: 0, end: 14 },
        false,
        TraceLimits::default(),
    )
    .unwrap();
    assert!(report.complete);
    assert!(report
        .origins
        .iter()
        .all(|origin| !absent.contains(&origin.commit)));
    assert!(report
        .origins
        .iter()
        .any(|origin| origin.reason == "file_introduced"));
}
