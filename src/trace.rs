//! Parent-relative physical range history, deliberately not author blame.
//!
//! Every mapping follows one audit edit script. Equal gaps establish byte
//! equality, not historical identity; replacement/deletion blocks propagate a
//! conservative influence range. All parents participate before a shared
//! ancestor is processed. Wasm is inspected, never executed.

use crate::audit::{self, ByteEdit, Diagnostic, Span};
use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct HistoryCommit {
    pub id: String,
    pub wasm: String,
    pub parents: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct HistorySnapshot {
    pub tip: String,
    pub commits: BTreeMap<String, HistoryCommit>,
    pub blobs: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct TraceLimits {
    pub max_edges: usize,
    pub max_compared_bytes: usize,
    pub max_ranges_per_commit: usize,
    /// Evidence records: diagnostics, gap mappings, events, their overlaps,
    /// and normalized parent ranges. Control nodes/edges/frontiers are exempt
    /// so even a zero budget can disclose why traversal stopped.
    pub max_records: usize,
}

impl Default for TraceLimits {
    fn default() -> Self {
        Self {
            max_edges: 256,
            max_compared_bytes: 64 * 1024 * 1024,
            max_ranges_per_commit: 1024,
            max_records: 16384,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceScope {
    Requested,
    Aligned,
    Influence,
}

impl TraceScope {
    fn rank(self) -> usize {
        match self {
            Self::Requested => 0,
            Self::Aligned => 1,
            Self::Influence => 2,
        }
    }

    fn through_gap(self) -> Self {
        if self == Self::Influence {
            self
        } else {
            Self::Aligned
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceRange {
    pub span: Span,
    pub scope: TraceScope,
}

#[derive(Debug, Serialize)]
pub struct TraceNode {
    pub commit: String,
    pub wasm: String,
    pub parents: Vec<String>,
    pub message: String,
    pub selected: Vec<TraceRange>,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct GapMapping {
    pub child: TraceRange,
    pub parent: TraceRange,
}

#[derive(Debug, Serialize)]
pub struct TraceOverlap {
    pub span: Span,
    pub scope: TraceScope,
    pub kind: String,
}

fn serialize_edit<S: Serializer>(edit: &Arc<ByteEdit>, serializer: S) -> Result<S::Ok, S::Error> {
    edit.as_ref().serialize(serializer)
}

#[derive(Debug, Serialize)]
pub struct TraceEvent {
    /// Shared in memory across cached blob pairs, serialized as one full edit.
    #[serde(serialize_with = "serialize_edit")]
    pub edit: Arc<ByteEdit>,
    pub overlaps: Vec<TraceOverlap>,
    pub disposition: String,
}

#[derive(Debug, Serialize)]
pub struct TraceEdge {
    pub parent: String,
    pub child: String,
    /// Null when a file is proven absent from this parent tree.
    pub parent_wasm: Option<String>,
    pub child_wasm: String,
    pub selected: Vec<TraceRange>,
    pub status: String,
    pub stopped_reason: Option<String>,
    pub exact_minimal: Option<bool>,
    pub alignment: Option<String>,
    pub parent_validation: Option<String>,
    pub child_validation: Option<String>,
    pub parent_diagnostics: Vec<Diagnostic>,
    pub child_diagnostics: Vec<Diagnostic>,
    pub gap_mappings: Vec<GapMapping>,
    pub events: Vec<TraceEvent>,
    /// All ranges proposed for parent propagation, including aligned gaps.
    /// A stopped edge does not publish these into the ancestor frontier.
    pub parent_influence: Vec<TraceRange>,
}

#[derive(Debug, Serialize)]
pub struct TraceFrontier {
    pub commit: String,
    pub selected: Vec<TraceRange>,
    pub reason: String,
    pub parent: Option<String>,
    pub child: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct TraceUsage {
    pub edges: usize,
    pub compared_bytes: usize,
    pub records: usize,
    pub cache_hits: usize,
}

#[derive(Debug, Serialize)]
pub struct TraceReport {
    pub schema_version: u32,
    pub tip: String,
    pub query: Span,
    pub complete: bool,
    pub identity_unproven: bool,
    pub interpretation: String,
    pub limits: TraceLimits,
    pub usage: TraceUsage,
    pub nodes: Vec<TraceNode>,
    pub edges: Vec<TraceEdge>,
    pub frontier: Vec<TraceFrontier>,
}

const HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";

fn span(start: usize, end: usize) -> Span {
    Span { start, end }
}

/// Validate the entire reachable graph before consuming traversal budgets.
/// Metadata keys are checked for consistency; authentication belongs to the
/// repository layer, and is not inferred by hashing these engine inputs.
fn order(history: &HistorySnapshot, absent: &BTreeSet<String>) -> Result<Vec<String>, String> {
    for id in absent {
        let node = history
            .commits
            .get(id)
            .ok_or_else(|| format!("absent-file marker references missing commit {id}"))?;
        if !node.wasm.is_empty() {
            return Err(format!(
                "absent-file commit {id} must not name a Wasm object"
            ));
        }
    }
    let mut colors = BTreeMap::<String, u8>::new();
    let mut checked_blobs = BTreeSet::new();
    let mut stack = vec![(history.tip.clone(), false)];
    let mut postorder = Vec::new();
    while let Some((id, exiting)) = stack.pop() {
        if exiting {
            colors.insert(id.clone(), 2);
            postorder.push(id);
            continue;
        }
        match colors.get(&id) {
            Some(2) => continue,
            Some(1) => return Err(format!("cycle in reachable history at {id}")),
            _ => {}
        }
        let node = history
            .commits
            .get(&id)
            .ok_or_else(|| format!("missing reachable commit {id}"))?;
        if node.id != id {
            return Err(format!(
                "commit key {id} differs from its node id {}",
                node.id
            ));
        }
        let mut parents = BTreeSet::new();
        for parent in &node.parents {
            if !parents.insert(parent) {
                return Err(format!("duplicate parent {parent} in commit {id}"));
            }
            if !history.commits.contains_key(parent) {
                return Err(format!("missing parent {parent} of commit {id}"));
            }
        }
        if !absent.contains(&id) && checked_blobs.insert(&node.wasm) {
            let bytes = history
                .blobs
                .get(&node.wasm)
                .ok_or_else(|| format!("missing Wasm blob {} for commit {id}", node.wasm))?;
            if !bytes.starts_with(HEADER) {
                return Err(format!(
                    "blob {} does not have a core WebAssembly version-1 header",
                    node.wasm
                ));
            }
        }
        colors.insert(id.clone(), 1);
        stack.push((id, true));
        for parent in node.parents.iter().rev() {
            stack.push((parent.clone(), false));
        }
    }
    postorder.reverse();
    Ok(postorder)
}

/// Union ranges without filling holes. Stronger influence dominates overlaps
/// and cannot become aligned again in an older unchanged gap.
fn normalize(ranges: impl IntoIterator<Item = TraceRange>) -> Vec<TraceRange> {
    let mut boundaries = BTreeMap::<usize, [isize; 3]>::new();
    for range in ranges {
        if range.span.start == range.span.end {
            continue;
        }
        let rank = range.scope.rank();
        boundaries.entry(range.span.start).or_default()[rank] += 1;
        boundaries.entry(range.span.end).or_default()[rank] -= 1;
    }
    let mut result: Vec<TraceRange> = Vec::new();
    let mut counts = [0isize; 3];
    let mut previous = 0;
    for (position, deltas) in boundaries {
        if previous < position {
            if let Some(rank) = (0..3).rev().find(|&rank| counts[rank] > 0) {
                let scope = [
                    TraceScope::Requested,
                    TraceScope::Aligned,
                    TraceScope::Influence,
                ][rank];
                if let Some(last) = result
                    .last_mut()
                    .filter(|last| last.span.end == previous && last.scope == scope)
                {
                    last.span.end = position;
                } else {
                    result.push(TraceRange {
                        span: span(previous, position),
                        scope,
                    });
                }
            }
        }
        for rank in 0..3 {
            counts[rank] += deltas[rank];
        }
        previous = position;
    }
    result
}

struct CachedDiff {
    exact_minimal: bool,
    alignment: String,
    parent_validation: String,
    child_validation: String,
    parent_diagnostics: Vec<Diagnostic>,
    child_diagnostics: Vec<Diagnostic>,
    edits: Vec<Arc<ByteEdit>>,
    gaps: Vec<(Span, Span)>,
}

fn comparison(old: &[u8], new: &[u8]) -> Result<CachedDiff, String> {
    let diff = audit::compare(old, new)?;
    let mut gaps = Vec::new();
    let mut old_cursor = 0;
    let mut new_cursor = 0;
    for edit in &diff.edits {
        if edit.old_span.start < old_cursor
            || edit.new_span.start < new_cursor
            || edit.old_span.start > edit.old_span.end
            || edit.new_span.start > edit.new_span.end
            || edit.old_span.end > old.len()
            || edit.new_span.end > new.len()
        {
            return Err("audit returned invalid physical edit spans".into());
        }
        let old_gap = span(old_cursor, edit.old_span.start);
        let new_gap = span(new_cursor, edit.new_span.start);
        if old_gap.end - old_gap.start != new_gap.end - new_gap.start
            || old[old_gap.start..old_gap.end] != new[new_gap.start..new_gap.end]
        {
            return Err("audit gap does not contain equal original bytes".into());
        }
        if new_gap.start < new_gap.end {
            gaps.push((old_gap, new_gap));
        }
        old_cursor = edit.old_span.end;
        new_cursor = edit.new_span.end;
    }
    if old[old_cursor..] != new[new_cursor..] {
        return Err("audit tail does not contain equal original bytes".into());
    }
    if new_cursor < new.len() {
        gaps.push((span(old_cursor, old.len()), span(new_cursor, new.len())));
    }
    Ok(CachedDiff {
        exact_minimal: diff.exact_minimal,
        alignment: diff.alignment,
        parent_validation: diff.old.validation,
        child_validation: diff.new.validation,
        parent_diagnostics: diff.old.diagnostics,
        child_diagnostics: diff.new.diagnostics,
        edits: diff.edits.into_iter().map(Arc::new).collect(),
        gaps,
    })
}

fn overlaps(
    selected: &[TraceRange],
    target: Span,
    boundary: bool,
    cursor: &mut usize,
) -> Vec<TraceOverlap> {
    while *cursor < selected.len()
        && (selected[*cursor].span.end < target.start
            || (!boundary && selected[*cursor].span.end == target.start))
    {
        *cursor += 1;
    }
    let mut result = Vec::new();
    for range in &selected[*cursor..] {
        if boundary {
            if range.span.start > target.start {
                break;
            }
            if range.span.end >= target.start {
                result.push(TraceOverlap {
                    span: target,
                    scope: range.scope,
                    kind: "boundary_touch".into(),
                });
            }
        } else {
            if range.span.start >= target.end {
                break;
            }
            let intersection = span(
                range.span.start.max(target.start),
                range.span.end.min(target.end),
            );
            if intersection.start < intersection.end {
                result.push(TraceOverlap {
                    span: intersection,
                    scope: range.scope,
                    kind: "byte_overlap".into(),
                });
            }
        }
    }
    result
}

fn charge(records: &mut usize, count: usize, remaining: usize) -> Option<()> {
    let next = records.checked_add(count)?;
    if next > remaining {
        return None;
    }
    *records = next;
    Some(())
}

/// Returns no partial evidence when the record budget cannot hold this edge.
fn evidence(edge: &mut TraceEdge, diff: &CachedDiff, remaining: usize) -> Option<usize> {
    let mut records = 0;
    charge(&mut records, diff.parent_diagnostics.len(), remaining)?;
    charge(&mut records, diff.child_diagnostics.len(), remaining)?;
    let mut parent_ranges = Vec::new();
    let mut gaps = Vec::new();
    let mut events = Vec::new();
    let mut cursor = 0;
    for &(old_gap, new_gap) in &diff.gaps {
        for overlap in overlaps(&edge.selected, new_gap, false, &mut cursor) {
            charge(&mut records, 1, remaining)?;
            let parent = TraceRange {
                span: span(
                    old_gap.start + (overlap.span.start - new_gap.start),
                    old_gap.start + (overlap.span.end - new_gap.start),
                ),
                scope: overlap.scope.through_gap(),
            };
            parent_ranges.push(parent.clone());
            gaps.push(GapMapping {
                child: TraceRange {
                    span: overlap.span,
                    scope: overlap.scope,
                },
                parent,
            });
        }
    }
    cursor = 0;
    for edit in &diff.edits {
        let boundary = edit.new_span.start == edit.new_span.end;
        let intersected = overlaps(&edge.selected, edit.new_span, boundary, &mut cursor);
        if intersected.is_empty() {
            continue;
        }
        charge(&mut records, 1, remaining)?;
        charge(&mut records, intersected.len(), remaining)?;
        let disposition = if edit.old_span.start == edit.old_span.end {
            "introduced_no_old_bytes"
        } else if boundary {
            parent_ranges.push(TraceRange {
                span: edit.old_span,
                scope: TraceScope::Influence,
            });
            "deletion_boundary"
        } else {
            parent_ranges.push(TraceRange {
                span: edit.old_span,
                scope: TraceScope::Influence,
            });
            "replacement_influence"
        };
        events.push(TraceEvent {
            edit: Arc::clone(edit),
            overlaps: intersected,
            disposition: disposition.into(),
        });
    }
    let parent_influence = if diff.exact_minimal {
        normalize(parent_ranges)
    } else {
        Vec::new()
    };
    charge(&mut records, parent_influence.len(), remaining)?;
    edge.parent_diagnostics = diff.parent_diagnostics.clone();
    edge.child_diagnostics = diff.child_diagnostics.clone();
    edge.gap_mappings = gaps;
    edge.events = events;
    edge.parent_influence = parent_influence;
    Some(records)
}

fn stopped(
    report: &mut TraceReport,
    commit: &str,
    selected: Vec<TraceRange>,
    reason: &str,
    parent: Option<String>,
    child: Option<String>,
) {
    report.complete = false;
    report.frontier.push(TraceFrontier {
        commit: commit.into(),
        selected,
        reason: reason.into(),
        parent,
        child,
    });
}

/// Trace a nonempty current physical range through every parent edge.
pub fn trace(
    history: &HistorySnapshot,
    query: Span,
    limits: TraceLimits,
) -> Result<TraceReport, String> {
    trace_with_absences(history, &BTreeSet::new(), query, limits)
}

/// Trace one file path through the real commit DAG. Absence is supplied only
/// after repository tree verification; it is not represented by fake Wasm bytes.
/// A path introduction ends propagation along that parent edge. This function
/// does not infer rename identity or jump across an intervening deletion.
pub fn trace_with_absences(
    history: &HistorySnapshot,
    absent: &BTreeSet<String>,
    query: Span,
    limits: TraceLimits,
) -> Result<TraceReport, String> {
    let order = order(history, absent)?;
    if absent.contains(&history.tip) {
        return Err("trace file is absent from the selected tip".into());
    }
    let tip = &history.commits[&history.tip];
    let tip_bytes = &history.blobs[&tip.wasm];
    if query.start >= query.end || query.end > tip_bytes.len() {
        return Err("trace requires a nonempty physical range within the selected tip blob".into());
    }
    let mut report = TraceReport {
        schema_version: 1, tip: history.tip.clone(), query, complete: true, identity_unproven: true,
        interpretation: "Parent-relative physical audit, not blame or author origin. Even exact-minimal gap mappings prove byte equality only within one nonunique edit script. Replacements and closed-endpoint deletion touches expand to whole old influence blocks; influence never regains alignment certainty. All incoming parent paths are unioned without filling holes before processing each ancestor once. Fallback alignments and budget stops leave explicit incomplete frontiers. Root snapshots and byte introductions are normal history boundaries. Metadata IDs are not authenticated by this engine. Records count diagnostics, gap mappings, events, event overlaps, and normalized parent ranges; control nodes, edge stubs, and frontier explanations are exempt.".into(),
        limits, usage: TraceUsage::default(), nodes: Vec::new(), edges: Vec::new(), frontier: Vec::new(),
    };
    let mut incoming = BTreeMap::from([(
        history.tip.clone(),
        vec![TraceRange {
            span: query,
            scope: TraceScope::Requested,
        }],
    )]);
    let mut cache = BTreeMap::<(String, String), Arc<CachedDiff>>::new();
    for id in order {
        let Some(selected) = incoming.remove(&id) else {
            continue;
        };
        let selected = normalize(selected);
        if selected.is_empty() {
            continue;
        }
        let node = &history.commits[&id];
        let mut out_node = TraceNode {
            commit: id.clone(),
            wasm: node.wasm.clone(),
            parents: node.parents.clone(),
            message: node.message.clone(),
            selected: selected.clone(),
            status: "traced".into(),
        };
        if selected.len() > limits.max_ranges_per_commit {
            out_node.status = "stopped".into();
            stopped(
                &mut report,
                &id,
                selected,
                "max_ranges_per_commit",
                None,
                None,
            );
            report.nodes.push(out_node);
            continue;
        }
        if node.parents.is_empty() {
            out_node.status = "root_snapshot".into();
            report.frontier.push(TraceFrontier {
                commit: id.clone(),
                selected,
                reason: "root_snapshot".into(),
                parent: None,
                child: None,
            });
            report.nodes.push(out_node);
            continue;
        }
        for parent_id in &node.parents {
            if report.usage.edges >= limits.max_edges {
                out_node.status = "stopped".into();
                stopped(
                    &mut report,
                    &id,
                    selected.clone(),
                    "max_edges",
                    Some(parent_id.clone()),
                    Some(id.clone()),
                );
                continue;
            }
            report.usage.edges += 1;
            let parent = &history.commits[parent_id];
            let mut edge = TraceEdge {
                parent: parent_id.clone(),
                child: id.clone(),
                parent_wasm: if absent.contains(parent_id) {
                    None
                } else {
                    Some(parent.wasm.clone())
                },
                child_wasm: node.wasm.clone(),
                selected: selected.clone(),
                status: "stopped".into(),
                stopped_reason: None,
                exact_minimal: None,
                alignment: None,
                parent_validation: None,
                child_validation: None,
                parent_diagnostics: Vec::new(),
                child_diagnostics: Vec::new(),
                gap_mappings: Vec::new(),
                events: Vec::new(),
                parent_influence: Vec::new(),
            };
            if absent.contains(parent_id) {
                edge.status = "file_absent".into();
                report.frontier.push(TraceFrontier {
                    commit: id.clone(),
                    selected: selected.clone(),
                    reason: "file_introduced_at_path".into(),
                    parent: Some(parent_id.clone()),
                    child: Some(id.clone()),
                });
                report.edges.push(edge);
                continue;
            }
            let mut stop_reason = None;
            if report.usage.records >= limits.max_records {
                stop_reason = Some("max_records");
            } else {
                let key = (parent.wasm.clone(), node.wasm.clone());
                let diff = if let Some(diff) = cache.get(&key) {
                    report.usage.cache_hits += 1;
                    Some(Arc::clone(diff))
                } else {
                    let old = &history.blobs[&parent.wasm];
                    let new = &history.blobs[&node.wasm];
                    let cost = old.len().checked_add(new.len());
                    if cost.is_none_or(|cost| {
                        cost > limits
                            .max_compared_bytes
                            .saturating_sub(report.usage.compared_bytes)
                    }) {
                        stop_reason = Some("max_compared_bytes");
                        None
                    } else {
                        report.usage.compared_bytes += cost.expect("checked above");
                        let diff = Arc::new(comparison(old, new)?);
                        cache.insert(key, Arc::clone(&diff));
                        Some(diff)
                    }
                };
                if let Some(diff) = diff {
                    edge.exact_minimal = Some(diff.exact_minimal);
                    edge.alignment = Some(diff.alignment.clone());
                    edge.parent_validation = Some(diff.parent_validation.clone());
                    edge.child_validation = Some(diff.child_validation.clone());
                    if let Some(records) =
                        evidence(&mut edge, &diff, limits.max_records - report.usage.records)
                    {
                        report.usage.records += records;
                        if !diff.exact_minimal {
                            stop_reason = Some("alignment_fallback");
                        } else {
                            let previous = incoming.get(parent_id).cloned().unwrap_or_default();
                            let proposed = normalize(
                                previous.into_iter().chain(edge.parent_influence.clone()),
                            );
                            if proposed.len() > limits.max_ranges_per_commit {
                                stop_reason = Some("max_ranges_per_commit");
                            } else {
                                if !proposed.is_empty() {
                                    incoming.insert(parent_id.clone(), proposed);
                                }
                                edge.status = "traced".into();
                                for event in &edge.events {
                                    if event.disposition == "introduced_no_old_bytes" {
                                        report.frontier.push(TraceFrontier {
                                            commit: id.clone(),
                                            selected: normalize(event.overlaps.iter().map(
                                                |overlap| TraceRange {
                                                    span: overlap.span,
                                                    scope: overlap.scope,
                                                },
                                            )),
                                            reason: "introduced_no_old_bytes".into(),
                                            parent: Some(parent_id.clone()),
                                            child: Some(id.clone()),
                                        });
                                    }
                                }
                            }
                        }
                    } else {
                        stop_reason = Some("max_records");
                    }
                }
            }
            if let Some(reason) = stop_reason {
                out_node.status = "stopped".into();
                edge.stopped_reason = Some(reason.into());
                stopped(
                    &mut report,
                    &id,
                    selected.clone(),
                    reason,
                    Some(parent_id.clone()),
                    Some(id.clone()),
                );
            }
            report.edges.push(edge);
        }
        report.nodes.push(out_node);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(payload: &[u8]) -> Vec<u8> {
        let mut bytes = HEADER.to_vec();
        bytes.push(0);
        let mut value = payload.len() + 2;
        loop {
            let byte = value as u8 & 127;
            value >>= 7;
            bytes.push(byte | if value == 0 { 0 } else { 128 });
            if value == 0 {
                break;
            }
        }
        bytes.extend_from_slice(&[1, b'x']);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn add(history: &mut HistorySnapshot, id: &str, blob: &str, parents: &[&str], bytes: Vec<u8>) {
        if let Some(existing) = history.blobs.get(blob) {
            assert_eq!(existing, &bytes);
        }
        history.blobs.insert(blob.into(), bytes);
        history.commits.insert(
            id.into(),
            HistoryCommit {
                id: id.into(),
                wasm: blob.into(),
                parents: parents.iter().map(|parent| (*parent).into()).collect(),
                message: format!("commit {id}"),
            },
        );
    }

    fn empty(tip: &str) -> HistorySnapshot {
        HistorySnapshot {
            tip: tip.into(),
            commits: BTreeMap::new(),
            blobs: BTreeMap::new(),
        }
    }

    fn pair(old: &[u8], new: &[u8]) -> HistorySnapshot {
        let mut history = empty("b");
        add(&mut history, "a", "old", &[], old.to_vec());
        add(&mut history, "b", "new", &["a"], new.to_vec());
        history
    }

    fn run(history: &HistorySnapshot, query: Span) -> TraceReport {
        trace(history, query, TraceLimits::default()).unwrap()
    }

    fn absent_node(history: &mut HistorySnapshot, id: &str, parents: &[&str]) {
        history.commits.insert(
            id.into(),
            HistoryCommit {
                id: id.into(),
                wasm: String::new(),
                parents: parents.iter().map(|p| (*p).into()).collect(),
                message: format!("absent {id}"),
            },
        );
    }

    #[test]
    fn file_absence_is_a_boundary_without_synthetic_bytes_or_rename_identity() {
        let bytes = custom(b"same bytes");
        let mut history = empty("again");
        add(&mut history, "first", "real", &[], bytes.clone());
        absent_node(&mut history, "deleted", &["first"]);
        add(&mut history, "again", "real", &["deleted"], bytes.clone());
        let absent = BTreeSet::from(["deleted".into()]);
        let report = trace_with_absences(
            &history,
            &absent,
            span(0, bytes.len()),
            TraceLimits::default(),
        )
        .unwrap();
        assert!(report.complete);
        assert_eq!(
            report
                .nodes
                .iter()
                .map(|n| n.commit.as_str())
                .collect::<Vec<_>>(),
            vec!["again"]
        );
        assert_eq!(report.edges.len(), 1);
        assert_eq!(report.edges[0].status, "file_absent");
        assert_eq!(report.edges[0].parent_wasm, None);
        assert_eq!(report.frontier[0].reason, "file_introduced_at_path");
        assert_eq!(report.frontier[0].parent.as_deref(), Some("deleted"));
        assert_eq!(report.usage.compared_bytes, 0);
        assert_eq!(report.usage.edges, 1);
        assert!(!history.blobs.contains_key(""));
    }

    #[test]
    fn merge_keeps_present_and_absent_file_edges_and_honors_edge_budget() {
        let bytes = custom(b"merge");
        let mut history = empty("merge");
        add(&mut history, "present", "real", &[], bytes.clone());
        absent_node(&mut history, "absent", &[]);
        add(
            &mut history,
            "merge",
            "real",
            &["present", "absent"],
            bytes.clone(),
        );
        let absent = BTreeSet::from(["absent".into()]);
        let query = span(0, bytes.len());
        let report = trace_with_absences(&history, &absent, query, TraceLimits::default()).unwrap();
        assert!(report.complete);
        assert_eq!(report.edges.len(), 2);
        assert_eq!(report.nodes.len(), 2);
        assert_eq!(
            report
                .frontier
                .iter()
                .filter(|f| f.reason == "file_introduced_at_path")
                .count(),
            1
        );
        assert_eq!(
            report
                .frontier
                .iter()
                .filter(|f| f.reason == "root_snapshot")
                .count(),
            1
        );
        let limits = TraceLimits {
            max_edges: 0,
            ..Default::default()
        };
        let report = trace_with_absences(&history, &absent, query, limits).unwrap();
        assert!(!report.complete);
        assert!(report.edges.is_empty());
        assert_eq!(report.frontier.len(), 2);
        assert!(report.frontier.iter().all(|f| f.reason == "max_edges"));
    }

    #[test]
    fn absence_cannot_hide_invalid_dag_or_claim_a_wasm_object() {
        let bytes = custom(b"checked");
        let mut history = empty("tip");
        absent_node(&mut history, "absent", &[]);
        add(&mut history, "tip", "real", &["absent"], bytes.clone());
        let query = span(0, bytes.len());
        let absent = BTreeSet::from(["absent".into()]);
        assert!(trace_with_absences(
            &history,
            &BTreeSet::from(["missing".into()]),
            query,
            TraceLimits::default()
        )
        .is_err());
        history.commits.get_mut("absent").unwrap().wasm = "real".into();
        assert!(trace_with_absences(&history, &absent, query, TraceLimits::default()).is_err());
        history.commits.get_mut("absent").unwrap().wasm = String::new();
        history.commits.get_mut("absent").unwrap().parents = vec!["missing".into()];
        assert!(trace_with_absences(&history, &absent, query, TraceLimits::default()).is_err());
        history.commits.get_mut("absent").unwrap().parents = vec!["tip".into()];
        assert!(trace_with_absences(&history, &absent, query, TraceLimits::default()).is_err());
        history.commits.get_mut("absent").unwrap().parents.clear();
        history.tip = "absent".into();
        assert!(trace_with_absences(&history, &absent, query, TraceLimits::default()).is_err());
    }

    #[test]
    fn ranges_are_checked_even_when_all_budgets_are_zero() {
        let bytes = custom(b"abc");
        let history = pair(&bytes, &bytes);
        let limits = TraceLimits {
            max_edges: 0,
            max_compared_bytes: 0,
            max_ranges_per_commit: 0,
            max_records: 0,
        };
        for query in [
            span(1, 1),
            span(2, 1),
            span(0, bytes.len() + 1),
            span(usize::MAX, usize::MAX),
        ] {
            assert!(trace(&history, query, limits).is_err());
        }
        let report = trace(&history, span(0, bytes.len()), limits).unwrap();
        assert!(!report.complete);
        assert_eq!(report.frontier[0].reason, "max_ranges_per_commit");
    }

    #[test]
    fn gap_mapping_tracks_offset_changes_and_checks_equal_slices() {
        let old = custom(b"0123456789");
        let new = custom(b"xxx0123456789");
        let old_start = old.len() - 10;
        let new_start = new.len() - 13;
        let report = run(&pair(&old, &new), span(new_start + 7, new_start + 10));
        assert!(report.complete);
        assert!(report.identity_unproven);
        let edge = &report.edges[0];
        assert!(edge.events.is_empty());
        assert_eq!(edge.gap_mappings.len(), 1);
        let mapping = &edge.gap_mappings[0];
        assert_eq!(mapping.parent.span, span(old_start + 4, old_start + 7));
        assert_eq!(mapping.parent.scope, TraceScope::Aligned);
        assert_eq!(
            &old[mapping.parent.span.start..mapping.parent.span.end],
            &new[mapping.child.span.start..mapping.child.span.end]
        );
        assert_eq!(report.nodes.last().unwrap().status, "root_snapshot");
    }

    #[test]
    fn replacement_expands_whole_old_block_and_never_regains_alignment() {
        let old = custom(b"abcde");
        let new = custom(b"aXYZ e");
        let mut history = empty("c");
        add(&mut history, "a", "root", &[], old.clone());
        add(&mut history, "b", "same", &["a"], old.clone());
        add(&mut history, "c", "new", &["b"], new.clone());
        let start = new.len() - 6;
        let report = run(&history, span(start + 2, start + 3));
        assert!(report.complete);
        let first = &report.edges[0];
        let event = first
            .events
            .iter()
            .find(|event| event.disposition == "replacement_influence")
            .unwrap();
        assert!(event.edit.old_span.end - event.edit.old_span.start > 1);
        assert!(first
            .parent_influence
            .iter()
            .all(|range| range.scope == TraceScope::Influence));
        let previous = report.edges.iter().find(|edge| edge.child == "b").unwrap();
        assert!(previous
            .gap_mappings
            .iter()
            .all(|mapping| mapping.parent.scope == TraceScope::Influence));
        assert!(report
            .nodes
            .last()
            .unwrap()
            .selected
            .iter()
            .all(|range| range.scope == TraceScope::Influence));
    }

    #[test]
    fn introduced_bytes_stop_without_inventing_a_parent_point_origin() {
        let old = custom(b"abc");
        let new = custom(b"abcXYZ");
        let start = new.len() - 3;
        let report = run(&pair(&old, &new), span(start, new.len()));
        assert!(report.complete);
        assert_eq!(report.nodes.len(), 1);
        assert!(report.edges[0].parent_influence.is_empty());
        assert!(report.edges[0]
            .events
            .iter()
            .any(|event| event.disposition == "introduced_no_old_bytes"));
        assert!(report
            .frontier
            .iter()
            .any(|frontier| frontier.reason == "introduced_no_old_bytes"));
        assert!(!report
            .frontier
            .iter()
            .any(|frontier| frontier.reason == "root_snapshot"));
    }

    #[test]
    fn deletions_include_query_start_end_and_eof_as_boundary_evidence() {
        for (old_payload, new_payload, query_start, query_end) in [
            (&b"abXYZcd"[..], &b"abcd"[..], 2, 3),
            (&b"abXYZcd"[..], &b"abcd"[..], 1, 2),
            (&b"abcXYZ"[..], &b"abc"[..], 2, 3),
        ] {
            let old = custom(old_payload);
            let new = custom(new_payload);
            let start = new.len() - new_payload.len();
            let report = run(
                &pair(&old, &new),
                span(start + query_start, start + query_end),
            );
            let event = report.edges[0]
                .events
                .iter()
                .find(|event| event.disposition == "deletion_boundary")
                .unwrap();
            assert_eq!(event.edit.new_span.start, event.edit.new_span.end);
            assert!(event
                .overlaps
                .iter()
                .all(|overlap| overlap.kind == "boundary_touch"
                    && overlap.span.start == overlap.span.end));
            assert!(report.edges[0]
                .parent_influence
                .iter()
                .any(|range| range.scope == TraceScope::Influence));
        }
    }

    #[test]
    fn repeated_bytes_are_alignment_relative_without_identity_claims() {
        let old = custom(b"aaaa");
        let new = custom(b"aaa");
        let report = run(&pair(&old, &new), span(new.len() - 3, new.len()));
        assert!(report.complete && report.identity_unproven);
        assert!(report.interpretation.contains("nonunique"));
        assert!(report.edges[0]
            .events
            .iter()
            .any(|event| event.disposition == "deletion_boundary"));
    }

    #[test]
    fn all_parents_reconverge_before_processing_an_ancestor_and_cache_bytes() {
        let bytes = custom(b"abcdef");
        let mut history = empty("d");
        add(&mut history, "a", "same", &[], bytes.clone());
        add(&mut history, "b", "same", &["a"], bytes.clone());
        add(&mut history, "c", "same", &["a"], bytes.clone());
        add(&mut history, "d", "same", &["b", "c"], bytes.clone());
        let report = run(&history, span(bytes.len() - 4, bytes.len() - 1));
        assert!(report.complete);
        assert_eq!(report.edges.len(), 4);
        assert_eq!(report.edges[0].parent, "b");
        assert_eq!(report.edges[1].parent, "c");
        assert_eq!(
            report
                .nodes
                .iter()
                .filter(|node| node.commit == "a")
                .count(),
            1
        );
        assert_eq!(report.nodes.last().unwrap().commit, "a");
        assert_eq!(report.usage.compared_bytes, bytes.len() * 2);
        assert_eq!(report.usage.cache_hits, 3);
        assert_eq!(report.nodes.last().unwrap().selected.len(), 1);
    }

    #[test]
    fn range_union_preserves_holes_and_influence_dominates_overlap() {
        let result = normalize([
            TraceRange {
                span: span(1, 4),
                scope: TraceScope::Aligned,
            },
            TraceRange {
                span: span(2, 3),
                scope: TraceScope::Influence,
            },
            TraceRange {
                span: span(7, 9),
                scope: TraceScope::Aligned,
            },
        ]);
        assert_eq!(result.len(), 4);
        assert_eq!(
            result[1],
            TraceRange {
                span: span(2, 3),
                scope: TraceScope::Influence
            }
        );
        assert_eq!(result[2].span.end, 4);
        assert_eq!(result[3].span.start, 7);
    }

    #[test]
    fn fallback_keeps_edge_evidence_and_stops_the_entire_parent_edge() {
        let old = custom(&vec![b'A'; 2048]);
        let new = custom(&vec![b'B'; 4096]);
        let report = run(&pair(&old, &new), span(new.len() - 4, new.len() - 2));
        assert!(!report.complete);
        assert_eq!(report.edges[0].exact_minimal, Some(false));
        assert_eq!(
            report.edges[0].stopped_reason.as_deref(),
            Some("alignment_fallback")
        );
        assert!(!report.edges[0].events.is_empty());
        assert!(report.edges[0].parent_influence.is_empty());
        assert_eq!(report.nodes.len(), 1);
        assert!(report
            .frontier
            .iter()
            .any(|frontier| frontier.reason == "alignment_fallback"));
    }

    #[test]
    fn each_budget_has_an_explicit_incomplete_frontier() {
        let old = custom(b"abc");
        let new = custom(b"axc");
        let history = pair(&old, &new);
        let defaults = TraceLimits::default();
        for (limits, reason) in [
            (
                TraceLimits {
                    max_edges: 0,
                    ..defaults
                },
                "max_edges",
            ),
            (
                TraceLimits {
                    max_compared_bytes: 0,
                    ..defaults
                },
                "max_compared_bytes",
            ),
            (
                TraceLimits {
                    max_records: 0,
                    ..defaults
                },
                "max_records",
            ),
            (
                TraceLimits {
                    max_ranges_per_commit: 0,
                    ..defaults
                },
                "max_ranges_per_commit",
            ),
            (
                TraceLimits {
                    max_records: 1,
                    ..defaults
                },
                "max_records",
            ),
        ] {
            let report = trace(&history, span(0, new.len()), limits).unwrap();
            assert!(!report.complete, "{reason}");
            assert!(
                report
                    .frontier
                    .iter()
                    .any(|frontier| frontier.reason == reason),
                "{reason}"
            );
            assert!(!report
                .frontier
                .iter()
                .any(|frontier| frontier.reason == "root_snapshot"));
            assert!(report.usage.records <= limits.max_records);
        }
        let mut merge = history;
        add(&mut merge, "c", "old", &[], old);
        merge.commits.get_mut("b").unwrap().parents.push("c".into());
        let report = trace(
            &merge,
            span(0, new.len()),
            TraceLimits {
                max_edges: 0,
                ..defaults
            },
        )
        .unwrap();
        assert!(report.edges.is_empty());
        assert_eq!(
            report
                .frontier
                .iter()
                .filter(|frontier| frontier.reason == "max_edges")
                .count(),
            2
        );
    }

    #[test]
    fn malformed_reachable_graphs_fail_before_traversal_budgets() {
        let bytes = custom(b"abc");
        let original = pair(&bytes, &bytes);
        let limits = TraceLimits {
            max_edges: 0,
            ..TraceLimits::default()
        };
        for kind in [
            "missing_tip",
            "wrong_id",
            "missing_parent",
            "duplicate_parent",
            "missing_blob",
            "bad_header",
            "cycle",
        ] {
            let mut history = original.clone();
            match kind {
                "missing_tip" => history.tip = "missing".into(),
                "wrong_id" => history.commits.get_mut("a").unwrap().id = "different".into(),
                "missing_parent" => history
                    .commits
                    .get_mut("a")
                    .unwrap()
                    .parents
                    .push("missing".into()),
                "duplicate_parent" => history
                    .commits
                    .get_mut("b")
                    .unwrap()
                    .parents
                    .push("a".into()),
                "missing_blob" => {
                    history.blobs.remove("old");
                }
                "bad_header" => history.blobs.get_mut("old").unwrap()[4] = 2,
                "cycle" => history
                    .commits
                    .get_mut("a")
                    .unwrap()
                    .parents
                    .push("b".into()),
                _ => unreachable!(),
            }
            assert!(
                trace(&history, span(0, bytes.len()), limits).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn unknown_instructions_and_malformed_custom_data_keep_raw_evidence() {
        let mut old = wat::parse_str("(module (func))").unwrap();
        *old.last_mut().unwrap() = 0xff;
        let mut new = old.clone();
        old.extend_from_slice(&[0, 7, 4, b'n', b'a', b'm', b'e', 1, 0x80]);
        new.extend_from_slice(&[0, 7, 4, b'n', b'a', b'm', b'e', 1, 0x81]);
        let report = run(&pair(&old, &new), span(new.len() - 1, new.len()));
        assert!(report.complete);
        assert_eq!(
            report.edges[0].parent_validation.as_deref(),
            Some("failed_or_unsupported")
        );
        assert!(report.edges[0]
            .parent_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "unknown_operator"));
        let event = &report.edges[0].events[0];
        assert_eq!(event.edit.old_hex, "80");
        assert_eq!(event.edit.new_hex, "81");
    }

    #[test]
    fn exhaustive_small_edits_cover_every_selected_byte_with_equal_gaps() {
        let mut words = Vec::new();
        for len in 0..=4 {
            for value in 0..(1usize << len) {
                words.push(
                    (0..len)
                        .map(|bit| ((value >> bit) & 1) as u8)
                        .collect::<Vec<_>>(),
                );
            }
        }
        for old_word in &words {
            for new_word in &words {
                let old = custom(old_word);
                let new = custom(new_word);
                let history = pair(&old, &new);
                for query in [span(0, new.len()), span(new.len() - 1, new.len())] {
                    let report = run(&history, query);
                    assert!(report.complete, "{old_word:?} -> {new_word:?}");
                    let edge = &report.edges[0];
                    assert_eq!(edge.exact_minimal, Some(true));
                    let mut covered = vec![false; new.len()];
                    for gap in &edge.gap_mappings {
                        let a = gap.parent.span;
                        let b = gap.child.span;
                        assert_eq!(&old[a.start..a.end], &new[b.start..b.end]);
                        covered[b.start..b.end].fill(true);
                    }
                    for event in &edge.events {
                        for overlap in &event.overlaps {
                            if overlap.kind == "byte_overlap" {
                                covered[overlap.span.start..overlap.span.end].fill(true);
                            }
                        }
                    }
                    assert!(
                        covered[query.start..query.end]
                            .iter()
                            .all(|covered| *covered),
                        "uncovered {old_word:?} -> {new_word:?} query={query:?}"
                    );
                    for range in &edge.parent_influence {
                        assert!(range.span.start < range.span.end && range.span.end <= old.len());
                    }
                }
            }
        }
    }
}
