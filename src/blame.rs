//! Physical byte attribution through verified Wasm history.
//! Equal gaps establish byte correspondence, not authorship or semantic identity.
use crate::audit::{self, Span};
use crate::trace::{HistorySnapshot, TraceLimits};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Origin {
    pub commit: String,
    pub tip_span: Span,
    pub origin_span: Span,
    pub reason: String,
}
#[derive(Serialize)]
pub struct Frontier {
    pub commit: String,
    pub tip_span: Span,
    pub commit_span: Span,
    pub reason: String,
}
#[derive(Serialize)]
pub struct BlameReport {
    pub schema_version: u32,
    pub tip: String,
    pub query: Span,
    pub first_parent: bool,
    pub complete: bool,
    pub historical_identity_proven: bool,
    pub interpretation: String,
    pub origins: Vec<Origin>,
    pub frontier: Vec<Frontier>,
    pub compared_bytes: usize,
    pub edges: usize,
    pub records: usize,
    pub all_alignments_minimal: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Piece {
    tip: Span,
    at: Span,
}
type Gaps = Vec<(Span, Span)>;

fn gaps(old: &[u8], new: &[u8]) -> Result<(Gaps, bool), String> {
    let diff = audit::compare(old, new)?;
    let (mut old_at, mut new_at) = (0, 0);
    let mut result = Vec::new();
    for edit in &diff.edits {
        if edit.old_span.start < old_at || edit.new_span.start < new_at {
            return Err("nonmonotonic audit edit script".into());
        }
        let old_gap = Span {
            start: old_at,
            end: edit.old_span.start,
        };
        let new_gap = Span {
            start: new_at,
            end: edit.new_span.start,
        };
        if old.get(old_gap.start..old_gap.end) != new.get(new_gap.start..new_gap.end) {
            return Err("unequal audit gap".into());
        }
        if new_gap.start < new_gap.end {
            result.push((new_gap, old_gap));
        }
        old_at = edit.old_span.end;
        new_at = edit.new_span.end;
    }
    if old.get(old_at..) != new.get(new_at..) {
        return Err("unequal final audit gap".into());
    }
    if new_at < new.len() {
        result.push((
            Span {
                start: new_at,
                end: new.len(),
            },
            Span {
                start: old_at,
                end: old.len(),
            },
        ));
    }
    Ok((result, diff.exact_minimal))
}

pub fn blame(
    history: &HistorySnapshot,
    absent: &BTreeSet<String>,
    query: Span,
    first_parent: bool,
    limits: TraceLimits,
) -> Result<BlameReport, String> {
    // The existing trace validator checks keys, the full reachable graph and
    // every raw module even when this command has a zero traversal budget.
    crate::trace::trace_with_absences(
        history,
        absent,
        query,
        TraceLimits {
            max_edges: 0,
            max_records: 0,
            ..limits
        },
    )?;
    let tip = history
        .commits
        .get(&history.tip)
        .ok_or("missing blame tip")?;
    let tip_bytes = history
        .blobs
        .get(&tip.wasm)
        .ok_or("missing blame tip bytes")?;
    let mut reachable = BTreeSet::new();
    let mut stack = vec![history.tip.clone()];
    while let Some(id) = stack.pop() {
        if reachable.insert(id.clone()) {
            stack.extend(history.commits[&id].parents.iter().cloned());
        }
    }
    let mut children: BTreeMap<String, usize> =
        reachable.iter().map(|id| (id.clone(), 0)).collect();
    for commit in reachable.iter().map(|id| &history.commits[id]) {
        for parent in &commit.parents {
            *children.get_mut(parent).ok_or("missing blame parent")? += 1;
        }
    }
    let mut ready: BTreeSet<_> = children
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut pending: BTreeMap<String, Vec<Piece>> = BTreeMap::from([(
        history.tip.clone(),
        vec![Piece {
            tip: query,
            at: query,
        }],
    )]);
    let mut report = BlameReport { schema_version: 1, tip: history.tip.clone(), query, first_parent, complete: true, historical_identity_proven: false, interpretation: "physical correspondence from one deterministic byte edit alignment; merge parents may supply multiple candidates; no authors, rename identity, or semantic equivalence is inferred".into(), origins: Vec::new(), frontier: Vec::new(), compared_bytes: 0, edges: 0, records: 0, all_alignments_minimal: true };
    let mut cache = BTreeMap::<(String, String), Gaps>::new();
    while let Some(id) = ready.pop_first() {
        let node = &history.commits[&id];
        let mut pieces = pending.remove(&id).unwrap_or_default();
        pieces.sort_by_key(|piece| (piece.tip.start, piece.tip.end, piece.at.start, piece.at.end));
        pieces.dedup();
        if !pieces.is_empty() {
            let child_bytes = history
                .blobs
                .get(&node.wasm)
                .ok_or("selected blame file is absent")?;
            let parents: Vec<_> = node
                .parents
                .iter()
                .take(if first_parent { 1 } else { usize::MAX })
                .collect();
            let mut mappings = Vec::new();
            let mut stopped = None;
            for parent in &parents {
                if report.edges >= limits.max_edges {
                    stopped = Some("edge_budget");
                    break;
                }
                report.edges += 1;
                if absent.contains(*parent) {
                    continue;
                }
                let parent_node = &history.commits[*parent];
                let parent_bytes = &history.blobs[&parent_node.wasm];
                let key = (parent_node.wasm.clone(), node.wasm.clone());
                let gap = if parent_node.wasm == node.wasm {
                    vec![(
                        Span {
                            start: 0,
                            end: child_bytes.len(),
                        },
                        Span {
                            start: 0,
                            end: child_bytes.len(),
                        },
                    )]
                } else if let Some(cached) = cache.get(&key) {
                    cached.clone()
                } else {
                    let cost = parent_bytes
                        .len()
                        .checked_add(child_bytes.len())
                        .ok_or("blame byte budget overflow")?;
                    if cost
                        > limits
                            .max_compared_bytes
                            .saturating_sub(report.compared_bytes)
                    {
                        stopped = Some("byte_budget");
                        break;
                    }
                    report.compared_bytes += cost;
                    let (gap, minimal) = gaps(parent_bytes, child_bytes)?;
                    report.all_alignments_minimal &= minimal;
                    cache.insert(key, gap.clone());
                    gap
                };
                mappings.push(((*parent).clone(), gap));
            }
            for piece in pieces {
                if piece.at.end > child_bytes.len()
                    || piece.at.end - piece.at.start != piece.tip.end - piece.tip.start
                {
                    return Err("invalid blame correspondence".into());
                }
                if let Some(reason) = stopped {
                    report.frontier.push(Frontier {
                        commit: id.clone(),
                        tip_span: piece.tip,
                        commit_span: piece.at,
                        reason: reason.into(),
                    });
                    continue;
                }
                let mut cuts = BTreeSet::from([piece.at.start, piece.at.end]);
                for (_, gaps) in &mappings {
                    for (child, _) in gaps {
                        let start = piece.at.start.max(child.start);
                        let end = piece.at.end.min(child.end);
                        if start < end {
                            cuts.insert(start);
                            cuts.insert(end);
                        }
                    }
                }
                let cuts: Vec<_> = cuts.into_iter().collect();
                let reserve = (cuts.len() - 1).saturating_mul(mappings.len().max(1));
                if reserve > limits.max_records.saturating_sub(report.records)
                    || cuts.len().saturating_sub(1) > limits.max_ranges_per_commit
                {
                    report.frontier.push(Frontier {
                        commit: id.clone(),
                        tip_span: piece.tip,
                        commit_span: piece.at,
                        reason: "record_or_range_budget".into(),
                    });
                    continue;
                }
                for window in cuts.windows(2) {
                    let at = Span {
                        start: window[0],
                        end: window[1],
                    };
                    let tip_span = Span {
                        start: piece.tip.start + at.start - piece.at.start,
                        end: piece.tip.start + at.end - piece.at.start,
                    };
                    let mut inherited = false;
                    for (parent, gaps) in &mappings {
                        for (child_gap, parent_gap) in gaps {
                            if child_gap.start <= at.start && at.end <= child_gap.end {
                                let parent_span = Span {
                                    start: parent_gap.start + at.start - child_gap.start,
                                    end: parent_gap.start + at.end - child_gap.start,
                                };
                                pending.entry(parent.clone()).or_default().push(Piece {
                                    tip: tip_span,
                                    at: parent_span,
                                });
                                report.records += 1;
                                inherited = true;
                                break;
                            }
                        }
                    }
                    if !inherited {
                        report.origins.push(Origin {
                            commit: id.clone(),
                            tip_span,
                            origin_span: at,
                            reason: if parents.is_empty() {
                                "root"
                            } else if mappings.is_empty() {
                                "file_introduced"
                            } else {
                                "changed_on_all_selected_parents"
                            }
                            .into(),
                        });
                        report.records += 1;
                    }
                }
            }
        }
        for parent in &node.parents {
            let count = children.get_mut(parent).ok_or("missing parent count")?;
            *count -= 1;
            if *count == 0 {
                ready.insert(parent.clone());
            }
        }
    }
    report.origins.sort_by_key(|origin| {
        (
            origin.tip_span.start,
            origin.tip_span.end,
            origin.commit.clone(),
            origin.origin_span.start,
        )
    });
    report.origins.dedup();
    for origin in &report.origins {
        let original = &history.blobs[&history.commits[&origin.commit].wasm];
        if tip_bytes.get(origin.tip_span.start..origin.tip_span.end)
            != original.get(origin.origin_span.start..origin.origin_span.end)
        {
            return Err("blame origin bytes differ from selected tip bytes".into());
        }
    }
    report.complete = report.frontier.is_empty();
    Ok(report)
}
