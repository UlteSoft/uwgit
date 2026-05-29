//! Analysis IR branch.
//!
//! CFG, call graph, reachability, and security analysis derive from the
//! Resolved IR hub, not from Normalized Diff IR.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::ir::{
    AnalysisModule, BasicBlockIr, CallGraphEdgeIr, CallGraphEdgeKindIr, CallGraphIr, CallSiteIr,
    CfgEdgeIr, CfgEdgeKindIr, ElementKindIr, ExternalKindIr, FunctionCfgIr, FunctionIr,
    FunctionKindIr, Immediate, ModuleIr, Opcode, ParsedOperator, ReachabilityIr, ResolvedModule,
    UnsafePathIr, UnsafeSinkIr, UnsafeSinkKindIr,
};

pub fn analysis_module(resolved: &ResolvedModule) -> AnalysisModule {
    let module = resolved.module.clone();
    let cfgs = resolved
        .functions
        .iter()
        .filter(|function| function.kind == FunctionKindIr::Defined)
        .map(|function| build_function_cfg(function, &resolved.module))
        .collect::<Vec<_>>();
    let call_graph = build_call_graph(&module, &cfgs);
    let reachability = build_reachability(&module, &call_graph);
    let unsafe_paths = build_unsafe_paths(&module, &cfgs, &call_graph);

    AnalysisModule::from_parts(module, cfgs, call_graph, reachability, unsafe_paths)
}

impl ResolvedModule {
    pub fn analyze(&self) -> AnalysisModule {
        analysis_module(self)
    }
}

#[derive(Debug, Clone)]
struct FrameInfo {
    kind: FrameKind,
    start_op: usize,
    end_op: Option<usize>,
    else_op: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Block,
    Loop,
    If,
}

fn build_function_cfg(function: &FunctionIr, module: &ModuleIr) -> FunctionCfgIr {
    let operators = &function.operators;
    let frames = collect_frames(operators);
    let next_exec = next_executable_indices(operators);
    let exec_positions = executable_positions(operators);
    let raw_to_exec_pos = exec_positions_map(operators.len(), &exec_positions);
    let leaders = block_leaders(
        operators,
        &exec_positions,
        &raw_to_exec_pos,
        &frames,
        &next_exec,
    );
    let blocks = build_blocks(function, operators, &exec_positions, &leaders);
    let raw_to_block_id = block_lookup(&blocks, operators.len());
    let call_sites = build_call_sites(function, module, &raw_to_block_id);
    let successors_by_raw = operator_successors(operators, &frames, &next_exec, &raw_to_block_id);
    let blocks = finalize_block_successors(blocks, &successors_by_raw);

    FunctionCfgIr {
        function_id: function.id.clone(),
        source_index: function.source_index,
        kind: function.kind,
        entry_block: blocks.first().map(|block| block.id),
        blocks,
        call_sites,
    }
}

fn executable_positions(operators: &[ParsedOperator]) -> Vec<usize> {
    operators
        .iter()
        .enumerate()
        .filter_map(|(index, operator)| (!operator.opcode.is_structural_marker()).then_some(index))
        .collect()
}

fn exec_positions_map(operators_len: usize, exec_positions: &[usize]) -> Vec<Option<usize>> {
    let mut mapping = vec![None; operators_len];
    for (exec_pos, raw_index) in exec_positions.iter().copied().enumerate() {
        mapping[raw_index] = Some(exec_pos);
    }
    mapping
}

fn block_leaders(
    operators: &[ParsedOperator],
    exec_positions: &[usize],
    raw_to_exec_pos: &[Option<usize>],
    frames: &[FrameInfo],
    next_exec: &[Option<usize>],
) -> Vec<bool> {
    let mut leaders = vec![false; exec_positions.len()];
    if let Some(first) = leaders.first_mut() {
        *first = true;
    } else {
        return leaders;
    }

    let mut frame_stack = Vec::new();
    let mut next_frame_id = 0usize;
    let mut previous_was_boundary = true;

    for (raw_index, operator) in operators.iter().enumerate() {
        if operator.opcode.is_structural_marker() {
            match operator.opcode {
                Opcode::Block | Opcode::Loop | Opcode::Catch | Opcode::CatchAll => {
                    frame_stack.push(next_frame_id);
                    next_frame_id += 1;
                }
                Opcode::Else => {}
                Opcode::End => {
                    frame_stack.pop();
                }
                _ => {}
            }
            previous_was_boundary = true;
            continue;
        }

        let Some(exec_pos) = raw_to_exec_pos[raw_index] else {
            continue;
        };

        if previous_was_boundary {
            leaders[exec_pos] = true;
        }

        match &operator.opcode {
            Opcode::If => {
                if let Some(target) = next_exec[raw_index].and_then(|raw| raw_to_exec_pos[raw]) {
                    leaders[target] = true;
                }
                if let Some(frame) = frames.get(next_frame_id) {
                    if let Some(else_op) = frame.else_op {
                        if let Some(target) =
                            next_exec[else_op].and_then(|raw| raw_to_exec_pos[raw])
                        {
                            leaders[target] = true;
                        }
                    } else if let Some(end_op) = frame.end_op {
                        if let Some(target) = next_exec[end_op].and_then(|raw| raw_to_exec_pos[raw])
                        {
                            leaders[target] = true;
                        }
                    }
                }
                frame_stack.push(next_frame_id);
                next_frame_id += 1;
            }
            Opcode::Br
            | Opcode::BrIf
            | Opcode::BrOnNull
            | Opcode::BrOnNonNull
            | Opcode::BrOnCast
            | Opcode::BrOnCastFail
            | Opcode::BrTable
            | Opcode::Return
            | Opcode::Unreachable
            | Opcode::Throw
            | Opcode::ThrowRef
            | Opcode::Rethrow
            | Opcode::Delegate
            | Opcode::ReturnCall
            | Opcode::ReturnCallIndirect
            | Opcode::ReturnCallRef
            | Opcode::TryTable => {
                if let Some(target) = next_exec[raw_index].and_then(|raw| raw_to_exec_pos[raw]) {
                    leaders[target] = true;
                }
            }
            _ => {}
        }

        previous_was_boundary = is_block_ending_opcode(&operator.opcode);
    }

    leaders
}

fn is_block_ending_opcode(opcode: &Opcode) -> bool {
    matches!(
        opcode,
        Opcode::If
            | Opcode::Br
            | Opcode::BrIf
            | Opcode::BrTable
            | Opcode::Return
            | Opcode::Unreachable
            | Opcode::Throw
            | Opcode::ThrowRef
            | Opcode::Rethrow
            | Opcode::Delegate
            | Opcode::ReturnCall
            | Opcode::ReturnCallIndirect
            | Opcode::ReturnCallRef
            | Opcode::TryTable
            | Opcode::BrOnNull
            | Opcode::BrOnNonNull
            | Opcode::BrOnCast
            | Opcode::BrOnCastFail
    )
}

fn build_blocks(
    function: &FunctionIr,
    operators: &[ParsedOperator],
    exec_positions: &[usize],
    leaders: &[bool],
) -> Vec<BasicBlockIr> {
    let mut blocks = Vec::new();
    let mut current_start = None;

    for (exec_pos, raw_index) in exec_positions.iter().copied().enumerate() {
        if leaders[exec_pos] {
            if let Some(start_exec_pos) = current_start.take() {
                blocks.push(build_block(
                    blocks.len(),
                    operators,
                    exec_positions,
                    start_exec_pos,
                    exec_pos - 1,
                ));
            }
            current_start = Some(exec_pos);
        }

        if exec_pos + 1 == exec_positions.len() {
            if let Some(start_exec_pos) = current_start.take() {
                blocks.push(build_block(
                    blocks.len(),
                    operators,
                    exec_positions,
                    start_exec_pos,
                    exec_pos,
                ));
            }
        } else if leaders[exec_pos + 1] {
            // None means no active block to finish; scanning continues
            // until the next leader initialises a new block.
            if let Some(start_exec_pos) = current_start.take() {
                blocks.push(build_block(
                    blocks.len(),
                    operators,
                    exec_positions,
                    start_exec_pos,
                    exec_pos,
                ));
            }
        }

        let _ = raw_index;
    }

    if blocks.is_empty() && !exec_positions.is_empty() {
        blocks.push(build_block(
            0,
            operators,
            exec_positions,
            0,
            exec_positions.len() - 1,
        ));
    }

    let _ = function;
    blocks
}

fn build_block(
    id: usize,
    operators: &[ParsedOperator],
    exec_positions: &[usize],
    start_exec_pos: usize,
    end_exec_pos: usize,
) -> BasicBlockIr {
    let operator_indices = exec_positions[start_exec_pos..=end_exec_pos].to_vec();
    let block_operators = operator_indices
        .iter()
        .map(|raw_index| operators[*raw_index].clone())
        .collect::<Vec<_>>();
    let start_operator_index = operator_indices.first().copied().unwrap_or(0);
    let end_operator_index = operator_indices.last().copied().unwrap_or(0);

    BasicBlockIr {
        id,
        start_operator_index,
        end_operator_index,
        start_offset: block_operators.first().map(|operator| operator.offset),
        end_offset: block_operators.last().map(|operator| operator.offset),
        operator_indices,
        operators: block_operators,
        successors: Vec::new(),
    }
}

fn finalize_block_successors(
    mut blocks: Vec<BasicBlockIr>,
    successors_by_raw: &[Vec<CfgEdgeIr>],
) -> Vec<BasicBlockIr> {
    for block in &mut blocks {
        if let Some(last_raw_index) = block.operator_indices.last().copied() {
            block.successors = successors_by_raw[last_raw_index].clone();
        }
    }
    blocks
}

fn block_lookup(blocks: &[BasicBlockIr], operators_len: usize) -> Vec<Option<usize>> {
    let mut lookup = vec![None; operators_len];
    for block in blocks {
        for raw_index in &block.operator_indices {
            lookup[*raw_index] = Some(block.id);
        }
    }
    lookup
}

fn build_call_sites(
    function: &FunctionIr,
    module: &ModuleIr,
    raw_to_block_id: &[Option<usize>],
) -> Vec<CallSiteIr> {
    function
        .operators
        .iter()
        .enumerate()
        .filter_map(|(operator_index, operator)| {
            let block_id = raw_to_block_id[operator_index]?;
            let target_function_index = operator.immediate.call_function_index();
            let target_function_id = target_function_index.and_then(|index| {
                module
                    .functions
                    .get(index as usize)
                    .map(|target| target.id.clone())
            });

            if !is_call_opcode(&operator.opcode) {
                return None;
            }

            Some(CallSiteIr {
                operator_index,
                block_id,
                offset: operator.offset,
                operator: operator.clone(),
                target_function_index,
                target_function_id,
                opcode: operator.opcode.as_str().to_owned(),
                tail_call: matches!(
                    operator.opcode,
                    Opcode::ReturnCall | Opcode::ReturnCallIndirect | Opcode::ReturnCallRef
                ),
            })
        })
        .collect()
}

fn is_call_opcode(opcode: &Opcode) -> bool {
    matches!(
        opcode,
        Opcode::Call
            | Opcode::CallIndirect
            | Opcode::CallRef
            | Opcode::ReturnCall
            | Opcode::ReturnCallIndirect
            | Opcode::ReturnCallRef
    )
}

fn operator_successors(
    operators: &[ParsedOperator],
    frames: &[FrameInfo],
    next_exec: &[Option<usize>],
    raw_to_block_id: &[Option<usize>],
) -> Vec<Vec<CfgEdgeIr>> {
    let mut frame_stack = Vec::new();
    let mut next_frame_id = 0usize;
    let mut successors = vec![Vec::new(); operators.len()];

    for (raw_index, operator) in operators.iter().enumerate() {
        if operator.opcode.is_structural_marker() {
            match operator.opcode {
                Opcode::Block | Opcode::Loop | Opcode::Catch | Opcode::CatchAll => {
                    frame_stack.push(next_frame_id);
                    next_frame_id += 1;
                }
                Opcode::Else => {}
                Opcode::End => {
                    frame_stack.pop();
                }
                _ => {}
            }
            continue;
        }

        let mut edges = Vec::new();
        let fallthrough = next_exec[raw_index].and_then(|raw| raw_to_block_id[raw]);

        match &operator.opcode {
            Opcode::If => {
                if let Some(target) = fallthrough {
                    edges.push(CfgEdgeIr {
                        kind: CfgEdgeKindIr::BranchTaken,
                        target_block: Some(target),
                    });
                }
                if let Some(target) = if let Some(frame) = frames.get(next_frame_id) {
                    if let Some(else_op) = frame.else_op {
                        next_exec[else_op].and_then(|raw| raw_to_block_id[raw])
                    } else if let Some(end_op) = frame.end_op {
                        next_exec[end_op].and_then(|raw| raw_to_block_id[raw])
                    } else {
                        None
                    }
                } else {
                    None
                } {
                    edges.push(CfgEdgeIr {
                        kind: CfgEdgeKindIr::BranchNotTaken,
                        target_block: Some(target),
                    });
                }

                frame_stack.push(next_frame_id);
                next_frame_id += 1;
            }
            Opcode::Br => {
                if let Some(target) =
                    branch_target(operator, &frame_stack, frames, next_exec, raw_to_block_id)
                {
                    edges.push(CfgEdgeIr {
                        kind: CfgEdgeKindIr::BranchTaken,
                        target_block: Some(target),
                    });
                }
            }
            Opcode::BrIf | Opcode::BrOnNull | Opcode::BrOnNonNull => {
                if let Some(target) =
                    branch_target(operator, &frame_stack, frames, next_exec, raw_to_block_id)
                {
                    edges.push(CfgEdgeIr {
                        kind: CfgEdgeKindIr::BranchTaken,
                        target_block: Some(target),
                    });
                }
                if let Some(target) = fallthrough {
                    edges.push(CfgEdgeIr {
                        kind: CfgEdgeKindIr::BranchNotTaken,
                        target_block: Some(target),
                    });
                }
            }
            Opcode::BrOnCast | Opcode::BrOnCastFail => {
                if let Some(target) =
                    branch_target(operator, &frame_stack, frames, next_exec, raw_to_block_id)
                {
                    edges.push(CfgEdgeIr {
                        kind: CfgEdgeKindIr::BranchTaken,
                        target_block: Some(target),
                    });
                }
                if let Some(target) = fallthrough {
                    edges.push(CfgEdgeIr {
                        kind: CfgEdgeKindIr::BranchNotTaken,
                        target_block: Some(target),
                    });
                }
            }
            Opcode::BrTable => {
                if let Immediate::BrTable {
                    targets,
                    default_target,
                } = &operator.immediate
                {
                    for depth in targets.iter().copied() {
                        if let Some(target) = branch_target_at_depth(
                            depth,
                            &frame_stack,
                            frames,
                            next_exec,
                            raw_to_block_id,
                        ) {
                            edges.push(CfgEdgeIr {
                                kind: CfgEdgeKindIr::BranchTableTarget,
                                target_block: Some(target),
                            });
                        }
                    }
                    if let Some(target) = branch_target_at_depth(
                        *default_target,
                        &frame_stack,
                        frames,
                        next_exec,
                        raw_to_block_id,
                    ) {
                        edges.push(CfgEdgeIr {
                            kind: CfgEdgeKindIr::BranchTableDefault,
                            target_block: Some(target),
                        });
                    }
                }
            }
            Opcode::Return
            | Opcode::Unreachable
            | Opcode::Throw
            | Opcode::ThrowRef
            | Opcode::Rethrow
            | Opcode::Delegate
            | Opcode::ReturnCall
            | Opcode::ReturnCallIndirect
            | Opcode::ReturnCallRef
            | Opcode::TryTable => {
                edges.push(CfgEdgeIr {
                    kind: if matches!(
                        operator.opcode,
                        Opcode::Return
                            | Opcode::ReturnCall
                            | Opcode::ReturnCallIndirect
                            | Opcode::ReturnCallRef
                    ) {
                        CfgEdgeKindIr::Return
                    } else {
                        CfgEdgeKindIr::Trap
                    },
                    target_block: None,
                });
            }
            _ => {
                if let Some(target) = fallthrough {
                    edges.push(CfgEdgeIr {
                        kind: CfgEdgeKindIr::Fallthrough,
                        target_block: Some(target),
                    });
                }
            }
        }

        successors[raw_index] = edges;
    }

    successors
}

fn collect_frames(operators: &[ParsedOperator]) -> Vec<FrameInfo> {
    let mut frames = Vec::new();
    let mut stack = Vec::new();

    for (index, operator) in operators.iter().enumerate() {
        match operator.opcode {
            Opcode::Block => {
                stack.push(frames.len());
                frames.push(FrameInfo {
                    kind: FrameKind::Block,
                    start_op: index,
                    end_op: None,
                    else_op: None,
                });
            }
            Opcode::Loop => {
                stack.push(frames.len());
                frames.push(FrameInfo {
                    kind: FrameKind::Loop,
                    start_op: index,
                    end_op: None,
                    else_op: None,
                });
            }
            Opcode::If => {
                stack.push(frames.len());
                frames.push(FrameInfo {
                    kind: FrameKind::If,
                    start_op: index,
                    end_op: None,
                    else_op: None,
                });
            }
            Opcode::Catch | Opcode::CatchAll => {
                stack.push(frames.len());
                frames.push(FrameInfo {
                    kind: FrameKind::Block,
                    start_op: index,
                    end_op: None,
                    else_op: None,
                });
            }
            Opcode::Else => {
                if let Some(frame_index) = stack.last().copied() {
                    frames[frame_index].else_op = Some(index);
                }
            }
            Opcode::End => {
                if let Some(frame_index) = stack.pop() {
                    frames[frame_index].end_op = Some(index);
                }
            }
            _ => {}
        }
    }

    frames
}

fn next_executable_indices(operators: &[ParsedOperator]) -> Vec<Option<usize>> {
    let mut next_exec = vec![None; operators.len()];
    let mut next = None;

    for index in (0..operators.len()).rev() {
        next_exec[index] = next;
        if !operators[index].opcode.is_structural_marker() {
            next = Some(index);
        }
    }

    next_exec
}

fn branch_target(
    operator: &ParsedOperator,
    frame_stack: &[usize],
    frames: &[FrameInfo],
    next_exec: &[Option<usize>],
    raw_to_block_id: &[Option<usize>],
) -> Option<usize> {
    match &operator.immediate {
        Immediate::Branch(depth) => {
            branch_target_at_depth(*depth, frame_stack, frames, next_exec, raw_to_block_id)
        }
        Immediate::BrOnCast { label, .. } => {
            branch_target_at_depth(*label, frame_stack, frames, next_exec, raw_to_block_id)
        }
        _ => None,
    }
}

fn branch_target_at_depth(
    depth: u32,
    frame_stack: &[usize],
    frames: &[FrameInfo],
    next_exec: &[Option<usize>],
    raw_to_block_id: &[Option<usize>],
) -> Option<usize> {
    let depth = depth as usize;
    let frame_index = frame_stack.len().checked_sub(depth + 1)?;
    let frame_id = *frame_stack.get(frame_index)?;
    let frame = frames.get(frame_id)?;

    let raw_target = match frame.kind {
        FrameKind::Loop => next_exec.get(frame.start_op).copied().flatten(),
        FrameKind::Block | FrameKind::If => {
            let end_op = frame.end_op?;
            next_exec.get(end_op).copied().flatten()
        }
    }?;

    raw_to_block_id.get(raw_target).copied().flatten()
}

fn build_call_graph(module: &ModuleIr, cfgs: &[FunctionCfgIr]) -> CallGraphIr {
    let roots = root_function_ids(module);
    let mut edges = Vec::new();

    for cfg in cfgs {
        for call_site in &cfg.call_sites {
            edges.extend(call_graph_edges_for_call_site(module, cfg, call_site));
        }
    }

    let roots = dedup_sorted(roots);
    let (reachable_functions, reachable_imports, unreachable_functions) =
        call_graph_reachability(module, &roots, &edges);

    CallGraphIr {
        roots: roots.clone(),
        edges,
        reachable_functions,
        reachable_imports,
        unreachable_functions,
    }
}

fn root_function_ids(module: &ModuleIr) -> Vec<String> {
    let mut roots = module
        .functions
        .iter()
        .filter(|function| !function.export_names.is_empty())
        .map(|function| function.id.clone())
        .collect::<Vec<_>>();

    if let Some(start_function) = module.start_function_index.and_then(|index| {
        module
            .functions
            .get(index as usize)
            .map(|function| function.id.clone())
    }) {
        roots.push(start_function);
    }

    dedup_sorted(roots)
}

fn call_graph_edges_for_call_site(
    module: &ModuleIr,
    cfg: &FunctionCfgIr,
    call_site: &CallSiteIr,
) -> Vec<CallGraphEdgeIr> {
    let edge_kind = match &call_site.operator.opcode {
        Opcode::Call => CallGraphEdgeKindIr::Direct,
        Opcode::ReturnCall => CallGraphEdgeKindIr::TailDirect,
        Opcode::CallIndirect => CallGraphEdgeKindIr::Indirect,
        Opcode::ReturnCallIndirect => CallGraphEdgeKindIr::TailIndirect,
        Opcode::CallRef => CallGraphEdgeKindIr::Ref,
        Opcode::ReturnCallRef => CallGraphEdgeKindIr::TailRef,
        _ => return Vec::new(),
    };

    let mut callee_ids = Vec::new();
    match &call_site.operator.opcode {
        Opcode::Call | Opcode::ReturnCall => {
            if let Some(id) = call_site.target_function_id.clone() {
                callee_ids.push(id);
            }
        }
        Opcode::CallIndirect | Opcode::ReturnCallIndirect => {
            if let Some((type_id, table_index)) =
                call_site.operator.immediate.call_indirect_target(module)
            {
                callee_ids.extend(indirect_call_target_ids(module, &type_id, table_index));
            }
        }
        Opcode::CallRef | Opcode::ReturnCallRef => {
            if let Some(type_id) = call_site.operator.immediate.call_ref_type_id(module) {
                callee_ids.extend(
                    module
                        .functions
                        .iter()
                        .filter(|function| function.type_id == type_id)
                        .map(|function| function.id.clone()),
                );
            }
        }
        _ => {}
    }

    callee_ids
        .into_iter()
        .map(|callee_function_id| CallGraphEdgeIr {
            caller_function_id: cfg.function_id.clone(),
            callee_function_id,
            call_site_index: call_site.operator_index,
            call_site_offset: call_site.offset,
            kind: edge_kind,
        })
        .collect()
}

fn indirect_call_target_ids(module: &ModuleIr, type_id: &str, table_index: u32) -> Vec<String> {
    if table_targets_are_dynamic(module, table_index) {
        return type_matching_function_ids(module, type_id);
    }

    let mut callee_ids = module
        .tables
        .iter()
        .filter(|table| table.index == table_index)
        .filter_map(|table| table.init_function_index)
        .chain(
            module
                .elements
                .iter()
                .filter(|element| {
                    element.kind == ElementKindIr::Active
                        && element.table_index == Some(table_index)
                })
                .flat_map(|element| element.function_indices.iter().copied()),
        )
        .filter_map(|function_index| module.functions.get(function_index as usize))
        .filter(|function| function.type_id == type_id)
        .map(|function| function.id.clone())
        .collect::<Vec<_>>();

    callee_ids.sort();
    callee_ids.dedup();
    callee_ids
}

fn type_matching_function_ids(module: &ModuleIr, type_id: &str) -> Vec<String> {
    module
        .functions
        .iter()
        .filter(|function| function.type_id == type_id)
        .map(|function| function.id.clone())
        .collect()
}

fn table_targets_are_dynamic(module: &ModuleIr, table_index: u32) -> bool {
    table_index < imported_table_count(module)
        || defined_table_has_unknown_init(module, table_index)
        || active_table_has_unknown_items(module, table_index)
        || module
            .functions
            .iter()
            .flat_map(|function| &function.operators)
            .any(|operator| table_mutation_may_affect(operator, table_index))
}

fn defined_table_has_unknown_init(module: &ModuleIr, table_index: u32) -> bool {
    module
        .tables
        .iter()
        .any(|table| table.index == table_index && table.has_unknown_init)
}

fn imported_table_count(module: &ModuleIr) -> u32 {
    module
        .imports
        .iter()
        .filter(|import| import.kind == ExternalKindIr::Table)
        .count() as u32
}

fn active_table_has_unknown_items(module: &ModuleIr, table_index: u32) -> bool {
    module.elements.iter().any(|element| {
        element.kind == ElementKindIr::Active
            && element.table_index == Some(table_index)
            && element.has_unknown_items
    })
}

fn table_mutation_may_affect(operator: &ParsedOperator, table_index: u32) -> bool {
    match (&operator.opcode, &operator.immediate) {
        (
            Opcode::TableSet | Opcode::TableGrow | Opcode::TableFill,
            Immediate::TableIndex(index),
        ) => *index == table_index,
        (
            Opcode::TableCopy,
            Immediate::TableCopy {
                dst_table,
                src_table: _,
            },
        ) => *dst_table == table_index,
        (Opcode::TableInit, _) => true,
        _ => false,
    }
}

fn call_graph_reachability(
    module: &ModuleIr,
    roots: &[String],
    edges: &[CallGraphEdgeIr],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut adjacency: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for edge in edges {
        adjacency
            .entry(edge.caller_function_id.as_str())
            .or_default()
            .insert(edge.callee_function_id.as_str());
    }

    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::new();
    for root in roots {
        if reachable.insert(root.as_str()) {
            queue.push_back(root.as_str());
        }
    }

    while let Some(function_id) = queue.pop_front() {
        if let Some(next_functions) = adjacency.get(function_id) {
            for next_function in next_functions {
                if reachable.insert(next_function) {
                    queue.push_back(next_function);
                }
            }
        }
    }

    let reachable_functions = module
        .functions
        .iter()
        .filter(|function| reachable.contains(function.id.as_str()))
        .map(|function| function.id.clone())
        .collect::<Vec<_>>();
    let reachable_imports = module
        .functions
        .iter()
        .filter(|function| {
            function.kind == FunctionKindIr::Imported && reachable.contains(function.id.as_str())
        })
        .map(|function| function.id.clone())
        .collect::<Vec<_>>();
    let unreachable_functions = module
        .functions
        .iter()
        .filter(|function| !reachable.contains(function.id.as_str()))
        .map(|function| function.id.clone())
        .collect::<Vec<_>>();

    (
        reachable_functions,
        reachable_imports,
        unreachable_functions,
    )
}

fn build_reachability(module: &ModuleIr, call_graph: &CallGraphIr) -> ReachabilityIr {
    ReachabilityIr {
        roots: call_graph.roots.clone(),
        reachable_functions: call_graph.reachable_functions.clone(),
        reachable_imports: call_graph.reachable_imports.clone(),
        unreachable_functions: module
            .functions
            .iter()
            .filter(|function| !call_graph.reachable_functions.contains(&function.id))
            .map(|function| function.id.clone())
            .collect(),
    }
}

fn build_unsafe_paths(
    module: &ModuleIr,
    cfgs: &[FunctionCfgIr],
    call_graph: &CallGraphIr,
) -> Vec<UnsafePathIr> {
    let mut predecessors: BTreeMap<&str, &str> = BTreeMap::new();
    let mut queue = VecDeque::new();
    let reachable_roots = call_graph
        .roots
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let adjacency =
        call_graph
            .edges
            .iter()
            .fold(BTreeMap::<&str, Vec<&str>>::new(), |mut map, edge| {
                map.entry(edge.caller_function_id.as_str())
                    .or_default()
                    .push(edge.callee_function_id.as_str());
                map
            });

    for root in reachable_roots {
        queue.push_back(root);
        predecessors.entry(root).or_insert(root);
    }

    while let Some(function_id) = queue.pop_front() {
        if let Some(next_functions) = adjacency.get(function_id) {
            for next_function in next_functions {
                if !predecessors.contains_key(next_function) {
                    predecessors.insert(next_function, function_id);
                    queue.push_back(next_function);
                }
            }
        }
    }

    let cfg_by_function_id = cfgs
        .iter()
        .map(|cfg| (cfg.function_id.as_str(), cfg))
        .collect::<BTreeMap<_, _>>();

    let mut paths = Vec::new();
    for function in module
        .functions
        .iter()
        .filter(|function| function.kind == FunctionKindIr::Defined)
    {
        let Some(cfg) = cfg_by_function_id.get(function.id.as_str()) else {
            continue;
        };
        let Some(sink) = first_unsafe_sink(cfg) else {
            continue;
        };
        if !call_graph
            .reachable_functions
            .iter()
            .any(|reachable| reachable == &function.id)
        {
            continue;
        }

        let function_path = reconstruct_function_path(&function.id, &predecessors);
        if function_path.is_empty() {
            continue;
        }

        paths.push(UnsafePathIr {
            entry_function_id: function_path
                .first()
                .cloned()
                .unwrap_or_else(|| function.id.clone()),
            function_path,
            sink,
        });
    }

    paths
}

fn first_unsafe_sink(cfg: &FunctionCfgIr) -> Option<UnsafeSinkIr> {
    for block in &cfg.blocks {
        for (offset, operator) in block.operators.iter().enumerate() {
            let Some(kind) = unsafe_sink_kind(&operator.opcode) else {
                continue;
            };
            return Some(UnsafeSinkIr {
                function_id: cfg.function_id.clone(),
                block_id: block.id,
                operator_index: block.operator_indices[offset],
                offset: operator.offset,
                opcode: operator.opcode.as_str().to_owned(),
                kind,
            });
        }
    }
    None
}

fn unsafe_sink_kind(opcode: &Opcode) -> Option<UnsafeSinkKindIr> {
    match opcode {
        Opcode::Unreachable => Some(UnsafeSinkKindIr::Trap),
        Opcode::CallIndirect
        | Opcode::ReturnCallIndirect
        | Opcode::CallRef
        | Opcode::ReturnCallRef => Some(UnsafeSinkKindIr::IndirectCall),
        Opcode::Throw
        | Opcode::ThrowRef
        | Opcode::Rethrow
        | Opcode::Delegate
        | Opcode::TryTable => Some(UnsafeSinkKindIr::Exception),
        Opcode::MemoryCopy | Opcode::MemoryFill | Opcode::MemoryInit | Opcode::DataDrop => {
            Some(UnsafeSinkKindIr::MemoryBulk)
        }
        Opcode::TableCopy | Opcode::TableFill | Opcode::TableInit | Opcode::ElemDrop => {
            Some(UnsafeSinkKindIr::TableBulk)
        }
        Opcode::I32Load
        | Opcode::I64Load
        | Opcode::F32Load
        | Opcode::F64Load
        | Opcode::I32Load8S
        | Opcode::I32Load8U
        | Opcode::I32Load16S
        | Opcode::I32Load16U
        | Opcode::I64Load8S
        | Opcode::I64Load8U
        | Opcode::I64Load16S
        | Opcode::I64Load16U
        | Opcode::I64Load32S
        | Opcode::I64Load32U
        | Opcode::I32Store
        | Opcode::I64Store
        | Opcode::F32Store
        | Opcode::F64Store
        | Opcode::I32Store8
        | Opcode::I32Store16
        | Opcode::I64Store8
        | Opcode::I64Store16
        | Opcode::I64Store32
        | Opcode::MemoryGrow
        | Opcode::MemorySize => Some(UnsafeSinkKindIr::MemoryAccess),
        Opcode::TableGet | Opcode::TableSet | Opcode::TableSize | Opcode::TableGrow => {
            Some(UnsafeSinkKindIr::TableAccess)
        }
        _ => None,
    }
}

fn reconstruct_function_path(
    function_id: &str,
    predecessors: &BTreeMap<&str, &str>,
) -> Vec<String> {
    let mut path = Vec::new();
    let mut current = function_id;
    let mut guard = 0usize;

    loop {
        path.push(current.to_owned());
        let Some(previous) = predecessors.get(current).copied() else {
            break;
        };
        if previous == current {
            break;
        }
        current = previous;
        guard += 1;
        if guard > predecessors.len() + 1 {
            break;
        }
    }

    path.reverse();
    path
}

fn dedup_sorted(items: Vec<String>) -> Vec<String> {
    let mut items = items;
    items.sort();
    items.dedup();
    items
}

trait ImmediateAnalysisExt {
    fn call_indirect_target(&self, module: &ModuleIr) -> Option<(String, u32)>;
    fn call_ref_type_id(&self, module: &ModuleIr) -> Option<String>;
}

impl ImmediateAnalysisExt for Immediate {
    fn call_indirect_target(&self, module: &ModuleIr) -> Option<(String, u32)> {
        match self {
            Immediate::CallIndirect {
                type_index,
                table_index,
            } => module
                .types
                .get(*type_index as usize)
                .map(|ty| (ty.id.clone(), *table_index)),
            _ => None,
        }
    }

    fn call_ref_type_id(&self, module: &ModuleIr) -> Option<String> {
        match self {
            Immediate::CallRef(type_index) => module
                .types
                .get(*type_index as usize)
                .map(|ty| ty.id.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::analysis_module;
    use crate::ir::{
        CallGraphEdgeKindIr, CfgEdgeKindIr, FunctionIr, FunctionKindIr, Immediate, ModuleIr,
        Opcode, ParsedOperator, ResolvedModule, TypeIr,
    };
    use crate::parse::parse_module;
    use crate::resolve::resolve_module;

    fn sample_operator(offset: u64, opcode: Opcode, immediate: Immediate) -> ParsedOperator {
        ParsedOperator {
            offset,
            opcode,
            immediate,
        }
    }

    #[test]
    fn analysis_branch_starts_from_resolved_ir() {
        let resolved =
            resolve_module(parse_module(include_bytes!("../tests/fixtures/old.wasm")).unwrap());

        let analysis = analysis_module(&resolved);

        assert_eq!(analysis.functions[0].id, resolved.functions[0].id);
        assert!(analysis.functions[0].fingerprint.is_none());
        assert_eq!(analysis.cfgs.len(), 1);
        assert!(!analysis.cfgs[0].blocks.is_empty());
        assert_eq!(analysis.cfgs[0].call_sites.len(), 0);
        assert_eq!(analysis.cfgs[0].entry_block, Some(0));
        assert_eq!(
            analysis.call_graph.roots,
            vec![resolved.functions[0].id.clone()]
        );
        assert_eq!(analysis.reachability.roots, analysis.call_graph.roots);
    }

    #[test]
    fn analysis_includes_start_function_as_root() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]);
        bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        bytes.extend_from_slice(&[0x08, 0x01, 0x00]);
        bytes.extend_from_slice(&[
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
        ]);

        let resolved = resolve_module(parse_module(&bytes).unwrap());
        let analysis = analysis_module(&resolved);

        assert_eq!(
            analysis.call_graph.roots,
            vec![resolved.functions[0].id.clone()]
        );
        assert_eq!(analysis.reachability.roots, analysis.call_graph.roots);
        assert_eq!(
            analysis.call_graph.reachable_functions,
            analysis.call_graph.roots
        );
    }

    #[test]
    fn analysis_resolves_call_indirect_from_active_element_table() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\0asm");
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x03, 0x04, 0x03, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x04, 0x04, 0x01, 0x70, 0x00, 0x01]);
        bytes.extend_from_slice(&[
            0x07, 0x09, 0x01, 0x05, b'e', b'n', b't', b'r', b'y', 0x00, 0x00,
        ]);
        bytes.extend_from_slice(&[0x09, 0x07, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x01, 0x01]);
        bytes.extend_from_slice(&[
            0x0a, 0x10, 0x03, 0x07, 0x00, 0x41, 0x00, 0x11, 0x00, 0x00, 0x0b, 0x02, 0x00, 0x0b,
            0x03, 0x00, 0x01, 0x0b,
        ]);

        let resolved = resolve_module(parse_module(&bytes).unwrap());
        let analysis = analysis_module(&resolved);
        let entry_id = resolved.functions[0].id.clone();
        let target_id = resolved.functions[1].id.clone();
        let decoy_id = resolved.functions[2].id.clone();

        assert_eq!(resolved.elements[0].table_index, Some(0));
        assert_eq!(resolved.elements[0].function_indices, vec![1]);
        assert!(analysis.call_graph.edges.iter().any(|edge| {
            edge.caller_function_id == entry_id
                && edge.callee_function_id == target_id
                && edge.kind == CallGraphEdgeKindIr::Indirect
        }));
        assert!(!analysis.call_graph.edges.iter().any(|edge| {
            edge.caller_function_id == entry_id
                && edge.callee_function_id == decoy_id
                && edge.kind == CallGraphEdgeKindIr::Indirect
        }));
    }

    #[test]
    fn analysis_merges_linear_ops_into_basic_blocks() {
        let mut module = ModuleIr::new();
        module.types.push(TypeIr {
            id: "type:void->void".to_owned(),
            source_index: 0,
            params: vec![],
            results: vec![],
        });
        module.functions.push(FunctionIr {
            id: "func:entry".to_owned(),
            source_index: 0,
            type_index: 0,
            type_id: "type:void->void".to_owned(),
            kind: FunctionKindIr::Defined,
            export_names: vec!["entry".to_owned()],
            locals: vec![],
            operators: vec![
                sample_operator(0, Opcode::Nop, Immediate::None),
                sample_operator(1, Opcode::Nop, Immediate::None),
                sample_operator(2, Opcode::If, Immediate::BlockType("void".to_owned())),
                sample_operator(3, Opcode::Nop, Immediate::None),
                sample_operator(4, Opcode::End, Immediate::None),
                sample_operator(5, Opcode::Return, Immediate::None),
            ],
            direct_calls: vec![],
            fingerprint: None,
        });

        let resolved = ResolvedModule::from_module(module);
        let analysis = analysis_module(&resolved);

        assert_eq!(analysis.cfgs[0].blocks.len(), 3);
        assert_eq!(analysis.cfgs[0].blocks[0].operators.len(), 3);
        assert_eq!(analysis.cfgs[0].blocks[0].successors.len(), 2);
        assert_eq!(analysis.cfgs[0].blocks[1].operators.len(), 1);
        assert_eq!(
            analysis.cfgs[0].blocks[1].successors[0].kind,
            CfgEdgeKindIr::Fallthrough
        );
        assert_eq!(
            analysis.cfgs[0].blocks[2].successors[0].kind,
            CfgEdgeKindIr::Return
        );
    }

    #[test]
    fn analysis_builds_call_graph_and_unsafe_paths() {
        let mut module = ModuleIr::new();
        module.types.push(TypeIr {
            id: "type:void->void".to_owned(),
            source_index: 0,
            params: vec![],
            results: vec![],
        });
        module.functions.push(FunctionIr {
            id: "func:entry".to_owned(),
            source_index: 0,
            type_index: 0,
            type_id: "type:void->void".to_owned(),
            kind: FunctionKindIr::Defined,
            export_names: vec!["entry".to_owned()],
            locals: vec![],
            operators: vec![
                sample_operator(0, Opcode::Call, Immediate::Call(1)),
                sample_operator(1, Opcode::Call, Immediate::Call(2)),
                sample_operator(2, Opcode::Return, Immediate::None),
            ],
            direct_calls: vec![1, 2],
            fingerprint: None,
        });
        module.functions.push(FunctionIr {
            id: "import:host:sink:func:type:void->void".to_owned(),
            source_index: 1,
            type_index: 0,
            type_id: "type:void->void".to_owned(),
            kind: FunctionKindIr::Imported,
            export_names: vec![],
            locals: vec![],
            operators: vec![],
            direct_calls: vec![],
            fingerprint: None,
        });
        module.functions.push(FunctionIr {
            id: "func:unsafe".to_owned(),
            source_index: 2,
            type_index: 0,
            type_id: "type:void->void".to_owned(),
            kind: FunctionKindIr::Defined,
            export_names: vec![],
            locals: vec![],
            operators: vec![sample_operator(
                0,
                Opcode::I32Store,
                Immediate::MemArg {
                    align: 2,
                    offset: 0,
                },
            )],
            direct_calls: vec![],
            fingerprint: None,
        });

        let resolved = ResolvedModule::from_module(module);
        let analysis = analysis_module(&resolved);

        assert!(analysis
            .call_graph
            .edges
            .iter()
            .any(|edge| edge.caller_function_id == "func:entry"
                && edge.callee_function_id == "import:host:sink:func:type:void->void"
                && edge.kind == CallGraphEdgeKindIr::Direct));
        assert!(analysis
            .reachability
            .reachable_imports
            .contains(&"import:host:sink:func:type:void->void".to_owned()));
        assert!(analysis.unsafe_paths.iter().any(|path| path.function_path
            == vec!["func:entry".to_owned(), "func:unsafe".to_owned()]
            && path.sink.function_id == "func:unsafe"));
    }

    #[test]
    fn cfg_handles_minimal_function_without_panic() {
        let mut module = ModuleIr::new();
        module.functions.push(FunctionIr {
            id: "func:empty".to_owned(),
            source_index: 0,
            type_index: 0,
            type_id: "type:void->void".to_owned(),
            kind: FunctionKindIr::Defined,
            export_names: vec![],
            locals: vec![],
            operators: vec![],
            direct_calls: vec![],
            fingerprint: None,
        });

        let resolved = ResolvedModule::from_module(module);
        let analysis = analysis_module(&resolved);

        assert_eq!(analysis.cfgs.len(), 1);
        assert!(analysis.cfgs[0].blocks.is_empty());
        assert_eq!(analysis.cfgs[0].entry_block, None);
        assert_eq!(analysis.cfgs[0].call_sites.len(), 0);
    }

    #[test]
    fn cfg_handles_branches_without_unwrap() {
        let mut module = ModuleIr::new();
        module.types.push(TypeIr {
            id: "type:void->void".to_owned(),
            source_index: 0,
            params: vec![],
            results: vec![],
        });
        module.functions.push(FunctionIr {
            id: "func:branchy".to_owned(),
            source_index: 0,
            type_index: 0,
            type_id: "type:void->void".to_owned(),
            kind: FunctionKindIr::Defined,
            export_names: vec!["branchy".to_owned()],
            locals: vec![],
            operators: vec![
                sample_operator(0, Opcode::Nop, Immediate::None),
                sample_operator(1, Opcode::Nop, Immediate::None),
                sample_operator(2, Opcode::If, Immediate::BlockType("void".to_owned())),
                sample_operator(3, Opcode::Nop, Immediate::None),
                sample_operator(4, Opcode::Else, Immediate::None),
                sample_operator(5, Opcode::Nop, Immediate::None),
                sample_operator(6, Opcode::End, Immediate::None),
                sample_operator(7, Opcode::Return, Immediate::None),
            ],
            direct_calls: vec![],
            fingerprint: None,
        });

        let resolved = ResolvedModule::from_module(module);
        let analysis = analysis_module(&resolved);

        assert_eq!(analysis.cfgs.len(), 1);
        let cfg = &analysis.cfgs[0];
        assert_eq!(cfg.blocks.len(), 4, "expected 4 basic blocks");
        assert_eq!(cfg.blocks[0].successors.len(), 2);
        assert_eq!(cfg.blocks[1].successors.len(), 1);
        assert_eq!(cfg.blocks[2].successors.len(), 1);
        assert_eq!(cfg.blocks[3].successors.len(), 1);
        assert_eq!(cfg.entry_block, Some(0));
    }

    #[test]
    fn analysis_classifies_table_ops_as_table_access() {
        let mut module = ModuleIr::new();
        module.functions.push(FunctionIr {
            id: "func:table".to_owned(),
            source_index: 0,
            type_index: 0,
            type_id: "type:void->void".to_owned(),
            kind: FunctionKindIr::Defined,
            export_names: vec!["table".to_owned()],
            locals: vec![],
            operators: vec![sample_operator(
                0,
                Opcode::TableGet,
                Immediate::TableIndex(0),
            )],
            direct_calls: vec![],
            fingerprint: None,
        });

        let resolved = ResolvedModule::from_module(module);
        let analysis = analysis_module(&resolved);

        assert_eq!(
            analysis.unsafe_paths[0].sink.kind,
            crate::ir::UnsafeSinkKindIr::TableAccess
        );
    }
}
