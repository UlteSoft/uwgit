//! Export-independent, conservative correspondence of static function graphs.
//!
//! These witnesses compare typed function bodies and direct function operands.
//! They do not establish historical identity, runtime behavior, Core validity,
//! or correspondence of the other module index spaces.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;

use crate::diff::ImportBindingEvidence;
use crate::ir::{
    ExternalKindIr, FunctionIr, FunctionKindIr, Immediate, LocalIr, ModuleIr, Opcode, TypeRefIr,
};

const SCOPE: &str = "unique_static_function_dependencies_without_export_roles";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyGraph {
    pub scope: String,
    pub identity_unproven: bool,
    pub nodes: Vec<DependencyNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyNode {
    pub old_source_index: u32,
    pub new_source_index: u32,
    pub kind: String,
    pub depth: usize,
    pub type_id: String,
    pub import: Option<ImportBindingEvidence>,
    pub references: Vec<DependencyReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyReference {
    pub old_operator_index: usize,
    pub new_operator_index: usize,
    pub old_offset: u64,
    pub new_offset: u64,
    pub opcode: String,
    pub old_target: u32,
    pub new_target: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyRoot {
    pub old_source_index: u32,
    pub new_source_index: u32,
    pub depth: usize,
}

impl DependencyGraph {
    pub fn empty() -> Self {
        Self {
            scope: SCOPE.into(),
            identity_unproven: true,
            nodes: Vec::new(),
        }
    }

    pub fn build(old: &ModuleIr, new: &ModuleIr) -> Self {
        let mut graph = Self::empty();
        let mut old_side = Side::new(old);
        let mut new_side = Side::new(new);
        let mut forward = BTreeMap::<u32, ProvenTarget>::new();
        let mut reverse = BTreeMap::<u32, ProvenTarget>::new();
        let mut groups = BTreeMap::<String, ReadyGroup>::new();

        loop {
            // Register the complete ready batch before considering any pair.
            // A group keeps all its members after pairing: consuming a match
            // must never turn a duplicate key into a unique key.
            let mut touched = BTreeSet::new();
            old_side.register_ready(true, &forward, &mut groups, &mut touched);
            new_side.register_ready(false, &reverse, &mut groups, &mut touched);
            let mut proposed = Vec::new();
            for key in touched {
                let group = &groups[&key];
                let ([old_index], [new_index]) = (&group.old[..], &group.new[..]) else {
                    continue;
                };
                if forward.contains_key(old_index) || reverse.contains_key(new_index) {
                    continue;
                }
                let Some(node) = dependency_node(
                    &old_side.functions[old_index],
                    &new_side.functions[new_index],
                    &forward,
                    &reverse,
                ) else {
                    continue;
                };
                proposed.push(node);
            }
            if proposed.is_empty() {
                break;
            }
            // No node in this batch may rely on another new node in the same
            // batch. All reference edges therefore point to a smaller depth.
            for node in proposed {
                let old_index = node.old_source_index;
                let new_index = node.new_source_index;
                forward.insert(
                    old_index,
                    ProvenTarget {
                        counterpart: new_index,
                        depth: node.depth,
                    },
                );
                reverse.insert(
                    new_index,
                    ProvenTarget {
                        counterpart: old_index,
                        depth: node.depth,
                    },
                );
                old_side.proven(old_index);
                new_side.proven(new_index);
                graph.nodes.push(node);
            }
        }
        graph.nodes.sort_by_key(|node| node.old_source_index);
        graph
    }

    pub fn root(&self, old_source_index: u32) -> Option<DependencyRoot> {
        let position = self
            .nodes
            .binary_search_by_key(&old_source_index, |node| node.old_source_index)
            .ok()?;
        let node = &self.nodes[position];
        Some(DependencyRoot {
            old_source_index: node.old_source_index,
            new_source_index: node.new_source_index,
            depth: node.depth,
        })
    }
}

#[derive(Clone, Copy)]
struct ProvenTarget {
    counterpart: u32,
    depth: usize,
}

struct FunctionState<'a> {
    function: &'a FunctionIr,
    import: Option<ImportBindingEvidence>,
    pending: usize,
    blocked: bool,
    submitted: bool,
}

struct Side<'a> {
    functions: BTreeMap<u32, FunctionState<'a>>,
    dependants: BTreeMap<u32, Vec<u32>>,
    ready: VecDeque<u32>,
}

impl<'a> Side<'a> {
    fn new(module: &'a ModuleIr) -> Self {
        let mut by_index = BTreeMap::<u32, Vec<&FunctionIr>>::new();
        for function in &module.functions {
            by_index
                .entry(function.source_index)
                .or_default()
                .push(function);
        }
        let unique: BTreeMap<_, _> = by_index
            .into_iter()
            .filter_map(|(index, functions)| match &functions[..] {
                [function] => Some((index, *function)),
                _ => None,
            })
            .collect();
        let mut imports = Vec::new();
        let mut import_counts = BTreeMap::<String, usize>::new();
        for import in module
            .imports
            .iter()
            .filter(|import| import.kind == ExternalKindIr::Func)
        {
            let binding = match &import.type_ref {
                TypeRefIr::Func {
                    type_index,
                    type_id,
                    exact,
                } => {
                    let binding = ImportBindingEvidence {
                        module: import.module.clone(),
                        name: import.name.clone(),
                        type_id: type_id.clone(),
                        exact: *exact,
                    };
                    let key = import_key(&binding);
                    *import_counts.entry(key).or_default() += 1;
                    Some((*type_index, binding))
                }
                _ => None,
            };
            // Function indices count function imports, not all import entries.
            imports.push(binding);
        }
        let mut functions = BTreeMap::new();
        let mut dependants = BTreeMap::<u32, Vec<u32>>::new();
        let mut ready = VecDeque::new();
        for (&index, &function) in &unique {
            // Pending counts callee nodes, while the final witness retains
            // every reference position, including repeated calls to one node.
            let dependencies: BTreeSet<_> = function
                .operators
                .iter()
                .filter_map(|operator| static_target(&operator.immediate))
                .collect();
            let mut blocked = function.operators.iter().any(|operator| {
                matches!(operator.opcode, Opcode::Unrecognized(_))
                    || matches!(operator.immediate, Immediate::Unrecognized(_))
            }) || dependencies
                .iter()
                .any(|target| !unique.contains_key(target));
            let import = if function.kind == FunctionKindIr::Imported {
                let binding = usize::try_from(index)
                    .ok()
                    .and_then(|position| imports.get(position))
                    .and_then(Option::as_ref)
                    .filter(|(type_index, binding)| {
                        *type_index == function.type_index && binding.type_id == function.type_id
                    })
                    .map(|(_, binding)| binding.clone());
                blocked |= binding
                    .as_ref()
                    .is_none_or(|binding| import_counts.get(&import_key(binding)) != Some(&1))
                    || !function.operators.is_empty()
                    || !function.locals.is_empty();
                binding
            } else {
                // A defined function cannot occupy an imported function slot.
                blocked |= usize::try_from(index)
                    .ok()
                    .is_some_and(|position| position < imports.len());
                None
            };
            let pending = dependencies.len();
            if !blocked {
                for target in dependencies {
                    dependants.entry(target).or_default().push(index);
                }
                if pending == 0 {
                    ready.push_back(index);
                }
            }
            functions.insert(
                index,
                FunctionState {
                    function,
                    import,
                    pending,
                    blocked,
                    submitted: false,
                },
            );
        }
        Self {
            functions,
            dependants,
            ready,
        }
    }

    fn register_ready(
        &mut self,
        old_side: bool,
        proven: &BTreeMap<u32, ProvenTarget>,
        groups: &mut BTreeMap<String, ReadyGroup>,
        touched: &mut BTreeSet<String>,
    ) {
        while let Some(index) = self.ready.pop_front() {
            let state = self
                .functions
                .get_mut(&index)
                .expect("ready function exists");
            if state.blocked || state.submitted || state.pending != 0 {
                continue;
            }
            state.submitted = true;
            let Some(key) = ready_key(state, old_side, proven) else {
                continue;
            };
            let group = groups.entry(key.clone()).or_default();
            if old_side {
                group.old.push(index);
            } else {
                group.new.push(index);
            }
            touched.insert(key);
        }
    }

    fn proven(&mut self, index: u32) {
        if let Some(dependants) = self.dependants.remove(&index) {
            for dependant in dependants {
                let state = self
                    .functions
                    .get_mut(&dependant)
                    .expect("dependant function exists");
                state.pending -= 1;
                if state.pending == 0 {
                    self.ready.push_back(dependant);
                }
            }
        }
    }
}

#[derive(Default)]
struct ReadyGroup {
    old: Vec<u32>,
    new: Vec<u32>,
}

#[derive(Serialize)]
enum FunctionKey<'a> {
    Import(&'a ImportBindingEvidence),
    Defined {
        type_id: &'a str,
        locals: &'a [LocalIr],
        operators: Vec<OperatorKey<'a>>,
    },
}

#[derive(Serialize)]
struct OperatorKey<'a> {
    opcode: &'a Opcode,
    immediate: OperandKey<'a>,
}

#[derive(Serialize)]
enum OperandKey<'a> {
    Unchanged(&'a Immediate),
    Call(u32),
    RefFunc(u32),
}

fn import_key(binding: &ImportBindingEvidence) -> String {
    serde_json::to_string(&FunctionKey::Import(binding)).expect("import binding serializes")
}

fn ready_key(
    state: &FunctionState<'_>,
    old_side: bool,
    proven: &BTreeMap<u32, ProvenTarget>,
) -> Option<String> {
    if let Some(binding) = &state.import {
        return Some(import_key(binding));
    }
    let mut operators = Vec::with_capacity(state.function.operators.len());
    for operator in &state.function.operators {
        let mapped_target = |target: u32| {
            proven
                .get(&target)
                .map(|entry| if old_side { entry.counterpart } else { target })
        };
        let immediate = match &operator.immediate {
            Immediate::Call(target) => OperandKey::Call(mapped_target(*target)?),
            Immediate::RefFunc(target) => OperandKey::RefFunc(mapped_target(*target)?),
            other => OperandKey::Unchanged(other),
        };
        operators.push(OperatorKey {
            opcode: &operator.opcode,
            immediate,
        });
    }
    Some(
        serde_json::to_string(&FunctionKey::Defined {
            type_id: &state.function.type_id,
            locals: &state.function.locals,
            operators,
        })
        .expect("typed function key serializes"),
    )
}

fn static_target(immediate: &Immediate) -> Option<u32> {
    match immediate {
        Immediate::Call(target) | Immediate::RefFunc(target) => Some(*target),
        _ => None,
    }
}

fn dependency_node(
    old: &FunctionState<'_>,
    new: &FunctionState<'_>,
    forward: &BTreeMap<u32, ProvenTarget>,
    reverse: &BTreeMap<u32, ProvenTarget>,
) -> Option<DependencyNode> {
    let a = old.function;
    let b = new.function;
    if a.kind != b.kind || a.type_id != b.type_id || a.locals != b.locals {
        return None;
    }
    if a.kind == FunctionKindIr::Imported {
        if old.import != new.import || old.import.is_none() {
            return None;
        }
        return Some(DependencyNode {
            old_source_index: a.source_index,
            new_source_index: b.source_index,
            kind: "unique_import_binding".into(),
            depth: 0,
            type_id: a.type_id.clone(),
            import: old.import.clone(),
            references: Vec::new(),
        });
    }
    if a.operators.len() != b.operators.len() {
        return None;
    }
    let mut references = Vec::new();
    let mut depth = 0;
    for (index, (old_operator, new_operator)) in a.operators.iter().zip(&b.operators).enumerate() {
        if old_operator.opcode != new_operator.opcode {
            return None;
        }
        let targets = match (&old_operator.immediate, &new_operator.immediate) {
            (Immediate::Call(a), Immediate::Call(b))
            | (Immediate::RefFunc(a), Immediate::RefFunc(b)) => Some((*a, *b)),
            (a, b) if a == b => None,
            _ => return None,
        };
        if let Some((old_target, new_target)) = targets {
            let old_proof = forward.get(&old_target)?;
            let new_proof = reverse.get(&new_target)?;
            if old_proof.counterpart != new_target
                || new_proof.counterpart != old_target
                || old_proof.depth != new_proof.depth
            {
                return None;
            }
            depth = depth.max(old_proof.depth.checked_add(1)?);
            references.push(DependencyReference {
                old_operator_index: index,
                new_operator_index: index,
                old_offset: old_operator.offset,
                new_offset: new_operator.offset,
                opcode: old_operator.opcode.as_str().into(),
                old_target,
                new_target,
            });
        }
    }
    Some(DependencyNode {
        old_source_index: a.source_index,
        new_source_index: b.source_index,
        kind: if references.is_empty() {
            "unique_reference_free_body"
        } else {
            "unique_mapped_reference_body"
        }
        .into(),
        depth,
        type_id: a.type_id.clone(),
        import: None,
        references,
    })
}
