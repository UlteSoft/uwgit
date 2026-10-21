//! Resolved IR construction.
//!
//! This is the central hub of the pipeline. It consumes Parsed IR, attaches
//! stable function identity, and stays intentionally un-normalized so both diff
//! and future analysis passes can branch from the same resolved module.

use crate::fingerprint::resolved_function_ids;
use crate::ir::{ExternalKindIr, ModuleIr, ParsedModule, ResolvedModule};

pub fn resolve_module(parsed: ParsedModule) -> ResolvedModule {
    let mut module = parsed.module;
    attach_function_exports(&mut module);
    refresh_function_stable_ids(&mut module);
    ResolvedModule::from_module(module)
}

fn attach_function_exports(module: &mut ModuleIr) {
    for export in &module.exports {
        if export.kind != ExternalKindIr::Func {
            continue;
        }
        if let Some(function) = module.functions.get_mut(export.item_index as usize) {
            function.export_names.push(export.name.clone());
        }
    }
    for function in &mut module.functions {
        function.export_names.sort();
    }
}

impl ParsedModule {
    pub fn resolve(self) -> ResolvedModule {
        resolve_module(self)
    }
}

fn refresh_function_stable_ids(module: &mut ModuleIr) {
    let ids = resolved_function_ids(module);
    for (function, id) in module.functions.iter_mut().zip(ids) {
        function.id = id;
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_module;
    use crate::ir::FunctionKindIr;
    use crate::parse::parse_module;

    #[test]
    fn resolve_attaches_exports_and_stable_ids() {
        let parsed = parse_module(include_bytes!("../tests/fixtures/old.wasm")).unwrap();
        assert_eq!(parsed.functions[0].export_names, Vec::<String>::new());

        let resolved = resolve_module(parsed);

        let function = &resolved.functions[0];
        assert_eq!(function.kind, FunctionKindIr::Defined);
        assert_eq!(function.export_names, ["add"]);
        assert_eq!(function.id, "func:export:add:type:i32,i32->i32");
        assert!(function.fingerprint.is_none());
    }

    #[test]
    fn unexported_chain_ids_survive_reordering_and_unused_imports() {
        let old = resolve_module(
            parse_module(
                &wat::parse_str(
                    "(module
                        (func $leaf (result i32) i32.const 7)
                        (func $mid (result i32) call $leaf)
                        (func $top (result i32) call $mid))",
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let new = resolve_module(
            parse_module(
                &wat::parse_str(
                    "(module
                        (import \"env\" \"unused\" (func))
                        (func $top (result i32) call $mid)
                        (func $leaf (result i32) i32.const 7)
                        (func $mid (result i32) call $leaf))",
                )
                .unwrap(),
            )
            .unwrap(),
        );

        for (old_index, new_index) in [(0, 2), (1, 3), (2, 1)] {
            assert_eq!(old.functions[old_index].id, new.functions[new_index].id);
        }
        for module in [&old, &new] {
            for (function, fingerprint) in module
                .functions
                .iter()
                .zip(crate::fingerprint::module_fingerprints(module))
            {
                assert!(fingerprint.reference_context_complete);
                assert_eq!(function.id, fingerprint.stable_id);
            }
        }
    }

    #[test]
    fn deep_unexported_chain_uses_iterative_callee_first_identity_resolution() {
        const DEPTH: usize = 1024;
        let chain = |reverse: bool| {
            let mut text = String::from("(module ");
            for position in 0..DEPTH {
                let index = if reverse {
                    DEPTH - position - 1
                } else {
                    position
                };
                let body = if index == 0 {
                    "i32.const 7".to_owned()
                } else {
                    format!("call $f{}", index - 1)
                };
                text.push_str(&format!("(func $f{index} (result i32) {body})"));
            }
            text.push(')');
            resolve_module(parse_module(&wat::parse_str(text).unwrap()).unwrap())
        };
        let forward = chain(false);
        let reverse = chain(true);

        for index in 0..DEPTH {
            assert_eq!(
                forward.functions[index].id,
                reverse.functions[DEPTH - index - 1].id
            );
        }
        for module in [&forward, &reverse] {
            assert!(crate::fingerprint::module_fingerprints(module)
                .iter()
                .all(|fingerprint| fingerprint.reference_context_complete));
        }
    }
}
