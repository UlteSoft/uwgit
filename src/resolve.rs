//! Resolved IR construction.
//!
//! This is the central hub of the pipeline. It consumes Parsed IR, attaches
//! stable function identity, and stays intentionally un-normalized so both diff
//! and future analysis passes can branch from the same resolved module.

use crate::fingerprint::stable_function_id;
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
    let ids = module
        .functions
        .iter()
        .map(|function| stable_function_id(module, function))
        .collect::<Vec<_>>();

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
}
