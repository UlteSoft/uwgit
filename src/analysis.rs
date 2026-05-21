//! Analysis IR branch.
//!
//! CFG, CallGraph, reachability, and security analysis should derive from the
//! Resolved IR hub, not from Normalized Diff IR.

use crate::ir::{AnalysisModule, ResolvedModule};

pub fn analysis_module(resolved: &ResolvedModule) -> AnalysisModule {
    AnalysisModule::from_module(resolved.module.clone())
}

#[cfg(test)]
mod tests {
    use super::analysis_module;
    use crate::parse::parse_module;
    use crate::resolve::resolve_module;

    #[test]
    fn analysis_branch_starts_from_resolved_ir() {
        let resolved =
            resolve_module(parse_module(include_bytes!("../tests/fixtures/old.wasm")).unwrap());

        let analysis = analysis_module(&resolved);

        assert_eq!(analysis.functions[0].id, resolved.functions[0].id);
        assert!(analysis.functions[0].fingerprint.is_none());
    }
}
