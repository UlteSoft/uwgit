//! Normalized Diff IR construction.
//!
//! Diff-specific canonical data is derived here from the Resolved IR hub. This
//! keeps CFG/CallGraph/Security analysis free to consume Resolved IR directly.

use crate::fingerprint::module_fingerprints;
use crate::ir::{NormalizedModule, ResolvedModule};

pub fn normalize_module(resolved: &ResolvedModule) -> NormalizedModule {
    let mut module = resolved.module.clone();
    let fingerprints = module_fingerprints(resolved);

    for (function, fingerprint) in module.functions.iter_mut().zip(fingerprints) {
        function.fingerprint = Some(fingerprint);
    }

    NormalizedModule::from_module(module)
}

#[cfg(test)]
mod tests {
    use super::normalize_module;
    use crate::parse::parse_module;
    use crate::resolve::resolve_module;

    #[test]
    fn normalize_adds_diff_fingerprints_without_mutating_resolved() {
        let resolved =
            resolve_module(parse_module(include_bytes!("../tests/fixtures/old.wasm")).unwrap());

        let normalized = normalize_module(&resolved);

        assert!(resolved.functions[0].fingerprint.is_none());
        assert!(normalized.functions[0].fingerprint.is_some());
    }
}
