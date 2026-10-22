//! Recreate exact native conflict sides without touching the working copy.
//! Resolve-undo images live in the same canonical, atomically replaced index.
use super::*;

pub(super) fn unresolve(index: &mut Index, paths: &[String]) -> Result<Vec<String>, String> {
    let mut selected = BTreeSet::new();
    for path in paths {
        validate_tree_path(path)?;
        selected.insert(path.clone());
    }
    let mut target = index.clone();
    let mut restored = Vec::new();
    for path in selected {
        let Some(stages) = target.resolve_undo.remove(&path) else {
            continue;
        };
        // An already unmerged path keeps its current sides. As with a normal
        // reinstatement, consuming its old undo record is explicit here.
        if target.conflicts.contains_key(&path) {
            continue;
        }
        target.files.remove(&path);
        target.intents.remove(&path);
        target.flags.remove(&path);
        target.conflicts.insert(path.clone(), stages);
        restored.push(path);
    }
    target.tidy();
    validate_index(&target)?;
    *index = target;
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sides() -> ConflictStages {
        ConflictStages {
            base: Some(WASM.to_vec()),
            ours: Some([WASM.as_slice(), &[0, 3, 1, b'x', 1]].concat()),
            // An unknown section must survive without a semantic validator.
            theirs: Some([WASM.as_slice(), &[255, 1, 254]].concat()),
        }
    }

    #[test]
    fn resolve_undo_upgrades_without_changing_old_index_encodings_or_images() {
        for (version, magic) in [(2, MAGIC), (3, STAGED_MAGIC), (4, FLAGS_MAGIC)] {
            let mut index = Index::empty();
            index.format = version;
            index.files.insert("a.wasm".into(), WASM.to_vec());
            let bytes = [magic.as_slice(), &canonical(&index).unwrap()].concat();
            assert_eq!(index_bytes(&decode_index(&bytes).unwrap()).unwrap(), bytes);
        }
        let mut old = OLD_MAGIC.to_vec();
        old.extend_from_slice(&6u64.to_le_bytes());
        old.extend_from_slice(&8u64.to_le_bytes());
        old.extend_from_slice(b"a.wasm");
        old.extend_from_slice(WASM);
        assert_eq!(decode_index(&old).unwrap().files["a.wasm"], WASM);

        let mut index = Index::empty();
        index.format = 3;
        index.conflicts.insert("a.wasm".into(), sides());
        index.resolve_path("a.wasm");
        index.files.insert("a.wasm".into(), WASM.to_vec());
        index.flags.insert(
            "a.wasm".into(),
            IndexFlags {
                skip_worktree: true,
                ..IndexFlags::default()
            },
        );
        index.intents.insert("later.wasm".into());
        let bytes = index_bytes(&index).unwrap();
        assert!(bytes.starts_with(RESOLVE_MAGIC));
        assert_eq!(decode_index(&bytes).unwrap(), index);
        assert_eq!(index.resolve_undo["a.wasm"], sides());
        index.resolve_undo.clear();
        let bytes = index_bytes(&index).unwrap();
        assert!(bytes.starts_with(RESOLVE_MAGIC));
        assert!(decode_index(&bytes).unwrap().skipped("a.wasm"));
    }

    #[test]
    fn malformed_undo_images_names_versions_and_unknown_fields_fail_closed() {
        let mut good = Index::empty();
        good.format = 5;
        good.resolve_undo.insert("a.wasm".into(), sides());
        for bad in 0..6 {
            let mut index = good.clone();
            match bad {
                0 => {
                    index.resolve_undo.insert("../outside".into(), sides());
                }
                1 => {
                    index
                        .resolve_undo
                        .insert("a.wasm".into(), ConflictStages::default());
                }
                2 => {
                    index.resolve_undo.get_mut("a.wasm").unwrap().ours = Some(vec![]);
                }
                3 => index.format = 4,
                4 => {
                    index.flags.insert(
                        "missing.wasm".into(),
                        IndexFlags {
                            skip_worktree: true,
                            ..IndexFlags::default()
                        },
                    );
                }
                _ => index.format = 6,
            }
            let bytes = [RESOLVE_MAGIC.as_slice(), &canonical(&index).unwrap()].concat();
            assert!(decode_index(&bytes).is_err(), "case {bad}");
        }
        let mut payload = serde_json::to_vec(&good).unwrap();
        payload.pop();
        payload.extend_from_slice(b",\"output_path\":\"/tmp/forged\"}\n");
        let error = decode_index(&[RESOLVE_MAGIC.as_slice(), &payload].concat()).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
        let mut bytes = index_bytes(&good).unwrap();
        bytes[8] = 4;
        assert!(decode_index(&bytes).is_err());
    }

    #[test]
    fn unresolve_validates_a_complete_structural_selection_before_consuming_any_record() {
        let mut index = Index::empty();
        index.format = 5;
        index.files.insert("node/child.wasm".into(), WASM.to_vec());
        index.resolve_undo.insert(
            "node".into(),
            ConflictStages {
                ours: Some(WASM.to_vec()),
                ..ConflictStages::default()
            },
        );
        index.resolve_undo.insert(
            "node/child.wasm".into(),
            ConflictStages {
                theirs: Some(WASM.to_vec()),
                ..ConflictStages::default()
            },
        );
        let before = index.clone();
        assert!(unresolve(&mut index, &["node".into()]).is_err());
        assert_eq!(index, before);
        assert!(unresolve(&mut index, &["node/child.wasm".into(), "../bad".into()]).is_err());
        assert_eq!(index, before);
        assert_eq!(
            unresolve(&mut index, &["node/child.wasm".into(), "node".into()]).unwrap(),
            ["node", "node/child.wasm"]
        );
        assert!(index.resolve_undo.is_empty());
        assert!(index.files.is_empty());
        assert_eq!(index.conflicts["node"].image(2), Some(&WASM.to_vec()));
        assert_eq!(
            index.conflicts["node/child.wasm"].image(3),
            Some(&WASM.to_vec())
        );
    }

    #[test]
    fn replay_checkpoint_binds_saved_undo_images_to_its_index_preimage() {
        use crate::repository::{ReplayCheckpoint, ReplayImages};
        let mut index = Index::empty();
        index.format = 5;
        index.files.insert("a.wasm".into(), WASM.to_vec());
        index.resolve_undo.insert("a.wasm".into(), sides());
        let bytes = index_bytes(&index).unwrap();
        let images = ReplayImages {
            files: index.files.clone(),
            conflicts: BTreeMap::new(),
        };
        let mut checkpoint = ReplayCheckpoint {
            action: "continue".into(),
            index_before: Some(bytes.clone()),
            index_after: bytes,
            work_before: files_worktree(&index.files),
            work_after: files_worktree(&index.files),
            owned_before: keys(&index.files),
        };
        validate_replay_checkpoint(&checkpoint, &images, None, None).unwrap();
        index.resolve_undo.clear();
        checkpoint.index_after = index_bytes(&index).unwrap();
        assert!(validate_replay_checkpoint(&checkpoint, &images, None, None)
            .unwrap_err()
            .contains("resolve-undo"));
    }
}
