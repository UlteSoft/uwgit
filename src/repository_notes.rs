//! Transferable annotations encoded as ordinary original-byte Wasm modules.
//! Their dedicated native branch is included in existing bundles and remotes.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Note {
    version: u32,
    target: String,
    text: String,
}

pub enum NotesRequest {
    List(Option<String>),
    Show(String),
    Set {
        target: String,
        message: String,
        force: bool,
        append: bool,
    },
    Copy {
        source: String,
        target: String,
        force: bool,
    },
    Remove {
        targets: Vec<String>,
        ignore_missing: bool,
    },
}

fn push_u32(mut value: u32, bytes: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        bytes.push(low | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}
fn encode_note(note: &Note) -> RepositoryResult<Vec<u8>> {
    if note.version != 1 || note.text.len() > 1024 * 1024 {
        return Err("note text must be at most 1 MiB".into());
    }
    require_id(&note.target)?;
    let payload = serde_json::to_vec(note).map_err(|error| error.to_string())?;
    let mut custom = Vec::new();
    push_u32(14, &mut custom);
    custom.extend_from_slice(b"uwgit.notes.v1");
    custom.extend_from_slice(&payload);
    let mut module = WASM_HEADER.to_vec();
    module.push(0);
    push_u32(
        u32::try_from(custom.len()).map_err(|_| "note module too large")?,
        &mut module,
    );
    module.extend(custom);
    Ok(module)
}
fn decode_note(bytes: &[u8]) -> RepositoryResult<Note> {
    let mut payload = None;
    for packet in wasmparser::Parser::new(0).parse_all(bytes) {
        match packet.map_err(|error| error.to_string())? {
            wasmparser::Payload::Version {
                encoding: wasmparser::Encoding::Module,
                ..
            }
            | wasmparser::Payload::End(_) => {}
            wasmparser::Payload::CustomSection(reader)
                if reader.name() == "uwgit.notes.v1" && payload.is_none() =>
            {
                payload = Some(reader.data())
            }
            _ => {
                return Err("notes branch contains a module outside the native notes layout".into())
            }
        }
    }
    let note: Note =
        serde_json::from_slice(payload.ok_or("notes module has no annotation payload")?)
            .map_err(|error| error.to_string())?;
    if encode_note(&note)? != bytes {
        return Err("non-canonical native notes module".into());
    }
    Ok(note)
}
fn target(snapshot: &Snapshot, reference: &str) -> RepositoryResult<String> {
    if valid_id(reference) {
        Ok(reference.into())
    } else {
        snapshot_revision(snapshot, reference)
    }
}

pub(super) fn retention_roots(snapshot: &Snapshot) -> RepositoryResult<Vec<String>> {
    let roots = snapshot
        .manifest
        .refs
        .iter()
        .filter(|(name, _)| name.starts_with("uwgit-notes-"))
        .map(|(_, id)| id.clone());
    let reachable = reachable_from_roots(roots, &snapshot.objects)?;
    Ok(reachable
        .into_iter()
        .filter_map(|id| match snapshot.objects.get(&id) {
            Some(Object::Wasm(bytes)) => decode_note(bytes).ok().map(|note| note.target),
            _ => None,
        })
        .filter(|id| snapshot.objects.contains_key(id))
        .collect())
}

impl Repository {
    pub fn notes(&self, namespace: &str, request: NotesRequest) -> RepositoryResult<Value> {
        validate_ref_name(namespace)?;
        let branch = format!("uwgit-notes-{namespace}");
        validate_ref_name(&branch)?;
        let _lock = self.lock()?;
        let snapshot = self.snapshot()?;
        let old = snapshot.manifest.refs.get(&branch).cloned();
        let mut notes = BTreeMap::new();
        if let Some(old) = &old {
            let selected = snapshot_files(&snapshot, old)?;
            if selected.legacy.is_some() || selected.legacy_path.is_some() {
                return Err("notes branch must contain a native named notes tree".into());
            }
            for (path, bytes) in selected.files {
                let id = path
                    .strip_suffix(".wasm")
                    .ok_or("notes tree contains an unexpected path")?;
                require_id(id)?;
                let note = decode_note(&bytes)?;
                if note.target != id {
                    return Err("note target differs from its tree path".into());
                }
                notes.insert(id.to_owned(), note.text);
            }
        }
        let original_notes = notes.clone();
        match request {
            NotesRequest::List(reference) => {
                let entries: Vec<_> = if let Some(reference) = reference {
                    let id = target(&snapshot, &reference)?;
                    let text = notes
                        .get(&id)
                        .ok_or("object has no note in this namespace")?;
                    vec![json!({"object":id,"text":text})]
                } else {
                    notes
                        .iter()
                        .map(|(id, text)| json!({"object":id,"text":text}))
                        .collect()
                };
                return Ok(
                    json!({"namespace":namespace,"reference":format!("refs/heads/{branch}"),"commit":old,"notes":entries}),
                );
            }
            NotesRequest::Show(reference) => {
                let id = target(&snapshot, &reference)?;
                return Ok(
                    json!({"object":id,"text":notes.get(&id).ok_or("object has no note in this namespace")?}),
                );
            }
            _ => {}
        }
        if snapshot.manifest.head == branch {
            return Err("notes cannot update a branch checked out by the calling worktree".into());
        }
        self.assert_branch_available(&branch)?;
        let operation = match request {
            NotesRequest::Set {
                target: reference,
                message,
                force,
                append,
            } => {
                let id = target(&snapshot, &reference)?;
                if !snapshot.objects.contains_key(&id) {
                    return Err("note target is not a stored object".into());
                }
                if message.is_empty() {
                    return Err("note message must not be empty".into());
                }
                let message = if let Some(old) = notes.get(&id) {
                    if append {
                        format!("{old}\n\n{message}")
                    } else if force {
                        message
                    } else {
                        return Err("object already has a note; use -f or append".into());
                    }
                } else {
                    message
                };
                if message.len() > 1024 * 1024 {
                    return Err("note text exceeds 1 MiB".into());
                }
                notes.insert(id, message);
                "notes-set"
            }
            NotesRequest::Copy {
                source,
                target: reference,
                force,
            } => {
                let source = target(&snapshot, &source)?;
                let id = target(&snapshot, &reference)?;
                if !snapshot.objects.contains_key(&id) {
                    return Err("note target is not a stored object".into());
                }
                let message = notes
                    .get(&source)
                    .ok_or("source object has no note")?
                    .clone();
                if notes.contains_key(&id) && !force {
                    return Err("target object already has a note; use -f".into());
                }
                notes.insert(id, message);
                "notes-copy"
            }
            NotesRequest::Remove {
                targets,
                ignore_missing,
            } => {
                let ids: Vec<_> = targets
                    .iter()
                    .map(|reference| target(&snapshot, reference))
                    .collect::<RepositoryResult<_>>()?;
                if !ignore_missing && ids.iter().any(|id| !notes.contains_key(id)) {
                    return Err("one or more objects have no note; no notes removed".into());
                }
                for id in ids {
                    notes.remove(&id);
                }
                "notes-remove"
            }
            NotesRequest::List(_) | NotesRequest::Show(_) => unreachable!(),
        };
        if notes == original_notes {
            return Ok(
                json!({"namespace":namespace,"commit":old,"status":"unchanged","head_updated":false}),
            );
        }
        let files: BTreeMap<_, _> = notes
            .iter()
            .map(|(id, text)| {
                encode_note(&Note {
                    version: 1,
                    target: id.clone(),
                    text: text.clone(),
                })
                .map(|bytes| (format!("{id}.wasm"), bytes))
            })
            .collect::<RepositoryResult<_>>()?;
        let mut encoded = BTreeMap::new();
        let parents: Vec<_> = old.iter().cloned().collect();
        let commit = prepare_tree_commit(
            &files,
            operation,
            &parents,
            None,
            &snapshot.encoded,
            &mut encoded,
        )?;
        self.install_tree_objects(&encoded, std::slice::from_ref(&commit))?;
        self.write_named_ref("refs", &branch, &commit, operation)?;
        Ok(
            json!({"namespace":namespace,"reference":format!("refs/heads/{branch}"),"old_commit":old,"commit":commit,"notes":notes.len(),"head_updated":false,"index_updated":false,"worktree_updated":false,"transferable":true}),
        )
    }
}
