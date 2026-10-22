//! Native index images and unmerged stages. Every stage stores original Wasm
//! bytes; an absent side is None rather than an invented empty module.
use super::*;
use crate::query_commands::QueryOutput;
use clap::{Parser, Subcommand};
#[path = "index_listing.rs"]
mod listing;

#[derive(Parser)]
#[command(name = "wasm-git")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    LsFiles {
        dir: String,
        #[command(flatten)]
        options: listing::Args,
    },
    ReadTree {
        dir: String,
        #[arg(long,conflicts_with_all=["merge","revisions","prefix"])]
        empty: bool,
        #[arg(short = 'm', long, conflicts_with = "prefix")]
        merge: bool,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(short = 'u', long, conflicts_with = "prefix")]
        update: bool,
        #[arg(short = 'n', long)]
        dry_run: bool,
        revisions: Vec<String>,
    },
    UpdateIndex {
        dir: String,
        #[command(flatten)]
        flags: index_flags::Options,
        #[arg(long)]
        add: bool,
        #[arg(long, conflicts_with_all = ["force_remove","index_info","cacheinfo"])]
        remove: bool,
        #[arg(long,conflicts_with_all=["index_info","cacheinfo"])]
        force_remove: bool,
        #[arg(long,conflicts_with_all=["cacheinfo","paths"])]
        index_info: bool,
        #[arg(long,conflicts_with_all=["index_info","paths"],num_args=1..=3)]
        cacheinfo: Vec<String>,
        #[arg(long,conflicts_with_all=["cacheinfo","paths","index_info"])]
        stdin: bool,
        #[arg(short = 'z')]
        nul: bool,
        #[arg(long)]
        dry_run: bool,
        paths: Vec<String>,
    },
    MergeIndex {
        dir: String,
        #[arg(short = 'a', long)]
        all: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(last = true)]
        paths: Vec<String>,
    },
    /// Materialize selected original index images, preserving index and HEAD.
    CheckoutIndex {
        dir: String,
        #[arg(short = 'a', long, conflicts_with_all=["stdin","paths"])]
        all: bool,
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(long)]
        ignore_skip_worktree_bits: bool,
        #[arg(short = 'q', long)]
        quiet: bool,
        #[arg(short = 'n', long)]
        no_create: bool,
        #[arg(long, conflicts_with = "temp")]
        prefix: Option<String>,
        #[arg(long, default_value="0", value_parser=["0","1","2","3","all"])]
        stage: String,
        #[arg(long)]
        temp: bool,
        #[arg(long, conflicts_with = "paths")]
        stdin: bool,
        #[arg(short = 'z')]
        nul: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(last = true)]
        paths: Vec<String>,
    },
}
pub fn index_command_handles(command: &str) -> bool {
    matches!(
        command,
        "ls-files" | "read-tree" | "update-index" | "merge-index" | "checkout-index"
    )
}
fn input(nul: bool) -> Result<Vec<String>, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err("index input exceeds the 64 MiB limit".into());
    }
    bytes
        .split(|byte| *byte == if nul { 0 } else { b'\n' })
        .filter(|row| !row.is_empty())
        .map(|row| {
            std::str::from_utf8(row)
                .map(str::to_owned)
                .map_err(|_| "index input must be UTF-8".into())
        })
        .collect()
}
const MAX_INPUT: u64 = 64 * 1024 * 1024;
fn temporary_images(
    state: &State,
    images: Vec<(String, Vec<Option<Vec<u8>>>)>,
    nul: bool,
    dry_run: bool,
) -> Result<QueryOutput, String> {
    if dry_run {
        return QueryOutput::json(
            json!({"dry_run":true,"temporary":true,"paths":images.iter().map(|(path,_)|path).collect::<Vec<_>>(),"index_updated":false,"worktree_updated":false,"head_updated":false}),
        );
    }
    let mut created = Vec::new();
    let mut output = String::new();
    let result = (|| {
        for (path, sides) in images {
            let mut names = Vec::new();
            for bytes in sides {
                let Some(bytes) = bytes else {
                    names.push(".".to_owned());
                    continue;
                };
                let name = format!(
                    "uwgit-index-{}-{}.wasm",
                    std::process::id(),
                    SEQUENCE.fetch_add(1, Ordering::Relaxed)
                );
                let full = state.repo.root.join(&name);
                // Register only a file this process created. A preexisting
                // colliding name must never be removed by error cleanup.
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&full)
                    .map_err(|e| error("create index image", &full, e))?;
                created.push(full.clone());
                file.write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|e| error("write index image", &full, e))?;
                names.push(name);
            }
            output.push_str(&names.join(" "));
            output.push('\t');
            output.push_str(&path);
            output.push(if nul { '\0' } else { '\n' });
        }
        File::open(&state.repo.root)
            .and_then(|file| file.sync_all())
            .map_err(|e| error("sync image directory", &state.repo.root, e))?;
        Ok(QueryOutput::new(output, 0))
    })();
    if result.is_err() {
        for path in created {
            let _ = fs::remove_file(path);
        }
    }
    result
}
pub(super) fn restore_side(state: &State, args: &[String]) -> Result<String, String> {
    let mut side = None;
    let mut literal = false;
    let mut paths = Vec::new();
    for value in &args[2..] {
        if literal {
            paths.push(value.clone());
            continue;
        }
        match value.as_str() {
            "--" => literal = true,
            "--ours" if side.is_none() => side = Some(2),
            "--theirs" if side.is_none() => side = Some(3),
            "--worktree" => {}
            option if option.starts_with('-') => {
                return Err(format!("unsupported unmerged restore option: {option}"))
            }
            _ => paths.push(value.clone()),
        }
    }
    if paths.is_empty() {
        return Err("unmerged restore requires explicit path selectors".into());
    }
    let side = side.ok_or("choose --ours or --theirs")?;
    let index = state.index()?.ok_or("no unmerged index")?;
    let selected = select_paths(&index.conflicts.keys().cloned().collect(), &paths)?;
    let owned = controlled_paths(&index);
    let mut work = state.snapshot_worktree(owned.iter().cloned())?;
    for path in &selected {
        work.insert(path.clone(), index.conflicts[path].image(side).cloned());
    }
    let changes = plan(state, &owned, &work)?;
    apply_plan(state, &changes)?;
    Ok(format!(
        "restored {} unmerged work paths from stage {side}; index stages preserved",
        selected.len()
    ))
}
fn wasm_object(repo: &Repository, id: &str) -> Result<Vec<u8>, String> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("cache entries require a complete native object ID".into());
    }
    let (_, kind, bytes) = repo.resolve_object(id)?;
    if kind != "wasm" {
        return Err("index entries require original Wasm objects".into());
    }
    validate_wasm(&bytes)?;
    Ok(bytes)
}
fn set_entry(
    state: &State,
    index: &mut Index,
    mode: &str,
    id: &str,
    stage: u8,
    path: &str,
) -> Result<(), String> {
    validate_tree_path(path)?;
    if stage > 3 {
        return Err("native index accepts stages 0..3".into());
    }
    if mode == "0" {
        index.files.remove(path);
        index.conflicts.remove(path);
        index.intents.remove(path);
        index.flags.remove(path);
        return Ok(());
    }
    if mode != "100644" {
        return Err("native index accepts regular Wasm entries and stages 0..3".into());
    }
    let bytes = wasm_object(&state.repo, id)?;
    index.intents.remove(path);
    index.flags.remove(path);
    if stage == 0 {
        index.conflicts.remove(path);
        index.files.insert(path.into(), bytes);
    } else {
        index.format = index.format.max(3);
        index.files.remove(path);
        let entry = index.conflicts.entry(path.into()).or_default();
        match stage {
            1 => entry.base = Some(bytes),
            2 => entry.ours = Some(bytes),
            3 => entry.theirs = Some(bytes),
            _ => unreachable!(),
        }
    }
    Ok(())
}
fn read_trees(
    state: &State,
    revisions: &[String],
    merge: bool,
    prefix: Option<&str>,
    empty: bool,
) -> Result<Index, String> {
    if empty {
        return Ok(Index::empty());
    }
    if (!merge && revisions.len() != 1) || (merge && !(2..=3).contains(&revisions.len())) {
        return Err("read-tree requires one tree, or -m BASE [OURS] THEIRS".into());
    }
    let snapshots = state.repo.archive_batch(revisions)?;
    let mut sources = Vec::new();
    let mut anchors = BTreeSet::new();
    let previous = state.index()?;
    anchors.extend(
        previous
            .as_ref()
            .and_then(|index| index.legacy_path.clone()),
    );
    if let Some(head) = state.head()? {
        anchors.extend(state.repo.files_at(&head)?.legacy_path);
    }
    for source in snapshots {
        if source.legacy.is_some() {
            return Err("read-tree needs a named Wasm tree".into());
        }
        anchors.extend(source.legacy_path);
        sources.push(source.files);
    }
    if anchors.len() > 1 {
        return Err("read-tree histories have conflicting legacy path anchors".into());
    }
    let anchor = anchors.into_iter().next();
    if let Some(prefix) = prefix {
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        validate_tree_path(prefix)?;
        let mut index = previous.unwrap_or_else(Index::empty);
        require_resolved_index(&index)?;
        index.legacy_path = anchor;
        for (path, bytes) in sources.remove(0) {
            let path = format!("{prefix}/{path}");
            if index.files.insert(path, bytes).is_some() {
                return Err("read-tree prefix would replace an index entry".into());
            }
        }
        validate_index(&index)?;
        return Ok(index);
    }
    let mut result = Index::empty();
    result.legacy_path = anchor;
    if !merge {
        result.files = sources.remove(0);
        return Ok(result);
    }
    let (base, ours, theirs) = if sources.len() == 3 {
        let theirs = sources.pop().unwrap();
        let ours = sources.pop().unwrap();
        (sources.pop().unwrap(), ours, theirs)
    } else {
        let ours = previous.unwrap_or_else(Index::empty);
        require_resolved_index(&ours)?;
        let theirs = sources.pop().unwrap();
        (sources.pop().unwrap(), ours.files, theirs)
    };
    let paths: BTreeSet<_> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .cloned()
        .collect();
    for path in paths {
        let (b, o, t) = (base.get(&path), ours.get(&path), theirs.get(&path));
        let chosen = if o == t || t == b {
            Some(o)
        } else if o == b {
            Some(t)
        } else {
            None
        };
        if let Some(chosen) = chosen {
            if let Some(bytes) = chosen {
                result.files.insert(path, bytes.clone());
            }
        } else {
            result.format = 3;
            result.conflicts.insert(
                path,
                ConflictStages {
                    base: b.cloned(),
                    ours: o.cloned(),
                    theirs: t.cloned(),
                },
            );
        }
    }
    // Trivial per-path selection alone can turn opposite file/directory
    // additions into an invalid resolved tree. Retain the original side
    // images for every member of each structural conflict instead.
    let all_paths = controlled_paths(&result);
    let mut structural = BTreeSet::new();
    for path in &all_paths {
        for (offset, _) in path.match_indices('/') {
            let parent = &path[..offset];
            if all_paths.contains(parent) {
                structural.insert(parent.to_owned());
                structural.insert(path.clone());
            }
        }
    }
    for path in structural {
        result.files.remove(&path);
        result.conflicts.insert(
            path.clone(),
            ConflictStages {
                base: base.get(&path).cloned(),
                ours: ours.get(&path).cloned(),
                theirs: theirs.get(&path).cloned(),
            },
        );
        result.format = 3;
    }
    validate_index(&result)?;
    Ok(result)
}
pub fn index_command(args: &[String]) -> Result<QueryOutput, String> {
    let cli = match Cli::try_parse_from(
        std::iter::once("wasm-git").chain(args.iter().map(String::as_str)),
    ) {
        Ok(cli) => cli,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(QueryOutput::new(error.to_string(), 0))
        }
        Err(error) => return Err(error.to_string()),
    };
    let dir = match &cli.command {
        Action::LsFiles { dir, .. }
        | Action::ReadTree { dir, .. }
        | Action::UpdateIndex { dir, .. }
        | Action::MergeIndex { dir, .. }
        | Action::CheckoutIndex { dir, .. } => dir,
    };
    let state = State::open(dir)?;
    let _lock = state.lock()?;
    state.repo.fsck()?;
    match cli.command {
        Action::CheckoutIndex {
            all,
            force,
            ignore_skip_worktree_bits,
            quiet,
            no_create,
            prefix,
            stage,
            temp,
            stdin,
            nul,
            dry_run,
            mut paths,
            ..
        } => {
            let temporary = temp || stage == "all";
            if temporary && (prefix.is_some() || no_create || force) {
                return Err(
                    "temporary image export cannot combine prefix, no-create, or force".into(),
                );
            }
            if nul && !stdin && !temporary {
                return Err("checkout-index -z requires --stdin or temporary output".into());
            }
            let index = state.index()?.unwrap_or_else(Index::empty);
            if all {
                paths = controlled_paths(&index).into_iter().collect();
            } else if stdin {
                paths = input(nul)?;
            }
            let mut images = Vec::new();
            let mut seen = BTreeSet::new();
            for path in paths {
                validate_tree_path(&path)?;
                if index.skipped(&path) && !ignore_skip_worktree_bits {
                    continue;
                }
                if index.intents.contains(&path) {
                    if quiet {
                        continue;
                    }
                    return Err(format!("intent-to-add has no stored image: {path}"));
                }
                if !seen.insert(path.clone()) {
                    continue;
                }
                if stage == "all" {
                    if let Some(sides) = index.conflicts.get(&path) {
                        images.push((
                            path,
                            (1..=3)
                                .map(|number| sides.image(number).cloned())
                                .collect::<Vec<_>>(),
                        ));
                    } else if !index.files.contains_key(&path) && !quiet {
                        return Err(format!("path is not in the index: {path}"));
                    }
                } else {
                    let bytes = if stage == "0" {
                        index.files.get(&path)
                    } else {
                        let number = stage.parse().map_err(|_| "invalid checkout stage")?;
                        index
                            .conflicts
                            .get(&path)
                            .and_then(|sides| sides.image(number))
                    };
                    if let Some(bytes) = bytes {
                        images.push((path, vec![Some(bytes.clone())]));
                    } else if !quiet {
                        return Err(format!("path has no stage {stage} entry: {path}"));
                    }
                }
            }
            if temporary {
                return temporary_images(&state, images, nul, dry_run);
            }
            let mut desired = Worktree::new();
            let mut owned = BTreeSet::new();
            for (path, mut sides) in images {
                let destination = format!("{}{path}", prefix.as_deref().unwrap_or(""));
                validate_tree_path(&destination)?;
                if destination
                    .split('/')
                    .any(|part| part.eq_ignore_ascii_case(".git"))
                {
                    return Err("checkout-index refuses to write foreign Git metadata".into());
                }
                let current = state.worktree_module(&destination)?;
                if current.is_none() && no_create {
                    continue;
                }
                if current.is_some() && !force {
                    if quiet {
                        continue;
                    }
                    return Err(format!(
                        "checkout-index destination already exists: {destination}; use --force"
                    ));
                }
                desired.insert(destination.clone(), sides.remove(0));
                owned.insert(destination);
            }
            let changes = plan(&state, &owned, &desired)?;
            if dry_run {
                QueryOutput::json(
                    json!({"dry_run":true,"paths":desired.keys().collect::<Vec<_>>(),"index_updated":false,"head_updated":false}),
                )
            } else {
                apply_plan(&state, &changes)?;
                Ok(QueryOutput::new(String::new(), 0))
            }
        }
        Action::LsFiles { options, .. } => listing::run(&state, options),
        Action::ReadTree {
            empty,
            merge,
            prefix,
            update,
            dry_run,
            revisions,
            ..
        } => {
            let mut target = read_trees(&state, &revisions, merge, prefix.as_deref(), empty)?;
            let old = state.index()?.unwrap_or_else(Index::empty);
            if !empty {
                index_flags::inherit(&mut target, &old);
            }
            let changes = if update {
                let owned = controlled_paths(&old);
                let mut work = files_worktree(&target.files);
                work.extend(
                    target
                        .conflicts
                        .iter()
                        .map(|(path, stages)| (path.clone(), stages.ours.clone())),
                );
                // Keep dirty bytes where the selected image is unchanged.
                // If a changed image would discard dirty bytes, reject the
                // entire update before touching either worktree or index.
                let current = state.snapshot_worktree(owned.iter().cloned())?;
                for path in &owned {
                    let expected = old.files.get(path).or_else(|| {
                        old.conflicts
                            .get(path)
                            .and_then(|stages| stages.ours.as_ref())
                    });
                    let desired = work.get(path).and_then(Option::as_ref);
                    let actual = current.get(path).and_then(Option::as_ref);
                    if target.skipped(path) && actual.is_none() {
                        work.insert(path.clone(), None);
                        continue;
                    }
                    if old.skipped(path) && actual.is_none() {
                        continue;
                    }
                    if desired == expected {
                        work.insert(path.clone(), actual.cloned());
                    } else if actual != expected {
                        return Err(format!(
                            "read-tree -u would discard dirty work bytes at {path}"
                        ));
                    }
                }
                Some(plan(&state, &owned, &work)?)
            } else {
                None
            };
            if !dry_run {
                if let Some(changes) = changes {
                    apply_plan(&state, &changes)?;
                }
                state.save_index(&target)?;
            }
            QueryOutput::json(
                json!({"status":"read_tree","dry_run":dry_run,"paths":target.files.keys().collect::<Vec<_>>(),"unmerged":target.conflicts.keys().collect::<Vec<_>>(),"worktree_updated":update&&!dry_run,"head_updated":false}),
            )
        }
        Action::UpdateIndex {
            flags,
            add,
            remove,
            force_remove,
            index_info,
            cacheinfo,
            stdin,
            nul,
            dry_run,
            mut paths,
            ..
        } => {
            if nul && !stdin && !index_info {
                return Err("-z requires --stdin or --index-info".into());
            }
            let mut index = state.index()?.unwrap_or_else(Index::empty);
            if flags.enabled() {
                if add || remove || force_remove || index_info || !cacheinfo.is_empty() {
                    return Err("index flags/refresh cannot combine content update modes".into());
                }
                if stdin {
                    paths = input(nul)?;
                }
                let checked = flags.update(&state, &mut index, paths)?;
                if !dry_run {
                    state.save_index(&index)?;
                }
                return QueryOutput::json(
                    json!({"status":"index_flags_updated","dry_run":dry_run,"verified_images":checked,"worktree_updated":false,"head_updated":false}),
                );
            }
            if index_info {
                for record in input(nul)? {
                    let (header, path) = record
                        .split_once('\t')
                        .ok_or("index-info requires MODE [TYPE] ID [STAGE]<TAB>PATH")?;
                    let fields: Vec<_> = header.split_whitespace().collect();
                    let (mode, id, stage) = match fields.as_slice() {
                        [mode, id] => (*mode, *id, 0),
                        [mode, "wasm", id] | [mode, "blob", id] => (*mode, *id, 0),
                        [mode, id, number] => (
                            *mode,
                            *id,
                            number.parse::<u8>().map_err(|_| "invalid index stage")?,
                        ),
                        [mode, "wasm", id, number] | [mode, "blob", id, number] => (
                            *mode,
                            *id,
                            number.parse::<u8>().map_err(|_| "invalid index stage")?,
                        ),
                        _ => return Err("invalid index-info record".into()),
                    };
                    set_entry(&state, &mut index, mode, id, stage, path)?;
                }
            } else if !cacheinfo.is_empty() {
                let values: Vec<_> = if cacheinfo.len() == 1 {
                    cacheinfo[0].splitn(3, ',').collect()
                } else {
                    cacheinfo.iter().map(String::as_str).collect()
                };
                let [mode, id, path] = values.as_slice() else {
                    return Err("--cacheinfo requires MODE,ID,PATH or three operands".into());
                };
                if !add && !index.files.contains_key(*path) && !index.conflicts.contains_key(*path)
                {
                    return Err("new cache entries require --add".into());
                }
                set_entry(&state, &mut index, mode, id, 0, path)?;
            } else {
                if stdin {
                    paths = input(nul)?;
                } else if nul {
                    return Err("-z requires --stdin or --index-info".into());
                }
                if paths.is_empty() {
                    return Err("update-index requires paths or an input mode".into());
                }
                for path in paths {
                    validate_tree_path(&path)?;
                    if force_remove {
                        index.files.remove(&path);
                        index.conflicts.remove(&path);
                        index.intents.remove(&path);
                        continue;
                    }
                    if !add
                        && !index.files.contains_key(&path)
                        && !index.conflicts.contains_key(&path)
                        && !index.intents.contains(&path)
                    {
                        return Err("new paths require --add".into());
                    }
                    match state.worktree_module(&path)? {
                        Some(bytes) => {
                            validate_wasm(&bytes)?;
                            index.files.insert(path.clone(), bytes);
                            index.conflicts.remove(&path);
                            index.intents.remove(&path);
                            index.flags.remove(&path);
                        }
                        None if remove => {
                            index.files.remove(&path);
                            index.conflicts.remove(&path);
                            index.intents.remove(&path);
                        }
                        None => return Err(format!("missing index input path: {path:?}")),
                    }
                }
            }
            index.tidy();
            validate_index(&index)?;
            if !dry_run {
                state.save_index(&index)?;
            }
            QueryOutput::json(
                json!({"status":"index_updated","dry_run":dry_run,"paths":index.files.keys().collect::<Vec<_>>(),"unmerged":index.conflicts.keys().collect::<Vec<_>>(),"worktree_updated":false,"head_updated":false}),
            )
        }
        Action::MergeIndex {
            all,
            dry_run,
            paths,
            ..
        } => {
            if all && !paths.is_empty() {
                return Err("merge-index --all and path selectors are mutually exclusive".into());
            }
            if !all && paths.is_empty() {
                return Err("merge-index requires --all or path selectors".into());
            }
            let mut index = state
                .index()?
                .ok_or("merge-index requires an existing index")?;
            let original = index.clone();
            let selected = select_paths(&index.conflicts.keys().cloned().collect(), &paths)?;
            let mut unresolved = Vec::new();
            let mut resolved = Vec::new();
            for path in selected {
                let sides = index.conflicts[&path].clone();
                match merge_file(
                    sides.base.as_ref(),
                    sides.ours.as_ref(),
                    sides.theirs.as_ref(),
                    &path,
                ) {
                    Ok(bytes) => {
                        if let Some(bytes) = bytes {
                            validate_wasm(&bytes)?;
                            index.files.insert(path.clone(), bytes);
                        } else {
                            index.files.remove(&path);
                        }
                        index.conflicts.remove(&path);
                        resolved.push(path);
                    }
                    Err(error) => unresolved.push(json!({"path":path,"reason":error})),
                }
            }
            let all_paths = controlled_paths(&index);
            let mut structural = BTreeSet::new();
            for path in &all_paths {
                for (offset, _) in path.match_indices('/') {
                    let parent = &path[..offset];
                    if all_paths.contains(parent) {
                        structural.insert(parent.to_owned());
                        structural.insert(path.clone());
                    }
                }
            }
            resolved.retain(|path| {
                if !structural.contains(path) {
                    return true;
                }
                index.files.remove(path);
                index.conflicts.insert(path.clone(), original.conflicts[path].clone());
                unresolved.push(json!({"path":path,"reason":"file/directory conflict requires an explicit tree resolution"}));
                false
            });
            validate_index(&index)?;
            if !dry_run {
                state.save_index(&index)?;
            }
            let mut output = QueryOutput::json(
                json!({"status":if unresolved.is_empty(){"merged_index"}else{"conflict"},"resolved":resolved,"unresolved":unresolved,"dry_run":dry_run,"worktree_updated":false,"head_updated":false}),
            )?;
            if !unresolved.is_empty() {
                output.exit_code = 2;
            }
            Ok(output)
        }
    }
}
