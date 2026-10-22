//! Index/worktree listings share native path admission and never publish data.
use super::*;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
#[path = "index_listing_details.rs"]
mod details;

#[derive(clap::Args)]
pub(super) struct Args {
    #[arg(short = 's', long)]
    stage: bool,
    #[arg(short = 'u', long)]
    unmerged: bool,
    #[arg(short = 'c', long)]
    cached: bool,
    #[arg(short = 'd', long)]
    deleted: bool,
    #[arg(short = 'm', long)]
    modified: bool,
    #[arg(short = 'o', long)]
    others: bool,
    #[arg(short = 'i', long)]
    ignored: bool,
    #[arg(short = 'k', long)]
    killed: bool,
    #[arg(long)]
    resolve_undo: bool,
    #[arg(long)]
    directory: bool,
    #[arg(long)]
    no_empty_directory: bool,
    #[arg(long)]
    eol: bool,
    #[arg(long, conflicts_with_all=["stage","unmerged"])]
    with_tree: Option<String>,
    #[arg(long, num_args=0..=1, require_equals=true, default_missing_value="12")]
    abbrev: Option<usize>,
    #[arg(short = 't')]
    tags: bool,
    #[arg(short = 'v', conflicts_with_all=["tags","monitor_tags","format"])]
    assume_tags: bool,
    #[arg(short = 'f', conflicts_with_all=["tags","assume_tags","format"])]
    monitor_tags: bool,
    #[arg(long)]
    deduplicate: bool,
    #[arg(long)]
    error_unmatch: bool,
    #[arg(long)]
    exclude_standard: bool,
    #[arg(short = 'x', long = "exclude")]
    excludes: Vec<String>,
    #[arg(short = 'X', long = "exclude-from")]
    exclude_from: Vec<String>,
    #[arg(long)]
    exclude_per_directory: Vec<String>,
    #[arg(short = 'z')]
    nul: bool,
    #[arg(long, conflicts_with_all=["stage","unmerged","others","killed","resolve_undo","eol","tags","json"])]
    format: Option<String>,
    #[arg(long)]
    json: bool,
    #[arg(last = true)]
    paths: Vec<String>,
}

struct Rules {
    names: Vec<String>,
    extra: Gitignore,
    directories: BTreeMap<PathBuf, Vec<Gitignore>>,
}
fn patterns(builder: &mut GitignoreBuilder, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 1024 * 1024 {
        return Err("one exclude file cannot exceed 1 MiB".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "exclude files must be UTF-8")?;
    for line in text.trim_start_matches('\u{feff}').lines() {
        builder.add_line(None, line).map_err(|e| e.to_string())?;
    }
    Ok(())
}
impl Rules {
    fn new(state: &State, options: &Args) -> Result<Self, String> {
        let mut extra = GitignoreBuilder::new(&state.repo.root);
        for file in &options.exclude_from {
            let bytes = regular(Path::new(file))?.ok_or("exclude file does not exist")?;
            patterns(&mut extra, &bytes)?;
        }
        for line in &options.excludes {
            extra.add_line(None, line).map_err(|e| e.to_string())?;
        }
        let mut names = Vec::new();
        if options.exclude_standard {
            names.extend([".gitignore".into(), ".uwgitignore".into()]);
        }
        for name in &options.exclude_per_directory {
            validate_tree_path(name)?;
            if name.contains('/') {
                return Err("exclude-per-directory requires a file basename".into());
            }
            names.push(name.clone());
        }
        Ok(Self {
            names,
            extra: extra.build().map_err(|e| e.to_string())?,
            directories: BTreeMap::new(),
        })
    }
    fn directory(&mut self, state: &State, relative: &str) -> Result<(), String> {
        let root = state.repo.root.join(relative);
        if self.directories.contains_key(&root) {
            return Ok(());
        }
        let mut rules = Vec::new();
        for name in &self.names {
            let path = if relative.is_empty() {
                name.clone()
            } else {
                format!("{relative}/{name}")
            };
            let Some(bytes) = state.worktree_module(&path)? else {
                continue;
            };
            let mut builder = GitignoreBuilder::new(&root);
            patterns(&mut builder, &bytes)?;
            rules.push(builder.build().map_err(|e| e.to_string())?);
        }
        self.directories.insert(root, rules);
        Ok(())
    }
    fn excluded(&mut self, state: &State, path: &str) -> Result<bool, String> {
        self.excluded_kind(state, path, false)
    }
    fn excluded_kind(
        &mut self,
        state: &State,
        path: &str,
        directory: bool,
    ) -> Result<bool, String> {
        self.directory(state, "")?;
        let mut ancestors = vec![state.repo.root.clone()];
        let mut prefix = String::new();
        let components: Vec<_> = path.split('/').collect();
        for (number, component) in components.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let is_dir = directory || number + 1 < components.len();
            let full = state.repo.root.join(&prefix);
            let explicit = self.extra.matched_path_or_any_parents(&full, is_dir);
            let mut decision = if explicit.is_ignore() {
                Some(true)
            } else if explicit.is_whitelist() {
                Some(false)
            } else {
                None
            };
            if decision.is_none() {
                'levels: for parent in ancestors.iter().rev() {
                    for matcher in self.directories[parent].iter().rev() {
                        let found = matcher.matched_path_or_any_parents(&full, is_dir);
                        if found.is_ignore() || found.is_whitelist() {
                            decision = Some(found.is_ignore());
                            break 'levels;
                        }
                    }
                }
            }
            if decision == Some(true) {
                return Ok(true);
            }
            if is_dir {
                self.directory(state, &prefix)?;
                ancestors.push(full);
            }
        }
        Ok(false)
    }
}

struct Row<'a> {
    path: String,
    stage: Option<u8>,
    bytes: Option<&'a Vec<u8>>,
    reason: char,
    undo: bool,
    directory: bool,
    historical: bool,
}
#[derive(Clone)]
enum Field {
    Text(String),
    Atom(String),
}
fn format_fields(format: &str) -> Result<Vec<Field>, String> {
    if format.len() > 8192 {
        return Err("index format exceeds 8192 bytes".into());
    }
    let mut fields = Vec::new();
    let mut remaining = format;
    while let Some(offset) = remaining.find('%') {
        fields.push(Field::Text(remaining[..offset].to_owned()));
        remaining = &remaining[offset + 1..];
        if let Some(rest) = remaining.strip_prefix('%') {
            fields.push(Field::Text("%".into()));
            remaining = rest;
        } else if let Some(rest) = remaining.strip_prefix('(') {
            let (atom, rest) = rest
                .split_once(')')
                .ok_or("unterminated index format atom")?;
            if !matches!(
                atom,
                "objectmode"
                    | "objectname"
                    | "objecttype"
                    | "objectsize"
                    | "stage"
                    | "path"
                    | "eolinfo:index"
                    | "eolinfo:worktree"
                    | "eolattr"
            ) {
                return Err(format!("unsupported native index field: {atom}"));
            }
            fields.push(Field::Atom(atom.into()));
            remaining = rest;
        } else if remaining.starts_with('x')
            && remaining.len() >= 3
            && remaining.as_bytes()[1..3].iter().all(u8::is_ascii_hexdigit)
        {
            let byte =
                u8::from_str_radix(&remaining[1..3], 16).map_err(|_| "invalid format escape")?;
            if !byte.is_ascii() {
                return Err("index format byte escapes must be ASCII".into());
            }
            fields.push(Field::Text(char::from(byte).to_string()));
            remaining = &remaining[3..];
        } else {
            return Err("invalid index format percent escape".into());
        }
    }
    fields.push(Field::Text(remaining.into()));
    Ok(fields)
}

pub(super) fn run(state: &State, options: Args) -> Result<QueryOutput, String> {
    if options.nul && options.json {
        return Err("-z requires text output".into());
    }
    if options.abbrev.is_some_and(|minimum| minimum > 64) {
        return Err("--abbrev requires a number in 0..=64; zero prints complete native IDs".into());
    }
    let has_excludes = options.exclude_standard
        || !options.excludes.is_empty()
        || !options.exclude_from.is_empty()
        || !options.exclude_per_directory.is_empty();
    if options.ignored && ((!options.cached && !options.others) || !has_excludes) {
        return Err(
            "ls-files --ignored requires explicit --cached or --others and exclude rules".into(),
        );
    }
    let format = options.format.as_deref().map(format_fields).transpose()?;
    let mut rules = Rules::new(state, &options)?;
    let index = state.index()?.unwrap_or_else(Index::empty);
    let controlled = controlled_paths(&index);
    let historical = options
        .with_tree
        .as_deref()
        .map(|revision| state.repo.archive_files(revision))
        .transpose()?;
    if historical
        .as_ref()
        .is_some_and(|tree| tree.legacy.is_some())
    {
        return Err("ls-files --with-tree requires a named native tree".into());
    }
    let historical_files = historical.as_ref().map(|tree| &tree.files);
    let view_paths: BTreeSet<_> = controlled
        .iter()
        .cloned()
        .chain(
            historical_files
                .into_iter()
                .flat_map(|files| files.keys().cloned()),
        )
        .collect();
    let pathspec = wasm_git::pathspec::Pathspec::new(&options.paths)?;
    if options.error_unmatch {
        pathspec.select(&view_paths)?;
    }
    let cached = !options.unmerged
        && (options.cached
            || options.stage
            || !(options.deleted
                || options.modified
                || options.others
                || options.killed
                || options.resolve_undo));
    let mut rows = Vec::new();
    for path in &controlled {
        if !pathspec.matches(path) || (options.ignored && !rules.excluded(state, path)?) {
            continue;
        }
        let mut images = Vec::new();
        if let Some(bytes) = index.files.get(path) {
            images.push((0, bytes));
        }
        if let Some(stages) = index.conflicts.get(path) {
            for stage in 1..=3 {
                if let Some(bytes) = stages.image(stage) {
                    images.push((stage, bytes));
                }
            }
        }
        let current = if options.deleted || options.modified {
            if index.hidden(path) {
                index.files.get(path).cloned()
            } else {
                state.worktree_module(path)?
            }
        } else {
            None
        };
        for (stage, bytes) in images {
            if cached || (options.unmerged && stage != 0) {
                rows.push(Row {
                    path: path.clone(),
                    stage: Some(stage),
                    bytes: Some(bytes),
                    reason: if stage != 0 {
                        'M'
                    } else if index.skipped(path) {
                        'S'
                    } else {
                        'H'
                    },
                    undo: false,
                    directory: false,
                    historical: false,
                });
            }
            if options.deleted && current.is_none() {
                rows.push(Row {
                    path: path.clone(),
                    stage: Some(stage),
                    bytes: Some(bytes),
                    reason: 'R',
                    undo: false,
                    directory: false,
                    historical: false,
                });
            }
            if options.modified && current.as_ref() != Some(bytes) {
                rows.push(Row {
                    path: path.clone(),
                    stage: Some(stage),
                    bytes: Some(bytes),
                    reason: 'C',
                    undo: false,
                    directory: false,
                    historical: false,
                });
            }
        }
        if index.intents.contains(path) {
            if cached {
                rows.push(Row {
                    path: path.clone(),
                    stage: Some(0),
                    bytes: None,
                    reason: if index.skipped(path) { 'S' } else { 'H' },
                    undo: false,
                    directory: false,
                    historical: false,
                });
            }
            if options.deleted && current.is_none() && !index.hidden(path) {
                rows.push(Row {
                    path: path.clone(),
                    stage: Some(0),
                    bytes: None,
                    reason: 'R',
                    undo: false,
                    directory: false,
                    historical: false,
                });
            }
            if options.modified && current.is_some() && !index.hidden(path) {
                rows.push(Row {
                    path: path.clone(),
                    stage: Some(0),
                    bytes: None,
                    reason: 'C',
                    undo: false,
                    directory: false,
                    historical: false,
                });
            }
        }
    }
    if let Some(files) = historical_files {
        for (path, bytes) in files {
            if controlled.contains(path)
                || !pathspec.matches(path)
                || (options.ignored && !rules.excluded(state, path)?)
            {
                continue;
            }
            let current = if options.deleted || options.modified {
                state.worktree_module(path)?
            } else {
                None
            };
            for reason in [
                cached.then_some('H'),
                (options.deleted && current.is_none()).then_some('R'),
                (options.modified && current.as_ref() != Some(bytes)).then_some('C'),
            ]
            .into_iter()
            .flatten()
            {
                rows.push(Row {
                    path: path.clone(),
                    stage: None,
                    bytes: Some(bytes),
                    reason,
                    undo: false,
                    directory: false,
                    historical: true,
                });
            }
        }
    }
    if options.others || options.killed {
        rows.extend(details::worktree_rows(
            state,
            &options,
            &mut rules,
            &view_paths,
            &pathspec,
        )?);
    }
    if options.resolve_undo {
        for (path, stages) in &index.resolve_undo {
            if !pathspec.matches(path) || (options.ignored && !rules.excluded(state, path)?) {
                continue;
            }
            for stage in 1..=3 {
                if let Some(bytes) = stages.image(stage) {
                    rows.push(Row {
                        path: path.clone(),
                        stage: Some(stage),
                        bytes: Some(bytes),
                        reason: 'U',
                        undo: true,
                        directory: false,
                        historical: false,
                    });
                }
            }
        }
    }
    rows.sort_by(|a, b| {
        a.undo
            .cmp(&b.undo)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.stage.cmp(&b.stage))
    });
    if options.deduplicate
        && !(options.stage
            || options.unmerged
            || options.tags
            || options.assume_tags
            || options.monitor_tags
            || options.resolve_undo
            || format.is_some())
    {
        rows.dedup_by(|a, b| a.path == b.path);
    }
    let needs_eol = options.eol
        || format.as_ref().is_some_and(|fields| {
            fields
                .iter()
                .any(|field| matches!(field, Field::Atom(atom) if atom.starts_with("eol")))
        });
    let mut images: Vec<&[u8]> = rows
        .iter()
        .filter_map(|row| row.bytes.map(Vec::as_slice))
        .collect();
    if options.abbrev.is_some_and(|minimum| minimum != 0) {
        images.extend(index.files.values().map(Vec::as_slice));
        for stages in index.conflicts.values().chain(index.resolve_undo.values()) {
            images.extend((1..=3).filter_map(|stage| stages.image(stage).map(Vec::as_slice)));
        }
        if let Some(files) = historical_files {
            images.extend(files.values().map(Vec::as_slice));
        }
    }
    let mut image_ids = state
        .repo
        .query_wasm_image_ids(&images, options.abbrev.unwrap_or(0))?
        .into_iter();
    let mut work_eol = BTreeMap::new();
    let mut output = String::new();
    let mut json_rows = Vec::new();
    for row in rows {
        let identity = row
            .bytes
            .map(|_| image_ids.next().expect("one identity per selected image"));
        let id = identity.as_ref().map(|(id, _)| id);
        let abbreviation = identity.as_ref().map(|(_, abbreviation)| abbreviation);
        let flags = !row.undo && !row.historical && !row.directory;
        let monitor = flags && index_flags::monitor_valid(state, &index, &row.path)?;
        let assume = flags
            && index
                .flags
                .get(&row.path)
                .is_some_and(|flag| flag.assume_unchanged);
        let mut json_row = json!({"path":row.path,"stage":row.stage,"object_id":id,"kind":row.bytes.map(|_|"wasm"),"byte_len":row.bytes.map(Vec::len),"reason":row.reason.to_string(),"object_may_be_unpublished":row.bytes.is_some(),"intent_to_add":index.intents.contains(&row.path),"assume_unchanged":assume,"skip_worktree":index.skipped(&row.path),"fsmonitor_valid":monitor});
        if row.undo {
            json_row["resolve_undo"] = json!(true);
            json_row["intent_to_add"] = json!(false);
            json_row["skip_worktree"] = json!(false);
        }
        if row.directory {
            json_row["directory"] = json!(true);
        }
        if row.historical {
            json_row["source"] = json!("tree");
            json_row["source_object"] = json!(historical.as_ref().map(|tree| &tree.object_id));
            json_row["index_entry"] = json!(false);
            json_row["object_may_be_unpublished"] = json!(false);
            json_row["intent_to_add"] = json!(false);
            json_row["skip_worktree"] = json!(false);
        }
        if options.abbrev.is_some() {
            json_row["object_abbrev"] = json!(abbreviation);
        }
        let (index_eol, actual_eol) = if needs_eol && !row.undo {
            let index_eol = if row.historical {
                ""
            } else {
                details::index_eol(row.bytes)?
            };
            let actual = if row.directory {
                ""
            } else if let Some(value) = work_eol.get(&row.path) {
                *value
            } else {
                let value = details::worktree_eol(state, &row.path)?;
                work_eol.insert(row.path.clone(), value);
                value
            };
            json_row["eol_index"] = json!(index_eol);
            json_row["eol_worktree"] = json!(actual);
            json_row["eol_attribute"] = json!("");
            (index_eol, actual)
        } else {
            ("", "")
        };
        json_rows.push(json_row);
        if let Some(fields) = &format {
            for field in fields {
                match field {
                    Field::Text(text) => output.push_str(text),
                    Field::Atom(atom) => output.push_str(&match atom.as_str() {
                        "path" => row.path.clone(),
                        "objectname" => abbreviation.cloned().unwrap_or_default(),
                        "objectmode" => "100644".into(),
                        "objecttype" => if row.bytes.is_some() {
                            "wasm"
                        } else {
                            "intent"
                        }
                        .into(),
                        "objectsize" => row
                            .bytes
                            .map(|bytes| bytes.len().to_string())
                            .unwrap_or_else(|| "-".into()),
                        "stage" => row
                            .stage
                            .map(|stage| stage.to_string())
                            .unwrap_or_else(|| "-".into()),
                        "eolinfo:index" => index_eol.into(),
                        "eolinfo:worktree" => actual_eol.into(),
                        "eolattr" => String::new(),
                        _ => unreachable!("validated fields"),
                    }),
                }
            }
        } else {
            if options.tags || options.assume_tags || options.monitor_tags {
                let lower = (options.assume_tags && assume) || (options.monitor_tags && monitor);
                output.push(if lower {
                    row.reason.to_ascii_lowercase()
                } else {
                    row.reason
                });
                output.push(' ');
            }
            if options.stage || options.unmerged || row.undo {
                if let (Some(id), Some(stage)) = (abbreviation, row.stage) {
                    output.push_str(&format!("100644 {id} {stage}\t"));
                }
                if !row.undo && index.intents.contains(&row.path) {
                    output.push_str("100644 - 0\t");
                }
            }
            if options.eol && !row.undo {
                output.push_str(&format!(
                    "i/{index_eol:<5} w/{actual_eol:<5} attr/{:<17}\t",
                    ""
                ));
            }
            output.push_str(&row.path);
        }
        output.push(if options.nul { '\0' } else { '\n' });
    }
    if options.json {
        let mut report = json!({"entries":json_rows,"index_format":index.format});
        if needs_eol {
            report["eol_policy"] =
                json!("original_bytes_no_conversion; Git attributes are not applied");
        }
        QueryOutput::json(report)
    } else {
        Ok(QueryOutput::new(output, 0))
    }
}
