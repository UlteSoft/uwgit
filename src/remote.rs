//! Named remotes and bounded, lossless RPC over HTTP(S) and SSH.
//!
//! A fetch installs verified objects and records an advertisement separately from
//! local branches. Every push uses a compare-and-swap lease, including ordinary
//! fast-forward pushes. Authentication secrets are never stored in configuration.

use crate::protocol::{self, Operation, RefNamespace, Request, Response};
use crate::repository::{Repository, RepositoryResult, RepositoryState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_TRANSFER: usize = protocol::MAX_PACKET_BYTES;
const MAX_CONFIG: u64 = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(35);
const USAGE: &str = "remote <DIR> [add <NAME> <URL>|remove <NAME>|rename <OLD> <NEW>|-v|show <NAME>]; fetch <DIR> [REMOTE]; push <DIR> [REMOTE] [SOURCE:DESTINATION] [-u|--set-upstream] [--force-with-lease <OLD_ID|absent>]; push <DIR> [REMOTE] --tags; push <DIR> [REMOTE] --delete <BRANCH|refs/tags/TAG> [--force-with-lease <OLD_ID>]; pull <DIR> [REMOTE] [BRANCH] [--ff-only] [-m <MESSAGE>] (message required unless --ff-only); clone <URL> <NEW_DIR>; HTTP URLs are http(s)://HOST/REPOSITORY; SSH URLs are ssh://USER@HOST/ABSOLUTE/ROOT/REPOSITORY; --allow-insecure-http explicitly permits non-loopback cleartext HTTP";
const LS_REMOTE_USAGE: &str = "ls-remote URL [PATTERN...] [--heads|--branches] [--tags] [--symref] [--refs] [--exit-code] [--json] [--allow-insecure-http]; ls-remote DIR [REMOTE [PATTERN...]] [OPTIONS]. DIR alone reads the existing origin configuration. Patterns match full refs or slash-delimited tails with * and ?; [] and backslash escapes are unsupported. -- ends options. Only HTTP(S) and SSH advertisements are queried; no objects are downloaded or verified, and no local repository metadata is written. --refs suppresses HEAD and its symbolic target. --exit-code returns 2 when no matching object-ID reference is advertised, including an unborn HEAD even if --symref prints its target.";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Remote {
    version: u32,
    name: String,
    url: String,
    allow_insecure_http: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tracking {
    version: u32,
    remote: String,
    url: String,
    state: RepositoryState,
}

/// A local view of an upstream. A missing remote or tracking branch is `None`,
/// while malformed metadata and unverifiable tracked objects remain errors.
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStatus {
    pub remote: String,
    pub branch: String,
    pub tip: Option<String>,
}

#[derive(Debug)]
enum Endpoint {
    Http {
        endpoint: String,
        repository: String,
        cleartext_remote: bool,
    },
    Ssh {
        host: String,
        port: Option<u16>,
        root: String,
        repository: String,
    },
}

impl Endpoint {
    fn repository(&self) -> &str {
        match self {
            Self::Http { repository, .. } | Self::Ssh { repository, .. } => repository,
        }
    }
}

pub fn is_remote_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://") || value.starts_with("ssh://")
}

fn name(value: &str) -> RepositoryResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || !value.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err("names must start with an ASCII letter or digit and contain at most 64 ASCII letters, digits, '-' or '_'".into());
    }
    Ok(())
}

fn branch_name(value: &str) -> RepositoryResult<()> {
    crate::repository::validate_ref_name(value).map_err(|_| "invalid remote branch name".into())
}

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_state(state: &RepositoryState) -> RepositoryResult<()> {
    if state.format != 1 {
        return Err("unsupported remote repository state version".into());
    }
    branch_name(&state.head)?;
    for (reference, id) in state.branches.iter().chain(state.tags.iter()) {
        branch_name(reference)?;
        if !valid_id(id) {
            return Err("remote state contains an invalid commit ID".into());
        }
    }
    Ok(())
}

fn authority(value: &str, ssh: bool) -> RepositoryResult<(String, Option<u16>, bool)> {
    let (user, address) = if let Some((user, host)) = value.split_once('@') {
        if !ssh
            || user.is_empty()
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            || user.starts_with('-')
        {
            return Err("invalid URL user or HTTP user information".into());
        }
        (Some(user), host)
    } else {
        (None, value)
    };
    let (host, port) = if address.starts_with('[') {
        let end = address.find(']').ok_or("unterminated IPv6 URL host")?;
        let host = &address[1..end];
        if !matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            return Err("invalid IPv6 URL host".into());
        }
        let rest = &address[end + 1..];
        let port = if rest.is_empty() {
            None
        } else {
            Some(rest.strip_prefix(':').ok_or("invalid URL authority")?)
        };
        (host, port)
    } else {
        let (host, port) = address
            .split_once(':')
            .map_or((address, None), |(h, p)| (h, Some(p)));
        if host.is_empty()
            || host.starts_with('-')
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        {
            return Err("invalid URL host".into());
        }
        (host, port)
    };
    let port = port
        .map(|p| {
            p.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| "invalid URL port".to_owned())
        })
        .transpose()?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    let display_host = if host.contains(':') && !ssh {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok((
        user.map_or(display_host.clone(), |u| format!("{u}@{display_host}")),
        port,
        loopback,
    ))
}

fn parse_url(value: &str) -> RepositoryResult<Endpoint> {
    if value.bytes().any(|b| b <= b' ' || b == 0x7f) || value.contains(['?', '#', '\\', '%']) {
        return Err(
            "remote URL contains unsupported characters, escaping, query or fragment".into(),
        );
    }
    let (scheme, rest) = value.split_once("://").ok_or("remote URL needs a scheme")?;
    let (authority_text, path) = rest
        .split_once('/')
        .ok_or("remote URL needs a repository path")?;
    match scheme {
        "http" | "https" => {
            protocol::repository_name(path)?;
            let (host, port, loopback) = authority(authority_text, false)?;
            let authority = port.map_or(host.clone(), |p| format!("{host}:{p}"));
            Ok(Endpoint::Http {
                endpoint: format!("{scheme}://{authority}/v1/uwgit"),
                repository: path.to_owned(),
                cleartext_remote: scheme == "http" && !loopback,
            })
        }
        "ssh" => {
            let (host, port, _) = authority(authority_text, true)?;
            let (root, repository) = path
                .rsplit_once('/')
                .ok_or("SSH URL needs an absolute server root and repository")?;
            protocol::repository_name(repository)?;
            if root
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            {
                return Err("SSH server root must have ordinary absolute path components".into());
            }
            Ok(Endpoint::Ssh {
                host,
                port,
                root: format!("/{root}"),
                repository: repository.to_owned(),
            })
        }
        _ => Err("supported remote URL schemes are http, https and ssh".into()),
    }
}

fn regular(path: &Path) -> RepositoryResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("read remote metadata: {e}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_CONFIG {
        return Err("remote metadata must be a bounded regular file".into());
    }
    let file = File::open(path).map_err(|error| format!("open remote metadata: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| format!("inspect opened remote metadata: {error}"))?
        .is_file()
    {
        return Err("opened remote metadata must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read remote metadata: {error}"))?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err("remote metadata exceeds the 1 MiB limit".into());
    }
    Ok(bytes)
}

fn directory(path: &Path) -> RepositoryResult<()> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err("remote metadata directory must not be a symlink".into())
            }
        }
        Err(e) => Err(format!("create remote metadata directory: {e}")),
    }
}

struct ConfigLock(PathBuf, File);
impl Drop for ConfigLock {
    fn drop(&mut self) {
        let _ = self.1.sync_all();
        let _ = fs::remove_file(&self.0);
    }
}

fn config_dir(repo: &Repository) -> RepositoryResult<PathBuf> {
    let path = repo.common_metadata().join("remotes");
    directory(&path)?;
    Ok(path)
}

fn config_lock(repo: &Repository) -> RepositoryResult<ConfigLock> {
    let path = repo.common_metadata().join("remote.lock");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| {
            format!(
                "cannot lock remote configuration; inspect .uwgit/remote.lock before retrying: {e}"
            )
        })?;
    Ok(ConfigLock(path, file))
}

fn load(repo: &Repository, remote: &str) -> RepositoryResult<Remote> {
    name(remote)?;
    let directory = config_dir(repo)?;
    let config: Remote =
        serde_json::from_slice(&regular(&directory.join(format!("{remote}.json")))?)
            .map_err(|e| format!("invalid remote configuration: {e}"))?;
    if config.version != 1 || config.name != remote {
        return Err("remote configuration version or name mismatch".into());
    }
    parse_url(&config.url)?;
    Ok(config)
}

fn optional_tracking(repo: &Repository, remote: &Remote) -> RepositoryResult<Option<Tracking>> {
    let path = config_dir(repo)?.join(format!("{}.tracking.json", remote.name));
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read remote tracking: {e}")),
        Ok(_) => {
            let tracking: Tracking = serde_json::from_slice(&regular(&path)?)
                .map_err(|e| format!("invalid remote tracking: {e}"))?;
            if tracking.version != 1 || tracking.remote != remote.name || tracking.url != remote.url
            {
                return Err("remote tracking identity mismatch".into());
            }
            validate_state(&tracking.state)?;
            Ok(Some(tracking))
        }
    }
}

fn tracking_spec(specification: &str) -> RepositoryResult<(&str, &str)> {
    let (remote, branch) = specification
        .split_once('/')
        .ok_or("upstream must be REMOTE/BRANCH from a previously fetched remote")?;
    name(remote)?;
    branch_name(branch)?;
    Ok((remote, branch))
}

fn existing_config_dir(repo: &Repository) -> RepositoryResult<Option<PathBuf>> {
    let path = repo.common_metadata().join("remotes");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("inspect remote configuration directory: {error}")),
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(Some(path)),
        Ok(_) => Err("remote metadata directory must be a regular directory".into()),
    }
}

fn load_readonly(repo: &Repository, remote: &str) -> RepositoryResult<Remote> {
    name(remote)?;
    let directory = existing_config_dir(repo)?.ok_or("remote has not been configured")?;
    let config: Remote =
        serde_json::from_slice(&regular(&directory.join(format!("{remote}.json")))?)
            .map_err(|error| format!("invalid remote configuration: {error}"))?;
    if config.version != 1 || config.name != remote {
        return Err("remote configuration version or name mismatch".into());
    }
    parse_url(&config.url)?;
    Ok(config)
}

/// Inspect one advertisement without fetching or creating local metadata. The
/// reference IDs remain unverified claims until a separate object download.
pub fn ls_remote_query(args: &[String]) -> RepositoryResult<crate::query_commands::QueryOutput> {
    use crate::query_commands::{tail_ref_match, validate_ref_pattern, QueryOutput};

    if crate::command_args::help_requested(args) {
        return Ok(QueryOutput::new(format!("{LS_REMOTE_USAGE}\n"), 0));
    }
    if args.first().map(String::as_str) != Some("ls-remote") {
        return Err(LS_REMOTE_USAGE.into());
    }
    let mut flags = BTreeSet::new();
    let mut operands = Vec::new();
    let mut literal = false;
    for arg in args.iter().skip(1) {
        if !literal && arg == "--" {
            literal = true;
        } else if !literal && arg.starts_with('-') {
            let flag = match arg.as_str() {
                "--branches" => "--heads",
                "--heads"
                | "--tags"
                | "--symref"
                | "--refs"
                | "--exit-code"
                | "--json"
                | "--allow-insecure-http" => arg.as_str(),
                _ => return Err(LS_REMOTE_USAGE.into()),
            };
            if !flags.insert(flag) {
                return Err(format!("ls-remote option cannot be repeated: {flag}"));
            }
        } else {
            operands.push(arg.as_str());
        }
    }
    let target = operands.first().ok_or(LS_REMOTE_USAGE)?;
    let direct = is_remote_url(target);
    if !direct && target.contains("://") {
        return Err("ls-remote URL schemes are http, https and ssh".into());
    }
    let patterns = if direct {
        &operands[1..]
    } else {
        operands.get(2..).unwrap_or_default()
    };
    for pattern in patterns {
        validate_ref_pattern(pattern)?;
    }
    let (remote, configured_name) = if direct {
        parse_url(target)?;
        (
            Remote {
                version: 1,
                name: "advertisement".into(),
                url: (*target).into(),
                allow_insecure_http: false,
            },
            None,
        )
    } else {
        let remote_name = operands.get(1).copied().unwrap_or("origin");
        name(remote_name)?;
        let repo = Repository::open(target)?;
        (load_readonly(&repo, remote_name)?, Some(remote_name))
    };
    let (response, payload) = exchange(
        &remote,
        Operation::Advertise {},
        &[],
        flags.contains("--allow-insecure-http"),
    )?;
    if !payload.is_empty() {
        return Err("ls-remote advertisement unexpectedly contains an object payload".into());
    }
    if response.tip.is_some() {
        return Err("ls-remote advertisement unexpectedly contains an update tip".into());
    }
    let state = response
        .state
        .ok_or("advertisement lacks repository state")?;
    validate_state(&state)?;
    let matches = |reference: &str| -> RepositoryResult<bool> {
        if patterns.is_empty() {
            return Ok(true);
        }
        for pattern in patterns {
            if tail_ref_match(reference, pattern)? {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let heads = flags.contains("--heads");
    let tags = flags.contains("--tags");
    let all = !heads && !tags;
    let include_head = all && !flags.contains("--refs") && matches("HEAD")?;
    let head_tip = state.branches.get(&state.head);
    let symbolic = include_head && flags.contains("--symref");
    let mut references = Vec::new();
    let mut text = String::new();
    let symbolic_target = format!("refs/heads/{}", state.head);
    if symbolic {
        text.push_str(&format!("ref: {symbolic_target}\tHEAD\n"));
    }
    if include_head {
        if let Some(id) = head_tip {
            text.push_str(&format!("{id}\tHEAD\n"));
            references.push(serde_json::json!({"name":"HEAD","id":id}));
        }
    }
    for (prefix, selected, entries) in [
        ("refs/heads/", all || heads, &state.branches),
        ("refs/tags/", all || tags, &state.tags),
    ] {
        if selected {
            for (name, id) in entries {
                let reference = format!("{prefix}{name}");
                if matches(&reference)? {
                    text.push_str(&format!("{id}\t{reference}\n"));
                    references.push(serde_json::json!({"name":reference,"id":id}));
                }
            }
        }
    }
    let exit_code = if flags.contains("--exit-code") && references.is_empty() {
        2
    } else {
        0
    };
    if flags.contains("--json") {
        let mut output = QueryOutput::json(serde_json::json!({
            "schema_version":1,
            "command":"ls-remote",
            "remote":configured_name,
            "url":remote.url,
            "advertised_only":true,
            "objects_verified":false,
            "unverified_objects":true,
            "head_branch":state.head,
            "head_tip":head_tip,
            "references":references,
            "symbolic_refs":if symbolic {
                vec![serde_json::json!({"name":"HEAD","target":symbolic_target})]
            } else { Vec::new() }
        }))?;
        output.exit_code = exit_code;
        Ok(output)
    } else {
        Ok(QueryOutput::new(text, exit_code))
    }
}

fn verified_tracking_tip(
    repo: &Repository,
    remote: &Remote,
    branch: &str,
) -> RepositoryResult<Option<String>> {
    let Some(tracking) = optional_tracking(repo, remote)? else {
        return Ok(None);
    };
    let Some(tip) = tracking.state.branches.get(branch) else {
        return Ok(None);
    };
    if repo.resolve(&format!("{}/{branch}", remote.name))? != *tip {
        return Err("verified remote tracking tip changed".into());
    }
    Ok(Some(tip.clone()))
}

/// The lock order is remote configuration, then the repository writer. No
/// network request is made while configuring an already fetched upstream.
pub fn configure_upstream(
    repo: &Repository,
    local: &str,
    specification: &str,
) -> RepositoryResult<()> {
    branch_name(local)?;
    let (remote_name, branch) = tracking_spec(specification)?;
    let _lock = config_lock(repo)?;
    let (state, upstreams) = repo.state_with_upstreams()?;
    let tip = state
        .branches
        .get(local)
        .ok_or("upstream requires a committed local branch")?;
    existing_config_dir(repo)?.ok_or("remote has not been configured")?;
    let remote = load(repo, remote_name)?;
    verified_tracking_tip(repo, &remote, branch)?
        .ok_or("upstream branch has not been fetched or is gone; fetch it before configuring")?;
    repo.set_upstream_checked(local, remote_name, branch, tip, upstreams.get(local))?;
    Ok(())
}

pub fn unset_upstream(repo: &Repository, local: &str) -> RepositoryResult<()> {
    branch_name(local)?;
    let _lock = config_lock(repo)?;
    let (state, upstreams) = repo.state_with_upstreams()?;
    let tip = state
        .branches
        .get(local)
        .ok_or("upstream requires a committed local branch")?;
    let previous = upstreams.get(local).ok_or("local branch has no upstream")?;
    repo.unset_upstream_checked(local, tip, previous)?;
    Ok(())
}

pub fn upstream_status(repo: &Repository, local: &str) -> RepositoryResult<Option<UpstreamStatus>> {
    branch_name(local)?;
    let _lock = config_lock(repo)?;
    let (state, upstreams) = repo.state_with_upstreams()?;
    if !state.branches.contains_key(local) && state.head != local {
        return Err("local branch does not exist".into());
    }
    let Some(upstream) = upstreams.get(local) else {
        return Ok(None);
    };
    let path = existing_config_dir(repo)?
        .map(|directory| directory.join(format!("{}.json", upstream.remote)));
    let tip = match path.map(fs::symlink_metadata).transpose() {
        Ok(None) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("inspect upstream remote: {error}")),
        Ok(Some(_)) => {
            verified_tracking_tip(repo, &load(repo, &upstream.remote)?, &upstream.branch)?
        }
    };
    Ok(Some(UpstreamStatus {
        remote: upstream.remote.clone(),
        branch: upstream.branch.clone(),
        tip,
    }))
}

fn atomic_json<T: Serialize>(repo: &Repository, path: &Path, value: &T) -> RepositoryResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("encode remote metadata: {e}"))?;
    let temp = repo.common_metadata().join("tmp").join(unique("remote"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| format!("create remote metadata: {e}"))?;
        file.write_all(&bytes)
            .map_err(|e| format!("write remote metadata: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("sync remote metadata: {e}"))?;
        // Replacing a symlink is safe, but silently accepting corrupt metadata is
        // not. Existing metadata must pass the same regular-file boundary.
        match fs::symlink_metadata(path) {
            Ok(_) => {
                regular(path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("inspect remote metadata: {e}")),
        }
        fs::rename(&temp, path).map_err(|e| format!("publish remote metadata: {e}"))?;
        File::open(path.parent().ok_or("missing remote metadata parent")?)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| format!("sync remote metadata directory: {e}"))
    })();
    let _ = fs::remove_file(temp);
    result
}

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

struct SecretHeader(PathBuf);
impl Drop for SecretHeader {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn secret_header() -> RepositoryResult<Option<SecretHeader>> {
    let Some(token) = std::env::var_os("UWGIT_REMOTE_TOKEN") else {
        return Ok(None);
    };
    let token = token
        .into_string()
        .map_err(|_| "remote token must be UTF-8")?;
    if token.is_empty() || token.len() > 4096 || token.bytes().any(|b| !(33..=126).contains(&b)) {
        return Err("remote token must be 1..4096 printable ASCII bytes without whitespace".into());
    }
    let path = PathBuf::from("/tmp").join(unique("uwgit-http-header"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| format!("create private authentication header: {e}"))?;
    let guard = SecretHeader(path);
    file.write_all(format!("Authorization: Bearer {token}\n").as_bytes())
        .map_err(|e| format!("write private authentication header: {e}"))?;
    Ok(Some(guard))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn subprocess(command: Command, input: Vec<u8>, label: &str) -> RepositoryResult<Vec<u8>> {
    subprocess_deadline(command, input, label, TIMEOUT)
}

/// The budget covers process exit and all three pipes. In particular, a proxy
/// process inheriting stdout must not turn joining a reader into an unbounded
/// wait after the immediate curl/ssh process has already exited. Pipe workers
/// report through a channel; an expired call drops their handles rather than
/// waiting for an untrusted descendant to close inherited descriptors.
fn subprocess_deadline(
    mut command: Command,
    input: Vec<u8>,
    label: &str,
    timeout: Duration,
) -> RepositoryResult<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    enum Completed {
        Input(std::io::Result<()>),
        Output(std::io::Result<Vec<u8>>),
        Errors(std::io::Result<Vec<u8>>),
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {label} transport: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("missing transport stdin")?;
    let stdout = child.stdout.take().ok_or("missing transport stdout")?;
    let stderr = child.stderr.take().ok_or("missing transport stderr")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let writer = sender.clone();
    std::thread::spawn(move || {
        let _ = writer.send(Completed::Input(stdin.write_all(&input)));
    });
    let reader = sender.clone();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take((MAX_TRANSFER + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = reader.send(Completed::Output(result));
    });
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr.take(65537).read_to_end(&mut bytes).map(|_| bytes);
        let _ = sender.send(Completed::Errors(result));
    });
    let mut status = None;
    let mut written = None;
    let mut bytes = None;
    let mut errors_finished = false;
    let result = loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(error) => break Err(format!("wait for {label} transport: {error}")),
            }
        }
        if let Some(status) = status {
            if !status.success() {
                break Err(format!("{label} transport exited unsuccessfully ({status}); check endpoint, authentication and transport configuration"));
            }
            if errors_finished && written.is_some() && bytes.is_some() {
                match written.take().ok_or("missing transport writer result")? {
                    Ok(()) => break Ok(bytes.take().ok_or("missing transport response")?),
                    Err(error) => break Err(format!("write {label} transport: {error}")),
                }
            }
        }
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
        else {
            break Err(format!(
                "{label} transport exceeded its {} millisecond process-and-pipe deadline",
                timeout.as_millis()
            ));
        };
        match receiver.recv_timeout(remaining.min(Duration::from_millis(20))) {
            Ok(Completed::Input(result)) => written = Some(result),
            Ok(Completed::Output(result)) => match result {
                Ok(output) if output.len() <= MAX_TRANSFER => bytes = Some(output),
                Ok(_) => break Err("remote response exceeds 64 MiB limit".into()),
                Err(error) => break Err(format!("read {label} transport: {error}")),
            },
            Ok(Completed::Errors(result)) => {
                if let Err(error) = result {
                    break Err(format!("read {label} transport errors: {error}"));
                }
                errors_finished = true;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) if status.is_some() => {
                break Err("transport pipe workers ended without a complete response".into())
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(remaining.min(Duration::from_millis(20)))
            }
        }
    };
    if status.is_none() {
        let _ = child.kill();
        // Reaping is independent of the RPC budget. No reader thread or wait on
        // a potentially stalled child can extend the caller's deadline.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    result
}

fn exchange(
    remote: &Remote,
    operation: Operation,
    payload: &[u8],
    allow_http: bool,
) -> RepositoryResult<(Response, Vec<u8>)> {
    let endpoint = parse_url(&remote.url)?;
    let request = Request {
        version: 1,
        repository: endpoint.repository().to_owned(),
        operation,
    };
    let mut encoded = Vec::new();
    protocol::write_packet(&mut encoded, &request, payload)?;
    if encoded.len() > MAX_TRANSFER {
        return Err("remote request exceeds 64 MiB limit".into());
    }
    let bytes = match endpoint {
        Endpoint::Http {
            endpoint,
            cleartext_remote,
            ..
        } => {
            if cleartext_remote && !(allow_http || remote.allow_insecure_http) {
                return Err("non-loopback HTTP requires --allow-insecure-http; use HTTPS to protect credentials and repository bytes".into());
            }
            let header = secret_header()?;
            let mut command = Command::new("curl");
            command.args([
                "-q",
                "--noproxy",
                "*",
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--proto",
                "=http,https",
                "--connect-timeout",
                "10",
                "--max-time",
                "30",
                "--max-filesize",
                "67108864",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/octet-stream",
                "--header",
                "Expect:",
                "--data-binary",
                "@-",
            ]);
            if let Some(header) = &header {
                command
                    .arg("--header")
                    .arg(format!("@{}", header.0.display()));
            }
            command
                .arg("--url")
                .arg(endpoint)
                .env_remove("UWGIT_REMOTE_TOKEN");
            subprocess(command, encoded, "HTTP")?
        }
        Endpoint::Ssh {
            host, port, root, ..
        } => {
            let executable = std::env::var_os("UWGIT_SSH_PROGRAM").unwrap_or_else(|| "ssh".into());
            let program =
                std::env::var("UWGIT_REMOTE_PROGRAM").unwrap_or_else(|_| "wasm-git".into());
            if program.is_empty() || program.contains(['\0', '\r', '\n']) {
                return Err("invalid remote executable path".into());
            }
            let mut command = Command::new(executable);
            command.args(["-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]);
            if let Some(port) = port {
                command.arg("-p").arg(port.to_string());
            }
            command
                .arg("--")
                .arg(host)
                .arg(format!(
                    "{} server --stdio --root {}",
                    shell_quote(&program),
                    shell_quote(&root)
                ))
                .env_remove("UWGIT_REMOTE_TOKEN");
            subprocess(command, encoded, "SSH")?
        }
    };
    let mut cursor = std::io::Cursor::new(&bytes);
    let (response, payload): (Response, Vec<u8>) = protocol::read_packet(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err("remote response has trailing bytes after its single RPC frame".into());
    }
    if response.version != 1 {
        return Err("unsupported remote response version".into());
    }
    if response.publication_unknown {
        let reason = if response.ok {
            "successful response illegally marks publication as unknown"
        } else {
            response
                .error
                .as_deref()
                .unwrap_or("unspecified publication failure")
        };
        return Err(format!("remote publication outcome is unknown: {reason}"));
    }
    if !response.ok {
        return Err(format!(
            "remote rejected request: {}",
            response.error.as_deref().unwrap_or("unspecified error")
        ));
    }
    if response.error.is_some() {
        return Err("successful remote response contains an error".into());
    }
    Ok((response, payload))
}

fn fetch(
    repo: &Repository,
    remote: &Remote,
    allow_http: bool,
) -> RepositoryResult<RepositoryState> {
    let baseline = {
        let _lock = config_lock(repo)?;
        if load(repo, &remote.name)? != *remote {
            return Err("remote configuration changed before fetching; retry fetch".into());
        }
        optional_tracking(repo, remote)?
    };
    let (response, payload) = exchange(remote, Operation::Fetch {}, &[], allow_http)?;
    let advertised = response
        .state
        .ok_or("fetch response lacks repository state")?;
    if payload.is_empty() {
        return Err("fetch response lacks its verified bundle".into());
    }
    let verified = Repository::bundle_state(&payload)?;
    if verified != advertised {
        return Err("remote advertisement does not match the verified bundle".into());
    }
    let installed = repo.install_bundle_bytes(&payload)?;
    let _lock = config_lock(repo)?;
    if load(repo, &remote.name)? != *remote {
        return Err("remote configuration changed while fetching; objects were installed but tracking was not updated".into());
    }
    // Compare the complete entry, including absence, rather than commit ancestry:
    // a separate fetch may legitimately observe a forced remote rewind.
    if optional_tracking(repo, remote)? != baseline {
        return Err("remote tracking changed while fetching; objects were installed but tracking was not updated; retry fetch".into());
    }
    let tracking = Tracking {
        version: 1,
        remote: remote.name.clone(),
        url: remote.url.clone(),
        state: installed.clone(),
    };
    atomic_json(
        repo,
        &config_dir(repo)?.join(format!("{}.tracking.json", remote.name)),
        &tracking,
    )?;
    Ok(installed)
}

fn pretty<T: Serialize>(value: &T) -> RepositoryResult<String> {
    serde_json::to_string_pretty(value).map_err(|e| format!("encode remote result: {e}"))
}

fn reference(value: &str) -> RepositoryResult<(RefNamespace, &str)> {
    let (namespace, value) = if let Some(value) = value.strip_prefix("refs/tags/") {
        (RefNamespace::Tag, value)
    } else {
        (
            RefNamespace::Branch,
            value.strip_prefix("refs/heads/").unwrap_or(value),
        )
    };
    branch_name(value)?;
    Ok((namespace, value))
}

fn remote_tip(
    state: &RepositoryState,
    namespace: &RefNamespace,
    reference: &str,
) -> Option<String> {
    match namespace {
        RefNamespace::Branch => state.branches.get(reference),
        RefNamespace::Tag => state.tags.get(reference),
    }
    .cloned()
}

fn lease(value: &str) -> RepositoryResult<Option<String>> {
    if value == "absent" {
        return Ok(None);
    }
    if !valid_id(value) {
        return Err("lease must be a complete lowercase commit ID or 'absent'".into());
    }
    Ok(Some(value.to_owned()))
}

struct RefChange<'a> {
    namespace: RefNamespace,
    reference: &'a str,
    expected: Option<String>,
    new: Option<&'a str>,
    force: bool,
}

fn update_ref(
    repo: &Repository,
    remote: &Remote,
    change: RefChange<'_>,
    allow_http: bool,
) -> RepositoryResult<()> {
    let RefChange {
        namespace,
        reference,
        expected,
        new,
        force,
    } = change;
    let bundle = if let Some(id) = new {
        repo.bundle_bytes(Some(id))?.1
    } else {
        Vec::new()
    };
    let operation = if matches!(namespace, RefNamespace::Branch) && new.is_some() {
        // The original branch operation remains wire-compatible.
        Operation::Push {
            branch: reference.to_owned(),
            expected,
            force,
        }
    } else {
        Operation::UpdateRef {
            namespace,
            name: reference.to_owned(),
            expected,
            new: new.map(str::to_owned),
            force,
        }
    };
    let (response, payload) = exchange(remote, operation, &bundle, allow_http)?;
    if !payload.is_empty() || response.tip.as_deref() != new {
        return Err("remote acknowledgement does not match the requested exact ref update; publication outcome is unknown, inspect the remote before retrying".into());
    }
    Ok(())
}

fn push_command(root: &str, args: &[&str], allow_http: bool) -> RepositoryResult<String> {
    let mut positional = Vec::new();
    let mut tags = false;
    let mut delete = false;
    let mut set_upstream = false;
    let mut explicit_lease = None;
    let mut index = 0;
    while index < args.len() {
        match args[index] {
            "--tags" if !tags => tags = true,
            "--delete" if !delete => delete = true,
            "-u" | "--set-upstream" if !set_upstream => set_upstream = true,
            "--force-with-lease" if explicit_lease.is_none() => {
                index += 1;
                explicit_lease = Some(lease(args.get(index).ok_or(USAGE)?)?);
            }
            option if option.starts_with('-') => {
                return Err(format!("unsupported or repeated push option: {option}"))
            }
            value => positional.push(value),
        }
        index += 1;
    }
    if positional.len() > 2
        || (tags && (delete || explicit_lease.is_some() || positional.len() > 1))
        || (delete && positional.is_empty())
        || (set_upstream && (tags || delete))
    {
        return Err(USAGE.into());
    }
    let (explicit_remote, specification) = if delete && positional.len() == 1 {
        (None, positional.first().copied())
    } else {
        (positional.first().copied(), positional.get(1).copied())
    };
    let repo = Repository::open(root)?;
    let (local, upstreams, remote) = {
        let _lock = config_lock(&repo)?;
        let (local, upstreams) = repo.state_with_upstreams()?;
        let remote_name = explicit_remote.unwrap_or_else(|| {
            upstreams
                .get(&local.head)
                .map_or("origin", |binding| binding.remote.as_str())
        });
        let remote = load(&repo, remote_name)?;
        (local, upstreams, remote)
    };
    let mut binding_source = None;
    let planned = if tags {
        None
    } else if delete {
        let (namespace, reference) = reference(specification.ok_or(USAGE)?)?;
        Some((namespace, reference.to_owned(), None))
    } else if let Some(specification) = specification {
        let (source, destination) = specification
            .split_once(':')
            .ok_or("push refspec must be SOURCE:DESTINATION")?;
        let (namespace, reference) = reference(destination)?;
        let tip = if set_upstream {
            if !matches!(namespace, RefNamespace::Branch) {
                return Err("push --set-upstream requires a branch destination".into());
            }
            let branch = if source == "HEAD" {
                local.head.as_str()
            } else {
                source.strip_prefix("refs/heads/").unwrap_or(source)
            };
            branch_name(branch)?;
            let tip = local
                .branches
                .get(branch)
                .cloned()
                .ok_or("push --set-upstream source must be a committed local branch")?;
            binding_source = Some((
                branch.to_owned(),
                tip.clone(),
                upstreams.get(branch).cloned(),
            ));
            tip
        } else {
            repo.resolve(source)?
        };
        Some((namespace, reference.to_owned(), Some(tip)))
    } else {
        let source = local
            .branches
            .get(&local.head)
            .cloned()
            .ok_or("current branch has no commits")?;
        if upstreams
            .get(&local.head)
            .is_some_and(|binding| binding.remote == remote.name && binding.branch != local.head)
        {
            return Err("simple push refused: local branch name differs from its upstream branch; specify SOURCE:DESTINATION explicitly".into());
        }
        if set_upstream {
            binding_source = Some((
                local.head.clone(),
                source.clone(),
                upstreams.get(&local.head).cloned(),
            ));
        }
        Some((RefNamespace::Branch, local.head.clone(), Some(source)))
    };
    let (advertisement, empty) = exchange(&remote, Operation::Advertise {}, &[], allow_http)?;
    if !empty.is_empty() {
        return Err("advertisement unexpectedly contains a bundle".into());
    }
    let state = advertisement
        .state
        .ok_or("advertisement lacks repository state")?;
    validate_state(&state)?;
    if tags {
        let mut updates = Vec::new();
        let mut failures = 0usize;
        let mut uncertain = false;
        for (tag, id) in &local.tags {
            if uncertain {
                failures += 1;
                updates.push(serde_json::json!({"namespace":"tag","name":tag,"tip":id,"status":"not_attempted","error":"an earlier publication outcome is unknown; inspect the remote before retrying"}));
                continue;
            }
            let old = state.tags.get(tag).cloned();
            if old.as_deref() == Some(id.as_str()) {
                updates.push(serde_json::json!({"namespace":"tag","name":tag,"tip":id,"status":"up_to_date"}));
                continue;
            }
            match update_ref(
                &repo,
                &remote,
                RefChange {
                    namespace: RefNamespace::Tag,
                    reference: tag,
                    expected: old,
                    new: Some(id),
                    force: false,
                },
                allow_http,
            ) {
                Ok(()) => updates.push(
                    serde_json::json!({"namespace":"tag","name":tag,"tip":id,"status":"pushed"}),
                ),
                Err(error) => {
                    failures += 1;
                    let status = if error.starts_with("remote rejected request:") {
                        "rejected"
                    } else {
                        uncertain = true;
                        "unknown"
                    };
                    updates.push(serde_json::json!({"namespace":"tag","name":tag,"tip":id,"status":status,"error":error}));
                }
            }
        }
        let status = if uncertain {
            "unknown"
        } else if failures == 0 {
            "pushed"
        } else if failures == updates.len() {
            "rejected"
        } else {
            "partial"
        };
        return pretty(
            &serde_json::json!({"remote":remote.name,"status":status,"atomic":false,"updates":updates}),
        );
    }
    let (namespace, reference, source) = planned.ok_or("missing push update")?;
    let actual = remote_tip(&state, &namespace, &reference);
    let expected = explicit_lease.clone().unwrap_or_else(|| actual.clone());
    if actual != expected {
        return Err("remote ref does not match the explicit force-with-lease expectation".into());
    }
    if delete && actual.is_none() {
        return Err("remote reference does not exist".into());
    }
    let namespace_text = match &namespace {
        RefNamespace::Branch => "branch",
        RefNamespace::Tag => "tag",
    };
    update_ref(
        &repo,
        &remote,
        RefChange {
            namespace,
            reference: &reference,
            expected,
            new: source.as_deref(),
            force: explicit_lease.is_some() && !delete,
        },
        allow_http,
    )?;
    if let Some((branch, tip, previous)) = binding_source {
        let save = (|| {
            let _lock = config_lock(&repo)?;
            if load(&repo, &remote.name)? != remote {
                return Err("remote configuration changed during push".into());
            }
            repo.set_upstream_checked(&branch, &remote.name, &reference, &tip, previous.as_ref())?;
            Ok::<(), String>(())
        })();
        save.map_err(|error| format!("remote ref was published and exactly acknowledged; local upstream update failed: {error}; inspect the local upstream before retrying"))?;
    }
    pretty(
        &serde_json::json!({"remote":remote.name,"namespace":namespace_text,"name":reference,"tip":source,"status":if delete {"deleted"} else {"pushed"},"upstream_configured":set_upstream}),
    )
}

/// Dispatch remote commands; arguments start with the subcommand, not argv[0].
pub fn run(args: &[String]) -> RepositoryResult<String> {
    if crate::command_args::help_requested(args) {
        return Ok(USAGE.into());
    }
    let transport_flags = crate::command_args::option_indices(args, "--allow-insecure-http");
    let ff_only_flags = if args.first().is_some_and(|command| command == "pull") {
        crate::command_args::option_indices(args, "--ff-only")
    } else {
        Vec::new()
    };
    if ff_only_flags.len() > 1 {
        return Err("pull --ff-only cannot be repeated".into());
    }
    let no_ff_flags = if args.first().is_some_and(|command| command == "pull") {
        crate::command_args::option_indices(args, "--no-ff")
    } else {
        Vec::new()
    };
    if no_ff_flags.len() > 1 {
        return Err("pull --no-ff cannot be repeated".into());
    }
    if !no_ff_flags.is_empty() && !ff_only_flags.is_empty() {
        return Err("pull --no-ff and --ff-only are mutually exclusive".into());
    }
    let no_ff = !no_ff_flags.is_empty();
    let ff_only = !ff_only_flags.is_empty();
    let allow_http = !transport_flags.is_empty();
    let args: Vec<&str> = args
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| {
            (!transport_flags.contains(&index)
                && !ff_only_flags.contains(&index)
                && !no_ff_flags.contains(&index))
            .then_some(arg.as_str())
        })
        .collect();
    match args.as_slice() {
        ["remote", root] | ["remote", root, "-v"] => {
            let repo = Repository::open(root)?;
            let _lock = config_lock(&repo)?;
            let mut remotes = Vec::new();
            for entry in
                fs::read_dir(config_dir(&repo)?).map_err(|e| format!("list remotes: {e}"))?
            {
                let entry = entry.map_err(|e| format!("list remotes: {e}"))?;
                let filename = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "non-UTF-8 remote metadata name")?;
                if filename.ends_with(".tracking.json") {
                    continue;
                }
                let remote = filename
                    .strip_suffix(".json")
                    .ok_or("unexpected file in remote configuration")?;
                remotes.push(load(&repo, remote)?);
            }
            remotes.sort_by(|a, b| a.name.cmp(&b.name));
            pretty(&remotes)
        }
        ["remote", root, "add", remote_name, url] => {
            name(remote_name)?;
            parse_url(url)?;
            let repo = Repository::open(root)?;
            let _lock = config_lock(&repo)?;
            let path = config_dir(&repo)?.join(format!("{remote_name}.json"));
            if path.try_exists().map_err(|e| e.to_string())? || fs::symlink_metadata(&path).is_ok()
            {
                return Err("remote already exists".into());
            }
            let remote = Remote {
                version: 1,
                name: (*remote_name).to_owned(),
                url: (*url).to_owned(),
                allow_insecure_http: allow_http,
            };
            atomic_json(&repo, &path, &remote)?;
            pretty(&remote)
        }
        ["remote", root, "show", remote_name] => {
            let repo = Repository::open(root)?;
            let _lock = config_lock(&repo)?;
            let remote = load(&repo, remote_name)?;
            pretty(
                &serde_json::json!({"remote": remote, "tracking": optional_tracking(&repo, &remote)?}),
            )
        }
        ["remote", root, "remove", remote_name] => {
            let repo = Repository::open(root)?;
            let _lock = config_lock(&repo)?;
            let remote = load(&repo, remote_name)?;
            optional_tracking(&repo, &remote)?;
            repo.upstreams()?;
            let directory = config_dir(&repo)?;
            let cleared = repo.remove_upstream_remote(remote_name)?;
            fs::remove_file(directory.join(format!("{remote_name}.json"))).map_err(|e| {
                format!("upstream bindings were cleared; remove remote configuration failed: {e}")
            })?;
            let tracking = directory.join(format!("{remote_name}.tracking.json"));
            match fs::remove_file(tracking) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("upstream bindings and remote configuration were removed; remove tracking failed: {e}")),
            }
            Ok(format!(
                "removed remote {remote_name}; cleared {cleared} upstream bindings"
            ))
        }
        ["remote", root, "rename", old, new] => {
            name(new)?;
            let repo = Repository::open(root)?;
            let _lock = config_lock(&repo)?;
            let mut remote = load(&repo, old)?;
            let mut tracking = optional_tracking(&repo, &remote)?;
            repo.upstreams()?;
            let directory = config_dir(&repo)?;
            let destination = directory.join(format!("{new}.json"));
            if fs::symlink_metadata(&destination).is_ok()
                || fs::symlink_metadata(directory.join(format!("{new}.tracking.json"))).is_ok()
            {
                return Err("destination remote already exists".into());
            }
            remote.name = (*new).to_owned();
            atomic_json(&repo, &destination, &remote).map_err(|error| format!("creating the new remote configuration failed or its durability is uncertain; old remote and upstream bindings remain: {error}"))?;
            if let Some(tracking) = tracking.as_mut() {
                tracking.remote = (*new).to_owned();
                atomic_json(
                    &repo,
                    &directory.join(format!("{new}.tracking.json")),
                    tracking,
                ).map_err(|error| format!("new remote configuration was created; copying tracking failed, old remote and upstream bindings remain: {error}"))?;
            }
            repo.rename_upstream_remote(old, new).map_err(|error| format!("new remote configuration and available tracking were created; upstream rename failed, old remote remains; inspect upstream bindings before retrying: {error}"))?;
            fs::remove_file(directory.join(format!("{old}.json")))
                .map_err(|e| format!("new remote and upstream bindings were published; removing old remote configuration failed: {e}"))?;
            if tracking.is_some() {
                fs::remove_file(directory.join(format!("{old}.tracking.json")))
                    .map_err(|e| format!("new remote and upstream bindings were published and old configuration removed; removing old tracking failed: {e}"))?;
            }
            pretty(&remote)
        }
        ["fetch", root] | ["fetch", root, _] => {
            let repo = Repository::open(root)?;
            let remote = load(&repo, args.get(2).copied().unwrap_or("origin"))?;
            pretty(&fetch(&repo, &remote, allow_http)?)
        }
        ["pull", root, rest @ ..] => {
            let message_position = rest
                .iter()
                .position(|arg| matches!(*arg, "-m" | "--message"));
            let (positionals, message) = match message_position {
                Some(position) if position <= 2 && rest.len() == position + 2 => {
                    (&rest[..position], rest[position + 1])
                }
                None if ff_only && rest.len() <= 2 => (rest, ""),
                _ => return Err(USAGE.into()),
            };
            if let Some(option) = positionals
                .iter()
                .find(|argument| argument.starts_with('-'))
            {
                return Err(format!("unsupported pull option: {option}"));
            }
            let repo = Repository::open(root)?;
            // Bind both current branch and tip before network I/O. A concurrent
            // switch or receive must be rejected rather than merging the fetched
            // history into an independently selected later branch.
            let (before, remote, branch) = {
                let _lock = config_lock(&repo)?;
                let (before, upstreams) = repo.state_with_upstreams()?;
                let upstream = upstreams.get(&before.head);
                let remote_name = positionals.first().copied().unwrap_or_else(|| {
                    upstream.map_or("origin", |binding| binding.remote.as_str())
                });
                let branch = positionals
                    .get(1)
                    .copied()
                    .unwrap_or_else(|| {
                        upstream
                            .filter(|binding| binding.remote == remote_name)
                            .map_or(before.head.as_str(), |binding| binding.branch.as_str())
                    })
                    .to_owned();
                branch_name(&branch)?;
                let remote = load(&repo, remote_name)?;
                (before, remote, branch)
            };
            let state = fetch(&repo, &remote, allow_http)?;
            let tip = state.branches.get(&branch).ok_or_else(|| {
                if positionals.len() == 2 {
                    format!("remote branch {branch:?} has no commit")
                } else {
                    format!("selected remote has no branch {branch:?} for the current branch or its upstream; specify BRANCH explicitly")
                }
            })?;
            let expected_head = before.branches.get(&before.head).map(String::as_str);
            let outcome = if ff_only {
                repo.merge_ff_only_on_branch(tip, message, &before.head, expected_head)?
            } else if no_ff {
                repo.merge_no_ff_on_branch(tip, message, &before.head, expected_head)?
            } else {
                repo.merge_on_branch(tip, message, &before.head, expected_head)?
            };
            pretty(&outcome)
        }
        ["push", root, rest @ ..] => push_command(root, rest, allow_http),
        ["clone", url, destination] if is_remote_url(url) => {
            let endpoint = parse_url(url)?;
            let remote = Remote {
                version: 1,
                name: "origin".into(),
                url: (*url).to_owned(),
                allow_insecure_http: allow_http,
            };
            let (response, payload) = exchange(&remote, Operation::Fetch {}, &[], allow_http)?;
            let state = response
                .state
                .ok_or("clone response lacks repository state")?;
            if payload.is_empty() {
                return Err("clone response lacks its verified bundle".into());
            }
            if Repository::bundle_state(&payload)? != state {
                return Err("remote advertisement does not match cloned bundle".into());
            }
            // Verification and advertisement comparison precede initialization.
            let repo = Repository::clone_bundle_bytes(&payload, destination)?;
            let _lock = config_lock(&repo)?;
            let directory = config_dir(&repo)?;
            atomic_json(&repo, &directory.join("origin.json"), &remote)?;
            let initial_upstream = state
                .branches
                .get(&state.head)
                .map(|tip| (state.head.clone(), tip.clone()));
            atomic_json(
                &repo,
                &directory.join("origin.tracking.json"),
                &Tracking {
                    version: 1,
                    remote: "origin".into(),
                    url: (*url).to_owned(),
                    state,
                },
            )?;
            if let Some((branch, tip)) = initial_upstream {
                repo.set_upstream_checked(&branch, "origin", &branch, &tip, None)
                    .map_err(|error| format!("clone and origin tracking were created; configuring the initial upstream failed: {error}"))?;
            }
            Ok(format!(
                "cloned {} into {}",
                endpoint.repository(),
                repo.root.display()
            ))
        }
        _ => Err(USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn process_exit_does_not_disable_the_pipe_deadline() {
        // A finite child inherits both output pipes after its parent exits. The
        // caller must return a deadline error instead of waiting for pipe EOF
        // and then reporting the immediate parent's zero exit as success.
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 2 & exit 0"]);
        let error = subprocess_deadline(
            command,
            Vec::new(),
            "fixed pipe fixture",
            Duration::from_millis(30),
        )
        .unwrap_err();
        assert!(error.contains("deadline"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn an_exited_transport_without_descendants_still_returns_exact_bytes() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf fixed-response"]);
        let response = subprocess_deadline(
            command,
            Vec::new(),
            "fixed response fixture",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(response, b"fixed-response");
    }

    #[test]
    fn urls_have_one_unambiguous_repository_and_safe_ssh_arguments() {
        for url in [
            "http://127.0.0.1:1234/repo",
            "https://example.org/repo",
            "http://[::1]:1234/repo",
            "ssh://user@host:2222/tmp/repos/repo",
            "ssh://user@[::1]:2222/tmp/repos/repo",
        ] {
            assert!(parse_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://user:password@host/repo",
            "http://host/repo?token=x",
            "http://host/a/b",
            "ssh://-oProxyCommand=evil/tmp/repo",
            "ssh://host/tmp/../repo",
            "ssh://host//repo",
            "ssh://host/tmp/repo;id",
            "ssh://host:0/tmp/repo",
            "ssh://user@host:65536/tmp/repo",
            "ssh://user@host/tmp/%72epo",
            "ssh://user@host/tmp/repo\n",
            "http://host/repo#x",
        ] {
            assert!(parse_url(url).is_err(), "{url}");
        }
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
