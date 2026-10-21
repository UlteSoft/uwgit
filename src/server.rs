//! Bounded HTTP RPC and SSH-invoked stdio service. Never executes Wasm.

use crate::protocol::{self, Operation, RefNamespace, Request, Response};
use crate::repository::{ReceiveError, Repository};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const USAGE: &str = "server --root DIR [--listen 127.0.0.1:9419] [--token-file FILE] [--allow-write] [--allow-force] [--max-connections N]; server --stdio --root DIR [--allow-force]";
const MAX_HEADER: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

struct Settings {
    root: PathBuf,
    token: Option<Vec<u8>>,
    write: bool,
    force: bool,
}

/// Refuse symbolic links in every existing path component, including root.
fn real_path(path: &Path, directory: bool) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => return Err("server paths must not contain '..'".into()),
            Component::CurDir => continue,
            _ => prefix.push(component),
        }
        let metadata = fs::symlink_metadata(&prefix).map_err(|e| format!("server path: {e}"))?;
        if metadata.file_type().is_symlink() {
            return Err("server paths must not contain symbolic links".into());
        }
    }
    let metadata = fs::symlink_metadata(&prefix).map_err(|e| e.to_string())?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err("server path has the wrong file type".into());
    }
    Ok(prefix)
}

fn repository_name(name: &str) -> Result<(), String> {
    protocol::repository_name(name)
}

fn process(
    settings: &Settings,
    request: Request,
    payload: &[u8],
) -> Result<(Response, Vec<u8>), String> {
    if request.version != 1 {
        return Err("unsupported RPC version".into());
    }
    repository_name(&request.repository)?;
    let root = real_path(&settings.root.join(&request.repository), true)?;
    let repository = Repository::open(root)?;
    let mut response = Response {
        version: 1,
        ok: true,
        publication_unknown: false,
        error: None,
        state: None,
        tip: None,
    };
    let bytes = match request.operation {
        Operation::Advertise {} => {
            if !payload.is_empty() {
                return Err("advertise requires an empty payload".into());
            }
            response.state = Some(repository.state()?);
            Vec::new()
        }
        Operation::Fetch {} => {
            if !payload.is_empty() {
                return Err("fetch requires an empty payload".into());
            }
            let (state, bytes) = repository.bundle_bytes(None)?;
            response.state = Some(state);
            bytes
        }
        Operation::Push {
            branch,
            expected,
            force,
        } => {
            if !settings.write {
                return Err("server is read-only".into());
            }
            if force && !settings.force {
                return Err("server does not allow forced updates".into());
            }
            match repository.receive_bundle_checked(payload, &branch, expected.as_deref(), force) {
                Ok(tip) => response.tip = Some(tip),
                Err(error) => return Ok((receive_error_response(error), Vec::new())),
            }
            // The successful receive already identifies the exact published tip.
            // A second, independently locked state read could fail after commit
            // or describe a later writer, falsely reporting this push as failed.
            Vec::new()
        }
        Operation::UpdateRef {
            namespace,
            name,
            expected,
            new,
            force,
        } => {
            if !settings.write {
                return Err("server is read-only".into());
            }
            if force && !settings.force {
                return Err("server does not allow forced updates".into());
            }
            let namespace = match namespace {
                RefNamespace::Branch => "branch",
                RefNamespace::Tag => "tag",
            };
            match repository.receive_ref_bundle_checked(
                payload,
                namespace,
                &name,
                expected.as_deref(),
                new.as_deref(),
                force,
            ) {
                Ok(tip) => response.tip = tip,
                Err(error) => return Ok((receive_error_response(error), Vec::new())),
            }
            Vec::new()
        }
    };
    Ok((response, bytes))
}

fn receive_error_response(error: ReceiveError) -> Response {
    Response {
        version: 1,
        ok: false,
        publication_unknown: error.publication_unknown,
        error: Some(error.message),
        state: None,
        tip: None,
    }
}

fn response_packet(response: &Response, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    if let Err(error) = protocol::write_packet(&mut bytes, response, payload) {
        // Oversized advertisements/transfers are application errors too. Keep
        // the bounded error frame readable rather than silently close a socket.
        bytes.clear();
        let response = Response {
            version: 1,
            ok: false,
            publication_unknown: response.publication_unknown
                || (response.ok && response.tip.is_some()),
            error: Some(format!("cannot encode RPC response: {error}")),
            state: None,
            tip: None,
        };
        protocol::write_packet(&mut bytes, &response, &[])?;
    }
    Ok(bytes)
}

fn rpc(settings: &Settings, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let outcome = protocol::read_complete_packet::<Request>(bytes)
        .and_then(|(request, payload)| process(settings, request, &payload));
    let (response, payload) = outcome.unwrap_or_else(|error| {
        (
            Response {
                version: 1,
                ok: false,
                publication_unknown: false,
                error: Some(error),
                state: None,
                tip: None,
            },
            Vec::new(),
        )
    });
    response_packet(&response, &payload)
}

fn equal_secret(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for (index, byte) in right.iter().enumerate() {
        difference |= usize::from(*byte ^ left.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

fn read_headers<R: Read>(reader: &mut R) -> Result<BTreeMap<String, String>, String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == MAX_HEADER {
            return Err("HTTP headers exceed 16 KiB".into());
        }
        let mut byte = [0];
        reader
            .read_exact(&mut byte)
            .map_err(|e| format!("read HTTP headers: {e}"))?;
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "HTTP headers must be ASCII")?;
    if !text.is_ascii() {
        return Err("HTTP headers must be ASCII".into());
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    if !matches!(
        lines.next(),
        Some("POST /v1/uwgit HTTP/1.1" | "POST /v1/uwgit HTTP/1.0")
    ) {
        return Err("expected POST /v1/uwgit HTTP/1.1".into());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
        if name.is_empty()
            || !name.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return Err("invalid HTTP header name".into());
        }
        if value.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
            return Err("invalid HTTP header value".into());
        }
        if headers
            .insert(
                name.to_ascii_lowercase(),
                value.trim_matches([' ', '\t']).to_owned(),
            )
            .is_some()
        {
            return Err("duplicate HTTP header".into());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err("Transfer-Encoding is not supported; use Content-Length".into());
    }
    if headers.get("host").is_none_or(|h| h.is_empty()) {
        return Err("HTTP Host is required".into());
    }
    Ok(headers)
}

/// One wall-clock I/O budget covers the entire connection. Per-read socket
/// timeouts alone allow a client making tiny progress to retain a worker forever.
struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "HTTP connection deadline exceeded")
            })
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

fn http_response(
    stream: &mut impl Write,
    status: &str,
    bytes: &[u8],
    binary: bool,
) -> Result<(), String> {
    let content_type = if binary {
        "application/octet-stream"
    } else {
        "text/plain; charset=utf-8"
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", bytes.len())
        .and_then(|()| stream.write_all(bytes))
        .and_then(|()| stream.flush())
        .map_err(|e| format!("write HTTP response: {e}"))
}

fn connection(stream: TcpStream, settings: &Settings, deadline: Instant) -> Result<(), String> {
    let mut stream = DeadlineStream { stream, deadline };
    let result = http_request(&mut stream, settings);
    finish_http(&mut stream);
    result
}

// RFC 9112 section 9.6: closing with unread request bytes can reset TCP and
// discard the response at the client. Send the response and FIN first, then
// discard pending input without parsing it or extending the connection budget.
// A peer waiting for an Expect rejection can see the complete response and EOF
// without transmitting a body. Excess input is bounded in both bytes and time.
fn finish_http(stream: &mut DeadlineStream) -> usize {
    if stream.stream.shutdown(Shutdown::Write).is_err() {
        return 0;
    }
    let mut buffer = [0u8; 16 * 1024];
    let mut consumed = 0;
    let limit = protocol::MAX_PACKET_BYTES + MAX_HEADER;
    while consumed < limit {
        let length = buffer.len().min(limit - consumed);
        match stream.read(&mut buffer[..length]) {
            Ok(0) => break,
            Ok(length) => consumed += length,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    consumed
}

fn http_request(stream: &mut DeadlineStream, settings: &Settings) -> Result<(), String> {
    let headers = match read_headers(stream) {
        Ok(headers) => headers,
        Err(error) => return http_response(stream, "400 Bad Request", error.as_bytes(), false),
    };
    if let Some(token) = &settings.token {
        let supplied = headers
            .get("authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("");
        if !equal_secret(supplied.as_bytes(), token) {
            return http_response(
                stream,
                "401 Unauthorized",
                b"authentication required",
                false,
            );
        }
    }
    let Some(length_text) = headers.get("content-length") else {
        return http_response(
            stream,
            "411 Length Required",
            b"Content-Length is required",
            false,
        );
    };
    if length_text.is_empty() || !length_text.bytes().all(|b| b.is_ascii_digit()) {
        return http_response(stream, "400 Bad Request", b"invalid Content-Length", false);
    }
    let Some(length) = length_text
        .parse::<usize>()
        .ok()
        .filter(|n| *n <= protocol::MAX_PACKET_BYTES)
    else {
        return http_response(
            stream,
            "413 Content Too Large",
            b"Content-Length must not exceed 64 MiB",
            false,
        );
    };
    if let Some(expect) = headers.get("expect") {
        if !expect.eq_ignore_ascii_case("100-continue") {
            return http_response(
                stream,
                "417 Expectation Failed",
                b"unsupported Expect",
                false,
            );
        }
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|e| e.to_string())?;
    }
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|e| format!("allocate HTTP body: {e}"))?;
    body.resize(length, 0);
    if let Err(error) = stream.read_exact(&mut body) {
        return http_response(
            stream,
            "400 Bad Request",
            format!("incomplete HTTP body: {error}").as_bytes(),
            false,
        );
    }
    let bytes = rpc(settings, &body)?;
    http_response(stream, "200 OK", &bytes, true)
}

fn read_token_file(path: &Path) -> Result<Vec<u8>, String> {
    let path = real_path(path, false)?;
    // The optional single LF is framing, outside the 1..4096 token bytes.
    if fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len()
        > 4097
    {
        return Err("token file exceeds 4097 bytes including its optional final newline".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(4098)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.ends_with(b"\n") {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.len() > 4096 || bytes.iter().any(|byte| !(33..=126).contains(byte))
    {
        return Err("token must contain 1..4096 printable ASCII bytes without whitespace".into());
    }
    Ok(bytes)
}

pub fn run(args: &[String]) -> Result<String, String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Ok(USAGE.into());
    }
    let mut root = None;
    let mut listen = "127.0.0.1:9419".to_owned();
    let mut listen_selected = false;
    let mut token_file = None;
    let mut stdio = false;
    let mut write = false;
    let mut force = false;
    let mut max_connections = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--stdio" => stdio = true,
            "--allow-write" => write = true,
            "--allow-force" => force = true,
            flag @ ("--root" | "--listen" | "--token-file" | "--max-connections") => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| format!("missing {flag} value; {USAGE}"))?;
                match flag {
                    "--root" => root = Some(PathBuf::from(value)),
                    "--listen" => {
                        listen = value.clone();
                        listen_selected = true;
                    }
                    "--token-file" => token_file = Some(PathBuf::from(value)),
                    _ => {
                        max_connections = Some(
                            value
                                .parse::<usize>()
                                .ok()
                                .filter(|n| *n > 0)
                                .ok_or("invalid maximum connections")?,
                        )
                    }
                }
            }
            _ => return Err(format!("unknown server argument; {USAGE}")),
        }
        index += 1;
    }
    if stdio && (listen_selected || max_connections.is_some()) {
        return Err("--listen and --max-connections are HTTP-only options".into());
    }
    let root = real_path(
        &root.ok_or_else(|| format!("--root is required; {USAGE}"))?,
        true,
    )?;
    let token = token_file.map(|path| read_token_file(&path)).transpose()?;
    if stdio && token.is_some() {
        return Err("stdio uses SSH authentication; token-file is for HTTP".into());
    }
    if !stdio && write && token.is_none() {
        return Err("HTTP --allow-write requires --token-file".into());
    }
    let settings = Arc::new(Settings {
        root,
        token,
        write: stdio || write,
        force,
    });
    if stdio {
        let mut input = std::io::stdin().lock();
        let (request, payload) = protocol::read_packet::<_, Request>(&mut input)?;
        let mut extra = [0];
        if input.read(&mut extra).map_err(|e| e.to_string())? != 0 {
            return Err("trailing bytes after stdio request".into());
        }
        let result = process(&settings, request, &payload);
        let (response, payload) = result.unwrap_or_else(|error| {
            (
                Response {
                    version: 1,
                    ok: false,
                    publication_unknown: false,
                    error: Some(error),
                    state: None,
                    tip: None,
                },
                Vec::new(),
            )
        });
        let mut output = std::io::stdout().lock();
        let bytes = response_packet(&response, &payload)?;
        output
            .write_all(&bytes)
            .map_err(|e| format!("write stdio response: {e}"))?;
        output.flush().map_err(|e| e.to_string())?;
        return Ok(String::new());
    }
    let listener = TcpListener::bind(&listen).map_err(|e| format!("listen: {e}"))?;
    println!(
        "{}",
        serde_json::json!({"listen":listener.local_addr().map_err(|e| e.to_string())?.to_string(),"read_only":!write,"protocol":1})
    );
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    for (accepted, incoming) in listener.incoming().enumerate() {
        let stream = incoming.map_err(|e| format!("accept: {e}"))?;
        let deadline = Instant::now() + TIMEOUT;
        if workers.len() == 16 {
            workers
                .remove(0)
                .join()
                .map_err(|_| "server worker panicked")?;
        }
        let settings = Arc::clone(&settings);
        workers.push(std::thread::spawn(move || {
            if let Err(error) = connection(stream, &settings, deadline) {
                eprintln!("server connection: {error}");
            }
        }));
        if max_connections.is_some_and(|maximum| accepted >= maximum - 1) {
            break;
        }
    }
    for worker in workers {
        worker.join().map_err(|_| "server worker panicked")?;
    }
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_framing_rejects_ambiguity_and_oversized_headers() {
        for request in [
            "POST /v1/uwgit HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            "POST /v1/uwgit HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /v1/uwgit HTTP/1.1\r\nHost : x\r\n\r\n",
            "POST /v1/uwgit HTTP/1.1\r\n\r\n",
            "GET /v1/uwgit HTTP/1.1\r\nHost: x\r\n\r\n",
        ] {
            assert!(read_headers(&mut request.as_bytes()).is_err());
        }
        assert!(read_headers(&mut vec![b'x'; MAX_HEADER + 1].as_slice()).is_err());
        assert!(read_headers(
            &mut b"POST /v1/uwgit HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n".as_slice()
        )
        .is_ok());
    }

    #[test]
    fn typed_receive_uncertainty_survives_rpc_encoding() {
        for publication_unknown in [false, true] {
            let response = receive_error_response(ReceiveError {
                message: "a typed receive outcome".into(),
                publication_unknown,
            });
            let bytes = response_packet(&response, &[]).unwrap();
            let (decoded, payload): (Response, _) = protocol::read_complete_packet(&bytes).unwrap();
            assert!(!decoded.ok);
            assert_eq!(decoded.publication_unknown, publication_unknown);
            assert_eq!(decoded.error.as_deref(), Some("a typed receive outcome"));
            assert!(payload.is_empty());
        }
    }

    #[test]
    fn oversized_response_is_a_readable_error_frame() {
        let response = Response {
            version: 1,
            ok: true,
            publication_unknown: false,
            error: None,
            state: None,
            tip: Some("x".repeat(65_536)),
        };
        let bytes = response_packet(&response, &[]).unwrap();
        let (response, payload): (Response, _) = protocol::read_complete_packet(&bytes).unwrap();
        assert!(!response.ok);
        assert!(response.error.unwrap().contains("metadata length"));
        assert!(response.tip.is_none());
        assert!(payload.is_empty());
    }

    #[test]
    fn connection_deadline_does_not_reset_when_reads_make_progress() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.write_all(b"xy").unwrap();
        let mut reader = DeadlineStream {
            stream: server,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        let mut byte = [0];
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'x']);
        // Moving the fixed deadline into the past avoids a sleeping test and
        // proves buffered progress cannot renew the connection's total budget.
        reader.deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        assert_eq!(
            reader.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            reader.write(b"late").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn rejected_expect_sends_response_and_fin_before_waiting_for_a_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let settings = Settings {
            root: PathBuf::from("/tmp"),
            token: Some(b"required-token".to_vec()),
            write: false,
            force: false,
        };
        let worker = std::thread::spawn(move || {
            connection(server, &settings, Instant::now() + Duration::from_secs(10))
        });
        client.write_all(b"POST /v1/uwgit HTTP/1.1\r\nHost: x\r\nContent-Length: 4096\r\nExpect: 100-continue\r\n\r\n").unwrap();
        // No body and no write shutdown: receiving the final response and EOF
        // must not depend on sending bytes that the rejected client will omit.
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
        assert!(response.ends_with(b"\r\n\r\nauthentication required"));
        assert!(!response.windows(12).any(|part| part == b"100 Continue"));
        client.shutdown(Shutdown::Write).unwrap();
        assert!(worker.join().unwrap().is_ok());
    }

    #[test]
    fn graceful_close_cannot_drain_queued_input_after_the_original_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.write_all(b"queued input").unwrap();
        let mut stream = DeadlineStream {
            stream: server,
            deadline: Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        };
        assert_eq!(finish_http(&mut stream), 0);
        // The raw descriptor still has the bytes: graceful teardown did not
        // reset the fixed deadline even when input was immediately readable.
        stream
            .stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut pending = [0u8; 12];
        stream.stream.read_exact(&mut pending).unwrap();
        assert_eq!(&pending, b"queued input");
    }

    #[test]
    fn repository_names_and_tokens_are_exact() {
        for name in ["", "..", ".hidden", "../x", "x/y", "%2e", "a\\b"] {
            assert!(repository_name(name).is_err());
        }
        assert!(repository_name("wasm-project.1").is_ok());
        assert!(equal_secret(b"secret", b"secret"));
        assert!(!equal_secret(b"secre", b"secret"));
        assert!(!equal_secret(b"secretX", b"secret"));
    }

    #[test]
    fn token_length_excludes_one_optional_final_line_feed() {
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let path = PathBuf::from("/tmp").join(format!(
            "uwgit-token-boundary-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let fixture = Fixture(path);
        for length in [1, 4095, 4096] {
            for newline in [false, true] {
                let expected = vec![b'T'; length];
                let mut file = expected.clone();
                if newline {
                    file.push(b'\n');
                }
                fs::write(&fixture.0, file).unwrap();
                assert_eq!(read_token_file(&fixture.0).unwrap(), expected);
            }
        }
        for bytes in [
            Vec::new(),
            b"\n".to_vec(),
            b"token\n\n".to_vec(),
            b"token\r\n".to_vec(),
            b"token\0".to_vec(),
            vec![0xff],
            vec![b'T'; 4097],
            [vec![b'T'; 4097], b"\n".to_vec()].concat(),
            [vec![b'T'; 4096], b"\n\n".to_vec()].concat(),
        ] {
            fs::write(&fixture.0, bytes).unwrap();
            assert!(read_token_file(&fixture.0).is_err());
        }
    }
}
