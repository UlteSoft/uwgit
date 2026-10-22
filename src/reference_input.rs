//! Streaming update-ref input. Prepared transactions keep the shared writer
//! lock until commit/abort/EOF; acknowledgements are flushed immediately.
use crate::repository::{
    ReferenceEdit, ReferenceEditKind, ReferenceExpectation, Repository, RepositoryResult,
};
use std::io::{BufRead, Read, Write};

const MAX_FIELD: u64 = 8192;

fn field(input: &mut impl BufRead, delimiter: u8) -> RepositoryResult<Option<String>> {
    let mut bytes = Vec::new();
    let count = input
        .take(MAX_FIELD + 1)
        .read_until(delimiter, &mut bytes)
        .map_err(|error| error.to_string())?;
    if count == 0 {
        return Ok(None);
    }
    if bytes.len() as u64 > MAX_FIELD {
        return Err("update-ref input record exceeds 8192 bytes".into());
    }
    if bytes.pop() != Some(delimiter) {
        return Err("unterminated update-ref input record".into());
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "update-ref requires UTF-8 input".into())
}

// Git's text protocol quotes fields as C strings, including octal escapes.
fn words(line: &str) -> RepositoryResult<Vec<String>> {
    let mut input = line.as_bytes().iter().copied().peekable();
    let mut result = Vec::new();
    while let Some(first) = input.next() {
        if first == b' ' || first == b'\t' {
            return Err("unexpected whitespace in update-ref input".into());
        }
        let mut word = Vec::new();
        if first == b'"' {
            loop {
                match input.next().ok_or("unclosed update-ref quoted field")? {
                    b'"' => break,
                    b'\\' => {
                        let escape = input.next().ok_or("incomplete update-ref escape")?;
                        let byte = match escape {
                            b'a' => 7,
                            b'b' => 8,
                            b't' => b'\t',
                            b'n' => b'\n',
                            b'v' => 11,
                            b'f' => 12,
                            b'r' => b'\r',
                            b'\\' => b'\\',
                            b'"' => b'"',
                            b'0'..=b'3' => {
                                let mut value = escape - b'0';
                                for _ in 0..2 {
                                    let digit = input.next().ok_or("incomplete octal escape")?;
                                    if !(b'0'..=b'7').contains(&digit) {
                                        return Err("invalid octal escape".into());
                                    }
                                    value = value * 8 + digit - b'0';
                                }
                                value
                            }
                            _ => return Err("unsupported update-ref quoted escape".into()),
                        };
                        word.push(byte);
                    }
                    byte => word.push(byte),
                }
            }
        } else {
            word.push(first);
            while input.peek().is_some_and(|byte| *byte != b' ') {
                word.push(input.next().unwrap());
            }
        }
        result.push(String::from_utf8(word).map_err(|_| "update-ref quoted field is not UTF-8")?);
        if let Some(separator) = input.next() {
            if separator != b' ' || input.peek().is_none() {
                return Err("invalid update-ref field separator".into());
            }
        }
    }
    if result.is_empty() {
        return Err("empty update-ref command".into());
    }
    Ok(result)
}

fn record(input: &mut impl BufRead, nul: bool) -> RepositoryResult<Option<Vec<String>>> {
    let Some(line) = field(input, if nul { 0 } else { b'\n' })? else {
        return Ok(None);
    };
    if !nul {
        return words(&line).map(Some);
    }
    let mut fields = line.splitn(2, ' ').map(str::to_owned).collect::<Vec<_>>();
    let needed = match fields[0].as_str() {
        "update" => 2,
        "symref-update" => 3,
        "create" | "delete" | "verify" | "symref-verify" => 1,
        "option" | "start" | "prepare" | "commit" | "abort" => 0,
        _ => return Err("unsupported update-ref input command".into()),
    };
    for _ in 0..needed {
        fields.push(field(input, 0)?.ok_or("incomplete NUL update-ref command")?);
    }
    Ok(Some(fields))
}

fn edit(fields: &[String], nul: bool, no_deref: bool) -> RepositoryResult<ReferenceEdit> {
    let old_oid = |value: &str| {
        if nul && value.is_empty() {
            None
        } else {
            Some(ReferenceExpectation::Oid(value.into()))
        }
    };
    let (kind, new, expected) = match fields {
        [command, _, new] if command == "update" => {
            (ReferenceEditKind::Update, Some(new.clone()), None)
        }
        [command, _, new, old] if command == "update" => {
            (ReferenceEditKind::Update, Some(new.clone()), old_oid(old))
        }
        [command, _, new] if command == "create" => {
            (ReferenceEditKind::Create, Some(new.clone()), None)
        }
        [command, _] if command == "delete" => (ReferenceEditKind::Delete, None, None),
        [command, _, old] if command == "delete" => (ReferenceEditKind::Delete, None, old_oid(old)),
        [command, _] if command == "verify" => (ReferenceEditKind::Verify, None, None),
        [command, _, old] if command == "verify" => (ReferenceEditKind::Verify, None, old_oid(old)),
        [command, _, new] if command == "symref-update" => {
            (ReferenceEditKind::SymrefUpdate, Some(new.clone()), None)
        }
        [command, _, new, mode, old] if command == "symref-update" => {
            let expected = match mode.as_str() {
                "ref" if !old.is_empty() => Some(ReferenceExpectation::Target(old.clone())),
                "oid" if !old.is_empty() => Some(ReferenceExpectation::Oid(old.clone())),
                "" if nul && old.is_empty() => None,
                _ => return Err("symref-update requires ref OLD_TARGET or oid OLD_ID".into()),
            };
            (ReferenceEditKind::SymrefUpdate, Some(new.clone()), expected)
        }
        [command, _] if command == "symref-verify" => (ReferenceEditKind::SymrefVerify, None, None),
        [command, _, old] if command == "symref-verify" => (
            ReferenceEditKind::SymrefVerify,
            None,
            if old.is_empty() {
                None
            } else {
                Some(ReferenceExpectation::Target(old.clone()))
            },
        ),
        _ => return Err("invalid update-ref command or field count".into()),
    };
    let symbolic = matches!(
        kind,
        ReferenceEditKind::SymrefUpdate | ReferenceEditKind::SymrefVerify
    );
    if symbolic && !no_deref {
        return Err("native symref HEAD commands require --no-deref or option no-deref".into());
    }
    if fields[1] == "HEAD" {
        if symbolic {
            for value in new
                .iter()
                .chain(expected.iter().filter_map(|expected| match expected {
                    ReferenceExpectation::Target(value) => Some(value),
                    _ => None,
                }))
            {
                let branch = value
                    .strip_prefix("refs/heads/")
                    .ok_or("native symbolic HEAD requires refs/heads/NAME")?;
                crate::repository::validate_ref_name(branch)?;
            }
        }
    } else {
        if symbolic {
            return Err("HEAD is the native symbolic reference".into());
        }
        let name = fields[1]
            .strip_prefix("refs/heads/")
            .or_else(|| fields[1].strip_prefix("refs/tags/"))
            .ok_or("update-ref requires refs/heads/NAME or refs/tags/NAME")?;
        crate::repository::validate_ref_name(name)?;
    }
    Ok(ReferenceEdit {
        kind,
        reference: fields[1].clone(),
        new,
        expected,
        no_deref,
    })
}

pub(super) fn run(
    repo: &Repository,
    nul: bool,
    allow_failures: bool,
    no_deref: bool,
    message: &str,
) -> RepositoryResult<()> {
    run_stream(
        repo,
        nul,
        allow_failures,
        no_deref,
        message,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}

fn run_stream(
    repo: &Repository,
    nul: bool,
    allow_failures: bool,
    no_deref: bool,
    message: &str,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> RepositoryResult<()> {
    let mut edits = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    let mut prepared = None;
    let mut explicit = false;
    let mut closed = false;
    let mut option_pending = false;
    while let Some(fields) = record(input, nul)? {
        if option_pending && matches!(fields[0].as_str(), "start" | "prepare" | "commit" | "abort")
        {
            return Err("no-deref option must precede a reference command".into());
        }
        match fields.as_slice() {
            [command] if command == "start" => {
                if prepared.is_some() || (explicit && !closed) {
                    return Err("transaction is already started".into());
                }
                explicit = true;
                closed = false;
            }
            [command] if command == "prepare" => {
                if closed || prepared.is_some() {
                    return Err("transaction is closed or already prepared".into());
                }
                prepared = Some(repo.prepare_reference_batch(&edits, message, allow_failures)?);
                explicit = true;
            }
            [command] if command == "commit" => {
                if closed {
                    return Err("transaction is closed; start another transaction".into());
                }
                let outcome = prepared
                    .take()
                    .map(Ok)
                    .unwrap_or_else(|| {
                        repo.prepare_reference_batch(&edits, message, allow_failures)
                    })?
                    .commit()?;
                for rejection in outcome.rejections {
                    writeln!(output, "{rejection}").map_err(|error| {
                        format!("reference batch committed but rejection reporting failed: {error}")
                    })?;
                }
                edits.clear();
                names.clear();
                closed = true;
            }
            [command] if command == "abort" => {
                if closed {
                    return Err("transaction is closed; start another transaction".into());
                }
                prepared = None;
                edits.clear();
                names.clear();
                closed = true;
            }
            [command, option] if command == "option" && option == "no-deref" => {
                if closed || prepared.is_some() || option_pending {
                    return Err("option requires an open, unprepared next reference command".into());
                }
                option_pending = true;
                continue;
            }
            _ => {
                if closed || prepared.is_some() {
                    return Err(
                        "cannot queue references in a closed or prepared transaction".into(),
                    );
                }
                let edit = edit(&fields, nul, no_deref || option_pending)?;
                if !names.insert(edit.reference.clone()) {
                    return Err("duplicate reference in transaction".into());
                }
                if edits.len() == 4096 {
                    return Err("reference transaction exceeds 4096 edits".into());
                }
                edits.push(edit);
                option_pending = false;
                continue;
            }
        }
        writeln!(output, "{}: ok", fields[0])
            .and_then(|()| output.flush())
            .map_err(|error| {
                format!("transaction control completed but acknowledgement failed: {error}")
            })?;
    }
    if option_pending {
        return Err("unused update-ref no-deref option".into());
    }
    if !explicit && !closed {
        let outcome = prepared
            .map(Ok)
            .unwrap_or_else(|| repo.prepare_reference_batch(&edits, message, allow_failures))?
            .commit()?;
        for rejection in outcome.rejections {
            writeln!(output, "{rejection}").map_err(|error| {
                format!("reference batch committed but rejection reporting failed: {error}")
            })?;
        }
        output.flush().map_err(|error| {
            format!("reference batch committed but response flush failed: {error}")
        })?;
    }
    // An explicitly started uncommitted transaction is aborted on EOF. Dropping
    // its prepared guard releases the writer lock without persisting a decision.
    Ok(())
}
