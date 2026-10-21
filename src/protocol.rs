//! Versioned, bounded binary RPC used identically by HTTP and SSH.

use crate::repository::RepositoryState;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use std::io::{Cursor, Read, Write};

const MAGIC: &[u8; 8] = b"UWGRPC01";
pub const MAX_PACKET_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 65_536;
const HEADER_BYTES: usize = 20;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub repository: String,
    pub operation: Operation,
}

pub fn repository_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("invalid server repository name".into());
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefNamespace {
    Branch,
    Tag,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Advertise {},
    Fetch {},
    Push {
        branch: String,
        #[serde(deserialize_with = "present_option")]
        expected: Option<String>,
        force: bool,
    },
    UpdateRef {
        namespace: RefNamespace,
        name: String,
        #[serde(deserialize_with = "present_option")]
        expected: Option<String>,
        #[serde(deserialize_with = "present_option")]
        new: Option<String>,
        force: bool,
    },
}

// A nullable mutation operand must still be present. Serde's ordinary Option
// default would turn an omitted `new` into a deletion and an omitted lease into
// the explicit absence expectation. deserialize_with also makes absence an error.
fn present_option<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub ok: bool,
    #[serde(default)]
    pub publication_unknown: bool,
    pub error: Option<String>,
    pub state: Option<RepositoryState>,
    pub tip: Option<String>,
}

fn lengths(metadata: usize, payload: usize) -> Result<(), String> {
    if metadata == 0 || metadata > MAX_METADATA_BYTES {
        return Err("RPC metadata length is outside 1..=65536".into());
    }
    if HEADER_BYTES
        .checked_add(metadata)
        .and_then(|n| n.checked_add(payload))
        .is_none_or(|n| n > MAX_PACKET_BYTES)
    {
        return Err("RPC packet exceeds 64 MiB".into());
    }
    Ok(())
}

pub fn write_packet<W: Write, T: Serialize>(
    writer: &mut W,
    metadata: &T,
    payload: &[u8],
) -> Result<(), String> {
    let metadata = serde_json::to_vec(metadata).map_err(|e| e.to_string())?;
    lengths(metadata.len(), payload.len())?;
    writer
        .write_all(MAGIC)
        .and_then(|()| writer.write_all(&(metadata.len() as u32).to_be_bytes()))
        .and_then(|()| writer.write_all(&(payload.len() as u64).to_be_bytes()))
        .and_then(|()| writer.write_all(&metadata))
        .and_then(|()| writer.write_all(payload))
        .map_err(|e| format!("write RPC packet: {e}"))
}

/// Read one frame without waiting for EOF. Stream owners check EOF separately.
pub fn read_packet<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<(T, Vec<u8>), String> {
    let mut header = [0; HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .map_err(|e| format!("read RPC header: {e}"))?;
    if &header[..8] != MAGIC {
        return Err("unrecognized RPC magic/version".into());
    }
    let metadata = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
    let payload = usize::try_from(u64::from_be_bytes(header[12..20].try_into().unwrap()))
        .map_err(|_| "RPC payload length does not fit this platform")?;
    lengths(metadata, payload)?;
    let mut json = vec![0; metadata];
    reader
        .read_exact(&mut json)
        .map_err(|e| format!("read RPC metadata: {e}"))?;
    let metadata =
        serde_json::from_slice(&json).map_err(|e| format!("invalid RPC metadata: {e}"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(payload)
        .map_err(|e| format!("allocate RPC payload: {e}"))?;
    bytes.resize(payload, 0);
    reader
        .read_exact(&mut bytes)
        .map_err(|e| format!("read RPC payload: {e}"))?;
    Ok((metadata, bytes))
}

pub fn read_complete_packet<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, Vec<u8>), String> {
    let mut reader = Cursor::new(bytes);
    let packet = read_packet(&mut reader)?;
    if reader.position() != bytes.len() as u64 {
        return Err("trailing bytes after RPC packet".into());
    }
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            version: 1,
            repository: "project".into(),
            operation: Operation::Fetch {},
        }
    }

    #[test]
    fn publication_outcome_flag_is_explicit_and_older_responses_default_to_known() {
        let legacy =
            br#"{"version":1,"ok":false,"error":"known rejection","state":null,"tip":null}"#;
        let response: Response = serde_json::from_slice(legacy).unwrap();
        assert!(!response.publication_unknown);
        let unknown = br#"{"version":1,"ok":false,"publication_unknown":true,"error":"inspect ref","state":null,"tip":null}"#;
        let response: Response = serde_json::from_slice(unknown).unwrap();
        assert!(response.publication_unknown);
    }

    #[test]
    fn packet_roundtrip_and_every_fixed_truncation() {
        let mut bytes = Vec::new();
        write_packet(&mut bytes, &request(), b"\0\xffpayload").unwrap();
        let (got, payload): (Request, _) = read_complete_packet(&bytes).unwrap();
        assert_eq!(got.repository, "project");
        assert_eq!(payload, b"\0\xffpayload");
        for end in [0, 7, 8, 11, 19, 20, bytes.len() - 1] {
            assert!(read_complete_packet::<Request>(&bytes[..end]).is_err());
        }
        bytes.push(0);
        assert!(read_complete_packet::<Request>(&bytes)
            .unwrap_err()
            .contains("trailing"));
    }

    #[test]
    fn lengths_and_unknown_fields_fail_before_payload_allocation() {
        for (metadata, payload) in [
            (0u32, 0u64),
            (65_537, 0),
            (1, u64::MAX),
            (1, MAX_PACKET_BYTES as u64),
        ] {
            let mut bytes = MAGIC.to_vec();
            bytes.extend(metadata.to_be_bytes());
            bytes.extend(payload.to_be_bytes());
            assert!(read_complete_packet::<Request>(&bytes).is_err());
        }
        for kind in ["advertise", "fetch"] {
            let metadata = serde_json::json!({"version":1,"repository":"x","operation":{"kind":kind,"unknown":true}});
            let mut bytes = Vec::new();
            write_packet(&mut bytes, &metadata, &[]).unwrap();
            assert!(read_complete_packet::<Request>(&bytes).is_err(), "{kind}");
        }
    }

    #[test]
    fn nullable_mutation_operands_must_be_present_but_explicit_null_remains_valid() {
        for (mut operation, missing) in [
            (
                serde_json::json!({"kind":"push","branch":"topic","expected":null,"force":false}),
                "expected",
            ),
            (
                serde_json::json!({"kind":"update_ref","namespace":"tag","name":"v1","expected":null,"new":null,"force":false}),
                "expected",
            ),
            (
                serde_json::json!({"kind":"update_ref","namespace":"branch","name":"topic","expected":null,"new":null,"force":false}),
                "new",
            ),
        ] {
            operation.as_object_mut().unwrap().remove(missing);
            let metadata =
                serde_json::json!({"version":1,"repository":"project","operation":operation});
            let mut frame = Vec::new();
            write_packet(&mut frame, &metadata, &[]).unwrap();
            let error = read_complete_packet::<Request>(&frame).unwrap_err();
            assert!(
                error.contains("missing field") && error.contains(missing),
                "{error}"
            );
        }
        for operation in [
            serde_json::json!({"kind":"push","branch":"topic","expected":null,"force":false}),
            serde_json::json!({"kind":"update_ref","namespace":"tag","name":"v1","expected":null,"new":null,"force":false}),
            serde_json::json!({"kind":"update_ref","namespace":"branch","name":"topic","expected":"a".repeat(64),"new":"b".repeat(64),"force":true}),
        ] {
            let metadata =
                serde_json::json!({"version":1,"repository":"project","operation":operation});
            let request: Request = serde_json::from_value(metadata.clone()).unwrap();
            assert_eq!(serde_json::to_value(request).unwrap(), metadata);
        }
    }
}
