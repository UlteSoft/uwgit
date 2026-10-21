//! Input for Core readers which ignore custom metadata, never stored Wasm bytes.
use std::borrow::Cow;

use serde::Serialize;
use wasmparser::BinaryReader;

use crate::audit::Span;

// wasmparser 0.249.0's private MAX_WASM_STRING_SIZE. This is an implementation
// limit on read_string(), not a bound in the Core name grammar.
const PINNED_NAME_LIMIT: usize = 100_000;

#[derive(Debug, Clone, Serialize)]
pub struct CustomNameProjection {
    pub path: String,
    /// Original length LEB and name bytes, including neither section header nor data.
    pub name_span: Span,
    /// The only changed byte in the temporary reader input.
    pub byte_span: Span,
    pub original_hex: String,
    pub projected_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorInput {
    /// original_bytes or custom_name_projection; all Core offsets are unchanged.
    pub kind: String,
    pub projections: Vec<CustomNameProjection>,
}

impl Default for ValidatorInput {
    fn default() -> Self {
        Self {
            kind: "original_bytes".into(),
            projections: Vec::new(),
        }
    }
}

pub(crate) struct ReaderView<'a> {
    pub bytes: Cow<'a, [u8]>,
    pub report: ValidatorInput,
}

impl<'a> ReaderView<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        let mut view = Self {
            bytes: Cow::Borrowed(bytes),
            report: ValidatorInput::default(),
        };
        if !bytes.starts_with(b"\0asm\x01\0\0\0") {
            return view;
        }
        let mut cursor = BinaryReader::new(&bytes[8..], 8);
        let mut custom_index = 0usize;
        while !cursor.eof() {
            let Ok(id) = cursor.read_u8() else { break };
            let Ok(size) = cursor.read_var_u32() else {
                break;
            };
            let start = cursor.original_position();
            if size as usize > cursor.bytes_remaining() {
                break;
            }
            let Ok(payload) = cursor.read_bytes(size as usize) else {
                break;
            };
            if id != 0 {
                continue;
            }
            let index = custom_index;
            custom_index += 1;
            // The bounded slice is essential: a truncated name must never
            // borrow bytes from the following independently framed section.
            let mut name_reader = BinaryReader::new(payload, start);
            let Ok(name_len) = name_reader.read_var_u32() else {
                continue;
            };
            if name_len as usize > name_reader.bytes_remaining() {
                continue;
            }
            let Ok(name) = name_reader.read_bytes(name_len as usize) else {
                continue;
            };
            if std::str::from_utf8(name).is_err() || name.len() <= PINNED_NAME_LIMIT {
                continue;
            }
            // The complete original Core name is legal. Let the pinned reader
            // see an empty name followed by uninterpreted custom data instead.
            // No section length or non-custom byte/offset changes. The custom
            // reader's projected data_offset must never be used for raw audit.
            view.bytes.to_mut()[start] = 0;
            view.report.projections.push(CustomNameProjection {
                path: format!("custom[{index}]/name"),
                name_span: Span {
                    start,
                    end: name_reader.original_position(),
                },
                byte_span: Span {
                    start,
                    end: start + 1,
                },
                original_hex: format!("{:02x}", bytes[start]),
                projected_hex: "00".into(),
            });
        }
        if !view.report.projections.is_empty() {
            view.report.kind = "custom_name_projection".into();
        }
        view
    }
}
