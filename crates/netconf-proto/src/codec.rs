// Copyright (C) 2026-present The NetCalyx Authors.
// Copyright (C) 2025-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Codec to read NETCONF in accordance with [RFC 6242](https://datatracker.ietf.org/doc/html/rfc6242).
//!
//! This codec IS NOT backward compatible with the obsoleted [RFC 4742](https://datatracker.ietf.org/doc/html/rfc4742).

use crate::capabilities::{Capability, NetconfVersion};
use crate::protocol::{Hello, NetConfMessage};
use crate::xml_utils::{ParsingError, XmlDeserialize, XmlParser, XmlSerialize, XmlWriter};
use quick_xml::NsReader;
use tokio_util::bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use tracing::trace;

const XML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
const HELLO_TERMINATOR: &str = "]]>]]>";
const CHUNK_START: &str = "\n#";
const MESSAGE_TERMINATOR: &str = "\n##\n";

/// Maximum chunk size as per RFC 6242
const MAX_CHUNK_SIZE: usize = 4294967295;

/// Maximum length of chunk size in characters
const MAX_CHUNK_SIZE_LEN: usize = 10;

/// Default maximum size (in bytes) of a single buffered NETCONF message,
/// used when no explicit value is configured. Bounds memory usage against
/// a peer that never terminates a message.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// SshCodec is a codec for encoding and decoding NETCONF messages over SSH as
/// per [RFC 6242](https://datatracker.ietf.org/doc/html/rfc6242).
#[derive(Debug)]
pub struct SshCodec {
    in_hello: bool,
    buf: BytesMut,
    /// Number of bytes at the start of `src` that have already been
    /// scanned for [`HELLO_TERMINATOR`], so repeated `decode` calls
    /// don't rescan the whole buffer from the beginning.
    hello_scanned: usize,
    /// Maximum total size (in bytes) of a single buffered message this codec
    /// will accept, configurable via [`SshCodec::with_max_message_size`].
    max_message_size: usize,
}

impl SshCodec {
    pub fn new() -> Self {
        Self::with_max_message_size(DEFAULT_MAX_MESSAGE_SIZE)
    }

    /// Create a new [`SshCodec`] with a configurable maximum
    /// message size (in bytes).
    pub fn with_max_message_size(max_message_size: usize) -> Self {
        Self {
            in_hello: true,
            buf: BytesMut::new(),
            hello_scanned: 0,
            max_message_size,
        }
    }

    /// The configured maximum buffered NETCONF message size (in bytes).
    pub const fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Returns an error if `len` exceeds the configured maximum message
    /// size while still waiting for the hello terminator.
    fn check_hello_size(&self, len: usize) -> Result<(), SshCodecError> {
        if len > self.max_message_size {
            let max_message_size = self.max_message_size;
            return Err(SshCodecError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Hello message exceeds maximum allowed size of {max_message_size} bytes"),
            )));
        }
        Ok(())
    }
}

impl Default for SshCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum SshCodecError {
    #[strum(to_string = "std::io:Error: `{0}`")]
    IO(std::io::Error),

    #[strum(to_string = "UTF decoding error: `{0}`")]
    Utf(std::str::Utf8Error),

    #[strum(to_string = "Integer decoding error: `{0}`")]
    Int(std::num::ParseIntError),

    #[strum(to_string = "NETCONF XML parsing error: `{0}`")]
    Parsing(ParsingError),

    #[strum(to_string = "XML encoding error: `{0}`")]
    Serialization(quick_xml::Error),
}

impl From<std::io::Error> for SshCodecError {
    fn from(err: std::io::Error) -> SshCodecError {
        SshCodecError::IO(err)
    }
}

impl std::error::Error for SshCodecError {}

impl From<std::str::Utf8Error> for SshCodecError {
    fn from(value: std::str::Utf8Error) -> Self {
        Self::Utf(value)
    }
}

impl From<std::num::ParseIntError> for SshCodecError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::Int(value)
    }
}

impl From<ParsingError> for SshCodecError {
    fn from(value: ParsingError) -> Self {
        Self::Parsing(value)
    }
}

impl From<quick_xml::Error> for SshCodecError {
    fn from(value: quick_xml::Error) -> Self {
        Self::Serialization(value)
    }
}

impl PartialEq for SshCodecError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::IO(_), Self::IO(_)) => true,
            (Self::Utf(v1), Self::Utf(v2)) => v1.eq(v2),
            (Self::Int(v1), Self::Int(v2)) => v1.eq(v2),
            (Self::Parsing(v1), Self::Parsing(v2)) => v1.eq(v2),
            // quick_xml::Error doesn't implement PartialEq,
            // fall back to comparing its Display representation
            (Self::Serialization(v1), Self::Serialization(v2)) => v1.to_string() == v2.to_string(),
            _ => false,
        }
    }
}

impl Decoder for SshCodec {
    type Item = NetConfMessage;
    type Error = SshCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.in_hello {
            if src.len() < HELLO_TERMINATOR.len() {
                // Not enough data to check for the terminator yet; must not
                // fall through to chunk-parsing while still in hello phase.
                self.check_hello_size(src.len())?;
                return Ok(None);
            }
            // Scan only the unscanned portion of `src`
            // (plus a small overlap so a split terminator isn't missed).
            let scan_from = self
                .hello_scanned
                .saturating_sub(HELLO_TERMINATOR.len() - 1);
            let pos = src[scan_from..]
                .windows(HELLO_TERMINATOR.len())
                .position(|w| w == HELLO_TERMINATOR.as_bytes())
                .map(|pos| scan_from + pos);
            if let Some(pos) = pos {
                self.check_hello_size(pos)?;
                let data = src.split_to(pos + HELLO_TERMINATOR.len());
                let data = &data[..pos];
                trace!("Parsing hello message: `{:?}`", std::str::from_utf8(data));
                let reader = NsReader::from_reader(data);
                let mut xml_parser = XmlParser::new(reader)?;
                let hello = Hello::xml_deserialize(&mut xml_parser)?;
                if !hello
                    .capabilities()
                    .contains(&Capability::NetconfBase(NetconfVersion::V1_1))
                {
                    return Err(SshCodecError::IO(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Hello message does not contain required base:1.1 capability, only NETCONF 1.1 as per RFC 6242 is supported",
                    )));
                }
                self.in_hello = false;
                self.hello_scanned = 0;
                return Ok(Some(NetConfMessage::Hello(hello)));
            }
            self.check_hello_size(src.len())?;
            // Remember how much has been scanned; keep the overlap
            // window unscanned for the next call.
            self.hello_scanned = src.len().saturating_sub(HELLO_TERMINATOR.len() - 1);
            return Ok(None);
        }

        loop {
            // Check if we have enough data to verify the chunk start sequence.
            if src.len() < CHUNK_START.len() {
                return Ok(None);
            }
            // Verify the chunk start sequence
            if !src.starts_with(CHUNK_START.as_bytes()) {
                return Err(SshCodecError::IO(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected chunk start sequence or message terminator",
                )));
            }

            // A chunk header ("\n#<digits>\n") and the terminator ("\n##\n")
            // share the "\n#" prefix, diverging only at the next byte.
            // The terminator may arrive in a separate `decode` call from
            // the preceding chunk data, so this check must run every loop
            // iteration or it risks being misread as a malformed chunk size.
            if src.len() < CHUNK_START.len() + 1 {
                // Not enough data yet to tell if the next byte is '#'
                // (terminator) or a digit (chunk header).
                return Ok(None);
            }
            if src[CHUNK_START.len()] == b'#' {
                if src.len() < MESSAGE_TERMINATOR.len() {
                    // Have "\n##" but not the trailing '\n' yet.
                    return Ok(None);
                }
                if !src.starts_with(MESSAGE_TERMINATOR.as_bytes()) {
                    return Err(SshCodecError::IO(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Malformed message terminator",
                    )));
                }
                let data = self.buf.split();
                trace!(
                    "Parsing netconf message: `{:?}`",
                    std::str::from_utf8(&data)
                );
                let reader = NsReader::from_reader(data.reader());
                let mut xml_parser = XmlParser::new(reader)?;
                let parsed = NetConfMessage::xml_deserialize(&mut xml_parser)?;
                src.advance(MESSAGE_TERMINATOR.len());
                return Ok(Some(parsed));
            }

            // Find the end of chunk size field
            let size_start = CHUNK_START.len();
            // Look for the newline after the chunk size, bounded by the
            // maximum possible size-field length. RFC 6242 maximum size
            // is 4294967295, so the size field will not exceed 11 characters
            // (including the newline).
            let search_len = std::cmp::min(src.len() - size_start, MAX_CHUNK_SIZE_LEN + 1);
            let size_end = src[size_start..size_start + search_len]
                .iter()
                .position(|&b| b == b'\n')
                .map(|pos| size_start + pos);
            let size_end = match size_end {
                Some(pos) => pos,
                None => {
                    if search_len > MAX_CHUNK_SIZE_LEN {
                        return Err(SshCodecError::IO(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Chunk size is not properly terminated with a newline",
                        )));
                    }
                    // Not enough data yet to find the size terminator.
                    return Ok(None);
                }
            };

            // Parse chunk size
            let chunk_size_slice = &src[size_start..size_end];
            let chunk_size_str = std::str::from_utf8(chunk_size_slice)?;
            // RFC 6242 chunk-size: at least one digit,
            // leading zeros are prohibited
            if chunk_size_str.is_empty() || chunk_size_str.starts_with('0') {
                return Err(SshCodecError::IO(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid chunk size: `{chunk_size_str}`"),
                )));
            }
            let chunk_size = chunk_size_str.parse::<usize>()?;

            // Validate chunk size per RFC 6242
            if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
                return Err(SshCodecError::IO(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid chunk size: {chunk_size}"),
                )));
            }

            // Bound the reassembled message size to avoid unbounded memory
            // growth from a peer that never sends the terminator. Use
            // `saturating_add` to avoid usize overflows on 32-bit targets.
            if self.buf.len().saturating_add(chunk_size) > self.max_message_size {
                let max_message_size = self.max_message_size;
                return Err(SshCodecError::IO(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Reassembled message exceeds maximum allowed size of {max_message_size} bytes"
                    ),
                )));
            }

            // Check if we have the complete chunk
            let chunk_start_pos = size_end + 1; // +1 for the LF after size
            let chunk_end_pos = chunk_start_pos.saturating_add(chunk_size);
            if src.len() < chunk_end_pos {
                return Ok(None); // Need more data
            }

            // Extract chunk data
            let chunk_data = &src[chunk_start_pos..chunk_end_pos];

            self.buf.extend_from_slice(chunk_data);

            // Advance past this chunk and loop back to the top, where the
            // next iteration will check whether what follows is another
            // chunk header or the message terminator.
            src.advance(chunk_end_pos);
        }
    }
}

impl Encoder<NetConfMessage> for SshCodec {
    type Error = SshCodecError;
    fn encode(&mut self, item: NetConfMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let buf = std::io::Cursor::new(Vec::new());
        let writer = quick_xml::writer::Writer::new_with_indent(buf, b' ', 2);
        let mut xml_writer = XmlWriter::new(writer);
        item.xml_serialize(&mut xml_writer)?;
        let buf = xml_writer.into_inner().into_inner();
        trace!("Serialized payload: `{:?}`", std::str::from_utf8(&buf));
        if let NetConfMessage::Hello(_) = item {
            dst.extend_from_slice(XML_HEADER.as_bytes());
            dst.extend_from_slice(&buf);
            dst.extend_from_slice(HELLO_TERMINATOR.as_bytes());
        } else {
            let size = buf.len();
            dst.extend_from_slice(format!("{CHUNK_START}{size}\n").as_bytes());
            dst.extend_from_slice(&buf);
            dst.extend_from_slice(MESSAGE_TERMINATOR.as_bytes());
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::capabilities::StandardCapability;
    use crate::protocol::{Rpc, RpcOperation, WellKnownOperation};
    use std::collections::HashSet;

    #[test]
    fn test_hello_netconf_1_0() {
        let hello_str = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>
      urn:ietf:params:netconf:base:1.0
    </capability>
    <capability>
      urn:ietf:params:netconf:capability:startup:1.0
    </capability>
  </capabilities>
  <session-id>4</session-id>
</hello>
]]>]]>"#;
        let mut buf = BytesMut::from(hello_str);
        let mut codec = SshCodec::new();
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(SshCodecError::IO(_))));
    }

    #[test]
    fn test_hello_netconf_1_1() {
        let hello_str = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>
      urn:ietf:params:netconf:base:1.1
    </capability>
    <capability>
      urn:ietf:params:netconf:capability:startup:1.0
    </capability>
  </capabilities>
  <session-id>4</session-id>
</hello>
]]>]]>"#;
        let expected = NetConfMessage::Hello(Hello::new(
            Some(4),
            HashSet::from([
                Capability::NetconfBase(NetconfVersion::V1_1),
                Capability::Standard(StandardCapability::Startup),
            ]),
        ));
        let mut buf = BytesMut::from(hello_str);
        let mut codec = SshCodec::new();
        let result = codec.decode(&mut buf);
        assert_eq!(result, Ok(Some(expected)));
    }

    #[test]
    fn test_hello_transition_with_chunks_decoding() {
        let input = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>
      urn:ietf:params:netconf:base:1.1
    </capability>
    <capability>
      urn:ietf:params:netconf:capability:startup:1.0
    </capability>
  </capabilities>
  <session-id>4</session-id>
</hello>
]]>]]>
#4
<rpc
#18
 message-id="102"

#79
     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <close-session/>
</rpc>
##
"#;
        let hello_expected = Ok(Some(NetConfMessage::Hello(Hello::new(
            Some(4),
            HashSet::from([
                Capability::NetconfBase(NetconfVersion::V1_1),
                Capability::Standard(StandardCapability::Startup),
            ]),
        ))));
        let rpc_expected = Ok(Some(NetConfMessage::Rpc(Rpc::new(
            "102".into(),
            RpcOperation::WellKnown(WellKnownOperation::CloseSession),
        ))));
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();

        let hello_parsed = codec.decode(&mut buf);
        assert_eq!(hello_parsed, hello_expected);

        let rpc_parsed = codec.decode(&mut buf);
        assert_eq!(rpc_parsed, rpc_expected);

        let eof_parsed = codec.decode(&mut buf);
        assert_eq!(eof_parsed, Ok(None));
    }

    #[test]
    fn short_message_stuck() {
        // a complete short chunked message must decode, not return Ok(None)
        let rpc = r#"<rpc message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><close-session/></rpc>"#;
        let input = format!("\n#{}\n{}\n##\n", rpc.len(), rpc);
        let mut buf = BytesMut::from(input.as_str());
        let mut codec = SshCodec::new();
        codec.in_hello = false;
        let result = codec.decode(&mut buf);
        assert!(
            result.unwrap().is_some(),
            "expected complete short message to decode"
        );
    }

    #[test]
    fn partial_short_message_waits() {
        // an incomplete chunk-size field must return Ok(None), not an error
        let input = "\n#4";
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();
        codec.in_hello = false;
        let result = codec.decode(&mut buf);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn malformed_size_field_errors() {
        // more than MAX_CHUNK_SIZE_LEN+1 digits without a newline must error
        let input = format!("\n#{}", "1".repeat(20));
        let mut buf = BytesMut::from(input.as_str());
        let mut codec = SshCodec::new();
        codec.in_hello = false;
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(SshCodecError::IO(_))));
    }

    #[test]
    fn leading_zero_chunk_size_errors() {
        // RFC 6242 disallows leading zeros in the chunk-size field
        let input = "\n#04\nabcd\n##\n";
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();
        codec.in_hello = false;
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(SshCodecError::IO(_))));
    }

    #[test]
    fn tiny_hello_fragment_waits() {
        // a first fragment shorter than the hello terminator must wait
        // for more data and not fall through to the chunk-parsing logic
        let mut buf = BytesMut::from("<?x");
        let mut codec = SshCodec::new();
        let result = codec.decode(&mut buf);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn hello_terminator_split_across_calls_is_found() {
        // the incremental hello scan must not miss a terminator that
        // is split across two decode() calls, at the overlap boundary
        let hello_str = r#"<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>
      urn:ietf:params:netconf:base:1.1
    </capability>
  </capabilities>
  <session-id>4</session-id>
</hello>
]]>]]>"#;
        let mut codec = SshCodec::new();
        // feed everything except the last byte of the terminator first
        let (first, last) = hello_str.split_at(hello_str.len() - 1);
        let mut buf = BytesMut::from(first);
        let result = codec.decode(&mut buf);
        assert_eq!(result, Ok(None));
        buf.extend_from_slice(last.as_bytes());
        let result = codec.decode(&mut buf);
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn oversized_hello_without_terminator_errors() {
        let mut codec = SshCodec::new();
        let mut buf = BytesMut::from(&b"<?xml"[..]);
        buf.extend_from_slice(&vec![b'a'; DEFAULT_MAX_MESSAGE_SIZE + 1]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(SshCodecError::IO(_))));
    }

    #[test]
    fn oversized_hello_with_terminator_in_single_read_errors() {
        // A full oversized hello message (including the terminator)
        // arriving in a single `decode` call must still be rejected.
        let max_message_size = 16;
        let mut codec = SshCodec::with_max_message_size(max_message_size);
        let hello_str = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<capabilities>
<capability>urn:ietf:params:netconf:base:1.1</capability>
</capabilities>
</hello>
]]>]]>"#;
        assert!(hello_str.len() > max_message_size);
        let mut buf = BytesMut::from(hello_str);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(SshCodecError::IO(_))));
    }

    #[test]
    fn oversized_reassembled_message_errors() {
        let mut codec = SshCodec::new();
        codec.in_hello = false;
        let chunk_size = DEFAULT_MAX_MESSAGE_SIZE + 1;
        let mut buf = BytesMut::from(format!("\n#{chunk_size}\n").as_str());
        buf.extend_from_slice(&vec![b'a'; chunk_size]);
        buf.extend_from_slice(MESSAGE_TERMINATOR.as_bytes());
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(SshCodecError::IO(_))));
    }

    #[test]
    fn configurable_max_message_size_is_enforced() {
        // a codec configured with a small max_message_size should reject
        // messages that would otherwise fit under the default limit
        let max_message_size = 16;
        let mut codec = SshCodec::with_max_message_size(max_message_size);
        assert_eq!(codec.max_message_size(), max_message_size);
        codec.in_hello = false;
        let chunk_size = max_message_size + 1;
        let mut buf = BytesMut::from(format!("\n#{chunk_size}\n").as_str());
        buf.extend_from_slice(&vec![b'a'; chunk_size]);
        buf.extend_from_slice(MESSAGE_TERMINATOR.as_bytes());
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(SshCodecError::IO(_))));

        // a message within the configured limit still decodes successfully
        let rpc = r#"<rpc message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><close-session/></rpc>"#;
        assert!(rpc.len() > max_message_size);
        let mut codec = SshCodec::with_max_message_size(rpc.len() + 1);
        codec.in_hello = false;
        let mut buf = BytesMut::from(format!("\n#{}\n{}\n##\n", rpc.len(), rpc).as_str());
        let result = codec.decode(&mut buf);
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_chunks_decoding() {
        let input = r#"
#4
<rpc
#18
 message-id="102"

#79
     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <close-session/>
</rpc>
##
"#;
        let expected = Ok(Some(NetConfMessage::Rpc(Rpc::new(
            "102".into(),
            RpcOperation::WellKnown(WellKnownOperation::CloseSession),
        ))));
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();
        // manually advance the codec beyond parsing the hello message
        codec.in_hello = false;

        let rpc_result = codec.decode(&mut buf);
        assert_eq!(rpc_result, expected);

        let eof_result = codec.decode(&mut buf);
        assert_eq!(eof_result, Ok(None));
    }

    #[test]
    fn message_terminator_split_across_calls_is_found() {
        // a terminator arriving in a separate `decode` call from its
        // preceding chunk must not be misparsed as an invalid chunk header
        let input = r#"
#4
<rpc
#18
 message-id="102"

#79
     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <close-session/>
</rpc>
"#;
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();
        codec.in_hello = false;

        // no terminator has arrived yet: decode should wait for more data
        let pending_result = codec.decode(&mut buf);
        assert_eq!(pending_result, Ok(None));

        // now the message terminator arrives on its own,
        // in a subsequent `decode` call
        buf.extend_from_slice(b"##\n");
        let expected = Ok(Some(NetConfMessage::Rpc(Rpc::new(
            "102".into(),
            RpcOperation::WellKnown(WellKnownOperation::CloseSession),
        ))));
        let rpc_result = codec.decode(&mut buf);
        assert_eq!(rpc_result, expected);

        let eof_result = codec.decode(&mut buf);
        assert_eq!(eof_result, Ok(None));
    }

    #[test]
    fn message_terminator_prefix_split_waits() {
        // the "\n##" prefix of the terminator alone
        // must not be misparsed as a chunk header
        let input = "\n#4\n<rpc\n##";
        let mut buf = BytesMut::from(input);
        let mut codec = SshCodec::new();
        codec.in_hello = false;

        let pending_result = codec.decode(&mut buf);
        assert_eq!(pending_result, Ok(None));
    }
}
