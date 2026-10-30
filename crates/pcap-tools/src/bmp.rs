// Copyright (C) 2026-present The NetCalyx Authors.
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

//! BMP specific helpers.

use crate::tcp_split::FlowKey;
use bytes::BytesMut;
use netcalyx_bmp_pkt::BmpMessage;
use netcalyx_bmp_pkt::codec::{BmpCodec, BmpCodecDecoderError};
use std::collections::HashMap;
use tokio_util::codec::Decoder;

/// Version (1 octet) + message length (4 octets) + message type (1 octet)
const BMP_COMMON_HEADER_LEN: usize = 6;

/// Total length of the BMP message at the start of `buf` taken from the
/// common header, `None` if the length field is not complete yet.
pub fn bmp_message_len(buf: &[u8]) -> Result<Option<usize>, String> {
    let Some(header) = buf.get(..5) else {
        return Ok(None);
    };
    let version = header[0];
    if version != 3 && version != 4 {
        return Err(format!("unexpected BMP version {version}"));
    }
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len < BMP_COMMON_HEADER_LEN {
        return Err(format!("invalid BMP message length {len}"));
    }
    Ok(Some(len))
}

/// Decodes extracted messages keeping one [`BmpCodec`] per flow, so the
/// parsing context learned from earlier messages (e.g. add-path) is retained.
#[derive(Default)]
pub struct BmpValidator {
    codecs: HashMap<FlowKey, BmpCodec>,
}

impl BmpValidator {
    pub fn validate(
        &mut self,
        flow: FlowKey,
        message: &[u8],
    ) -> Result<BmpMessage, BmpCodecDecoderError> {
        let codec = self.codecs.entry(flow).or_default();
        let mut buf = BytesMut::from(message);
        match codec.decode(&mut buf)? {
            Some(msg) => Ok(msg),
            None => Err(BmpCodecDecoderError::Incomplete(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bmp_message_len() {
        assert_eq!(bmp_message_len(&[]), Ok(None));
        assert_eq!(bmp_message_len(&[3, 0, 0, 0]), Ok(None));
        assert_eq!(bmp_message_len(&[3, 0, 0, 0, 6]), Ok(Some(6)));
        assert_eq!(bmp_message_len(&[3, 0, 0, 1, 0, 4, 0]), Ok(Some(256)));
        assert!(bmp_message_len(&[2, 0, 0, 0, 6]).is_err());
        assert!(bmp_message_len(&[3, 0, 0, 0, 5]).is_err());
    }
}
