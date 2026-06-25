// Copyright (C) 2024-present The NetGauze Authors.
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

use crate::raw::{MediaType, UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket};
use crate::wire::deserialize::{LocatedUdpNotifPacketParsingError, UdpNotifPacketParsingError};
use crate::wire::serialize::UdpNotifPacketWritingError;
use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BufMut, BytesMut};
use netcalyx_parse_utils::{LocatedParsingError, ReadablePdu, Span, WritablePdu};
use nom::error::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::time::{Duration, Instant};
use tokio_util::codec::{Decoder, Encoder};

/// Minimum length in bytes of the UDP-Notif fixed header (version/flags,
/// header length, message length, publisher-id, and message-id) without any
/// optional fields, per draft-ietf-netconf-udp-notif.
const MIN_HEADER_LENGTH: u8 = 12;

/// Default maximum number of segments per reassembly buffer.
/// Adjust according to draft-ietf-netconf-udp-notif recommendations.
pub const DEFAULT_MAX_SEGMENTS: u16 = 64;

/// Default reassembly timeout.
/// Adjust according to draft-ietf-netconf-udp-notif recommendations.
pub const DEFAULT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Counts of reassembly events accumulated since the last call to
/// [`UdpPacketCodec::take_reassembly_events`].  The caller should
/// drain this after each `decode()` call or periodically and forward
/// the counts to its telemetry layer.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReassemblyEventCounts {
    /// Number of incomplete reassembly buffers evicted because they exceeded
    /// the configured timeout.
    pub timeout_evictions: u64,
    /// Number of segments dropped because their segment number was already
    /// present in the reassembly buffer (network retransmission or
    /// message-id reuse).
    pub duplicate_drops: u64,
    /// Number of reassembly buffers aborted because they exceeded the
    /// configured maximum segment count.
    pub max_segments_exceeded: u64,
}

#[derive(Debug, strum_macros::Display, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum ReassemblyBufferError {
    #[strum(
        to_string = "UDP-Notif packet with last segment marker is not received for the packet with \
         media-type={media_type}, publisher-id={publisher_id}, and message-id={message_id} and the \
         total number of segments received are {received}"
    )]
    LastSegmentIsNotReceived {
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        received: usize,
    },

    #[strum(
        to_string = "UDP-Notif packet with incomplete number of segments, media-type={media_type}, \
        publisher-id={publisher_id}, and message-id={message_id} and the total number of segments \
        received are {received}"
    )]
    IncompleteSegments {
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        needed: u16,
        received: u16,
    },

    #[strum(
        to_string = "UDP-Notif packet with incorrect segment sequence, media-type={media_type}, \
        publisher-id={publisher_id}, and message-id={message_id} received {received} segments in \
        total and is missing a packet with sequence number {missing_segment_number}"
    )]
    MissingSegment {
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
        received: usize,
        missing_segment_number: u16,
    },

    #[strum(
        to_string = "UDP-Notif reassembly aborted: publisher-id={publisher_id}, \
        message-id={message_id} exceeded the maximum allowed segment count of {max_segments}"
    )]
    MaxSegmentsExceeded {
        publisher_id: u32,
        message_id: u32,
        max_segments: u16,
    },
}

impl std::error::Error for ReassemblyBufferError {}

#[derive(Debug)]
struct ReassemblyBuffer {
    timestamp: Instant,
    has_last: bool,
    expected_count: u16,
    segments: BTreeMap<u16, UdpNotifPacket>,
}

impl ReassemblyBuffer {
    #[inline]
    fn is_timed_out(&self, timeout_duration: Duration) -> bool {
        Instant::now().duration_since(self.timestamp) > timeout_duration
    }

    fn add_segment(&mut self, segment_number: u16, packet: UdpNotifPacket, is_last: bool) {
        if is_last {
            self.expected_count = segment_number + 1;
            self.has_last = true;
        }
        self.segments.insert(segment_number, packet);
    }

    #[inline]
    fn ready_to_reassemble(&self) -> bool {
        self.has_last && self.segments.len() == self.expected_count as usize
    }

    fn reassemble(
        self,
        media_type: MediaType,
        publisher_id: u32,
        message_id: u32,
    ) -> Result<UdpNotifPacket, ReassemblyBufferError> {
        if !self.has_last {
            let number_of_received_segments = self.segments.len();
            return Err(ReassemblyBufferError::LastSegmentIsNotReceived {
                media_type,
                publisher_id,
                message_id,
                received: number_of_received_segments,
            });
        }
        if self.expected_count as usize != self.segments.len() {
            return Err(ReassemblyBufferError::IncompleteSegments {
                media_type,
                publisher_id,
                message_id,
                needed: self.expected_count,
                received: self.segments.len() as u16,
            });
        }
        for (expected_number, (seg_no, _)) in self.segments.iter().enumerate() {
            if expected_number != *seg_no as usize {
                let received = self.segments.len();
                return Err(ReassemblyBufferError::MissingSegment {
                    media_type,
                    publisher_id,
                    message_id,
                    received,
                    missing_segment_number: expected_number as u16,
                });
            }
        }

        // into_values() yields in ascending key (segment-number) order; the
        // checks above guarantee segments.len() == expected_count >= 1, so
        // next() always returns Some — the error arm is unreachable.
        let mut segments = self.segments.into_values();
        let first_segment = segments
            .next()
            .ok_or(ReassemblyBufferError::IncompleteSegments {
                media_type,
                publisher_id,
                message_id,
                needed: self.expected_count,
                received: 0,
            })?;
        let mut assembled_payload = BytesMut::from(first_segment.payload());

        // Per draft-ietf-netconf-udp-notif Section 4.1, all options (other than
        // the segmentation option) are carried on the first segment and are
        // appended to the reassembled header. Options on subsequent segments are
        // ignored.
        let options: HashMap<_, _> = first_segment
            .options()
            .iter()
            .filter(|(k, _)| *k != &UdpNotifOptionCode::Segment)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for pkt in segments {
            assembled_payload.unsplit(BytesMut::from(pkt.payload()));
        }

        Ok(UdpNotifPacket::new(
            first_segment.media_type(),
            first_segment.publisher_id(),
            first_segment.message_id(),
            options,
            assembled_payload.freeze(),
        ))
    }
}

impl Default for ReassemblyBuffer {
    fn default() -> Self {
        Self {
            timestamp: Instant::now(),
            has_last: false,
            expected_count: 1,
            segments: BTreeMap::new(),
        }
    }
}

#[derive(Debug, strum_macros::Display, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum UdpPacketCodecError {
    #[strum(to_string = "I/O error {0}")]
    IoError(String),

    #[strum(to_string = "Invalid UDP-Notif header length {0}")]
    InvalidHeaderLength(u8),

    #[strum(to_string = "Invalid UDP-Notif message length {0}")]
    InvalidMessageLength(u16),

    #[strum(to_string = "UDP-Notif packet parsing error: {0}")]
    UdpNotifError(UdpNotifPacketParsingError),

    #[strum(to_string = "Segments reassembly error: {0}")]
    ReassemblyError(ReassemblyBufferError),

    #[strum(to_string = "UDP-Notif serialization error: {0}")]
    WritingError(UdpNotifPacketWritingError),
}

impl<'a> From<nom::Err<LocatedUdpNotifPacketParsingError<'a>>> for UdpPacketCodecError {
    fn from(err: nom::Err<LocatedUdpNotifPacketParsingError<'a>>) -> Self {
        match err {
            nom::Err::Incomplete(_) => {
                Self::UdpNotifError(UdpNotifPacketParsingError::NomError(ErrorKind::Eof))
            }
            nom::Err::Error(err) | nom::Err::Failure(err) => {
                Self::UdpNotifError(err.error().clone())
            }
        }
    }
}

impl From<ReassemblyBufferError> for UdpPacketCodecError {
    fn from(value: ReassemblyBufferError) -> Self {
        Self::ReassemblyError(value)
    }
}

impl std::error::Error for UdpPacketCodecError {}

impl From<io::Error> for UdpPacketCodecError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<UdpNotifPacketWritingError> for UdpPacketCodecError {
    fn from(e: UdpNotifPacketWritingError) -> Self {
        Self::WritingError(e)
    }
}

#[derive(Debug)]
pub struct UdpPacketCodec {
    /// Stores incomplete messages that are being reassembled from multiple
    /// segments.
    incomplete_messages: HashMap<(u32, u32), ReassemblyBuffer>,
    /// Maximum number of segments tolerated per in-progress reassembly buffer.
    max_segments: u16,
    /// How long to keep an incomplete reassembly buffer before discarding it.
    reassembly_timeout: Duration,
    /// Accumulated reassembly event counts since the last call to
    /// [`Self::take_reassembly_events`].
    reassembly_events: ReassemblyEventCounts,
}

impl Default for UdpPacketCodec {
    fn default() -> Self {
        Self {
            incomplete_messages: HashMap::new(),
            max_segments: DEFAULT_MAX_SEGMENTS,
            reassembly_timeout: DEFAULT_REASSEMBLY_TIMEOUT,
            reassembly_events: ReassemblyEventCounts::default(),
        }
    }
}

impl UdpPacketCodec {
    pub fn new(max_segments: u16, reassembly_timeout: Duration) -> Self {
        Self {
            incomplete_messages: HashMap::new(),
            max_segments,
            reassembly_timeout,
            reassembly_events: ReassemblyEventCounts::default(),
        }
    }

    /// Drain the accumulated reassembly event counts and reset them to zero.
    /// The service actor should call this after each `decode()` or periodically
    /// and forward the values to OTel counters.
    ///
    /// [`std::mem::take`] moves the current value out and writes
    /// [`Default::default`] (all-zero counters) back in one step — this is
    /// the idiomatic way to "move out" of a struct field without leaving it
    /// uninitialised.
    #[inline]
    pub fn take_reassembly_events(&mut self) -> ReassemblyEventCounts {
        std::mem::take(&mut self.reassembly_events)
    }

    /// Current number of incomplete reassembly buffers (segments received but
    /// reassembly not yet complete).  Useful to e.g. update an OTel gauge.
    #[inline]
    pub fn incomplete_messages_count(&self) -> usize {
        self.incomplete_messages.len()
    }

    /// Validate the fixed header against a single, self-contained UDP datagram.
    ///
    /// Unlike a TCP stream codec, every `decode()` call receives exactly one
    /// complete datagram, so a buffer that is shorter than the declared header
    /// or message length is malformed (truncated) rather than "incomplete".
    /// Such datagrams are rejected with an error instead of being held for a
    /// future read.
    #[inline]
    fn check_len(&self, buf: &BytesMut) -> Result<(u8, u16), UdpPacketCodecError> {
        if buf.len() < MIN_HEADER_LENGTH as usize {
            // Datagram is shorter than the fixed header: malformed/truncated.
            return Err(UdpPacketCodecError::InvalidHeaderLength(buf.len() as u8));
        }
        let header_len = buf[1];
        if header_len < MIN_HEADER_LENGTH || buf.len() < header_len as usize {
            return Err(UdpPacketCodecError::InvalidHeaderLength(header_len));
        }
        let message_length = NetworkEndian::read_u16(&buf[2..4]);
        if message_length < header_len as u16 || buf.len() != message_length as usize {
            return Err(UdpPacketCodecError::InvalidMessageLength(message_length));
        }
        Ok((header_len, message_length))
    }

    #[inline]
    fn extract_segment_info(options: &HashMap<UdpNotifOptionCode, UdpNotifOption>) -> (u16, bool) {
        options
            .get(&UdpNotifOptionCode::Segment)
            .map(|opt| {
                if let UdpNotifOption::Segment { number, last } = opt {
                    (*number, *last)
                } else {
                    unreachable!()
                }
            })
            .unwrap_or((0, true))
    }

    fn try_reassemble_segments(
        &mut self,
        pkt: UdpNotifPacket,
    ) -> Result<Option<UdpNotifPacket>, UdpPacketCodecError> {
        let (seg_no, is_last) = Self::extract_segment_info(pkt.options());
        let media_type = pkt.media_type();
        let publisher_id = pkt.publisher_id();
        let message_id = pkt.message_id();

        // Short-circuit for unsegmented or single-segment messages
        if seg_no == 0 && is_last {
            return Ok(Some(pkt));
        }

        let message_key = (publisher_id, message_id);

        // Detect duplicate segment numbers: a segment whose number is already
        // present in the buffer is either a network retransmission or a sign that
        // the sender has reused the message-id for a new message.
        // Duplicate segments are dropped according to draft-ietf-netconf-udp-notif.
        let is_duplicate = self
            .incomplete_messages
            .get(&message_key)
            .map(|buf| buf.segments.contains_key(&seg_no))
            .unwrap_or(false);

        if is_duplicate {
            self.reassembly_events.duplicate_drops += 1;
            return Ok(None);
        }

        let reassembly_buf = self.incomplete_messages.entry(message_key).or_default();
        reassembly_buf.add_segment(seg_no, pkt, is_last);

        // Enforce the per-message segment cap
        if reassembly_buf.segments.len() > self.max_segments as usize {
            self.incomplete_messages.remove(&message_key);
            self.reassembly_events.max_segments_exceeded += 1;
            return Err(UdpPacketCodecError::ReassemblyError(
                ReassemblyBufferError::MaxSegmentsExceeded {
                    publisher_id,
                    message_id,
                    max_segments: self.max_segments,
                },
            ));
        }

        if !reassembly_buf.ready_to_reassemble() {
            return Ok(None);
        }

        // The buffer was just confirmed ready, so we can reassemble
        // and remove it from the incomplete_messages map.
        match self.incomplete_messages.remove(&message_key) {
            Some(reassembled) => Ok(Some(reassembled.reassemble(
                media_type,
                publisher_id,
                message_id,
            )?)),
            None => Ok(None),
        }
    }
}

impl Decoder for UdpPacketCodec {
    type Item = UdpNotifPacket;
    type Error = UdpPacketCodecError;

    #[inline]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Evict reassembly buffers that have exceeded the configured timeout,
        // accumulating the count into reassembly_events for the caller to report.
        let before = self.incomplete_messages.len();
        self.incomplete_messages
            .retain(|_, b| !b.is_timed_out(self.reassembly_timeout));
        let evicted = before - self.incomplete_messages.len();
        if evicted > 0 {
            self.reassembly_events.timeout_evictions += evicted as u64;
        }

        // Early return for empty buffer (nothing to decode)
        if buf.is_empty() {
            return Ok(None);
        }

        // Validate the fixed header fields and confirm the datagram contains a
        // complete message before attempting to parse
        let (_, msg_len) = self.check_len(buf)?;

        // `check_len` above already enforces `buf.len() == msg_len as usize`,
        // so `split_to(buf.len())` is equivalent to `split_to(msg_len)` here.
        // The explicit split is kept to make the byte boundary visible.
        let pkt_buf = buf.split_to(buf.len());
        match UdpNotifPacket::from_wire(Span::new(pkt_buf.chunk())) {
            Ok((span, pkt)) => {
                // Check that the message length matches the actual length of the message
                if span.location_offset() != msg_len as usize || !span.is_empty() {
                    return Err(UdpPacketCodecError::InvalidMessageLength(msg_len));
                }
                self.try_reassemble_segments(pkt)
            }
            Err(err) => Err(err)?,
        }
    }
}

impl Encoder<UdpNotifPacket> for UdpPacketCodec {
    type Error = UdpPacketCodecError;

    #[inline]
    fn encode(&mut self, pkt: UdpNotifPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut writer = dst.writer();
        pkt.write(&mut writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::MediaType;
    use bytes::Bytes;
    use std::time::Duration;
    #[test]
    fn test_decode() {
        let mut codec = UdpPacketCodec::default();
        let value: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x0c, // Header length
            0x00, 0x0e, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0xff, 0xff, // dummy payload
        ];
        let pkt = UdpNotifPacket::new(
            MediaType::YangDataJson,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(&[0xff, 0xff][..]),
        );
        let mut buf = BytesMut::from(&value[..]);

        let value = codec.decode(&mut buf);
        assert_eq!(value, Ok(Some(pkt)))
    }

    #[test]
    fn test_encode() {
        let mut codec = UdpPacketCodec::default();
        let expected: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x0c, // Header length
            0x00, 0x0e, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0xff, 0xff, // dummy payload
        ];
        let pkt = UdpNotifPacket::new(
            MediaType::YangDataJson,
            0x01000001,
            0x02000002,
            HashMap::new(),
            Bytes::from(&[0xff, 0xff][..]),
        );
        let mut buf = BytesMut::new();
        codec.encode(pkt, &mut buf).expect("encode failed");
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_decode_segmented() {
        let mut codec = UdpPacketCodec::default();
        let value_wire1: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x14, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x00, // segment 0, not the last segment
            0xff, 0xff, 0xff, 0xff, // dummy payload
        ];
        let value_wire2: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x18, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x03, // segment 1, last segment
            0xee, 0xee, 0xee, 0xee, // dummy payload
            0xdd, 0xdd, 0xdd, 0xdd, // dummy payload
        ];

        let mut buf = BytesMut::from(&value_wire1[..]);
        let value1 = codec.decode(&mut buf);
        buf.extend_from_slice(&value_wire2[..]);
        let value2 = codec.decode(&mut buf);

        assert!(matches!(value1, Ok(None)));
        assert_eq!(
            value2,
            Ok(Some(UdpNotifPacket::new(
                MediaType::YangDataJson,
                0x01000001,
                0x02000002,
                HashMap::new(),
                Bytes::from(
                    &[
                        0xff, 0xff, 0xff, 0xff, // payload from the first segment
                        0xee, 0xee, 0xee, 0xee, // payload from the second segment
                        0xdd, 0xdd, 0xdd, 0xdd,
                    ][..]
                ),
            )))
        )
    }

    #[test]
    fn test_decode_unordered_segmented() {
        let mut codec = UdpPacketCodec::default();
        let value_wire1: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x18, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x03, // segment 1, last segment
            0xee, 0xee, 0xee, 0xee, // dummy payload
            0xdd, 0xdd, 0xdd, 0xdd, // dummy payload
        ];
        let value_wire2: Vec<u8> = vec![
            0x21, // version 1, no private space, Media type: 1 = YANG data JSON
            0x10, // Header length
            0x00, 0x14, // Message length
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x00, // segment 0, not the last segment
            0xff, 0xff, 0xff, 0xff, // dummy payload
        ];

        let mut buf = BytesMut::from(&value_wire1[..]);

        let value1 = codec.decode(&mut buf);

        buf.extend_from_slice(&value_wire2[..]);
        let value2 = codec.decode(&mut buf);

        assert!(matches!(value1, Ok(None)));
        assert_eq!(
            value2,
            Ok(Some(UdpNotifPacket::new(
                MediaType::YangDataJson,
                0x01000001,
                0x02000002,
                HashMap::new(),
                Bytes::from(
                    &[
                        0xff, 0xff, 0xff, 0xff, // payload from the first segment
                        0xee, 0xee, 0xee, 0xee, // payload from the second segment
                        0xdd, 0xdd, 0xdd, 0xdd,
                    ][..]
                ),
            )))
        )
    }
    #[test]
    fn test_decode_empty_buffer() {
        let mut codec = UdpPacketCodec::default();
        let mut buf = BytesMut::new();
        assert_eq!(codec.decode(&mut buf), Ok(None));
    }

    #[test]
    fn test_decode_truncated_header() {
        let mut codec = UdpPacketCodec::default();
        // Buffer shorter than the 12-byte fixed header.
        let mut buf = BytesMut::from(&[0x21u8, 0x0c, 0x00][..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(UdpPacketCodecError::InvalidHeaderLength(3))
        ));
    }

    #[test]
    fn test_decode_header_len_too_small() {
        let mut codec = UdpPacketCodec::default();
        // header_len byte = 4, below MIN_HEADER_LENGTH (12).
        let value: Vec<u8> = vec![
            0x21, 0x04, 0x00, 0x0e, // header_len=4
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0xff, 0xff, // payload
        ];
        let mut buf = BytesMut::from(&value[..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(UdpPacketCodecError::InvalidHeaderLength(4))
        ));
    }

    #[test]
    fn test_decode_message_len_too_small() {
        let mut codec = UdpPacketCodec::default();
        // message_length = 4, below header_len (12).
        let value: Vec<u8> = vec![
            0x21, 0x0c, 0x00, 0x04, // message_length=4
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0xff, 0xff, // payload
        ];
        let mut buf = BytesMut::from(&value[..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(UdpPacketCodecError::InvalidMessageLength(4))
        ));
    }

    #[test]
    fn test_decode_duplicate_segment() {
        let mut codec = UdpPacketCodec::default();
        let seg0: Vec<u8> = vec![
            0x21, 0x10, 0x00, 0x14, // header_len=16, message_length=20
            0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x00, // segment 0, not last
            0xff, 0xff, 0xff, 0xff, // payload
        ];
        let mut buf = BytesMut::from(&seg0[..]);
        assert_eq!(codec.decode(&mut buf), Ok(None));

        // Resend the same segment (duplicate).
        buf.extend_from_slice(&seg0[..]);
        assert_eq!(codec.decode(&mut buf), Ok(None));

        let events = codec.take_reassembly_events();
        assert_eq!(events.duplicate_drops, 1);
        // Second drain must be zeroed.
        assert_eq!(codec.take_reassembly_events().duplicate_drops, 0);
    }

    #[test]
    fn test_decode_max_segments_exceeded() {
        let mut codec = UdpPacketCodec::new(1, DEFAULT_REASSEMBLY_TIMEOUT);
        let seg0: Vec<u8> = vec![
            0x21, 0x10, 0x00, 0x14, 0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x00, // segment 0, not last
            0xff, 0xff, 0xff, 0xff,
        ];
        let seg1: Vec<u8> = vec![
            0x21, 0x10, 0x00, 0x14, 0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x02, // segment 1, not last
            0xff, 0xff, 0xff, 0xff,
        ];

        let mut buf = BytesMut::from(&seg0[..]);
        assert_eq!(codec.decode(&mut buf), Ok(None));
        assert_eq!(codec.incomplete_messages_count(), 1);

        buf.extend_from_slice(&seg1[..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(UdpPacketCodecError::ReassemblyError(
                ReassemblyBufferError::MaxSegmentsExceeded { .. }
            ))
        ));
        // Buffer must be removed after the cap is exceeded.
        assert_eq!(codec.incomplete_messages_count(), 0);

        let events = codec.take_reassembly_events();
        assert_eq!(events.max_segments_exceeded, 1);
    }

    #[test]
    fn test_decode_timeout_eviction() {
        let mut codec = UdpPacketCodec::new(DEFAULT_MAX_SEGMENTS, Duration::from_millis(1));
        let seg0: Vec<u8> = vec![
            0x21, 0x10, 0x00, 0x14, 0x01, 0x00, 0x00, 0x01, // Publisher ID
            0x02, 0x00, 0x00, 0x02, // Message ID
            0x01, 0x04, 0x00, 0x00, // segment 0, not last
            0xff, 0xff, 0xff, 0xff,
        ];

        let mut buf = BytesMut::from(&seg0[..]);
        assert_eq!(codec.decode(&mut buf), Ok(None));
        assert_eq!(codec.incomplete_messages_count(), 1);

        std::thread::sleep(Duration::from_millis(5));

        // An empty-buffer decode drives the eviction pass without consuming data.
        let mut empty = BytesMut::new();
        assert_eq!(codec.decode(&mut empty), Ok(None));
        assert_eq!(codec.incomplete_messages_count(), 0);

        let events = codec.take_reassembly_events();
        assert_eq!(events.timeout_evictions, 1);
    }
}
