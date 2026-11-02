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

//! Re-segment TCP streams so that every application message is carried in its
//! own TCP segment.

use crate::writer::LegacyPcapWriter;
use bytes::BytesMut;
use netcalyx_pcap_reader::{PcapIter, TransportProtocol};
use pcap_parser::Linktype;
use pdu::{EthernetPdu, Ip, TcpPdu};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const PCAP_BUFFER_SIZE: usize = 165_536;

const IP_PROTO_TCP: u8 = 6;
const IPV6_HEADER_LEN: usize = 40;
const TCP_FLAGS_OFFSET: usize = 13;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;

pub type FlowKey = (IpAddr, u16, IpAddr, u16);

#[derive(Debug, thiserror::Error)]
pub enum SplitError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("failed to open pcap: {0}")]
    Pcap(String),

    #[error("input and output refer to the same file: {}", .0.display())]
    SameFile(PathBuf),

    #[error("frame {frame}: {reason}")]
    MalformedFrame { frame: usize, reason: String },

    #[error("frame {frame}: flow {flow:?} lost message framing: {reason}")]
    Framing {
        frame: usize,
        flow: FlowKey,
        reason: String,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SplitStats {
    pub frames_in: usize,
    pub messages_out: usize,
    pub packets_out: usize,
    /// Segments whose payload was already received (retransmissions or the
    /// same packet captured on multiple interfaces), dropped
    pub duplicate_segments: usize,
    /// Flows with bytes that did not form a complete message at EOF (including
    /// out-of-order data after a gap)
    pub incomplete_flows: Vec<(FlowKey, usize)>,
}

struct FlowState {
    buf: BytesMut,
    /// Next input sequence number expected to extend `buf`
    expected_seq: u32,
    /// Segments received ahead of `expected_seq`
    pending: Vec<(u32, Vec<u8>)>,
    /// Sequence number of the next written segment
    next_seq: u32,
}

impl FlowState {
    fn new(seq: u32) -> Self {
        Self {
            buf: BytesMut::new(),
            expected_seq: seq,
            pending: vec![],
            next_seq: seq,
        }
    }

    /// Add a segment to the stream, returns the number of fully duplicate
    /// segments that were dropped.
    fn push_segment(&mut self, seq: u32, payload: &[u8]) -> usize {
        self.pending.push((seq, payload.to_vec()));
        let mut duplicates = 0;
        let mut progressed = true;
        while progressed {
            progressed = false;
            self.pending.retain(|(seq, data)| {
                // Serial number arithmetic (RFC 1982) to handle wrap around
                let already_received = self.expected_seq.wrapping_sub(*seq) as i32;
                if already_received < 0 {
                    return true;
                }
                let already_received = already_received as usize;
                if already_received < data.len() {
                    self.buf.extend_from_slice(&data[already_received..]);
                    self.expected_seq = self
                        .expected_seq
                        .wrapping_add((data.len() - already_received) as u32);
                    progressed = true;
                } else {
                    duplicates += 1;
                }
                false
            });
        }
        duplicates
    }

    fn pending_len(&self) -> usize {
        self.buf.len()
            + self
                .pending
                .iter()
                .map(|(_, data)| data.len())
                .sum::<usize>()
    }
}

/// Read `input`, reassemble TCP streams with a destination port in `ports`,
/// cut them into messages using `message_len` and write every message into
/// its own TCP segment in `output` (legacy pcap). All other frames are dropped.
///
/// Streams are reassembled by sequence number: retransmitted/duplicate data
/// is dropped and out-of-order segments are reordered. Each stream starts at
/// its first captured segment with payload.
///
/// Each new segment reuses the link/IP/TCP headers of the frame that completed
/// the message (with fixed lengths, sequence number and checksums) and its
/// capture timestamp. Messages that do not fit into a single IP packet are
/// spread over multiple segments.
///
/// `message_len` returns the total length of the message at the start of the
/// buffer, `None` if more bytes are needed to tell, or an error if the stream
/// is not aligned to a message boundary. `on_message` is called for every
/// extracted message with the flow and the frame number that completed it.
/// If `rewrite_dst_port` is set, it replaces the TCP destination port of the
/// written segments.
pub fn split_tcp_messages<L, M>(
    input: &Path,
    output: &Path,
    ports: &[u16],
    rewrite_dst_port: Option<u16>,
    message_len: L,
    mut on_message: M,
) -> Result<SplitStats, SplitError>
where
    L: Fn(&[u8]) -> Result<Option<usize>, String>,
    M: FnMut(FlowKey, usize, &[u8]),
{
    // Creating the output would truncate the input while it is being read
    if let (Ok(input), Ok(output)) = (input.canonicalize(), output.canonicalize())
        && input == output
    {
        return Err(SplitError::SameFile(output));
    }
    let reader = pcap_parser::create_reader(PCAP_BUFFER_SIZE, File::open(input)?)
        .map_err(|err| SplitError::Pcap(format!("{err:?}")))?;
    let mut iter = PcapIter::new(reader);
    let mut writer = LegacyPcapWriter::new(BufWriter::new(File::create(output)?));
    let mut flows: HashMap<FlowKey, FlowState> = HashMap::new();
    let mut stats = SplitStats::default();

    while let Some((src_ip, src_port, dst_ip, dst_port, protocol, _)) = iter.next() {
        if protocol != TransportProtocol::TCP || !ports.contains(&dst_port) {
            continue;
        }
        let frame = iter.frame_counter();
        let link_type = iter.link_type();
        let segment = TcpSegment::parse(link_type, iter.raw_frame())
            .map_err(|reason| SplitError::MalformedFrame { frame, reason })?;
        let flow = (src_ip, src_port, dst_ip, dst_port);
        // New connection reusing the four-tuple, restart reassembly
        if segment.syn
            && let Some(old) = flows.remove(&flow)
            && old.pending_len() > 0
        {
            stats.incomplete_flows.push((flow, old.pending_len()));
        }
        if segment.payload().is_empty() {
            continue;
        }
        let state = flows
            .entry(flow)
            .or_insert_with(|| FlowState::new(segment.seq));
        stats.duplicate_segments += state.push_segment(segment.seq, segment.payload());

        while let Some(len) = message_len(&state.buf).map_err(|reason| SplitError::Framing {
            frame,
            flow,
            reason,
        })? && state.buf.len() >= len
        {
            let message = state.buf.split_to(len);
            on_message(flow, frame, &message);
            for chunk in message.chunks(segment.max_payload_len()) {
                let packet = segment
                    .with_payload(state.next_seq, rewrite_dst_port, chunk)
                    .map_err(|reason| SplitError::MalformedFrame { frame, reason })?;
                writer.write_frame(link_type, iter.timestamp(), &packet)?;
                state.next_seq = state.next_seq.wrapping_add(chunk.len() as u32);
                stats.packets_out += 1;
            }
            stats.messages_out += 1;
        }
    }
    writer.finish()?;

    stats.frames_in = iter.frame_counter();
    stats.incomplete_flows.extend(
        flows
            .into_iter()
            .map(|(flow, state)| (flow, state.pending_len()))
            .filter(|(_, len)| *len > 0),
    );
    Ok(stats)
}

/// Offsets of the headers of a captured TCP segment, used as template to
/// build new segments with a different payload.
struct TcpSegment<'a> {
    frame: &'a [u8],
    ip_offset: usize,
    tcp_offset: usize,
    payload_offset: usize,
    payload_end: usize,
    is_ipv4: bool,
    seq: u32,
    syn: bool,
}

impl<'a> TcpSegment<'a> {
    fn parse(link_type: Linktype, frame: &'a [u8]) -> Result<Self, String> {
        let ip_offset = match link_type {
            Linktype::ETHERNET => EthernetPdu::new(frame)
                .map_err(|err| format!("invalid ethernet header: {err:?}"))?
                .computed_ihl(),
            Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => 0,
            Linktype::NULL | Linktype::LOOP => 4,
            Linktype::LINUX_SLL => 16,
            Linktype::LINUX_SLL2 => 20,
            other => return Err(format!("unsupported link type {other:?}")),
        };
        let ip_buf = frame
            .get(ip_offset..)
            .ok_or_else(|| "truncated link layer header".to_string())?;
        let ip = Ip::new(ip_buf).map_err(|err| format!("invalid IP header: {err:?}"))?;
        let (is_ipv4, ip_header_len, ip_packet_len, protocol) = match ip {
            Ip::Ipv4(ipv4) => (
                true,
                ipv4.computed_ihl(),
                usize::from(ipv4.total_length()),
                ipv4.protocol(),
            ),
            Ip::Ipv6(ipv6) => (
                false,
                ipv6.computed_ihl(),
                IPV6_HEADER_LEN + usize::from(ipv6.payload_length()),
                ipv6.computed_protocol(),
            ),
        };
        if protocol != IP_PROTO_TCP {
            return Err(format!("expected TCP, got IP protocol {protocol}"));
        }
        let tcp_offset = ip_offset + ip_header_len;
        let tcp = TcpPdu::new(
            frame
                .get(tcp_offset..)
                .ok_or_else(|| "truncated TCP header".to_string())?,
        )
        .map_err(|err| format!("invalid TCP header: {err:?}"))?;
        let payload_offset = tcp_offset + tcp.computed_data_offset();
        // Bound by the IP length to drop link layer padding/trailers
        let payload_end = ip_offset + ip_packet_len;
        if payload_end < payload_offset || payload_end > frame.len() {
            return Err("truncated TCP segment".to_string());
        }
        Ok(Self {
            frame,
            ip_offset,
            tcp_offset,
            payload_offset,
            payload_end,
            is_ipv4,
            seq: tcp.sequence_number(),
            syn: tcp.syn(),
        })
    }

    fn payload(&self) -> &'a [u8] {
        &self.frame[self.payload_offset..self.payload_end]
    }

    /// Largest payload that keeps the IP length fields within `u16`
    fn max_payload_len(&self) -> usize {
        let counted_headers = if self.is_ipv4 {
            self.payload_offset - self.ip_offset
        } else {
            self.payload_offset - self.ip_offset - IPV6_HEADER_LEN
        };
        usize::from(u16::MAX) - counted_headers
    }

    fn with_payload(
        &self,
        seq: u32,
        dst_port: Option<u16>,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let (ip, tcp) = (self.ip_offset, self.tcp_offset);
        let mut out = Vec::with_capacity(self.payload_offset + payload.len());
        out.extend_from_slice(&self.frame[..self.payload_offset]);
        out.extend_from_slice(payload);

        let ip_len = out.len() - ip;
        if self.is_ipv4 {
            let total_len = u16::try_from(ip_len).map_err(|_| "IPv4 packet too large")?;
            out[ip + 2..ip + 4].copy_from_slice(&total_len.to_be_bytes());
            let checksum = pdu::Ipv4Pdu::new(&out[ip..])
                .map_err(|err| format!("invalid IPv4 header: {err:?}"))?
                .computed_checksum();
            out[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
        } else {
            let payload_len =
                u16::try_from(ip_len - IPV6_HEADER_LEN).map_err(|_| "IPv6 packet too large")?;
            out[ip + 4..ip + 6].copy_from_slice(&payload_len.to_be_bytes());
        }

        if let Some(dst_port) = dst_port {
            out[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
        }
        out[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
        // Control segments are not reproduced, keep the output a plain data
        // stream
        out[tcp + TCP_FLAGS_OFFSET] &= !(TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST);
        let checksum = {
            let ip_pdu = Ip::new(&out[ip..]).map_err(|err| format!("invalid IP: {err:?}"))?;
            TcpPdu::new(&out[tcp..])
                .map_err(|err| format!("invalid TCP: {err:?}"))?
                .computed_checksum(&ip_pdu)
        };
        out[tcp + 16..tcp + 18].copy_from_slice(&checksum.to_be_bytes());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_state_reassembly() {
        let mut state = FlowState::new(u32::MAX - 1);
        assert_eq!(state.push_segment(u32::MAX - 1, &[1, 2, 3]), 0);
        // Full retransmission
        assert_eq!(state.push_segment(u32::MAX - 1, &[1, 2, 3]), 1);
        // Out of order, after a gap
        assert_eq!(state.push_segment(3, &[6, 7]), 0);
        assert_eq!(&state.buf[..], &[1, 2, 3]);
        // Partial overlap filling the gap
        assert_eq!(state.push_segment(0, &[3, 4, 5]), 0);
        assert_eq!(&state.buf[..], &[1, 2, 3, 4, 5, 6, 7]);
        assert!(state.pending.is_empty());
        assert_eq!(state.expected_seq, 5);
    }

    fn ipv4_tcp_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        let total_len = (40 + payload.len()) as u16;
        frame.extend_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, IP_PROTO_TCP, 0, 0]);
        frame[16..18].copy_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        frame.extend_from_slice(&[0x30, 0x39, 0x27, 0x10, 0, 0, 0, 1, 0, 0, 0, 1]);
        frame.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        frame.extend_from_slice(payload);
        // Ethernet padding must not be treated as payload
        frame.extend_from_slice(&[0; 4]);
        frame
    }

    #[test]
    fn test_tcp_segment_with_payload() {
        let frame = ipv4_tcp_frame(&[1, 2, 3]);
        let segment = TcpSegment::parse(Linktype::ETHERNET, &frame).unwrap();
        assert_eq!(segment.payload(), &[1, 2, 3]);
        assert_eq!(segment.seq, 1);
        assert_eq!(segment.max_payload_len(), usize::from(u16::MAX) - 40);

        let max_payload = vec![0xab; segment.max_payload_len()];
        let packet = segment
            .with_payload(1000, Some(1790), &max_payload)
            .unwrap();
        let rebuilt = TcpSegment::parse(Linktype::ETHERNET, &packet).unwrap();
        assert_eq!(rebuilt.payload(), max_payload.as_slice());
        assert_eq!(rebuilt.seq, 1000);

        let Ok(Ip::Ipv4(ipv4)) = Ip::new(&packet[14..]) else {
            panic!("expected IPv4");
        };
        assert_eq!(ipv4.checksum(), ipv4.computed_checksum());
        let tcp = TcpPdu::new(&packet[34..]).unwrap();
        assert_eq!(tcp.destination_port(), 1790);
        assert_eq!(tcp.checksum(), tcp.computed_checksum(&Ip::Ipv4(ipv4)));

        assert!(
            segment
                .with_payload(0, None, &[0; u16::MAX as usize])
                .is_err()
        );
    }

    #[test]
    fn test_tcp_segment_with_payload_clears_control_flags() {
        let mut frame = ipv4_tcp_frame(&[1, 2, 3]);
        let flags = 14 + 20 + TCP_FLAGS_OFFSET;
        let data_flags = frame[flags];
        frame[flags] |= TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST;
        let segment = TcpSegment::parse(Linktype::ETHERNET, &frame).unwrap();

        let packet = segment.with_payload(1, None, &[1]).unwrap();
        assert_eq!(packet[flags], data_flags);
        let Ok(ip) = Ip::new(&packet[14..]) else {
            panic!("expected IP");
        };
        let tcp = TcpPdu::new(&packet[34..]).unwrap();
        assert_eq!(tcp.checksum(), tcp.computed_checksum(&ip));
    }

    #[test]
    fn test_split_resets_flow_on_syn() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.pcap");
        let output = dir.path().join("out.pcap");
        let tcp = 14 + 20;
        let segment = |seq: u32, flags: u8, payload: &[u8]| {
            let mut frame = ipv4_tcp_frame(payload);
            frame[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
            frame[tcp + TCP_FLAGS_OFFSET] = flags;
            frame
        };
        let mut writer = crate::writer::LegacyPcapWriter::new(File::create(&input).unwrap());
        for frame in [
            // First connection, message (length-prefixed) left incomplete
            segment(100, 0x18, &[3, 0xaa]),
            // Second connection on the same four-tuple
            segment(5000, TCP_FLAG_SYN, &[]),
            segment(5001, 0x18, &[2, 0xbb]),
        ] {
            writer
                .write_frame(Linktype::ETHERNET, std::time::Duration::ZERO, &frame)
                .unwrap();
        }
        writer.finish().unwrap();

        let mut messages = vec![];
        let stats = split_tcp_messages(
            &input,
            &output,
            &[10000],
            None,
            |buf| Ok(buf.first().map(|len| usize::from(*len))),
            |_, _, msg| messages.push(msg.to_vec()),
        )
        .unwrap();
        assert_eq!(messages, vec![vec![2, 0xbb]]);
        assert_eq!(stats.messages_out, 1);
        assert_eq!(stats.incomplete_flows.len(), 1);
        assert_eq!(stats.incomplete_flows[0].1, 2);
    }

    #[test]
    fn test_split_rejects_same_input_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capture.pcap");
        std::fs::write(&path, b"original").unwrap();
        let alias = dir.path().join(".").join("capture.pcap");

        let result = split_tcp_messages(&path, &alias, &[1790], None, |_| Ok(None), |_, _, _| {});
        assert!(matches!(result, Err(SplitError::SameFile(_))));
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }
}
