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

use bytes::BytesMut;
use netcalyx_bmp_pkt::BmpMessage;
use netcalyx_bmp_pkt::codec::BmpCodec;
use netcalyx_pcap_reader::PcapIter;
use netcalyx_pcap_tools::bmp::{BmpValidator, bmp_message_len};
use netcalyx_pcap_tools::tcp_split::{PCAP_BUFFER_SIZE, SplitStats, split_tcp_messages};
use pdu::{EthernetPdu, Ip, TcpPdu};
use std::fs::File;
use std::path::{Path, PathBuf};
use tokio_util::codec::Decoder;

const BMP_PORT: u16 = 10000;
const REWRITTEN_PORT: u16 = 1790;

fn input_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../assets/pcaps/bmp/path-status/ipv4_unicast_path_marking.pcap")
}

/// Decode a capture as a stream, returning the messages decoded from every
/// packet
fn decode_per_packet(path: &Path, port: u16) -> Vec<Vec<BmpMessage>> {
    let reader = pcap_parser::create_reader(PCAP_BUFFER_SIZE, File::open(path).unwrap()).unwrap();
    let mut codec = BmpCodec::default();
    let mut buf = BytesMut::new();
    let mut packets = vec![];
    for (_, _, _, dst_port, _, payload) in PcapIter::new(reader) {
        if dst_port != port {
            continue;
        }
        buf.extend_from_slice(&payload);
        let mut messages = vec![];
        while let Some(msg) = codec.decode(&mut buf).unwrap() {
            messages.push(msg);
        }
        packets.push(messages);
    }
    assert!(buf.is_empty());
    packets
}

#[test]
fn test_bmp_split_one_message_per_packet() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("split.pcap");
    let mut validator = BmpValidator::default();

    let stats = split_tcp_messages(
        &input_path(),
        &output,
        &[BMP_PORT],
        Some(REWRITTEN_PORT),
        bmp_message_len,
        |flow, _, msg| {
            validator.validate(flow, msg).unwrap();
        },
    )
    .unwrap();

    assert_eq!(
        stats,
        SplitStats {
            frames_in: 2,
            messages_out: 5,
            packets_out: 5,
            duplicate_segments: 0,
            incomplete_flows: vec![],
        }
    );

    let original: Vec<BmpMessage> = decode_per_packet(&input_path(), BMP_PORT)
        .into_iter()
        .flatten()
        .collect();
    let split = decode_per_packet(&output, REWRITTEN_PORT);
    assert_eq!(split.len(), 5);
    assert!(split.iter().all(|messages| messages.len() == 1));
    assert_eq!(split.into_iter().flatten().collect::<Vec<_>>(), original);
}

#[test]
fn test_bmp_split_headers_are_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("split.pcap");
    split_tcp_messages(
        &input_path(),
        &output,
        &[BMP_PORT],
        None,
        bmp_message_len,
        |_, _, _| {},
    )
    .unwrap();

    let reader =
        pcap_parser::create_reader(PCAP_BUFFER_SIZE, File::open(&output).unwrap()).unwrap();
    let mut iter = PcapIter::new(reader);
    let mut expected_seq = None;
    while let Some((.., payload)) = iter.next() {
        let frame = iter.raw_frame();
        let eth = EthernetPdu::new(frame).unwrap();
        let l3 = &frame[eth.computed_ihl()..];
        let Ip::Ipv4(ipv4) = Ip::new(l3).unwrap() else {
            panic!("expected IPv4");
        };
        assert_eq!(usize::from(ipv4.total_length()), l3.len());
        assert_eq!(ipv4.checksum(), ipv4.computed_checksum());
        let tcp = TcpPdu::new(&l3[ipv4.computed_ihl()..]).unwrap();
        assert_eq!(tcp.destination_port(), BMP_PORT);
        assert_eq!(tcp.checksum(), tcp.computed_checksum(&Ip::Ipv4(ipv4)));
        if let Some(seq) = expected_seq {
            assert_eq!(tcp.sequence_number(), seq);
        }
        expected_seq = Some(tcp.sequence_number().wrapping_add(payload.len() as u32));
    }
}
