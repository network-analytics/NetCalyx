// Copyright (C) 2026-present The NetCalyx Authors.
// Copyright (C) 2023-present The NetGauze Authors.
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

//! Helper library to read pcap files, this library is not meant for production
//! use but rather for testing purposes.
//!
//! Example:
//! ```rust,ignore
//! use std::{collections::HashMap, fs::File};
//!
//! use bytes::BytesMut;
//! use pcap_parser::PcapNGReader;
//! use tokio_util::codec::Decoder;
//!
//! use netcalyx_bmp_pkt::codec::BmpCodec;
//! use netcalyx_pcap_reader::{PcapIter, TransportProtocol};
//!
//! let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
//! path.push_str("/data/bmp.pcapng");
//! let file = File::open(path).unwrap();
//! let reader = PcapNGReader::new(165536, file).unwrap();
//! let reader = Box::new(reader);
//! let iter = PcapIter::new(reader);
//! let mut peers = HashMap::new();
//! for (src_ip, src_port, dst_ip, dst_port, protocol, value) in iter {
//!     if protocol != TransportProtocol::TCP {
//!         continue;
//!     }
//!     let key = (src_ip, src_port, dst_ip, dst_port);
//!     let (codec, buf) = peers
//!         .entry(key)
//!         .or_insert((BmpCodec::default(), BytesMut::new()));
//!     buf.extend_from_slice(value.as_slice());
//!     // A segment can carry multiple messages
//!     loop {
//!         match codec.decode(buf) {
//!             Ok(Some(msg)) => println!("{}", serde_json::to_string(&msg).unwrap()),
//!             Ok(None) => break,
//!             Err(err) => {
//!                 println!("Error parsing BMP Message: {:?}", err);
//!                 break;
//!             }
//!         }
//!     }
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use pcap_parser::data::PacketData;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use pdu::{Ethernet, Ipv4, Ipv4Pdu, Ipv6, Ipv6Pdu, Tcp, Udp};

/// Transport Protocol
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TransportProtocol {
    TCP,
    UDP,
}

/// Iterator over pcap files
pub struct PcapIter<'a> {
    reader: Box<dyn PcapReaderIterator + 'a>,
    /// Per interface: link type, timestamp offset (seconds) and timestamp
    /// resolution (units per second)
    interfaces: Vec<(Linktype, u64, u64)>,
    frame_counter: usize,
    timestamp: Duration,
    link_type: Linktype,
    raw_frame: Vec<u8>,
}

impl<'a> PcapIter<'a> {
    pub const fn new(reader: Box<dyn PcapReaderIterator + 'a>) -> Self {
        Self {
            reader,
            interfaces: vec![],
            frame_counter: 0,
            timestamp: Duration::ZERO,
            link_type: Linktype::NULL,
            raw_frame: vec![],
        }
    }

    /// Return the current frame counter
    pub const fn frame_counter(&self) -> usize {
        self.frame_counter
    }

    /// Capture timestamp (since UNIX epoch) of the last returned frame
    pub const fn timestamp(&self) -> Duration {
        self.timestamp
    }

    /// Link type of the last returned frame
    pub const fn link_type(&self) -> Linktype {
        self.link_type
    }

    /// Captured bytes (including link layer header) of the last returned frame
    pub fn raw_frame(&self) -> &[u8] {
        &self.raw_frame
    }
}

fn to_duration(secs: u32, fraction: u32, resolution: u64) -> Duration {
    let nanos = u64::from(fraction) * 1_000_000_000 / resolution;
    Duration::new(u64::from(secs), nanos as u32)
}

impl Iterator for PcapIter<'_> {
    type Item = (IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::Legacy(legacy_packet) => {
                            let (link_type, _, resolution) = self.interfaces[0];
                            let caplen = legacy_packet.caplen as usize;
                            self.frame_counter += 1;
                            let packet_data =
                                data::get_packetdata(legacy_packet.data, link_type, caplen);
                            let result = PcapIter::parse_packet(packet_data);
                            if result.is_some() {
                                self.link_type = link_type;
                                self.timestamp = to_duration(
                                    legacy_packet.ts_sec,
                                    legacy_packet.ts_usec,
                                    resolution,
                                );
                                self.raw_frame.clear();
                                self.raw_frame.extend_from_slice(
                                    &legacy_packet.data[..caplen.min(legacy_packet.data.len())],
                                );
                            }
                            self.reader.consume(offset);
                            if result.is_some() {
                                return result;
                            }
                        }
                        PcapBlockOwned::LegacyHeader(header) => {
                            self.reader.consume(offset);
                            let resolution = if header.is_nanosecond_precision() {
                                1_000_000_000
                            } else {
                                1_000_000
                            };
                            self.interfaces.push((header.network, 0, resolution));
                            continue;
                        }
                        PcapBlockOwned::NG(Block::InterfaceDescription(description)) => {
                            // Memorize link type and timestamp format for that
                            // given interface
                            self.interfaces.push((
                                description.linktype,
                                u64::try_from(description.ts_offset()).unwrap_or(0),
                                description.ts_resolution().unwrap_or(1_000_000),
                            ));
                            self.reader.consume(offset);
                            continue;
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                            let (link_type, ts_offset, resolution) =
                                self.interfaces[packet.if_id as usize];
                            let caplen = packet.caplen as usize;
                            self.frame_counter += 1;
                            let packet_data = data::get_packetdata(packet.data, link_type, caplen);
                            let result = PcapIter::parse_packet(packet_data);
                            if result.is_some() {
                                let (secs, fraction) = packet.decode_ts(ts_offset, resolution);
                                self.link_type = link_type;
                                self.timestamp = to_duration(secs, fraction, resolution);
                                self.raw_frame.clear();
                                self.raw_frame.extend_from_slice(
                                    &packet.data[..caplen.min(packet.data.len())],
                                );
                            }
                            self.reader.consume(offset);
                            if result.is_some() {
                                return result;
                            }
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(_)) => {
                            todo!()
                        }
                        PcapBlockOwned::NG(_) => {
                            self.reader.consume(offset);
                            continue;
                        }
                    };
                }
                Err(PcapError::Incomplete(_)) => {
                    self.reader.refill().unwrap();
                }
                Err(PcapError::Eof) => return None,
                Err(PcapError::ReadError) => todo!(),
                Err(PcapError::HeaderNotRecognized) => todo!(),
                Err(PcapError::NomError(_, _)) => {
                    todo!()
                }
                Err(PcapError::OwnedNomError(_, _)) => todo!(),
                Err(PcapError::BufferTooSmall) => todo!(),
                Err(PcapError::UnexpectedEof) => todo!(),
            }
        }
    }
}

impl<'a> PcapIter<'a> {
    fn parse_packet(
        data: Option<PacketData<'a>>,
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        match data {
            None => None,
            Some(PacketData::L2(l2_pkt)) => Self::parse_ethernet(l2_pkt),
            Some(PacketData::L3(ether_type, data)) => {
                match ether_type {
                    // See for ethernet numbers https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
                    0x0800 => Self::parse_ipv4(Ipv4Pdu::new(data).expect("Invalid IPv4")),
                    0x86DD => Self::parse_ipv6(Ipv6Pdu::new(data).expect("Invalid IPv6")),
                    _ => unimplemented!("Only IPv4 and IPv6 packets are supported"),
                }
            }
            Some(PacketData::L4(_, _)) => unimplemented!("Only Ethernet packets are supported"),
            Some(PacketData::Unsupported(_)) => {
                unimplemented!("Only Ethernet and L3 packets are supported")
            }
        }
    }

    fn parse_ethernet(
        l2_pkt: &'a [u8],
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        pdu::EthernetPdu::new(l2_pkt)
            .map(|eth_pdu| match eth_pdu.inner() {
                Err(_) => None,
                Ok(Ethernet::Raw(_)) => unimplemented!(),
                Ok(Ethernet::Arp(_)) => None,
                Ok(Ethernet::Ipv4(ipv4_pdu)) => Self::parse_ipv4(ipv4_pdu),
                Ok(Ethernet::Ipv6(ipv6_pdu)) => Self::parse_ipv6(ipv6_pdu),
            })
            .unwrap()
    }

    fn parse_ipv4(
        ipv4_pdu: Ipv4Pdu<'_>,
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        let src_ip = IpAddr::V4(Ipv4Addr::from(ipv4_pdu.source_address()));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(ipv4_pdu.destination_address()));
        match ipv4_pdu.inner() {
            Err(_) => None,
            Ok(ipv4) => match ipv4 {
                Ipv4::Raw(_) => None,
                Ipv4::Tcp(tcp) => {
                    let src_port = tcp.source_port();
                    let dst_port = tcp.destination_port();
                    match tcp.inner() {
                        Err(_) => None,
                        Ok(Tcp::Raw(payload)) => Some((
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            TransportProtocol::TCP,
                            payload.to_vec(),
                        )),
                    }
                }
                Ipv4::Udp(udp) => {
                    let src_port = udp.source_port();
                    let dst_port = udp.destination_port();
                    // UDP payload length, to avoiding parsing any padding
                    // bytes.
                    let len = udp.length() as usize - 8;
                    match udp.inner() {
                        Err(_) => None,
                        Ok(Udp::Raw(payload)) => {
                            assert!(
                                len <= payload.len(),
                                "Invalid UDP payload length calculation"
                            );
                            Some((
                                src_ip,
                                src_port,
                                dst_ip,
                                dst_port,
                                TransportProtocol::UDP,
                                payload[..len].to_vec(),
                            ))
                        }
                    }
                }
                Ipv4::Icmp(_) => None,
                Ipv4::Gre(_) => unimplemented!("GRE Protocol is not supported!"),
                Ipv4::Esp(_) => unimplemented!("ESP Protocol is not supported!"),
            },
        }
    }

    fn parse_ipv6(
        ipv6_pdu: Ipv6Pdu<'_>,
    ) -> Option<(IpAddr, u16, IpAddr, u16, TransportProtocol, Vec<u8>)> {
        let src_ip = IpAddr::V6(Ipv6Addr::from(ipv6_pdu.source_address()));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(ipv6_pdu.destination_address()));
        match ipv6_pdu.inner() {
            Err(_) => None,
            Ok(ipv6) => match ipv6 {
                Ipv6::Raw(_) => None,
                Ipv6::Tcp(tcp) => {
                    let src_port = tcp.source_port();
                    let dst_port = tcp.destination_port();
                    match tcp.inner() {
                        Err(_) => None,
                        Ok(Tcp::Raw(payload)) => Some((
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            TransportProtocol::TCP,
                            payload.to_vec(),
                        )),
                    }
                }
                Ipv6::Udp(udp) => {
                    let src_port = udp.source_port();
                    let dst_port = udp.destination_port();
                    match udp.inner() {
                        Err(_) => None,
                        Ok(Udp::Raw(payload)) => Some((
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            TransportProtocol::UDP,
                            payload.to_vec(),
                        )),
                    }
                }
                Ipv6::Icmp(_) => None,
                Ipv6::Gre(_) => unimplemented!("GRE Protocol is not supported!"),
                Ipv6::Esp(_) => unimplemented!("ESP Protocol is not supported!"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    #[allow(clippy::while_let_on_iterator)]
    #[test]
    fn it_pcap() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
        path.push_str("/data/bgp.pcap");
        let file = File::open(path).unwrap();
        let reader = LegacyPcapReader::new(165536, file).unwrap();
        let reader = Box::new(reader);
        let mut iter = PcapIter::new(reader);
        let mut results = vec![];
        while let Some(val) = iter.next() {
            if results.is_empty() {
                assert_eq!(iter.link_type(), Linktype::ETHERNET);
                assert_eq!(iter.timestamp(), Duration::new(954_392_208, 953_280_000));
                assert_eq!(iter.raw_frame().len(), 60);
            }
            results.push(val);
        }
        assert_eq!(results.len(), 20);
        assert_eq!(iter.frame_counter(), 20);
        assert_eq!(iter.timestamp(), Duration::new(954_392_217, 533_067_000));
    }

    #[allow(clippy::while_let_on_iterator)]
    #[test]
    fn it_pcapng() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_owned();
        path.push_str("/data/bmp.pcapng");
        let file = File::open(path).unwrap();
        let reader = PcapNGReader::new(165536, file).unwrap();
        let reader = Box::new(reader);
        let mut iter = PcapIter::new(reader);
        let mut results = vec![];
        while let Some(val) = iter.next() {
            if results.is_empty() {
                assert_eq!(iter.link_type(), Linktype::ETHERNET);
                // Nanosecond if_tsresol
                assert_eq!(iter.timestamp(), Duration::new(1_664_821_745, 954_189_467));
                assert_eq!(iter.raw_frame().len(), 138);
            }
            results.push(val);
        }
        assert_eq!(results.len(), 9);
        assert_eq!(iter.timestamp(), Duration::new(1_664_821_878, 4_147_116));
        assert_eq!(iter.raw_frame().len(), 295);
    }
}
