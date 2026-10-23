// Copyright (C) 2026-present The NetCalyx Authors.
// Copyright (C) 2022-present The NetGauze Authors.
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

//! Codecs to decode and encode BMP Protocol messages from byte streams

use crate::iana::BmpVersion;
use crate::wire::deserializer::BmpMessageParsingError;
use crate::wire::serializer::BmpMessageWritingError;
use crate::{BmpMessage, PeerKey, v3, v4};
use byteorder::{ByteOrder, NetworkEndian};
use bytes::{Buf, BufMut, BytesMut};
use netcalyx_bgp_pkt::BgpMessage;
use netcalyx_bgp_pkt::capabilities::BgpCapability;
use std::collections::HashSet;

use crate::wire::deserializer::BmpParsingContext;
use netcalyx_bgp_pkt::capabilities::{AddPathAddressFamily, AddPathCapability, MultipleLabel};
use netcalyx_parse_utils::{LocatedParsingError, ReadablePduWithOneInput, Span, WritablePdu};
use nom::Needed;
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, Encoder};

/// Min length for a valid BMP Message: 1-octet version + 4-octet length
pub const BMP_MESSAGE_MIN_LENGTH: usize = 5;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum BmpCodecDecoderError {
    IoError(String),
    Incomplete(Option<usize>),
    BmpMessageParsingError(BmpMessageParsingError),
}

impl From<std::io::Error> for BmpCodecDecoderError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}

/// Encoder and Decoder for [`BmpMessage`]
#[derive(Debug, Default)]
pub struct BmpCodec {
    /// Helper to track in the decoder if we are inside a BMP message or not
    in_message: bool,
    ctx: BmpParsingContext,
}

#[inline]
fn get_caps(
    capabilities: Vec<&BgpCapability>,
) -> (Vec<AddPathCapability>, Vec<Vec<MultipleLabel>>) {
    let add_path_caps = capabilities
        .iter()
        .flat_map(|cap| {
            if let BgpCapability::AddPath(add_path) = cap {
                Some(add_path)
            } else {
                None
            }
        })
        .cloned()
        .collect::<Vec<AddPathCapability>>();
    let multiple_labels_caps = capabilities
        .iter()
        .flat_map(|cap| {
            if let BgpCapability::MultipleLabels(value) = cap {
                Some(value)
            } else {
                None
            }
        })
        .cloned()
        .collect::<Vec<Vec<MultipleLabel>>>();
    (add_path_caps, multiple_labels_caps)
}

/// Negotiate ADD-PATH per address family from the local (sent OPEN)
/// perspective. Sending requires remote receive support; receiving requires
/// remote send support.
fn negotiate_add_path(
    sent_caps: &[AddPathCapability],
    received_caps: &[AddPathCapability],
    is_loc_rib: bool,
) -> AddPathCapability {
    // For local-rib, the RX and TX opens must be identical. The mere presence
    // of an add-path capability indicates usage of add-path in the loc-rib
    // messages of this AFI/SAFI, regardless of the capability value announced.
    // c.f RFC9069 Section 5.2
    if is_loc_rib {
        return AddPathCapability::new(
            sent_caps
                .iter()
                .flat_map(|x| x.address_families())
                .map(|x| AddPathAddressFamily::new(x.address_type(), true, true))
                .collect(),
        );
    }

    AddPathCapability::new(
        sent_caps
            .iter()
            .flat_map(|cap| cap.address_families())
            .filter_map(|local| {
                let mut matching = received_caps
                    .iter()
                    .flat_map(|cap| cap.address_families())
                    .filter(|remote| remote.address_type() == local.address_type())
                    .peekable();

                matching.peek()?;

                Some(AddPathAddressFamily::new(
                    local.address_type(),
                    local.send() && matching.clone().any(|remote| remote.receive()),
                    local.receive() && matching.any(|remote| remote.send()),
                ))
            })
            .collect(),
    )
}

impl BmpCodec {
    pub fn update_parsing_ctx(&mut self, msg: &BmpMessage) {
        self.ctx.update(msg)
    }
}

impl BmpParsingContext {
    /// Update the parsing context based on information presented in the payload
    /// of BMP message. It updates BGP parsing flags such as: Add Path and
    /// Multi label MPLS capabilities
    pub fn update(&mut self, msg: &BmpMessage) {
        fn handle_peer_up(ctx: &mut BmpParsingContext, peer_up: &v3::PeerUpNotificationMessage) {
            let (sent_open, received_open) =
                match (peer_up.sent_message(), peer_up.received_message()) {
                    (BgpMessage::Open(sent_open), BgpMessage::Open(received_open)) => {
                        (sent_open, received_open)
                    }
                    _ => return,
                };

            let send_caps = sent_open.capabilities();
            let received_caps = received_open.capabilities();
            let (sent_add_path_caps, sent_multiple_labels_caps) = get_caps(send_caps);
            let (received_add_path_caps, received_multiple_labels_caps) = get_caps(received_caps);

            let is_loc_rib = peer_up.peer_header().peer_type().is_loc_rib();
            let negotiated_add_path =
                negotiate_add_path(&sent_add_path_caps, &received_add_path_caps, is_loc_rib);
            let sent_multiple_labels_caps: HashSet<MultipleLabel> =
                HashSet::from_iter(sent_multiple_labels_caps.into_iter().flatten());
            let received_multiple_labels_caps: HashSet<MultipleLabel> =
                HashSet::from_iter(received_multiple_labels_caps.into_iter().flatten());
            let common_multiple_labels_caps: Vec<MultipleLabel> = sent_multiple_labels_caps
                .intersection(&received_multiple_labels_caps)
                .cloned()
                .collect();
            // Add Key for the router announcing BMP to the collector
            let peer_key = PeerKey::from_peer_header(peer_up.peer_header());
            let bgp_ctx = ctx.entry(peer_key).or_default();
            // According to
            // [RFC 9069 Section 6.1.1](https://datatracker.ietf.org/doc/html/rfc9069#name-multiple-loc-rib-peers)
            // In some implementations, it might be required to have more
            // than one emulated peer for Loc-RIB to convey different address
            // families for the same Loc-RIB. In this case, the peer
            // distinguisher and BGP ID should be the same since they represent
            // the same Loc-RIB instance. Each emulated peer instance MUST send
            // a Peer Up with the OPEN message indicating the address family
            // capabilities. A BMP receiver MUST process these capabilities
            // to know which peer belongs to which address family.
            if !is_loc_rib {
                bgp_ctx.add_path_mut().clear();
                bgp_ctx.multiple_labels_mut().clear();
            }
            bgp_ctx.update_add_path(&negotiated_add_path);
            bgp_ctx.update_capabilities(&BgpCapability::MultipleLabels(
                common_multiple_labels_caps.clone(),
            ));

            // Add a key for the BGP Peer of the first router
            // In Loc-Rib the bgp open message is duplicated,
            // no need to go through it again.
            if !is_loc_rib {
                let peer_key = PeerKey::new(
                    peer_up.peer_header().address(),
                    peer_up.peer_header().peer_type(),
                    peer_up.peer_header().rd(),
                    peer_up.peer_header().peer_as(),
                    received_open.bgp_id(),
                );
                let bgp_ctx = ctx.entry(peer_key).or_default();
                bgp_ctx.add_path_mut().clear();
                bgp_ctx.multiple_labels_mut().clear();
                bgp_ctx.update_add_path(&negotiated_add_path);
                bgp_ctx.update_capabilities(&BgpCapability::MultipleLabels(
                    common_multiple_labels_caps,
                ));
            }
        }

        match msg {
            BmpMessage::V3(value) => match value {
                v3::BmpMessageValue::PeerDownNotification(peer_down) => {
                    let peer_key = PeerKey::from_peer_header(peer_down.peer_header());
                    self.remove(&peer_key);
                }
                v3::BmpMessageValue::Termination(_) => {
                    self.clear();
                }
                v3::BmpMessageValue::PeerUpNotification(peer_up) => {
                    handle_peer_up(self, peer_up);
                }
                _ => {}
            },
            BmpMessage::V4(value) => match value {
                v4::BmpMessageValue::PeerDownNotification(notif) => {
                    let peer_key = PeerKey::from_peer_header(notif.peer_header());
                    self.remove(&peer_key);
                }
                v4::BmpMessageValue::PeerUpNotification(peer_up) => handle_peer_up(self, peer_up),
                v4::BmpMessageValue::Termination(_) => {
                    self.clear();
                }
                _ => {}
            },
        }
    }
}

impl Encoder<BmpMessage> for BmpCodec {
    type Error = BmpMessageWritingError;

    fn encode(&mut self, bmp_msg: BmpMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(bmp_msg.len());
        let mut writer = dst.writer();
        bmp_msg.write(&mut writer)?;
        Ok(())
    }
}

impl Decoder for BmpCodec {
    type Item = BmpMessage;
    type Error = BmpCodecDecoderError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.in_message || buf.len() >= BMP_MESSAGE_MIN_LENGTH {
            let version: u8 = buf[0];
            // Fail early if the version is invalid
            if let Err(e) = BmpVersion::try_from(version) {
                buf.advance(1);
                return Err(BmpCodecDecoderError::BmpMessageParsingError(
                    BmpMessageParsingError::UndefinedBmpVersion(e),
                ));
            }
            // Read the length, starting form after the version
            let length = NetworkEndian::read_u32(&buf[1..BMP_MESSAGE_MIN_LENGTH]) as usize;
            if buf.len() < length {
                // We still didn't read all the bytes for the message yet
                self.in_message = true;
                Ok(None)
            } else {
                self.in_message = false;
                let msg = match BmpMessage::from_wire(Span::new(buf), &mut self.ctx) {
                    Ok((span, msg)) => {
                        self.update_parsing_ctx(&msg);
                        buf.advance(span.location_offset());
                        msg
                    }
                    Err(error) => {
                        let err = match error {
                            nom::Err::Incomplete(needed) => {
                                let needed = match needed {
                                    Needed::Unknown => None,
                                    Needed::Size(size) => Some(size.get()),
                                };
                                BmpCodecDecoderError::Incomplete(needed)
                            }
                            nom::Err::Error(error) | nom::Err::Failure(error) => {
                                BmpCodecDecoderError::BmpMessageParsingError(error.error().clone())
                            }
                        };
                        // Make sure we advance the buffer far enough,
                        // so we don't get stuck on an error value.
                        // Unfortunately, BMP doesn't have synchronization
                        // values like in BGP to understand we are in a new
                        // message.
                        buf.advance(if length < 5 { 5 } else { length });
                        return Err(err);
                    }
                };
                Ok(Some(msg))
            }
        } else {
            // We don't have enough data yet to start processing
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::{InitiationInformation, PeerDownNotificationReason, TerminationInformation};
    use crate::*;
    use chrono::TimeZone;
    use netcalyx_bgp_pkt::capabilities::{
        ExtendedNextHopEncoding, ExtendedNextHopEncodingCapability, FourOctetAsCapability,
        MultiProtocolExtensionsCapability,
    };
    use netcalyx_bgp_pkt::nlri::{
        Ipv4Unicast, Ipv4UnicastAddress, Ipv6Unicast, Ipv6UnicastAddress,
    };
    use netcalyx_bgp_pkt::open::{BgpOpenMessage, BgpOpenMessageParameter};
    use netcalyx_bgp_pkt::path_attribute::{MpReach, MpUnreach, PathAttribute, PathAttributeValue};
    use netcalyx_bgp_pkt::update::BgpUpdateMessage;
    use netcalyx_iana::address_family::{AddressFamily, AddressType};
    use std::collections::HashMap;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    #[test]
    fn test_codec() -> Result<(), BmpMessageWritingError> {
        let msg = BmpMessage::V3(v3::BmpMessageValue::Initiation(v3::InitiationMessage::new(
            vec![
                InitiationInformation::SystemDescription("test11".to_string()),
                InitiationInformation::SystemName("PE2".to_string()),
            ],
        )));
        let mut code = BmpCodec::default();
        let mut buf = BytesMut::with_capacity(msg.len());
        let mut empty_buf = BytesMut::with_capacity(msg.len());
        let mut error_buf = BytesMut::from(&[0xffu8, 0x00u8, 0x00u8, 0x00u8, 0x01u8, 0xffu8][..]);

        code.encode(msg.clone(), &mut buf)?;
        let decode = code.decode(&mut buf);
        let decode_empty = code.decode(&mut empty_buf);
        let decode_error = code.decode(&mut error_buf);

        assert!(decode.is_ok());
        assert_eq!(decode.unwrap(), Some(msg));
        assert!(decode_empty.is_ok());
        assert_eq!(decode_empty.unwrap(), None);
        assert!(decode_error.is_err());
        Ok(())
    }

    #[test]
    fn test_peer_key_add_remove() -> Result<(), BmpMessageWritingError> {
        let peer_header = PeerHeader::new(
            BmpPeerType::GlobalInstancePeer {
                ipv6: true,
                post_policy: false,
                asn2: false,
                adj_rib_out: false,
            },
            None,
            Some(IpAddr::V6(Ipv6Addr::from_str("fc00::1").unwrap())),
            64512,
            Ipv4Addr::new(10, 0, 0, 1),
            Some(Utc.timestamp_opt(1664821826, 645593000).unwrap()),
        );

        let peer_up = BmpMessage::V3(v3::BmpMessageValue::PeerUpNotification(
            v3::PeerUpNotificationMessage::build(
                peer_header.clone(),
                Some(IpAddr::V6(Ipv6Addr::from_str("fc00::3").unwrap())),
                Some(179),
                Some(29834),
                BgpMessage::Open(BgpOpenMessage::new(
                    64512,
                    180,
                    Ipv4Addr::new(10, 0, 0, 3),
                    vec![
                        BgpOpenMessageParameter::Capabilities(vec![
                            BgpCapability::MultiProtocolExtensions(
                                MultiProtocolExtensionsCapability::new(
                                    AddressType::Ipv4MplsLabeledVpn,
                                ),
                            ),
                        ]),
                        BgpOpenMessageParameter::Capabilities(vec![BgpCapability::FourOctetAs(
                            FourOctetAsCapability::new(64512),
                        )]),
                        BgpOpenMessageParameter::Capabilities(vec![
                            BgpCapability::ExtendedNextHopEncoding(
                                ExtendedNextHopEncodingCapability::new(vec![
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4Unicast,
                                        AddressFamily::IPv6,
                                    ),
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4Multicast,
                                        AddressFamily::IPv6,
                                    ),
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4MplsLabeledVpn,
                                        AddressFamily::IPv6,
                                    ),
                                ]),
                            ),
                        ]),
                    ],
                )),
                BgpMessage::Open(BgpOpenMessage::new(
                    64512,
                    180,
                    Ipv4Addr::new(10, 0, 0, 1),
                    vec![
                        BgpOpenMessageParameter::Capabilities(vec![
                            BgpCapability::MultiProtocolExtensions(
                                MultiProtocolExtensionsCapability::new(
                                    AddressType::Ipv4MplsLabeledVpn,
                                ),
                            ),
                        ]),
                        BgpOpenMessageParameter::Capabilities(vec![BgpCapability::FourOctetAs(
                            FourOctetAsCapability::new(64512),
                        )]),
                        BgpOpenMessageParameter::Capabilities(vec![
                            BgpCapability::ExtendedNextHopEncoding(
                                ExtendedNextHopEncodingCapability::new(vec![
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4Unicast,
                                        AddressFamily::IPv6,
                                    ),
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4Multicast,
                                        AddressFamily::IPv6,
                                    ),
                                    ExtendedNextHopEncoding::new(
                                        AddressType::Ipv4MplsLabeledVpn,
                                        AddressFamily::IPv6,
                                    ),
                                ]),
                            ),
                        ]),
                    ],
                )),
                vec![],
            )
            .unwrap(),
        ));

        let peer_down = BmpMessage::V3(v3::BmpMessageValue::PeerDownNotification(
            v3::PeerDownNotificationMessage::build(
                peer_header.clone(),
                PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(2),
            )
            .unwrap(),
        ));

        let terminate = BmpMessage::V3(v3::BmpMessageValue::Termination(
            v3::TerminationMessage::new(vec![TerminationInformation::String("test".to_string())]),
        ));

        let mut codec = BmpCodec::default();
        let peer_key = PeerKey::from_peer_header(&peer_header);
        // Check initially empty
        assert!(!codec.ctx.contains_key(&peer_key));

        // Check peer registered correctly
        codec.update_parsing_ctx(&peer_up);
        assert!(codec.ctx.contains_key(&peer_key));

        // Check peer removed after a Peer Down Message
        codec.update_parsing_ctx(&peer_down);
        assert!(!codec.ctx.contains_key(&peer_key));

        // Register again
        codec.update_parsing_ctx(&peer_up);
        assert!(codec.ctx.contains_key(&peer_key));

        // Check peer removed after a terminate message
        codec.update_parsing_ctx(&terminate);
        assert!(!codec.ctx.contains_key(&peer_key));
        Ok(())
    }

    #[test]
    fn test_add_path_direction_negotiation() {
        let combinations = itertools::iproduct!(
            [false, true],
            [false, true],
            [false, true],
            [false, true],
            [false, true]
        );

        for (local_send, local_receive, remote_send, remote_receive, adj_rib_out) in combinations {
            let header = PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: false,
                    post_policy: false,
                    asn2: false,
                    adj_rib_out,
                },
                None,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                64512,
                Ipv4Addr::new(192, 0, 2, 1),
                None,
            );
            let open = |id, families| {
                BgpMessage::Open(BgpOpenMessage::new(
                    64512,
                    180,
                    id,
                    vec![BgpOpenMessageParameter::Capabilities(vec![
                        BgpCapability::AddPath(AddPathCapability::new(families)),
                    ])],
                ))
            };
            let peer_up = BmpMessage::V3(v3::BmpMessageValue::PeerUpNotification(
                v3::PeerUpNotificationMessage::build(
                    header.clone(),
                    Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
                    Some(179),
                    Some(12345),
                    open(
                        Ipv4Addr::new(192, 0, 2, 2),
                        vec![
                            AddPathAddressFamily::new(
                                AddressType::Ipv4Unicast,
                                local_send,
                                local_receive,
                            ),
                            AddPathAddressFamily::new(AddressType::Ipv6Unicast, true, true),
                        ],
                    ),
                    open(
                        Ipv4Addr::new(192, 0, 2, 3),
                        vec![AddPathAddressFamily::new(
                            AddressType::Ipv4Unicast,
                            remote_send,
                            remote_receive,
                        )],
                    ),
                    vec![],
                )
                .unwrap(),
            ));
            let mut codec = BmpCodec::default();
            codec.update_parsing_ctx(&peer_up);
            // Check both the header key and the alternate
            // BGP-ID key.
            for id in [header.bgp_id(), Ipv4Addr::new(192, 0, 2, 3)] {
                let key = PeerKey::new(
                    header.address(),
                    header.peer_type(),
                    header.rd(),
                    header.peer_as(),
                    id,
                );
                let peer_ctx = codec.ctx.get_peer(&key).unwrap();
                for out in [false, true] {
                    let expected = if out {
                        local_send && remote_receive
                    } else {
                        local_receive && remote_send
                    };
                    assert_eq!(
                        peer_ctx
                            .add_path()
                            .add_path_enabled(AddressType::Ipv4Unicast, out),
                        expected,
                        "local=({local_send},{local_receive}), remote=({remote_send},{remote_receive}), peer_up_out={adj_rib_out}, out={out}"
                    );
                    assert!(!peer_ctx.add_path().contains_key(&AddressType::Ipv6Unicast));
                }
            }
        }
    }

    // Build matching IPv4 and IPv6 ADD-PATH entries with the requested
    // direction bits.
    fn add_path_capability(send: bool, receive: bool) -> BgpCapability {
        BgpCapability::AddPath(AddPathCapability::new(
            [AddressType::Ipv4Unicast, AddressType::Ipv6Unicast]
                .map(|family| AddPathAddressFamily::new(family, send, receive))
                .to_vec(),
        ))
    }

    // Wrap the supplied OPENs and peer header in the requested BMP version.
    fn peer_up_message(
        version: BmpVersion,
        header: PeerHeader,
        sent: BgpMessage,
        received: BgpMessage,
    ) -> BmpMessage {
        let peer_up =
            v3::PeerUpNotificationMessage::build(header, None, None, None, sent, received, vec![])
                .unwrap();
        match version {
            BmpVersion::Version3 => {
                BmpMessage::V3(v3::BmpMessageValue::PeerUpNotification(peer_up))
            }
            BmpVersion::Version4 => {
                BmpMessage::V4(v4::BmpMessageValue::PeerUpNotification(peer_up))
            }
        }
    }

    // Build IPv4 and IPv6 announcements and withdrawals with an optional path
    // ID.
    fn add_path_update(path_id: Option<u32>) -> BgpMessage {
        let route = Ipv4UnicastAddress::new(
            path_id,
            Ipv4Unicast::from_net("198.51.100.0/24".parse().unwrap()).unwrap(),
        );
        let route_v6 = Ipv6UnicastAddress::new(
            path_id,
            Ipv6Unicast::from_net("2001:db8::/48".parse().unwrap()).unwrap(),
        );
        let attributes = [
            PathAttributeValue::MpReach(MpReach::Ipv6Unicast {
                next_hop_global: "2001:db8::1".parse().unwrap(),
                next_hop_local: None,
                nlri: vec![route_v6],
            }),
            PathAttributeValue::MpUnreach(MpUnreach::Ipv6Unicast {
                nlri: vec![route_v6],
            }),
        ]
        .map(|value| PathAttribute::from(true, false, false, false, value).unwrap())
        .to_vec();
        BgpMessage::Update(BgpUpdateMessage::new(vec![route], attributes, vec![route]))
    }

    // Wrap an UPDATE with an optional v4 message-local ADD-PATH override.
    fn route_monitoring_message(
        version: BmpVersion,
        header: PeerHeader,
        update: BgpMessage,
        override_support: Option<bool>,
    ) -> BmpMessage {
        match version {
            BmpVersion::Version3 => {
                assert!(override_support.is_none());
                BmpMessage::V3(v3::BmpMessageValue::RouteMonitoring(
                    v3::RouteMonitoringMessage::build(header, update).unwrap(),
                ))
            }
            BmpVersion::Version4 => {
                let tlvs = override_support
                    .map(|support| {
                        let (send, receive) = if header.peer_type().is_adj_rib_out() {
                            (support, !support)
                        } else {
                            (!support, support)
                        };
                        v4::RouteMonitoringTlv::build(
                            0,
                            v4::RouteMonitoringTlvValue::StatelessParsing(add_path_capability(
                                send, receive,
                            )),
                        )
                        .unwrap()
                    })
                    .into_iter()
                    .collect();
                BmpMessage::V4(v4::BmpMessageValue::RouteMonitoring(
                    v4::RouteMonitoringMessage::build(header, update, tlvs).unwrap(),
                ))
            }
        }
    }

    // Round-trip one message through the existing codec and require full
    // consumption.
    fn assert_codec_roundtrip(codec: &mut BmpCodec, message: BmpMessage) {
        let mut buf = BytesMut::new();
        codec.encode(message.clone(), &mut buf).unwrap();
        assert_eq!(codec.decode(&mut buf), Ok(Some(message)));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_loc_rib_add_path_ignores_capability_direction() {
        let bgp_id = Ipv4Addr::new(192, 0, 2, 1);
        for version in [BmpVersion::Version3, BmpVersion::Version4] {
            for (send, receive) in [(true, false), (false, true), (true, true)] {
                let header = PeerHeader::new(
                    BmpPeerType::LocRibInstancePeer { filtered: false },
                    None,
                    None,
                    64512,
                    bgp_id,
                    None,
                );
                let open = BgpMessage::Open(BgpOpenMessage::new(
                    64512,
                    180,
                    bgp_id,
                    vec![BgpOpenMessageParameter::Capabilities(vec![
                        BgpCapability::FourOctetAs(FourOctetAsCapability::new(64512)),
                        add_path_capability(send, receive),
                    ])],
                ));
                let mut codec = BmpCodec::default();
                assert_codec_roundtrip(
                    &mut codec,
                    peer_up_message(version, header.clone(), open.clone(), open),
                );
                let ctx = codec
                    .ctx
                    .get_peer(&PeerKey::from_peer_header(&header))
                    .unwrap();
                for family in [AddressType::Ipv4Unicast, AddressType::Ipv6Unicast] {
                    for outbound in [false, true] {
                        assert!(
                            ctx.add_path().add_path_enabled(family, outbound),
                            "version={version:?}, send={send}, receive={receive}"
                        );
                    }
                }
                assert_codec_roundtrip(
                    &mut codec,
                    route_monitoring_message(version, header, add_path_update(Some(42)), None),
                );
            }
        }
    }

    // Exercise both directions and aliases, temporary overrides, and session
    // reset.
    fn assert_bidirectional_add_path_decoding(version: BmpVersion) {
        let local_id = Ipv4Addr::new(192, 0, 2, 1);
        let remote_id = Ipv4Addr::new(192, 0, 2, 2);
        let header = |adj_rib_out, bgp_id| {
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: false,
                    post_policy: false,
                    asn2: false,
                    adj_rib_out,
                },
                None,
                Some(IpAddr::V4(remote_id)),
                64512,
                bgp_id,
                None,
            )
        };
        let open = |bgp_id, send, receive| {
            BgpMessage::Open(BgpOpenMessage::new(
                64512,
                180,
                bgp_id,
                vec![BgpOpenMessageParameter::Capabilities(vec![
                    add_path_capability(send, receive),
                ])],
            ))
        };

        for peer_up_out in [false, true] {
            for local_send in [false, true] {
                let peer_up = peer_up_message(
                    version,
                    header(peer_up_out, local_id),
                    open(local_id, local_send, !local_send),
                    open(remote_id, true, true),
                );
                let mut codec = BmpCodec::default();
                assert_codec_roundtrip(&mut codec, peer_up);

                // A single Peer Up supplies the session's capabilities for
                // both directions and both BGP-ID lookup aliases.
                for bgp_id in [local_id, remote_id] {
                    for (adj_rib_out, override_support) in [
                        (false, None),
                        (true, None),
                        (false, Some(false)),
                        (true, Some(true)),
                        (false, None),
                        (true, None),
                    ] {
                        if version == BmpVersion::Version3 && override_support.is_some() {
                            continue;
                        }
                        let support = override_support.unwrap_or(adj_rib_out == local_send);
                        let path_id = if support { Some(42) } else { None };
                        let message = route_monitoring_message(
                            version,
                            header(adj_rib_out, bgp_id),
                            add_path_update(path_id),
                            override_support,
                        );
                        assert_codec_roundtrip(&mut codec, message);
                    }
                }
                let empty_open =
                    |bgp_id| BgpMessage::Open(BgpOpenMessage::new(64512, 180, bgp_id, vec![]));
                let reset = peer_up_message(
                    version,
                    header(peer_up_out, local_id),
                    empty_open(local_id),
                    empty_open(remote_id),
                );
                assert_codec_roundtrip(&mut codec, reset);
                for bgp_id in [local_id, remote_id] {
                    let key = PeerKey::from_peer_header(&header(false, bgp_id));
                    let ctx = codec.ctx.get_peer(&key).unwrap();
                    assert!(ctx.add_path().is_empty());
                }
            }
        }
    }

    #[test]
    fn test_bidirectional_add_path_decoding_v3() {
        assert_bidirectional_add_path_decoding(BmpVersion::Version3);
    }

    #[test]
    fn test_bidirectional_add_path_decoding_v4() {
        assert_bidirectional_add_path_decoding(BmpVersion::Version4);
    }

    #[test]
    fn test_multiple_peer_up_for_loc_rib() {
        // announces add path for IPv4
        let up1_wire = vec![
            0x04, 0x00, 0x00, 0x00, 0xa6, 0x03, 0x03, 0x80, 0x00, 0x02, 0xfb, 0xf0, 0x00, 0x30,
            0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x30, 0xcb, 0x00, 0x71, 0x30, 0x68, 0x9a,
            0xf6, 0x17, 0x00, 0x07, 0xf7, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x31, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4, 0xcb, 0x00, 0x71, 0x30, 0x14, 0x02,
            0x12, 0x41, 0x04, 0xfb, 0xf0, 0x00, 0x30, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x45,
            0x04, 0x00, 0x01, 0x01, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x31, 0x01, 0x04, 0x5b, 0xa0, 0x00,
            0xb4, 0xcb, 0x00, 0x71, 0x30, 0x14, 0x02, 0x12, 0x41, 0x04, 0xfb, 0xf0, 0x00, 0x30,
            0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x45, 0x04, 0x00, 0x01, 0x01, 0x03,
        ];

        // announces add path for IPv6
        let up2_wire = vec![
            0x04, 0x00, 0x00, 0x00, 0xa6, 0x03, 0x03, 0x80, 0x00, 0x02, 0xfb, 0xf0, 0x00, 0x30,
            0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x30, 0xcb, 0x00, 0x71, 0x30, 0x68, 0x9a,
            0xf6, 0x17, 0x00, 0x07, 0xf7, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x31, 0x01, 0x04, 0x5b, 0xa0, 0x00, 0xb4, 0xcb, 0x00, 0x71, 0x30, 0x14, 0x02,
            0x12, 0x41, 0x04, 0xfb, 0xf0, 0x00, 0x30, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x45,
            0x04, 0x00, 0x02, 0x01, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x31, 0x01, 0x04, 0x5b, 0xa0, 0x00,
            0xb4, 0xcb, 0x00, 0x71, 0x30, 0x14, 0x02, 0x12, 0x41, 0x04, 0xfb, 0xf0, 0x00, 0x30,
            0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x45, 0x04, 0x00, 0x02, 0x01, 0x03,
        ];

        let peer_key = PeerKey::new(
            None,
            BmpPeerType::LocRibInstancePeer { filtered: true },
            Some(RouteDistinguisher::As4Administrator {
                asn4: 4226809904,
                number: 23,
            }),
            4226809904,
            Ipv4Addr::new(203, 0, 113, 48),
        );
        let mut codec = BmpCodec::default();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&up1_wire);
        buf.extend_from_slice(&up2_wire);

        // check after each decoded BGP open if the ADD Path ctx
        // is including the new address family
        let _ = codec
            .decode(&mut buf)
            .expect("decode up1_wire failed")
            .expect("no message decoded from up1");
        // Only IPv4 add path is added to the BGP decoding context
        // for the first peer up message
        let add_path1 = codec
            .ctx
            .get_peer(&peer_key)
            .expect("peer lookup failed")
            .add_path();
        assert_eq!(
            &**add_path1,
            &HashMap::from([(
                AddressType::Ipv4Unicast,
                AddPathAddressFamily::new(AddressType::Ipv4Unicast, true, true)
            )])
        );
        let _ = codec
            .decode(&mut buf)
            .expect("decode up1_wire failed")
            .expect("no message decoded from up2");
        // IPv6 add path is added to the BGP decoding context
        // without deleting the add path for IPv4
        let add_path2 = codec
            .ctx
            .get_peer(&peer_key)
            .expect("peer lookup failed")
            .add_path();
        assert_eq!(
            &**add_path2,
            &HashMap::from([
                (
                    AddressType::Ipv4Unicast,
                    AddPathAddressFamily::new(AddressType::Ipv4Unicast, true, true)
                ),
                (
                    AddressType::Ipv6Unicast,
                    AddPathAddressFamily::new(AddressType::Ipv6Unicast, true, true)
                )
            ])
        );
    }
}
