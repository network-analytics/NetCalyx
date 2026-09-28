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

//! RIB vocabulary: table addressing, AFI-SAFI identity and the per-route
//! "extra" payloads for labeled families.

use std::net::Ipv6Addr;

use netcalyx_bgp_pkt::nlri::{MplsLabel, RouteDistinguisher};
use netcalyx_bmp_pkt::{PeerHeader, PeerKey};
use netcalyx_iana::address_family::{AddressFamily, AddressType, SubsequentAddressFamily};

/// A unique identifier for any RIB table in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TableId {
    pub context: RibContext,
    pub afi_safi: AfiSafiType,
}

/// Identifies a routing table instance within a router.
/// Derived from the BMP per-peer header's RD field.
///   - Global: the default/global routing table (RD absent, or the literal
///     all-zero 8-byte encoding BMP uses for Global Instance Peers, RFC 7854
///     4.2)
///   - Vrf(rd): a VRF-specific routing table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RibContext {
    Global,
    Vrf(RouteDistinguisher),
}

impl From<Option<RouteDistinguisher>> for RibContext {
    fn from(rd: Option<RouteDistinguisher>) -> Self {
        match rd {
            None | Some(RouteDistinguisher::As2Administrator { asn2: 0, number: 0 }) => {
                RibContext::Global
            }
            Some(rd) => RibContext::Vrf(rd),
        }
    }
}

/// Peer identity with the RD normalized the way [`RibContext`] normalizes it.
///
/// `PeerKey` compares its RD verbatim while `RibContext` folds an absent RD and
/// the literal all-zero type-0 encoding into the global table. Without this
/// normalization, a router that reports no RD on peer-up but `0:0` on later
/// updates would produce two different `PeerKey`s for the same session,
/// splitting its adj-rib between them.
pub fn peer_identity(header: &PeerHeader) -> PeerKey {
    let rd = match RibContext::from(header.rd()) {
        RibContext::Global => None,
        RibContext::Vrf(rd) => Some(rd),
    };
    PeerKey::new(
        header.address(),
        header.peer_type(),
        rd,
        header.peer_as(),
        header.bgp_id(),
    )
}

/// BGP AFI-SAFI type identities (RFC 4760).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AfiSafiType {
    Ipv4Unicast,
    Ipv6Unicast,
    Ipv4LabeledUnicast,
    Ipv6LabeledUnicast,
    L3VpnIpv4Unicast,
    L3VpnIpv6Unicast,
    Unsupported(AddressFamily, SubsequentAddressFamily),
}

impl AfiSafiType {
    pub fn from_afi_safi(afi: AddressFamily, safi: SubsequentAddressFamily) -> Self {
        match (afi, safi) {
            (AddressFamily::IPv4, SubsequentAddressFamily::Unicast) => AfiSafiType::Ipv4Unicast,
            (AddressFamily::IPv6, SubsequentAddressFamily::Unicast) => AfiSafiType::Ipv6Unicast,
            (AddressFamily::IPv4, SubsequentAddressFamily::NlriMplsLabels) => {
                AfiSafiType::Ipv4LabeledUnicast
            }
            (AddressFamily::IPv6, SubsequentAddressFamily::NlriMplsLabels) => {
                AfiSafiType::Ipv6LabeledUnicast
            }
            (AddressFamily::IPv4, SubsequentAddressFamily::MplsVpn) => {
                AfiSafiType::L3VpnIpv4Unicast
            }
            (AddressFamily::IPv6, SubsequentAddressFamily::MplsVpn) => {
                AfiSafiType::L3VpnIpv6Unicast
            }
            _ => AfiSafiType::Unsupported(afi, safi),
        }
    }
}

impl From<AddressType> for AfiSafiType {
    fn from(addr_type: AddressType) -> Self {
        match addr_type {
            AddressType::Ipv4Unicast => AfiSafiType::Ipv4Unicast,
            AddressType::Ipv6Unicast => AfiSafiType::Ipv6Unicast,
            AddressType::Ipv4NlriMplsLabels => AfiSafiType::Ipv4LabeledUnicast,
            AddressType::Ipv6NlriMplsLabels => AfiSafiType::Ipv6LabeledUnicast,
            AddressType::Ipv4MplsLabeledVpn => AfiSafiType::L3VpnIpv4Unicast,
            AddressType::Ipv6MplsLabeledVpn => AfiSafiType::L3VpnIpv6Unicast,
            addr_type => AfiSafiType::Unsupported(
                addr_type.address_family(),
                addr_type.subsequent_address_family(),
            ),
        }
    }
}

/// Forwarding information carried per route for labeled families.
/// Flow enrichment needs this, not just the path attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabeledRouteExtra {
    /// Classic MPLS label stack
    Mpls(Box<[MplsLabel]>),
    /// SRv6 SID information
    Srv6(Box<Srv6RouteExtra>),
}

impl Default for LabeledRouteExtra {
    fn default() -> Self {
        LabeledRouteExtra::Mpls(Box::new([]))
    }
}

impl LabeledRouteExtra {
    pub fn labels(&self) -> &[MplsLabel] {
        match self {
            LabeledRouteExtra::Mpls(l) => l,
            LabeledRouteExtra::Srv6(s) => &s.label_stack,
        }
    }
}

/// Relevant info from the BGP-SID extension.
/// The dummy label stack from the route is retained for completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6RouteExtra {
    pub sid: Ipv6Addr,
    pub endpoint_behaviour: u16,
    pub label_stack: Box<[MplsLabel]>,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn rib_context_from_none_rd_is_global() {
        assert_eq!(RibContext::from(None), RibContext::Global);
    }

    #[test]
    fn rib_context_from_type0_zero_rd_is_global() {
        let zero_as2 = RouteDistinguisher::As2Administrator { asn2: 0, number: 0 };
        assert_eq!(RibContext::from(Some(zero_as2)), RibContext::Global);
    }

    #[test]
    fn rib_context_from_type1_and_type2_zero_admin_rds_are_distinct_vrfs() {
        // Only the type-0 encoding is bit-for-bit all zero on the wire (RFC
        // 4364 4.2); type-1/type-2 RDs with a zero administrator still carry
        // a nonzero type field, so they are real, distinct RDs, not Global.
        let zero_ipv4 = RouteDistinguisher::Ipv4Administrator {
            ip: Ipv4Addr::UNSPECIFIED,
            number: 0,
        };
        let zero_as4 = RouteDistinguisher::As4Administrator { asn4: 0, number: 0 };

        assert_eq!(
            RibContext::from(Some(zero_ipv4)),
            RibContext::Vrf(zero_ipv4)
        );
        assert_eq!(RibContext::from(Some(zero_as4)), RibContext::Vrf(zero_as4));
        assert_ne!(RibContext::from(Some(zero_ipv4)), RibContext::Global);
        assert_ne!(RibContext::from(Some(zero_as4)), RibContext::Global);
    }

    #[test]
    fn rib_context_from_nonzero_rd_is_vrf() {
        let rd = RouteDistinguisher::As2Administrator {
            asn2: 65000,
            number: 1,
        };
        assert_eq!(RibContext::from(Some(rd)), RibContext::Vrf(rd));
    }

    #[test]
    fn afi_safi_type_from_afi_safi_maps_known_pairs() {
        use netcalyx_iana::address_family::SubsequentAddressFamily;

        assert_eq!(
            AfiSafiType::from_afi_safi(AddressFamily::IPv4, SubsequentAddressFamily::Unicast),
            AfiSafiType::Ipv4Unicast
        );
        assert_eq!(
            AfiSafiType::from_afi_safi(AddressFamily::IPv6, SubsequentAddressFamily::MplsVpn),
            AfiSafiType::L3VpnIpv6Unicast
        );
    }

    #[test]
    fn afi_safi_type_from_afi_safi_falls_back_to_unsupported() {
        use netcalyx_iana::address_family::SubsequentAddressFamily;

        assert_eq!(
            AfiSafiType::from_afi_safi(AddressFamily::IPv4, SubsequentAddressFamily::Multicast),
            AfiSafiType::Unsupported(AddressFamily::IPv4, SubsequentAddressFamily::Multicast)
        );
    }

    #[test]
    fn afi_safi_type_from_address_type_matches_from_afi_safi() {
        assert_eq!(
            AfiSafiType::from(AddressType::Ipv4NlriMplsLabels),
            AfiSafiType::Ipv4LabeledUnicast
        );
    }

    #[test]
    fn labeled_route_extra_labels_reads_both_variants() {
        let mpls = LabeledRouteExtra::Mpls(Box::new([MplsLabel::new([0, 0, 1])]));
        assert_eq!(mpls.labels(), &[MplsLabel::new([0, 0, 1])]);

        let srv6 = LabeledRouteExtra::Srv6(Box::new(Srv6RouteExtra {
            sid: Ipv6Addr::UNSPECIFIED,
            endpoint_behaviour: 0,
            label_stack: Box::new([MplsLabel::new([0, 0, 2])]),
        }));
        assert_eq!(srv6.labels(), &[MplsLabel::new([0, 0, 2])]);
    }

    #[test]
    fn peer_identity_normalizes_absent_and_zero_rd_the_same() {
        use netcalyx_bmp_pkt::BmpPeerType;

        fn header(rd: Option<RouteDistinguisher>) -> PeerHeader {
            PeerHeader::new(
                BmpPeerType::GlobalInstancePeer {
                    ipv6: false,
                    post_policy: false,
                    asn2: false,
                    adj_rib_out: false,
                },
                rd,
                None,
                65000,
                Ipv4Addr::new(1, 1, 1, 1),
                None,
            )
        }

        let zero_rd = RouteDistinguisher::As2Administrator { asn2: 0, number: 0 };
        let no_rd = peer_identity(&header(None));
        let with_zero_rd = peer_identity(&header(Some(zero_rd)));
        assert_eq!(no_rd, with_zero_rd);
    }
}
