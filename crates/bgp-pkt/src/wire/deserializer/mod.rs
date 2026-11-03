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

//! Deserializer library for BGP's wire protocol

pub mod capabilities;
pub mod community;
pub mod nlri;
pub mod notification;
pub mod open;
pub mod path_attribute;
pub mod route_refresh;
pub mod update;

use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netcalyx_iana::address_family::AddressType;
use nom::IResult;
use nom::error::ErrorKind;
use nom::number::complete::{be_u8, be_u16, be_u32, be_u128};
use serde::{Deserialize, Serialize};

use netcalyx_parse_utils::{
    ErrorKindSerdeDeref, ReadablePdu, ReadablePduWithOneInput, ReadablePduWithTwoInputs, Span,
    parse_into_located, parse_into_located_one_input, parse_into_located_two_inputs,
};

use crate::BgpMessage;
use crate::capabilities::{AddPathAddressFamily, AddPathCapability, BgpCapability, MultipleLabel};
use crate::iana::{BgpMessageType, UndefinedBgpMessageType};
use crate::notification::{BgpNotificationMessage, FiniteStateMachineError, MessageHeaderError};
use crate::wire::deserializer::capabilities::BgpCapabilityParsingError;
use crate::wire::deserializer::notification::BgpNotificationMessageParsingError;
use crate::wire::deserializer::open::BgpOpenMessageParsingError;
use crate::wire::deserializer::path_attribute::PathAttributeParsingError;
use crate::wire::deserializer::route_refresh::BgpRouteRefreshMessageParsingError;
use crate::wire::deserializer::update::BgpUpdateMessageParsingError;
use crate::wire::serializer::nlri::{IPV4_LEN, IPV6_LEN};
use netcalyx_serde_macros::LocatedError;

/// Min message size in BGP is 19 octets. They're counted from
/// 16-octets synchronization header, 2-octets length, and 1 octet for type.
pub const BGP_MIN_MESSAGE_LENGTH: u16 = 19;

/// [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271) defined max length as 4096.
/// *Note*, this only applies to [`BgpMessage::Open`] and
/// [`BgpMessage::KeepAlive`] according to the updated
/// [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654)
pub const BGP_MAX_MESSAGE_LENGTH: u16 = 4096;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct BgpParsingIgnoredErrors {
    non_unicast_withdraw_nlri: Vec<Ipv4Net>,
    non_unicast_update_nlri: Vec<Ipv4Net>,
    capability_errors: Vec<BgpCapabilityParsingError>,
    path_attr_errors: Vec<PathAttributeParsingError>,
}

impl BgpParsingIgnoredErrors {
    pub const fn non_unicast_withdraw_nlri(&self) -> &Vec<Ipv4Net> {
        &self.non_unicast_withdraw_nlri
    }

    pub const fn non_unicast_update_nlri(&self) -> &Vec<Ipv4Net> {
        &self.non_unicast_update_nlri
    }

    pub const fn capability_errors(&self) -> &Vec<BgpCapabilityParsingError> {
        &self.capability_errors
    }

    pub const fn path_attr_errors(&self) -> &Vec<PathAttributeParsingError> {
        &self.path_attr_errors
    }
}

/// ADD-PATH support from the local OPEN's perspective, stored per direction.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct AddPathMap {
    send: HashSet<AddressType>,
    receive: HashSet<AddressType>,
}

impl AddPathMap {
    /// Replace both direction settings for a family.
    pub fn insert(&mut self, family: AddPathAddressFamily) -> Option<AddPathAddressFamily> {
        let address_type = family.address_type();
        let previous = self.get(&address_type);
        for (set, enabled) in [
            (&mut self.send, family.send()),
            (&mut self.receive, family.receive()),
        ] {
            if enabled {
                set.insert(address_type);
            } else {
                set.remove(&address_type);
            }
        }
        previous
    }

    pub fn get(&self, address_type: &AddressType) -> Option<AddPathAddressFamily> {
        let send = self.send.contains(address_type);
        let receive = self.receive.contains(address_type);
        (send || receive).then(|| AddPathAddressFamily::new(*address_type, send, receive))
    }

    pub fn clear(&mut self) {
        self.send.clear();
        self.receive.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.send.is_empty() && self.receive.is_empty()
    }

    pub fn len(&self) -> usize {
        self.send.union(&self.receive).count()
    }

    /// Combine support from duplicate entries or additional capabilities.
    pub fn extend(&mut self, other: &Self) {
        self.send.extend(&other.send);
        self.receive.extend(&other.receive);
    }

    /// Match local sending to remote receiving, and vice versa.
    pub fn negotiate(&self, remote: &Self) -> Self {
        Self {
            send: self.send.intersection(&remote.receive).copied().collect(),
            receive: self.receive.intersection(&remote.send).copied().collect(),
        }
    }

    pub fn add_path_enabled(&self, address_type: AddressType, direction: MessageDirection) -> bool {
        match direction {
            MessageDirection::Outbound => self.send.contains(&address_type),
            MessageDirection::Inbound => self.receive.contains(&address_type),
        }
    }
}

impl FromIterator<AddPathAddressFamily> for AddPathMap {
    fn from_iter<T: IntoIterator<Item = AddPathAddressFamily>>(iter: T) -> Self {
        let mut families = Self::default();
        for family in iter {
            if family.send() {
                families.send.insert(family.address_type());
            }
            if family.receive() {
                families.receive.insert(family.address_type());
            }
        }
        families
    }
}

/// Receiver label limits for one address family from the local OPEN's
/// perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct MultipleLabelsLimits {
    inbound: u8,
    outbound: u8,
}

impl MultipleLabelsLimits {
    /// Create limits for inbound and outbound messages, respectively.
    pub const fn new(inbound: u8, outbound: u8) -> Self {
        Self { inbound, outbound }
    }

    /// Return the inbound message limit.
    pub const fn inbound(&self) -> u8 {
        self.inbound
    }

    /// Return the outbound message limit.
    pub const fn outbound(&self) -> u8 {
        self.outbound
    }

    /// Return the limit for `direction`.
    pub const fn get(&self, direction: MessageDirection) -> u8 {
        match direction {
            MessageDirection::Inbound => self.inbound,
            MessageDirection::Outbound => self.outbound,
        }
    }
}

/// Receiver label limits from the local OPEN's perspective.
///
/// Families without an entry default to a single label
/// ([RFC 8277](https://datatracker.ietf.org/doc/html/rfc8277)).
#[derive(Debug, Default, Clone, PartialEq, Eq, derive_more::From)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct MultipleLabelsMap(HashMap<AddressType, MultipleLabelsLimits>);

impl FromIterator<(AddressType, MultipleLabelsLimits)> for MultipleLabelsMap {
    fn from_iter<T: IntoIterator<Item = (AddressType, MultipleLabelsLimits)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl MultipleLabelsMap {
    const DEFAULT_LIMIT: u8 = 1;

    pub fn insert(
        &mut self,
        address_type: AddressType,
        inbound: u8,
        outbound: u8,
    ) -> Option<MultipleLabelsLimits> {
        self.0
            .insert(address_type, MultipleLabelsLimits::new(inbound, outbound))
    }

    pub fn entry(
        &mut self,
        address_type: AddressType,
    ) -> std::collections::hash_map::Entry<'_, AddressType, MultipleLabelsLimits> {
        self.0.entry(address_type)
    }

    pub fn get(&self, address_type: &AddressType, direction: MessageDirection) -> Option<u8> {
        self.0.get(address_type).map(|limits| limits.get(direction))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Combine limits from another map, overriding existing entries.
    pub fn extend(&mut self, other: &Self) {
        self.0.extend(&other.0);
    }

    pub fn multiple_labels_limit(
        &self,
        address_type: AddressType,
        direction: MessageDirection,
    ) -> u8 {
        self.get(&address_type, direction)
            .unwrap_or(Self::DEFAULT_LIMIT)
    }
}

/// Direction of a complete BGP message, from the local OPEN's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum MessageDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone)]
pub struct BgpParsingContext {
    asn4: bool,
    multiple_labels: MultipleLabelsMap,
    add_path: AddPathMap,
    fail_on_non_unicast_withdraw_nlri: bool,
    fail_on_non_unicast_update_nlri: bool,
    fail_on_capability_error: bool,
    fail_on_malformed_path_attr: bool,
    parsing_errors: BgpParsingIgnoredErrors,
}

impl BgpParsingContext {
    /// Initialize ADD-PATH and receiver label limits for both message
    /// directions.
    pub fn new(
        asn4: bool,
        multiple_labels: MultipleLabelsMap,
        add_path: AddPathMap,
        fail_on_non_unicast_withdraw_nlri: bool,
        fail_on_non_unicast_update_nlri: bool,
        fail_on_capability_error: bool,
        fail_on_malformed_path_attr: bool,
    ) -> Self {
        Self {
            asn4,
            multiple_labels,
            add_path,
            fail_on_non_unicast_withdraw_nlri,
            fail_on_non_unicast_update_nlri,
            fail_on_capability_error,
            fail_on_malformed_path_attr,
            parsing_errors: BgpParsingIgnoredErrors::default(),
        }
    }

    pub fn asn2_default() -> Self {
        Self::new(
            false,
            MultipleLabelsMap::default(),
            AddPathMap::default(),
            true,
            true,
            true,
            true,
        )
    }

    pub const fn asn4(&self) -> bool {
        self.asn4
    }

    pub fn set_asn4(&mut self, value: bool) {
        self.asn4 = value
    }

    pub const fn multiple_labels(&self) -> &MultipleLabelsMap {
        &self.multiple_labels
    }

    pub fn multiple_labels_mut(&mut self) -> &mut MultipleLabelsMap {
        &mut self.multiple_labels
    }

    /// Negotiated ADD-PATH settings from the local OPEN's perspective.
    pub const fn add_path(&self) -> &AddPathMap {
        &self.add_path
    }

    pub fn add_path_mut(&mut self) -> &mut AddPathMap {
        &mut self.add_path
    }

    /// Set ADD-PATH values for each address family, merging duplicate entries
    /// so a direction is enabled if any duplicate enables it.
    pub fn update_add_path(&mut self, add_path: &AddPathCapability) {
        let support = AddPathMap::from_iter(add_path.address_families().iter().copied());
        for address_family in add_path.address_families() {
            let address_type = address_family.address_type();
            self.add_path.insert(AddPathAddressFamily::new(
                address_type,
                support.add_path_enabled(address_type, MessageDirection::Outbound),
                support.add_path_enabled(address_type, MessageDirection::Inbound),
            ));
        }
    }

    /// Store a Multiple Labels capability limit for messages in `direction`.
    #[inline]
    pub fn update_multiple_label_capability(
        &mut self,
        multiple_label: &MultipleLabel,
        direction: MessageDirection,
    ) {
        let limits = self
            .multiple_labels
            .0
            .entry(multiple_label.address_type())
            .or_insert(MultipleLabelsLimits::new(
                MultipleLabelsMap::DEFAULT_LIMIT,
                MultipleLabelsMap::DEFAULT_LIMIT,
            ));
        match direction {
            MessageDirection::Inbound => limits.inbound = multiple_label.count(),
            MessageDirection::Outbound => limits.outbound = multiple_label.count(),
        };
    }

    /// Receiver label limit for `address_type` for `direction`.
    #[inline]
    pub fn multiple_labels_limit(
        &self,
        address_type: AddressType,
        direction: MessageDirection,
    ) -> u8 {
        self.multiple_labels
            .multiple_labels_limit(address_type, direction)
    }

    /// Whether ADD-PATH applies to `address_type` for `direction`.
    #[inline]
    pub fn add_path_enabled(&self, address_type: AddressType, direction: MessageDirection) -> bool {
        self.add_path.add_path_enabled(address_type, direction)
    }

    /// Store capability settings, including both ADD-PATH directions from
    /// the local OPEN's perspective. Multiple Labels limits are stored for
    /// `direction`.
    #[inline]
    pub fn update_capabilities(&mut self, capability: &BgpCapability, direction: MessageDirection) {
        match capability {
            BgpCapability::AddPath(add_path) => self.update_add_path(add_path),
            BgpCapability::MultipleLabels(multiple_labels) => {
                let mut seen = HashSet::new();
                for multiple_label in multiple_labels.labels() {
                    if seen.insert(multiple_label.address_type()) {
                        self.update_multiple_label_capability(multiple_label, direction);
                    }
                }
            }
            _ => {}
        }
    }

    pub const fn fail_on_non_unicast_withdraw_nlri(&self) -> bool {
        self.fail_on_non_unicast_withdraw_nlri
    }

    pub const fn fail_on_non_unicast_update_nlri(&self) -> bool {
        self.fail_on_non_unicast_update_nlri
    }

    pub const fn fail_on_capability_error(&self) -> bool {
        self.fail_on_capability_error
    }

    pub const fn fail_on_malformed_path_attr(&self) -> bool {
        self.fail_on_malformed_path_attr
    }

    pub const fn parsing_errors(&self) -> &BgpParsingIgnoredErrors {
        &self.parsing_errors
    }

    // Move out existing parsing errors and replace it with a new empty instant
    pub fn reset_parsing_errors(&mut self) -> BgpParsingIgnoredErrors {
        std::mem::take(&mut self.parsing_errors)
    }
}

impl Default for BgpParsingContext {
    fn default() -> Self {
        Self::new(
            true,
            MultipleLabelsMap::default(),
            AddPathMap::default(),
            true,
            true,
            true,
            true,
        )
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv4PrefixParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidIpv4PrefixLen(u8),
}

impl<'a> ReadablePdu<'a, LocatedIpv4PrefixParsingError<'a>> for Ipv4Net {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv4PrefixParsingError<'a>> {
        let input = buf;
        let (buf, prefix_len) = be_u8(buf)?;
        <Self as ReadablePduWithTwoInputs<u8, Span<'_>, LocatedIpv4PrefixParsingError<'_>>>::from_wire(
            buf, prefix_len, input
        )
    }
}

impl<'a> ReadablePduWithTwoInputs<'a, u8, Span<'a>, LocatedIpv4PrefixParsingError<'a>> for Ipv4Net {
    /// A second version that assumes the prefix length has been read else where
    /// in the message Useful for Labeled VPN NLRI
    fn from_wire(
        buf: Span<'a>,
        prefix_len: u8,
        prefix_location: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedIpv4PrefixParsingError<'a>> {
        // The prefix value must fall into the octet boundary,
        // even if the prefix_len doesn't. For example,
        // prefix_len=24 => prefix_size=24 while prefix_len=19 => prefix_size=24
        let prefix_size = if prefix_len >= u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        let (buf, prefix) = nom::bytes::complete::take(prefix_size.min(4))(buf)?;
        // Fill the rest of bits with zeros if
        let mut network = [0; 4];
        prefix.iter().enumerate().for_each(|(i, v)| network[i] = *v);
        let addr = Ipv4Addr::from(network);

        match Ipv4Net::new(addr, prefix_len) {
            Ok(net) => Ok((buf, net)),
            Err(_) => Err(nom::Err::Error(LocatedIpv4PrefixParsingError::new(
                prefix_location,
                Ipv4PrefixParsingError::InvalidIpv4PrefixLen(prefix_len),
            ))),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Ipv6PrefixParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidIpv6PrefixLen(u8),
}

impl<'a> ReadablePdu<'a, LocatedIpv6PrefixParsingError<'a>> for Ipv6Net {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpv6PrefixParsingError<'a>> {
        let input = buf;
        let (buf, prefix_len) = be_u8(buf)?;
        <Self as ReadablePduWithTwoInputs<u8, Span<'_>, LocatedIpv6PrefixParsingError<'_>>>::from_wire(
            buf, prefix_len, input
        )
    }
}

impl<'a> ReadablePduWithTwoInputs<'a, u8, Span<'a>, LocatedIpv6PrefixParsingError<'a>> for Ipv6Net {
    fn from_wire(
        buf: Span<'a>,
        prefix_len: u8,
        prefix_location: Span<'a>,
    ) -> IResult<Span<'a>, Self, LocatedIpv6PrefixParsingError<'a>> {
        // The prefix value must fall into the octet boundary,
        // even if the prefix_len doesn't. For example,
        // prefix_len=24 => prefix_size=24 while prefix_len=19 => prefix_size=24
        let prefix_size = if prefix_len >= u8::MAX - 7 {
            u8::MAX
        } else {
            prefix_len.div_ceil(8)
        };
        let (buf, prefix) = nom::bytes::complete::take(prefix_size.min(16))(buf)?;
        // Fill the rest of bits with zeros if
        let mut network = [0; 16];
        prefix.iter().enumerate().for_each(|(i, v)| network[i] = *v);
        let addr = Ipv6Addr::from(network);

        match Ipv6Net::new(addr, prefix_len) {
            Ok(net) => Ok((buf, net)),
            Err(_) => Err(nom::Err::Error(LocatedIpv6PrefixParsingError::new(
                prefix_location,
                Ipv6PrefixParsingError::InvalidIpv6PrefixLen(prefix_len),
            ))),
        }
    }
}

#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum IpAddrParsingError {
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),
    InvalidIpAddressType(u8),
    InvalidIpAddressLength(u8),
}

impl<'a> ReadablePdu<'a, LocatedIpAddrParsingError<'a>> for IpAddr {
    fn from_wire(buf: Span<'a>) -> IResult<Span<'a>, Self, LocatedIpAddrParsingError<'a>> {
        let input = buf;
        let (buf, ip_len) = be_u8(buf)?;
        let (buf, addr) = match ip_len {
            IPV4_LEN => {
                let (mp_buf, addr) = be_u32(buf)?;
                (mp_buf, IpAddr::V4(Ipv4Addr::from(addr)))
            }
            IPV6_LEN => {
                let (mp_buf, addr) = be_u128(buf)?;
                (mp_buf, IpAddr::V6(Ipv6Addr::from(addr)))
            }
            _ => {
                return Err(nom::Err::Error(LocatedIpAddrParsingError::new(
                    input,
                    IpAddrParsingError::InvalidIpAddressType(ip_len),
                )));
            }
        };
        Ok((buf, addr))
    }
}

/// BGP Message Parsing errors
#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpMessageParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),

    /// The first 16-bytes of a BGP message is NOT all set to `1`
    /// For simplicity, we carry the equivalent [`u128`] value that was invalid
    /// instead of the whole buffer
    ConnectionNotSynchronized(u128),

    /// Couldn't recognize the type octet in the BGPMessage, see
    /// [UndefinedBgpMessageType]
    UndefinedBgpMessageType(#[from_external] UndefinedBgpMessageType),

    /// BGP Message length is not in the defined \[min, max\] range for the
    /// given message type
    BadMessageLength(u16),

    BgpOpenMessageParsingError(
        #[from_located(module = "crate::wire::deserializer::open")] BgpOpenMessageParsingError,
    ),

    BgpUpdateMessageParsingError(
        #[from_located(module = "crate::wire::deserializer::update")] BgpUpdateMessageParsingError,
    ),

    BgpNotificationMessageParsingError(
        #[from_located(module = "crate::wire::deserializer::notification")]
        BgpNotificationMessageParsingError,
    ),

    BgpRouteRefreshMessageParsingError(
        #[from_located(module = "crate::wire::deserializer::route_refresh")]
        BgpRouteRefreshMessageParsingError,
    ),
}

/// Smaller error variant of BgpMessageParsingError for small stack allocations
/// in parse_bgp_message_length_and_type
#[derive(LocatedError, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum BgpMessageOpenAndLengthParsingError {
    /// Errors triggered by the nom parser, see [ErrorKind] for
    /// additional information.
    #[serde(with = "ErrorKindSerdeDeref")]
    NomError(#[from_nom] ErrorKind),

    /// Couldn't recognize the type octet in the BGPMessage, see
    /// [UndefinedBgpMessageType]
    UndefinedBgpMessageType(#[from_external] UndefinedBgpMessageType),

    /// BGP Message length is not in the defined \[min, max\] range for the
    /// given message type
    BadMessageLength(u16),
}

#[inline]
fn into_located_bgp_message_parsing_error(
    value: nom::Err<LocatedBgpMessageOpenAndLengthParsingError<'_>>,
) -> nom::Err<LocatedBgpMessageParsingError<'_>> {
    #[inline]
    fn convert(
        inner_error: LocatedBgpMessageOpenAndLengthParsingError<'_>,
    ) -> LocatedBgpMessageParsingError<'_> {
        LocatedBgpMessageParsingError::new(
            inner_error.span,
            match inner_error.error {
                BgpMessageOpenAndLengthParsingError::NomError(val) => {
                    BgpMessageParsingError::NomError(val)
                }
                BgpMessageOpenAndLengthParsingError::UndefinedBgpMessageType(val) => {
                    BgpMessageParsingError::UndefinedBgpMessageType(val)
                }
                BgpMessageOpenAndLengthParsingError::BadMessageLength(val) => {
                    BgpMessageParsingError::BadMessageLength(val)
                }
            },
        )
    }

    match value {
        nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
        nom::Err::Error(value) => nom::Err::Error(convert(value)),
        nom::Err::Failure(value) => nom::Err::Failure(convert(value)),
    }
}

/// Parse [`BgpMessage`] length and type, then check that the length of a BGP
/// message is valid according to it's type. Takes into consideration both rules at [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
/// and [RFC8654 Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654).
#[inline]
fn parse_bgp_message_length_and_type(
    buf: Span<'_>,
) -> IResult<
    Span<'_>,
    (u16, BgpMessageType, Span<'_>),
    LocatedBgpMessageOpenAndLengthParsingError<'_>,
> {
    let pre_len_buf = buf;
    let (buf, length) = be_u16(buf)?;

    // Fail early if the message length is not valid
    if length < BGP_MIN_MESSAGE_LENGTH {
        return Err(nom::Err::Error(
            LocatedBgpMessageOpenAndLengthParsingError::new(
                pre_len_buf,
                BgpMessageOpenAndLengthParsingError::BadMessageLength(length),
            ),
        ));
    }

    // Only read the subset that is defined by the length
    // Check the message size before doing any math on it
    let remainder_result = nom::bytes::complete::take::<
        u16,
        Span<'_>,
        LocatedBgpMessageParsingError<'_>,
    >(length - 18)(buf);
    let (remainder_buf, buf) = match remainder_result {
        Ok((remainder_buf, buf)) => (remainder_buf, buf),
        Err(_) => {
            return Err(nom::Err::Error(
                LocatedBgpMessageOpenAndLengthParsingError::new(
                    pre_len_buf,
                    BgpMessageOpenAndLengthParsingError::BadMessageLength(length),
                ),
            ));
        }
    };
    let (buf, message_type) = nom::combinator::map_res(be_u8, BgpMessageType::try_from)(buf)?;

    match message_type {
        BgpMessageType::Open | BgpMessageType::KeepAlive => {
            if !(BGP_MIN_MESSAGE_LENGTH..=BGP_MAX_MESSAGE_LENGTH).contains(&length) {
                return Err(nom::Err::Error(
                    LocatedBgpMessageOpenAndLengthParsingError::new(
                        pre_len_buf,
                        BgpMessageOpenAndLengthParsingError::BadMessageLength(length),
                    ),
                ));
            }
        }
        BgpMessageType::Update | BgpMessageType::Notification | BgpMessageType::RouteRefresh => {}
    }
    Ok((buf, (length, message_type, remainder_buf)))
}

/// Parse a BGP message without an explicit direction, defaulting to inbound.
impl<'a> ReadablePduWithOneInput<'a, &mut BgpParsingContext, LocatedBgpMessageParsingError<'a>>
    for BgpMessage
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BgpParsingContext,
    ) -> IResult<Span<'a>, Self, LocatedBgpMessageParsingError<'a>> {
        <Self as ReadablePduWithTwoInputs<_, _, _>>::from_wire(buf, ctx, MessageDirection::Inbound)
    }
}

impl<'a>
    ReadablePduWithTwoInputs<
        'a,
        &mut BgpParsingContext,
        MessageDirection,
        LocatedBgpMessageParsingError<'a>,
    > for BgpMessage
{
    fn from_wire(
        buf: Span<'a>,
        ctx: &mut BgpParsingContext,
        direction: MessageDirection,
    ) -> IResult<Span<'a>, Self, LocatedBgpMessageParsingError<'a>> {
        let (buf, _) = nom::combinator::map_res(be_u128, |x| {
            if x == u128::MAX {
                Ok(x)
            } else {
                Err(BgpMessageParsingError::ConnectionNotSynchronized(x))
            }
        })(buf)?;

        // Parse both length and type together, since we need to do input
        // validation on the length based on the type of the message
        let (buf, (_, message_type, remainder_buf)) = match parse_bgp_message_length_and_type(buf) {
            Ok(value) => value,
            Err(err) => return Err(into_located_bgp_message_parsing_error(err)),
        };
        let (buf, msg) = match message_type {
            BgpMessageType::Open => {
                let (buf, open) = parse_into_located_one_input(buf, ctx)?;
                (buf, BgpMessage::Open(open))
            }
            BgpMessageType::Update => {
                let (buf, update) = parse_into_located_two_inputs(buf, ctx, direction)?;
                (buf, BgpMessage::Update(update))
            }
            BgpMessageType::Notification => {
                let (buf, notification) = parse_into_located(buf)?;
                (buf, BgpMessage::Notification(notification))
            }
            BgpMessageType::KeepAlive => (buf, BgpMessage::KeepAlive),
            BgpMessageType::RouteRefresh => {
                let (buf, route_refresh) = parse_into_located(buf)?;
                (buf, BgpMessage::RouteRefresh(route_refresh))
            }
        };

        // Make sure we consumed the full BGP message as specified by its length
        if !buf.is_empty() {
            return Err(nom::Err::Error(LocatedBgpMessageParsingError::new(
                buf,
                BgpMessageParsingError::NomError(ErrorKind::NonEmpty),
            )));
        }
        Ok((remainder_buf, msg))
    }
}

impl From<BgpMessageParsingError> for BgpNotificationMessage {
    fn from(value: BgpMessageParsingError) -> Self {
        match value {
            BgpMessageParsingError::NomError(_) => {
                // TODO: more detailed error
                BgpNotificationMessage::MessageHeaderError(MessageHeaderError::Unspecific {
                    value: vec![],
                })
            }
            BgpMessageParsingError::ConnectionNotSynchronized(header) => {
                BgpNotificationMessage::MessageHeaderError(
                    MessageHeaderError::ConnectionNotSynchronized {
                        value: header.to_be_bytes().to_vec(),
                    },
                )
            }
            BgpMessageParsingError::UndefinedBgpMessageType(msg_type) => {
                BgpNotificationMessage::MessageHeaderError(MessageHeaderError::BadMessageType {
                    value: msg_type.0.to_be_bytes().to_vec(),
                })
            }
            BgpMessageParsingError::BadMessageLength(bad_length) => {
                BgpNotificationMessage::MessageHeaderError(MessageHeaderError::BadMessageLength {
                    value: bad_length.to_be_bytes().to_vec(),
                })
            }
            BgpMessageParsingError::BgpOpenMessageParsingError(open_err) => {
                BgpNotificationMessage::OpenMessageError(open_err.into())
            }
            BgpMessageParsingError::BgpUpdateMessageParsingError(update_err) => {
                BgpNotificationMessage::UpdateMessageError(update_err.into())
            }
            BgpMessageParsingError::BgpNotificationMessageParsingError(_notification) => {
                // Notification messages parsing should be ignored
                // and consider a session closed.
                BgpNotificationMessage::FiniteStateMachineError(
                    FiniteStateMachineError::Unspecific { value: vec![] },
                )
            }
            BgpMessageParsingError::BgpRouteRefreshMessageParsingError(route_refresh_error) => {
                BgpNotificationMessage::RouteRefreshError(route_refresh_error.into())
            }
        }
    }
}

#[inline]
pub fn read_tlv_header_t16_l16<'a, E, T>(buf: Span<'a>) -> Result<(u16, u16, Span<'a>, Span<'a>), E>
where
    E: From<nom::Err<T>>,
    T: nom::error::ParseError<netcalyx_locate::BinarySpan<&'a [u8]>>,
{
    let (span, tlv_type) = be_u16(buf)?;
    let (span, tlv_length) = be_u16(span)?;
    let (remainder, data) = nom::bytes::complete::take(tlv_length)(span)?;

    Ok((tlv_type, tlv_length, data, remainder))
}

#[inline]
pub fn read_tlv_header_t8_l16<'a, E, T>(buf: Span<'a>) -> Result<(u8, u16, Span<'a>, Span<'a>), E>
where
    E: From<nom::Err<T>>,
    T: nom::error::ParseError<netcalyx_locate::BinarySpan<&'a [u8]>>,
{
    let (span, tlv_type) = be_u8(buf)?;
    let (span, tlv_length) = be_u16(span)?;
    let (remainder, data) = nom::bytes::complete::take(tlv_length)(span)?;

    Ok((tlv_type, tlv_length, data, remainder))
}
