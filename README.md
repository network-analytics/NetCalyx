# NetCalyx

[<img alt="github" src="https://img.shields.io/badge/github-netcalyx/netcalyx-8da0cb??style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/network-analytics/NetCalyx)

> **NetCalyx** is a fork of [NetGauze](https://github.com/NetGauze/NetGauze),
> licensed under Apache-2.0. See [NOTICE](NOTICE) for attribution and
> [AUTHORS](AUTHORS) for the author list.

NetCalyx is a set of Rust libraries and programs for network monitoring, telemetry collection, and protocol analysis. It
provides high-performance, type-safe packet parsing and serialization for key network protocols, along with a
network telemetry collector daemon that can be used to collect and process telemetry data from multiple sources.

NetCalyx leverages Rust's type system to ensure protocol correctness at compile time when possible — packets are
represented as rich, immutable data structures where invalid states are unrepresentable.

## Protocol Libraries

### BGP

- Packet representation and wire format serialization/deserialization: [`netcalyx-bgp-pkt`](crates/bgp-pkt/README.md)
- BGP Speaker with connection management and fine-state-machine (FSM): [
  `netcalyx-bgp-speaker`](crates/bgp-speaker/README.md)

Supports BGP-4, MP-BGP (IPv4/IPv6 Unicast & Multicast, MPLS VPN, EVPN, BGP-LS), 4-octet ASN, Add-Path, Route Refresh,
Extended Messages, and communities (standard, extended, large).

### BMP

- Packet representation and wire format serialization/deserialization: [`netcalyx-bmp-pkt`](crates/bmp-pkt/README.md)
- Support for BMP v3 and v4, including all message types and peer states.
- Service building block for receiving BMP messages: [`netcalyx-bmp-service`](crates/bmp-service/README.md)

### IPFIX and NetFlow V9

- Packet representation and wire format serialization/deserialization: [`netcalyx-flow-pkt`](crates/flow-pkt/README.md)
- Service building block for receiving messages: [`netcalyx-flow-service`](crates/flow-service/README.md)

Includes a code generator for IANA IPFIX Information Elements as well as support for enterprise-specific IEs (e.g.,
VMware, Nokia).

### UDP-Notif

- Packet representation and wire format serialization/deserialization: [
  `netcalyx-udp-notif-pkt`](crates/udp-notif-pkt/README.md)
- Service building block for receiving messages: [`netcalyx-udp-notif-service`](crates/udp-notif-service/README.md)

### YANG-Push

- Data models and YANG validation: [`netcalyx-yang-push`](crates/yang-push/README.md)

### NETCONF

- Protocol types, XML parsing, and SSH client wiring: [`netcalyx-netconf-proto`](crates/netconf-proto/README.md)

## Collector Daemon

[`netcalyx-collector`](crates/collector/README.md) is a network telemetry collector that ties the protocol libraries
together into a deployable service.

**Inputs:** IPFIX/NetFlow V9, UDP-Notif, YANG-Push, and Kafka for enrichment data, while BMP and BGP are currently
work in progress.

**Publishers:** Kafka (Avro, JSON, YANG)

**Features:**

- Flow aggregation and enrichment
- OpenTelemetry metrics export (OTLP)
- jemalloc memory allocator for production workloads
- YAML-based configuration with per-module log filtering
- RPM packaging support

```bash
cargo run -p netcalyx-collector -- /path/to/config.yaml
```

See example configurations in [`crates/collector/`](crates/collector/).

## Tools

### PCAP Decoder

[`netcalyx-pcap-decoder`](crates/pcap-decoder/README.md) — Swiss army knife CLI tool to decode BGP, BMP, IPFIX/NetFlow,
and UDP-Notif from PCAP files into JSON Lines format.

```bash
cargo run -p netcalyx-pcap-decoder -- --protocol bmp --ports 11019 input.pcap -o output.jsonl
```

## Foundational Crates

These crates provide shared infrastructure used across the protocol libraries:

| Crate                                           | Purpose                                                          |
|-------------------------------------------------|------------------------------------------------------------------|
| [`netcalyx-iana`](crates/iana/)                 | IANA registry constants for address families, capabilities, etc. |
| [`netcalyx-parse-utils`](crates/parse-utils/)   | Traits and helpers for nom-based protocol parsing                |
| [`netcalyx-serde-macros`](crates/serde-macros/) | Procedural macros for error location tracking in parsers         |
| [`netcalyx-locate`](crates/locate/)             | Binary span types for tracking byte positions during parsing     |
| [`netcalyx-analytics`](crates/analytics/)       | Analytics and aggregation primitives                             |

## Quick Start

Add the crate you need to your `Cargo.toml`:

```toml
[dependencies]
netcalyx-bgp-pkt = "0.9"
```

Parse a BGP message from bytes:

```rust
use netcalyx_bgp_pkt::BgpMessage;
use netcalyx_bgp_pkt::wire::deserializer::BgpParsingContext;
use netcalyx_parse_utils::{ReadablePduWithOneInput, Span};

let raw: & [u8] = & [ /* BGP message bytes */ ];
let span = Span::new(raw);
let mut ctx = BgpParsingContext::default ();
let (_remaining, message) = BgpMessage::from_wire(span, & mut ctx).unwrap();
```

## Design Principles

NetCalyx follows a consistent architecture across all protocol crates, documented in [
`docs/pdu_serde.md`](docs/pdu_serde.md):

- **Immutable PDUs** — packets are immutable once constructed
- **Enum-driven correctness** — protocol constants are represented as enums so invalid values are caught at compile time
- **Separated concerns** — packet representation (`*-pkt`) is independent of wire format parsing (`wire/`) and service
  integration (`*-service`)
- **Fuzz-tested** — all protocol parsers are continuously fuzzed via `cargo-fuzz`

# Development Documentation

## Running Tests

NetCalyx uses macro tests from the [trybuild](https://crates.io/crates/trybuild) crate and PCAP-based regression tests.

```bash
# Standard test run
cargo test --features=codec

# Regenerate expected macro test output
TRYBUILD=overwrite cargo test

# Regenerate expected PCAP test output
OVERWRITE=true cargo test
```

## Code Formatting and Linting

```bash
cargo +nightly fmt
cargo +nightly clippy --tests -- -Dclippy::all
```

## Running Examples

```bash
# List available examples
ls crates/*/examples

# Run the IPFIX/NetFlow printer
cargo run -p netcalyx-flow-service --example print-flow
```

## Fuzz Testing

```bash
cargo install cargo-fuzz

cargo +nightly fuzz run fuzz-bgp-pkt
cargo +nightly fuzz run fuzz-bgp-pkt-serialize
cargo +nightly fuzz run fuzz-bgp-peer
cargo +nightly fuzz run fuzz-bmp-pkt
cargo +nightly fuzz run fuzz-bmp-pkt-serialize
cargo +nightly fuzz run fuzz-ipfix-pkt
cargo +nightly fuzz run fuzz-netflow-v9-pkt
```

## Building RPMs

```bash
cargo install cargo-generate-rpm
cargo build --release -p netcalyx-collector
strip target/release/netcalyx-collector
cargo generate-rpm -p crates/collector
# Package output: target/generate-rpm/
```

## License

Copyright (C) 2026-present The NetCalyx Authors. All rights reserved.
Copyright (C) 2022-present The NetGauze Authors. All rights reserved.

NetCalyx is licensed under the Apache License, Version 2.0
([LICENSE])(LICENSE) or <http://www.apache.org/licenses/LICENSE-2.0>).
Attribution notices are in [NOTICE](NOTICE).
The author list is in [AUTHORS](AUTHORS).


## Authors

See the [AUTHORS](AUTHORS) file; see also the full
[contributor graph](https://github.com/network-analytics/NetCalyx/graphs/contributors).

NetGauze was created by **Ahmed Elhassany** ([@ahassany](https://github.com/ahassany)),
originally started in 2019 as a BGP library. It has since evolved into a full-fledged
network telemetry toolkit with contributions from many individuals.


## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.

