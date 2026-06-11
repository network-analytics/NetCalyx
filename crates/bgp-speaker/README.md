# BGP Speaker Library

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netcalyx-bgp-speaker.svg

[crates-url]: https://crates.io/crates/netcalyx-bgp-speaker

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/network-analytics/NetCalyx/blob/main/LICENSE

[docs-badge]: https://docs.rs/netcalyx-bgp-speaker/badge.svg

[docs-url]: https://docs.rs/netcalyx-bgp-speaker


Handle BGP connection and FSM machine and generate a stream of (FSM state, BGP Event).

### Example: Listener that logs incoming messages

```cargo run --example log_listener -- 600 192.168.56.1```