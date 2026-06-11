# Services to receive IPFIX/Netflow packets

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]


[crates-badge]: https://img.shields.io/crates/v/netcalyx-flow-service.svg

[crates-url]: https://crates.io/crates/netcalyx-flow-service

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/network-analytics/NetCalyx/blob/main/LICENSE

[docs-badge]: https://docs.rs/netcalyx-flow-service/badge.svg

[docs-url]: https://docs.rs/netcalyx-flow-service


Building blocks to develop IPFIX/Netflow collectors.
See [print-flow](examples/print-flow.rs) for a simple code to receive IPFIX and Netflow packets from the network.

## Run example

Simple server that will listen to IPFIX/Netflow V9 UDP packets. It handles decoding packets according the template map
per client and print them out to the console.

``` cargo run --example print-flow```