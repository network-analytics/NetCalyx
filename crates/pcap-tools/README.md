# NetCalyx PCAP Tools

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Apache licensed][apache-badge]][apache-url]

[crates-badge]: https://img.shields.io/crates/v/netcalyx-pcap-tools.svg

[crates-url]: https://crates.io/crates/netcalyx-pcap-tools

[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg

[apache-url]: https://github.com/network-analytics/NetCalyx/blob/main/LICENSE

[docs-badge]: https://docs.rs/netcalyx-pcap-tools/badge.svg

[docs-url]: https://docs.rs/netcalyx-pcap-tools

Assorted CLI utilities to manipulate PCAP files containing network telemetry protocols.

```bash
cargo run -p netcalyx-pcap-tools -- --help
```

## `bmp-split`

Rewrites a BMP capture so that every TCP segment carries exactly one BMP message (useful when the exporter packs
multiple messages per segment or splits a message across segments).

```bash
netcalyx-pcap-tools bmp-split --help
netcalyx-pcap-tools bmp-split --input in.pcap --output out.pcap --ports 1790 [--validate]
```

- Input can be PCAP or PCAPNG (Enhanced Packet Blocks), output is legacy PCAP (microsecond timestamps).
- Only TCP packets towards `--ports` with payload are kept, all other frames are dropped.
- The destination port of the output packets is rewritten to 1790 (BMP default), override with `--rewrite-port`.
- Each new segment reuses the link/IP/TCP headers and the timestamp of the frame that completed the message; IP length,
  TCP sequence number and checksums are recomputed so the stream is still reassembled correctly by Wireshark.
- Messages larger than a single IP packet are spread over multiple segments.
- Control segments without payload (handshake, teardown) are dropped and SYN/FIN/RST flags are cleared on the
  generated segments, so the output is a plain data stream.
- Input and output must be different files.
- TCP streams are reassembled by sequence number: retransmissions and duplicates (e.g., the same packet captured on
  multiple interfaces with `-i any`) are dropped and out-of-order segments are reordered. A SYN restarts reassembly
  of its four-tuple, so reconnections reusing the same source port are handled if their handshake is captured.
- `--validate` decodes every message with the NetCalyx BMP parser and reports failures.

## Adding a new command

1. Create `src/commands/<name>.rs` with a `#[derive(clap::Args)]` struct holding the command options and a
   `run(self) -> ExitCode` method.
2. Declare the module in [`src/commands/mod.rs`](src/commands/mod.rs), add a variant to `Command` (its doc comment
   becomes the `--help` text) and dispatch to it in `Command::run`.
3. Put reusable logic in the library (`src/lib.rs` modules, e.g. `tcp_split`, `writer`) so it can be tested and shared;
   keep the command module limited to CLI parsing and reporting.
4. Document the command in this README.
