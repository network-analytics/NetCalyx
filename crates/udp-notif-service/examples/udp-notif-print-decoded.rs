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

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use futures_util::stream::SplitSink;
use netcalyx_parse_utils::{ReadablePdu, Span};
use netcalyx_udp_notif_pkt::codec::UdpPacketCodec;
use netcalyx_udp_notif_pkt::decoded::UdpNotifPacketDecoded;
use netcalyx_udp_notif_pkt::raw::{UdpNotifOption, UdpNotifOptionCode, UdpNotifPacket};
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio_util::codec::{BytesCodec, Decoder};
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, info, warn};

fn init_tracing() {
    // Delegate filtering entirely to RUST_LOG so callers can set any level,
    // including TRACE, without recompiling.
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

/// Peek at the raw bytes to extract segment metadata without consuming the
/// buffer. Returns `(publisher_id, message_id, segment_number, is_last)` only
/// when a `Segment` option is present, i.e. the datagram is part of a segmented
/// message. Returns `None` for unsegmented packets or if the header cannot be
/// parsed.
fn peek_segment_info(buf: &BytesMut) -> Option<(u32, u32, u16, bool)> {
    let (_, pkt) = UdpNotifPacket::from_wire(Span::new(buf.as_ref())).ok()?;
    let (seg_no, is_last) = pkt
        .options()
        .get(&UdpNotifOptionCode::Segment)
        .and_then(|opt| {
            if let UdpNotifOption::Segment { number, last } = opt {
                Some((*number, *last))
            } else {
                None
            }
        })?;
    Some((pkt.publisher_id(), pkt.message_id(), seg_no, is_last))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    init_tracing();
    let listen_addr = "0.0.0.0:9999";
    let socket = UdpSocket::bind(&listen_addr).await?;
    info!("listening on addr: {}", listen_addr);

    let framed = UdpFramed::new(socket, BytesCodec::default());
    let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
    // Per-client codec state.
    let mut clients: HashMap<_, UdpPacketCodec> = HashMap::new();
    // Per-client reassembly progress: (publisher_id, message_id) -> segments
    // received so far.
    let mut pending: HashMap<_, HashMap<(u32, u32), u32>> = HashMap::new();

    while let Some(next) = stream.next().await {
        match next {
            Ok((mut buf, addr)) => {
                // Peek at segment metadata — we'll use this after draining
                // codec events so that eviction cleanup runs
                // before we increment the pending counter.
                let seg_info = peek_segment_info(&buf);

                // If we haven't seen the client before, create a new
                // UdpPacketCodec for it. UdpPacketCodec handles
                // the decoding/encoding of udp-notif packets.
                let codec = clients.entry(addr).or_default();
                let result = codec.decode(&mut buf);

                // Drain reassembly event counts and log any anomalies with peer
                // context.
                let reassembly_events = codec.take_reassembly_events();
                if reassembly_events.timeout_evictions > 0 {
                    warn!(
                        %addr,
                        evicted = reassembly_events.timeout_evictions,
                        "evicted timed-out reassembly buffers"
                    );
                    // We don't know which (publisher_id, message_id) keys
                    // were evicted, so clear all pending state for this peer
                    // to avoid stale counts.
                    pending.remove(&addr);
                }
                if reassembly_events.duplicate_drops > 0 {
                    warn!(
                        %addr,
                        dropped = reassembly_events.duplicate_drops,
                        "dropped duplicate segments"
                    );
                }

                // Now that stale pending state has been cleared, update
                // the counter for the segment that was just processed.
                if let Some((pub_id, msg_id, seg_no, is_last)) = seg_info {
                    let received = pending
                        .entry(addr)
                        .or_default()
                        .entry((pub_id, msg_id))
                        .or_insert(0);
                    *received += 1;
                    info!(
                        %addr,
                        publisher_id = pub_id,
                        message_id = msg_id,
                        segment = seg_no,
                        is_last,
                        received_so_far = *received,
                        "segment received"
                    );
                }

                match result {
                    Ok(Some(msg)) => {
                        let pub_id = msg.publisher_id();
                        let msg_id = msg.message_id();
                        // Always clean up the pending counter using the
                        // message's own IDs, regardless of seg_info. This
                        // handles the case where the reassembly-triggering
                        // segment had no Segment option (e.g. a single-segment
                        // retransmission after a prior segmented run timed
                        // out).
                        if let Some(total) = pending
                            .get_mut(&addr)
                            .and_then(|m| m.remove(&(pub_id, msg_id)))
                        {
                            info!(
                                %addr,
                                publisher_id = pub_id,
                                message_id = msg_id,
                                total_segments = total,
                                "reassembly complete"
                            );
                        }
                        match UdpNotifPacketDecoded::try_from(&msg) {
                            Ok(decoded) => match serde_json::to_string(&decoded) {
                                Ok(json) => println!("{json}"),
                                Err(err) => {
                                    error!(%addr, error = %err, "failed to serialize decoded packet to JSON");
                                    debug!(%addr, packet = ?decoded, "packet that failed to serialize");
                                }
                            },
                            Err(err) => {
                                error!(%addr, error = %err, "failed to decode UDP-Notif payload");
                            }
                        }
                    }
                    Ok(None) => {
                        if let Some((pub_id, msg_id, seg_no, _)) = seg_info {
                            let received = pending
                                .get(&addr)
                                .and_then(|m| m.get(&(pub_id, msg_id)))
                                .copied()
                                .unwrap_or(0);
                            warn!(
                                %addr,
                                publisher_id = pub_id,
                                message_id = msg_id,
                                segment = seg_no,
                                received,
                                "waiting for more segments"
                            );
                        } else {
                            info!("message incomplete or too short to decode")
                        }
                    }
                    Err(err) => {
                        if let Some((pub_id, msg_id, _, _)) = seg_info {
                            pending.get_mut(&addr).map(|m| m.remove(&(pub_id, msg_id)));
                            error!(
                                %addr,
                                publisher_id = pub_id,
                                message_id = msg_id,
                                error = %err,
                                "error decoding or reassembling packet"
                            );
                        } else {
                            error!(%addr, "error decoding packet: {:?}", err);
                        }
                    }
                }
            }
            Err(err) => {
                error!("error getting next packet: {:?}, exiting", err);
                return Ok(());
            }
        }
    }
    Ok(())
}
