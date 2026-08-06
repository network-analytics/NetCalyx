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

use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::stream::SplitSink;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio_util::codec::{BytesCodec, Decoder};
use tokio_util::udp::UdpFramed;
use tracing::{debug, error, info};

use netcalyx_udp_notif_pkt::codec::UdpPacketCodec;

fn init_tracing() {
    // Delegate filtering entirely to RUST_LOG so callers can set any level,
    // including TRACE, without recompiling.
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    init_tracing();
    let listen_addr = "0.0.0.0:9999";
    let socket = UdpSocket::bind(&listen_addr).await?;
    info!("listening on addr: {}", listen_addr);

    let framed = UdpFramed::new(socket, BytesCodec::default());
    let (_tx, mut stream): (SplitSink<_, (Bytes, _)>, _) = framed.split();
    let mut clients = HashMap::new();
    while let Some(next) = stream.next().await {
        match next {
            Ok((mut buf, addr)) => {
                // If we haven't seen the client before, create a new UdpPacketCodec for it.
                // UdpPacketCodec handles the decoding/encoding of udp-notif packets.
                let result = clients
                    .entry(addr)
                    .or_insert(UdpPacketCodec::default())
                    .decode(&mut buf);
                match result {
                    Ok(Some(msg)) => match serde_json::to_string(&msg) {
                        Ok(json) => println!("{json}"),
                        Err(err) => {
                            error!(%addr, error = %err, "failed to serialize packet to JSON");
                            debug!(%addr, packet = ?msg, "packet that failed to serialize");
                        }
                    },
                    Ok(None) => info!("message incomplete or too short to decode"),
                    Err(err) => error!("error decoding packet: {:?}", err),
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
