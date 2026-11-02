// Copyright (C) 2026-present The NetCalyx Authors.
// Copyright (C) 2025-present The NetGauze Authors.
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

//! Validation actor event loop and its public handle.

use crate::cache::actor::{CacheLookupCommand, CacheResponse};
use crate::validation::processing::ValidatedNotification;
use crate::validation::state::CachedPeerSubscriptions;
use crate::validation::stats::ValidationStats;
use netcalyx_udp_notif_service::UdpNotifRequest;
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq, strum_macros::Display)]
pub enum ValidationActorError {
    #[strum(serialize = "Failed to send cache lookup command")]
    CacheLookupSendError,
    #[strum(serialize = "Failed to receive cache response")]
    CacheResponseReceiveError,
    #[strum(serialize = "Failed to send the decoded UDP-Notif packet")]
    SendError,
}

impl std::error::Error for ValidationActorError {}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ValidationActorCommand {
    Shutdown,
}

pub(crate) struct ValidationActor {
    pub(crate) max_buffered_packets_per_peer: usize,
    pub(crate) max_buffered_packets_per_subscription: usize,
    /// Whether `anydata` nodes are validated strictly against their
    /// schema (see `yang5::data::DataParserFlags::ANYDATA_STRICT`).
    pub(crate) anydata_strict: bool,
    pub(crate) peer_cache: FxHashMap<IpAddr, CachedPeerSubscriptions>,
    pub(crate) cmd_rx: mpsc::Receiver<ValidationActorCommand>,
    pub(crate) rx: async_channel::Receiver<Arc<UdpNotifRequest>>,
    pub(crate) tx: async_channel::Sender<ValidatedNotification>,
    pub(crate) cache_cmd_tx: async_channel::Sender<CacheLookupCommand>,
    pub(crate) cache_tx: async_channel::Sender<CacheResponse>,
    pub(crate) cache_rx: async_channel::Receiver<CacheResponse>,
    /// Packets buffered while their subscription waits for schemas to arrive,
    /// then drained in pending_packets once the cache responds. They are
    /// processed one at a time.
    pub(crate) pending_packets: VecDeque<Arc<UdpNotifRequest>>,
    pub(crate) stats: ValidationStats,
}

impl ValidationActor {
    /// Actor event loop. Runs until a shutdown command is received or a
    /// fatal channel error occurs.
    async fn run(mut self) -> Result<String, ValidationActorError> {
        info!("Starting YANG-Push validation actor");
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(ValidationActorCommand::Shutdown) => {
                            info!("Shutting down YANG-Push validation actor");
                            Ok("Enrichment shutdown successfully".to_string())
                        }
                        None => {
                            let msg = "YANG-Push validation actor terminated due to command channel closing";
                            warn!(msg);
                            Ok(msg.to_string())
                        }
                    }
                }
                msg = self.cache_rx.recv() => {
                    match msg {
                        Ok(response) => {
                            if let Err(err) = self.process_cache_response(response) {
                                let err_msg = "YANG-Push validation actor cache response processing unrecoverable error, shutting down";
                                warn!(error=%err, err_msg);
                                return Ok(err_msg.to_string());
                            }
                        }
                        Err(error) => {
                            let err_msg = "YANG-Push validation actor cache receiver channel closed unexpectedly, shutting down";
                            warn!(error=%error, err_msg);
                            return Ok(err_msg.to_string());
                        }
                    }
                }
                Some(message) = async { self.pending_packets.pop_front() }, if !self.pending_packets.is_empty() => {
                    self.stats
                        .pending
                        .record(self.pending_packets.len() as u64, &[]);
                    if let Err(err) = self.process_udp_notif_msg(message, true).await {
                        let err_msg = "YANG-Push validation actor buffered packet processing unrecoverable error, shutting down";
                        warn!(error=%err, err_msg);
                        return Ok(err_msg.to_string());
                    }
                }
                msg = self.rx.recv() => {
                    match msg {
                        Ok(msg) => {
                            self.stats.received.add(
                                1,
                                &Self::peer_tags_from_packet(
                                    msg.peer_address(),
                                    msg.packet(),
                                ),
                            );
                            if let Err(err) = self.process_udp_notif_msg(msg, false).await {
                                let err_msg = "YANG-Push validation actor UDP-Notif processing unrecoverable error, shutting down";
                                warn!(error=%err, err_msg);
                                return Ok(err_msg.to_string());
                            }
                        }
                        Err(error) => {
                            let err_msg = "YANG-Push validation actor UDP Notif receiver channel closed unexpectedly, shutting down";
                            warn!(error=%error, err_msg);
                            return Ok(err_msg.to_string());
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, strum_macros::Display)]
pub enum ValidationActorHandleError {
    #[strum(serialize = "Failed to send command to actor")]
    SendErr,
}

impl std::error::Error for ValidationActorHandleError {}

#[derive(Debug, Clone)]
pub struct ValidationActorHandle {
    cmd_tx: mpsc::Sender<ValidationActorCommand>,
}

impl ValidationActorHandle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        buffer_size: usize,
        max_buffered_packets_per_peer: usize,
        max_buffered_packets_per_subscription: usize,
        anydata_strict: bool,
        rx: async_channel::Receiver<Arc<UdpNotifRequest>>,
        tx: async_channel::Sender<ValidatedNotification>,
        cache_cmd_tx: async_channel::Sender<CacheLookupCommand>,
        stats: either::Either<opentelemetry::metrics::Meter, ValidationStats>,
    ) -> Result<
        (
            tokio::task::JoinHandle<Result<String, ValidationActorError>>,
            Self,
        ),
        ValidationActorHandleError,
    > {
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let (cache_tx, cache_rx) = async_channel::bounded(buffer_size);
        let stats = match stats {
            either::Either::Left(meter) => ValidationStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = ValidationActor {
            max_buffered_packets_per_peer,
            max_buffered_packets_per_subscription,
            anydata_strict,
            peer_cache: FxHashMap::default(),
            cmd_rx,
            rx,
            tx,
            cache_cmd_tx,
            cache_tx,
            cache_rx,
            pending_packets: VecDeque::new(),
            stats,
        };
        let handle = ValidationActorHandle { cmd_tx };
        let join_handle = tokio::spawn(async move { actor.run().await });
        Ok((join_handle, handle))
    }

    pub async fn shutdown(&self) -> Result<(), ValidationActorHandleError> {
        self.cmd_tx
            .send(ValidationActorCommand::Shutdown)
            .await
            .map_err(|_| ValidationActorHandleError::SendErr)
    }
}

#[cfg(test)]
mod tests;
