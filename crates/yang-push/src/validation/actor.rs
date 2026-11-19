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

//! Actor runtime for the validation stage.
//!
//! [`ValidationActor`] only moves data between channels: it feeds incoming
//! packets and cache responses into the [`Validator`] and executes the
//! resulting [`PacketOutcome`]s (forwarding downstream or sending cache
//! lookups).

use crate::cache::actor::{CacheLookupCommand, CacheResponse};
use crate::validation::processing::{
    CacheLookup, PacketOutcome, ValidatedNotification, Validator, notification_type,
};
use crate::validation::stats::{DropReason, ValidationStats, with_reason};
use netcalyx_udp_notif_service::UdpNotifRequest;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

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
enum ValidationActorCommand {
    Shutdown,
}

struct ValidationActor {
    validator: Validator,
    cmd_rx: mpsc::Receiver<ValidationActorCommand>,
    rx: async_channel::Receiver<Arc<UdpNotifRequest>>,
    tx: async_channel::Sender<ValidatedNotification>,
    cache_cmd_tx: async_channel::Sender<CacheLookupCommand>,
    cache_tx: async_channel::Sender<CacheResponse>,
    cache_rx: async_channel::Receiver<CacheResponse>,
}

impl ValidationActor {
    /// Run a packet through the [`Validator`] and execute the outcome.
    async fn process_udp_notif_msg(
        &mut self,
        message: Arc<UdpNotifRequest>,
        is_reprocessed: bool,
    ) -> Result<(), ValidationActorError> {
        match self.validator.process_packet(message, is_reprocessed) {
            PacketOutcome::Forward {
                notification,
                peer_tags,
            } => self.forward(notification, &peer_tags).await,
            PacketOutcome::CacheLookup(lookup) => self.send_cache_lookup(lookup).await,
            PacketOutcome::Consumed => Ok(()),
        }
    }

    /// Forward a validated (or unvalidated) notification to the next actor.
    async fn forward(
        &self,
        notification: ValidatedNotification,
        peer_tags: &[opentelemetry::KeyValue],
    ) -> Result<(), ValidationActorError> {
        let peer = notification.session.peer();
        let message_id = notification.packet.message_id();
        let publisher_id = notification.packet.publisher_id();
        let notification_type = notification_type(&notification.packet);
        let subscription_id = notification.subscription_info.id();
        let router_content_id = notification.subscription_info.content_id().to_string();
        let target = notification.subscription_info.target().to_string();
        let cached_content_id = notification.cached_content_id.clone().unwrap_or_default();

        if self.tx.send(notification).await.is_err() {
            warn!(
                peer=%peer,
                message_id,
                publisher_id,
                subscription_id,
                router_content_id,
                target,
                cached_content_id,
                notification_type,
                "Failed to send UDP-Notif message to the next actor"
            );
            self.validator
                .stats()
                .dropped
                .add(1, &with_reason(peer_tags, DropReason::SendError));
            return Err(ValidationActorError::SendError);
        }
        self.validator.stats().sent.add(1, peer_tags);
        trace!(
            peer=%peer,
            message_id,
            publisher_id,
            subscription_id,
            router_content_id,
            target,
            cached_content_id,
            notification_type,
            "Successfully sent UDP-Notif message to the next actor"
        );
        Ok(())
    }

    /// Send a schema lookup request to the cache actor.
    async fn send_cache_lookup(&self, lookup: CacheLookup) -> Result<(), ValidationActorError> {
        let description = format!("{lookup:?}");
        self.cache_cmd_tx
            .send(lookup.into_command(self.cache_tx.clone()))
            .await
            .map_err(|error| {
                warn!(
                    lookup=description,
                    error=%error,
                    "Error sending lookup request to the cache"
                );
                ValidationActorError::CacheLookupSendError
            })
    }

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
                            Ok("YANG-Push validation actor shutdown successfully".to_string())
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
                        Ok(response) => self.validator.process_cache_response(response),
                        Err(error) => {
                            let err_msg = "YANG-Push validation actor cache receiver channel closed unexpectedly, shutting down";
                            warn!(error=%error, err_msg);
                            return Ok(err_msg.to_string());
                        }
                    }
                }
                Some(message) = async { self.validator.pop_pending() }, if self.validator.has_pending() => {
                    if let Err(err) = self.process_udp_notif_msg(message, true).await {
                        let err_msg = "YANG-Push validation actor buffered packet processing unrecoverable error, shutting down";
                        warn!(error=%err, err_msg);
                        return Ok(err_msg.to_string());
                    }
                }
                msg = self.rx.recv() => {
                    match msg {
                        Ok(msg) => {
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
            validator: Validator::new(
                max_buffered_packets_per_peer,
                max_buffered_packets_per_subscription,
                anydata_strict,
                stats,
            ),
            cmd_rx,
            rx,
            tx,
            cache_cmd_tx,
            cache_tx,
            cache_rx,
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
