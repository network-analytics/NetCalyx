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

//! NetCalyx YANG-based Kafka Publisher
//!
//! This module provides functionality for publishing JSON messages to Apache
//! Kafka with support for YANG schema registration to Confluent Schema
//! Registry.
//!
//! # Overview
//!
//! The YANG Kafka publisher consists of several key components:
//!
//! - `YangConverter`: A trait that defines how to convert input data to
//!   YANG-compliant JSON
//! - `KafkaConfig`: Configuration for Kafka connection and YANG schema settings
//! - `KafkaYangPublisherActor`: The main actor that handles message publishing
//! - `KafkaYangPublisherActorHandle`: A handle for controlling the publisher
//!   actor
use crate::publishers::LoggingProducerContext;
use ipnet::IpNet;
use netcalyx_netconf_proto::yanglib::{
    DependencyError, PermissiveVersionChecker, SchemaConstructionError, SchemaLoadingError,
    YangLibrary,
};
use netcalyx_yang_push::cache::actor::CacheLookupCommand;
use netcalyx_yang_push::cache::storage::{
    SubscriptionInfo, YangLibraryCacheError, YangLibraryReference,
};
use netcalyx_yang_push::{
    ContentId, OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY, OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
    OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
};
use rdkafka::config::{ClientConfig, FromClientConfigAndContext};
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::{Header, OwnedHeaders};
use rdkafka::producer::{BaseRecord, Producer, ThreadedProducer};
use schema_registry_client::rest::schema_registry_client::{Client, SchemaRegistryClient};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use strum::VariantNames;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

/// Maximum polling interval when Kafka message queue is full
const MAX_POLLING_INTERVAL: Duration = Duration::from_secs(5);

// --- config ---

/// Trait for converting input data to YANG-compliant JSON format
pub trait YangConverter<T, E: std::error::Error> {
    /// Get optional subject prefix for schema registry
    fn subject_prefix(&self) -> Option<&str>;

    /// Get root schema name (e.g. ietf-telemetry-message)
    fn root_schema_name(&self) -> &str;

    /// Get the default YANG library to be used for messages without a
    /// content_id.
    ///
    /// If none is returned, then the message will be sent to Kafka without a
    /// schema
    fn default_yang_lib(&self) -> Option<&YangLibraryReference>;

    /// Get a YANG library for to extend the schema from the router with.
    ///
    /// If none is returned, then the message from the router is not extended
    /// with any schema
    fn extension_yang_lib_ref(&self) -> Option<&YangLibraryReference>;

    // Get ContentId from the input message
    fn content_id(&self, input: &T) -> Option<ContentId>;

    /// Extract a key from the input message for Kafka partitioning
    fn get_key(&self, input: &T) -> Option<serde_json::Value>;

    /// Serialize the input data to YANG-compliant JSON
    fn serialize_json(&self, input: T) -> Result<Vec<u8>, E>;

    /// Get the [SubscriptionInfo] of a given message
    fn subscription_info(&self, input: &T) -> Option<SubscriptionInfo>;
}

/// Configuration for the Kafka YANG publisher
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig<C>
where
    C: Serialize,
{
    /// Target Kafka topic for publishing messages
    pub topic: String,

    /// Key/Value producer configs are defined in librdkafka
    pub producer_config: HashMap<String, String>,

    /// Unique identifier for this writer instance
    pub writer_id: String,

    /// URL of the Confluent Schema Registry
    pub schema_registry_url: String,

    /// YANG converter implementation
    pub yang_converter: C,
}

// --- telemetry ---

/// Build OTel tags (peer address + subscription context) for schema
/// lookup metrics, when subscription info is available
fn subscription_info_tags(
    subscription_info: Option<&SubscriptionInfo>,
) -> Vec<opentelemetry::KeyValue> {
    let Some(subscription_info) = subscription_info else {
        return Vec::new();
    };
    vec![
        opentelemetry::KeyValue::new(
            "network.peer.address",
            subscription_info.peer_ip().to_string(),
        ),
        opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_ID_KEY,
            opentelemetry::Value::I64(subscription_info.id().into()),
        ),
        opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_TARGET_KEY,
            format!("{}", subscription_info.target()),
        ),
        opentelemetry::KeyValue::new(
            OTL_YANG_PUSH_SUBSCRIPTION_ROUTER_CONTENT_ID_KEY,
            subscription_info.content_id().to_string(),
        ),
    ]
}

// Attribute key shared by the `schema_registration_errors` and
// `schema_fallbacks` counters.
const REASON_KEY: &str = "reason";

/// Attribute values for the `reason` key on the `schema_registration_errors`
/// counter.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum_macros::VariantNames, strum_macros::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
enum SchemaRegistrationErrorReason {
    CacheLookupSendFailed,
    LoadSchemasFailed,
    YangLibraryFailed,
    ModuleSetBuilderFailed,
    ExtendYangLibFailed,
    RegisterSchemaFailed,
    MissingSchemaId,
}

/// Attribute values for the `reason` key on the `schema_fallbacks` counter.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum_macros::VariantNames, strum_macros::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
enum SchemaFallbackReason {
    NoContentIdWithDefault,
    NoContentIdNoDefault,
    NotFoundInCache,
    CacheChannelClosed,
    CacheLookupTimeout,
    CacheLookupSendFailed,
}

// Attribute key for the `outcome` tag on the `cache_actor_requests_duration`
// histogram.
const OUTCOME_KEY: &str = "outcome";

/// Attribute values for the `outcome` key on the
/// `cache_actor_requests_duration` histogram.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum_macros::VariantNames, strum_macros::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
enum CacheActorRequestOutcome {
    Success,
    NotFound,
    ChannelClosed,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct KafkaYangPublisherStats {
    received: opentelemetry::metrics::Counter<u64>,
    sent: opentelemetry::metrics::Counter<u64>,
    send_retries: opentelemetry::metrics::Counter<u64>,
    error_decode: opentelemetry::metrics::Counter<u64>,
    error_send: opentelemetry::metrics::Counter<u64>,
    delivered_messages: opentelemetry::metrics::Counter<u64>,
    failed_delivery_messages: opentelemetry::metrics::Counter<u64>,
    cache_hits: opentelemetry::metrics::Counter<u64>,
    cache_misses: opentelemetry::metrics::Counter<u64>,
    cache_actor_requests_duration: opentelemetry::metrics::Histogram<f64>,
    cache_actor_timeouts: opentelemetry::metrics::Counter<u64>,
    schema_registry_registrations: opentelemetry::metrics::Counter<u64>,
    schema_registration_errors: opentelemetry::metrics::Counter<u64>,
    schema_fallbacks: opentelemetry::metrics::Counter<u64>,
}

impl KafkaYangPublisherStats {
    fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netcalyx.collector.kafka.yang.received")
            .with_description("Received messages from upstream producer")
            .build();
        let sent = meter
            .u64_counter("netcalyx.collector.kafka.yang.sent")
            .with_description("Number of messages successfully sent to Kafka")
            .build();
        let send_retries = meter
            .u64_counter("netcalyx.collector.kafka.yang.send.retries")
            .with_description("Number of send retries to Kafka due to full queue in librdkafka")
            .build();
        let error_decode = meter
            .u64_counter("netcalyx.collector.kafka.yang.error_decode")
            .with_description("Error decoding message into YANG")
            .build();
        let error_send = meter
            .u64_counter("netcalyx.collector.kafka.yang.error_send")
            .with_description("Error sending message to Kafka")
            .build();
        let delivered_messages = meter
            .u64_counter("netcalyx.collector.kafka.yang.delivered_messages")
            .with_description("Messages confirmed to be delivered to Kafka")
            .build();
        let failed_delivery_messages = meter
            .u64_counter("netcalyx.collector.kafka.yang.failed_delivery_messages")
            .with_description("Messages failed delivery to Kafka")
            .build();
        let cache_hits = meter
            .u64_counter("netcalyx.collector.kafka.yang.schema_cache.hits")
            .with_description(
                "Schema ID lookups satisfied from the local in-process schema_id_cache \
                (no round-trip to the CacheActor)",
            )
            .build();
        let cache_misses = meter
            .u64_counter("netcalyx.collector.kafka.yang.schema_cache.misses")
            .with_description("Schema ID lookups not found in the local schema_id_cache, forwarded to the CacheActor")
            .build();
        let cache_actor_requests_duration = meter
            .f64_histogram("netcalyx.collector.kafka.yang.cache_actor.requests.duration")
            .with_description(format!(
                "Duration of CacheActor round-trip schema lookups, tagged with outcome ({})",
                CacheActorRequestOutcome::VARIANTS.join(" | ")
            ))
            .with_unit("s")
            .with_boundaries(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .build();
        let cache_actor_timeouts = meter
            .u64_counter("netcalyx.collector.kafka.yang.cache_actor.requests.timeouts")
            .with_description("CacheActor round-trip requests that timed out")
            .build();
        let schema_registry_registrations = meter
            .u64_counter("netcalyx.collector.kafka.yang.schema_registry.registrations")
            .with_description(
                "Schemas registered with the Schema Registry, including default/custom \
                schemas at actor startup and on cache-miss lookups",
            )
            .build();
        let schema_registration_errors = meter
            .u64_counter("netcalyx.collector.kafka.yang.schema_registry.registration_errors")
            .with_description(format!(
                "Failures resolving, loading, extending, or registering a schema during a \
                cache-miss lookup, tagged with reason ({})",
                SchemaRegistrationErrorReason::VARIANTS.join(" | ")
            ))
            .build();
        let schema_fallbacks = meter
            .u64_counter("netcalyx.collector.kafka.yang.schema.fallbacks")
            .with_description(format!(
                "Messages that fell back to the default schema or were sent without a \
                schema, tagged with reason ({})",
                SchemaFallbackReason::VARIANTS.join(" | ")
            ))
            .build();
        Self {
            received,
            sent,
            send_retries,
            error_decode,
            error_send,
            delivered_messages,
            failed_delivery_messages,
            cache_hits,
            cache_misses,
            cache_actor_requests_duration,
            cache_actor_timeouts,
            schema_registry_registrations,
            schema_registration_errors,
            schema_fallbacks,
        }
    }
}

// --- actor ---

#[derive(Debug, strum_macros::Display)]
pub enum KafkaYangPublisherActorError<E: std::error::Error> {
    /// Error communicating with the Kafka brokers
    #[strum(to_string = "KafkaError: {0}")]
    KafkaError(KafkaError),

    /// Serde JSON Error
    #[strum(to_string = "JSON Error: {0}")]
    JsonError(serde_json::Error),

    /// Error receiving incoming messages from input async_channel
    #[strum(to_string = "Error receiving messages from upstream producer")]
    ReceiveErr,

    /// YANG converter error
    #[strum(to_string = "YangConverterError: {0}")]
    YangConverterError(E),

    /// Error sending cache lookup request to SchemaCache Actor
    #[strum(to_string = "CacheLookupError")]
    CacheLookupError,

    /// YANG Library schema construction error
    #[strum(to_string = "YANG Library Schema Construction Error: {0}")]
    YangLibSchemaError(SchemaConstructionError),

    /// Yang Library dependency error
    #[strum(to_string = "YANG Library Dependency Error: {0}")]
    YangLibDependencyError(DependencyError),

    /// Schema Registration Error
    #[strum(to_string = "Schema Registration Error: {0}")]
    SchemaRegistrationError(String),

    /// YANG Library Cache Error
    #[strum(to_string = "YANG Library Cache Error: {0}")]
    YangLibraryCacheError(YangLibraryCacheError),

    #[strum(to_string = "YANG Library Schema Loading Error: {0}")]
    SchemaLoadingError(SchemaLoadingError),
}

impl<E: std::error::Error> std::error::Error for KafkaYangPublisherActorError<E> {}

impl<E: std::error::Error> From<KafkaError> for KafkaYangPublisherActorError<E> {
    fn from(e: KafkaError) -> Self {
        Self::KafkaError(e)
    }
}

impl<E: std::error::Error> From<async_channel::SendError<CacheLookupCommand>>
    for KafkaYangPublisherActorError<E>
{
    fn from(_e: async_channel::SendError<CacheLookupCommand>) -> Self {
        Self::CacheLookupError
    }
}

impl<E: std::error::Error> From<SchemaConstructionError> for KafkaYangPublisherActorError<E> {
    fn from(e: SchemaConstructionError) -> Self {
        Self::YangLibSchemaError(e)
    }
}

impl<E: std::error::Error> From<DependencyError> for KafkaYangPublisherActorError<E> {
    fn from(e: DependencyError) -> Self {
        Self::YangLibDependencyError(e)
    }
}

impl<E: std::error::Error> From<YangLibraryCacheError> for KafkaYangPublisherActorError<E> {
    fn from(e: YangLibraryCacheError) -> Self {
        Self::YangLibraryCacheError(e)
    }
}

impl<E: std::error::Error> From<SchemaLoadingError> for KafkaYangPublisherActorError<E> {
    fn from(e: SchemaLoadingError) -> Self {
        Self::SchemaLoadingError(e)
    }
}

#[derive(Debug, Clone, Copy)]
enum KafkaYangPublisherActorCommand {
    Shutdown,
}

/// The main actor responsible for publishing messages to Kafka with YANG
/// schemas
///
/// The actor handles:
/// - receiving messages from an async channel
/// - converting messages using the provided YANG converter
/// - publishing messages to Kafka with proper schema headers
/// - handling retries and error conditions
struct KafkaYangPublisherActor<T, E: std::error::Error, C: YangConverter<T, E>>
where
    T: Send + Sync,
    E: Send + Sync,
    C: Send + Sync + Serialize,
{
    cmd_rx: mpsc::Receiver<KafkaYangPublisherActorCommand>,
    config: KafkaConfig<C>,
    producer: ThreadedProducer<LoggingProducerContext>,
    msg_recv: async_channel::Receiver<T>,
    stats: KafkaYangPublisherStats,
    sr_client: SchemaRegistryClient,
    /// The default schema id to be used with messages that do not have a
    /// content_id
    default_schema_id: Option<i32>,
    /// Extended YANG library to extend the schemas from the router with,
    #[allow(clippy::type_complexity)]
    extension_yang_library: Option<(YangLibrary, HashMap<Box<str>, Box<str>>)>,
    /// [ContentId] to schema registry ID mapping cache
    schema_id_cache: HashMap<ContentId, i32>,
    cache_req_tx: async_channel::Sender<CacheLookupCommand>,
    _phantom: std::marker::PhantomData<(T, E)>,
}

impl<T, E, C> KafkaYangPublisherActor<T, E, C>
where
    T: Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
    C: YangConverter<T, E> + Send + Sync + Serialize,
{
    /// Create a Kafka producer based on configuration
    fn get_producer(
        stats: &KafkaYangPublisherStats,
        config: &KafkaConfig<C>,
    ) -> Result<ThreadedProducer<LoggingProducerContext>, KafkaYangPublisherActorError<E>> {
        let mut producer_config = ClientConfig::new();
        for (k, v) in &config.producer_config {
            producer_config.set(k.as_str(), v.as_str());
        }
        let producer_context = LoggingProducerContext {
            telemetry_attributes: Box::new([]),
            delivered_messages: stats.delivered_messages.clone(),
            failed_delivery_messages: stats.failed_delivery_messages.clone(),
        };
        match ThreadedProducer::from_config_and_context(&producer_config, producer_context) {
            Ok(p) => Ok(p),
            Err(err) => {
                error!("Failed to create Kafka producer: {err}");
                Err(err)?
            }
        }
    }

    /// Create a new actor instance from configuration
    async fn from_config(
        cmd_rx: mpsc::Receiver<KafkaYangPublisherActorCommand>,
        config: KafkaConfig<C>,
        custom_schemas: HashMap<IpNet, YangLibraryReference>,
        msg_recv: async_channel::Receiver<T>,
        stats: KafkaYangPublisherStats,
        cache_req_tx: async_channel::Sender<CacheLookupCommand>,
    ) -> Result<Self, KafkaYangPublisherActorError<E>> {
        let producer = Self::get_producer(&stats, &config)?;

        // Create the schema registry Client
        let client_conf = schema_registry_client::rest::client_config::ClientConfig::new(vec![
            config.schema_registry_url.clone(),
        ]);
        let sr_client = SchemaRegistryClient::new(client_conf);

        // Load and register provided default schema
        let default_schema_id =
            if let Some(default_yang_lib_ref) = config.yang_converter.default_yang_lib() {
                let default_schema_id = Self::register_yang_lib_ref(
                    &sr_client,
                    default_yang_lib_ref,
                    config.yang_converter.root_schema_name(),
                    config.yang_converter.subject_prefix(),
                )
                .await?;
                stats.schema_registry_registrations.add(1, &[]);
                Some(default_schema_id)
            } else {
                None
            };

        let extension_yang_library =
            if let Some(yang_lib_ref) = config.yang_converter.extension_yang_lib_ref() {
                let yang_lib = yang_lib_ref.yang_library()?;
                let schemas =
                    yang_lib.load_schemas_from_search_path(yang_lib_ref.search_dir().as_path())?;
                Some((yang_lib, schemas))
            } else {
                None
            };

        // Load and register provided custom schemas (custom schemas
        // are already extended with the telemetry-message schema)
        let mut schema_id_cache = HashMap::new();

        for yang_lib_ref in custom_schemas.values() {
            let content_id = yang_lib_ref.content_id();
            let schema_id = Self::register_yang_lib_ref(
                &sr_client,
                yang_lib_ref,
                config.yang_converter.root_schema_name(),
                config.yang_converter.subject_prefix(),
            )
            .await?;
            stats.schema_registry_registrations.add(1, &[]);
            // Store schema registry ID in cache
            schema_id_cache.insert(content_id.to_string(), schema_id);
        }

        info!("Root and custom schema loading and registering complete!");
        info!("Starting Kafka YANG publisher to topic: `{}`", config.topic);

        Ok(Self {
            cmd_rx,
            config,
            producer,
            msg_recv,
            stats,
            sr_client,
            default_schema_id,
            extension_yang_library,
            schema_id_cache,
            cache_req_tx,
            _phantom: std::marker::PhantomData,
        })
    }

    async fn register_yang_lib_ref(
        sr_client: &SchemaRegistryClient,
        yang_lib_ref: &YangLibraryReference,
        root_schema_name: &str,
        subject_prefix: Option<&str>,
    ) -> Result<i32, KafkaYangPublisherActorError<E>> {
        let yang_lib = yang_lib_ref.yang_library()?;
        let schemas =
            yang_lib.load_schemas_from_search_path(yang_lib_ref.search_dir().as_path())?;
        let content_id = yang_lib_ref.content_id();
        let registered_schema = yang_lib
            .register_schema(root_schema_name, subject_prefix, &schemas, sr_client)
            .await?;

        let schema_id = registered_schema.id.ok_or_else(|| {
            KafkaYangPublisherActorError::SchemaRegistrationError(format!(
                "Schema ID not found in registered schema response for content_id: {content_id}"
            ))
        })?;
        Ok(schema_id)
    }

    /// Get schema ID from cache or by registering the schema to the schema
    /// registry
    async fn register_schema(
        &mut self,
        content_id: Option<&str>,
        subscription_info: Option<&SubscriptionInfo>,
    ) -> Result<Option<i32>, KafkaYangPublisherActorError<E>> {
        let mut tags = subscription_info_tags(subscription_info);
        let id = if let Some(id) = content_id {
            id
        } else {
            let reason = if self.default_schema_id.is_some() {
                SchemaFallbackReason::NoContentIdWithDefault
            } else {
                SchemaFallbackReason::NoContentIdNoDefault
            };
            tags.push(opentelemetry::KeyValue::new(
                REASON_KEY,
                <&str>::from(reason),
            ));
            self.stats.schema_fallbacks.add(1, &tags);
            return if let Some(default_schema_id) = self.default_schema_id {
                if let Some(subscription_info) = subscription_info {
                    warn!(
                        peer_ip=%subscription_info.peer_ip(),
                        subscription_id=subscription_info.id(),
                        router_content_id=subscription_info.content_id(),
                        target=%subscription_info.target(),
                        default_schema_id,
                        "No content ID provided and for subscription, \
                        using default schema ID"
                    );
                } else {
                    warn!(
                        default_schema_id,
                        "No content ID provided and no subscription information, \
                        using default schema ID"
                    );
                }
                Ok(Some(default_schema_id))
            } else {
                if let Some(subscription_info) = subscription_info {
                    warn!(
                        peer_ip=%subscription_info.peer_ip(),
                        subscription_id=subscription_info.id(),
                        router_content_id=subscription_info.content_id(),
                        target=%subscription_info.target(),
                        "No content ID provided, for subscription, \
                        and no default schema ID configured!, falling back to not using any schema"
                    );
                } else {
                    warn!(
                        "No content ID provided, no subscription information, \
                        and no default schema ID configured!, falling back to not using any schema"
                    );
                }
                Ok(None)
            };
        };

        // Check if we already have this schema registered
        if let Some(&schema_id) = self.schema_id_cache.get(id) {
            self.stats.cache_hits.add(1, &tags);
            if let Some(subscription_info) = subscription_info {
                trace!(
                    peer_ip=%subscription_info.peer_ip(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    schema_id,
                    content_id,
                    "Found schemaID for the corresponding contentID"
                );
            } else {
                trace!(
                    schema_id,
                    content_id,
                    "Found schemaID for the corresponding contentID without subscription info"
                );
            }

            return Ok(Some(schema_id));
        }
        self.stats.cache_misses.add(1, &tags);

        // Request schema from SchemaCache Actor
        // (with timeout to prevent hanging)
        let (response_tx, response_rx) = oneshot::channel();
        let cache_lookup_start = Instant::now();

        if let Err(err) = self
            .cache_req_tx
            .send(CacheLookupCommand::LookupByContentIdOneShot {
                content_id: id.to_string(),
                tx: response_tx,
            })
            .await
        {
            let mut error_tags = tags.clone();
            error_tags.push(opentelemetry::KeyValue::new(
                REASON_KEY,
                <&str>::from(SchemaRegistrationErrorReason::CacheLookupSendFailed),
            ));
            self.stats.schema_registration_errors.add(1, &error_tags);

            tags.push(opentelemetry::KeyValue::new(
                REASON_KEY,
                <&str>::from(SchemaFallbackReason::CacheLookupSendFailed),
            ));
            self.stats.schema_fallbacks.add(1, &tags);

            warn!(
                "Failed to request schema for content_id: {id}, fallback to using root schema \
                (id={:?}): {err}",
                self.default_schema_id
            );
            return Ok(self.default_schema_id);
        }

        // TODO: expose timeout to config
        let (content_id, yang_lib_ref) = match tokio::time::timeout(
            Duration::from_secs(5),
            response_rx,
        )
        .await
        {
            Ok(Ok((content_id, Some(yang_lib_ref)))) => {
                let mut outcome_tags = tags.clone();
                outcome_tags.push(opentelemetry::KeyValue::new(
                    OUTCOME_KEY,
                    <&str>::from(CacheActorRequestOutcome::Success),
                ));
                self.stats
                    .cache_actor_requests_duration
                    .record(cache_lookup_start.elapsed().as_secs_f64(), &outcome_tags);
                (content_id, yang_lib_ref)
            }
            Ok(Ok((content_id, None))) => {
                let mut outcome_tags = tags.clone();
                outcome_tags.push(opentelemetry::KeyValue::new(
                    OUTCOME_KEY,
                    <&str>::from(CacheActorRequestOutcome::NotFound),
                ));
                self.stats
                    .cache_actor_requests_duration
                    .record(cache_lookup_start.elapsed().as_secs_f64(), &outcome_tags);
                tags.push(opentelemetry::KeyValue::new(
                    REASON_KEY,
                    <&str>::from(SchemaFallbackReason::NotFoundInCache),
                ));
                self.stats.schema_fallbacks.add(1, &tags);
                warn!(
                    "Schema not found for content ID '{:?}', fallback to using root schema (id={content_id})",
                    self.default_schema_id
                );
                return Ok(self.default_schema_id);
            }
            Ok(Err(_)) => {
                let mut outcome_tags = tags.clone();
                outcome_tags.push(opentelemetry::KeyValue::new(
                    OUTCOME_KEY,
                    <&str>::from(CacheActorRequestOutcome::ChannelClosed),
                ));
                self.stats
                    .cache_actor_requests_duration
                    .record(cache_lookup_start.elapsed().as_secs_f64(), &outcome_tags);
                tags.push(opentelemetry::KeyValue::new(
                    REASON_KEY,
                    <&str>::from(SchemaFallbackReason::CacheChannelClosed),
                ));
                self.stats.schema_fallbacks.add(1, &tags);
                warn!(
                    "Schema request channel closed for content ID '{:?}', fallback to using root schema (id={:?})",
                    id, self.default_schema_id
                );
                return Ok(self.default_schema_id);
            }
            Err(_) => {
                self.stats.cache_actor_timeouts.add(1, &tags);
                let mut outcome_tags = tags.clone();
                outcome_tags.push(opentelemetry::KeyValue::new(
                    OUTCOME_KEY,
                    <&str>::from(CacheActorRequestOutcome::Timeout),
                ));
                self.stats
                    .cache_actor_requests_duration
                    .record(cache_lookup_start.elapsed().as_secs_f64(), &outcome_tags);
                tags.push(opentelemetry::KeyValue::new(
                    REASON_KEY,
                    <&str>::from(SchemaFallbackReason::CacheLookupTimeout),
                ));
                self.stats.schema_fallbacks.add(1, &tags);
                warn!(
                    "Schema request timeout for content ID '{}', fallback to using root schema (id={:?})",
                    id, self.default_schema_id
                );
                return Ok(self.default_schema_id);
            }
        };

        // Handle schema_cache response, extend and register schema
        let mut schemas = yang_lib_ref.load_schemas().inspect_err(|_| {
            tags.push(opentelemetry::KeyValue::new(
                REASON_KEY,
                <&str>::from(SchemaRegistrationErrorReason::LoadSchemasFailed),
            ));
            self.stats.schema_registration_errors.add(1, &tags);
        })?;
        let mut yang_lib = yang_lib_ref.yang_library().inspect_err(|_| {
            tags.push(opentelemetry::KeyValue::new(
                REASON_KEY,
                <&str>::from(SchemaRegistrationErrorReason::YangLibraryFailed),
            ));
            self.stats.schema_registration_errors.add(1, &tags);
        })?;

        if let Some((extension_yang_lib, extension_schemas)) = self.extension_yang_library.as_ref()
        {
            let mut builder = yang_lib
                .into_module_set_builder(&schemas, "ALL".into(), &PermissiveVersionChecker)
                .inspect_err(|_| {
                    tags.push(opentelemetry::KeyValue::new(
                        REASON_KEY,
                        <&str>::from(SchemaRegistrationErrorReason::ModuleSetBuilderFailed),
                    ));
                    self.stats.schema_registration_errors.add(1, &tags);
                })?;
            builder
                .extend_from_yang_lib(
                    extension_yang_lib.clone(),
                    extension_schemas,
                    &PermissiveVersionChecker,
                )
                .inspect_err(|_| {
                    tags.push(opentelemetry::KeyValue::new(
                        REASON_KEY,
                        <&str>::from(SchemaRegistrationErrorReason::ExtendYangLibFailed),
                    ));
                    self.stats.schema_registration_errors.add(1, &tags);
                })?;

            let (yang_lib_extended, schemas_extended) = builder.build_yang_lib();
            yang_lib = yang_lib_extended;
            schemas = schemas_extended;
        }

        let registered_schema = yang_lib
            .register_schema(
                self.config.yang_converter.root_schema_name(),
                self.config.yang_converter.subject_prefix(),
                &schemas,
                &self.sr_client,
            )
            .await
            .inspect_err(|_| {
                tags.push(opentelemetry::KeyValue::new(
                    REASON_KEY,
                    <&str>::from(SchemaRegistrationErrorReason::RegisterSchemaFailed),
                ));
                self.stats.schema_registration_errors.add(1, &tags);
            })?;

        let schema_id = registered_schema.id.ok_or_else(|| {
            tags.push(opentelemetry::KeyValue::new(
                REASON_KEY,
                <&str>::from(SchemaRegistrationErrorReason::MissingSchemaId),
            ));
            self.stats.schema_registration_errors.add(1, &tags);
            KafkaYangPublisherActorError::SchemaRegistrationError(format!(
                "Schema ID not found in registered schema response for content_id: {id}"
            ))
        })?;
        self.stats.schema_registry_registrations.add(1, &tags);
        self.schema_id_cache.insert(content_id, schema_id);
        Ok(Some(schema_id))
    }

    /// Send a single message to Kafka
    ///
    /// This method:
    /// - converts the input message using the YANG converter
    /// - encodes the result as JSON bytes
    /// - extracts the message key (if any)
    /// - sends to Kafka with schema ID in the kafka header
    /// - handles retries for queue full conditions
    ///
    /// If the Kafka queue is full, this method will retry with exponentially
    /// increasing delays up to [`MAX_POLLING_INTERVAL`]. If the maximum
    /// interval is exceeded, the message is dropped and an error is
    /// returned.
    async fn send(&mut self, input: T) -> Result<(), KafkaYangPublisherActorError<E>> {
        let content_id = self.config.yang_converter.content_id(&input);
        let subscription_info = self.config.yang_converter.subscription_info(&input);
        let key = self.config.yang_converter.get_key(&input);
        let tags = subscription_info_tags(subscription_info.as_ref());

        let encoded_value = match self.config.yang_converter.serialize_json(input) {
            Ok(bytes) => bytes,
            Err(err) => {
                error!("Error serializing message to JSON bytes: {err}");
                let mut tags = tags.clone();
                tags.push(opentelemetry::KeyValue::new(
                    "netcalyx.json.serialize.error.msg",
                    err.to_string(),
                ));
                self.stats.error_decode.add(1, &tags);
                return Err(KafkaYangPublisherActorError::YangConverterError(err));
            }
        };

        let encoded_key = match key {
            Some(key) => match serde_json::to_vec(&key) {
                Ok(value) => Some(value),
                Err(err) => {
                    error!("Error encoding serde_json::Value for key into byte array: {err}");
                    let mut tags = tags.clone();
                    tags.push(opentelemetry::KeyValue::new(
                        "netcalyx.json.encode.error.msg",
                        err.to_string(),
                    ));
                    self.stats.error_decode.add(1, &tags);
                    return Err(KafkaYangPublisherActorError::JsonError(err));
                }
            },
            None => None,
        };

        // Get schema ID
        let schema_id = self
            .register_schema(content_id.as_deref(), subscription_info.as_ref())
            .await?;

        let mut headers = OwnedHeaders::new();
        let schema_id_str = schema_id.map(|id| id.to_string());

        // Create headers with schema ID
        if schema_id_str.is_some() {
            headers = headers.insert(Header {
                key: "schema-id",
                value: schema_id_str.as_deref(),
            });
            headers = headers.insert(Header {
                key: "content-type",
                value: Some("application/yang.data+json"),
            })
        }

        let mut record: BaseRecord<'_, Vec<u8>, Vec<u8>> = match &encoded_key {
            Some(key) => BaseRecord::to(self.config.topic.as_str())
                .payload(&encoded_value)
                .key(key)
                .headers(headers),
            None => BaseRecord::to(self.config.topic.as_str())
                .payload(&encoded_value)
                .headers(headers),
        };

        let mut polling_interval = Duration::from_micros(10);
        loop {
            match self.producer.send(record) {
                Ok(_) => {
                    self.stats.sent.add(1, &tags);
                    return Ok(());
                }
                Err((err, rec)) => match err {
                    KafkaError::MessageProduction(RDKafkaErrorCode::QueueFull) => {
                        // Exponential backoff when the librdkafka is full
                        if polling_interval > MAX_POLLING_INTERVAL {
                            error!("Kafka polling interval exceeded, dropping record");
                            let mut tags = tags.clone();
                            tags.push(opentelemetry::KeyValue::new(
                                "netcalyx.kafka.sent.error.msg",
                                err.to_string(),
                            ));
                            self.stats.error_send.add(1, &tags);
                            return Err(KafkaYangPublisherActorError::KafkaError(err));
                        }
                        debug!("Kafka message queue is full, sleeping for {polling_interval:?}");
                        self.stats.send_retries.add(1, &tags);
                        tokio::time::sleep(polling_interval).await;
                        polling_interval *= 2;
                        record = rec;
                        continue;
                    }
                    err => {
                        error!("Error sending message: {err}");
                        let mut tags = tags.clone();
                        tags.push(opentelemetry::KeyValue::new(
                            "netcalyx.kafka.sent.error.msg",
                            err.to_string(),
                        ));
                        self.stats.error_send.add(1, &tags);
                        return Err(KafkaYangPublisherActorError::KafkaError(err));
                    }
                },
            }
        }
    }

    /// Main actor event loop
    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    return match cmd {
                        Some(KafkaYangPublisherActorCommand::Shutdown) => {
                            info!("Received shutdown signal");
                            if let Err(err) = self.producer.flush(Duration::from_millis(1000)) {
                                error!("Failed to flush messages before shutting down: {err}");
                            }
                            Ok("Shutting down".to_string())
                        }
                        None => {
                            warn!("KafkaYangPublisher terminated due to command channel closing");
                            Ok("KafkaYangPublisher shutdown successfully".to_string())
                        }
                    }
                }
                msg = self.msg_recv.recv() => {
                    match msg {
                        Ok(msg) => {
                            let subscription_info = self.config.yang_converter.subscription_info(&msg);
                            self.stats
                                .received
                                .add(1, &subscription_info_tags(subscription_info.as_ref()));
                            if let Err(err) = self.send(msg).await {
                                error!("Error sending message to Kafka: {err}");
                            }
                        }
                        Err(_) => {
                            return Err(anyhow::anyhow!(KafkaYangPublisherActorError::<E>::ReceiveErr))
                        }
                    }
                }
            }
        }
    }
}

// --- actor handle ---

#[derive(Debug)]
pub enum KafkaYangPublisherActorHandleError {
    SendError,
}

/// Handle for controlling a Kafka YANG publisher actor
#[derive(Debug)]
pub struct KafkaYangPublisherActorHandle<T, E, C>
where
    E: std::error::Error,
    C: YangConverter<T, E>,
{
    cmd_tx: mpsc::Sender<KafkaYangPublisherActorCommand>,
    _phantom: std::marker::PhantomData<(T, E, C)>,
}

impl<T, E, C> KafkaYangPublisherActorHandle<T, E, C>
where
    T: Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
    C: YangConverter<T, E> + Send + Sync + Serialize + 'static,
{
    pub async fn from_config(
        config: KafkaConfig<C>,
        custom_schemas: HashMap<IpNet, YangLibraryReference>,
        msg_recv: async_channel::Receiver<T>,
        stats: either::Either<opentelemetry::metrics::Meter, KafkaYangPublisherStats>,
        cache_req_tx: async_channel::Sender<CacheLookupCommand>,
    ) -> Result<(JoinHandle<anyhow::Result<String>>, Self), KafkaYangPublisherActorError<E>> {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let stats = match stats {
            either::Either::Left(meter) => KafkaYangPublisherStats::new(meter),
            either::Either::Right(stats) => stats,
        };
        let actor = KafkaYangPublisherActor::from_config(
            cmd_rx,
            config,
            custom_schemas,
            msg_recv,
            stats,
            cache_req_tx,
        )
        .await?;
        let join_handle = tokio::spawn(actor.run());
        let handle = Self {
            cmd_tx,
            _phantom: std::marker::PhantomData,
        };
        Ok((join_handle, handle))
    }

    pub async fn shutdown(&self) -> Result<(), KafkaYangPublisherActorHandleError> {
        self.cmd_tx
            .send(KafkaYangPublisherActorCommand::Shutdown)
            .await
            .map_err(|_| KafkaYangPublisherActorHandleError::SendError)
    }
}
