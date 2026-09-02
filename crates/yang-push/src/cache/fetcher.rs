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

//! YANG Library fetching from external sources.
//!
//! This module provides abstractions for retrieving YANG libraries and schemas
//! from network devices. The primary implementation fetches data via NETCONF
//! over SSH.
//!
//! # Architecture
//!
//! - [`YangLibraryFetcher`]: Trait defining the fetch interface
//! - [`NetconfYangLibraryFetcher`]: NETCONF/SSH implementation
//! - [`FetcherResult`]: Type alias for fetch operation results

use crate::cache::storage::{SubscriptionInfo, YangLibraryCacheError};
use netcalyx_netconf_proto::capabilities::{Capability, NetconfVersion};
use netcalyx_netconf_proto::client::{NetconfSshConnectConfig, SshAuth, SshHandler, connect};
use netcalyx_netconf_proto::yang_module_cache::YangModuleCache;
use netcalyx_netconf_proto::yang_push::filters::{
    DatastoreFilterSpec, DatastoreXPathFilter, StreamSelectionFilterObjects,
};
use netcalyx_netconf_proto::yang_push::subscription::{
    DatastoreSelectionFilterObjects, Target, YangPushModuleVersion,
};
use netcalyx_netconf_proto::yang_push::types::SubscriptionId;
use netcalyx_netconf_proto::yanglib::{DatastoreName, PermissiveVersionChecker, YangLibrary};
use netcalyx_udp_notif_service::SessionInfo;
use rand::RngExt;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

pub type FetcherResult = Result<
    (SubscriptionInfo, YangLibrary, HashMap<Box<str>, Box<str>>),
    Box<(SubscriptionInfo, YangLibraryCacheError)>,
>;

/// Append `module` to `modules` as a [`YangPushModuleVersion`], skipping it if
/// a module with the same name is already present.
fn push_module(
    modules: &mut Vec<YangPushModuleVersion>,
    module: &netcalyx_netconf_proto::yanglib::Module,
) {
    if modules.iter().any(|m| m.name() == module.name()) {
        return;
    }
    modules.push(YangPushModuleVersion::new(
        module.name().into(),
        module.revision().map(|x| x.into()),
        None,
    ));
}

/// Resolve every module referenced by a namespace binding against the device
/// YANG Library. Used for subtree filters and stream filters, where modules
/// are identified by the root element namespace.
fn resolve_by_namespaces(
    router_yang_library: &YangLibrary,
    ds_name: &DatastoreName,
    namespaces: &[(Box<str>, Box<str>)],
    empty: &SubscriptionInfo,
) -> Result<Vec<YangPushModuleVersion>, Box<(SubscriptionInfo, YangLibraryCacheError)>> {
    let mut ret = Vec::with_capacity(namespaces.len());
    for (_prefix, namespace) in namespaces {
        let module = router_yang_library
            .find_module_by_datastore_and_ns(ds_name, namespace)
            .ok_or_else(|| {
                error!(
                    %namespace,
                    %ds_name,
                    "target module not found in device YANG Library by namespace",
                );
                Box::new((
                    empty.clone(),
                    YangLibraryCacheError::ModuleNamespaceNotFound {
                        namespace: namespace.clone(),
                        datastore: ds_name.to_string().into_boxed_str(),
                    },
                ))
            })?;
        trace!(namespace=%namespace, module=%module.name(), "resolved target module by namespace");
        push_module(&mut ret, module);
    }
    Ok(ret)
}

/// Resolve xpath-filter modules per the RFC 8641 XPath context for
/// `datastore-xpath-filter`: prefixes declared via `xmlns` take precedence
/// (e.g. Huawei), otherwise the prefix is the YANG module name from the
/// server's base context (e.g. Cisco IOS-XR). Both are conformant; we try the
/// declared binding first, then the module name.
fn resolve_by_xpath(
    router_yang_library: &YangLibrary,
    ds_name: &DatastoreName,
    xpath: &DatastoreXPathFilter,
    empty: &SubscriptionInfo,
) -> Result<Vec<YangPushModuleVersion>, Box<(SubscriptionInfo, YangLibraryCacheError)>> {
    let declared: HashMap<&str, &str> = xpath
        .namespaces
        .iter()
        .map(|(prefix, ns)| (prefix.as_ref(), ns.as_ref()))
        .collect();
    let mut ret = Vec::new();
    let prefixes = xpath.path_prefixes();
    trace!(
        %ds_name,
        path = %xpath.path,
        ?prefixes,
        declared_prefixes = declared.len(),
        "resolving target modules from xpath filter",
    );
    for prefix in prefixes {
        let module = if let Some(namespace) = declared.get(prefix.as_str()) {
            router_yang_library
                .find_module_by_datastore_and_ns(ds_name, namespace)
                .ok_or_else(|| {
                    error!(
                        %prefix,
                        namespace,
                        %ds_name,
                        "target module not found for declared xpath prefix namespace",
                    );
                    Box::new((
                        empty.clone(),
                        YangLibraryCacheError::ModuleNamespaceNotFound {
                            namespace: (*namespace).into(),
                            datastore: ds_name.to_string().into_boxed_str(),
                        },
                    ))
                })?
        } else {
            // No xmlns binding: per RFC 8641 the prefix is the YANG module
            // name in the server's base XPath context.
            debug!(
                %prefix,
                "xpath prefix has no declared namespace binding, resolving it as a module name",
            );
            router_yang_library
                .find_module_by_datastore_and_name(ds_name, &prefix)
                .ok_or_else(|| {
                    error!(
                        %prefix,
                        "target module not found when resolving xpath prefix as a module name",
                    );
                    Box::new((
                        empty.clone(),
                        YangLibraryCacheError::ModulePrefixNotFound(
                            prefix.clone().into_boxed_str(),
                        ),
                    ))
                })?
        };
        trace!(%prefix, module=%module.name(), "resolved target module from xpath prefix");
        push_module(&mut ret, module);
    }
    Ok(ret)
}

/// Fetch YANG Library and schemas from an external source
pub trait YangLibraryFetcher {
    /// A non-blocking version which returns a [JoinHandle]
    /// to the worker getting the YANG Library and schemas
    fn fetch(
        &self,
        subscription_info: SubscriptionInfo,
        session: SessionInfo,
    ) -> impl Future<Output = JoinHandle<FetcherResult>> + Send;

    /// A blocking version which returns directly the YANG library and schemas.
    fn fetch_blocking(
        &self,
        subscription_info: SubscriptionInfo,
        session: SessionInfo,
    ) -> impl Future<Output = FetcherResult> + Send;

    fn fetch_by_subscription_id(
        &self,
        session: SessionInfo,
        subscription_id: SubscriptionId,
    ) -> impl Future<Output = JoinHandle<FetcherResult>> + Send;

    fn fetch_by_subscription_id_blocking(
        &self,
        session: SessionInfo,
        subscription_id: SubscriptionId,
    ) -> impl Future<Output = FetcherResult> + Send;
}

#[derive(Clone)]
struct FetchConfig {
    user: String,
    private_key: Arc<russh::keys::ssh_key::PrivateKey>,
    client_config: Arc<russh::client::Config>,
    default_port: u16,
    timeout: std::time::Duration,
    module_cache: YangModuleCache,
}

#[derive(Clone, Copy)]
pub struct RetryConfig {
    max_retries: u32,
    max_backoff: std::time::Duration,
}

impl RetryConfig {
    pub fn new(max_retries: u32, max_backoff: std::time::Duration) -> Self {
        Self {
            max_retries,
            max_backoff,
        }
    }
}

/// A [YangLibraryFetcher] which fetches the YANG Library and schemas
/// from a NETCONF device over SSH.
///
/// TODO: Add support for other authentication methods
/// (e.g., password, keyboard-interactive)
///
/// TODO: Add support for custom ports per device
///
/// TODO: Add peer to management address mapping support for devices using
/// different IP address to send the YANG-Push messages
pub struct NetconfYangLibraryFetcher {
    fetch_cfg: FetchConfig,
    retry_cfg: RetryConfig,
}

/// Base delay for exponential backoff (1 second).
const BASE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

impl NetconfYangLibraryFetcher {
    pub fn new(
        user: String,
        private_key: Arc<russh::keys::ssh_key::PrivateKey>,
        client_config: russh::client::Config,
        default_port: u16,
        default_timeout: std::time::Duration,
        retry_cfg: RetryConfig,
        global_module_cache: YangModuleCache,
    ) -> Self {
        Self {
            fetch_cfg: FetchConfig {
                user,
                private_key,
                client_config: Arc::new(client_config),
                default_port,
                timeout: default_timeout,
                module_cache: global_module_cache,
            },
            retry_cfg,
        }
    }

    async fn fetch_from_device(
        cfg: &FetchConfig,
        subscription_info: SubscriptionInfo,
        session: SessionInfo,
    ) -> FetcherResult {
        let collector = session.collector();
        let interface = session.interface();
        let peer_ip = subscription_info.peer_ip();
        let subscription_id = subscription_info.id();
        let host = SocketAddr::new(peer_ip, cfg.default_port);
        info!(
            host=%host,
            collector=%collector,
            interface,
            peer_ip=%peer_ip,
            subscription_id,
            "starting fetching YANG Library from device",
        );
        let ssh_handler = SshHandler::default();
        let auth = SshAuth::Key {
            user: cfg.user.clone(),
            private_key: Arc::clone(&cfg.private_key),
        };
        let announce_caps = HashSet::from([Capability::NetconfBase(NetconfVersion::V1_1)]);
        let config = NetconfSshConnectConfig::new(
            auth,
            host,
            None,
            interface.map(str::to_string),
            announce_caps,
            ssh_handler,
            Arc::clone(&cfg.client_config),
        )
        .with_module_cache(cfg.module_cache.clone());

        let mut client = match tokio::time::timeout(cfg.timeout, connect(config)).await {
            Ok(Ok(c)) => c,
            Ok(Err(err)) => {
                error!(host=%host,error=%err, "error connecting to device over SSH");
                return Err(Box::new((subscription_info.clone(), err.into())));
            }
            Err(err) => {
                error!(host=%host,error=%err, "timeout while connecting to device over SSH");
                return Err(Box::new((subscription_info.clone(), err.into())));
            }
        };
        let modules = subscription_info
            .models()
            .iter()
            .map(|x| x.name())
            .collect::<Vec<_>>();
        // TODO: add timeout to loading YANG Library from the device
        let (yang_lib, schemas) = client
            .load_from_modules(&modules, &PermissiveVersionChecker)
            .await
            .map_err(|err| Box::new((subscription_info.clone(), err.into())))?;
        match tokio::time::timeout(cfg.timeout, client.close()).await {
            Ok(Ok(_)) => {
                info!(host=%host,"SSH connection closed successfully");
            }
            Ok(Err(err)) => warn!(host=%host, error=%err, "Error closing SSH connection"),
            Err(err) => {
                warn!(host=%host, error=%err, "Timeout while closing SSH connection")
            }
        }
        info!(
            host=%host,
            peer_ip=%peer_ip,
            subscription_id,
            cached_content_id=yang_lib.content_id(),
            schema_count=schemas.len(),
            "YANG Library fetched from device",
        );
        Ok((subscription_info, yang_lib, schemas))
    }

    async fn fetch_from_device_by_id(
        cfg: &FetchConfig,
        session: SessionInfo,
        subscription_id: SubscriptionId,
    ) -> FetcherResult {
        let collector = session.collector();
        let interface = session.interface();
        let peer_ip = session.peer().ip();
        let host = SocketAddr::new(peer_ip, cfg.default_port);
        info!(
            host=%host,
            collector=%collector,
            interface,
            peer_ip=%peer_ip,
            subscription_id,
            "starting fetching YANG Library from device",
        );
        let ssh_handler = SshHandler::default();
        let auth = SshAuth::Key {
            user: cfg.user.clone(),
            private_key: Arc::clone(&cfg.private_key),
        };
        let announce_caps = HashSet::from([Capability::NetconfBase(NetconfVersion::V1_1)]);
        let config = NetconfSshConnectConfig::new(
            auth,
            host,
            None,
            interface.map(String::from),
            announce_caps,
            ssh_handler,
            Arc::clone(&cfg.client_config),
        )
        .with_module_cache(cfg.module_cache.clone());
        // Empty subscription info returned in case of errors to keep track of peer and
        // subscription ID
        let empty = SubscriptionInfo::new_empty(peer_ip, subscription_id);
        let mut client = match tokio::time::timeout(cfg.timeout, connect(config)).await {
            Ok(Ok(c)) => c,
            Ok(Err(err)) => {
                error!(host=%host,error=%err, "error connecting to device over SSH");
                return Err(Box::new((empty, err.into())));
            }
            Err(err) => {
                error!(host=%host,error=%err, "timeout while connecting to device over SSH");
                return Err(Box::new((empty, err.into())));
            }
        };

        let mut subscription = client
            .get_yang_push_subscription_by_id(subscription_id)
            .await
            .map_err(|err| Box::new((empty.clone(), err.into())))?;
        let router_yang_library = client
            .get_yang_library()
            .await
            .map_err(|err| Box::new((empty.clone(), err.into())))?;

        let modules = if let Some(modules) = &subscription.module_version {
            debug!(
                host=%host,
                subscription_id,
                module_count = modules.len(),
                "device reported module-version for subscription, using it to resolve target modules",
            );
            modules.clone().to_vec()
        } else {
            let (ds_name, modules) = match &subscription.target {
                Target::Stream(stream_target) => match &stream_target.filter {
                    StreamSelectionFilterObjects::ByReference(name) => {
                        // references are resolved in the NETCONF client,
                        // if we reach this point, there must be a misconfigured router,
                        error!(
                            %name,
                            subscription_id,
                            "stream selection filter reached fetcher unresolved by reference, likely a misconfigured router",
                        );
                        return Err(Box::new((
                            empty,
                            YangLibraryCacheError::UnresolvedFilterReference(name.clone()),
                        )));
                    }
                    StreamSelectionFilterObjects::WithInSubscription(filter) => {
                        let ds_name = DatastoreName::Running;
                        let modules = resolve_by_namespaces(
                            &router_yang_library,
                            &ds_name,
                            filter.namespaces(),
                            &empty,
                        )?;
                        (ds_name, modules)
                    }
                },
                Target::Datastore(datastore_target) => match &datastore_target.selection {
                    DatastoreSelectionFilterObjects::ByReference(name) => {
                        error!(
                            %name,
                            subscription_id,
                            "datastore selection filter reached fetcher unresolved by reference, likely a misconfigured router",
                        );
                        return Err(Box::new((
                            empty,
                            YangLibraryCacheError::UnresolvedFilterReference(name.clone()),
                        )));
                    }
                    DatastoreSelectionFilterObjects::WithInSubscription(filter) => {
                        let ds_name = datastore_target.datastore.clone();
                        let modules = match filter {
                            DatastoreFilterSpec::Xpath(xpath) => {
                                resolve_by_xpath(&router_yang_library, &ds_name, xpath, &empty)?
                            }
                            DatastoreFilterSpec::Subtree(subtree) => resolve_by_namespaces(
                                &router_yang_library,
                                &ds_name,
                                &subtree.namespaces,
                                &empty,
                            )?,
                        };
                        (ds_name, modules)
                    }
                },
            };
            if modules.is_empty() {
                error!(
                    host=%host,
                    subscription_id,
                    %ds_name,
                    "no target modules could be resolved from subscription filter",
                );
                return Err(Box::new((
                    empty,
                    YangLibraryCacheError::NoTargetModulesResolved {
                        subscription_id,
                        datastore: ds_name.to_string().into_boxed_str(),
                    },
                )));
            }
            debug!(
                host=%host,
                subscription_id,
                %ds_name,
                modules = ?modules.iter().map(|m| m.name()).collect::<Vec<_>>(),
                "resolved target modules from subscription filter",
            );
            modules
        };

        let mut module_names = modules.iter().map(|x| x.name()).collect::<Vec<_>>();
        if !module_names.contains(&"ietf-subscribed-notifications") {
            module_names.push("ietf-subscribed-notifications");
        }
        debug!(
            peer_ip=%peer_ip,
            subscription_id,
            module_names=?module_names,
            "final module list requested from device for subscription",
        );
        // TODO: add timeout to loading YANG Library from the device
        let (yang_lib, schemas) = client
            .load_from_modules(&module_names, &PermissiveVersionChecker)
            .await
            .map_err(|err| Box::new((empty.clone(), err.into())))?;
        match tokio::time::timeout(cfg.timeout, client.close()).await {
            Ok(Ok(_)) => {
                info!(host=%host,"SSH connection closed successfully");
            }
            Ok(Err(err)) => warn!(host=%host, error=%err, "Error closing SSH connection"),
            Err(err) => {
                warn!(host=%host, error=%err, "Timeout while closing SSH connection")
            }
        }
        // Normalize the target xpath filter to the canonical module-name,
        // prefix-on-change form so the downstream pipeline sees one encoding
        // regardless of how the device reported it (xmlns-declared prefixes vs
        // module-name base context).
        if let Target::Datastore(datastore_target) = &mut subscription.target
            && let DatastoreSelectionFilterObjects::WithInSubscription(DatastoreFilterSpec::Xpath(
                xpath,
            )) = &mut datastore_target.selection
        {
            match xpath.normalize_path(|uri| {
                router_yang_library
                    .find_module_by_datastore_and_ns(&datastore_target.datastore, uri)
                    .map(|m| m.name().into())
            }) {
                Some(normalized) => {
                    if normalized.as_str() != xpath.path.as_ref() {
                        debug!(
                            subscription_id,
                            from = %xpath.path,
                            to = %normalized,
                            "normalized target xpath filter",
                        );
                    }
                    xpath.path = normalized.into_boxed_str();
                    xpath.namespaces = Box::new([]);
                }
                None => warn!(
                    subscription_id,
                    path = %xpath.path,
                    "could not normalize target xpath filter, keeping original",
                ),
            }
        }
        let subscription_target = subscription.target.try_into().map_err(|err| {
            Box::new((
                empty,
                YangLibraryCacheError::InvalidSubscriptionTarget(format!("{err}").into_boxed_str()),
            ))
        })?;
        let subscription_info = SubscriptionInfo::new(
            peer_ip,
            subscription_id,
            subscription_target,
            subscription.stop_time,
            subscription.transport,
            subscription.encoding,
            subscription.purpose,
            subscription.update_trigger,
            modules.into_boxed_slice(),
            router_yang_library.content_id().to_string(),
        );
        info!(
            host=%host,
            peer_ip=%peer_ip,
            subscription_id,
            router_content_id=subscription_info.content_id(),
            target=%subscription_info.target(),
            cached_content_id=yang_lib.content_id(),
            schema_count = schemas.len(),
            "YANG Library fetched from device",
        );
        Ok((subscription_info, yang_lib, schemas))
    }

    /// Retry `operation` with exponential backoff and equal jitter.
    ///
    /// `operation` is called up to `retry.max_retries + 1` times. Each failed
    /// attempt waits `base * 2^(attempt-1)` (capped at `retry.max_backoff`)
    /// with equal jitter before the next try.
    async fn with_retry<F, Fut>(peer_ip: IpAddr, retry: RetryConfig, operation: F) -> FetcherResult
    where
        F: Fn() -> Fut,
        Fut: Future<Output = FetcherResult>,
    {
        let mut last_err = None;
        for attempt in 0..=retry.max_retries {
            if attempt > 0 {
                let backoff_secs = BASE_DELAY.as_secs_f64() * 2.0_f64.powi(attempt as i32 - 1);
                let capped = backoff_secs.min(retry.max_backoff.as_secs_f64());
                let half = capped / 2.0;
                let jitter = rand::rng().random_range(0.0..=half);
                let delay = std::time::Duration::from_secs_f64(half + jitter);
                trace!(
                    %peer_ip,
                    attempt,
                    delay_ms = delay.as_millis() as u64,
                    "retrying YANG Library fetch after backoff",
                );
                tokio::time::sleep(delay).await;
            }
            match operation().await {
                Ok(result) => return Ok(result),
                Err(err) => last_err = Some(err),
            }
        }
        last_err.map(Err).unwrap()
    }
}

impl YangLibraryFetcher for NetconfYangLibraryFetcher {
    async fn fetch(
        &self,
        subscription_info: SubscriptionInfo,
        session: SessionInfo,
    ) -> JoinHandle<FetcherResult> {
        let fetch_cfg = self.fetch_cfg.clone();
        let retry_cfg = self.retry_cfg;
        tokio::spawn(async move {
            Self::with_retry(subscription_info.peer_ip(), retry_cfg, || {
                Self::fetch_from_device(&fetch_cfg, subscription_info.clone(), session.clone())
            })
            .await
        })
    }

    async fn fetch_blocking(
        &self,
        subscription_info: SubscriptionInfo,
        session: SessionInfo,
    ) -> FetcherResult {
        Self::with_retry(subscription_info.peer_ip(), self.retry_cfg, || {
            Self::fetch_from_device(&self.fetch_cfg, subscription_info.clone(), session.clone())
        })
        .await
    }

    async fn fetch_by_subscription_id(
        &self,
        session: SessionInfo,
        subscription_id: SubscriptionId,
    ) -> JoinHandle<FetcherResult> {
        let fetch_cfg = self.fetch_cfg.clone();
        let retry_cfg = self.retry_cfg;
        let peer_ip = session.peer().ip();
        tokio::spawn(async move {
            Self::with_retry(peer_ip, retry_cfg, || {
                Self::fetch_from_device_by_id(&fetch_cfg, session.clone(), subscription_id)
            })
            .await
        })
    }

    async fn fetch_by_subscription_id_blocking(
        &self,
        session: SessionInfo,
        subscription_id: SubscriptionId,
    ) -> FetcherResult {
        let peer_ip = session.peer().ip();
        Self::with_retry(peer_ip, self.retry_cfg, || {
            Self::fetch_from_device_by_id(&self.fetch_cfg, session.clone(), subscription_id)
        })
        .await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    #[allow(clippy::type_complexity)]
    pub(crate) struct TestYangLibFetcher {
        pub yang_libs: HashMap<SubscriptionInfo, (YangLibrary, HashMap<Box<str>, Box<str>>)>,
        /// for testing, the number of times a SubscriptionInfo has been fetched
        pub fetch_counts: Arc<Mutex<HashMap<SubscriptionInfo, usize>>>,
    }

    impl TestYangLibFetcher {
        #[allow(clippy::type_complexity)]
        pub(crate) fn new(
            yang_libs: HashMap<SubscriptionInfo, (YangLibrary, HashMap<Box<str>, Box<str>>)>,
        ) -> Self {
            for (subscription_info, (yang_lib, _schemas)) in &yang_libs {
                info!(
                    peer_ip=%subscription_info.peer_ip(),
                    subscription_id=subscription_info.id(),
                    router_content_id=subscription_info.content_id(),
                    target=%subscription_info.target(),
                    cached_content_id=yang_lib.content_id(),
                    "Fetcher stored YANG Library in cache",
                )
            }
            Self {
                yang_libs,
                fetch_counts: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn get_from_cache(&self, subscription_info: SubscriptionInfo) -> FetcherResult {
            info!(
                peer_ip=%subscription_info.peer_ip(),
                subscription_id=subscription_info.id(),
                router_content_id=subscription_info.content_id(),
                target=%subscription_info.target(),
                "fetching from device by subscription info"
            );
            // Increment counter in the instance state
            {
                let mut counts = self.fetch_counts.lock().unwrap();
                *counts.entry(subscription_info.clone()).or_default() += 1;
            }

            let (yang_lib, schemas) =
                self.yang_libs
                    .get(&subscription_info)
                    .cloned()
                    .ok_or_else(|| {
                        info!(
                            peer_ip=%subscription_info.peer_ip(),
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            target=%subscription_info.target(),
                            "YANG Library not found in cache"
                        );
                        Box::new((
                            subscription_info.clone(),
                            YangLibraryCacheError::IoError(std::io::Error::other("not found")),
                        ))
                    })?;
            Ok((subscription_info, yang_lib, schemas))
        }

        fn get_from_cache_by_id(&self, subscription_info: SubscriptionInfo) -> FetcherResult {
            let peer_ip = subscription_info.peer_ip();
            let subscription_id = subscription_info.id();
            info!(
                peer_ip=%peer_ip,
                subscription_id,
                "fetching from device by id"
            );
            let subscription_info = self
                .yang_libs
                .keys()
                .find(|x| x.id() == subscription_id && x.peer_ip() == peer_ip);
            let subscription_info = if let Some(subscription_info) = subscription_info {
                subscription_info.clone()
            } else {
                SubscriptionInfo::new_empty(peer_ip, subscription_id)
            };
            // Increment counter in the instance state
            {
                let mut counts = self.fetch_counts.lock().unwrap();
                *counts.entry(subscription_info.clone()).or_default() += 1;
            }
            if subscription_info.is_empty() {
                return Err(Box::new((
                    subscription_info,
                    YangLibraryCacheError::IoError(std::io::Error::other("not found")),
                )));
            }
            let (yang_lib, schemas) =
                self.yang_libs
                    .get(&subscription_info)
                    .cloned()
                    .ok_or_else(|| {
                        info!(
                            peer_ip=%subscription_info.peer_ip(),
                            subscription_id=subscription_info.id(),
                            router_content_id=subscription_info.content_id(),
                            target=%subscription_info.target(),
                            "YANG Library not found in cache"
                        );
                        Box::new((
                            subscription_info.clone(),
                            YangLibraryCacheError::IoError(std::io::Error::other("not found")),
                        ))
                    })?;
            Ok((subscription_info, yang_lib, schemas))
        }
    }

    impl YangLibraryFetcher for TestYangLibFetcher {
        async fn fetch(
            &self,
            subscription_info: SubscriptionInfo,
            _session: SessionInfo,
        ) -> JoinHandle<FetcherResult> {
            let result = self.get_from_cache(subscription_info);
            tokio::spawn(async move { result })
        }

        async fn fetch_blocking(
            &self,
            subscription_info: SubscriptionInfo,
            _session: SessionInfo,
        ) -> FetcherResult {
            self.get_from_cache(subscription_info)
        }

        async fn fetch_by_subscription_id(
            &self,
            session: SessionInfo,
            subscription_id: SubscriptionId,
        ) -> JoinHandle<FetcherResult> {
            let subscription_info =
                SubscriptionInfo::new_empty(session.peer().ip(), subscription_id);
            let result = self.get_from_cache_by_id(subscription_info);
            tokio::spawn(async move { result })
        }

        async fn fetch_by_subscription_id_blocking(
            &self,
            session: SessionInfo,
            subscription_id: SubscriptionId,
        ) -> FetcherResult {
            let subscription_info =
                SubscriptionInfo::new_empty(session.peer().ip(), subscription_id);
            self.get_from_cache_by_id(subscription_info)
        }
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use netcalyx_netconf_proto::yanglib::YangLibrary;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn retry_cfg(max_retries: u32) -> RetryConfig {
        RetryConfig::new(max_retries, std::time::Duration::from_millis(1))
    }

    fn dummy_peer_ip() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    fn make_ok() -> FetcherResult {
        let info = SubscriptionInfo::new_empty(dummy_peer_ip(), 1);
        let yang_lib = YangLibrary::new("test-content-id".into(), vec![], vec![], vec![]);
        Ok((info, yang_lib, HashMap::new()))
    }

    fn make_err(msg: &'static str) -> FetcherResult {
        let info = SubscriptionInfo::new_empty(dummy_peer_ip(), 1);
        Err(Box::new((
            info,
            YangLibraryCacheError::IoError(std::io::Error::other(msg)),
        )))
    }

    /// A single attempt that succeeds immediately — no retries should happen.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_succeeds_on_first_attempt() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        let result = NetconfYangLibraryFetcher::with_retry(dummy_peer_ip(), retry_cfg(5), || {
            let cc = Arc::clone(&cc);
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                make_ok()
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "should not retry on success"
        );
        assert!(
            !logs_contain("retrying YANG Library fetch after backoff"),
            "no backoff trace log should appear when succeeding on first attempt"
        );
    }

    /// max_retries = 0 means exactly one attempt; failure is returned
    /// immediately.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_no_retry_when_max_retries_zero() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        let result = NetconfYangLibraryFetcher::with_retry(dummy_peer_ip(), retry_cfg(0), || {
            let cc = Arc::clone(&cc);
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                make_err("always fails")
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "should try exactly once"
        );
        assert!(
            !logs_contain("retrying YANG Library fetch after backoff"),
            "no backoff trace log should appear with max_retries = 0"
        );
    }

    /// All attempts fail: the last error is returned and total calls ==
    /// max_retries + 1.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_all_retries_exhausted_returns_last_error() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);
        const MAX_RETRIES: u32 = 3;

        let result =
            NetconfYangLibraryFetcher::with_retry(dummy_peer_ip(), retry_cfg(MAX_RETRIES), || {
                let cc = Arc::clone(&cc);
                async move {
                    let n = cc.fetch_add(1, Ordering::SeqCst);
                    make_err(if n == MAX_RETRIES {
                        "last error"
                    } else {
                        "transient"
                    })
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            MAX_RETRIES + 1,
            "should attempt max_retries + 1 times total"
        );
        assert!(
            logs_contain("retrying YANG Library fetch after backoff"),
            "backoff trace log should appear for each retry"
        );
    }

    /// Succeeds on the N-th attempt — prior failures must not be surfaced.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_succeeds_after_transient_failures() {
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);
        const FAIL_FIRST: u32 = 2; // fail twice, succeed on the 3rd call

        let result = NetconfYangLibraryFetcher::with_retry(dummy_peer_ip(), retry_cfg(5), || {
            let cc = Arc::clone(&cc);
            async move {
                let n = cc.fetch_add(1, Ordering::SeqCst);
                if n < FAIL_FIRST {
                    make_err("transient")
                } else {
                    make_ok()
                }
            }
        })
        .await;

        assert!(result.is_ok(), "should ultimately succeed");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            FAIL_FIRST + 1,
            "should stop retrying once it succeeds"
        );
        assert!(
            logs_contain("retrying YANG Library fetch after backoff"),
            "backoff trace log should appear for the transient failures"
        );
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::*;
    use netcalyx_netconf_proto::yang_push::filters::DatastoreXPathFilter;
    use netcalyx_netconf_proto::yanglib::{Datastore, Module, ModuleSet, Schema, YangLibrary};

    fn empty_info() -> SubscriptionInfo {
        SubscriptionInfo::new_empty("127.0.0.1".parse().unwrap(), 1)
    }

    /// A single-datastore, single-module-set YANG Library fixture.
    /// `modules` are `(name, namespace)` pairs.
    fn make_yang_library(ds_name: DatastoreName, modules: &[(&str, &str)]) -> YangLibrary {
        let modules = modules
            .iter()
            .map(|(name, ns)| {
                Module::new(
                    (*name).into(),
                    None,
                    (*ns).into(),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                    Box::new([]),
                )
            })
            .collect();
        YangLibrary::new(
            "test-content-id".into(),
            vec![ModuleSet::new("modules".into(), modules, vec![])],
            vec![Schema::new("schema".into(), Box::new(["modules".into()]))],
            vec![Datastore::new(ds_name, "schema".into())],
        )
    }

    fn xpath_filter(namespaces: &[(&str, &str)], path: &str) -> DatastoreXPathFilter {
        DatastoreXPathFilter {
            namespaces: namespaces
                .iter()
                .map(|(p, ns)| ((*p).into(), (*ns).into()))
                .collect(),
            path: path.into(),
        }
    }

    /// Two datastores, each with its own schema/module-set pinning a
    /// different revision of the same module name.
    fn make_multi_datastore_yang_library() -> YangLibrary {
        let module = |revision: &str| {
            Module::new(
                "foo-mod".into(),
                Some(revision.into()),
                "urn:example:foo".into(),
                Box::new([]),
                Box::new([]),
                Box::new([]),
                Box::new([]),
                Box::new([]),
            )
        };
        YangLibrary::new(
            "test-content-id".into(),
            vec![
                ModuleSet::new("operational-set".into(), vec![module("2020-01-01")], vec![]),
                ModuleSet::new("running-set".into(), vec![module("2023-01-01")], vec![]),
            ],
            vec![
                Schema::new("op-schema".into(), Box::new(["operational-set".into()])),
                Schema::new("run-schema".into(), Box::new(["running-set".into()])),
            ],
            vec![
                Datastore::new(DatastoreName::Operational, "op-schema".into()),
                Datastore::new(DatastoreName::Running, "run-schema".into()),
            ],
        )
    }

    #[test]
    fn test_resolve_by_namespaces_resolves_each_namespace_to_a_module() {
        let yang_lib = make_yang_library(
            DatastoreName::Running,
            &[("if-mod", "urn:example:interfaces")],
        );
        let namespaces: Box<[(Box<str>, Box<str>)]> =
            Box::new([("if".into(), "urn:example:interfaces".into())]);

        let result = resolve_by_namespaces(
            &yang_lib,
            &DatastoreName::Running,
            &namespaces,
            &empty_info(),
        )
        .expect("namespace should resolve to a module");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name(), "if-mod");
    }

    #[test]
    fn test_resolve_by_namespaces_dedups_same_module_seen_twice() {
        // Two distinct namespace bindings resolving to the same module must
        // only appear once in the result (push_module dedup).
        let yang_lib = make_yang_library(
            DatastoreName::Running,
            &[("if-mod", "urn:example:interfaces")],
        );
        let namespaces: Box<[(Box<str>, Box<str>)]> = Box::new([
            ("a".into(), "urn:example:interfaces".into()),
            ("b".into(), "urn:example:interfaces".into()),
        ]);

        let result = resolve_by_namespaces(
            &yang_lib,
            &DatastoreName::Running,
            &namespaces,
            &empty_info(),
        )
        .expect("namespaces should resolve");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name(), "if-mod");
    }

    #[test]
    fn test_resolve_by_namespaces_unknown_namespace_is_a_hard_error() {
        let yang_lib = make_yang_library(DatastoreName::Running, &[]);
        let namespaces: Box<[(Box<str>, Box<str>)]> =
            Box::new([("if".into(), "urn:example:unknown".into())]);

        let err = resolve_by_namespaces(
            &yang_lib,
            &DatastoreName::Running,
            &namespaces,
            &empty_info(),
        )
        .expect_err("unknown namespace must not resolve");

        assert!(matches!(
            err.1,
            YangLibraryCacheError::ModuleNamespaceNotFound { .. }
        ));
    }

    /// Cisco IOS-XR style: no `xmlns` binding declared, prefix equals the
    /// YANG module name directly (RFC 8641 base XPath context).
    #[test]
    fn test_resolve_by_xpath_falls_back_to_module_name_when_undeclared() {
        let yang_lib = make_yang_library(
            DatastoreName::Running,
            &[(
                "Cisco-IOS-XR-procmem-oper",
                "urn:cisco:params:xml:ns:yang:procmem-oper",
            )],
        );
        let filter = xpath_filter(
            &[],
            "/Cisco-IOS-XR-procmem-oper:processes-memory/nodes/node",
        );

        let result = resolve_by_xpath(&yang_lib, &DatastoreName::Running, &filter, &empty_info())
            .expect("undeclared prefix should resolve as a module name");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name(), "Cisco-IOS-XR-procmem-oper");
    }

    /// The module-name fallback must scope its lookup to the target
    /// datastore, the same as the declared-namespace path does — not return
    /// whichever module-set happens to be first in the library. Regression
    /// test for a module name present, at different revisions, in two
    /// datastores' module sets.
    #[test]
    fn test_resolve_by_xpath_module_name_fallback_is_scoped_by_datastore() {
        let yang_lib = make_multi_datastore_yang_library();
        let filter = xpath_filter(&[], "/foo-mod:thing");

        let result = resolve_by_xpath(&yang_lib, &DatastoreName::Running, &filter, &empty_info())
            .expect("module name should resolve within the running datastore");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name(), "foo-mod");
        assert_eq!(result[0].revision(), Some("2023-01-01"));
    }

    /// Huawei style: `xmlns` binding declared on the filter takes precedence
    /// over treating the prefix as a module name.
    #[test]
    fn test_resolve_by_xpath_prefers_declared_namespace_binding() {
        let yang_lib = make_yang_library(
            DatastoreName::Running,
            &[("huawei-devm", "urn:huawei:yang:huawei-devm")],
        );
        let filter = xpath_filter(
            &[("devm", "urn:huawei:yang:huawei-devm")],
            "/devm:devm/devm:chassis",
        );

        let result = resolve_by_xpath(&yang_lib, &DatastoreName::Running, &filter, &empty_info())
            .expect("declared xmlns binding should resolve the module");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name(), "huawei-devm");
    }

    /// `hw-hwt` appears only inside the predicate literal, never as a
    /// node-name prefix; its module must still resolve into the fetch list.
    #[test]
    fn test_resolve_by_xpath_resolves_module_referenced_only_in_predicate_literal() {
        let yang_lib = make_yang_library(
            DatastoreName::Operational,
            &[
                ("ietf-hardware", "urn:ietf:params:xml:ns:yang:ietf-hardware"),
                ("huawei-hardware", "urn:huawei:yang:huawei-hardware"),
                (
                    "huawei-hardware-types",
                    "urn:huawei:yang:huawei-hardware-types",
                ),
                (
                    "bbf-hardware-transceivers",
                    "urn:bbf:yang:bbf-hardware-transceivers",
                ),
            ],
        );
        let filter = xpath_filter(
            &[
                ("hw", "urn:ietf:params:xml:ns:yang:ietf-hardware"),
                ("hw-hw", "urn:huawei:yang:huawei-hardware"),
                ("hw-hwt", "urn:huawei:yang:huawei-hardware-types"),
                ("bbf-hw-xcvr", "urn:bbf:yang:bbf-hardware-transceivers"),
            ],
            "/hw:hardware/hw:component[hw-hw:sub-class='hw-hwt:ethernetCsmacd-xcvr-link']/bbf-hw-xcvr:transceiver-link",
        );

        let mut result = resolve_by_xpath(
            &yang_lib,
            &DatastoreName::Operational,
            &filter,
            &empty_info(),
        )
        .expect("all modules, including the predicate-literal one, should resolve")
        .into_iter()
        .map(|m| m.name().to_string())
        .collect::<Vec<_>>();
        result.sort_unstable();

        assert_eq!(
            result,
            vec![
                "bbf-hardware-transceivers",
                "huawei-hardware",
                "huawei-hardware-types",
                "ietf-hardware",
            ]
        );
    }

    /// A literal that merely looks like a QName (e.g. an interface name
    /// `'ge:0'`) but has no declared `xmlns` binding must not be treated as
    /// a required module, or resolution fails just because no `ge` module
    /// exists.
    #[test]
    fn test_resolve_by_xpath_ignores_undeclared_literal_shaped_value() {
        let yang_lib = make_yang_library(
            DatastoreName::Operational,
            &[(
                "ietf-interfaces",
                "urn:ietf:params:xml:ns:yang:ietf-interfaces",
            )],
        );
        let filter = xpath_filter(
            &[("if", "urn:ietf:params:xml:ns:yang:ietf-interfaces")],
            "/if:interfaces/if:interface[if:name='ge:0']",
        );

        let result = resolve_by_xpath(
            &yang_lib,
            &DatastoreName::Operational,
            &filter,
            &empty_info(),
        )
        .expect("undeclared literal-shaped value must not fail resolution")
        .into_iter()
        .map(|m| m.name().to_string())
        .collect::<Vec<_>>();

        assert_eq!(result, vec!["ietf-interfaces"]);
    }

    #[test]
    fn test_resolve_by_xpath_multiple_distinct_prefixes_resolve_independently() {
        let yang_lib = make_yang_library(
            DatastoreName::Running,
            &[
                ("if-mod", "urn:example:interfaces"),
                ("rt-mod", "urn:example:routing"),
            ],
        );
        let filter = xpath_filter(
            &[
                ("if", "urn:example:interfaces"),
                ("rt", "urn:example:routing"),
            ],
            "/if:interfaces/if:interface | /rt:routing/rt:ribs",
        );

        let mut result =
            resolve_by_xpath(&yang_lib, &DatastoreName::Running, &filter, &empty_info())
                .expect("both prefixes should resolve")
                .into_iter()
                .map(|m| m.name().to_string())
                .collect::<Vec<_>>();
        result.sort_unstable();

        assert_eq!(result, vec!["if-mod", "rt-mod"]);
    }

    #[test]
    fn test_resolve_by_xpath_declared_namespace_not_in_library_is_a_hard_error() {
        let yang_lib = make_yang_library(DatastoreName::Running, &[]);
        let filter = xpath_filter(&[("devm", "urn:huawei:yang:huawei-devm")], "/devm:devm");

        let err = resolve_by_xpath(&yang_lib, &DatastoreName::Running, &filter, &empty_info())
            .expect_err("declared namespace missing from library must fail");

        assert!(matches!(
            err.1,
            YangLibraryCacheError::ModuleNamespaceNotFound { .. }
        ));
    }

    #[test]
    fn test_resolve_by_xpath_undeclared_prefix_not_a_module_name_is_a_hard_error() {
        let yang_lib = make_yang_library(DatastoreName::Running, &[]);
        let filter = xpath_filter(&[], "/bogus:interfaces");

        let err = resolve_by_xpath(&yang_lib, &DatastoreName::Running, &filter, &empty_info())
            .expect_err("prefix with no binding and no matching module must fail");

        assert!(matches!(
            err.1,
            YangLibraryCacheError::ModulePrefixNotFound(ref p) if p.as_ref() == "bogus"
        ));
    }
}
