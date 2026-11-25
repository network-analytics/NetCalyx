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

use crate::config::AdminApiConfig;
use anyhow::anyhow;
use axum::extract::{Path, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use netcalyx_yang_push::validation::{
    ClearCacheReport, ValidationActorError, ValidationActorHandle, ValidationActorHandleError,
    YangPushCacheSnapshot,
};
use serde::Serialize;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tracing::{error, info, warn};

/// Actor handles across all UDP-Notif pipelines, grouped by actor type. Set
/// once after pipeline setup; `None` if no actor is configured.
#[derive(Debug, Clone, Default)]
pub struct UdpNotifHandles {
    pub validation: Arc<OnceLock<Option<ValidationActorHandle>>>,
}

/// Actor handles the admin API operates on, grouped by pipeline types.
#[derive(Debug, Clone, Default)]
pub struct AdminApiHandles {
    pub udp_notif_pipelines: UdpNotifHandles,
}

/// Shared state of the admin API handlers.
#[derive(Debug, Clone)]
struct AdminApiState {
    handles: AdminApiHandles,
    stats: AdminApiStats,
    access_token: String,
}

/// OpenTelemetry metrics of the admin API.
#[derive(Debug, Clone)]
struct AdminApiStats {
    received: opentelemetry::metrics::Counter<u64>,
    replied: opentelemetry::metrics::Counter<u64>,
    client_errors: opentelemetry::metrics::Counter<u64>,
    server_errors: opentelemetry::metrics::Counter<u64>,
    get_cache_duration: opentelemetry::metrics::Histogram<f64>,
    clear_cache_duration: opentelemetry::metrics::Histogram<f64>,
}

impl AdminApiStats {
    fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netcalyx.admin_api.received")
            .with_description("Number of HTTP requests received by the admin API")
            .build();
        let replied = meter
            .u64_counter("netcalyx.admin_api.replied")
            .with_description("Number of HTTP responses sent by the admin API")
            .build();
        let client_errors = meter
            .u64_counter("netcalyx.admin_api.client_errors")
            .with_description("Number of admin API responses with a client error (4xx)")
            .build();
        let server_errors = meter
            .u64_counter("netcalyx.admin_api.server_errors")
            .with_description("Number of admin API responses with a server error (5xx)")
            .build();
        let get_cache_duration = meter
            .f64_histogram("netcalyx.admin_api.get_cache.duration")
            .with_description("Duration of admin API requests fetching the YANG-Push cache")
            .with_unit("s")
            .with_boundaries(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .build();
        let clear_cache_duration = meter
            .f64_histogram("netcalyx.admin_api.clear_cache.duration")
            .with_description("Duration of admin API requests clearing the YANG-Push cache")
            .with_unit("s")
            .with_boundaries(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .build();
        Self {
            received,
            replied,
            client_errors,
            server_errors,
            get_cache_duration,
            clear_cache_duration,
        }
    }
}

/// Errors returned by the admin API handlers. Internal error details are
/// only logged, not sent to the client.
#[derive(Debug, strum_macros::Display)]
enum AdminApiError {
    #[strum(to_string = "Failed to fetch YANG-Push cache")]
    GetCache(ValidationActorHandleError),

    #[strum(to_string = "Failed to clear YANG-Push cache")]
    ClearCache(ValidationActorHandleError),

    #[strum(to_string = "Validation actor not available")]
    ValidationActorNotAvailable,
}

/// JSON body returned for failed admin API requests.
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for AdminApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AdminApiError::GetCache(err) | AdminApiError::ClearCache(err) => match err {
                ValidationActorHandleError::ActorErr(ValidationActorError::PeerNotFound(_)) => {
                    (StatusCode::NOT_FOUND, err.to_string())
                }

                ValidationActorHandleError::ActorErr(ValidationActorError::SchemaFetchPending(
                    _,
                )) => (StatusCode::CONFLICT, err.to_string()),

                _ => {
                    error!(error = %err, "{self}");
                    (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
                }
            },

            AdminApiError::ValidationActorNotAvailable => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
        };
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

/// Runs the HTTPS admin REST API.
pub async fn serve(
    config: AdminApiConfig,
    handles: AdminApiHandles,
    meter: opentelemetry::metrics::Meter,
) -> anyhow::Result<()> {
    let address = config.address;
    let stats = AdminApiStats::new(meter);
    let state = AdminApiState {
        handles,
        stats,
        access_token: config.access_token,
    };

    let app = router(state);

    let tls_config = RustlsConfig::from_pem_file(&config.tls_cert_path, &config.tls_key_path)
        .await
        .map_err(|err| anyhow!("Error loading Admin API TLS certificate and key: {err}"))?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .and_then(tokio::net::TcpListener::into_std)
        .map_err(|err| anyhow!("Error binding Admin API to {address}: {err}"))?;
    info!(%address, "HTTPS admin API listening");
    axum_server::from_tcp_rustls(listener, tls_config)?
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

fn router(state: AdminApiState) -> Router {
    let v1 = v1_routes().layer(middleware::from_fn_with_state(
        state.clone(),
        record_admin_api_metrics,
    ));
    Router::new()
        .nest("/v1", v1)
        .route("/health", get(health))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authorize_admin_api_request,
        ))
        .with_state(state)
}

fn v1_routes() -> Router<AdminApiState> {
    Router::new()
        .route(
            "/yang-push/cache",
            get(get_yang_push_cache).delete(clear_yang_push_cache),
        )
        .route(
            "/yang-push/cache/{peer_ip}",
            get(get_yang_push_cache).delete(clear_yang_push_cache),
        )
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn record_admin_api_metrics(
    State(state): State<AdminApiState>,
    req: Request,
    next: Next,
) -> Response {
    let stats = &state.stats;
    let duration = match *req.method() {
        Method::GET => Some(&stats.get_cache_duration),
        Method::DELETE => Some(&stats.clear_cache_duration),
        _ => None,
    };
    stats.received.add(1, &[]);
    let start = Instant::now();

    let response = next.run(req).await;

    if let Some(duration) = duration {
        duration.record(start.elapsed().as_secs_f64(), &[]);
    }

    stats.replied.add(1, &[]);
    if response.status().is_client_error() {
        stats.client_errors.add(1, &[]);
    } else if response.status().is_server_error() {
        stats.server_errors.add(1, &[]);
    }

    response
}

/// Rejects requests without a valid `Authorization: Bearer <token>` header.
async fn authorize_admin_api_request(
    State(state): State<AdminApiState>,
    req: Request,
    next: Next,
) -> Response {
    let reason = match req.headers().get(header::AUTHORIZATION) {
        None => "missing_authorization_header",
        Some(value) => match value.to_str().ok().and_then(|v| v.strip_prefix("Bearer ")) {
            None => "malformed_authorization_header",

            Some(token)
                if constant_time_eq::constant_time_eq(
                    token.as_bytes(),
                    state.access_token.as_bytes(),
                ) =>
            {
                return next.run(req).await;
            }

            Some(_) => "invalid_token",
        },
    };

    // Only the path is logged, the query string is not.
    warn!(
        method = %req.method(),
        path = req.uri().path(),
        reason,
        "Rejected unauthorized admin API request"
    );
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(ErrorResponse {
            error: "Unauthorized".to_string(),
        }),
    )
        .into_response()
}

async fn get_yang_push_cache(
    peer_ip: Option<Path<IpAddr>>,
    State(state): State<AdminApiState>,
) -> Result<Json<YangPushCacheSnapshot>, AdminApiError> {
    let peer_ip = peer_ip.map(|Path(peer_ip)| peer_ip);
    match state
        .handles
        .udp_notif_pipelines
        .validation
        .get()
        .and_then(Option::as_ref)
    {
        Some(handle) => handle
            .get_yang_push_cache(peer_ip)
            .await
            .map(Json)
            .map_err(AdminApiError::GetCache),
        None => Err(AdminApiError::ValidationActorNotAvailable),
    }
}

async fn clear_yang_push_cache(
    peer_ip: Option<Path<IpAddr>>,
    State(state): State<AdminApiState>,
) -> Result<Json<ClearCacheReport>, AdminApiError> {
    let peer_ip = peer_ip.map(|Path(peer_ip)| peer_ip);
    match state
        .handles
        .udp_notif_pipelines
        .validation
        .get()
        .and_then(Option::as_ref)
    {
        Some(handle) => {
            let report = handle
                .clear_yang_push_cache(peer_ip)
                .await
                .map_err(AdminApiError::ClearCache)?;
            info!(
                peer = peer_ip.map_or_else(|| "all".to_string(), |ip| ip.to_string()),
                cleared_peers = ?report.cleared_peers,
                skipped_peers = ?report.skipped_peers,
                "YANG-Push cache cleared via admin API"
            );
            Ok(Json(report))
        }
        None => Err(AdminApiError::ValidationActorNotAvailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use netcalyx_udp_notif_service::UdpNotifRequest;
    use tower::ServiceExt;

    const TOKEN: &str = "secret";

    /// Router without a configured validation actor.
    fn app() -> Router {
        app_with(None)
    }

    /// Router backed by a real validation actor with an empty cache. Get/clear
    /// behaviour is tested in the validation actor, the route tests only
    /// check that the right actor method is called.
    fn app_with_actor() -> (Router, async_channel::Sender<Arc<UdpNotifRequest>>) {
        let (udp_notif_tx, udp_notif_rx) = async_channel::bounded(1);
        let (validated_tx, _validated_rx) = async_channel::bounded(1);
        let (cache_cmd_tx, _cache_cmd_rx) = async_channel::bounded(1);
        let (_join_handle, handle) = ValidationActorHandle::new(
            1,
            1,
            1,
            true,
            udp_notif_rx,
            validated_tx,
            cache_cmd_tx,
            either::Left(opentelemetry::global::meter("test")),
        )
        .unwrap();
        (app_with(Some(handle)), udp_notif_tx)
    }

    fn app_with(validation: Option<ValidationActorHandle>) -> Router {
        let handles = AdminApiHandles::default();
        handles
            .udp_notif_pipelines
            .validation
            .set(validation)
            .unwrap();
        router(AdminApiState {
            handles,
            stats: AdminApiStats::new(opentelemetry::global::meter("test")),
            access_token: TOKEN.to_string(),
        })
    }

    fn request(method: Method, uri: &str, authorization: Option<&str>) -> Request {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn bearer() -> String {
        format!("Bearer {TOKEN}")
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn error_message(response: Response) -> String {
        body_json(response).await["error"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn test_admin_api_health_with_valid_token() {
        let response = app()
            .oneshot(request(Method::GET, "/health", Some(&bearer())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_api_missing_token_unauthorized() {
        let response = app()
            .oneshot(request(Method::GET, "/health", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(error_message(response).await, "Unauthorized");
    }

    #[tokio::test]
    async fn test_admin_api_wrong_token_unauthorized() {
        let response = app()
            .oneshot(request(Method::GET, "/health", Some("Bearer wrong")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_api_cache_without_validation_actor_unavailable() {
        let response = app()
            .oneshot(request(Method::GET, "/v1/yang-push/cache", Some(&bearer())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            error_message(response).await,
            "Validation actor not available"
        );
    }

    #[tokio::test]
    async fn test_admin_api_invalid_ip_format_bad_request() {
        let response = app()
            .oneshot(request(
                Method::GET,
                "/v1/yang-push/cache/not-an-ip",
                Some(&bearer()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_admin_api_error_mapping() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let cases = [
            (
                AdminApiError::ClearCache(ValidationActorHandleError::ActorErr(
                    ValidationActorError::SchemaFetchPending(ip),
                )),
                StatusCode::CONFLICT,
                "Cannot clear cache for peer 192.0.2.1: schema fetch pending",
            ),
            // Internal error details must not reach the client.
            (
                AdminApiError::GetCache(ValidationActorHandleError::SendErr),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch YANG-Push cache",
            ),
            (
                AdminApiError::ClearCache(ValidationActorHandleError::ReceiveErr),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to clear YANG-Push cache",
            ),
        ];
        for (error, status, message) in cases {
            let response = error.into_response();
            assert_eq!(response.status(), status);
            assert_eq!(error_message(response).await, message);
        }
    }

    #[tokio::test]
    async fn test_admin_api_get_cache_routes() {
        let (app, _udp_notif_tx) = app_with_actor();

        let response = app
            .clone()
            .oneshot(request(Method::GET, "/v1/yang-push/cache", Some(&bearer())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await, serde_json::json!({}));

        let response = app
            .oneshot(request(
                Method::GET,
                "/v1/yang-push/cache/192.0.2.1",
                Some(&bearer()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            error_message(response).await,
            "Peer 192.0.2.1 not found in YANG-Push cache"
        );
    }

    #[tokio::test]
    async fn test_admin_api_clear_cache_routes() {
        let (app, _udp_notif_tx) = app_with_actor();

        let response = app
            .clone()
            .oneshot(request(
                Method::DELETE,
                "/v1/yang-push/cache",
                Some(&bearer()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({"cleared_peers": [], "skipped_peers": []})
        );

        let response = app
            .oneshot(request(
                Method::DELETE,
                "/v1/yang-push/cache/192.0.2.1",
                Some(&bearer()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            error_message(response).await,
            "Peer 192.0.2.1 not found in YANG-Push cache"
        );
    }
}
