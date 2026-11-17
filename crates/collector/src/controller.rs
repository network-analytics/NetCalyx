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

use crate::config::ControllerConfig;
use axum::extract::{Path, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use netcalyx_yang_push::validation::{
    ValidationActorError, ValidationActorHandle, ValidationActorHandleError, YangPushCacheSnapshot,
};
use serde::Serialize;
use std::net::IpAddr;
use std::time::Instant;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// Shared state of the controller API handlers.
#[derive(Debug, Clone)]
struct ControllerState {
    validation_handle: ValidationActorHandle,
    stats: ControllerStats,
    access_token: String,
}

/// OpenTelemetry metrics of the controller API.
#[derive(Debug, Clone)]
struct ControllerStats {
    received: opentelemetry::metrics::Counter<u64>,
    replied: opentelemetry::metrics::Counter<u64>,
    client_errors: opentelemetry::metrics::Counter<u64>,
    server_errors: opentelemetry::metrics::Counter<u64>,
    get_cache_duration: opentelemetry::metrics::Histogram<f64>,
    clear_cache_duration: opentelemetry::metrics::Histogram<f64>,
}

impl ControllerStats {
    fn new(meter: opentelemetry::metrics::Meter) -> Self {
        let received = meter
            .u64_counter("netcalyx.controller.received")
            .with_description("Number of HTTP requests received by the controller API")
            .build();
        let replied = meter
            .u64_counter("netcalyx.controller.replied")
            .with_description("Number of HTTP responses sent by the controller API")
            .build();
        let client_errors = meter
            .u64_counter("netcalyx.controller.client_errors")
            .with_description("Number of controller API responses with a client error (4xx)")
            .build();
        let server_errors = meter
            .u64_counter("netcalyx.controller.server_errors")
            .with_description("Number of controller API responses with a server error (5xx)")
            .build();
        let get_cache_duration = meter
            .f64_histogram("netcalyx.controller.get_cache.duration")
            .with_description("Duration of controller API requests fetching the YANG-Push cache")
            .with_unit("s")
            .with_boundaries(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .build();
        let clear_cache_duration = meter
            .f64_histogram("netcalyx.controller.clear_cache.duration")
            .with_description("Duration of controller API requests clearing the YANG-Push cache")
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

/// Errors returned by the controller handlers. Internal error details are
/// only logged, not sent to the client.
#[derive(Debug, strum_macros::Display)]
enum ControllerError {
    #[strum(to_string = "Failed to fetch YANG-Push cache")]
    GetCache(ValidationActorHandleError),
    #[strum(to_string = "Failed to clear YANG-Push cache")]
    ClearCache(ValidationActorHandleError),
}

/// JSON body returned for failed controller requests.
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for ControllerError {
    fn into_response(self) -> Response {
        let (ControllerError::GetCache(err) | ControllerError::ClearCache(err)) = &self;
        let (status, message) = match err {
            ValidationActorHandleError::ActorErr(ValidationActorError::PeerNotFound(_)) => {
                (StatusCode::NOT_FOUND, err.to_string())
            }
            _ => {
                error!(error = %err, "{self}");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

/// Spawns the HTTPS controller REST API.
pub fn spawn(
    config: &ControllerConfig,
    validation_handle: ValidationActorHandle,
    meter: opentelemetry::metrics::Meter,
) -> JoinHandle<()> {
    let config = config.clone();
    tokio::spawn(async move {
        let address = config.address;
        if let Err(err) = serve(config, validation_handle, meter).await {
            error!(error = %err, %address, "Controller API failed");
        }
    })
}

async fn serve(
    config: ControllerConfig,
    validation_handle: ValidationActorHandle,
    meter: opentelemetry::metrics::Meter,
) -> std::io::Result<()> {
    let address = config.address;
    let stats = ControllerStats::new(meter);
    let state = ControllerState {
        validation_handle,
        stats,
        access_token: config.access_token,
    };

    let app = Router::new()
        .route(
            "/yang-push-cache",
            get(get_yang_push_cache).delete(clear_yang_push_cache),
        )
        .route(
            "/yang-push-cache/{peer_ip}",
            get(get_yang_push_cache).delete(clear_yang_push_cache),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authorize_controller_request,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            record_controller_metrics,
        ))
        .with_state(state);

    let tls_config =
        RustlsConfig::from_pem_file(&config.tls_cert_path, &config.tls_key_path).await?;
    info!(%address, "HTTPS controller API listening");
    axum_server::bind_rustls(address, tls_config)
        .serve(app.into_make_service())
        .await
}

async fn record_controller_metrics(
    State(state): State<ControllerState>,
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
async fn authorize_controller_request(
    State(state): State<ControllerState>,
    req: Request,
    next: Next,
) -> Response {
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match provided {
        Some(token)
            if constant_time_eq::constant_time_eq(
                token.as_bytes(),
                state.access_token.as_bytes(),
            ) =>
        {
            next.run(req).await
        }
        _ => {
            warn!("Rejected unauthorized controller API request");
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                Json(ErrorResponse {
                    error: "Unauthorized".to_string(),
                }),
            )
                .into_response()
        }
    }
}

async fn get_yang_push_cache(
    peer_ip: Option<Path<IpAddr>>,
    State(state): State<ControllerState>,
) -> Result<Json<YangPushCacheSnapshot>, ControllerError> {
    let peer_ip = peer_ip.map(|Path(peer_ip)| peer_ip);
    state
        .validation_handle
        .get_yang_push_cache(peer_ip)
        .await
        .map(Json)
        .map_err(ControllerError::GetCache)
}

async fn clear_yang_push_cache(
    peer_ip: Option<Path<IpAddr>>,
    State(state): State<ControllerState>,
) -> Result<Json<Vec<IpAddr>>, ControllerError> {
    let peer_ip = peer_ip.map(|Path(peer_ip)| peer_ip);
    state
        .validation_handle
        .clear_yang_push_cache(peer_ip)
        .await
        .map(Json)
        .map_err(ControllerError::ClearCache)
}
