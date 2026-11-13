# Copyright (C) 2026-present The NetCalyx Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Container image for netcalyx-collector, built from this checkout.
#
# Run the commands below from the repository root. The collector depends on
# other workspace crates, so the build context is the whole workspace.
#
# Build for the host architecture:
#
#   docker build -f crates/collector/Dockerfile -t netcalyx-collector .
#
# Build for linux/amd64 and linux/arm64 in one go. The foreign architecture
# runs under QEMU and takes much longer than the native one:
#
#   docker buildx build -f crates/collector/Dockerfile --platform linux/amd64,linux/arm64 -t netcalyx-collector .
#
# Run with a config file mounted from the host:
#
#   docker run --rm --network host \
#     -v "/path/to/config.yaml:/etc/netcalyx/config.yaml:ro" \
#     netcalyx-collector /etc/netcalyx/config.yaml
#
# Each architecture builds natively. libyang and librdkafka are compiled
# from source through cmake, which does not cross-compile without a sysroot
# for the target.

FROM rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS base
WORKDIR /src
# cmake builds librdkafka and the bundled libyang, which links against pcre2.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cmake pkg-config libpcre2-dev \
 && rm -rf /var/lib/apt/lists/*
# cargo-chef caches the dependency build as its own layer, so a change to
# NetCalyx's own sources rebuilds only the workspace crates.
RUN cargo install cargo-chef --locked --version 0.1.78

FROM base AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM base AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --package netcalyx-collector --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --package netcalyx-collector \
 && strip target/release/netcalyx-collector

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime
LABEL org.opencontainers.image.title="netcalyx-collector" \
      org.opencontainers.image.description="NetCalyx network telemetry collector" \
      org.opencontainers.image.source="https://github.com/network-analytics/NetCalyx" \
      org.opencontainers.image.licenses="Apache-2.0"
# ca-certificates: TLS to Kafka, the schema registry and HTTP publishers.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --user-group --no-create-home --home-dir /var/lib/netcalyx netcalyx \
 && install -d -o netcalyx -g netcalyx /var/lib/netcalyx
COPY --from=builder /src/target/release/netcalyx-collector /usr/bin/netcalyx-collector
COPY --from=builder /src/LICENSE /src/NOTICE /usr/share/doc/netcalyx-collector/
USER netcalyx
# The only directory the netcalyx user can write to. Point cache_location
# here or mount a volume for it; the collector does not create it.
WORKDIR /var/lib/netcalyx
ENTRYPOINT ["netcalyx-collector"]
