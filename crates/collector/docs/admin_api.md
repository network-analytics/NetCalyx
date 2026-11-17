# Admin API architecture

The collector can run an optional HTTPS admin API for inspecting and managing
pipeline state. It currently exposes the YANG-Push validation actor's peer
cache, which contains per-peer and per-subscription state.

## Actor handles

The API holds handles to configured actors and routes each request to the
appropriate actor. The handles are:

- **Grouped** by pipeline type, then actor type.
- **Optional**, because actors depend on the configured pipelines and
  publishers.
- **Currently limited** to one UDP-Notif validation actor. If multiple
  validation actors exist, only the first created actor is exposed, and
  requests operate only on its peer cache.

Pipeline setup publishes the handle after creating the actors. If no handle is
available, including while setup is still in progress, cache requests return
`503 Service Unavailable`.

The API sends commands through the handle and waits for the actor's response.
The validation actor owns and modifies the peer cache; clearing it does not
clear the schema cache.

```text
HTTPS request -> authentication -> API handler -> UDP-Notif validation handle
                                               -> validation actor -> peer cache
```

## Configuration and authentication

Configure the optional top-level `admin_api` section in the collector
configuration:

```yaml
admin_api:
  address: "127.0.0.1:3000"
  tls_cert_path: "/path/to/certificate-chain.pem"
  tls_key_path: "/path/to/private-key.pem"
  access_token: "<non-empty-secret>"
```

Omitting the section disables the API. The certificate chain and private key
must be PEM encoded. The access token must not be empty or whitespace-only.
Every request, including the health check, must include
`Authorization: Bearer <token>`. Missing, malformed, or invalid credentials
receive `401 Unauthorized`.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | Returns `200 OK` when the API responds. |
| GET | `/v1/yang-push/cache` | Returns a snapshot of all cached peers. |
| GET | `/v1/yang-push/cache/{peer_ip}` | Returns a snapshot of the specified peer. |
| DELETE | `/v1/yang-push/cache` | Clears all eligible peers. |
| DELETE | `/v1/yang-push/cache/{peer_ip}` | Clears the specified peer. |

`peer_ip` is an IPv4 or IPv6 address. GET returns JSON grouped by peer IP and
subscription ID. Each subscription snapshot contains its cached content ID,
subscription information, buffered packet count, and schema-fetch status; it
does not include the YANG context or buffered packets.

DELETE returns JSON with `cleared_peers` and `skipped_peers` arrays. When
clearing all peers, peers with a schema fetch in progress are retained and
reported as skipped. Clearing a specific peer with a pending fetch returns
`409 Conflict` without clearing it.

A specific peer that is not in the cache returns `404 Not Found`; an invalid IP
address returns `400 Bad Request`. Actor communication failures return
`500 Internal Server Error`, with details logged rather than exposed to the
client.

## Metrics

For authenticated requests to the versioned cache endpoints, the API records
the following OpenTelemetry metrics:

| Metric | Description |
| --- | --- |
| `netcalyx.admin_api.received` | Requests received. |
| `netcalyx.admin_api.replied` | Responses sent. |
| `netcalyx.admin_api.client_errors` | Responses with a 4xx status. |
| `netcalyx.admin_api.server_errors` | Responses with a 5xx status. |
| `netcalyx.admin_api.get_cache.duration` | GET request duration in seconds. |
| `netcalyx.admin_api.clear_cache.duration` | DELETE request duration in seconds. |

The duration metrics are histograms. Authentication failures and the health
endpoint are outside the versioned routes' metrics middleware.