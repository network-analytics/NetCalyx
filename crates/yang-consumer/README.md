# NetCalyx YANG Consumer

A CLI utility that consumes YANG-encoded telemetry messages from Kafka
and validates them against YANG schemas stored in a Schema Registry.

## Features

- Consumes messages from a Kafka topic with configurable partitions and offsets
- Fetches YANG schemas (including dependencies) from a Schema Registry
- Builds and caches YANG Library contexts for validation
- Validates message payloads against their associated YANG schemas
- Supports tail mode to read the last N messages per partition
- Supports follow mode to continuously consume new messages

## Installation

```bash
cargo install netcalyx-yang-consumer
```

Or build from source:

```bash
git clone https://github.com/network-analytics/NetCalyx.git
cd NetCalyx
cargo build --release -p netcalyx-yang-consumer
```

## CLI Usage

```bash
netcalyx-yang-consumer --help
```

Logging is controlled via the `RUST_LOG` environment variable (defaults to `info`).

### Examples

Follow a topic on a local plaintext broker:

```bash
RUST_LOG=netcalyx_yang_consumer=info,info \
    ./target/debug/netcalyx-yang-consumer \
      -b localhost:9092 \
      -s http://localhost:8081 \
      --group my-consumer-group \
      -t telemetry-message-yang \
      -f
```

Read the last 1000 messages using a librdkafka config file (e.g. for an
authenticated broker) and a remote Schema Registry:

```bash
RUST_LOG=netcalyx_yang_consumer=info,info \
    ./target/debug/netcalyx-yang-consumer \
      -c librdkafka.json \
      -s http://schema-registry.example.com/ \
      --group my-consumer-group \
      -t device-yang-raw \
      -n 1000
```

### librdkafka config files

Any [librdkafka configuration property](https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md)
can be passed via `--config-file` as a flat JSON object.

CLI flags
(`--bootstrap-servers`, `--group`) take precedence over values set here.

SASL over SSL (e.g. AWS MSK):

```json
{
  "security.protocol": "SASL_SSL",
  "sasl.mechanism": "SCRAM-SHA-512",
  "sasl.username": "<username>",
  "sasl.password": "<password>",
  "metadata.broker.list": "broker-1.example.com:9096,broker-2.example.com:9096"
}
```

Mutual TLS with client certificates:

```json
{
  "security.protocol": "ssl",
  "ssl.certificate.location": "/path/to/cert.crt",
  "ssl.key.location": "/path/to/client.key",
  "ssl.ca.location": "/path/to/root_ca.crt",
  "metadata.broker.list": "kafka.example.com:9093"
}
```
