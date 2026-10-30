# Analytics observability fault and capacity probes

This directory owns black-box evidence for the OBS-02/03/05/06/11 analytics
path. The probes do not replace product tests and do not use an in-process
store. They use disposable ClickHouse and NATS containers and read production
migrations at runtime.

Frozen contract:

- ClickHouse `clickhouse/clickhouse-server:25.3.6.56-alpine`
- access/security raw TTL: 30/90 days, monthly partitions
- snapshot keyset order: `(occurred_at, event_id) DESC`
- NATS subject: `cdnca.analytics.ingest.v1.<node>`
- authoritative headers: `Nats-Msg-Id`, `Cdnca-Node-Id`,
  `Cdnca-Tenant-Id`, `Cdnca-Site-Id`, `Cdnca-Config-Version-Id`, and
  `Cdnca-Installation-Id`
- ingest recovery: 99% within 60 seconds; query p95 at most 2 seconds and p99
  at most 5 seconds
- ACK response loss: one committed ACK response is discarded, the connection is
  closed, and only the remaining unacknowledged deliveries may redeliver
- sensitive values: zero occurrences in the transmitted event, ClickHouse raw
  rows, API response, and task output

Run all probes:

```sh
tests/analytics-observability/run.sh
```

Useful overrides:

```sh
OBS_CAPACITY_ROWS=100000 OBS_QUERY_SAMPLES=100 OBS_QUERY_CONCURRENCY=8 \
  tests/analytics-observability/clickhouse_smoke.sh
```

Exit `77` means a required local executable or fixed image could not be made
available. A discovered migration or runtime contract mismatch exits `1`.
`run.sh` executes every probe and returns failure if any probe fails, while
preserving `77` only when every non-passing probe was skipped.

The chain wrapper runs the existing real Edge/Gateway/NATS transport smoke and
the real NATS/control/ClickHouse integration against the same fixed service
versions. It must not be interpreted as a single-message end-to-end proof
unless the wire audit also passes. In particular, capture fields cannot be
invented in this test directory to bypass a strict production v1 decoder.
