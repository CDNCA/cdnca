-- P0080: bind this migration to the frozen security-event-state authority.
-- predecessor_up_sha256=ad2680f3507124b164d4e45096064ff0aeb9b1e42ab3bafe99396e1f3453dd12
-- predecessor_down_sha256=599d45fd70ab13a9d733ca30f43b0a22c1e22b3e8cf1aeb0b80a7e93d0fa5be2

ALTER TABLE access_events
    ADD COLUMN IF NOT EXISTS listen_port UInt16 DEFAULT 0 AFTER host;

CREATE TABLE IF NOT EXISTS site_realtime_access_facts_v1
(
    metric_version UInt16,
    tenant_id UUID,
    site_id UUID,
    event_id String,
    occurred_at DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC'),
    host String,
    listen_port UInt16,
    cache_status LowCardinality(String),
    upstream_result LowCardinality(String),
    status_code UInt16,
    request_bytes UInt64,
    response_bytes UInt64,
    duration_us UInt64,
    origin_connect_us Nullable(UInt64),
    origin_first_byte_us Nullable(UInt64),
    origin_total_us Nullable(UInt64),
    source_watermark UInt64,
    finalized_through DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, site_id, event_id)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS site_realtime_access_facts_mv_v1
TO site_realtime_access_facts_v1 AS
SELECT
    metric_version, tenant_id, site_id, event_id, occurred_at, ingested_at, lower(host), listen_port,
    cache_status, upstream_result, status_code, request_bytes, response_bytes, duration_us,
    origin_connect_us, origin_first_byte_us, origin_total_us,
    toUInt64(toUnixTimestamp64Milli(ingested_at)) AS source_watermark,
    ingested_at AS finalized_through
FROM access_events;

INSERT INTO site_realtime_access_facts_v1
SELECT
    metric_version, tenant_id, site_id, event_id, occurred_at, ingested_at, lower(host), listen_port,
    cache_status, upstream_result, status_code, request_bytes, response_bytes, duration_us,
    origin_connect_us, origin_first_byte_us, origin_total_us,
    toUInt64(toUnixTimestamp64Milli(ingested_at)), ingested_at
FROM access_events FINAL;
