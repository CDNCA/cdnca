CREATE TABLE IF NOT EXISTS access_hourly_facts_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    occurred_at DateTime64(3, 'UTC'),
    hour DateTime('UTC'),
    site_id UUID,
    node_id UUID,
    status_code UInt16,
    request_bytes UInt64,
    response_bytes UInt64,
    ingested_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, event_id)
TTL hour + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 10000;

CREATE TABLE IF NOT EXISTS security_hourly_facts_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    occurred_at DateTime64(3, 'UTC'),
    hour DateTime('UTC'),
    site_id UUID,
    node_id UUID,
    event_type LowCardinality(String),
    action LowCardinality(String),
    request_bytes UInt64,
    response_bytes UInt64,
    ingested_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, event_id)
TTL hour + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 10000;

CREATE MATERIALIZED VIEW IF NOT EXISTS access_hourly_mv_v1
TO access_hourly_facts_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    site_id,
    node_id,
    status_code,
    request_bytes,
    response_bytes,
    ingested_at
FROM access_events;

CREATE MATERIALIZED VIEW IF NOT EXISTS security_hourly_mv_v1
TO security_hourly_facts_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    site_id,
    node_id,
    event_type,
    action,
    request_bytes,
    response_bytes,
    ingested_at
FROM security_events;

INSERT INTO access_hourly_facts_v1
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC'),
    site_id,
    node_id,
    status_code,
    request_bytes,
    response_bytes,
    ingested_at
FROM access_events FINAL;

INSERT INTO security_hourly_facts_v1
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC'),
    site_id,
    node_id,
    event_type,
    action,
    request_bytes,
    response_bytes,
    ingested_at
FROM security_events FINAL;

CREATE OR REPLACE VIEW access_hourly_v1 AS
SELECT
    metric_version,
    tenant_id,
    site_id,
    node_id,
    hour,
    status_code,
    count() AS request_count,
    sum(request_bytes) AS request_bytes,
    sum(response_bytes) AS response_bytes,
    request_bytes + response_bytes AS total_bytes,
    response_bytes * 8.0 / 3600.0 AS average_bandwidth_bps
FROM access_hourly_facts_v1 FINAL
GROUP BY metric_version, tenant_id, site_id, node_id, hour, status_code;

CREATE OR REPLACE VIEW security_hourly_v1 AS
SELECT
    metric_version,
    tenant_id,
    site_id,
    node_id,
    hour,
    event_type,
    action,
    count() AS event_count,
    sum(request_bytes) AS request_bytes,
    sum(response_bytes) AS response_bytes
FROM security_hourly_facts_v1 FINAL
GROUP BY metric_version, tenant_id, site_id, node_id, hour, event_type, action;
