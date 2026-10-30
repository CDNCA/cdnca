CREATE TABLE IF NOT EXISTS access_events
(
    metric_version UInt16 CODEC(T64, ZSTD(1)),
    event_id String CODEC(ZSTD(3)),
    occurred_at DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    tenant_id UUID CODEC(ZSTD(1)),
    site_id UUID CODEC(ZSTD(1)),
    node_id UUID CODEC(ZSTD(1)),
    request_id String DEFAULT '' CODEC(ZSTD(3)),
    trace_id String DEFAULT '' CODEC(ZSTD(3)),
    config_version_id String DEFAULT '' CODEC(ZSTD(3)),
    host String CODEC(ZSTD(3)),
    path String CODEC(ZSTD(3)),
    client_ip IPv6 CODEC(ZSTD(1)),
    country_code LowCardinality(String) DEFAULT '',
    carrier LowCardinality(String) DEFAULT '',
    method LowCardinality(String),
    protocol LowCardinality(String),
    cache_status LowCardinality(String),
    upstream_result LowCardinality(String) DEFAULT '',
    status_code UInt16 CODEC(T64, ZSTD(1)),
    request_bytes UInt64 CODEC(T64, ZSTD(1)),
    response_bytes UInt64 CODEC(T64, ZSTD(1)),
    duration_us UInt64 CODEC(T64, ZSTD(1)),
    INDEX access_occurred_at_idx occurred_at TYPE minmax GRANULARITY 1,
    INDEX access_site_idx site_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX access_node_idx node_id TYPE bloom_filter(0.01) GRANULARITY 4,
    CONSTRAINT access_metric_version_v1 CHECK metric_version = 1,
    CONSTRAINT access_event_id_valid CHECK length(event_id) > 0 AND length(event_id) <= 128,
    CONSTRAINT access_scope_valid CHECK tenant_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND site_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND node_id != toUUID('00000000-0000-0000-0000-000000000000'),
    CONSTRAINT access_status_code_valid CHECK status_code >= 100 AND status_code <= 599,
    CONSTRAINT access_bytes_nonnegative CHECK request_bytes >= 0 AND response_bytes >= 0
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 10000;

CREATE TABLE IF NOT EXISTS security_events
(
    metric_version UInt16 CODEC(T64, ZSTD(1)),
    event_id String CODEC(ZSTD(3)),
    occurred_at DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    tenant_id UUID CODEC(ZSTD(1)),
    site_id UUID CODEC(ZSTD(1)),
    node_id UUID CODEC(ZSTD(1)),
    request_id String DEFAULT '' CODEC(ZSTD(3)),
    trace_id String DEFAULT '' CODEC(ZSTD(3)),
    config_version_id String DEFAULT '' CODEC(ZSTD(3)),
    host String CODEC(ZSTD(3)),
    path String CODEC(ZSTD(3)),
    client_ip IPv6 CODEC(ZSTD(1)),
    country_code LowCardinality(String) DEFAULT '',
    carrier LowCardinality(String) DEFAULT '',
    event_type LowCardinality(String),
    action LowCardinality(String),
    severity LowCardinality(String),
    rule_id String DEFAULT '' CODEC(ZSTD(3)),
    status_code UInt16 CODEC(T64, ZSTD(1)),
    request_bytes UInt64 CODEC(T64, ZSTD(1)),
    response_bytes UInt64 CODEC(T64, ZSTD(1)),
    INDEX security_occurred_at_idx occurred_at TYPE minmax GRANULARITY 1,
    INDEX security_site_idx site_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX security_node_idx node_id TYPE bloom_filter(0.01) GRANULARITY 4,
    CONSTRAINT security_metric_version_v1 CHECK metric_version = 1,
    CONSTRAINT security_event_id_valid CHECK length(event_id) > 0 AND length(event_id) <= 128,
    CONSTRAINT security_scope_valid CHECK tenant_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND site_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND node_id != toUUID('00000000-0000-0000-0000-000000000000'),
    CONSTRAINT security_status_code_valid CHECK status_code = 0 OR (status_code >= 100 AND status_code <= 599),
    CONSTRAINT security_bytes_nonnegative CHECK request_bytes >= 0 AND response_bytes >= 0
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 10000;

CREATE VIEW IF NOT EXISTS access_hourly_v1 AS
SELECT
    metric_version,
    tenant_id,
    site_id,
    node_id,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    status_code,
    count() AS request_count,
    sum(request_bytes) AS request_bytes,
    sum(response_bytes) AS response_bytes,
    request_bytes + response_bytes AS total_bytes,
    response_bytes * 8.0 / 3600.0 AS average_bandwidth_bps
FROM access_events FINAL
GROUP BY metric_version, tenant_id, site_id, node_id, hour, status_code;

CREATE VIEW IF NOT EXISTS security_hourly_v1 AS
SELECT
    metric_version,
    tenant_id,
    site_id,
    node_id,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    event_type,
    action,
    count() AS event_count,
    sum(request_bytes) AS request_bytes,
    sum(response_bytes) AS response_bytes
FROM security_events FINAL
GROUP BY metric_version, tenant_id, site_id, node_id, hour, event_type, action;
