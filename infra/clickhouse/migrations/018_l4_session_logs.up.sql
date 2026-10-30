CREATE TABLE IF NOT EXISTS l4_session_logs_v1
(
    tenant_id UUID,
    node_id UUID,
    site_id UUID,
    stream_id UUID,
    listener_id UUID,
    session_id String,
    started_at DateTime64(3, 'UTC'),
    finalized_at DateTime64(3, 'UTC'),
    protocol LowCardinality(String),
    listen_port UInt16,
    client_ip String,
    client_port UInt16,
    peer_ip String,
    upstream_addr String,
    upstream_connect_ms Nullable(UInt32),
    bytes_up UInt64,
    bytes_down UInt64,
    status_code UInt16,
    end_reason LowCardinality(String),
    event_id String,
    source_watermark UInt64,
    INDEX l4_session_logs_client_ip client_ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree(source_watermark)
PARTITION BY toYYYYMM(finalized_at)
ORDER BY (tenant_id, finalized_at, event_id)
TTL toDateTime(finalized_at, 'UTC') + INTERVAL 30 DAY DELETE;
