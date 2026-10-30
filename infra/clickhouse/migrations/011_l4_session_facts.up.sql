CREATE TABLE IF NOT EXISTS l4_session_facts_v1
(
    tenant_id UUID,
    node_id UUID,
    site_id UUID,
    stream_id UUID,
    listener_id UUID,
    session_id String,
    started_at DateTime64(3, 'UTC'),
    finalized_at DateTime64(3, 'UTC'),
    bytes_up UInt64,
    bytes_down UInt64,
    status_code UInt16,
    error_code LowCardinality(String),
    config_version_id UUID,
    config_revision UInt64,
    protocol LowCardinality(String),
    listen_port UInt16,
    event_id String,
    traceparent String,
    task_id String,
    source_watermark UInt64,
    evidence_sha256 FixedString(64),
    canonical_event_sha256 FixedString(64)
)
ENGINE = ReplacingMergeTree(source_watermark)
PARTITION BY toYYYYMM(finalized_at)
ORDER BY (tenant_id, finalized_at, event_id)
TTL toDateTime(finalized_at, 'UTC') + INTERVAL 30 DAY DELETE;
