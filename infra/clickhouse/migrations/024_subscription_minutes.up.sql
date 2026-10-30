-- ML-07 (024, ADR 0012 §6.2; 025 is sec-log-agg): market subscription minute
-- counters the dynamic routing nodes report (cdnca_limits, telemetry record
-- subscription_minute.v1). One row per (subscription, minute, node); the
-- node's event ID is deterministic in the same three, so a redelivery
-- replaces its own row (read with FINAL). Aggregated per subscription across
-- nodes by ML-08 (usage report v2 peaks, §6.3 holds).
CREATE TABLE IF NOT EXISTS subscription_minutes_v1
(
    package_subscription_id UUID,
    minute DateTime('UTC'),
    node_id UUID,
    tenant_id UUID,
    site_id UUID,
    installation_id String,
    config_version_id UUID,
    event_id String,
    max_requests UInt64,
    max_connections UInt64,
    max_new_cps UInt64,
    max_qps UInt64,
    bytes_out UInt64,
    peak_bps UInt64,
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(minute)
ORDER BY (package_subscription_id, minute, node_id)
TTL minute + INTERVAL 400 DAY DELETE;
