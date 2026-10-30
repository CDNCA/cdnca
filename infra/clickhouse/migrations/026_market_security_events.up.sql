-- ML-21 (026 占位，ADR 0012 §19.1；合入时主会话改号): security digests a leaf
-- controller relayed for this controller's market-supplied sites
-- (operation supply.secdigest, libs/marketproto/secdigest), bound to the
-- local site by site_supply_leaf_sites.leaf_site_id. One row per summary,
-- mitigation ("action") and attack log line of a 5-minute leaf window; a
-- redelivered digest replaces its own rows (read with FINAL). Log lines
-- carry only client IP, host, path, action, detector and rule (no request
-- body, cookie or header values), as on the leaf.
CREATE TABLE IF NOT EXISTS market_security_events_v1
(
    tenant_id UUID,
    site_id UUID,
    supply_id UUID,
    leaf_member_id UUID,
    leaf_ref String,
    leaf_site_id UUID,
    window_start DateTime64(3, 'UTC'),
    row_kind LowCardinality(String),
    row_index UInt32,
    occurred_at DateTime64(3, 'UTC'),
    source LowCardinality(String),
    action LowCardinality(String),
    detector LowCardinality(String),
    rule_id String,
    client_ip String,
    host String CODEC(ZSTD(3)),
    path String CODEC(ZSTD(3)),
    target_kind LowCardinality(String),
    target String,
    level UInt8,
    until DateTime64(3, 'UTC'),
    reason String CODEC(ZSTD(3)),
    events UInt64,
    blocked UInt64,
    challenged UInt64,
    banned UInt64,
    clients UInt64,
    dropped_logs UInt64,
    received_at DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    INDEX market_security_received received_at TYPE minmax GRANULARITY 1
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(window_start)
ORDER BY (tenant_id, site_id, window_start, leaf_member_id, row_kind, row_index)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE;
