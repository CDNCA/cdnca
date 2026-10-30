-- ad-08-store (placeholder 021 = integration head + 1; 022 on merge): smart auto
-- defense control-plane facts (ADR 0010 section 4.5 as narrowed by node
-- autonomy, user 10-19 06:20: no minute summary, baseline or sample table).
--
-- autodefense_verdicts_v1: individual verdicts (L2 and above) the nodes
-- report, one row per verdict; verdict_id is derived from node, report
-- scope, seq and index, so a redelivered report replaces its own rows.
CREATE TABLE IF NOT EXISTS autodefense_verdicts_v1
(
    tenant_id UUID,
    site_id UUID,
    node_id UUID,
    verdict_id UUID,
    occurred_at DateTime64(3, 'UTC'),
    target_kind LowCardinality(String),
    target String,
    score UInt8,
    level UInt8,
    until DateTime64(3, 'UTC'),
    reason String CODEC(ZSTD(3)),
    snapshot_revision UInt64,
    report_seq UInt64,
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    INDEX autodefense_verdicts_target target TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, site_id, occurred_at, verdict_id)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE;

-- node_security_events_v1 (F4, ge-ddos 遗留 2): platform-level node security
-- events that belong to no tenant or site (empty connection bans, node rate
-- bans, layer 4 port group state changes and adjustments). Platform
-- administrators only; never joined into tenant security_events.
CREATE TABLE IF NOT EXISTS node_security_events_v1
(
    node_id UUID,
    event_id UUID,
    occurred_at DateTime64(3, 'UTC'),
    source LowCardinality(String),
    kind LowCardinality(String),
    port_group LowCardinality(String),
    client_ip String,
    count UInt64,
    duration_seconds UInt32,
    level UInt8,
    reason String CODEC(ZSTD(3)),
    detail String CODEC(ZSTD(3)),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    INDEX node_security_events_client client_ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (node_id, occurred_at, event_id)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE;
