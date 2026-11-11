-- real user monitoring minutes the dynamic routing
-- nodes report (cdnca_rum, telemetry record rum_minute.v1). No visitor data:
-- per (site, minute, node, dimension, value) page views and one histogram
-- per Web Vital (bucket -> count, edgeconfig.RUMBucket; cls is the score
-- times 1000), and per error group counts. The node's event ID is
-- deterministic in (node, site, minute), so a redelivery replaces its own
-- rows (read with FINAL).
CREATE TABLE IF NOT EXISTS rum_minutes_v1
(
    tenant_id UUID,
    site_id UUID,
    minute DateTime('UTC'),
    node_id UUID,
    dimension LowCardinality(String),
    value String,
    views UInt64,
    lcp Map(UInt16, UInt64),
    inp Map(UInt16, UInt64),
    cls Map(UInt16, UInt64),
    fcp Map(UInt16, UInt64),
    ttfb Map(UInt16, UInt64),
    dropped UInt64,
    event_id String,
    installation_id String,
    config_version_id UUID,
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(minute)
ORDER BY (tenant_id, site_id, minute, dimension, value, node_id)
TTL minute + INTERVAL 35 DAY DELETE;

CREATE TABLE IF NOT EXISTS rum_errors_v1
(
    tenant_id UUID,
    site_id UUID,
    minute DateTime('UTC'),
    node_id UUID,
    kind LowCardinality(String),
    element LowCardinality(String),
    target String,
    status UInt16,
    count UInt64,
    event_id String,
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(minute)
ORDER BY (tenant_id, site_id, minute, kind, element, target, status, node_id)
TTL minute + INTERVAL 35 DAY DELETE;
