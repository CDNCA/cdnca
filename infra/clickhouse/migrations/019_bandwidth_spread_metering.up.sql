-- ge-analytics: bandwidth peak/95th spread over the transfer time, and usage
-- that outlives the access log TTL (access_logs_days, default 7 days).
--
-- The node now logs duration_us ($request_time). Package facts carry it and
-- the site, so package usage, peak and 95th read the 400-day facts instead
-- of raw access_events. access_metering_facts_v1 is the same for every
-- access event (sites without a package too), with the host, for the admin
-- usage search.
ALTER TABLE package_metric_access_facts_v1
    ADD COLUMN IF NOT EXISTS site_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000') AFTER installation_id,
    ADD COLUMN IF NOT EXISTS duration_us UInt64 DEFAULT 0 AFTER response_bytes;
DROP VIEW IF EXISTS package_metric_access_facts_mv_v1;
CREATE MATERIALIZED VIEW package_metric_access_facts_mv_v1
TO package_metric_access_facts_v1 AS
SELECT
    metric_version,
    tenant_id,
    package_subscription_id,
    installation_id,
    site_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC') AS period_start,
    toStartOfHour(occurred_at, 'UTC') + INTERVAL 1 HOUR AS period_end,
    request_bytes,
    response_bytes,
    duration_us,
    blocked,
    ingested_at
FROM access_events
WHERE package_subscription_id != toUUID('00000000-0000-0000-0000-000000000000');

CREATE TABLE IF NOT EXISTS access_metering_facts_v1
(
    metric_version UInt16,
    tenant_id UUID,
    package_subscription_id UUID,
    site_id UUID,
    event_id String,
    occurred_at DateTime64(3, 'UTC'),
    host String CODEC(ZSTD(3)),
    request_bytes UInt64,
    response_bytes UInt64,
    duration_us UInt64,
    blocked Bool,
    ingested_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 10000;

CREATE MATERIALIZED VIEW IF NOT EXISTS access_metering_facts_mv_v1
TO access_metering_facts_v1 AS
SELECT
    metric_version,
    tenant_id,
    package_subscription_id,
    site_id,
    event_id,
    occurred_at,
    host,
    request_bytes,
    response_bytes,
    duration_us,
    blocked,
    ingested_at
FROM access_events;

INSERT INTO access_metering_facts_v1
SELECT
    metric_version, tenant_id, package_subscription_id, site_id, event_id, occurred_at, host,
    request_bytes, response_bytes, duration_us, blocked, ingested_at
FROM access_events FINAL;

-- L4 session facts are metering too (admin usage search, TCP billing): keep
-- them as long as the HTTP metering facts.
ALTER TABLE l4_session_facts_v1 MODIFY TTL toDateTime(finalized_at, 'UTC') + INTERVAL 400 DAY DELETE;
