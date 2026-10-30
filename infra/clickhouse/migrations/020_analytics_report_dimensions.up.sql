-- ge-analytics: history report dimensions.
--
-- access_events / security_events get the client's province (IP library,
-- filled by the control plane at ingest with country_code and carrier) and
-- the access log gets the client's browser and OS family (parsed from the
-- User-Agent on the node; the raw User-Agent is not stored unless captured).
-- access_hourly_facts_v1 (history, TTL follows bandwidth_history_days) gets
-- every low-cardinality report dimension plus the client address, so cache
-- hit ratio, unique client IPs and the domain/region/province/carrier/
-- browser/OS rankings are available for the whole history range, not only
-- for the access log retention (access_logs_days).
ALTER TABLE access_events
    ADD COLUMN IF NOT EXISTS province LowCardinality(String) DEFAULT '' AFTER carrier,
    ADD COLUMN IF NOT EXISTS client_browser LowCardinality(String) DEFAULT '' AFTER blocked,
    ADD COLUMN IF NOT EXISTS client_os LowCardinality(String) DEFAULT '' AFTER client_browser;
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS province LowCardinality(String) DEFAULT '' AFTER carrier;

ALTER TABLE access_hourly_facts_v1
    ADD COLUMN IF NOT EXISTS host String DEFAULT '' CODEC(ZSTD(3)) AFTER node_id,
    ADD COLUMN IF NOT EXISTS listen_port UInt16 DEFAULT 0 AFTER host,
    ADD COLUMN IF NOT EXISTS cache_status LowCardinality(String) DEFAULT '' AFTER status_code,
    ADD COLUMN IF NOT EXISTS client_ip IPv6 DEFAULT toIPv6('::') AFTER cache_status,
    ADD COLUMN IF NOT EXISTS country_code LowCardinality(String) DEFAULT '' AFTER client_ip,
    ADD COLUMN IF NOT EXISTS province LowCardinality(String) DEFAULT '' AFTER country_code,
    ADD COLUMN IF NOT EXISTS carrier LowCardinality(String) DEFAULT '' AFTER province,
    ADD COLUMN IF NOT EXISTS client_browser LowCardinality(String) DEFAULT '' AFTER carrier,
    ADD COLUMN IF NOT EXISTS client_os LowCardinality(String) DEFAULT '' AFTER client_browser;

DROP VIEW IF EXISTS access_hourly_mv_v1;
CREATE MATERIALIZED VIEW access_hourly_mv_v1
TO access_hourly_facts_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    site_id,
    node_id,
    host,
    listen_port,
    status_code,
    cache_status,
    client_ip,
    country_code,
    province,
    carrier,
    client_browser,
    client_os,
    request_bytes,
    response_bytes,
    ingested_at
FROM access_events;
