-- P015 preserves the P014 access query projection while removing the false
-- source-coverage claim introduced by P009. ClickHouse stores request facts;
-- the independent source-window authority is finalized in PostgreSQL.
-- predecessor_up_sha256=373fc236fa24eee7d14b0d10c254ab68481ec4561dea8a2789cc2fad3677ad2a
-- predecessor_down_sha256=6e086f88815da358efbbc69ddc1e0a7d0de4e80830798ac6eef6fe28f7ee6b38

DROP VIEW IF EXISTS site_realtime_access_facts_mv_v1;

ALTER TABLE site_realtime_access_facts_v1
    UPDATE source_watermark = 0,
           finalized_through = toDateTime64(0, 3, 'UTC')
    WHERE source_watermark = toUInt64(toUnixTimestamp64Milli(ingested_at))
      AND finalized_through = ingested_at
    SETTINGS mutations_sync = 2;

CREATE MATERIALIZED VIEW IF NOT EXISTS site_realtime_access_facts_mv_v1
TO site_realtime_access_facts_v1 AS
SELECT
    metric_version, tenant_id, site_id, event_id, occurred_at, ingested_at, lower(host), listen_port,
    cache_status, upstream_result, status_code, request_bytes, response_bytes, duration_us,
    origin_connect_us, origin_first_byte_us, origin_total_us,
    toUInt64(0) AS source_watermark,
    toDateTime64(0, 3, 'UTC') AS finalized_through
FROM access_events;
