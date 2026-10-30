DROP VIEW IF EXISTS site_realtime_access_facts_mv_v1;

ALTER TABLE site_realtime_access_facts_v1
    UPDATE source_watermark = toUInt64(toUnixTimestamp64Milli(ingested_at)),
           finalized_through = ingested_at
    WHERE source_watermark = 0
      AND finalized_through = toDateTime64(0, 3, 'UTC')
    SETTINGS mutations_sync = 2;

CREATE MATERIALIZED VIEW IF NOT EXISTS site_realtime_access_facts_mv_v1
TO site_realtime_access_facts_v1 AS
SELECT
    metric_version, tenant_id, site_id, event_id, occurred_at, ingested_at, lower(host), listen_port,
    cache_status, upstream_result, status_code, request_bytes, response_bytes, duration_us,
    origin_connect_us, origin_first_byte_us, origin_total_us,
    toUInt64(toUnixTimestamp64Milli(ingested_at)) AS source_watermark,
    ingested_at AS finalized_through
FROM access_events;
