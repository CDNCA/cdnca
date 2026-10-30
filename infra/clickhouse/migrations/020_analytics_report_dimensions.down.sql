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
    status_code,
    request_bytes,
    response_bytes,
    ingested_at
FROM access_events;
ALTER TABLE access_hourly_facts_v1
    DROP COLUMN IF EXISTS client_os,
    DROP COLUMN IF EXISTS client_browser,
    DROP COLUMN IF EXISTS carrier,
    DROP COLUMN IF EXISTS province,
    DROP COLUMN IF EXISTS country_code,
    DROP COLUMN IF EXISTS client_ip,
    DROP COLUMN IF EXISTS cache_status,
    DROP COLUMN IF EXISTS listen_port,
    DROP COLUMN IF EXISTS host;
ALTER TABLE security_events DROP COLUMN IF EXISTS province;
ALTER TABLE access_events
    DROP COLUMN IF EXISTS client_os,
    DROP COLUMN IF EXISTS client_browser,
    DROP COLUMN IF EXISTS province;
