CREATE OR REPLACE VIEW security_hourly_v1 AS
SELECT
    metric_version,
    tenant_id,
    site_id,
    node_id,
    hour,
    event_type,
    action,
    count() AS event_count,
    sum(request_bytes) AS request_bytes,
    sum(response_bytes) AS response_bytes
FROM security_hourly_facts_v1 FINAL
GROUP BY metric_version, tenant_id, site_id, node_id, hour, event_type, action;
DROP VIEW IF EXISTS security_hourly_mv_v1;
CREATE MATERIALIZED VIEW security_hourly_mv_v1
TO security_hourly_facts_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    site_id,
    node_id,
    event_type,
    action,
    request_bytes,
    response_bytes,
    ingested_at
FROM security_events;
ALTER TABLE security_hourly_facts_v1 DROP COLUMN IF EXISTS requests;
DROP VIEW IF EXISTS security_event_count_mv_v1;
DROP TABLE IF EXISTS security_event_count_state_v1;
ALTER TABLE security_events DROP COLUMN IF EXISTS event_count;
