DROP VIEW IF EXISTS security_hourly_v1;
DROP VIEW IF EXISTS access_hourly_v1;
DROP VIEW IF EXISTS security_hourly_mv_v1;
DROP VIEW IF EXISTS access_hourly_mv_v1;
DROP TABLE IF EXISTS security_hourly_facts_v1 SYNC;
DROP TABLE IF EXISTS access_hourly_facts_v1 SYNC;

CREATE VIEW IF NOT EXISTS access_hourly_v1 AS
SELECT
    metric_version,
    tenant_id,
    site_id,
    node_id,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    status_code,
    count() AS request_count,
    sum(request_bytes) AS request_bytes,
    sum(response_bytes) AS response_bytes,
    request_bytes + response_bytes AS total_bytes,
    response_bytes * 8.0 / 3600.0 AS average_bandwidth_bps
FROM access_events FINAL
GROUP BY metric_version, tenant_id, site_id, node_id, hour, status_code;

CREATE VIEW IF NOT EXISTS security_hourly_v1 AS
SELECT
    metric_version,
    tenant_id,
    site_id,
    node_id,
    toStartOfHour(occurred_at, 'UTC') AS hour,
    event_type,
    action,
    count() AS event_count,
    sum(request_bytes) AS request_bytes,
    sum(response_bytes) AS response_bytes
FROM security_events FINAL
GROUP BY metric_version, tenant_id, site_id, node_id, hour, event_type, action;
