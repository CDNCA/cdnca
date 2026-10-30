DROP VIEW IF EXISTS package_metric_access_facts_mv_v1;
CREATE MATERIALIZED VIEW package_metric_access_facts_mv_v1
TO package_metric_access_facts_v1 AS
SELECT
    metric_version,
    tenant_id,
    package_subscription_id,
    installation_id,
    event_id,
    occurred_at,
    toStartOfHour(occurred_at, 'UTC') AS period_start,
    toStartOfHour(occurred_at, 'UTC') + INTERVAL 1 HOUR AS period_end,
    request_bytes,
    response_bytes,
    ingested_at
FROM access_events
WHERE package_subscription_id != toUUID('00000000-0000-0000-0000-000000000000');
ALTER TABLE package_metric_access_facts_v1 DROP COLUMN IF EXISTS blocked;
ALTER TABLE access_events DROP COLUMN IF EXISTS blocked;
