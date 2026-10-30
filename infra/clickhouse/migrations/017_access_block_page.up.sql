-- FX60/NF38: block pages (WAF / bound security rules answering 403, and later
-- CC v2 bans/challenges) are tagged by the node. Package traffic sums skip them
-- when openresty security block_page_not_counted is on; old rows stay counted.
ALTER TABLE access_events
    ADD COLUMN IF NOT EXISTS blocked Bool DEFAULT false AFTER duration_us;
ALTER TABLE package_metric_access_facts_v1
    ADD COLUMN IF NOT EXISTS blocked Bool DEFAULT false AFTER response_bytes;
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
    blocked,
    ingested_at
FROM access_events
WHERE package_subscription_id != toUUID('00000000-0000-0000-0000-000000000000');
