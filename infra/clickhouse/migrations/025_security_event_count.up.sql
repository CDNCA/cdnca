-- sec-log-agg (CH 025; 024 = ML-07b subscription_minutes): a CC challenge page / 429 is
-- logged once per (site, client IP, rule, action) and minute with the
-- number of requests it stands for. Every other security event is one
-- request (the default).
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS event_count UInt32 DEFAULT 1;

-- The security log query reads precomputed state, never security_events
-- (as security_event_evidence_state_v1, migration 022): latest by ingested_at.
CREATE TABLE IF NOT EXISTS security_event_count_state_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    ingested_at DateTime64(3, 'UTC'),
    occurred_at DateTime64(3, 'UTC'),
    latest_count_state AggregateFunction(argMax, UInt32, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id, occurred_at, metric_version, ingested_at)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS security_event_count_mv_v1
TO security_event_count_state_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(event_count, ingested_at) AS latest_count_state
FROM security_events
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;

-- The dashboard counts security events in requests (主会话 10-21): the
-- hourly facts carry each event's request count; the row count stays
-- available as security_event_rows.
ALTER TABLE security_hourly_facts_v1 ADD COLUMN IF NOT EXISTS requests UInt32 DEFAULT 1;

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
    ingested_at,
    event_count AS requests
FROM security_events;

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
    sum(requests) AS security_requests,
    sum(request_bytes) AS request_bytes,
    sum(response_bytes) AS response_bytes
FROM security_hourly_facts_v1 FINAL
GROUP BY metric_version, tenant_id, site_id, node_id, hour, event_type, action;
