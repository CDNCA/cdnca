-- ge-waf (GoEdge parity G1, 占位号): attack evidence of WAF / ACL security
-- events - the deciding policy, the detector and matched fragment, the
-- User-Agent and a request body excerpt (cut on the node). Older events keep
-- the empty defaults.
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS policy_id String DEFAULT '' CODEC(ZSTD(3));
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS detector LowCardinality(String) DEFAULT '';
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS matched String DEFAULT '' CODEC(ZSTD(3));
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS user_agent String DEFAULT '' CODEC(ZSTD(3));
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS request_body_excerpt String DEFAULT '' CODEC(ZSTD(3));

-- The security log query (analyticslog blockEventPageSQL) reads the payload
-- from precomputed state, never security_events: the evidence gets a state
-- table of its own, latest by ingested_at like security_event_query_payload_state_v1.
CREATE TABLE IF NOT EXISTS security_event_evidence_state_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    ingested_at DateTime64(3, 'UTC'),
    occurred_at DateTime64(3, 'UTC'),
    latest_evidence_state AggregateFunction(argMax, Tuple(String, LowCardinality(String), String, String, String), DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id, occurred_at, metric_version, ingested_at)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS security_event_evidence_mv_v1
TO security_event_evidence_state_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(policy_id, detector, matched, user_agent, request_body_excerpt), ingested_at) AS latest_evidence_state
FROM security_events
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;
