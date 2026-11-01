-- log-read-perf: a narrow digest table for the log list conflict probe.
-- An event is ambiguous when two different payloads share one ingested_at
-- (uniqExact(tuple(ingested_at, payload_digest)) > uniqExact(ingested_at) in
-- the 012 states). Finding the window's ambiguous events from those states
-- means merging the filter state of every event in the window (7 days of 7M
-- events: 12 s, 1.2 GiB; 30 days: 93 s or OOM in 4 GiB).
-- *_event_version_digest_v1 keeps per (tenant, occurred_at,
-- cityHash64(event_id), ingested_at) the min and max sipHash128 of the
-- version's columns; min != max after merge means two different versions at
-- one ingested_at. The page reads it FINAL in one streaming pass (7 days:
-- ~0.2 s, <1 MiB). sipHash128 over the columns, Nullable ones as (isNull,
-- ifNull) pairs so NULL and '' stay distinct; a chance collision between two
-- versions (~2^-128) only hides that pair. A cityHash64 clash between two
-- events only adds a candidate, which the page resolves from the 012 states.
-- The 004/005/012/028 views keep their SHA256 payload_digest: measured at the
-- same cost per row as sipHash128 (~1.1 s per million rows on one core, the
-- time is in reading the Map and String columns), so rebuilding live views
-- buys nothing.
CREATE TABLE IF NOT EXISTS access_event_version_digest_v1
(
    metric_version UInt16,
    tenant_id UUID,
    occurred_at DateTime64(3, 'UTC'),
    event_key UInt64,
    ingested_at DateTime64(3, 'UTC'),
    version_digest_min SimpleAggregateFunction(min, UInt128),
    version_digest_max SimpleAggregateFunction(max, UInt128)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, occurred_at, event_key, metric_version, ingested_at)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS access_event_version_digest_mv_v1
TO access_event_version_digest_v1 AS
SELECT
    metric_version,
    tenant_id,
    occurred_at,
    cityHash64(event_id) AS event_key,
    ingested_at,
    version_digest AS version_digest_min,
    version_digest AS version_digest_max
FROM
(
    SELECT *, reinterpretAsUInt128(sipHash128(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        isNull(task_id), ifNull(task_id, ''), installation_id, request_headers, response_headers,
        isNull(request_body), ifNull(request_body, ''), isNull(response_body), ifNull(response_body, ''),
        isNull(ja4), ifNull(ja4, ''), host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, isNull(origin_connect_us), ifNull(origin_connect_us, 0),
        isNull(origin_first_byte_us), ifNull(origin_first_byte_us, 0),
        isNull(origin_total_us), ifNull(origin_total_us, 0)
    )) AS version_digest
    FROM access_events
);

INSERT INTO access_event_version_digest_v1
SELECT
    metric_version,
    tenant_id,
    occurred_at,
    cityHash64(event_id) AS event_key,
    ingested_at,
    version_digest AS version_digest_min,
    version_digest AS version_digest_max
FROM
(
    SELECT *, reinterpretAsUInt128(sipHash128(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        isNull(task_id), ifNull(task_id, ''), installation_id, request_headers, response_headers,
        isNull(request_body), ifNull(request_body, ''), isNull(response_body), ifNull(response_body, ''),
        isNull(ja4), ifNull(ja4, ''), host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, isNull(origin_connect_us), ifNull(origin_connect_us, 0),
        isNull(origin_first_byte_us), ifNull(origin_first_byte_us, 0),
        isNull(origin_total_us), ifNull(origin_total_us, 0)
    )) AS version_digest
    FROM access_events
);

CREATE TABLE IF NOT EXISTS security_event_version_digest_v1
(
    metric_version UInt16,
    tenant_id UUID,
    occurred_at DateTime64(3, 'UTC'),
    event_key UInt64,
    ingested_at DateTime64(3, 'UTC'),
    version_digest_min SimpleAggregateFunction(min, UInt128),
    version_digest_max SimpleAggregateFunction(max, UInt128)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, occurred_at, event_key, metric_version, ingested_at)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS security_event_version_digest_mv_v1
TO security_event_version_digest_v1 AS
SELECT
    metric_version,
    tenant_id,
    occurred_at,
    cityHash64(event_id) AS event_key,
    ingested_at,
    version_digest AS version_digest_min,
    version_digest AS version_digest_max
FROM
(
    SELECT *, reinterpretAsUInt128(sipHash128(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        isNull(task_id), ifNull(task_id, ''), installation_id, request_headers, response_headers,
        isNull(request_body), ifNull(request_body, ''), isNull(response_body), ifNull(response_body, ''),
        isNull(ja4), ifNull(ja4, ''), host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        isNull(origin_connect_us), ifNull(origin_connect_us, 0),
        isNull(origin_first_byte_us), ifNull(origin_first_byte_us, 0),
        isNull(origin_total_us), ifNull(origin_total_us, 0)
    )) AS version_digest
    FROM security_events
);

INSERT INTO security_event_version_digest_v1
SELECT
    metric_version,
    tenant_id,
    occurred_at,
    cityHash64(event_id) AS event_key,
    ingested_at,
    version_digest AS version_digest_min,
    version_digest AS version_digest_max
FROM
(
    SELECT *, reinterpretAsUInt128(sipHash128(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        isNull(task_id), ifNull(task_id, ''), installation_id, request_headers, response_headers,
        isNull(request_body), ifNull(request_body, ''), isNull(response_body), ifNull(response_body, ''),
        isNull(ja4), ifNull(ja4, ''), host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        isNull(origin_connect_us), ifNull(origin_connect_us, 0),
        isNull(origin_first_byte_us), ifNull(origin_first_byte_us, 0),
        isNull(origin_total_us), ifNull(origin_total_us, 0)
    )) AS version_digest
    FROM security_events
);
