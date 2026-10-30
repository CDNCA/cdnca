CREATE TABLE IF NOT EXISTS access_event_query_index_state_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    ingested_at DateTime64(3, 'UTC'),
    occurred_at DateTime64(3, 'UTC'),
    latest_filter_state AggregateFunction(argMax, Tuple(
        DateTime64(3, 'UTC'), UUID, UUID, String, IPv6, String, String, String, String, String, String,
        UInt16, UInt64, UInt64, Nullable(String), Nullable(UInt64), Nullable(UInt64), Nullable(UInt64),
        String, String, DateTime64(3, 'UTC'), String
    ), DateTime64(3, 'UTC')),
    version_pair_state AggregateFunction(uniqExact, Tuple(DateTime64(3, 'UTC'), String)),
    ingested_at_state AggregateFunction(uniqExact, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, occurred_at, event_id, metric_version, ingested_at)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS access_event_query_payload_state_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    ingested_at DateTime64(3, 'UTC'),
    occurred_at DateTime64(3, 'UTC'),
    latest_payload_state AggregateFunction(argMax, Tuple(
        UUID, DateTime64(3, 'UTC'), UUID, UUID, String, String, String, Nullable(String), String,
        Map(String, String), Map(String, String), Nullable(String), Nullable(String), Nullable(String),
        String, String, IPv6, LowCardinality(String), LowCardinality(String), LowCardinality(String),
        LowCardinality(String), LowCardinality(String), LowCardinality(String), UInt16, UInt64, UInt64,
        UInt64, Nullable(UInt64), Nullable(UInt64), Nullable(UInt64)
    ), DateTime64(3, 'UTC')),
    version_pair_state AggregateFunction(uniqExact, Tuple(DateTime64(3, 'UTC'), String)),
    ingested_at_state AggregateFunction(uniqExact, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id, occurred_at, metric_version, ingested_at)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS access_event_query_index_mv_v1
TO access_event_query_index_state_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(
        occurred_at, site_id, node_id, path, client_ip, toString(country_code), toString(carrier),
        toString(method), toString(protocol), toString(cache_status), toString(upstream_result), status_code,
        request_bytes, response_bytes, ja4, origin_connect_us, origin_first_byte_us, origin_total_us,
        lowerUTF8(arrayElement(response_headers, arrayFirst(key -> lowerUTF8(key) = 'content-type', mapKeys(response_headers)))),
        arrayElement(request_headers, arrayFirst(key -> lowerUTF8(key) = 'user-agent', mapKeys(request_headers))),
        ingested_at, payload_digest
    ), ingested_at) AS latest_filter_state,
    uniqExactState(tuple(ingested_at, payload_digest)) AS version_pair_state,
    uniqExactState(ingested_at) AS ingested_at_state
FROM
(
    SELECT *, hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    )))) AS payload_digest
    FROM access_events
)
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;

CREATE MATERIALIZED VIEW IF NOT EXISTS access_event_query_payload_mv_v1
TO access_event_query_payload_state_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(
        package_subscription_id, occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body, response_body, ja4,
        host, path, client_ip, country_code, carrier, method, protocol, cache_status, upstream_result,
        status_code, request_bytes, response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    ), ingested_at) AS latest_payload_state,
    uniqExactState(tuple(ingested_at, payload_digest)) AS version_pair_state,
    uniqExactState(ingested_at) AS ingested_at_state
FROM
(
    SELECT *, hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    )))) AS payload_digest
    FROM access_events
)
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;

INSERT INTO access_event_query_index_state_v1
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(
        occurred_at, site_id, node_id, path, client_ip, toString(country_code), toString(carrier),
        toString(method), toString(protocol), toString(cache_status), toString(upstream_result), status_code,
        request_bytes, response_bytes, ja4, origin_connect_us, origin_first_byte_us, origin_total_us,
        lowerUTF8(arrayElement(response_headers, arrayFirst(key -> lowerUTF8(key) = 'content-type', mapKeys(response_headers)))),
        arrayElement(request_headers, arrayFirst(key -> lowerUTF8(key) = 'user-agent', mapKeys(request_headers))),
        ingested_at, payload_digest
    ), ingested_at),
    uniqExactState(tuple(ingested_at, payload_digest)),
    uniqExactState(ingested_at)
FROM
(
    SELECT *, hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    )))) AS payload_digest
    FROM access_events
)
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;

INSERT INTO access_event_query_payload_state_v1
    (metric_version, tenant_id, event_id, ingested_at, occurred_at, latest_payload_state,
     version_pair_state, ingested_at_state)
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(
        package_subscription_id, occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body, response_body, ja4,
        host, path, client_ip, country_code, carrier, method, protocol, cache_status, upstream_result,
        status_code, request_bytes, response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    ), ingested_at),
    uniqExactState(tuple(ingested_at, payload_digest)),
    uniqExactState(ingested_at)
FROM
(
    SELECT *, hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    )))) AS payload_digest
    FROM access_events
)
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;

CREATE TABLE IF NOT EXISTS security_event_query_index_state_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    ingested_at DateTime64(3, 'UTC'),
    occurred_at DateTime64(3, 'UTC'),
    latest_filter_state AggregateFunction(argMax, Tuple(
        DateTime64(3, 'UTC'), UUID, UUID, String, IPv6, String, String, String, String, UInt16,
        Nullable(String), Nullable(UInt64), Nullable(UInt64), Nullable(UInt64), DateTime64(3, 'UTC'), String
    ), DateTime64(3, 'UTC')),
    version_pair_state AggregateFunction(uniqExact, Tuple(DateTime64(3, 'UTC'), String)),
    ingested_at_state AggregateFunction(uniqExact, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, occurred_at, event_id, metric_version, ingested_at)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS security_event_query_payload_state_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    ingested_at DateTime64(3, 'UTC'),
    occurred_at DateTime64(3, 'UTC'),
    latest_payload_state AggregateFunction(argMax, Tuple(
        UUID, DateTime64(3, 'UTC'), UUID, UUID, String, String, String, Nullable(String), String,
        Map(String, String), Map(String, String), Nullable(String), Nullable(String), Nullable(String),
        String, String, IPv6, LowCardinality(String), LowCardinality(String), LowCardinality(String),
        LowCardinality(String), LowCardinality(String), String, UInt16, UInt64, UInt64,
        Nullable(UInt64), Nullable(UInt64), Nullable(UInt64)
    ), DateTime64(3, 'UTC')),
    version_pair_state AggregateFunction(uniqExact, Tuple(DateTime64(3, 'UTC'), String)),
    ingested_at_state AggregateFunction(uniqExact, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, event_id, occurred_at, metric_version, ingested_at)
TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS security_event_query_index_mv_v1
TO security_event_query_index_state_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(
        occurred_at, site_id, node_id, path, client_ip, toString(country_code), toString(carrier),
        toString(event_type), toString(action), status_code, ja4, origin_connect_us, origin_first_byte_us,
        origin_total_us, ingested_at, payload_digest
    ), ingested_at) AS latest_filter_state,
    uniqExactState(tuple(ingested_at, payload_digest)) AS version_pair_state,
    uniqExactState(ingested_at) AS ingested_at_state
FROM
(
    SELECT *, hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        origin_connect_us, origin_first_byte_us, origin_total_us
    )))) AS payload_digest
    FROM security_events
)
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;

CREATE MATERIALIZED VIEW IF NOT EXISTS security_event_query_payload_mv_v1
TO security_event_query_payload_state_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(
        package_subscription_id, occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body, response_body, ja4,
        host, path, client_ip, country_code, carrier, event_type, action, severity, rule_id, status_code,
        request_bytes, response_bytes, origin_connect_us, origin_first_byte_us, origin_total_us
    ), ingested_at) AS latest_payload_state,
    uniqExactState(tuple(ingested_at, payload_digest)) AS version_pair_state,
    uniqExactState(ingested_at) AS ingested_at_state
FROM
(
    SELECT *, hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        origin_connect_us, origin_first_byte_us, origin_total_us
    )))) AS payload_digest
    FROM security_events
)
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;

INSERT INTO security_event_query_index_state_v1
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(
        occurred_at, site_id, node_id, path, client_ip, toString(country_code), toString(carrier),
        toString(event_type), toString(action), status_code, ja4, origin_connect_us, origin_first_byte_us,
        origin_total_us, ingested_at, payload_digest
    ), ingested_at),
    uniqExactState(tuple(ingested_at, payload_digest)),
    uniqExactState(ingested_at)
FROM
(
    SELECT *, hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        origin_connect_us, origin_first_byte_us, origin_total_us
    )))) AS payload_digest
    FROM security_events
)
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;

INSERT INTO security_event_query_payload_state_v1
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    occurred_at,
    argMaxState(tuple(
        package_subscription_id, occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body, response_body, ja4,
        host, path, client_ip, country_code, carrier, event_type, action, severity, rule_id, status_code,
        request_bytes, response_bytes, origin_connect_us, origin_first_byte_us, origin_total_us
    ), ingested_at),
    uniqExactState(tuple(ingested_at, payload_digest)),
    uniqExactState(ingested_at)
FROM
(
    SELECT *, hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        origin_connect_us, origin_first_byte_us, origin_total_us
    )))) AS payload_digest
    FROM security_events
)
GROUP BY metric_version, tenant_id, event_id, ingested_at, occurred_at;
