CREATE TABLE IF NOT EXISTS access_version_evidence_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    ingested_at DateTime64(3, 'UTC'),
    payload_digest String,
    payload_snapshot String,
    INDEX access_evidence_event_idx event_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX access_evidence_digest_idx payload_digest TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(ingested_at)
ORDER BY (metric_version, tenant_id, event_id, ingested_at, payload_digest)
TTL toDateTime(ingested_at, 'UTC') + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS security_version_evidence_v1
(
    metric_version UInt16,
    tenant_id UUID,
    event_id String,
    ingested_at DateTime64(3, 'UTC'),
    payload_digest String,
    payload_snapshot String,
    INDEX security_evidence_event_idx event_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX security_evidence_digest_idx payload_digest TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(ingested_at)
ORDER BY (metric_version, tenant_id, event_id, ingested_at, payload_digest)
TTL toDateTime(ingested_at, 'UTC') + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS access_version_evidence_mv_v1
TO access_version_evidence_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    )))) AS payload_digest,
    toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    )) AS payload_snapshot
FROM access_events;

CREATE MATERIALIZED VIEW IF NOT EXISTS security_version_evidence_mv_v1
TO security_version_evidence_v1 AS
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        origin_connect_us, origin_first_byte_us, origin_total_us
    )))) AS payload_digest,
    toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        origin_connect_us, origin_first_byte_us, origin_total_us
    )) AS payload_snapshot
FROM security_events;

INSERT INTO access_version_evidence_v1
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    )))),
    toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, method,
        protocol, cache_status, upstream_result, status_code, request_bytes,
        response_bytes, duration_us, origin_connect_us, origin_first_byte_us,
        origin_total_us
    ))
FROM access_events;

INSERT INTO security_version_evidence_v1
SELECT
    metric_version,
    tenant_id,
    event_id,
    ingested_at,
    hex(SHA256(toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        origin_connect_us, origin_first_byte_us, origin_total_us
    )))),
    toJSONString(tuple(
        occurred_at, site_id, node_id, request_id, trace_id, config_version_id,
        task_id, installation_id, request_headers, response_headers, request_body,
        response_body, ja4, host, path, client_ip, country_code, carrier, event_type,
        action, severity, rule_id, status_code, request_bytes, response_bytes,
        origin_connect_us, origin_first_byte_us, origin_total_us
    ))
FROM security_events;
