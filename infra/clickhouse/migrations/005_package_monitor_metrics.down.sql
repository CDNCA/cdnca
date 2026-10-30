DROP VIEW IF EXISTS package_metric_finalized_v1;
DROP VIEW IF EXISTS package_metric_access_facts_mv_v1;
DROP VIEW IF EXISTS security_version_evidence_mv_v1;
DROP VIEW IF EXISTS access_version_evidence_mv_v1;
DROP TABLE IF EXISTS package_metric_connection_facts_v1;
DROP TABLE IF EXISTS package_metric_access_facts_v1;

ALTER TABLE security_events DROP COLUMN IF EXISTS package_subscription_id;
ALTER TABLE access_events DROP COLUMN IF EXISTS package_subscription_id;

CREATE MATERIALIZED VIEW access_version_evidence_mv_v1
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

CREATE MATERIALIZED VIEW security_version_evidence_mv_v1
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
