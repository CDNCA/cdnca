-- Preserve the existing analytics-log projection contract while carrying the
-- listen port that has been present on access_events since migration 009.
ALTER TABLE access_event_query_payload_state_v1
    ADD COLUMN IF NOT EXISTS listen_port_state AggregateFunction(argMax, UInt16, DateTime64(3, 'UTC'));

DROP VIEW IF EXISTS access_event_query_payload_mv_v1;

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
    uniqExactState(ingested_at) AS ingested_at_state,
    argMaxState(listen_port, ingested_at) AS listen_port_state
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
     version_pair_state, ingested_at_state, listen_port_state)
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
    uniqExactState(ingested_at),
    argMaxState(listen_port, ingested_at)
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
