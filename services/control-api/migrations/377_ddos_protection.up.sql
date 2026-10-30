LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_377_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 376 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 376 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=376 AND
        migration_id='376_ge_nodes' AND
        checksum_sha256='0ad20b16426922d6431242432f2f849377f08a1ba877d5cb789549c45844f36b' AND
        down_checksum_sha256='226f0e4861f84b421af0549207d09998e888abfd6e0dfe4eb5d9f4298fba4ae9' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('system_configuration_v2_ddos_protection_is_valid(jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 377 requires the exact verified 376 release head' USING ERRCODE='P3770';
    END IF;
END;
$migration_377_up$;

-- r136 ge-ddos (GoEdge comparison G2): the platform system configuration
-- gains the optional ddos_protection category (edgeconfig.DDoSProtection),
-- the node-level kernel connection limits every edge node applies to the TCP
-- ports it serves. The control plane writes the canonical form (allow
-- networks masked, sorted, unique); this check is the database's own bound.
CREATE FUNCTION system_configuration_v2_ddos_protection_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    empty jsonb;
    network text;
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY[
           'max_connections_per_ip','new_connections_per_second','new_connections_per_minute',
           'rate_ban_seconds','max_connections_per_port','allow_networks','cc_kernel_ban'
       ], ARRAY['empty_connection']) OR
       NOT system_configuration_json_integer(candidate->'max_connections_per_ip', 0, 1000000) OR
       NOT system_configuration_json_integer(candidate->'new_connections_per_second', 0, 1000000) OR
       NOT system_configuration_json_integer(candidate->'new_connections_per_minute', 0, 60000000) OR
       NOT system_configuration_json_integer(candidate->'rate_ban_seconds', 0, 604800) OR
       NOT system_configuration_json_integer(candidate->'max_connections_per_port', 0, 10000000) OR
       ((candidate->>'rate_ban_seconds')::bigint > 0 AND (candidate->>'new_connections_per_second')::bigint = 0 AND
        (candidate->>'new_connections_per_minute')::bigint = 0) OR
       jsonb_typeof(candidate->'cc_kernel_ban') <> 'string' OR
       candidate->>'cc_kernel_ban' NOT IN ('off','exclusive_ports','site_ports') OR
       jsonb_typeof(candidate->'allow_networks') <> 'array' OR
       jsonb_array_length(candidate->'allow_networks') > 256 THEN
        RETURN false;
    END IF;
    -- cidr refuses host bits; its text is the canonical prefix Go writes.
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(candidate->'allow_networks') item
               WHERE jsonb_typeof(item) <> 'string') THEN
        RETURN false;
    END IF;
    FOR network IN SELECT value FROM jsonb_array_elements_text(candidate->'allow_networks') LOOP
        IF network::cidr::text <> network THEN
            RETURN false;
        END IF;
    END LOOP;
    IF candidate ? 'empty_connection' THEN
        empty := candidate->'empty_connection';
        IF NOT system_configuration_v2_json_keys_exact(empty, ARRAY[
               'idle_seconds','threshold','window_seconds','ban_seconds']) OR
           NOT system_configuration_json_integer(empty->'idle_seconds', 5, 600) OR
           NOT system_configuration_json_integer(empty->'threshold', 3, 10000) OR
           NOT system_configuration_json_integer(empty->'window_seconds', 10, 3600) OR
           NOT system_configuration_json_integer(empty->'ban_seconds', 1, 604800) THEN
            RETURN false;
        END IF;
    END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION system_configuration_snapshot_is_valid(candidate bytea)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    raw text;
    document jsonb;
    configuration jsonb;
BEGIN
    raw := convert_from(candidate, 'UTF8');
    IF raw <> btrim(raw) THEN RETURN false; END IF;
    document := raw::jsonb;
    IF raw <> document::text OR
       NOT system_configuration_v2_json_keys_exact(document, ARRAY['schema','configuration']) OR
       jsonb_typeof(document->'schema') <> 'string' OR
       document->>'schema' <> 'cdnca.system-configuration/v2' THEN
        RETURN false;
    END IF;
    configuration := document->'configuration';
    IF NOT system_configuration_v2_json_keys_exact(configuration, ARRAY[
           'nginx','secrets','defaults','resources','error_pages'
       ], ARRAY['node_monitoring','ddos_protection']) OR
       NOT system_configuration_v2_nginx_is_valid(configuration->'nginx') OR
       NOT system_configuration_v2_defaults_is_valid(configuration->'defaults') OR
       NOT system_configuration_v2_resources_is_valid(configuration->'resources') OR
       NOT system_configuration_v2_error_pages_is_valid(configuration->'error_pages') OR
       NOT system_configuration_v2_secrets_is_valid(configuration->'secrets') OR
       (configuration ? 'node_monitoring' AND
        NOT system_configuration_v2_node_monitoring_is_valid(configuration->'node_monitoring')) OR
       (configuration ? 'ddos_protection' AND
        NOT system_configuration_v2_ddos_protection_is_valid(configuration->'ddos_protection')) THEN
        RETURN false;
    END IF;
    RETURN system_configuration_render_canonical_snapshot(document) = candidate;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;
