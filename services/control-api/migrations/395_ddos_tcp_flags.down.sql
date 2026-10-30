LOCK TABLE schema_migrations, system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_395_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 395 OR
       (SELECT max(version) FROM schema_migrations) <> 395 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=395 AND
        migration_id='395_ddos_tcp_flags' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM system_configuration_revisions
        WHERE convert_from(canonical_snapshot, 'UTF8')::jsonb->'configuration'->'ddos_protection' ?|
              ARRAY['tcp_flag_filter','tcp_flag_types','drop_invalid']
       ) THEN
        RAISE EXCEPTION 'migration 395 down requires the exact verified migration head and no TCP flag filter or drop_invalid revision'
            USING ERRCODE='P3951';
    END IF;
END;
$migration_395_down$;

-- Back to the 377 check.
CREATE OR REPLACE FUNCTION system_configuration_v2_ddos_protection_is_valid(candidate jsonb)
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
