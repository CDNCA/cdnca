LOCK TABLE schema_migrations, system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_395_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 394 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 394 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=394 AND
        migration_id='394_aggregated_edge_quality' AND
        checksum_sha256='31742813bd63915494f29db87db6d17dfd6f99da4474cb9ecb57fb0761da40c3' AND
        down_checksum_sha256='0253b97951f615c5b604f5ab57d6ad9e7202f36108497d783e6dc5c9f1375fcb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('system_configuration_v2_ddos_protection_is_valid(jsonb)') IS NULL THEN
        RAISE EXCEPTION 'migration 395 requires the exact verified 394 release head' USING ERRCODE='P3950';
    END IF;
END;
$migration_395_up$;

-- r136 ddos-tcpflags (placeholder number, reserved 397; renumbered on merge):
-- the ddos_protection category gains the TCP malformed flag filter
-- (tcp_flag_filter + tcp_flag_types, a canonical ordered subset of
-- null/xmas/syn_fin/syn_rst/fin/all; the switch needs a type) and
-- drop_invalid (conntrack INVALID). All three are optional: a value saved
-- before has them off. Go (edgeconfig.NormalizeDDoSProtection) writes the
-- canonical form; this is the database's own bound.
CREATE OR REPLACE FUNCTION system_configuration_v2_ddos_protection_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    empty jsonb;
    network text;
    flag_types text[] := ARRAY['null','xmas','syn_fin','syn_rst','fin','all'];
    given text[];
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY[
           'max_connections_per_ip','new_connections_per_second','new_connections_per_minute',
           'rate_ban_seconds','max_connections_per_port','allow_networks','cc_kernel_ban'
       ], ARRAY['empty_connection','tcp_flag_filter','tcp_flag_types','drop_invalid']) OR
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
    -- The Go encoder omits false switches and an empty type list.
    IF (candidate ? 'tcp_flag_filter' AND candidate->'tcp_flag_filter' <> 'true'::jsonb) OR
       (candidate ? 'drop_invalid' AND candidate->'drop_invalid' <> 'true'::jsonb) THEN
        RETURN false;
    END IF;
    IF candidate ? 'tcp_flag_types' THEN
        IF jsonb_typeof(candidate->'tcp_flag_types') <> 'array' OR jsonb_array_length(candidate->'tcp_flag_types') = 0 OR
           EXISTS (SELECT 1 FROM jsonb_array_elements(candidate->'tcp_flag_types') item
                   WHERE jsonb_typeof(item) <> 'string') THEN
            RETURN false;
        END IF;
        SELECT array_agg(value ORDER BY ordinality) INTO given
        FROM jsonb_array_elements_text(candidate->'tcp_flag_types') WITH ORDINALITY;
        -- Canonical: known types, unique, in flag_types order.
        IF given IS DISTINCT FROM ARRAY(SELECT kind FROM unnest(flag_types) WITH ORDINALITY AS t(kind, position)
                                        WHERE kind = ANY(given) ORDER BY position) THEN
            RETURN false;
        END IF;
    ELSIF candidate ? 'tcp_flag_filter' THEN
        RETURN false;
    END IF;
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
