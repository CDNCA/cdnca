LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_239$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 238 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 238 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 238 AND migration_id = '238_l4_stream_sequence_delete_grants' AND
              checksum_sha256 = '1408c479408d540459eb5d78d7ae98c75c6382b6a40c330170a4c0976f5a28f7' AND
              down_checksum_sha256 = '3b8bf691cfa55800344620895fb587c82dce74de5cf97ef6a2f6a26d389010a9' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'nodes' AND column_name = 'management_settings'
       ) THEN
        RAISE EXCEPTION 'migration 239 requires the exact verified 238 release head and nodes without management settings'
            USING ERRCODE = 'P2390';
    END IF;
END;
$migration_239$;

ALTER TABLE nodes ADD COLUMN management_settings jsonb NOT NULL DEFAULT jsonb_build_object(
    'schema_version', 1,
    'sort', 100,
    'node_type', 'L1',
    'cache_directory', '',
    'cache_limit_gb', 0,
    'log_directory', '',
    'ip_location', jsonb_build_object(
        'country', '', 'province', '', 'city', '', 'isp', '', 'country_code', ''
    ),
    'auto_disable', jsonb_build_object(
        'bandwidth_limit', 0,
        'bandwidth_unit', 'Mbps',
        'traffic_enabled', true,
        'traffic_from_day', 1,
        'traffic_from_time', '00:00:00',
        'traffic_total_gb', 500,
        'traffic_types', jsonb_build_array('outbound'),
        'excluded_interfaces', '',
        'disabled_periods', ''
    ),
    'secondary_ips', '[]'::jsonb
);

ALTER TABLE nodes ADD CONSTRAINT nodes_management_settings_239_check CHECK (
    jsonb_typeof(management_settings) = 'object' AND
    jsonb_typeof(management_settings->'schema_version') = 'number' AND
    (management_settings->>'schema_version')::integer = 1 AND
    jsonb_typeof(management_settings->'sort') = 'number' AND
    (management_settings->>'sort')::integer BETWEEN 0 AND 999999 AND
    jsonb_typeof(management_settings->'node_type') = 'string' AND
    management_settings->>'node_type' IN ('L1', 'L2') AND
    jsonb_typeof(management_settings->'cache_directory') = 'string' AND
    jsonb_typeof(management_settings->'cache_limit_gb') = 'number' AND
    jsonb_typeof(management_settings->'log_directory') = 'string' AND
    jsonb_typeof(management_settings->'ip_location') = 'object' AND
    jsonb_typeof(management_settings->'ip_location'->'country') = 'string' AND
    jsonb_typeof(management_settings->'ip_location'->'province') = 'string' AND
    jsonb_typeof(management_settings->'ip_location'->'city') = 'string' AND
    jsonb_typeof(management_settings->'ip_location'->'isp') = 'string' AND
    jsonb_typeof(management_settings->'ip_location'->'country_code') = 'string' AND
    jsonb_typeof(management_settings->'auto_disable') = 'object' AND
    jsonb_typeof(management_settings->'auto_disable'->'bandwidth_limit') = 'number' AND
    jsonb_typeof(management_settings->'auto_disable'->'bandwidth_unit') = 'string' AND
    jsonb_typeof(management_settings->'auto_disable'->'traffic_enabled') = 'boolean' AND
    jsonb_typeof(management_settings->'auto_disable'->'traffic_from_day') = 'number' AND
    jsonb_typeof(management_settings->'auto_disable'->'traffic_from_time') = 'string' AND
    jsonb_typeof(management_settings->'auto_disable'->'traffic_total_gb') = 'number' AND
    jsonb_typeof(management_settings->'auto_disable'->'traffic_types') = 'array' AND
    jsonb_typeof(management_settings->'auto_disable'->'excluded_interfaces') = 'string' AND
    jsonb_typeof(management_settings->'auto_disable'->'disabled_periods') = 'string' AND
    jsonb_typeof(management_settings->'secondary_ips') = 'array' AND
    jsonb_array_length(management_settings->'secondary_ips') <= 64
);
