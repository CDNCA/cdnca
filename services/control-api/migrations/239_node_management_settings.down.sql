LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_239_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 239 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 239 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 239 AND migration_id = '239_node_management_settings' AND
              checksum_sha256 = '2889178f6f06f46209c9ffa6e49166a152447cd4b171325620e9779034fa5324' AND integrity_state = 'verified' AND
              metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'nodes' AND column_name = 'management_settings'
       ) THEN
        RAISE EXCEPTION 'migration 239 rollback requires the exact verified 239 release head'
            USING ERRCODE = 'P2391';
    END IF;
    IF EXISTS (
        SELECT 1 FROM nodes WHERE management_settings <> jsonb_build_object(
            'schema_version', 1, 'sort', 100, 'node_type', 'L1',
            'cache_directory', '', 'cache_limit_gb', 0, 'log_directory', '',
            'ip_location', jsonb_build_object(
                'country', '', 'province', '', 'city', '', 'isp', '', 'country_code', ''
            ),
            'auto_disable', jsonb_build_object(
                'bandwidth_limit', 0, 'bandwidth_unit', 'Mbps', 'traffic_enabled', true,
                'traffic_from_day', 1, 'traffic_from_time', '00:00:00', 'traffic_total_gb', 500,
                'traffic_types', jsonb_build_array('outbound'),
                'excluded_interfaces', '', 'disabled_periods', ''
            ),
            'secondary_ips', '[]'::jsonb
        )
    ) THEN
        RAISE EXCEPTION 'migration 239 rollback cannot discard node management settings'
            USING ERRCODE = 'P2392';
    END IF;
END;
$migration_239_down$;

ALTER TABLE nodes DROP CONSTRAINT nodes_management_settings_239_check;
ALTER TABLE nodes DROP COLUMN management_settings;
