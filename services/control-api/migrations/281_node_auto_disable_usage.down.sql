LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_281_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 281 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 281 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=281 AND
        migration_id='281_node_auto_disable_usage' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 281 down requires the exact verified migration head' USING ERRCODE='P2810';
    END IF;
END;
$migration_281_down$;

-- Switched-off traffic limits stay off: turning them back on would enforce a
-- cap nobody chose. Only the default for new nodes is restored.
ALTER TABLE nodes ALTER COLUMN management_settings SET DEFAULT jsonb_build_object(
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
DROP TABLE node_auto_disable_usage;
