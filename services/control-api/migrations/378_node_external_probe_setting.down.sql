LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_378_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 378 OR
       (SELECT max(version) FROM schema_migrations) <> 378 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=378 AND
        migration_id='378_node_external_probe_setting' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 378 down requires the exact verified migration head' USING ERRCODE='P3781';
    END IF;
END;
$migration_378_down$;

ALTER TABLE nodes DROP CONSTRAINT nodes_management_settings_external_probe_378_check;
UPDATE nodes SET management_settings = management_settings - 'external_probe';
ALTER TABLE nodes ALTER COLUMN management_settings SET DEFAULT jsonb_build_object(
    'schema_version', 1, 'sort', 100, 'node_type', 'L1', 'cache_directory', '', 'cache_limit_gb', 0,
    'log_directory', '',
    'ip_location', jsonb_build_object('country', '', 'province', '', 'city', '', 'isp', '', 'country_code', ''),
    'auto_disable', jsonb_build_object('bandwidth_limit', 0, 'bandwidth_unit', 'Mbps', 'traffic_enabled', false,
        'traffic_from_day', 1, 'traffic_from_time', '00:00:00', 'traffic_total_gb', 500,
        'traffic_types', jsonb_build_array('outbound'), 'excluded_interfaces', '', 'disabled_periods', ''),
    'secondary_ips', '[]'::jsonb);
