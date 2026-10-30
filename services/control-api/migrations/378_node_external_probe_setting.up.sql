LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_378_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 377 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 377 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=377 AND
        migration_id='377_ddos_protection' AND
        checksum_sha256='ad1e06fdd563af1c6a0aff2f2f168d2131662bb62104a6af4bba782fb88ebcf1' AND
        down_checksum_sha256='60f1f4da452c625a07765a5fb88af4e2fe683d6f8e4a57aeaa14f24b0038fdbf' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 378 requires the exact verified 377 release head' USING ERRCODE='P3780';
    END IF;
END;
$migration_378_up$;

-- Nodes vote as peers in external probing by default (节点管理 > 外部探测);
-- the Agent installs probe-only (market_probe.enabled, never join_market).
ALTER TABLE nodes ALTER COLUMN management_settings SET DEFAULT
    jsonb_set(jsonb_build_object(
        'schema_version', 1, 'sort', 100, 'node_type', 'L1', 'cache_directory', '', 'cache_limit_gb', 0,
        'log_directory', '',
        'ip_location', jsonb_build_object('country', '', 'province', '', 'city', '', 'isp', '', 'country_code', ''),
        'auto_disable', jsonb_build_object('bandwidth_limit', 0, 'bandwidth_unit', 'Mbps', 'traffic_enabled', false,
            'traffic_from_day', 1, 'traffic_from_time', '00:00:00', 'traffic_total_gb', 500,
            'traffic_types', jsonb_build_array('outbound'), 'excluded_interfaces', '', 'disabled_periods', ''),
        'secondary_ips', '[]'::jsonb), '{external_probe}', 'true'::jsonb);
UPDATE nodes SET management_settings = management_settings || '{"external_probe": true}'::jsonb
WHERE NOT management_settings ? 'external_probe';
ALTER TABLE nodes ADD CONSTRAINT nodes_management_settings_external_probe_378_check CHECK (
    jsonb_typeof(management_settings->'external_probe') = 'boolean'
);
