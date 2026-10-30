LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_281_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 280 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 280 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=280 AND
        migration_id='280_node_serving_holds' AND
        checksum_sha256='fa2d1e6483ca3be92caf05bb736b2ec0009a95b661fcdaa73ebbb8e2d8381841' AND
        down_checksum_sha256='1f1f1b7c726f7230b68f0d937c7ca561c25d865cb17f03605d6730c023f045f0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_auto_disable_usage') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 281 requires the exact verified 280 release head' USING ERRCODE='P2810';
    END IF;
END;
$migration_281_up$;

-- Running accounting of one node's auto-disable period, advanced from
-- node_metric_samples.telemetry_json per-NIC counters. settings_digest binds
-- the accumulated usage to the period anchor, traffic types and excluded NICs;
-- a different digest or period restarts accounting from the period start.
CREATE TABLE node_auto_disable_usage (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    settings_digest text NOT NULL CHECK (settings_digest ~ '^[0-9a-f]{64}$'),
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    counters jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(counters) = 'object'),
    usage_bytes bigint NOT NULL CHECK (usage_bytes >= 0),
    over_streak integer NOT NULL CHECK (over_streak >= 0),
    under_streak integer NOT NULL CHECK (under_streak >= 0),
    last_bandwidth_bps bigint NOT NULL CHECK (last_bandwidth_bps >= 0),
    updated_at timestamptz NOT NULL,
    CHECK (period_end > period_start)
);
GRANT SELECT, INSERT, UPDATE ON node_auto_disable_usage TO cdnca_control_app, cdnca_control_runtime;

-- Auto-disable now takes nodes out of DNS. Until this release its settings
-- were stored but never enforced, and the 239 default switched a 500 GB
-- monthly outbound cap on for every node. The reference product ships the
-- traffic limit off, so new nodes default to off, and nodes whose traffic
-- limit is still exactly the untouched 239 default are switched off instead of
-- suddenly being capped by the upgrade. Any other value was chosen by an
-- operator and is kept as is.
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
        'traffic_enabled', false,
        'traffic_from_day', 1,
        'traffic_from_time', '00:00:00',
        'traffic_total_gb', 500,
        'traffic_types', jsonb_build_array('outbound'),
        'excluded_interfaces', '',
        'disabled_periods', ''
    ),
    'secondary_ips', '[]'::jsonb
);
UPDATE nodes
SET management_settings = jsonb_set(management_settings, '{auto_disable,traffic_enabled}', 'false'::jsonb)
WHERE management_settings->'auto_disable'->'traffic_enabled' = 'true'::jsonb
  AND management_settings->'auto_disable'->'traffic_total_gb' = '500'::jsonb
  AND management_settings->'auto_disable'->'traffic_from_day' = '1'::jsonb
  AND management_settings->'auto_disable'->>'traffic_from_time' = '00:00:00'
  AND management_settings->'auto_disable'->'traffic_types' = '["outbound"]'::jsonb;
