LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_240_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 240 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 240 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 240 AND migration_id = '240_node_monitoring_compatibility_fields' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 240 rollback requires the exact verified 240 release head'
            USING ERRCODE = 'P2401';
    END IF;
END;
$migration_240_down$;

CREATE OR REPLACE FUNCTION system_configuration_v2_node_monitoring_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'port_mode','probe_timeout_ms','probe_interval_ms','failure_debounce_ms',
               'failure_threshold','recovery_debounce_ms','recovery_threshold',
               'recovery_notification_enabled'
           ], ARRAY['custom_port'])
       AND candidate->>'port_mode' IN ('default','custom')
       AND ((candidate->>'port_mode' = 'default' AND NOT candidate ? 'custom_port') OR
            (candidate->>'port_mode' = 'custom' AND candidate ? 'custom_port' AND
             system_configuration_json_integer(candidate->'custom_port', 1, 65535)))
       AND system_configuration_json_integer(candidate->'probe_interval_ms', 1000, 300000)
       AND system_configuration_json_integer(candidate->'probe_timeout_ms', 100, 60000)
       AND (candidate->>'probe_timeout_ms')::integer <= (candidate->>'probe_interval_ms')::integer
       AND system_configuration_json_integer(candidate->'failure_threshold', 1, 20)
       AND system_configuration_json_integer(candidate->'recovery_threshold', 1, 20)
       AND system_configuration_json_integer(candidate->'failure_debounce_ms', 0, 3600000)
       AND system_configuration_json_integer(candidate->'recovery_debounce_ms', 0, 3600000)
       AND jsonb_typeof(candidate->'recovery_notification_enabled') = 'boolean';
$$;
