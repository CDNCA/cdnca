LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_240_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 239 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 239 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 239 AND migration_id = '239_node_management_settings' AND
              checksum_sha256 = '2889178f6f06f46209c9ffa6e49166a152447cd4b171325620e9779034fa5324' AND
              down_checksum_sha256 = 'c9672a6d6e71ad8f21ab93af8c017eabdb98317bd1efbb2fabbd1d9162e241e7' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 240 requires the exact verified 239 release head'
            USING ERRCODE = 'P2400';
    END IF;
END;
$migration_240_up$;

CREATE OR REPLACE FUNCTION system_configuration_v2_node_monitoring_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'port_mode','probe_timeout_ms','probe_interval_ms','failure_debounce_ms',
               'failure_threshold','recovery_debounce_ms','recovery_threshold',
               'recovery_notification_enabled'
           ], ARRAY[
               'custom_port','monitor_enabled','protocol','monitor_port','monitor_groups',
               'monitor_action','failure_ratio','bandwidth_over_limit'
           ])
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
       AND jsonb_typeof(candidate->'recovery_notification_enabled') = 'boolean'
       AND (NOT candidate ? 'monitor_enabled' OR jsonb_typeof(candidate->'monitor_enabled') = 'boolean')
       AND (NOT candidate ? 'protocol' OR candidate->>'protocol' IN ('http','tcp','ping'))
       AND (NOT candidate ? 'monitor_port' OR system_configuration_json_integer(candidate->'monitor_port', 1, 65535))
       AND (NOT candidate ? 'monitor_groups' OR (
           jsonb_typeof(candidate->'monitor_groups') = 'array' AND
           jsonb_array_length(candidate->'monitor_groups') BETWEEN 1 AND 5 AND
           NOT EXISTS (
               SELECT 1 FROM jsonb_array_elements_text(candidate->'monitor_groups') AS group_name
               WHERE group_name NOT IN ('domestic','telecom','unicom','mobile','overseas')
           ) AND
           (SELECT count(*) FROM jsonb_array_elements(candidate->'monitor_groups')) =
           (SELECT count(DISTINCT value) FROM jsonb_array_elements_text(candidate->'monitor_groups') AS item(value))
       ))
       AND (NOT candidate ? 'monitor_action' OR candidate->>'monitor_action' IN ('none','pause'))
       AND (NOT candidate ? 'failure_ratio' OR system_configuration_json_integer(candidate->'failure_ratio', 1, 100))
       AND (NOT candidate ? 'bandwidth_over_limit' OR system_configuration_json_integer(candidate->'bandwidth_over_limit', 1, 20));
$$;
