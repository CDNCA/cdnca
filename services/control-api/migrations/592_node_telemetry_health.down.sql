LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_592_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 592 OR
       (SELECT max(version) FROM schema_migrations) <> 592 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=592 AND
        migration_id='592_node_telemetry_health' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 592 down requires the exact verified migration head' USING ERRCODE='P5921';
    END IF;
END;
$migration_592_down$;

-- The next heartbeats report it again after a reapply; nothing else reads it.
ALTER TABLE node_presence
    DROP CONSTRAINT node_presence_telemetry_592_shape_check,
    DROP COLUMN telemetry_count,
    DROP COLUMN telemetry_last_seen_at,
    DROP COLUMN telemetry_first_seen_at,
    DROP COLUMN telemetry_error_code;
