LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_590_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 590 OR
       (SELECT max(version) FROM schema_migrations) <> 590 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=590 AND
        migration_id='590_node_installation_serving' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 590 down requires the exact verified migration head' USING ERRCODE='P5901';
    END IF;
END;
$migration_590_down$;

-- The next heartbeats report it again after a reapply; nothing else reads it.
ALTER TABLE node_presence
    DROP CONSTRAINT node_presence_installation_serving_590_shape_check,
    DROP COLUMN installation_recovery_failures,
    DROP COLUMN installation_recovery_cause,
    DROP COLUMN installation_recovery_at,
    DROP COLUMN installation_recovery_result,
    DROP COLUMN installation_stopped_at,
    DROP COLUMN installation_serving,
    DROP COLUMN installation_allowed;
