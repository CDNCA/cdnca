LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_468_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 468 OR
       (SELECT max(version) FROM schema_migrations) <> 468 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=468 AND
        migration_id='468_node_native_runtime' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 468 down requires the exact verified migration head' USING ERRCODE='P4681';
    END IF;
END;
$migration_468_down$;

-- The next heartbeats report it again after a reapply; nothing else reads it.
ALTER TABLE node_presence
    DROP CONSTRAINT node_presence_native_runtime_468_shape_check,
    DROP COLUMN native_runtime_error_code,
    DROP COLUMN native_runtime_previous_release,
    DROP COLUMN native_runtime_release,
    DROP COLUMN native_runtime_state;
