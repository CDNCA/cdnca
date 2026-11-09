LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_647_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 647 OR
       (SELECT max(version) FROM schema_migrations) <> 647 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=647 AND
        migration_id='647_node_packaging_toolset' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 647 down requires the exact verified migration head' USING ERRCODE='P6471';
    END IF;
END;
$migration_647_down$;

-- The next heartbeats report it again after a reapply; nothing else reads it.
ALTER TABLE node_presence
    DROP CONSTRAINT node_presence_toolset_647_shape_check,
    DROP COLUMN toolset_helper_sha256,
    DROP COLUMN toolset_scripts_sha256,
    DROP COLUMN toolset_helper_reason,
    DROP COLUMN toolset_helper_status,
    DROP COLUMN toolset_refreshed_at,
    DROP COLUMN toolset_refresh_reason,
    DROP COLUMN toolset_refresh_version,
    DROP COLUMN toolset_refresh_status;
