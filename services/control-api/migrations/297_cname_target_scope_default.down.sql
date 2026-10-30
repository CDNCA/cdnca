LOCK TABLE schema_migrations, cname_allocation_targets IN ACCESS EXCLUSIVE MODE;

DO $migration_297_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 297 OR
       (SELECT max(version) FROM schema_migrations) <> 297 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=297 AND
        migration_id='297_cname_target_scope_default' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 297 down requires the exact verified migration head' USING ERRCODE='P2971';
    END IF;
END;
$migration_297_down$;

-- Only the default goes; stored targets keep their scope.
DROP TRIGGER a_cname_allocation_targets_scope_297 ON cname_allocation_targets;
DROP FUNCTION default_cname_target_node_group_scope_297();
