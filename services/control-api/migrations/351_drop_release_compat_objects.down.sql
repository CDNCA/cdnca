LOCK TABLE schema_migrations, cname_allocation_targets, security_activation_capability_waits IN ACCESS EXCLUSIVE MODE;

DO $migration_351_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 351 OR
       (SELECT max(version) FROM schema_migrations) <> 351 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=351 AND
        migration_id='351_drop_release_compat_objects' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 351 down requires the exact verified migration head' USING ERRCODE='P3511';
    END IF;
END;
$migration_351_down$;

-- Restores 297's default and 306's column as they were; existing waits read
-- false, which is what 306 stored for every wait it created.
ALTER TABLE security_activation_capability_waits
    ADD COLUMN compatible_challenge boolean NOT NULL DEFAULT false;

CREATE FUNCTION default_cname_target_node_group_scope_297() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.node_group_scope_id IS NULL THEN
        NEW.node_group_scope_id := NEW.tenant_scope_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER a_cname_allocation_targets_scope_297
BEFORE INSERT ON cname_allocation_targets
FOR EACH ROW EXECUTE FUNCTION default_cname_target_node_group_scope_297();
REVOKE ALL ON FUNCTION default_cname_target_node_group_scope_297() FROM PUBLIC;
