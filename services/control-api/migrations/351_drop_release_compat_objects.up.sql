LOCK TABLE schema_migrations, cname_allocation_targets, security_activation_capability_waits IN ACCESS EXCLUSIVE MODE;

DO $migration_351_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 350 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 350 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=350 AND
        migration_id='350_aggregated_edge' AND
        checksum_sha256='f25689a94b20c9f8f6286e2095b0831bbf11c6eb3a17326d1f6674cd3d65f9cf' AND
        down_checksum_sha256='0fe195c37967496d268c4d643badab6bea184c61140d650d178e40eced3495d2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='cname_allocation_targets'::regclass AND
        tgname='a_cname_allocation_targets_scope_297' AND
        tgfoid='default_cname_target_node_group_scope_297()'::regprocedure
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_attribute WHERE attrelid='security_activation_capability_waits'::regclass AND
        attname='compatible_challenge' AND NOT attisdropped
       ) THEN
        RAISE EXCEPTION 'migration 351 requires the exact verified 350 release head' USING ERRCODE='P3510';
    END IF;
END;
$migration_351_up$;

-- 1.0.35 is the initial release (no rollback to 1.0.33 or earlier binaries).
-- 297's default only filled node_group_scope_id for a writer predating 287;
-- every current writer names it, and 287's guard still refuses a NULL.
DROP TRIGGER a_cname_allocation_targets_scope_297 ON cname_allocation_targets;
DROP FUNCTION default_cname_target_node_group_scope_297();

-- The "publish as compatible challenge" switch is gone: nothing writes or
-- reads this column any more.
ALTER TABLE security_activation_capability_waits DROP COLUMN compatible_challenge;
