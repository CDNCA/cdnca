LOCK TABLE schema_migrations, rule_pack_enablements IN ACCESS EXCLUSIVE MODE;

DO $migration_419_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 419 OR
       (SELECT max(version) FROM schema_migrations) <> 419 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=419 AND
        migration_id='419_official_rule_pack_enablement' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 419 down requires the exact verified migration head' USING ERRCODE='P4191';
    END IF;
END;
$migration_419_down$;

-- The control plane's own "open to lower levels" rows have no user; they
-- carry no administrator decision, so they are dropped (the packs go back to
-- locked; rows below them stay and apply again once an administrator opens
-- the pack).
DELETE FROM rule_pack_enablements WHERE updated_by_user_id IS NULL;
ALTER TABLE rule_pack_enablements
    DROP CONSTRAINT rule_pack_enablements_system_row_419,
    ALTER COLUMN updated_by_user_id SET NOT NULL;
