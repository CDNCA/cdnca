LOCK TABLE schema_migrations, rule_pack_enablements, site_security_mounts IN ACCESS EXCLUSIVE MODE;

DO $migration_454_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 454 OR
       (SELECT max(version) FROM schema_migrations) <> 454 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=454 AND
        migration_id='454_official_rule_pack_default_on' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 454 down requires the exact verified migration head' USING ERRCODE='P4541';
    END IF;
    -- Mounts the control plane published itself would lose their row shape;
    -- a site owner republishes them first.
    IF EXISTS (SELECT 1 FROM site_security_mounts WHERE published_by_user_id IS NULL) THEN
        RAISE EXCEPTION 'migration 454 rollback would drop system published rule pack mounts' USING ERRCODE='P4542';
    END IF;
END;
$migration_454_down$;

-- Default-on official packs go back to "open, still disabled" (419).
UPDATE rule_pack_enablements SET state='inherit' WHERE updated_by_user_id IS NULL AND state='enabled';
ALTER TABLE site_security_mounts ALTER COLUMN published_by_user_id SET NOT NULL;
ALTER TABLE rule_pack_enablements
    DROP CONSTRAINT rule_pack_enablements_system_row_454,
    ADD CONSTRAINT rule_pack_enablements_system_row_419 CHECK (updated_by_user_id IS NOT NULL OR
        level = 'platform' AND rule_id IS NULL AND state = 'inherit' AND allow_lower AND priority IS NULL AND params IS NULL);
