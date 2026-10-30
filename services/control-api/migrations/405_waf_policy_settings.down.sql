LOCK TABLE schema_migrations, security_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_405_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 405 OR
       (SELECT max(version) FROM schema_migrations) <> 405 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=405 AND
        migration_id='405_waf_policy_settings' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 405 down requires the exact verified migration head' USING ERRCODE='P4051';
    END IF;
    -- Settings are policy facts their published versions carry; dropping
    -- them would make the active snapshot unreproducible.
    IF EXISTS (SELECT 1 FROM security_policies WHERE waf_settings IS NOT NULL) THEN
        RAISE EXCEPTION 'WAF policies carry observe mode or auto block; rollback of 405 is unsafe' USING ERRCODE='P4052';
    END IF;
END;
$migration_405_down$;

ALTER TABLE security_policies DROP CONSTRAINT security_policies_waf_settings_405, DROP COLUMN waf_settings;
