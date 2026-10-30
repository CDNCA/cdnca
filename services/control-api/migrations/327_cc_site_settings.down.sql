LOCK TABLE schema_migrations, security_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_327_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 327 OR
       (SELECT max(version) FROM schema_migrations) <> 327 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=327 AND
        migration_id='327_cc_site_settings' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 327 down requires the exact verified migration head' USING ERRCODE='P3271';
    END IF;
END;
$migration_327_down$;

-- Policies go back to their rules' own durations and no auto switch.
ALTER TABLE security_policies
    DROP CONSTRAINT security_policies_cc_settings_327,
    DROP COLUMN cc_settings;
