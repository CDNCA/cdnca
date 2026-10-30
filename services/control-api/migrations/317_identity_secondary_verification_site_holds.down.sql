LOCK TABLE schema_migrations, identity_secondary_verification_site_holds IN ACCESS EXCLUSIVE MODE;

DO $migration_317_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 317 OR
       (SELECT max(version) FROM schema_migrations) <> 317 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=317 AND
        migration_id='317_identity_secondary_verification_site_holds' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 317 down requires the exact verified migration head' USING ERRCODE='P3171';
    END IF;
    -- Open holds are stopped sites the binary must restore; history rows are audit.
    IF EXISTS (SELECT 1 FROM identity_secondary_verification_site_holds) THEN
        RAISE EXCEPTION 'migration 317 rollback would discard secondary verification site holds; release them and deploy a compatible binary'
            USING ERRCODE='P3171';
    END IF;
END;
$migration_317_down$;

DROP TABLE identity_secondary_verification_site_holds;
