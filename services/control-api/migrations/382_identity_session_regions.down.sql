LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_382_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 382 OR
       (SELECT max(version) FROM schema_migrations) <> 382 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=382 AND
        migration_id='382_identity_session_regions' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 382 down requires the exact verified migration head' USING ERRCODE='P3821';
    END IF;
END;
$migration_382_down$;

-- Region baselines are derived per sign-in; dropping them only stops the check.
DROP TABLE identity_session_regions;
