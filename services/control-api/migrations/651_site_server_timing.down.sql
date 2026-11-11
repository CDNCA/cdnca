LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_651_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 651 OR
       (SELECT max(version) FROM schema_migrations) <> 651 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=651 AND
        migration_id='651_site_server_timing' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 651 down requires the exact verified migration head' USING ERRCODE='P6511';
    END IF;
END;
$migration_651_down$;

-- Nodes stop answering Server-Timing (the next publication drops the field).
ALTER TABLE sites
    DROP COLUMN server_timing;
