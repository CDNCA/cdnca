LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_356_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 356 OR
       (SELECT max(version) FROM schema_migrations) <> 356 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=356 AND
        migration_id='356_site_cache_shared_across_domains' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 356 down requires the exact verified migration head' USING ERRCODE='P3561';
    END IF;
END;
$migration_356_down$;

-- Every site keys its cache by the request host again.
ALTER TABLE sites
    DROP COLUMN cache_shared_across_domains;
