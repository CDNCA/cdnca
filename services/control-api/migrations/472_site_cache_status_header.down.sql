LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_472_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 472 OR
       (SELECT max(version) FROM schema_migrations) <> 472 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=472 AND
        migration_id='472_site_cache_status_header' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 472 down requires the exact verified migration head' USING ERRCODE='P4721';
    END IF;
END;
$migration_472_down$;

-- Nodes stop answering the cache status header.
ALTER TABLE sites
    DROP COLUMN cache_status_header;
