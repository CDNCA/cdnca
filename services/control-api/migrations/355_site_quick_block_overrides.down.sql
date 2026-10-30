LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_355_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 355 OR
       (SELECT max(version) FROM schema_migrations) <> 355 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=355 AND
        migration_id='355_site_quick_block_overrides' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 355 down requires the exact verified migration head' USING ERRCODE='P3551';
    END IF;
END;
$migration_355_down$;

-- Sites go back to their library's quick block on their next release.
DROP TABLE site_quick_block_write_requests;
DROP TABLE site_quick_block_overrides;
