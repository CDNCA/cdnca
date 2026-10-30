LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_374_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 374 OR
       (SELECT max(version) FROM schema_migrations) <> 374 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=374 AND
        migration_id='374_site_crs_overrides' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 374 down requires the exact verified migration head' USING ERRCODE='P3741';
    END IF;
END;
$migration_374_down$;

-- Sites go back to their library's CRS profile and exclusions on their next release.
DROP TABLE site_crs_write_requests;
DROP TABLE site_crs_overrides;
