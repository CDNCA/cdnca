LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_326_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 326 OR
       (SELECT max(version) FROM schema_migrations) <> 326 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=326 AND
        migration_id='326_site_force_https' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 326 down requires the exact verified migration head' USING ERRCODE='P3261';
    END IF;
END;
$migration_326_down$;

-- Sites stop redirecting plain HTTP.
ALTER TABLE sites
    DROP CONSTRAINT sites_force_https_326,
    DROP COLUMN https_redirect_port,
    DROP COLUMN force_https;
