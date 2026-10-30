LOCK TABLE schema_migrations, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_307_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 307 OR
       (SELECT max(version) FROM schema_migrations) <> 307 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=307 AND
        migration_id='307_site_origin_keepalive' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 307 down requires the exact verified migration head' USING ERRCODE='P3071';
    END IF;
END;
$migration_307_down$;

-- Sites go back to the nginx default reuse.
ALTER TABLE site_origin_pools
    DROP CONSTRAINT site_origin_pools_keepalive_idle_timeout_307,
    DROP COLUMN keepalive_idle_timeout_ms,
    DROP COLUMN keepalive_enabled;
