LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_654_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 654 OR
       (SELECT max(version) FROM schema_migrations) <> 654 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=654 AND
        migration_id='654_site_rum' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 654 down requires the exact verified migration head' USING ERRCODE='P6541';
    END IF;
END;
$migration_654_down$;

-- The collected minutes stay in ClickHouse (034, 35 day TTL); sites lose the
-- switch and the next publication drops rum from the site objects.
ALTER TABLE sites DROP COLUMN rum_sample_percent;
