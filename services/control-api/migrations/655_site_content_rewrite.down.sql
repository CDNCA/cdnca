LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_655_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 655 OR
       (SELECT max(version) FROM schema_migrations) <> 655 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=655 AND
        migration_id='655_site_content_rewrite' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 655 down requires the exact verified migration head' USING ERRCODE='P6551';
    END IF;
END;
$migration_655_down$;

-- Sites lose their rules; the next publication drops content_rewrite from
-- the site objects.
ALTER TABLE sites DROP COLUMN content_rewrite;
