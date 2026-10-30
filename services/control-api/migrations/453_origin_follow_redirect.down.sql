LOCK TABLE schema_migrations, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_453_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 453 OR
       (SELECT max(version) FROM schema_migrations) <> 453 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=453 AND
        migration_id='453_origin_follow_redirect' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 453 down requires the exact verified migration head' USING ERRCODE='P4531';
    END IF;
    -- A site that follows origin redirects would silently stop doing so.
    IF EXISTS (SELECT 1 FROM site_origin_pools WHERE follow_redirect) THEN
        RAISE EXCEPTION 'migration 453 rollback would drop origin redirect following' USING ERRCODE='P4532';
    END IF;
END;
$migration_453_down$;

ALTER TABLE site_origin_pools
    DROP COLUMN follow_redirect_cross_origin,
    DROP COLUMN follow_redirect_max_hops,
    DROP COLUMN follow_redirect;
