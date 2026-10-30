LOCK TABLE schema_migrations, theme_error_pages IN ACCESS EXCLUSIVE MODE;

DO $migration_471_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 471 OR
       (SELECT max(version) FROM schema_migrations) <> 471 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=471 AND
        migration_id='471_theme_block_pages' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 471 down requires the exact verified migration head' USING ERRCODE='P4712';
    END IF;
    -- Theme packages rendered after 471 carry the block pages; dropping the
    -- rows would change a stored package. Refuse instead.
    IF EXISTS (SELECT 1 FROM theme_error_pages WHERE category = 'edge_route') THEN
        RAISE EXCEPTION 'migration 471 rollback would drop theme block pages (edge_route 403/429)' USING ERRCODE='P4713';
    END IF;
END;
$migration_471_down$;

-- Back to the 360 category check and the 391 status check.
ALTER TABLE theme_error_pages DROP CONSTRAINT theme_error_pages_status_471,
    DROP CONSTRAINT theme_error_pages_category_471;
ALTER TABLE theme_error_pages ADD CHECK (category IN ('edge_connect', 'no_host', 'unknown_site'));
ALTER TABLE theme_error_pages ADD CONSTRAINT theme_error_pages_status_391 CHECK (
    (category = 'edge_connect' AND status_code IN (502, 503, 504)) OR
    (category = 'no_host' AND status_code = 400) OR
    (category = 'unknown_site' AND status_code IN (403, 404, 410, 421))
);
