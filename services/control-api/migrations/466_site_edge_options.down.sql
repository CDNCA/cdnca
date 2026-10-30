LOCK TABLE schema_migrations, sites, site_origin_pools, l2_topology_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_466_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 466 OR
       (SELECT max(version) FROM schema_migrations) <> 466 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=466 AND
        migration_id='466_site_edge_options' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 466 down requires the exact verified migration head' USING ERRCODE='P4661';
    END IF;
    -- A site using one of the options would silently lose it.
    IF EXISTS (SELECT 1 FROM site_origin_pools WHERE search_engine_origin IS NOT NULL OR acme_passthrough OR
               NOT response_buffering OR NOT request_buffering OR l2_mode <> 'package') THEN
        RAISE EXCEPTION 'migration 466 rollback would drop site edge options' USING ERRCODE='P4662';
    END IF;
END;
$migration_466_down$;

DROP INDEX sites_single_default_466;
DROP TRIGGER site_origin_pools_l2_config_466 ON site_origin_pools;
DROP FUNCTION assert_site_l2_config_466();
ALTER TABLE site_origin_pools
    DROP CONSTRAINT site_origin_pools_l2_custom_466_check,
    DROP COLUMN l2_config_id,
    DROP COLUMN l2_mode,
    DROP COLUMN request_buffering,
    DROP COLUMN response_buffering,
    DROP COLUMN acme_passthrough,
    DROP COLUMN search_engine_origin;
