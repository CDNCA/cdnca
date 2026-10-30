LOCK TABLE schema_migrations,
    site_origin_route_write_requests, site_origin_routes, site_origin_route_endpoints,
    site_origin_route_pools, site_origin_route_configs
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 109 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 109 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=109 AND migration_id='109_site_origin_route_control'
          AND checksum_sha256='d6b3a67fa2504b048f969317c7605868ebe3ad4edf122286d546edfb023310c2'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=108 AND migration_id='108_notification_provider_settlement'
          AND checksum_sha256='8f56c7f03a30c90547edbca9f50da785ed5cf05ddf2395e431c95cb791409ce9'
          AND down_checksum_sha256='63590fa028e8dc35df49171ef6d790b3cb50e136b0fd44f2f0522d405df3a1f9'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 109 rollback requires the exact verified 109 head'
            USING ERRCODE='P1090';
    END IF;
END;
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM site_origin_route_configs) OR
       EXISTS (SELECT 1 FROM site_origin_route_pools) OR
       EXISTS (SELECT 1 FROM site_origin_route_endpoints) OR
       EXISTS (SELECT 1 FROM site_origin_routes) OR
       EXISTS (SELECT 1 FROM site_origin_route_write_requests) THEN
        RAISE EXCEPTION 'migration 109 rollback would discard site origin route facts'
            USING ERRCODE='P1091';
    END IF;
END;
$$;

DROP TABLE site_origin_route_write_requests;
DROP TABLE site_origin_routes;
DROP TABLE site_origin_route_endpoints;
ALTER TABLE site_origin_route_configs
    DROP CONSTRAINT site_origin_route_configs_default_pool_fk,
    DROP CONSTRAINT site_origin_route_configs_default_fallback_pool_fk;
DROP TABLE site_origin_route_configs;
DROP TABLE site_origin_route_pools;
