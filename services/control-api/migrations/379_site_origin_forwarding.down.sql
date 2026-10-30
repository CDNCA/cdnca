LOCK TABLE schema_migrations, site_origin_pools, site_origins, site_origin_routes IN ACCESS EXCLUSIVE MODE;

DO $migration_379_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 379 OR
       (SELECT max(version) FROM schema_migrations) <> 379 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=379 AND
        migration_id='379_site_origin_forwarding' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 379 down requires the exact verified migration head' USING ERRCODE='P3791';
    END IF;
END;
$migration_379_down$;

-- Sites go back to the 378 origin model; settings only 379 has are lost.
DROP TABLE site_origin_trust_bundles;
DELETE FROM site_origin_routes WHERE path_prefix IS NULL AND cardinality(node_regions) = 0 AND cardinality(client_cidrs) = 0;
ALTER TABLE site_origin_routes
    DROP CONSTRAINT site_origin_routes_condition_379,
    ADD CONSTRAINT site_origin_routes_check CHECK (
        path_prefix IS NOT NULL OR cardinality(node_regions) > 0 OR cardinality(client_cidrs) > 0
    ),
    DROP COLUMN hosts;

ALTER TABLE site_origins
    DROP COLUMN max_conns,
    DROP COLUMN backup;

UPDATE site_origin_pools SET balance_method = 'round_robin' WHERE balance_method IN ('hash', 'sticky');
ALTER TABLE site_origin_pools
    DROP CONSTRAINT site_origin_pools_tls_379,
    DROP CONSTRAINT site_origin_pools_tls_ca_379,
    DROP CONSTRAINT site_origin_pools_request_host_379,
    DROP CONSTRAINT site_origin_pools_sticky_379,
    DROP CONSTRAINT site_origin_pools_hash_key_379,
    DROP COLUMN trusted_proxy_cidrs,
    DROP COLUMN websocket_allowed_origins,
    DROP COLUMN websocket_enabled,
    DROP COLUMN follow_port,
    DROP COLUMN tls_ca_sha256,
    DROP COLUMN tls_ca_pem,
    DROP COLUMN tls_trust,
    DROP COLUMN tls_sni,
    DROP COLUMN https_port,
    DROP COLUMN origin_scheme,
    DROP COLUMN request_host,
    DROP COLUMN request_host_mode,
    DROP COLUMN sticky_name,
    DROP COLUMN sticky_source,
    DROP COLUMN hash_key,
    DROP CONSTRAINT site_origin_pools_balance_method_check,
    ADD CONSTRAINT site_origin_pools_balance_method_check CHECK (
        balance_method IN ('round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random')
    );

CREATE OR REPLACE FUNCTION validate_site_origin_pool(target_site_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    pool_failover smallint;
    origin_count integer;
    enabled_count integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sites WHERE id = target_site_id) THEN
        RETURN;
    END IF;

    SELECT failover_tries
    INTO pool_failover
    FROM site_origin_pools
    WHERE site_id = target_site_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'site origin pool is required for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), count(*) FILTER (WHERE enabled)
    INTO origin_count, enabled_count
    FROM site_origins
    WHERE site_id = target_site_id;

    IF origin_count < 1 OR origin_count > 32 OR enabled_count < 1 OR pool_failover > enabled_count THEN
        RAISE EXCEPTION 'site origin pool invariant failed for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;
