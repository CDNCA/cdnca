DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM site_origin_write_requests) THEN
        RAISE EXCEPTION 'cannot roll back site origin pools after origin writes exist';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM site_origin_pools pool
        JOIN sites site ON site.id = pool.site_id
        JOIN LATERAL (
            SELECT
                array_agg(
                    CASE
                        WHEN origin.port = 80 THEN origin.host
                        WHEN position(':' IN origin.host) > 0
                            THEN '[' || origin.host || ']:' || origin.port::text
                        ELSE origin.host || ':' || origin.port::text
                    END
                    ORDER BY origin.position
                ) AS origins,
                array_agg(origin.host ORDER BY origin.position) AS origin_hosts,
                bool_and(origin.weight = 1 AND origin.enabled) AS defaults_only
            FROM site_origins origin
            WHERE origin.site_id = pool.site_id
        ) derived ON true
        WHERE pool.balance_method <> 'round_robin'
           OR pool.failover_tries <> 1
           OR pool.connect_timeout_ms <> 3000
           OR pool.read_timeout_ms <> 30000
           OR NOT derived.defaults_only
           OR site.origins IS DISTINCT FROM derived.origins
           OR site.origin_hosts IS DISTINCT FROM derived.origin_hosts
    ) THEN
        RAISE EXCEPTION 'cannot roll back non-default site origin pool state';
    END IF;
END;
$$;

DROP TRIGGER sites_require_origin_pool ON sites;
DROP TRIGGER site_origin_pools_validate ON site_origin_pools;
DROP TRIGGER site_origins_validate ON site_origins;
DROP FUNCTION check_site_origin_pool_from_site();
DROP FUNCTION check_site_origin_pool_from_pool();
DROP FUNCTION check_site_origin_pool_from_origin();
DROP FUNCTION validate_site_origin_pool(uuid);
DROP TABLE site_origin_write_requests;
DROP TABLE site_origins;
DROP TABLE site_origin_pools;
