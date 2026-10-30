LOCK TABLE schema_migrations, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_453_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 452 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 452 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=452 AND
        migration_id='452_node_security_waf_ban_alerts' AND
        checksum_sha256='4edf8710fbeb0e36b55fe8790d0929e1075d05e50890871abeb0ccc585599617' AND
        down_checksum_sha256='4e4cd71ee8088a8cf4732be4d4494d0efd4df2209396f25399affbff69f30507' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='site_origin_pools' AND column_name='follow_redirect'
       ) THEN
        RAISE EXCEPTION 'migration 453 requires the exact verified 452 release head' USING ERRCODE='P4530';
    END IF;
END;
$migration_453_up$;

-- 453 (r136 ge36-cache; placeholder number, renumbered on merge). Origin
-- redirect following (GoEdge "回源跟随"): the edge follows a 301/302/303/307/
-- 308 from the origin for a bodyless GET/HEAD and serves the final response.
--   follow_redirect               off by default;
--   follow_redirect_max_hops      redirects followed per request (1..5, 3: with
--                                 the node's own internal redirects nginx's
--                                 limit of 10 per request is not reached);
--   follow_redirect_cross_origin  a Location naming a host other than the
--                                 visitor's host, the site's domains or the
--                                 pool's origins is followed too (off: such a
--                                 redirect is returned to the visitor).
-- Publication needs the node capability ORIGIN_FOLLOW_REDIRECT.
ALTER TABLE site_origin_pools
    ADD COLUMN follow_redirect boolean NOT NULL DEFAULT false,
    ADD COLUMN follow_redirect_max_hops smallint NOT NULL DEFAULT 3
        CHECK (follow_redirect_max_hops BETWEEN 1 AND 5),
    ADD COLUMN follow_redirect_cross_origin boolean NOT NULL DEFAULT false;
