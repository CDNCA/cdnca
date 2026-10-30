LOCK TABLE schema_migrations, sites, site_origin_pools, l2_topology_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_466_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 465 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 465 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=465 AND
        migration_id='465_package_cname_sync' AND
        checksum_sha256='769f707d96643c9ac8d7001c4167ab12d73c3f86cdcd84ccafd58554ea72a61e' AND
        down_checksum_sha256='2235ca001a1ded0c1d73ca91d3c58d09b306507e2f545576febbd8226ccc6bc8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='site_origin_pools' AND column_name='acme_passthrough'
       ) THEN
        RAISE EXCEPTION 'migration 466 requires the exact verified 465 release head' USING ERRCODE='P4660';
    END IF;
END;
$migration_466_up$;

-- 466 (r136 site-backend6): local placeholder on the 459 head; merged as the
-- reserved 467 after 466. Site editing options of the competitor's advanced tab:
--   search_engine_origin  搜索引擎回源: host[:port] search engine crawlers
--                         (by User-Agent) are proxied to; they bypass the
--                         cache. NULL: off.
--   acme_passthrough      源站申请证书: /.well-known/acme-challenge/ goes to
--                         the origin unless the node holds our own token for
--                         that host and token (our issuance wins).
--   response_buffering /  数据实时返回 / 数据实时发送 (proxy_buffering /
--   request_buffering     proxy_request_buffering): off applies only to
--                         requests the cache does not serve.
--   l2_mode, l2_config_id 网站 L2 配置: package (the line group's L2, the
--                         default), off (straight to the origin), custom
--                         (only the L2 nodes of l2_config_id).
-- Publication needs node capability SITE_EDGE_OPTIONS for the first three.
ALTER TABLE site_origin_pools
    ADD COLUMN search_engine_origin text
        CHECK (search_engine_origin IS NULL OR
               char_length(search_engine_origin) BETWEEN 1 AND 512 AND search_engine_origin !~ '[[:space:][:cntrl:]/?#@]'),
    ADD COLUMN acme_passthrough boolean NOT NULL DEFAULT false,
    ADD COLUMN response_buffering boolean NOT NULL DEFAULT true,
    ADD COLUMN request_buffering boolean NOT NULL DEFAULT true,
    ADD COLUMN l2_mode text NOT NULL DEFAULT 'package' CHECK (l2_mode IN ('package', 'off', 'custom')),
    ADD COLUMN l2_config_id uuid,
    ADD CONSTRAINT site_origin_pools_l2_custom_466_check CHECK ((l2_mode = 'custom') = (l2_config_id IS NOT NULL));

-- A custom L2 names a live L2 configuration of the site's scope.
CREATE FUNCTION assert_site_l2_config_466()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.l2_config_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM l2_topology_configs config
        JOIN sites site ON site.id = NEW.site_id AND site.scope_id = config.tenant_scope_id
        WHERE config.id = NEW.l2_config_id AND config.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'site L2 configuration % is not an L2 configuration of the site''s scope', NEW.l2_config_id
            USING ERRCODE = 'P4663';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER site_origin_pools_l2_config_466
    BEFORE INSERT OR UPDATE OF l2_config_id ON site_origin_pools
    FOR EACH ROW EXECUTE FUNCTION assert_site_l2_config_466();

-- 默认站点: one default site in the whole installation (it answers every
-- Host no site serves, on every node).
CREATE UNIQUE INDEX sites_single_default_466 ON sites ((true)) WHERE is_default AND deleted_at IS NULL;
