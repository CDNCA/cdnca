-- 494（r136 tp-b3a-be，回源设置对齐竞品需后端 5 项；本地占位 490，merge-p3 合入改为 494、前驱 493）。
LOCK TABLE schema_migrations, site_origin_pools, site_origins IN ACCESS EXCLUSIVE MODE;

DO $migration_494_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 493 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 493 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=493 AND
        migration_id='493_system_configuration_nginx_override_scope_key' AND
        checksum_sha256='fa961053ca5cc3d43427db05819f3c367d4df16578dc72a937c0c43b0ddba1a5' AND
        down_checksum_sha256='73b0a06256b2c413c8bea9a3e8eca6cf6162110f2882fa9a6a5fb224d97c7572' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        (table_name='site_origin_pools' AND column_name IN ('http_port', 'origin_auth_enabled') OR
         table_name='site_origins' AND column_name='port_inherited')) THEN
        RAISE EXCEPTION 'migration 494 requires the exact verified 493 release head' USING ERRCODE='P4940';
    END IF;
END;
$migration_494_up$;

-- 竞品回源设置（tenant-parity b3a 需后端清单）：
-- 1. 回源协议"跟随协议和端口" = origin_scheme 'follow' 且 follow_port：两种访问协议都按访客端口回源。
--    此时两个端口都不使用，固定为默认值（与 http 时 https_port=443 同一写法）。
-- 2. 回源域名"访问域名+端口" = request_host_mode 'visitor_port'：Host 为访客域名加访问端口。
-- 3. 池级"HTTP 回源端口" http_port（默认 80）；HTTPS 回源时 https_port 也作池级默认（不再限 443）。
--    site_origins.port_inherited = 该源站没单独设端口，port 存按池级端口算出的实际端口
--    （http/follow 用 http_port，https 用 https_port），其他读 port 的地方不用改；改池级端口时整池重写。
-- 4. 站点级回源鉴权开关 origin_auth_enabled：关闭时该站点的签名规则不下发，规则本身保留。
-- 1.0.35 是初始版本（用户 10-24 定不考虑兼容）；已有行取默认值即与原行为一致。
ALTER TABLE site_origin_pools
    ADD COLUMN http_port integer NOT NULL DEFAULT 80 CHECK (http_port BETWEEN 1 AND 65535),
    ADD COLUMN origin_auth_enabled boolean NOT NULL DEFAULT true,
    DROP CONSTRAINT site_origin_pools_request_host_mode_check,
    ADD CONSTRAINT site_origin_pools_request_host_mode_check
        CHECK (request_host_mode IN ('visitor', 'visitor_port', 'origin', 'custom')),
    DROP CONSTRAINT site_origin_pools_tls_379,
    ADD CONSTRAINT site_origin_pools_ports_494 CHECK (
        (origin_scheme <> 'http' OR (tls_sni IS NULL AND tls_trust = 'system' AND https_port = 443)) AND
        (origin_scheme <> 'https' OR http_port = 80) AND
        (origin_scheme <> 'follow' OR NOT follow_port OR (http_port = 80 AND https_port = 443))
    );

ALTER TABLE site_origins
    ADD COLUMN port_inherited boolean NOT NULL DEFAULT false;
