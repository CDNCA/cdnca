-- 494（r136 tp-b3a-be）回退：去掉池级 HTTP 端口、站点回源鉴权开关、源站端口继承标记，恢复 379 约束。
-- 存在 494 才允许的取值（访问域名+端口、跟随协议和端口、HTTPS 非 443、继承端口）时拒绝回退，不静默改写数据。
LOCK TABLE schema_migrations, site_origin_pools, site_origins IN ACCESS EXCLUSIVE MODE;

DO $migration_494_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 494 OR
       (SELECT max(version) FROM schema_migrations) <> 494 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=494 AND
        migration_id='494_site_origin_parity' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 494 down requires the exact verified migration head' USING ERRCODE='P4941';
    END IF;
    IF EXISTS (SELECT 1 FROM site_origin_pools WHERE request_host_mode = 'visitor_port' OR http_port <> 80 OR
               NOT origin_auth_enabled OR (origin_scheme = 'follow' AND follow_port) OR
               (origin_scheme = 'https' AND https_port <> 443)) OR
       EXISTS (SELECT 1 FROM site_origins WHERE port_inherited) THEN
        RAISE EXCEPTION 'migration 494 down: settings only 494 allows are in use' USING ERRCODE='P4942';
    END IF;
END;
$migration_494_down$;

ALTER TABLE site_origins DROP COLUMN port_inherited;

ALTER TABLE site_origin_pools
    DROP CONSTRAINT site_origin_pools_ports_494,
    ADD CONSTRAINT site_origin_pools_tls_379 CHECK (
        (origin_scheme <> 'http' OR (tls_sni IS NULL AND tls_trust = 'system')) AND
        (origin_scheme = 'follow' OR https_port = 443)
    ),
    DROP CONSTRAINT site_origin_pools_request_host_mode_check,
    ADD CONSTRAINT site_origin_pools_request_host_mode_check
        CHECK (request_host_mode IN ('visitor', 'origin', 'custom')),
    DROP COLUMN origin_auth_enabled,
    DROP COLUMN http_port;
