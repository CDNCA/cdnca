LOCK TABLE schema_migrations, site_origin_route_endpoints IN ACCESS EXCLUSIVE MODE;

DO $migration_485_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 485 OR
       (SELECT max(version) FROM schema_migrations) <> 485 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=485 AND
        migration_id='485_site_origin_route_endpoint_host' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 485 down requires the exact verified migration head' USING ERRCODE='P4851';
    END IF;
    -- inet 放不下域名：有域名端点就拒绝回退，而不是丢掉或改写客户的回源配置。只有 IP 端点时可以回退。
    IF EXISTS (SELECT 1 FROM site_origin_route_endpoints WHERE NOT pg_input_is_valid(host, 'inet')) THEN
        RAISE EXCEPTION 'migration 485 down found DNS origin-route endpoints that inet cannot hold' USING ERRCODE='P4852';
    END IF;
END;
$migration_485_down$;

ALTER TABLE site_origin_route_endpoints
    DROP CONSTRAINT site_origin_route_endpoints_host_check,
    ALTER COLUMN host TYPE inet USING host::inet,
    ADD CONSTRAINT site_origin_route_endpoints_host_check CHECK (
        host <> '0.0.0.0'::inet AND host <> '::'::inet AND
        host <> '255.255.255.255'::inet AND
        NOT host << '169.254.0.0/16'::inet AND NOT host << 'fe80::/10'::inet AND
        NOT host << '224.0.0.0/4'::inet AND NOT host << 'ff00::/8'::inet
    );

DROP FUNCTION site_origin_route_host_valid_485(text);
