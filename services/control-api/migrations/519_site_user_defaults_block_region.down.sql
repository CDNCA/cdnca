-- 519（r136 fp-site7）回退：删区域屏蔽预设默认，设置项约束恢复 518。
-- 已并入站点 WAF 副本的区域规则属于站点，不回退。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_519_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 519 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=519 AND
        migration_id='519_site_user_defaults_block_region' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 519 down requires the exact verified migration head' USING ERRCODE='P5191';
    END IF;
END;
$migration_519_down$;

DELETE FROM site_user_defaults WHERE setting_name = 'block_region';
ALTER TABLE site_user_defaults
    DROP CONSTRAINT site_user_defaults_setting_name_check,
    ADD CONSTRAINT site_user_defaults_setting_name_check CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time',
        'ssl_protocols', 'ssl_cipher_preset', 'origin_protocol', 'backend_http_port',
        'origin_connect_timeout', 'origin_read_timeout',
        'cc_ban_seconds', 'cc_pass_seconds', 'gzip_enable', 'dns_provider', 'ipv6_enable',
        'http2', 'http3', 'ssl_prefer_server_ciphers',
        'cc_policy', 'waf_policy', 'acl_policy', 'block_proxy', 'req_header', 'post_size_limit',
        'proxy_cache', 'cond_origin'));
