-- 520（r136 tls-custom）回退：删站点自定义套件列与默认设置 ssl_cipher_suites，约束恢复 519。
-- 已用 custom 的站点回到 compatible（白名单就是 compatible 预设的套件，客户端都还能握手），
-- custom 的 ssl_cipher_preset 默认值同样改回 compatible。
LOCK TABLE schema_migrations, sites, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_520_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 520 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=520 AND
        migration_id='520_site_tls_custom_cipher_suites' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 520 down requires the exact verified migration head' USING ERRCODE='P5201';
    END IF;
END;
$migration_520_down$;

ALTER TABLE sites DROP CONSTRAINT sites_tls_cipher_preset_520;
UPDATE sites SET tls_cipher_preset='compatible' WHERE tls_cipher_preset='custom';
ALTER TABLE sites
    DROP COLUMN tls_cipher_suites,
    ADD CONSTRAINT sites_tls_cipher_preset_387 CHECK (
        tls_cipher_preset IN ('modern','compatible','legacy') AND
        (tls_cipher_preset = 'legacy' OR NOT tls_protocols && ARRAY['TLSv1','TLSv1.1']::text[])
    );

DELETE FROM site_user_defaults WHERE setting_name = 'ssl_cipher_suites';
UPDATE site_user_defaults SET setting_value='compatible'
WHERE setting_name = 'ssl_cipher_preset' AND setting_value = 'custom';
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
        'proxy_cache', 'cond_origin',
        'block_region')),
    DROP CONSTRAINT site_user_defaults_setting_value_check,
    ADD CONSTRAINT site_user_defaults_setting_value_check CHECK (
        setting_value = btrim(setting_value) AND char_length(setting_value) >= 1 AND
        char_length(setting_value) <= CASE
            WHEN setting_name IN ('proxy_cache', 'cond_origin') THEN 65536
            WHEN setting_name = 'req_header' THEN 8192
            ELSE 256 END);
