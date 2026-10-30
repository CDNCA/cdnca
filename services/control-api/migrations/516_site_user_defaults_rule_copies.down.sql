-- 516（r136 fp-site5b）回退：删新增 6 项的默认值，设置项与取值约束恢复 515。
-- 已复制给站点的规则库、绑定与 HTTP 策略属于站点，不回退。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_516_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 516 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=516 AND
        migration_id='516_site_user_defaults_rule_copies' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 516 down requires the exact verified migration head' USING ERRCODE='P5161';
    END IF;
END;
$migration_516_down$;

DELETE FROM site_user_defaults WHERE setting_name IN ('cc_policy', 'waf_policy', 'acl_policy', 'block_proxy', 'req_header', 'post_size_limit');
ALTER TABLE site_user_defaults
    DROP CONSTRAINT site_user_defaults_setting_name_check,
    ADD CONSTRAINT site_user_defaults_setting_name_check CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time',
        'ssl_protocols', 'ssl_cipher_preset', 'origin_protocol', 'backend_http_port',
        'origin_connect_timeout', 'origin_read_timeout',
        'cc_ban_seconds', 'cc_pass_seconds', 'gzip_enable', 'dns_provider', 'ipv6_enable',
        'http2', 'http3', 'ssl_prefer_server_ciphers')),
    DROP CONSTRAINT site_user_defaults_setting_value_check,
    ADD CONSTRAINT site_user_defaults_setting_value_check CHECK (
        setting_value = btrim(setting_value) AND char_length(setting_value) BETWEEN 1 AND 256);
