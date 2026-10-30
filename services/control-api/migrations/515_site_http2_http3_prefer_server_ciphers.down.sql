-- 515（r136 fp-site5a）回退：删站点 HTTP2/HTTP3/prefer 三列与 3 项默认值，设置项约束恢复 514 的 23 项。
LOCK TABLE schema_migrations, sites, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_515_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 515 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=515 AND
        migration_id='515_site_http2_http3_prefer_server_ciphers' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 515 down requires the exact verified migration head' USING ERRCODE='P5151';
    END IF;
END;
$migration_515_down$;

-- 节点回到全部站点 HTTP/2、HTTP/3 开，prefer 按预设。
DELETE FROM site_user_defaults WHERE setting_name IN ('http2', 'http3', 'ssl_prefer_server_ciphers');
ALTER TABLE site_user_defaults
    DROP CONSTRAINT site_user_defaults_setting_name_check,
    ADD CONSTRAINT site_user_defaults_setting_name_check CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time',
        'ssl_protocols', 'ssl_cipher_preset', 'origin_protocol', 'backend_http_port',
        'origin_connect_timeout', 'origin_read_timeout',
        'cc_ban_seconds', 'cc_pass_seconds', 'gzip_enable', 'dns_provider', 'ipv6_enable'));
ALTER TABLE sites
    DROP COLUMN tls_prefer_server_ciphers,
    DROP COLUMN http3_enabled,
    DROP COLUMN http2_enabled;
