-- 514（r136 fp-site4）回退：删新增 5 项的默认值，设置项约束恢复 513 的 18 项。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_514_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 514 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=514 AND
        migration_id='514_site_user_defaults_cc_gzip_dns' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 514 down requires the exact verified migration head' USING ERRCODE='P5141';
    END IF;
END;
$migration_514_down$;

DELETE FROM site_user_defaults WHERE setting_name IN ('cc_ban_seconds', 'cc_pass_seconds', 'gzip_enable', 'dns_provider', 'ipv6_enable');
ALTER TABLE site_user_defaults
    DROP CONSTRAINT site_user_defaults_setting_name_check,
    ADD CONSTRAINT site_user_defaults_setting_name_check CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time',
        'ssl_protocols', 'ssl_cipher_preset', 'origin_protocol', 'backend_http_port',
        'origin_connect_timeout', 'origin_read_timeout'));
