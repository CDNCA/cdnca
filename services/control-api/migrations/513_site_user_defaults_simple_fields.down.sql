-- 513（r136 fp-site3）回退：删新增 6 项的默认值，设置项约束恢复 492 的 12 项。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_513_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 513 OR
       (SELECT max(version) FROM schema_migrations) <> 513 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=513 AND
        migration_id='513_site_user_defaults_simple_fields' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 513 down requires the exact verified migration head' USING ERRCODE='P5131';
    END IF;
END;
$migration_513_down$;

DELETE FROM site_user_defaults WHERE setting_name IN ('ssl_protocols', 'ssl_cipher_preset', 'origin_protocol',
    'backend_http_port', 'origin_connect_timeout', 'origin_read_timeout');
ALTER TABLE site_user_defaults
    DROP CONSTRAINT site_user_defaults_setting_name_check,
    ADD CONSTRAINT site_user_defaults_setting_name_check CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time'));
