-- 513（r136 fp-site3，Q1 用户 10-25 12:3x：网站默认设置 36 项补齐，第二批简单字段）。分支占位 503，
-- merge-p9 改为 513、前驱 512（集成头）。
-- 新增 6 个设置项：TLS 协议、密码套件预设、回源协议、回源 HTTP 端口、回源连接/读取超时（秒）。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_513_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 512 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 512 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=512 AND
        migration_id='512_waf_adapt_repeat_site' AND
        checksum_sha256='15653b01b18cbd95b9f5c205da9d4cb6376e2051fe64e27c16f5cbe1619e1ccd' AND
        down_checksum_sha256='09536ef812f97e50db7aba8227efe1e2d331e8e4a198ac2680312cdad92b22ec' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='site_user_defaults_setting_name_check' AND
        conrelid=to_regclass(current_schema() || '.site_user_defaults')
       ) THEN
        RAISE EXCEPTION 'migration 513 requires the exact verified 512 release head' USING ERRCODE='P5130';
    END IF;
END;
$migration_513_up$;

ALTER TABLE site_user_defaults
    DROP CONSTRAINT site_user_defaults_setting_name_check,
    ADD CONSTRAINT site_user_defaults_setting_name_check CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time',
        'ssl_protocols', 'ssl_cipher_preset', 'origin_protocol', 'backend_http_port',
        'origin_connect_timeout', 'origin_read_timeout'));
