-- 514（r136 fp-site4，Q1：网站默认设置 36 项补齐，第三批）。分支占位 511，merge-p9 改为 514、
-- 前驱 513（fp-site3）。
-- 新增 5 个设置项：CC 黑名单时间 / 白名单时间（秒，新建 CC 策略时带入）、Gzip 开关、默认 DNS API 账号、IPv6。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_514_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 513 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=513 AND
        migration_id='513_site_user_defaults_simple_fields' AND
        checksum_sha256='c45caa34f12ed06d320fb3beb52ad1b9f353b594417478ae168199a89c308876' AND
        down_checksum_sha256='3a28588acdf48a798046ca81c16159be9cfbad97a8f1f36289a5136dadd90d7f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='site_user_defaults_setting_name_check' AND
        conrelid=to_regclass(current_schema() || '.site_user_defaults')
       ) THEN
        RAISE EXCEPTION 'migration 514 requires the exact verified 513 head' USING ERRCODE='P5140';
    END IF;
END;
$migration_514_up$;

ALTER TABLE site_user_defaults
    DROP CONSTRAINT site_user_defaults_setting_name_check,
    ADD CONSTRAINT site_user_defaults_setting_name_check CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time',
        'ssl_protocols', 'ssl_cipher_preset', 'origin_protocol', 'backend_http_port',
        'origin_connect_timeout', 'origin_read_timeout',
        'cc_ban_seconds', 'cc_pass_seconds', 'gzip_enable', 'dns_provider', 'ipv6_enable'));
