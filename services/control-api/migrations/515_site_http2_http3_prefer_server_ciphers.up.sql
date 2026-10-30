-- 515（r136 fp-site5a，Q1：网站默认设置 #7 HTTP2 / #8 HTTP3 / #12 ssl_prefer_server_ciphers 按站点生效）。
-- 分支占位 512，merge-p9 改为 515、前驱 514（fp-site4）。
LOCK TABLE schema_migrations, sites, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_515_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 514 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=514 AND
        migration_id='514_site_user_defaults_cc_gzip_dns' AND
        checksum_sha256='0637dafeff710df58ca6b22c437fcacef48ac9854335ee0e358ff15ccb1fb40c' AND
        down_checksum_sha256='09c0658d7146d0c32e9da7f5bc20a863714d24d49d7b27a4c4915e9b75289643' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='site_user_defaults_setting_name_check' AND
        conrelid=to_regclass(current_schema() || '.site_user_defaults')
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND
              column_name IN ('http2_enabled','http3_enabled','tls_prefer_server_ciphers')
       ) THEN
        RAISE EXCEPTION 'migration 515 requires the exact verified 514 head' USING ERRCODE='P5150';
    END IF;
END;
$migration_515_up$;

-- 站点 HTTPS 协议开关（编辑站点 > HTTPS）。
-- http2_enabled：关则该站的 TLS 连接只协商 http/1.1（节点原生补丁 27 按连接设 ALPN，能力 SITE_TLS_OPTIONS）。
-- http3_enabled：关则该站不发 Alt-Svc、拒绝 QUIC 握手（节点按站点已支持，无新能力）；仍需 TLSv1.3。
-- tls_prefer_server_ciphers：NULL 按密码套件预设（modern 关，compatible/legacy 开）；显式值与预设不同时需 SITE_TLS_OPTIONS。
-- 已有站点保持现状（HTTP/2、HTTP/3 开，prefer 按预设）。列变更照常推高 scope 的 source_revision（335）。
ALTER TABLE sites
    ADD COLUMN http2_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN http3_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN tls_prefer_server_ciphers boolean;

-- 默认设置新增 3 项：http2 / http3 / ssl_prefer_server_ciphers（1 / 0），建站请求未写时带入。
ALTER TABLE site_user_defaults
    DROP CONSTRAINT site_user_defaults_setting_name_check,
    ADD CONSTRAINT site_user_defaults_setting_name_check CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time',
        'ssl_protocols', 'ssl_cipher_preset', 'origin_protocol', 'backend_http_port',
        'origin_connect_timeout', 'origin_read_timeout',
        'cc_ban_seconds', 'cc_pass_seconds', 'gzip_enable', 'dns_provider', 'ipv6_enable',
        'http2', 'http3', 'ssl_prefer_server_ciphers'));
