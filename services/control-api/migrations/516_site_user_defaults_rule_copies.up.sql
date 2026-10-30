-- 516（r136 fp-site5b，Q1：网站默认设置复杂规则按复制快照）。分支占位 513，merge-p9 改为 516、
-- 前驱 515（fp-site5a）。
-- 新增 6 个设置项：默认 CC / WAF / 黑白名单 IP 规则库（本人规则库 ID，建站时复制成新站专用一份）、
-- 屏蔽透明代理、源站请求头、上传文件大小限制（MB，写新站 HTTP 策略）。
-- 源站请求头每行一个「名称: 值」，最多 64 行，放宽 setting_value 长度到 8192。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_516_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 515 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=515 AND
        migration_id='515_site_http2_http3_prefer_server_ciphers' AND
        checksum_sha256='ef8696f8e7f2bc5eb26eab764eb3db456fa11df7306e673cdaf660223f601a9e' AND
        down_checksum_sha256='05ff7df871fb8100643e151c8d0b90dce0b2f16577078315e143ac2fb3105695' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='site_user_defaults_setting_name_check' AND
        conrelid=to_regclass(current_schema() || '.site_user_defaults')
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='site_user_defaults_setting_value_check' AND
        conrelid=to_regclass(current_schema() || '.site_user_defaults')
       ) THEN
        RAISE EXCEPTION 'migration 516 requires the exact verified 515 head' USING ERRCODE='P5160';
    END IF;
END;
$migration_516_up$;

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
        'cc_policy', 'waf_policy', 'acl_policy', 'block_proxy', 'req_header', 'post_size_limit')),
    DROP CONSTRAINT site_user_defaults_setting_value_check,
    ADD CONSTRAINT site_user_defaults_setting_value_check CHECK (
        setting_value = btrim(setting_value) AND char_length(setting_value) >= 1 AND
        char_length(setting_value) <= CASE WHEN setting_name = 'req_header' THEN 8192 ELSE 256 END);
