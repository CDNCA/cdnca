-- 518（r136 fp-site6，Q1：网站默认设置 #3 网站缓存 / #30 条件源站，独立维护的默认文档）。
-- 分支占位 515，merge-p9 改为 518、前驱 517（fp-cert）。
-- proxy_cache：一份缓存策略文档（JSON，同站点缓存页），建站同事务写成新站首个缓存策略修订。
-- cond_origin：只有条件规则（JSON routes），源站池为占位 @default，建站换成新站自身默认源站池；不含源站地址。
-- 两者取值上限 65536 字符，其余不变。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_518_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 517 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=517 AND
        migration_id='517_certificate_issuer_remark' AND
        checksum_sha256='5a8b1b9764b7850f0aa4355bf3828bbf3cb7ba0a9c81111d0f5ccf14ee99bf0a' AND
        down_checksum_sha256='3aa382edad4a30e1b7a3787bda23001755fc678d9bca1f72b8ee0398a8ec9fcc' AND
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
        RAISE EXCEPTION 'migration 518 requires the exact verified 517 head' USING ERRCODE='P5180';
    END IF;
END;
$migration_518_up$;

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
        'proxy_cache', 'cond_origin')),
    DROP CONSTRAINT site_user_defaults_setting_value_check,
    ADD CONSTRAINT site_user_defaults_setting_value_check CHECK (
        setting_value = btrim(setting_value) AND char_length(setting_value) >= 1 AND
        char_length(setting_value) <= CASE
            WHEN setting_name IN ('proxy_cache', 'cond_origin') THEN 65536
            WHEN setting_name = 'req_header' THEN 8192
            ELSE 256 END);
