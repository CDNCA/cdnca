-- 519（r136 fp-site7，Q1：网站默认设置 #4/#31 区域屏蔽快捷预设，竞品 block_region）。
-- 分支占位 516，merge-p9 改为 519、前驱 518（fp-site6）。
-- block_region：abrord_inc / abrord_no_inc / china_inc / china_not_inc / none（取值照竞品），
-- 建站时一条 WAF country 规则并入新站 WAF 副本（与屏蔽透明代理同路径），none 不建规则。取值约束不变（256）。
LOCK TABLE schema_migrations, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_519_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 518 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=518 AND
        migration_id='518_site_user_defaults_documents' AND
        checksum_sha256='b909362db80e615f2a525035eab28b73f9412c2a78300e02eb537b5482869bb9' AND
        down_checksum_sha256='6cf6cf19d87abd595207389968fb51a639c03983bc18f1a09035beec6c7a5cba' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='site_user_defaults_setting_name_check' AND
        conrelid=to_regclass(current_schema() || '.site_user_defaults')
       ) THEN
        RAISE EXCEPTION 'migration 519 requires the exact verified 518 head' USING ERRCODE='P5190';
    END IF;
END;
$migration_519_up$;

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
        'block_region'));
