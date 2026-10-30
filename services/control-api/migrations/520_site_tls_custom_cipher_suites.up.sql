-- 520（r136 tls-custom）：站点自定义 TLS1.2 密码套件 + 网站默认设置 #11「自定义套件」。
-- 分支占位 517，merge-p9 改为 520、前驱 519（fp-site7）。
LOCK TABLE schema_migrations, sites, site_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_520_up$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 519 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=519 AND
        migration_id='519_site_user_defaults_block_region' AND
        checksum_sha256='1a06ffb308fcc63c57a59a60fa3e58575edbbb127f644640a448d47b720213dd' AND
        down_checksum_sha256='d1c6b413f854a066e3a926645a7b0cde25b79577dbffd509dfa7b6b3af8a4bc9' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='sites_tls_cipher_preset_387' AND
        conrelid=to_regclass(current_schema() || '.sites')
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname='site_user_defaults_setting_value_check' AND
        conrelid=to_regclass(current_schema() || '.site_user_defaults')
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='tls_cipher_suites'
       ) THEN
        RAISE EXCEPTION 'migration 520 requires the exact verified 519 head' USING ERRCODE='P5200';
    END IF;
END;
$migration_520_up$;

-- tls_cipher_preset 新增 custom：tls_cipher_suites 是有序 OpenSSL TLS1.2 套件名列表，
-- 名字必须取自 edgeconfig.TLSCustomCipherSuites 白名单（Go 校验，这里只管形状与耦合）：
-- custom ⇔ 列表非空（1..20 项、无空项）；custom 要求协议含 TLSv1.2（TLSv1/1.1 仍只能 legacy，原约束保留）。
-- 已有站点不变（NULL）。列变更照常推高 scope 的 source_revision（335）。
ALTER TABLE sites
    ADD COLUMN tls_cipher_suites text[],
    DROP CONSTRAINT sites_tls_cipher_preset_387,
    ADD CONSTRAINT sites_tls_cipher_preset_520 CHECK (
        tls_cipher_preset IN ('modern','compatible','legacy','custom') AND
        (tls_cipher_preset = 'legacy' OR NOT tls_protocols && ARRAY['TLSv1','TLSv1.1']::text[]) AND
        ((tls_cipher_preset = 'custom') = (tls_cipher_suites IS NOT NULL)) AND
        (tls_cipher_suites IS NULL OR
         cardinality(tls_cipher_suites) BETWEEN 1 AND 20 AND array_position(tls_cipher_suites, NULL) IS NULL AND
         'TLSv1.2' = ANY(tls_protocols))
    );

-- 默认设置 #11：ssl_cipher_preset 可取 custom（取值在 Go 校验），新键 ssl_cipher_suites
-- （冒号分隔的白名单套件，最长 20 个名字，取值上限 1024）。
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
        'block_region', 'ssl_cipher_suites')),
    DROP CONSTRAINT site_user_defaults_setting_value_check,
    ADD CONSTRAINT site_user_defaults_setting_value_check CHECK (
        setting_value = btrim(setting_value) AND char_length(setting_value) >= 1 AND
        char_length(setting_value) <= CASE
            WHEN setting_name IN ('proxy_cache', 'cond_origin') THEN 65536
            WHEN setting_name = 'req_header' THEN 8192
            WHEN setting_name = 'ssl_cipher_suites' THEN 1024
            ELSE 256 END);
