LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_463_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 462 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 462 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=462 AND
        migration_id='462_node_dnspup_probe' AND
        checksum_sha256='bef82dc2fa73b6da7b1996f5017c5aeb666eedb60993ae9a5c70dfa874904fb3' AND
        down_checksum_sha256='c841ad0ddcf7785eda6750e4ebdd81fbbafe1511cc8170c91692404557bc7c93' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 463 requires the exact verified 462 release head' USING ERRCODE='P4630';
    END IF;
END;
$migration_463_up$;

-- 463（r136 dns-namecom，占位号：主会话预留 control 463，合入时改号并把前驱守卫改为实际前一版）。
-- 内置 DNS 服务商 name.com（用户 10-22 23:05 决定，写进主控包、不做插件）：provider_type 'namecom'。
-- 凭据 username + api_token 走既有凭据加密（credential_ciphertext），本迁移只放开封闭 CHECK。
-- name.com 记录没有线路字段：适配器只写默认线路；TTL 下限 300（低于时按 300 写入，见 dnsproviderremote.EffectiveTTL）。
ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http', 'plugin',
        'namecom')
);
