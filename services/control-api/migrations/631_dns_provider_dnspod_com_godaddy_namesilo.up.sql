-- 631：前驱 630_market_node_probe_alerts。
-- 主控内置 DNS 服务商新增 DNSPod.com（国际版）、GoDaddy、Namesilo。
-- provider_type 'dnspod_com'（dp_id + dp_key，api.dnspod.com 旧版 API）/ 'godaddy'（api_key + api_secret，sso-key）/ 'namesilo'（key）；
-- 凭据走既有凭据加密（credential_ciphertext），本迁移只放开封闭 CHECK。
-- 三家都只写默认线路；TTL 下限 DNSPod.com 600（免费版）、GoDaddy 600、Namesilo 3600，低于时按下限写入（dnsproviderremote.EffectiveTTL）。
LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_631_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 630 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 630 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=630 AND
        migration_id='630_market_node_probe_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 631 requires the exact verified 630 release head' USING ERRCODE='P6310';
    END IF;
END;
$migration_631_up$;

ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http', 'plugin',
        'namecom', 'dnspod_com', 'godaddy', 'namesilo')
);
