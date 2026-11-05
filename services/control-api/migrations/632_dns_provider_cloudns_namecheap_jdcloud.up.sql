LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_632_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 631 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 631 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=631 AND
        migration_id='631_dns_provider_dnspod_com_godaddy_namesilo' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 632 requires the exact verified 631 release head' USING ERRCODE='P6320';
    END IF;
END;
$migration_632_up$;

-- 632：前驱 631（DNSPod.com / GoDaddy / Namesilo），CHECK 列表含 631 的三个值，down 回到 631 之后的列表。
-- 内置 DNS 服务商 ClouDNS / Namecheap / 京东云：
-- provider_type 'cloudns'（凭据 sub_auth_id + auth_password）、'namecheap'（username + api_key + source_ip，
-- 来源 IP 须在 Namecheap 白名单）、'jdcloud'（access_key_id + access_key_secret）。
-- 凭据走既有凭据加密（credential_ciphertext），本迁移只放开封闭 CHECK。
-- 能力：ClouDNS、Namecheap 只写默认线路；京东云写 默认/电信/联通/移动/境外（免费版无境外）。
ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http', 'plugin',
        'namecom', 'dnspod_com', 'godaddy', 'namesilo', 'cloudns', 'namecheap', 'jdcloud')
);
