LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_632_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 632 OR
       (SELECT max(version) FROM schema_migrations) <> 632 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=632 AND
        migration_id='632_dns_provider_cloudns_namecheap_jdcloud' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 632 down requires the exact verified migration head' USING ERRCODE='P6321';
    END IF;
    -- 回退会让已有的 ClouDNS / Namecheap / 京东云服务商违反 CHECK：有就拒绝，不静默删除用户的 DNS 配置。
    IF EXISTS (SELECT 1 FROM dns_providers WHERE provider_type IN ('cloudns', 'namecheap', 'jdcloud')) THEN
        RAISE EXCEPTION 'migration 632 rollback would drop ClouDNS, Namecheap or JD Cloud DNS providers in use' USING ERRCODE='P6322';
    END IF;
END;
$migration_632_down$;

ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http', 'plugin',
        'namecom', 'dnspod_com', 'godaddy', 'namesilo')
);
