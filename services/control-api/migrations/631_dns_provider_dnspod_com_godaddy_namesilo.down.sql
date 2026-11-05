-- 631 回滚：provider_type CHECK 回到 630 的取值（去掉 dnspod_com / godaddy / namesilo）。
LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_631_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 631 OR
       (SELECT max(version) FROM schema_migrations) <> 631 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=631 AND
        migration_id='631_dns_provider_dnspod_com_godaddy_namesilo' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 631 down requires the exact verified migration head' USING ERRCODE='P6311';
    END IF;
    -- 回退会让已有的这三类服务商违反 CHECK：有就拒绝，不静默删除用户的 DNS 配置。
    IF EXISTS (SELECT 1 FROM dns_providers WHERE provider_type IN ('dnspod_com', 'godaddy', 'namesilo')) THEN
        RAISE EXCEPTION 'migration 631 rollback would drop DNSPod.com / GoDaddy / Namesilo DNS providers in use' USING ERRCODE='P6312';
    END IF;
END;
$migration_631_down$;

ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http', 'plugin',
        'namecom')
);
