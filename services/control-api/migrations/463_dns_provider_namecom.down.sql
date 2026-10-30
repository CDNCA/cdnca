LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_463_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 463 OR
       (SELECT max(version) FROM schema_migrations) <> 463 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=463 AND
        migration_id='463_dns_provider_namecom' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 463 down requires the exact verified migration head' USING ERRCODE='P4631';
    END IF;
    -- 回退会让已有的 name.com 服务商违反 CHECK：有就拒绝，不静默删除用户的 DNS 配置。
    IF EXISTS (SELECT 1 FROM dns_providers WHERE provider_type = 'namecom') THEN
        RAISE EXCEPTION 'migration 463 rollback would drop name.com DNS providers in use' USING ERRCODE='P4632';
    END IF;
END;
$migration_463_down$;

ALTER TABLE dns_providers DROP CONSTRAINT dns_providers_provider_type_check;
ALTER TABLE dns_providers ADD CONSTRAINT dns_providers_provider_type_check CHECK (
    provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la', 'custom_http', 'plugin')
);
