-- 599 回退：删除用户端域名解析的清单缓存与操作记录（记录本身在 DNS 商，不受影响）。
-- 操作记录里还有"不确定"态（已提交给 DNS 商、未回读确认）时拒绝回退，避免丢掉待重查的线索。
LOCK TABLE schema_migrations, tenant_dns_provider_listings, tenant_dns_domains, tenant_dns_record_ops
    IN ACCESS EXCLUSIVE MODE;

DO $migration_599_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 599 OR
       (SELECT max(version) FROM schema_migrations) <> 599 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=599 AND
        migration_id='599_tenant_dns_hub' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 599 down requires the exact verified migration head' USING ERRCODE='P5991';
    END IF;
    IF EXISTS (SELECT 1 FROM tenant_dns_record_ops WHERE state = 'uncertain') THEN
        RAISE EXCEPTION 'migration 599 down: unconfirmed DNS hub record operations exist' USING ERRCODE='P5992';
    END IF;
END;
$migration_599_down$;

DROP TABLE tenant_dns_record_ops;
DROP TABLE tenant_dns_domains;
DROP TABLE tenant_dns_provider_listings;
DROP FUNCTION tenant_dns_hub_provider_guard_599();
