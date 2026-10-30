-- 569 回滚：去掉 DNS 账户来源列；旧版本回到“平台副本与本人账户不区分”的行为。
LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_569_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 569 OR
       (SELECT max(version) FROM schema_migrations) <> 569 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=569 AND
        migration_id='569_dns_provider_managed_by' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 569 down requires the exact verified migration head' USING ERRCODE='P5691';
    END IF;
END;
$migration_569_down$;

ALTER TABLE dns_providers DROP COLUMN managed_by;
