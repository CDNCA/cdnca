-- 492（r136 tp-b2）回退：删网站默认设置、自动加记录任务和 DNS 账号备注，写请求约束恢复 413 的取值。
LOCK TABLE schema_migrations, dns_providers, site_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_492_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 492 OR
       (SELECT max(version) FROM schema_migrations) <> 492 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=492 AND
        migration_id='492_tenant_site_defaults_auto_dns' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 492 down requires the exact verified migration head' USING ERRCODE='P4921';
    END IF;
END;
$migration_492_down$;

DELETE FROM site_write_requests
WHERE operation IN ('site_default.create', 'site_default.update', 'site_default.delete');
ALTER TABLE site_write_requests
    DROP CONSTRAINT site_write_requests_operation_check,
    ADD CONSTRAINT site_write_requests_operation_check CHECK (
        operation IN ('site.create', 'site.update', 'site.delete', 'site.lock', 'site.unlock',
                      'site.status_recovery.unlock', 'site.status_recovery.renewal',
                      'site.status_recovery.traffic_top_up')
    );
DROP TABLE site_auto_dns_tasks;
DROP TABLE site_user_defaults;
ALTER TABLE dns_providers DROP COLUMN remark;
