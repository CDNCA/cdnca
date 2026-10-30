-- 550 回滚：去掉 CNAME 域名"参与随机分配"开关。
-- 管理员勾选过的域名是运营可见的配置，回滚会悄悄丢掉，此时拒绝回滚（先在 CNAME 域名页取消全部勾选）。
-- 已随机分配出去的 CNAME 不受影响（claim 记录的是具体区）。
LOCK TABLE schema_migrations, dns_zones IN ACCESS EXCLUSIVE MODE;

DO $migration_550_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 550 OR
       (SELECT max(version) FROM schema_migrations) <> 550 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=550 AND
        migration_id='550_cname_zone_random_allocation' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 550 down requires the exact verified migration head' USING ERRCODE='P5501';
    END IF;
    IF EXISTS (SELECT 1 FROM dns_zones WHERE random_allocation) THEN
        RAISE EXCEPTION 'migration 550 rollback would discard the CNAME domains marked for random allocation'
            USING ERRCODE='P5502';
    END IF;
END;
$migration_550_down$;

DROP INDEX dns_zones_random_allocation_550_idx;
ALTER TABLE dns_zones DROP COLUMN random_allocation;
