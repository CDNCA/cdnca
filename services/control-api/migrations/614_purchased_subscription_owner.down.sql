-- 614 回退：只做版本守卫，不删回填的归属行。
-- package_monitor_subscription_owners 只追加（078 触发器拒绝 DELETE），站点外键
-- sites_package_subscription_owner_113_fk 也引用它；这些行满足 078 的全部约束，
-- 对 613 及更早的代码同样是合法数据。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_614_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 614 OR
       (SELECT max(version) FROM schema_migrations) <> 614 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=614 AND
        migration_id='614_purchased_subscription_owner' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 614 down requires the exact verified migration head' USING ERRCODE='P6141';
    END IF;
END;
$migration_614_down$;
