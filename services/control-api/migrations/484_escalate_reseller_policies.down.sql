LOCK TABLE schema_migrations, escalate_package_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_484_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 484 OR
       (SELECT max(version) FROM schema_migrations) <> 484 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=484 AND
        migration_id='484_escalate_reseller_policies' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 484 down requires the exact verified migration head' USING ERRCODE='P4843';
    END IF;
END;
$migration_484_down$;

-- 只去掉所有者守卫；代理商已配的策略保留（所有者仍等于套餐所有者，483 的数据形状不变）。
DROP TRIGGER escalate_package_policies_owner_484 ON escalate_package_policies;
DROP FUNCTION guard_escalate_policy_owner_484();
