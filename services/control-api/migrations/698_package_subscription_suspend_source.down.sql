-- 698 回退：删除暂停来源读取函数。暂停版本快照里的 suspend_source 键保留，697 及更早版本不读它。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_698_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 698 OR
       (SELECT max(version) FROM schema_migrations) <> 698 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=698 AND
        migration_id='698_package_subscription_suspend_source' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 698 down requires the exact verified migration head' USING ERRCODE='P6981';
    END IF;
END;
$migration_698_down$;

DROP FUNCTION package_subscription_suspend_source_698(uuid);
