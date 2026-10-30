-- 497（r136 region-override-trim）回退：只删清理函数；被清掉的资源/默认配置区域覆盖不恢复
-- （控制端本来就拒绝保存这类覆盖）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_497_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 497 OR
       (SELECT max(version) FROM schema_migrations) <> 497 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=497 AND
        migration_id='497_system_configuration_trim_region_overrides' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 497 down requires the exact verified migration head' USING ERRCODE='P4972';
    END IF;
END;
$migration_497_down$;

DROP FUNCTION system_configuration_trim_region_overrides_497(jsonb);
