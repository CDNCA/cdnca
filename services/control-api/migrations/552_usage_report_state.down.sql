-- 554 回滚：删掉用量上报持久状态。旧版本回到进程内存序号（L08 修复前的行为）；
-- 授权端仍按序号单调拒收，回滚不会让授权端接受倒退的序号。
LOCK TABLE schema_migrations, control_usage_report_state IN ACCESS EXCLUSIVE MODE;

DO $migration_552_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 552 OR
       (SELECT max(version) FROM schema_migrations) <> 552 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=552 AND
        migration_id='552_usage_report_state' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 552 down requires the exact verified migration head' USING ERRCODE='P5521';
    END IF;
END;
$migration_552_down$;

DROP TABLE control_usage_report_state;
