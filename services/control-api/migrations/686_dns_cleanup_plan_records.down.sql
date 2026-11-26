-- 686 回滚：删除清除计划的完整记录表。685 及更早版本执行清除时不读这张表（按 item_id 解析记录）。
LOCK TABLE schema_migrations, background_job_items IN ACCESS EXCLUSIVE MODE;

DO $migration_686_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 686 OR
       (SELECT max(version) FROM schema_migrations) <> 686 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=686 AND
        migration_id='686_dns_cleanup_plan_records' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 686 down requires the exact verified migration head' USING ERRCODE='P6861';
    END IF;
END;
$migration_686_down$;

DROP TABLE dns_cleanup_plan_records;
