LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_424_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 424 OR
       (SELECT max(version) FROM schema_migrations) <> 424 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=424 AND
        migration_id='424_rule_intel_report_state' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 424 down requires the exact verified migration head' USING ERRCODE='P4241';
    END IF;
END;
$migration_424_down$;

-- 状态行只是投递记录（报告可随时从源数据重建），下降直接删除。
DROP TABLE rule_intel_report_state;
