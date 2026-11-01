-- 609 回滚：去掉线路组智能调度。仍有省份线路 DNS 记录（line_scope 含「:」）时拒绝回滚，
-- 先关闭智能调度、等省份线路撤下（cnamelines 把空集写到线路并删行）再回滚，不留无人管理的 DNS 记录。
LOCK TABLE schema_migrations, cname_carrier_line_records IN ACCESS EXCLUSIVE MODE;

DO $migration_609_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 609 OR
       (SELECT max(version) FROM schema_migrations) <> 609 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=609 AND
        migration_id='609_smart_schedule' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 609 down requires the exact verified migration head' USING ERRCODE='P6093';
    END IF;
    IF EXISTS (SELECT 1 FROM cname_carrier_line_records WHERE position(':' IN line_scope) > 0) THEN
        RAISE EXCEPTION 'migration 609 down refuses province line records' USING ERRCODE='P6094';
    END IF;
END;
$migration_609_down$;

ALTER TABLE cname_carrier_line_records DROP CONSTRAINT cname_carrier_line_records_line_scope_609_check,
    ADD CONSTRAINT cname_carrier_line_records_line_scope_check
        CHECK (line_scope IN ('telecom', 'unicom', 'mobile', 'overseas'));
DROP TABLE node_line_smart_selections;
DROP TABLE smart_schedule_ingest_cursors;
DROP TABLE node_line_latency_samples;
DROP TABLE node_line_group_smart_schedules;
