-- 699 回退：删除请求编号列与两个筛选索引，恢复 556 的原因约束（只有 denied 带原因）。
-- 失败行在 699 期间记下的 reason_code 清空（698 及更早版本不写也不读它）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_699_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 699 OR
       (SELECT max(version) FROM schema_migrations) <> 699 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=699 AND
        migration_id='699_billing_bridge_log_request_id' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 699 down requires the exact verified migration head' USING ERRCODE='P6991';
    END IF;
END;
$migration_699_down$;

DROP INDEX billing_bridge_logs_service_699_idx;
DROP INDEX billing_bridge_logs_request_699_idx;
UPDATE billing_bridge_logs SET reason_code = NULL WHERE result = 'failure' AND reason_code IS NOT NULL;
ALTER TABLE billing_bridge_logs
    DROP CONSTRAINT billing_bridge_logs_reason_699_check,
    ADD CONSTRAINT billing_bridge_logs_reason_556_check CHECK ((result = 'denied') = (reason_code IS NOT NULL)),
    DROP COLUMN request_id;
