-- 621 回退：不改数据。被置 failed 的订单不恢复为 pending / validating / issuing：订单状态机（048）不允许
--   failed 回到进行中，恢复后调度也只会再以同一个不可重试码失败。
LOCK TABLE schema_migrations, certificate_orders IN ACCESS EXCLUSIVE MODE;

DO $migration_621_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 621 OR
       (SELECT max(version) FROM schema_migrations) <> 621 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=621 AND
        migration_id='621_certificate_order_outbox_failure' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 621 down requires the exact verified migration head' USING ERRCODE='P6211';
    END IF;
END;
$migration_621_down$;
