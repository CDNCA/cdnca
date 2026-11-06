-- 640 回退：删除 DNS 批次幂等表，operation CHECK 恢复为 233 的列表。
-- platform_default / smart_schedule 的写入记录只用于幂等去重（回退后的代码不读），旧约束无法表示，删除这些行
-- （行保护触发器在删除期间停用，同 215/227/234 的做法）；与 638 回退直接删批次幂等表一致。
LOCK TABLE schema_migrations, node_scheduling_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_640_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 640 OR
       (SELECT max(version) FROM schema_migrations) <> 640 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=640 AND
        migration_id='640_line_group_dnshub_batch_idempotency' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 640 down requires the exact verified migration head' USING ERRCODE='P6401';
    END IF;
END;
$migration_640_down$;

DROP TABLE tenant_dns_record_batch_requests;

ALTER TABLE node_scheduling_write_requests DISABLE TRIGGER node_scheduling_write_requests_state;
DELETE FROM node_scheduling_write_requests
WHERE operation IN ('node_scheduling.group.platform_default', 'node_scheduling.group.smart_schedule');
ALTER TABLE node_scheduling_write_requests ENABLE TRIGGER node_scheduling_write_requests_state;

ALTER TABLE node_scheduling_write_requests
    DROP CONSTRAINT node_scheduling_write_requests_operation_check,
    ADD CONSTRAINT node_scheduling_write_requests_operation_check CHECK (operation IN (
        'node_scheduling.group.put',
        'node_scheduling.group.create',
        'node_scheduling.group.update',
        'node_scheduling.group.rollback',
        'node_scheduling.group.delete',
        'node_scheduling.target_snapshot.create'
    ));
