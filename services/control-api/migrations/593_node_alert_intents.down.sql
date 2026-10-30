-- 593 回滚：删掉节点告警通知意图表。旧版本回到只在保存点里入队、失败即丢的行为；仍 pending 的意图拒绝回滚（不静默丢弃待补发通知）。
LOCK TABLE schema_migrations, node_alert_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_593_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 593 OR
       (SELECT max(version) FROM schema_migrations) <> 593 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=593 AND
        migration_id='593_node_alert_intents' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 593 down requires the exact verified migration head' USING ERRCODE='P5931';
    END IF;
    IF EXISTS (SELECT 1 FROM node_alert_intents WHERE status = 'pending') THEN
        RAISE EXCEPTION 'migration 593 rollback would drop pending node alerts' USING ERRCODE='P5932';
    END IF;
END;
$migration_593_down$;

DROP TABLE node_alert_intents;
