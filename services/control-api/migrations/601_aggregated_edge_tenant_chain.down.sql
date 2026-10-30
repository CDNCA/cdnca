-- 601 回退：删除租户保底链选择表与 aggregated_edge.tenant.switch 通知事件。
-- 已入队或已发送的消息引用模板时拒绝回退（不留孤儿消息）。
LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_601_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 601 OR
       (SELECT max(version) FROM schema_migrations) <> 601 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=601 AND
        migration_id='601_aggregated_edge_tenant_chain' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 601 down requires the exact verified migration head' USING ERRCODE='P6011';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'aggregated_edge.tenant.switch.zh-cn') THEN
        RAISE EXCEPTION 'migration 601 rollback would orphan tenant switch notifications' USING ERRCODE='P6012';
    END IF;
END;
$migration_601_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'aggregated_edge.tenant.switch.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'aggregated_edge.tenant.switch';
DELETE FROM notification_event_policies WHERE event_type = 'aggregated_edge.tenant.switch';
DELETE FROM admin_inbox_messages WHERE event_type = 'aggregated_edge.tenant.switch';
DROP TABLE fallback_chain_tenant_choices;
