-- 633 回滚：去掉 control.db_pool.saturated / control.db_pool.recovered 通知。
LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_633_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 633 OR
       (SELECT max(version) FROM schema_migrations) <> 633 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=633 AND
        migration_id='633_control_db_pool_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 633 down requires the exact verified migration head' USING ERRCODE='P6331';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN
            ('control.db_pool.saturated.zh-cn', 'control.db_pool.recovered.zh-cn')) THEN
        RAISE EXCEPTION 'migration 633 rollback would orphan control database pool notifications' USING ERRCODE='P6332';
    END IF;
END;
$migration_633_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id IN
    ('control.db_pool.saturated.zh-cn', 'control.db_pool.recovered.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('control.db_pool.saturated', 'control.db_pool.recovered');
DELETE FROM notification_event_policies WHERE event_type IN ('control.db_pool.saturated', 'control.db_pool.recovered');
DELETE FROM admin_inbox_messages WHERE event_type IN ('control.db_pool.saturated', 'control.db_pool.recovered');
