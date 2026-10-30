-- 571 回滚：删掉线路组备用 IP 状态与两类通知。旧版本回到只在视图里现算、不通知的行为。
LOCK TABLE schema_migrations, notification_event_policies, notification_templates, node_line_group_backup_states
    IN ACCESS EXCLUSIVE MODE;

DO $migration_571_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 571 OR
       (SELECT max(version) FROM schema_migrations) <> 571 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=571 AND
        migration_id='571_node_line_backup_states' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 571 down requires the exact verified migration head' USING ERRCODE='P5711';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN ('node.line_group.backup_ip_activated.zh-cn',
        'node.line_group.primary_ip_restored.zh-cn')) THEN
        RAISE EXCEPTION 'migration 571 rollback would orphan line group backup IP notifications' USING ERRCODE='P5712';
    END IF;
END;
$migration_571_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id IN ('node.line_group.backup_ip_activated.zh-cn',
    'node.line_group.primary_ip_restored.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('node.line_group.backup_ip_activated',
    'node.line_group.primary_ip_restored');
DELETE FROM notification_event_policies WHERE event_type IN ('node.line_group.backup_ip_activated',
    'node.line_group.primary_ip_restored');
DELETE FROM admin_inbox_messages WHERE event_type IN ('node.line_group.backup_ip_activated',
    'node.line_group.primary_ip_restored');

DROP TABLE node_line_group_backup_states;
