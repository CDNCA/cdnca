LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_554_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 554 OR
       (SELECT max(version) FROM schema_migrations) <> 554 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=554 AND
        migration_id='554_node_bandwidth_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 554 down requires the exact verified migration head' USING ERRCODE='P5541';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN ('node.bandwidth.exceeded.zh-cn',
        'node.bandwidth.recovered.zh-cn')) THEN
        RAISE EXCEPTION 'migration 554 rollback would orphan node bandwidth notifications' USING ERRCODE='P5542';
    END IF;
END;
$migration_554_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id IN ('node.bandwidth.exceeded.zh-cn',
    'node.bandwidth.recovered.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('node.bandwidth.exceeded', 'node.bandwidth.recovered');
DELETE FROM notification_event_policies WHERE event_type IN ('node.bandwidth.exceeded', 'node.bandwidth.recovered');
DELETE FROM admin_inbox_messages WHERE event_type IN ('node.bandwidth.exceeded', 'node.bandwidth.recovered');
