LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_575_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 575 OR
       (SELECT max(version) FROM schema_migrations) <> 575 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=575 AND
        migration_id='575_node_install_trust_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 575 down requires the exact verified migration head' USING ERRCODE='P5751';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'node.install_trust.failed.zh-cn') THEN
        RAISE EXCEPTION 'migration 575 rollback would orphan node install trust notifications' USING ERRCODE='P5752';
    END IF;
END;
$migration_575_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id = 'node.install_trust.failed.zh-cn';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'node.install_trust.failed';
DELETE FROM notification_event_policies WHERE event_type = 'node.install_trust.failed';
DELETE FROM admin_inbox_messages WHERE event_type = 'node.install_trust.failed';
