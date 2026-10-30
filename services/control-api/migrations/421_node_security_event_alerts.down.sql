LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_421_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 421 OR
       (SELECT max(version) FROM schema_migrations) <> 421 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=421 AND
        migration_id='421_node_security_event_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 421 down requires the exact verified migration head' USING ERRCODE='P4211';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'node.security.event.zh-cn') THEN
        RAISE EXCEPTION 'migration 421 rollback would orphan node security notifications' USING ERRCODE='P4212';
    END IF;
END;
$migration_421_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'node.security.event.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'node.security.event';
DELETE FROM notification_event_policies WHERE event_type = 'node.security.event';
