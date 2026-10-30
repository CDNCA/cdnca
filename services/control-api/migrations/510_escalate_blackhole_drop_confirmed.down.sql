LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_510_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 510 OR
       (SELECT max(version) FROM schema_migrations) <> 510 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=510 AND
        migration_id='510_escalate_blackhole_drop_confirmed' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 510 down requires the exact verified migration head' USING ERRCODE='P5101';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'security.escalate.blackhole_drop_confirmed.zh-cn' OR
               (template_id = 'security.escalate.blackhole.zh-cn' AND template_version = 2)) THEN
        RAISE EXCEPTION 'migration 510 rollback would orphan attack escalation blackhole notifications' USING ERRCODE='P5102';
    END IF;
END;
$migration_510_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'security.escalate.blackhole_drop_confirmed.zh-cn' AND version = 1;
DELETE FROM notification_templates WHERE template_id = 'security.escalate.blackhole.zh-cn' AND version = 2;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'security.escalate.blackhole_drop_confirmed';
DELETE FROM notification_event_policies WHERE event_type = 'security.escalate.blackhole_drop_confirmed';
DELETE FROM admin_inbox_messages WHERE event_type = 'security.escalate.blackhole_drop_confirmed';
