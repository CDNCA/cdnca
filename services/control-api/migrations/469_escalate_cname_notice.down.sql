LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_469_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 469 OR
       (SELECT max(version) FROM schema_migrations) <> 469 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=469 AND
        migration_id='469_escalate_cname_notice' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 469 down requires the exact verified migration head' USING ERRCODE='P4691';
    END IF;
    -- Queued or sent messages reference the template: refuse instead of orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'security.escalate.cname_change_required.zh-cn') THEN
        RAISE EXCEPTION 'migration 469 rollback would orphan attack escalation CNAME notifications' USING ERRCODE='P4692';
    END IF;
END;
$migration_469_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'security.escalate.cname_change_required.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'security.escalate.cname_change_required';
DELETE FROM notification_event_policies WHERE event_type = 'security.escalate.cname_change_required';
DELETE FROM admin_inbox_messages WHERE event_type = 'security.escalate.cname_change_required';
