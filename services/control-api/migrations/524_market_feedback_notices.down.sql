LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_524_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 524 OR
       (SELECT max(version) FROM schema_migrations) <> 524 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=524 AND
        migration_id='524_market_feedback_notices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 524 down requires the exact verified migration head' USING ERRCODE='P5241';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN
        ('market.feedback.opened.zh-cn', 'market.feedback.updated.zh-cn')) THEN
        RAISE EXCEPTION 'migration 524 rollback would orphan market feedback notifications' USING ERRCODE='P5242';
    END IF;
END;
$migration_524_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN
    ('market.feedback.opened.zh-cn', 'market.feedback.updated.zh-cn') AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('market.feedback.opened', 'market.feedback.updated');
DELETE FROM admin_inbox_messages WHERE event_type IN ('market.feedback.opened', 'market.feedback.updated');
DELETE FROM notification_event_policies WHERE event_type IN ('market.feedback.opened', 'market.feedback.updated');
