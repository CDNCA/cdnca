LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_336_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 336 OR
       (SELECT max(version) FROM schema_migrations) <> 336 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=336 AND
        migration_id='336_cc_auto_switch_notifications' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 336 down requires the exact verified migration head' USING ERRCODE='P3361';
    END IF;
    -- Templates referenced by queued or delivered outbox rows cannot be dropped.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='package.monitor.cc_rule_auto_switch.zh-cn') OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type='package.monitor.cc_rule_auto_switch') THEN
        RAISE EXCEPTION 'migration 336 rollback would discard CC auto switch notification history' USING ERRCODE='P3362';
    END IF;
END;
$migration_336_down$;

DROP TABLE cc_auto_switch_notification_windows;
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='package.monitor.cc_rule_auto_switch.zh-cn';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type='package.monitor.cc_rule_auto_switch';
UPDATE notification_event_policies
SET supported=false, enabled=false, sms_enabled=false, email_enabled=false, default_email=false, updated_at=now()
WHERE event_type='package.monitor.cc_rule_auto_switch';
