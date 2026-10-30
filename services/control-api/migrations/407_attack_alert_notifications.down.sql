LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_407_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 407 OR
       (SELECT max(version) FROM schema_migrations) <> 407 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=407 AND
        migration_id='407_attack_alert_notifications' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 407 down requires the exact verified migration head' USING ERRCODE='P4071';
    END IF;
    -- Templates referenced by queued or delivered outbox rows cannot be dropped.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='security.attack.detected.zh-cn') OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type='security.attack.detected') THEN
        RAISE EXCEPTION 'migration 407 rollback would discard attack alert notification history' USING ERRCODE='P4072';
    END IF;
END;
$migration_407_down$;

DROP TABLE attack_alert_site_states;
DROP TABLE attack_alert_cursor;
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='security.attack.detected.zh-cn';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type='security.attack.detected';
DELETE FROM notification_event_policies WHERE event_type='security.attack.detected';
