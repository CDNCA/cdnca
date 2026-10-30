LOCK TABLE schema_migrations, notification_event_policies, notification_templates, notification_subscriptions,
    notification_events IN ACCESS EXCLUSIVE MODE;

DO $migration_323_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 323 OR
       (SELECT max(version) FROM schema_migrations) <> 323 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=323 AND
        migration_id='323_notification_subscription_defaults' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 323 down requires the exact verified migration head' USING ERRCODE='P3231';
    END IF;
    -- Operator ticket notifications already sent must not be orphaned.
    IF EXISTS (SELECT 1 FROM notification_events WHERE event_type LIKE 'ticket.staff.%') THEN
        RAISE EXCEPTION 'migration 323 rollback would discard operator ticket notifications' USING ERRCODE='P3231';
    END IF;
END;
$migration_323_down$;

DELETE FROM notification_subscriptions WHERE event_type IN ('ticket.staff.created', 'ticket.staff.replied');
DELETE FROM notification_event_policies WHERE event_type IN ('ticket.staff.created', 'ticket.staff.replied');
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN ('ticket_staff_created', 'ticket_staff_replied');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
ALTER TABLE notification_event_policies DROP COLUMN default_sms, DROP COLUMN default_email;
