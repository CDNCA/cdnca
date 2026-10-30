LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_488_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 488 OR
       (SELECT max(version) FROM schema_migrations) <> 488 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=488 AND
        migration_id='488_market_renewal_stop_notices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 488 down requires the exact verified migration head' USING ERRCODE='P4881';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN
        ('market.renewal.stopped.zh-cn', 'market.renewal.resumed.zh-cn')) THEN
        RAISE EXCEPTION 'migration 488 rollback would orphan market renewal notifications' USING ERRCODE='P4882';
    END IF;
END;
$migration_488_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN
    ('market.renewal.stopped.zh-cn', 'market.renewal.resumed.zh-cn') AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('market.renewal.stopped', 'market.renewal.resumed');
DELETE FROM admin_inbox_messages WHERE event_type IN ('market.renewal.stopped', 'market.renewal.resumed');
DELETE FROM notification_event_policies WHERE event_type IN ('market.renewal.stopped', 'market.renewal.resumed');
