LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_558_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 558 OR
       (SELECT max(version) FROM schema_migrations) <> 558 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=558 AND
        migration_id='558_market_renewal_compensated_notices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 558 down requires the exact verified migration head' USING ERRCODE='P5581';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE (template_id = 'market.renewal.compensated.zh-cn') OR
        (template_id IN ('market.renewal.stopped.zh-cn', 'market.renewal.resumed.zh-cn') AND template_version = 2)) THEN
        RAISE EXCEPTION 'migration 558 rollback would orphan market renewal compensation notifications' USING ERRCODE='P5582';
    END IF;
END;
$migration_558_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'market.renewal.compensated.zh-cn' AND version = 1;
DELETE FROM notification_templates WHERE template_id IN ('market.renewal.stopped.zh-cn', 'market.renewal.resumed.zh-cn') AND version = 2;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'market.renewal.compensated';
DELETE FROM admin_inbox_messages WHERE event_type = 'market.renewal.compensated';
DELETE FROM notification_event_policies WHERE event_type = 'market.renewal.compensated';
