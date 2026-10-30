LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_441_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 441 OR
       (SELECT max(version) FROM schema_migrations) <> 441 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=441 AND
        migration_id='441_market_commission_notices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 441 down requires the exact verified migration head' USING ERRCODE='P4411';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id LIKE 'market.commission.%.zh-cn') THEN
        RAISE EXCEPTION 'migration 441 rollback would orphan market commission notifications' USING ERRCODE='P4412';
    END IF;
END;
$migration_441_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id LIKE 'market.commission.%.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type LIKE 'market.commission.%';
DELETE FROM admin_inbox_messages WHERE event_type LIKE 'market.commission.%';
DELETE FROM notification_event_policies WHERE event_type LIKE 'market.commission.%';
