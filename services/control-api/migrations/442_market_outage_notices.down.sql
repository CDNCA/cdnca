LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_442_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 442 OR
       (SELECT max(version) FROM schema_migrations) <> 442 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=442 AND
        migration_id='442_market_outage_notices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 442 down requires the exact verified migration head' USING ERRCODE='P4421';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN
        ('market.supply.outage.zh-cn', 'market.supply.restored.zh-cn', 'market.supply.cancel_available.zh-cn')) THEN
        RAISE EXCEPTION 'migration 442 rollback would orphan market outage notifications' USING ERRCODE='P4422';
    END IF;
END;
$migration_442_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN
    ('market.supply.outage.zh-cn', 'market.supply.restored.zh-cn', 'market.supply.cancel_available.zh-cn') AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('market.supply.outage', 'market.supply.restored', 'market.supply.cancel_available');
DELETE FROM admin_inbox_messages WHERE event_type IN ('market.supply.outage', 'market.supply.restored', 'market.supply.cancel_available');
DELETE FROM notification_event_policies WHERE event_type IN ('market.supply.outage', 'market.supply.restored', 'market.supply.cancel_available');
