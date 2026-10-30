LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_445_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 445 OR
       (SELECT max(version) FROM schema_migrations) <> 445 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=445 AND
        migration_id='445_market_deposit_notices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 445 down requires the exact verified migration head' USING ERRCODE='P4451';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN
        ('market.seller.deposit_mode.zh-cn', 'market.seller.deposit_shortfall.zh-cn', 'market.seller.default_compensated.zh-cn', 'market.seller.defaulted.zh-cn')) THEN
        RAISE EXCEPTION 'migration 445 rollback would orphan market deposit notifications' USING ERRCODE='P4452';
    END IF;
END;
$migration_445_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN
    ('market.seller.deposit_mode.zh-cn', 'market.seller.deposit_shortfall.zh-cn', 'market.seller.default_compensated.zh-cn', 'market.seller.defaulted.zh-cn') AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('market.seller.deposit_mode', 'market.seller.deposit_shortfall', 'market.seller.default_compensated', 'market.seller.defaulted');
DELETE FROM admin_inbox_messages WHERE event_type IN ('market.seller.deposit_mode', 'market.seller.deposit_shortfall', 'market.seller.default_compensated', 'market.seller.defaulted');
DELETE FROM notification_event_policies WHERE event_type IN ('market.seller.deposit_mode', 'market.seller.deposit_shortfall', 'market.seller.default_compensated', 'market.seller.defaulted');
