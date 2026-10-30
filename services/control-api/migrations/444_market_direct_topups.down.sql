LOCK TABLE schema_migrations, payment_channels, payment_reconcile_mismatches, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_444_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 444 OR
       (SELECT max(version) FROM schema_migrations) <> 444 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=444 AND
        migration_id='444_market_direct_topups' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 444 down requires the exact verified migration head' USING ERRCODE='P4441';
    END IF;
    -- Money received into this seller's merchant account and channels opened
    -- for the market cannot be expressed by the 431 schema.
    IF EXISTS (SELECT 1 FROM market_direct_topup_orders) OR
       EXISTS (SELECT 1 FROM payment_channels WHERE scenes <> ARRAY['recharge']::text[]) OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN ('market.direct_topup.paid.zh-cn',
           'market.direct_topup.received.zh-cn', 'payment.market_topup.rejected.zh-cn')) THEN
        RAISE EXCEPTION 'migration 444 rollback would drop direct top-up facts' USING ERRCODE='P4442';
    END IF;
END;
$migration_444_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN ('market.direct_topup.paid.zh-cn',
    'market.direct_topup.received.zh-cn', 'payment.market_topup.rejected.zh-cn') AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('market.direct_topup.paid', 'market.direct_topup.received',
    'payment.market_topup.rejected');
DELETE FROM admin_inbox_messages WHERE event_type IN ('market.direct_topup.paid', 'market.direct_topup.received',
    'payment.market_topup.rejected');
DELETE FROM notification_event_policies WHERE event_type IN ('market.direct_topup.paid', 'market.direct_topup.received',
    'payment.market_topup.rejected');
ALTER TABLE payment_reconcile_mismatches DROP CONSTRAINT payment_reconcile_mismatches_order_444;
ALTER TABLE payment_reconcile_mismatches DROP COLUMN market_topup_id;
ALTER TABLE payment_reconcile_mismatches ADD CHECK (kind = 'remote_only' OR (order_id IS NOT NULL AND local_amount_minor IS NOT NULL));
DROP TABLE market_direct_topup_reports;
DROP TABLE market_direct_topup_payments;
DROP TABLE market_direct_topup_orders;
ALTER TABLE payment_channels DROP CONSTRAINT payment_channels_scenes_444;
ALTER TABLE payment_channels ADD CHECK (scenes = ARRAY['recharge']::text[]);
