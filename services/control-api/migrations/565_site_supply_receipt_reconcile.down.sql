LOCK TABLE schema_migrations, site_supply_leaf_sites, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_565_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 565 OR
       (SELECT max(version) FROM schema_migrations) <> 565 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=565 AND
        migration_id='565_site_supply_receipt_reconcile' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 565 down requires the exact verified migration head' USING ERRCODE='P5651';
    END IF;
    -- A committing leaf has answered but its outcome is unconfirmed: 555 has no
    -- state for it, so refuse rather than lose which revision it may run.
    IF EXISTS (SELECT 1 FROM site_supply_leaf_sites WHERE state = 'committing') THEN
        RAISE EXCEPTION 'migration 565 down refuses to drop unconfirmed leaf receipts' USING ERRCODE='P5652';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'market.supply.receipt_unconfirmed.zh-cn') THEN
        RAISE EXCEPTION 'migration 565 rollback would orphan receipt notifications' USING ERRCODE='P5653';
    END IF;
END;
$migration_565_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id = 'market.supply.receipt_unconfirmed.zh-cn';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'market.supply.receipt_unconfirmed';
DELETE FROM notification_event_policies WHERE event_type = 'market.supply.receipt_unconfirmed';
DELETE FROM admin_inbox_messages WHERE event_type = 'market.supply.receipt_unconfirmed';

DROP INDEX site_supply_leaf_sites_reconcile_565_idx;
ALTER TABLE site_supply_leaf_sites DROP CONSTRAINT site_supply_leaf_sites_committing_565;
ALTER TABLE site_supply_leaf_sites DROP COLUMN next_reconcile_at, DROP COLUMN reconcile_attempts,
    DROP COLUMN pending_digest, DROP COLUMN pending_revision;
ALTER TABLE site_supply_leaf_sites DROP CONSTRAINT site_supply_leaf_sites_state_565;
ALTER TABLE site_supply_leaf_sites ADD CONSTRAINT site_supply_leaf_sites_state_check CHECK (
    state IN ('pending', 'applied', 'failed', 'inconsistent'));
