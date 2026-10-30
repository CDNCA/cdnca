LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_587_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 587 OR
       (SELECT max(version) FROM schema_migrations) <> 587 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=587 AND
        migration_id='587_plugin_promo_charge_notice' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 587 down requires the exact verified migration head' USING ERRCODE='P5871';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'market.plugin.promo_charge.zh-cn') THEN
        RAISE EXCEPTION 'migration 587 rollback would orphan plugin promo notifications' USING ERRCODE='P5872';
    END IF;
END;
$migration_587_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'market.plugin.promo_charge.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'market.plugin.promo_charge';
DELETE FROM admin_inbox_messages WHERE event_type = 'market.plugin.promo_charge';
DELETE FROM notification_event_policies WHERE event_type = 'market.plugin.promo_charge';
