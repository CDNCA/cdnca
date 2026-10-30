LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_370_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 370 OR
       (SELECT max(version) FROM schema_migrations) <> 370 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=370 AND migration_id='370_plugin_webhook_site_filter' AND
        integrity_state='verified'
       ) THEN
        RAISE EXCEPTION 'migration 370 down requires the verified 370 head' USING ERRCODE='P3709';
    END IF;
    IF EXISTS (SELECT 1 FROM plugin_webhook_subscriptions WHERE site_ids IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 370 down would widen site-filtered subscriptions' USING ERRCODE='P3709';
    END IF;
END;
$migration_370_down$;

LOCK TABLE plugin_webhook_subscriptions, plugin_webhook_deliveries IN ACCESS EXCLUSIVE MODE;

DROP TRIGGER plugin_webhook_deliveries_site_filter_370 ON plugin_webhook_deliveries;
DROP TRIGGER plugin_webhook_subscriptions_site_filter_370 ON plugin_webhook_subscriptions;
DROP FUNCTION validate_plugin_webhook_delivery_site_370();
DROP FUNCTION validate_plugin_webhook_site_filter_370();
ALTER TABLE plugin_webhook_subscriptions DROP CONSTRAINT plugin_webhook_subscriptions_site_ids_370,
    DROP COLUMN site_ids;
