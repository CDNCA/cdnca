LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_404_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 404 OR
       (SELECT max(version) FROM schema_migrations) <> 404 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=404 AND
        migration_id='404_payment_plugin_reconciliation' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 404 down requires the exact verified migration head' USING ERRCODE='P4041';
    END IF;
    -- Reconciliation results and the alerts already queued are history.
    IF EXISTS (SELECT 1 FROM payment_reconcile_runs) OR EXISTS (
        SELECT 1 FROM notification_outbox
        WHERE template_id IN ('payment.reconcile.mismatch.zh-cn', 'payment.plugin.alert.zh-cn')
       ) THEN
        RAISE EXCEPTION 'migration 404 rollback would discard payment reconciliation history' USING ERRCODE='P4042';
    END IF;
END;
$migration_404_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates
WHERE template_id IN ('payment.reconcile.mismatch.zh-cn', 'payment.plugin.alert.zh-cn') AND version=1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('payment.reconcile.mismatch', 'payment.plugin.alert');
DELETE FROM notification_event_policies WHERE event_type IN ('payment.reconcile.mismatch', 'payment.plugin.alert');
DROP TABLE payment_reconcile_mismatches;
DROP TABLE payment_reconcile_runs;
