LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_347_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 347 OR
       (SELECT max(version) FROM schema_migrations) <> 347 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=347 AND
        migration_id='347_acme_http01_epoch_drift_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 347 down requires the exact verified migration head' USING ERRCODE='P3479';
    END IF;
    -- Templates referenced by queued or delivered outbox rows cannot be dropped.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='acme.http01.epoch_drift.zh-cn') THEN
        RAISE EXCEPTION 'migration 347 rollback would discard HTTP-01 drift alert history' USING ERRCODE='P3479';
    END IF;
END;
$migration_347_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='acme.http01.epoch_drift.zh-cn' AND version=1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type='acme.http01.epoch_drift';
DELETE FROM notification_event_policies WHERE event_type='acme.http01.epoch_drift';
