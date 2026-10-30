LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_388_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 388 OR
       (SELECT max(version) FROM schema_migrations) <> 388 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=388 AND
        migration_id='388_certificate_notices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 388 down requires the exact verified migration head' USING ERRCODE='P3881';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox
               WHERE template_id='certificate.renew_failed.zh-cn') THEN
        RAISE EXCEPTION 'migration 388 down refuses: certificate notices were sent' USING ERRCODE='P3882';
    END IF;
END;
$migration_388_down$;

DELETE FROM notification_subscriptions WHERE event_type='certificate.renew_failed';
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version=1 AND
    template_id='certificate.renew_failed.zh-cn';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_event_policies WHERE event_type='certificate.renew_failed';
