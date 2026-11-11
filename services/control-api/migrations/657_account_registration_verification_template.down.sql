LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_657_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 657 OR
       (SELECT max(version) FROM schema_migrations) <> 657 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=657 AND
           migration_id='657_account_registration_verification_template' AND integrity_state='verified' AND
           metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='account_registration_verification') THEN
        RAISE EXCEPTION 'migration 657 rollback requires the exact unused verified release head' USING ERRCODE='P6570';
    END IF;
END;
$migration_657_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='account_registration_verification' AND version=1 AND channel IN ('email','sms');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
