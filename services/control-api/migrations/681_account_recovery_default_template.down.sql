LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_681_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 681 OR
       (SELECT max(version) FROM schema_migrations) <> 681 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=681 AND
           migration_id='681_account_recovery_default_template' AND integrity_state='verified' AND
           metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='account_recovery_email') THEN
        RAISE EXCEPTION 'migration 681 rollback requires the exact unused verified release head' USING ERRCODE='P6810';
    END IF;
END;
$migration_681_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='account_recovery_email' AND version=1 AND channel='email';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
