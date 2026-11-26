LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_696_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 696 OR
       (SELECT max(version) FROM schema_migrations) <> 696 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=696 AND
           migration_id='696_origin_failover_hold_template' AND integrity_state='verified' AND
           metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='site.origin.failover.hold.zh-cn') THEN
        RAISE EXCEPTION 'migration 696 rollback requires the exact unused verified release head' USING ERRCODE='P6961';
    END IF;
END;
$migration_696_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='site.origin.failover.hold.zh-cn' AND version=1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
