LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_622_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 622 OR
       (SELECT max(version) FROM schema_migrations) <> 622 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=622 AND
        migration_id='622_market_terms_notice_sla' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 622 down requires the exact verified migration head' USING ERRCODE='P6221';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'market.terms.changed.zh-cn' AND template_version = 2) THEN
        RAISE EXCEPTION 'migration 622 rollback would orphan market terms changed notifications' USING ERRCODE='P6222';
    END IF;
END;
$migration_622_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'market.terms.changed.zh-cn' AND version = 2;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
