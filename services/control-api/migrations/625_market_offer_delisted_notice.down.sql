LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_625_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 625 OR
       (SELECT max(version) FROM schema_migrations) <> 625 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=625 AND
        migration_id='625_market_offer_delisted_notice' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 625 down requires the exact verified migration head' USING ERRCODE='P6251';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'market.terms.changed.zh-cn' AND template_version = 3) THEN
        RAISE EXCEPTION 'migration 625 rollback would orphan market terms changed notifications' USING ERRCODE='P6252';
    END IF;
END;
$migration_625_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'market.terms.changed.zh-cn' AND version = 3;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
