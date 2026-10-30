LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_443_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 443 OR
       (SELECT max(version) FROM schema_migrations) <> 443 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=443 AND
        migration_id='443_market_terms_notice' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 443 down requires the exact verified migration head' USING ERRCODE='P4431';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='market.terms.changed.zh-cn') THEN
        RAISE EXCEPTION 'migration 443 rollback would orphan market notifications' USING ERRCODE='P4432';
    END IF;
END;
$migration_443_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='market.terms.changed.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type='market.terms.changed';
DELETE FROM admin_inbox_messages WHERE event_type='market.terms.changed';
DELETE FROM notification_event_policies WHERE event_type='market.terms.changed';
