LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_430_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 430 OR
       (SELECT max(version) FROM schema_migrations) <> 430 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=430 AND
        migration_id='430_market_notices' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 430 down requires the exact verified migration head' USING ERRCODE='P4301';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id LIKE 'market.%.zh-cn') THEN
        RAISE EXCEPTION 'migration 430 rollback would orphan market notifications' USING ERRCODE='P4302';
    END IF;
END;
$migration_430_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id LIKE 'market.%.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type LIKE 'market.%';
DELETE FROM admin_inbox_messages WHERE event_type LIKE 'market.%';
DELETE FROM notification_event_policies WHERE event_type LIKE 'market.%';
