LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_438_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 438 OR
       (SELECT max(version) FROM schema_migrations) <> 438 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=438 AND
        migration_id='438_market_downstream_attacked' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 438 down requires the exact verified migration head' USING ERRCODE='P4381';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id='market.downstream.attacked.zh-cn') THEN
        RAISE EXCEPTION 'migration 438 rollback would orphan market notifications' USING ERRCODE='P4382';
    END IF;
END;
$migration_438_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id='market.downstream.attacked.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type='market.downstream.attacked';
DELETE FROM admin_inbox_messages WHERE event_type='market.downstream.attacked';
DELETE FROM notification_event_policies WHERE event_type='market.downstream.attacked';
