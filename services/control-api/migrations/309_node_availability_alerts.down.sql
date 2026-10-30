LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_309_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 309 OR
       (SELECT max(version) FROM schema_migrations) <> 309 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=309 AND
        migration_id='309_node_availability_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 309 down requires the exact verified migration head' USING ERRCODE='P3091';
    END IF;
    -- Templates referenced by queued or delivered outbox rows cannot be dropped.
    IF EXISTS (SELECT 1 FROM notification_outbox
               WHERE template_id IN ('node.availability.offline.zh-cn', 'node.availability.recovered.zh-cn')) THEN
        RAISE EXCEPTION 'migration 309 rollback would discard node alert history' USING ERRCODE='P3091';
    END IF;
END;
$migration_309_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates
WHERE template_id IN ('node.availability.offline.zh-cn', 'node.availability.recovered.zh-cn') AND version=1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions
WHERE event_type IN ('node.availability.offline', 'node.availability.recovered');
DELETE FROM notification_event_policies
WHERE event_type IN ('node.availability.offline', 'node.availability.recovered');
