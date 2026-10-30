LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_422_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 422 OR
       (SELECT max(version) FROM schema_migrations) <> 422 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=422 AND
        migration_id='422_node_security_xdp_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 422 down requires the exact verified migration head' USING ERRCODE='P4221';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'node.security.xdp.zh-cn') THEN
        RAISE EXCEPTION 'migration 422 rollback would orphan node XDP notifications' USING ERRCODE='P4222';
    END IF;
END;
$migration_422_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'node.security.xdp.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
