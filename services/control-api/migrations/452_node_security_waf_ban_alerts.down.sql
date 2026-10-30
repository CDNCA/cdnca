LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_452_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 452 OR
       (SELECT max(version) FROM schema_migrations) <> 452 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=452 AND
        migration_id='452_node_security_waf_ban_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 452 down requires the exact verified migration head' USING ERRCODE='P4521';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'node.security.waf_ban.zh-cn') THEN
        RAISE EXCEPTION 'migration 452 rollback would orphan WAF ban notifications' USING ERRCODE='P4522';
    END IF;
END;
$migration_452_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'node.security.waf_ban.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'node.security.waf_ban';
DELETE FROM notification_event_policies WHERE event_type = 'node.security.waf_ban';
DELETE FROM admin_inbox_messages WHERE event_type = 'node.security.waf_ban';
