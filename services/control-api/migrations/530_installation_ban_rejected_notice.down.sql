LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_530_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 530 OR
       (SELECT max(version) FROM schema_migrations) <> 530 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=530 AND
        migration_id='530_installation_ban_rejected_notice' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 530 down requires the exact verified migration head' USING ERRCODE='P5301';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'installation_ban.rejected.zh-cn') THEN
        RAISE EXCEPTION 'migration 530 rollback would orphan installation ban rejection notifications' USING ERRCODE='P5302';
    END IF;
END;
$migration_530_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'installation_ban.rejected.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'installation_ban.rejected';
DELETE FROM notification_event_policies WHERE event_type = 'installation_ban.rejected';
DELETE FROM admin_inbox_messages WHERE event_type = 'installation_ban.rejected';
