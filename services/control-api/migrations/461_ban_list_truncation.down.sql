LOCK TABLE schema_migrations, security_ban_node_state, escalate_site_drop_node_states, notification_event_policies,
    notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_461_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 461 OR
       (SELECT max(version) FROM schema_migrations) <> 461 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=461 AND
        migration_id='461_ban_list_truncation' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 461 down requires the exact verified migration head' USING ERRCODE='P4611';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'node.security.list_truncated.zh-cn') THEN
        RAISE EXCEPTION 'migration 461 rollback would orphan list truncation notifications' USING ERRCODE='P4612';
    END IF;
END;
$migration_461_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'node.security.list_truncated.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'node.security.list_truncated';
DELETE FROM notification_event_policies WHERE event_type = 'node.security.list_truncated';
DELETE FROM admin_inbox_messages WHERE event_type = 'node.security.list_truncated';

ALTER TABLE escalate_site_drop_node_states
    DROP CONSTRAINT escalate_site_drop_node_states_truncation_check,
    DROP COLUMN truncated_entries,
    DROP COLUMN warning_code;
ALTER TABLE security_ban_node_state
    DROP CONSTRAINT security_ban_node_state_truncation_check,
    DROP COLUMN truncated_entries,
    DROP COLUMN warning_code;
