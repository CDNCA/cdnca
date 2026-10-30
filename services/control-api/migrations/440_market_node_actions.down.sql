LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_440_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 440 OR
       (SELECT max(version) FROM schema_migrations) <> 440 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=440 AND
        migration_id='440_market_node_actions' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 440 down requires the exact verified migration head' USING ERRCODE='P4401';
    END IF;
    -- Queued or sent messages reference the templates: refuse instead of
    -- orphaning them.
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN
        ('market.node.action.zh-cn', 'market.site.paused.zh-cn', 'market.site.resumed.zh-cn')) THEN
        RAISE EXCEPTION 'migration 440 rollback would orphan market notifications' USING ERRCODE='P4402';
    END IF;
    IF EXISTS (SELECT 1 FROM market_node_action_queue WHERE reported_at IS NULL) THEN
        RAISE EXCEPTION 'migration 440 rollback would drop unreported node actions' USING ERRCODE='P4403';
    END IF;
END;
$migration_440_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN ('market.node.action.zh-cn', 'market.site.paused.zh-cn', 'market.site.resumed.zh-cn')
    AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('market.node.action', 'market.site.paused', 'market.site.resumed');
DELETE FROM admin_inbox_messages WHERE event_type IN ('market.node.action', 'market.site.paused', 'market.site.resumed');
DELETE FROM notification_event_policies WHERE event_type IN ('market.node.action', 'market.site.paused', 'market.site.resumed');
DROP TABLE market_node_action_queue;
