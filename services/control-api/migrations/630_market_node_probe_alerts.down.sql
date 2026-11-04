-- 630 回滚：去掉订阅节点本主控探测告警状态列与 market.node.probe_unreachable / probe_recovered 通知。
LOCK TABLE schema_migrations, market_subscribed_nodes, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_630_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 630 OR
       (SELECT max(version) FROM schema_migrations) <> 630 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=630 AND
        migration_id='630_market_node_probe_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 630 down requires the exact verified migration head' USING ERRCODE='P6301';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id IN
            ('market.node.probe_unreachable.zh-cn', 'market.node.probe_recovered.zh-cn')) THEN
        RAISE EXCEPTION 'migration 630 rollback would orphan market node probe notifications' USING ERRCODE='P6302';
    END IF;
END;
$migration_630_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id IN
    ('market.node.probe_unreachable.zh-cn', 'market.node.probe_recovered.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type IN ('market.node.probe_unreachable', 'market.node.probe_recovered');
DELETE FROM notification_event_policies WHERE event_type IN ('market.node.probe_unreachable', 'market.node.probe_recovered');
DELETE FROM admin_inbox_messages WHERE event_type IN ('market.node.probe_unreachable', 'market.node.probe_recovered');

ALTER TABLE market_subscribed_nodes DROP CONSTRAINT market_subscribed_nodes_probe_alert_revision_630,
    DROP COLUMN probe_alert_revision, DROP COLUMN probe_alerted;
