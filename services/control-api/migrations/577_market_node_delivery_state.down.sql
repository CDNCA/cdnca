-- 577 回滚：去掉构建失败计数表、叶子送达节点状态列与 market.supply.node_delivery_failed 通知。
LOCK TABLE schema_migrations, site_supply_leaf_sites, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_577_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 577 OR
       (SELECT max(version) FROM schema_migrations) <> 577 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=577 AND
        migration_id='577_market_node_delivery_state' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 577 down requires the exact verified migration head' USING ERRCODE='P5771';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'market.supply.node_delivery_failed.zh-cn') THEN
        RAISE EXCEPTION 'migration 577 rollback would orphan node delivery notifications' USING ERRCODE='P5772';
    END IF;
END;
$migration_577_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE version = 1 AND template_id = 'market.supply.node_delivery_failed.zh-cn';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'market.supply.node_delivery_failed';
DELETE FROM notification_event_policies WHERE event_type = 'market.supply.node_delivery_failed';
DELETE FROM admin_inbox_messages WHERE event_type = 'market.supply.node_delivery_failed';

DROP INDEX site_supply_leaf_sites_node_check_577_idx;
ALTER TABLE site_supply_leaf_sites DROP CONSTRAINT site_supply_leaf_sites_node_state_577;
ALTER TABLE site_supply_leaf_sites DROP COLUMN next_node_check_at, DROP COLUMN node_checked_at,
    DROP COLUMN node_check_attempts, DROP COLUMN node_detail, DROP COLUMN node_reason, DROP COLUMN node_state;
DROP TABLE origin_auth_delivery_build_failures;
