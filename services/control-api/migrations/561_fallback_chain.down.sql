-- 561 回滚：删掉保底链配置与链 worker 维护的绑定，候选/历史/冻结原因约束回到 460 的取值。
-- 已落在 backup_group / attack_overflow / locked 的行先改回旧取值（备组线路回到 local，
-- 历史原因记为 failover，锁定改为 flap_limit 冻结），保证旧约束可加回。
LOCK TABLE schema_migrations, site_supply_bindings, aggregated_edge_line_targets, aggregated_edge_switch_events,
    aggregated_edge_site_schedules, fallback_chain_settings, fallback_chain_site_overrides, fallback_chain_own_health,
    escalate_site_states, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_561_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 561 OR
       (SELECT max(version) FROM schema_migrations) <> 561 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=561 AND
        migration_id='561_fallback_chain' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 561 down requires the exact verified migration head' USING ERRCODE='P5611';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_outbox WHERE template_id = 'security.escalate.unlimited.zh-cn') THEN
        RAISE EXCEPTION 'migration 561 rollback would orphan attack escalation unlimited notifications' USING ERRCODE='P5612';
    END IF;
END;
$migration_561_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'security.escalate.unlimited.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_subscriptions WHERE event_type = 'security.escalate.unlimited';
DELETE FROM notification_event_policies WHERE event_type = 'security.escalate.unlimited';
DELETE FROM admin_inbox_messages WHERE event_type = 'security.escalate.unlimited';
-- D 级经无限防线路组生效的站点退回 460 的取值（线路组路由仍在 escalate_site_routes）。
UPDATE escalate_site_states SET c_via='line_group' WHERE c_via='unlimited';
ALTER TABLE escalate_site_states DROP CONSTRAINT escalate_site_states_c_via_561_check;
ALTER TABLE escalate_site_states ADD CONSTRAINT escalate_site_states_c_via_check
    CHECK (c_via IN ('', 'line_group', 'cloudflare'));

UPDATE aggregated_edge_line_targets SET kind='local' WHERE kind='backup_group';
UPDATE aggregated_edge_switch_events SET from_kind='local' WHERE from_kind='backup_group';
UPDATE aggregated_edge_switch_events SET to_kind='local' WHERE to_kind='backup_group';
UPDATE aggregated_edge_switch_events SET reason='failover' WHERE reason='attack_overflow';
UPDATE aggregated_edge_site_schedules SET frozen_reason='flap_limit' WHERE frozen_reason='locked';
DELETE FROM site_supply_bindings WHERE source='fallback_chain';

ALTER TABLE aggregated_edge_site_schedules DROP CONSTRAINT aggregated_edge_site_schedules_frozen_reason_561_check;
ALTER TABLE aggregated_edge_site_schedules ADD CONSTRAINT aggregated_edge_site_schedules_frozen_reason_check
    CHECK (frozen_reason IN ('', 'flap_limit'));

DROP INDEX aggregated_edge_switch_events_window_561_idx;
CREATE INDEX aggregated_edge_switch_events_window_394_idx ON aggregated_edge_switch_events (site_id, created_at)
    WHERE reason IN ('failover', 'failback', 'quality');
ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_reason_561_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_reason_460_check
    CHECK (reason IN ('failover', 'failback', 'quality', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy', 'recovered', 'attack_escalate'));
ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_to_kind_561_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_to_kind_check
    CHECK (to_kind IN ('', 'third_party_cdn', 'market_subscription', 'local', 'follow_default'));
ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_from_kind_561_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_from_kind_check
    CHECK (from_kind IN ('', 'third_party_cdn', 'market_subscription', 'local', 'follow_default'));

ALTER TABLE aggregated_edge_line_targets DROP CONSTRAINT aggregated_edge_line_targets_backup_561_check;
ALTER TABLE aggregated_edge_line_targets DROP CONSTRAINT aggregated_edge_line_targets_kind_561_check;
ALTER TABLE aggregated_edge_line_targets ADD CONSTRAINT aggregated_edge_line_targets_kind_check
    CHECK (kind IN ('third_party_cdn', 'market_subscription', 'local', 'follow_default'));

DROP INDEX site_supply_bindings_chain_561_idx;
ALTER TABLE site_supply_bindings DROP COLUMN source;

DROP TABLE fallback_chain_own_health;
DROP TABLE fallback_chain_site_overrides;
DROP TABLE fallback_chain_settings;
