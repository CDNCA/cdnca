-- 561（fix-fallbackchain，用户 10-27 22:2x/22:4x）：全自动保底链。
-- 网站默认线路按 自有节点 → 备用线路组 → 订阅的供货商节点 → 商户自己的第三方 CDN 逐级切换
-- （黑洞仍由攻击自动升级 D 级执行，不在链内）。链复用聚合边缘调度（366/394/420/460）：
--   * fallback_chain_settings：平台默认（单行，默认开、默认顺序），新站点不写行即套用；
--   * fallback_chain_site_overrides：单站覆盖（关闭 / 自定义顺序与排除级），无行=继承；
--   * site_supply_bindings.source：fallback_chain = 链 worker 自动维护的候选绑定（市场供给 / 第三方
--     CDN），manual = 管理员手工绑定；关链或排除某级时只删 fallback_chain 行；
--   * 候选 / 切换历史 kind 加 backup_group（套餐 backup_node_group_id，A/AAAA，只在默认线路）；
--   * 切换原因加 attack_overflow（攻击自动升级 A/B/C 都扛不住，跳过源站门）；
--   * 冻结原因加 locked（管理员锁定某级）；
--   * fallback_chain_own_health：自有级健康翻转时间（回切需持续恢复满最短停留）；
--   * 最后一级（攻击自动升级 D 级，仅攻击触发，用户 10-27 23:0x）管理员二选一：blackhole（黑洞）或
--     unlimited（切到管理员选定的“无限防”线路组，默认）；未选线路组时回落黑洞；单站可覆盖为黑洞。
--     escalate_site_states.c_via 加 unlimited（D 级经无限防线路组生效），通知 security.escalate.unlimited。
-- 前驱：集成头 552（usage_report_state）。553–561 由并行任务占用，合入时主会话按连号改钉。
LOCK TABLE schema_migrations, site_supply_bindings, aggregated_edge_line_targets, aggregated_edge_switch_events,
    aggregated_edge_site_schedules, escalate_site_states, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_561_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 560 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 560 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=560 AND
        migration_id='560_autodefense_admin_login_allows' AND
        checksum_sha256='6730caea4013f8f96f7011b0ec52739f49f558012f18704800762d670bfcb307' AND
        down_checksum_sha256='845255d88b7ad124f5c4ac1f912847edca32a95b6d38a101a90322ebf6fe6b28' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('fallback_chain_settings') IS NOT NULL OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='security.escalate.unlimited'
       ) THEN
        RAISE EXCEPTION 'migration 561 requires the exact verified 560 release head' USING ERRCODE='P5610';
    END IF;
END;
$migration_561_up$;

CREATE TABLE fallback_chain_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT true,
    chain_order text[] NOT NULL DEFAULT ARRAY['local', 'backup_group', 'market_subscription', 'third_party_cdn'],
    -- 最后一级：unlimited = 切到 last_resort_* 指定的无限防线路组（未指定时回落黑洞），blackhole = 黑洞。
    last_resort text NOT NULL DEFAULT 'unlimited' CHECK (last_resort IN ('blackhole', 'unlimited')),
    last_resort_owner_scope_id uuid,
    last_resort_line_group_id uuid,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    FOREIGN KEY (last_resort_owner_scope_id, last_resort_line_group_id) REFERENCES node_line_groups(tenant_scope_id, id)
        ON DELETE SET NULL,
    CHECK ((last_resort_owner_scope_id IS NULL) = (last_resort_line_group_id IS NULL)),
    CHECK (cardinality(chain_order) BETWEEN 1 AND 4 AND
        chain_order <@ ARRAY['local', 'backup_group', 'market_subscription', 'third_party_cdn'])
);
INSERT INTO fallback_chain_settings(singleton, updated_at) VALUES (true, '2026-10-27 00:00:00+00');

CREATE TABLE fallback_chain_site_overrides (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    mode text NOT NULL CHECK (mode IN ('inherit', 'off', 'custom')),
    chain_order text[] NOT NULL DEFAULT '{}',
    excluded text[] NOT NULL DEFAULT '{}',
    -- 单站最后一级：inherit = 跟随平台默认，blackhole = 本站只用黑洞。两项都跟随时不留行。
    last_resort text NOT NULL DEFAULT 'inherit' CHECK (last_resort IN ('inherit', 'blackhole')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    CHECK (chain_order <@ ARRAY['local', 'backup_group', 'market_subscription', 'third_party_cdn'] AND
        excluded <@ ARRAY['local', 'backup_group', 'market_subscription', 'third_party_cdn']),
    CHECK (mode <> 'custom' OR cardinality(chain_order) BETWEEN 1 AND 4)
);

-- 自有级（local / backup_group）的健康翻转时间：回切要“持续恢复满最短停留”。
CREATE TABLE fallback_chain_own_health (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    level text NOT NULL CHECK (level IN ('local', 'backup_group')),
    healthy boolean NOT NULL,
    changed_at timestamptz NOT NULL CHECK (isfinite(changed_at)),
    PRIMARY KEY (site_id, level)
);

ALTER TABLE site_supply_bindings ADD COLUMN source text NOT NULL DEFAULT 'manual'
    CONSTRAINT site_supply_bindings_source_561_check CHECK (source IN ('manual', 'fallback_chain'));
CREATE INDEX site_supply_bindings_chain_561_idx ON site_supply_bindings (site_id) WHERE source = 'fallback_chain';

ALTER TABLE aggregated_edge_line_targets DROP CONSTRAINT aggregated_edge_line_targets_kind_check;
ALTER TABLE aggregated_edge_line_targets ADD CONSTRAINT aggregated_edge_line_targets_kind_561_check
    CHECK (kind IN ('third_party_cdn', 'market_subscription', 'local', 'backup_group', 'follow_default'));
ALTER TABLE aggregated_edge_line_targets ADD CONSTRAINT aggregated_edge_line_targets_backup_561_check
    CHECK (kind <> 'backup_group' OR line_scope = '');

ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_from_kind_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_from_kind_561_check
    CHECK (from_kind IN ('', 'third_party_cdn', 'market_subscription', 'local', 'backup_group', 'follow_default'));
ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_to_kind_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_to_kind_561_check
    CHECK (to_kind IN ('', 'third_party_cdn', 'market_subscription', 'local', 'backup_group', 'follow_default'));
ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_reason_460_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_reason_561_check
    CHECK (reason IN ('failover', 'failback', 'quality', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy', 'recovered', 'attack_escalate',
        'attack_overflow'));
DROP INDEX aggregated_edge_switch_events_window_394_idx;
CREATE INDEX aggregated_edge_switch_events_window_561_idx ON aggregated_edge_switch_events (site_id, created_at)
    WHERE reason IN ('failover', 'failback', 'quality', 'attack_overflow');

ALTER TABLE aggregated_edge_site_schedules DROP CONSTRAINT aggregated_edge_site_schedules_frozen_reason_check;
ALTER TABLE aggregated_edge_site_schedules ADD CONSTRAINT aggregated_edge_site_schedules_frozen_reason_561_check
    CHECK (frozen_reason IN ('', 'flap_limit', 'locked'));

ALTER TABLE escalate_site_states DROP CONSTRAINT escalate_site_states_c_via_check;
ALTER TABLE escalate_site_states ADD CONSTRAINT escalate_site_states_c_via_561_check
    CHECK (c_via IN ('', 'line_group', 'cloudflare', 'unlimited'));

-- D 级经无限防线路组生效时通知站长（黑洞仍是 security.escalate.blackhole）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('security.escalate.unlimited', true, true, true, 1, 1, true, true, true, now());
INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('security.escalate.unlimited.zh-cn', 1, 'sms', '',
     '网站{{.domain}}遭受大流量攻击，{{.occurred_at}}已切到无限防线路组{{.line_group}}承载，网站照常访问，攻击回落后自动切回。',
     ARRAY['domain','occurred_at','line_group'], '2026-10-28 00:00:00+00'),
    ('security.escalate.unlimited.zh-cn', 1, 'email', '攻击自动升级：{{.domain}} 已切到无限防线路组',
     '网站 {{.domain}} 遭受大流量攻击，高防线路组已扛不住。平台在 {{.occurred_at}} 把它切到了无限防线路组 {{.line_group}} 承载（没有进入黑洞），访客可以照常访问。攻击回落后会自动逐级切回，无需操作。',
     ARRAY['domain','occurred_at','line_group'], '2026-10-28 00:00:00+00');

REVOKE ALL ON fallback_chain_settings, fallback_chain_site_overrides, fallback_chain_own_health FROM PUBLIC;
GRANT SELECT, UPDATE ON fallback_chain_settings TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON fallback_chain_site_overrides, fallback_chain_own_health TO cdnca_control_app, cdnca_control_runtime;
