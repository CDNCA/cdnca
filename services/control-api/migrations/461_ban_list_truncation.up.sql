LOCK TABLE schema_migrations, security_ban_node_state, escalate_site_drop_node_states, notification_event_policies,
    notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_461_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 460 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 460 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=460 AND
        migration_id='460_attack_escalation' AND
        checksum_sha256='1df7430b58c0d00752bac88118cfb40c49171b93f323d3d5ca6b57e3debda662' AND
        down_checksum_sha256='5476994323e7aaeae25b23915c6b6e72e01762072f3df6173c91c8e0b71668f5' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='node.security.list_truncated'
       ) THEN
        RAISE EXCEPTION 'migration 461 requires the exact verified 460 release head' USING ERRCODE='P4610';
    END IF;
END;
$migration_461_up$;

-- 461（r136 esc-gw；占位，守卫指 460，合入时改号）。
-- 主会话 10-23 22:35：节点的封禁名单 / 站点丢弃名单超过契约上限（≤ 1 MiB gRPC 消息）时不整份拒签，
-- 分发端按优先级裁到上限照常签发（封禁：releases 全留，bans 按剩余时长最长、其次最新创建；
-- 站点丢弃：until 最晚优先）。被裁条数记在节点状态 warning_code=list_truncated / truncated_entries
-- （与节点回执的 error_code 分开），并经通知中心告诉持 nodes.manage 的平台成员：
-- 每个（名单类型, 节点）按小时去重（internal/securityban truncation.go）。
ALTER TABLE security_ban_node_state
    ADD COLUMN warning_code text NOT NULL DEFAULT '' CHECK (warning_code IN ('', 'list_truncated')),
    ADD COLUMN truncated_entries integer NOT NULL DEFAULT 0 CHECK (truncated_entries >= 0),
    ADD CONSTRAINT security_ban_node_state_truncation_check CHECK ((warning_code = '') = (truncated_entries = 0));
ALTER TABLE escalate_site_drop_node_states
    ADD COLUMN warning_code text NOT NULL DEFAULT '' CHECK (warning_code IN ('', 'list_truncated')),
    ADD COLUMN truncated_entries integer NOT NULL DEFAULT 0 CHECK (truncated_entries >= 0),
    ADD CONSTRAINT escalate_site_drop_node_states_truncation_check CHECK ((warning_code = '') = (truncated_entries = 0));

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('node.security.list_truncated', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.security.list_truncated.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}的{{.list_kind}}超出上限，已裁掉{{.truncated}}条后下发。',
     ARRAY['node_name','list_kind','truncated'], '2026-10-23 00:00:00+00'),
    ('node.security.list_truncated.zh-cn', 1, 'email', '名单超限已裁剪：节点 {{.node_name}} 的{{.list_kind}}',
     '节点 {{.node_name}}（{{.node_ip}}）的{{.list_kind}}共 {{.total}} 条，超过单次下发上限 {{.limit}} 条，已在 {{.occurred_at}}（UTC）按优先级裁掉 {{.truncated}} 条后照常签发下发，其余条目继续生效。封禁名单保留全部解除记录与剩余时长最长的封禁；站点丢弃名单保留到期最晚的站点。请减少该节点承载站点的封禁数量或把站点分散到更多节点。同一节点同一名单每小时只通知一次。',
     ARRAY['node_name','node_ip','list_kind','total','limit','truncated','occurred_at'], '2026-10-23 00:00:00+00');
