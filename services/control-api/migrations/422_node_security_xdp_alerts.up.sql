LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_422_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 421 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 421 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=421 AND
        migration_id='421_node_security_event_alerts' AND
        checksum_sha256='a1b78379c70f918fc5efff8c6b6291bfd417444937f10e3339fd2a58bbfb54b5' AND
        down_checksum_sha256='51f53b9be781092f73e0d870a1201c0c8ddf78723561b3f3329b7dd2822e2597' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='node.security.event'
       ) OR EXISTS (
        SELECT 1 FROM notification_templates WHERE template_id='node.security.xdp.zh-cn'
       ) THEN
        RAISE EXCEPTION 'migration 422 requires the exact verified 421 release head' USING ERRCODE='P4220';
    END IF;
END;
$migration_422_up$;

-- 422（r136 xdp-events；占位，合入时改号，紧跟 sec-events 的 421/426）。
-- The node XDP filter's run time fallback to nftables and its reattach are
-- node security events (node_event source xdp, kind fallback / reattached;
-- event node.security.event, merged per node + source + kind + hour like
-- the kernel bans). They have no client or ban, so their own templates
-- (control-api internal/autodefense node_event_alerts.go).
INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.security.xdp.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}({{.node_ip}})：{{.event_kind}}（{{.xdp_reason_text}}）。',
     ARRAY['node_name','node_ip','event_kind','xdp_reason_text'], '2026-10-20 00:00:00+00'),
    ('node.security.xdp.zh-cn', 1, 'email', '节点安全事件：{{.node_name}} {{.event_kind}}',
     '节点 {{.node_name}}（{{.node_ip}}）在 {{.occurred_at}}（UTC）{{.event_kind}}（{{.xdp_reason_text}}，{{.xdp_event}}/{{.xdp_reason}}）。回落期间节点由 nftables 执行全部内核规则，XDP_FILTER 能力已同步撤销；重新挂载后自动恢复。同一节点同类事件每小时只通知一次。',
     ARRAY['node_name','node_ip','event_kind','xdp_reason_text','xdp_event','xdp_reason','occurred_at'], '2026-10-20 00:00:00+00');
