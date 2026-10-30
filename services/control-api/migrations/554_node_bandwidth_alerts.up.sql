LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_554_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 553 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 553 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=553 AND
        migration_id='553_aggregated_edge_observability' AND
        checksum_sha256='6c5f692b9b40b8e332d6217ede2f7091ef4e0aaad638afcb1d4f1d2ae4e0a525' AND
        down_checksum_sha256='21f006ab097f84f0672acd827480b343694aa5905faa0070955512db7f0050ac' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN ('node.bandwidth.exceeded', 'node.bandwidth.recovered')
       ) THEN
        RAISE EXCEPTION 'migration 554 requires the exact verified 553 release head' USING ERRCODE='P5540';
    END IF;
END;
$migration_554_up$;

-- 554（fix-cuaccp2 NODE-N03，主会话 10-27 预留；占位，合入时由主会话改号与改钉前驱，前驱暂钉 547_node_ip_location_resolution）。
-- 节点带宽超限自动停用（node_serving_holds source=auto_disable reason=bandwidth_exceeded）与恢复
-- （bandwidth_recovered）通知持 nodes.manage 的平台成员，与停用同事务入队（internal/nodeserving bandwidth_alert.go）；
-- 每次停用/恢复按 hold revision 去重，重复提醒在 hold 已再变化时撤回。只发平台节点；流量超额、禁用时段、改设置不发。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('node.bandwidth.exceeded', true, true, true, 1, 1, true, true, false, now()),
    ('node.bandwidth.recovered', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.bandwidth.exceeded.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}({{.node_ip}})带宽{{.bandwidth}}超过上限{{.bandwidth_limit}}，已自动停用，时间{{.occurred_at}}。',
     ARRAY['node_name','node_ip','bandwidth','bandwidth_limit','occurred_at'], '2026-10-27 00:00:00+00'),
    ('node.bandwidth.exceeded.zh-cn', 1, 'email', '节点带宽超限：节点已自动停用',
     '节点 {{.node_name}}（{{.node_ip}}）连续多次带宽超过上限，已在 {{.occurred_at}}（UTC）自动停用并从解析中暂停。最近带宽：{{.bandwidth}}，上限：{{.bandwidth_limit}}。带宽回落到上限以下且停用满 5 分钟后自动恢复。',
     ARRAY['node_name','node_ip','bandwidth','bandwidth_limit','occurred_at'], '2026-10-27 00:00:00+00'),
    ('node.bandwidth.recovered.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}({{.node_ip}})带宽已回落到{{.bandwidth}}（上限{{.bandwidth_limit}}），已恢复服务，时间{{.occurred_at}}。',
     ARRAY['node_name','node_ip','bandwidth','bandwidth_limit','occurred_at'], '2026-10-27 00:00:00+00'),
    ('node.bandwidth.recovered.zh-cn', 1, 'email', '节点带宽恢复：节点已恢复服务',
     '节点 {{.node_name}}（{{.node_ip}}）带宽已回落到上限以下，已在 {{.occurred_at}}（UTC）自动恢复并重新加入解析。最近带宽：{{.bandwidth}}，上限：{{.bandwidth_limit}}。',
     ARRAY['node_name','node_ip','bandwidth','bandwidth_limit','occurred_at'], '2026-10-27 00:00:00+00');
