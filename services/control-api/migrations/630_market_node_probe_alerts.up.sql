-- 630（前驱 629 market_supply_l2_config）。
-- 本主控探测订阅市场节点（internal/nodeprobe 已把订阅端点纳入控制面探测，结果在 node_line_endpoint_health）：
--   1. market_subscribed_nodes.probe_alerted / probe_alert_revision：本主控探测告警状态。按节点汇总当前线路组版本里
--      启用的端点（有 healthy 即正常；否则有 unhealthy 即异常），转异常时 probe_alerted=true 并发一次告警，转正常时
--      置回并发一次恢复；节点不再被探测（移出分组、市场移除）时静默复位。revision 每次转换 +1，做告警来源 ID 与 CAS。
--      市场同步（marketsubscribe.syncNodes 的 upsert）不写这两列。
--   2. 通知 market.node.probe_unreachable / market.node.probe_recovered（marketplace.purchase 持有者，短信+邮件 zh-cn v1）。
--      正文只含卖家名与节点短号，不含节点地址（报价可能隐藏 IP）。DNS 摘除仍以市场判定为准，正文写明。
LOCK TABLE schema_migrations, market_subscribed_nodes, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_630_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 629 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 629 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=629 AND
        migration_id='629_market_supply_l2_config' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='market_subscribed_nodes' AND column_name='probe_alerted'
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies
        WHERE event_type IN ('market.node.probe_unreachable', 'market.node.probe_recovered')
       ) THEN
        RAISE EXCEPTION 'migration 630 requires the exact verified 629 release head' USING ERRCODE='P6300';
    END IF;
END;
$migration_630_up$;

ALTER TABLE market_subscribed_nodes
    ADD COLUMN probe_alerted boolean NOT NULL DEFAULT false,
    ADD COLUMN probe_alert_revision bigint NOT NULL DEFAULT 0
        CONSTRAINT market_subscribed_nodes_probe_alert_revision_630 CHECK (probe_alert_revision >= 0);

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.node.probe_unreachable', true, true, true, 1, 1, true, true, false, now()),
    ('market.node.probe_recovered', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.node.probe_unreachable.zh-cn', 1, 'sms', '',
     '订阅节点{{.node}}（卖家{{.seller}}）本主控探测连续失败，市场判定{{.market_health}}；是否停止解析以市场判定为准，请到线路分组查看。',
     ARRAY['node','seller','supply','market_health','occurred_at'], '2026-11-05 00:00:00+00'),
    ('market.node.probe_unreachable.zh-cn', 1, 'email', '订阅节点本主控探测不可达：{{.node}}',
     '订阅节点 {{.node}}（卖家 {{.seller}}，订阅 {{.supply}}）在 {{.occurred_at}}（UTC）被本主控探测连续判定不可达，所在线路分组的探测都已失败。市场判定：{{.market_health}}。是否停止解析以市场判定为准：市场仍判定正常时该节点照常解析，可能只是本主控到该节点的网络异常。请到「节点管理 → 线路分组」查看，或联系卖家。',
     ARRAY['node','seller','supply','market_health','occurred_at'], '2026-11-05 00:00:00+00'),
    ('market.node.probe_recovered.zh-cn', 1, 'sms', '',
     '订阅节点{{.node}}（卖家{{.seller}}）本主控探测已恢复。',
     ARRAY['node','seller','supply','market_health','occurred_at'], '2026-11-05 00:00:00+00'),
    ('market.node.probe_recovered.zh-cn', 1, 'email', '订阅节点本主控探测已恢复：{{.node}}',
     '订阅节点 {{.node}}（卖家 {{.seller}}，订阅 {{.supply}}）在 {{.occurred_at}}（UTC）本主控探测已恢复。市场判定：{{.market_health}}。',
     ARRAY['node','seller','supply','market_health','occurred_at'], '2026-11-05 00:00:00+00');
