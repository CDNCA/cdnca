LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_510_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 509 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 509 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=509 AND
        migration_id='509_error_page_asset_name' AND
        checksum_sha256='3f8d0df112806f7a9be9d3fb1f6453466c3d085ee5e9fa281d384947b2f2d333' AND
        down_checksum_sha256='91113797adc319abcf00c5713eb5a02370accd17199fd0fa41066bc48d58a58d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='security.escalate.blackhole_drop_confirmed'
       ) OR EXISTS (
        SELECT 1 FROM notification_templates WHERE template_id='security.escalate.blackhole.zh-cn' AND version=2
       ) THEN
        RAISE EXCEPTION 'migration 510 requires the exact verified 509 release head' USING ERRCODE='P5100';
    END IF;
END;
$migration_510_up$;

-- 510（r136 be-gap-2，主会话 10-25 15:3x 定：黑洞通知补"节点已确认丢弃"阶段，接 sitedrop 回执）。
-- 本地占位 501（前驱 500），merge-p7 改号为 510（前驱 509）。
-- 1. 进入黑洞的第一条通知（DNS 已指向 0.0.0.0）不再说"节点丢弃残余流量"：那时节点还没回执。
--    邮件模板 v2 只说解析已切走、节点丢弃确认后另行通知（enqueueTemplated 取每个渠道的最新版本；短信 v1 本就没说丢弃）。
-- 2. 新事件 security.escalate.blackhole_drop_confirmed：承载本站的每个节点都确认应用了含本站的丢弃快照
--    （escalate_site_drop_node_states 回执 applied_revision >= revision）后通知一次；
--    同一次进入黑洞只发一次（source 绑定那条 applied D 事件）。默认邮件开、短信关（与 469 同口径）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('security.escalate.blackhole_drop_confirmed', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('security.escalate.blackhole.zh-cn', 2, 'email', '攻击自动升级：{{.domain}} 已进入黑洞',
     '网站 {{.domain}} 在 {{.occurred_at}} 因持续大流量攻击（全部节点合计 {{.qps}} 请求/秒、{{.bps}} bit/秒）升级到 D 级「黑洞」：域名解析已指向 0.0.0.0（TTL 60 秒），访问暂时中断。节点正在应用本站的丢弃规则，全部节点确认后会再通知你。攻击持续低于阈值且停留期满后会自动逐级回切；也可以在控制台「攻击升级」查看状态与历史。',
     ARRAY['domain','occurred_at','qps','bps'], '2026-10-25 00:00:00+00'),
    ('security.escalate.blackhole_drop_confirmed.zh-cn', 1, 'sms', '',
     '网站{{.domain}}黑洞已生效：{{.nodes}}个节点已确认丢弃本站残余流量。',
     ARRAY['domain','nodes'], '2026-10-25 00:00:00+00'),
    ('security.escalate.blackhole_drop_confirmed.zh-cn', 1, 'email', '攻击自动升级：{{.domain}} 的节点已确认丢弃',
     '网站 {{.domain}} 进入黑洞（{{.occurred_at}}）后，承载它的 {{.nodes}} 个节点已于 {{.confirmed_at}} 确认应用丢弃规则，仍打到节点的残余流量会被直接丢弃。{{.limited}}攻击持续低于阈值且停留期满后会自动逐级回切。',
     ARRAY['domain','occurred_at','confirmed_at','nodes','limited'], '2026-10-25 00:00:00+00');
