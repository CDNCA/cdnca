LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_430_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 429 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 429 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=429 AND
        migration_id='429_waf_adapt_permissions' AND
        checksum_sha256='ea7538057b5aab098b210bcbc8917e6e1a06eaa042d1096a096f963467643aa1' AND
        down_checksum_sha256='120f1748313304637252bcb01f89bffc147635e0c152d0f3381021cb0a3ccfcb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type LIKE 'market.%'
       ) THEN
        RAISE EXCEPTION 'migration 430 requires the exact verified 429 release head' USING ERRCODE='P4300';
    END IF;
END;
$migration_430_up$;

-- 430（r136 ML-10，ADR 0012 §8/§20；merge-batch7 合入改号 428→430，前一版 429_waf_adapt_permissions）。
-- Node market notices in the notification center. The market signs each
-- notice and puts it in this member's relay inbox (operation market.notice);
-- control-api internal/marketruntime turns it into the event of the same
-- name for the platform members holding marketplace.purchase (buyer
-- notices) or marketplace.sell (seller notices). Members choose channels
-- per event (tenant_subscribed); email on by default, SMS off.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.limit.warn80', true, true, true, 1, 24, true, true, false, now()),
    ('market.limit.warn95', true, true, true, 1, 24, true, true, false, now()),
    ('market.limit.reached', true, true, true, 1, 24, true, true, false, now()),
    ('market.limit.recovered', true, true, true, 1, 24, true, true, false, now()),
    ('market.prepaid.low', true, true, true, 1, 24, true, true, false, now()),
    ('market.prepaid.exhausted', true, true, true, 1, 24, true, true, false, now()),
    ('market.prepaid.restored', true, true, true, 1, 24, true, true, false, now()),
    ('market.overdraft.warn', true, true, true, 1, 24, true, true, false, now()),
    ('market.overdraft.capped', true, true, true, 1, 24, true, true, false, now()),
    ('market.node.overloaded', true, true, true, 1, 24, true, true, false, now()),
    ('market.node.recovered', true, true, true, 1, 24, true, true, false, now()),
    ('market.supply.all_overloaded', true, true, true, 1, 24, true, true, false, now()),
    ('market.plugin.unavailable', true, true, true, 1, 24, true, true, false, now()),
    ('market.plugin.restored', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.limit.warn80.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}的{{.metric}}已达上限80%：{{.observed}}/{{.cap}}。', ARRAY['offer','subscription','metric','observed','cap'], '2026-10-21 00:00:00+00'),
    ('market.limit.warn80.zh-cn', 1, 'email', '节点市场：{{.offer}} {{.metric}} 达到上限 80%', '供给 {{.offer}}（订阅 {{.subscription}}）的 {{.metric}} 当前 {{.observed}}，上限 {{.cap}}，已达 80%。每个周期每个阶段只通知一次。', ARRAY['offer','subscription','metric','observed','cap'], '2026-10-21 00:00:00+00'),
    ('market.limit.warn95.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}的{{.metric}}已达上限95%：{{.observed}}/{{.cap}}。', ARRAY['offer','subscription','metric','observed','cap'], '2026-10-21 00:00:00+00'),
    ('market.limit.warn95.zh-cn', 1, 'email', '节点市场：{{.offer}} {{.metric}} 达到上限 95%', '供给 {{.offer}}（订阅 {{.subscription}}）的 {{.metric}} 当前 {{.observed}}，上限 {{.cap}}，已达 95%，到限后按卖方设置的处置执行。', ARRAY['offer','subscription','metric','observed','cap'], '2026-10-21 00:00:00+00'),
    ('market.limit.reached.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}的{{.metric}}已到上限{{.cap}}，处置：{{.action}}。', ARRAY['offer','subscription','metric','observed','cap','action'], '2026-10-21 00:00:00+00'),
    ('market.limit.reached.zh-cn', 1, 'email', '节点市场：{{.offer}} {{.metric}} 已到上限', '供给 {{.offer}}（订阅 {{.subscription}}）的 {{.metric}} 达到 {{.observed}}，上限 {{.cap}}，已按 {{.action}} 处置（pause=暂停调度，stop=停止服务）。回落或续订后自动恢复。', ARRAY['offer','subscription','metric','observed','cap','action'], '2026-10-21 00:00:00+00'),
    ('market.limit.recovered.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}的{{.metric}}限额已恢复。', ARRAY['offer','subscription','metric','action'], '2026-10-21 00:00:00+00'),
    ('market.limit.recovered.zh-cn', 1, 'email', '节点市场：{{.offer}} {{.metric}} 已恢复', '供给 {{.offer}}（订阅 {{.subscription}}）的 {{.metric}} 已回落到上限以下，{{.action}} 处置已解除，调度自动恢复。', ARRAY['offer','subscription','metric','action'], '2026-10-21 00:00:00+00'),
    ('market.prepaid.low.zh-cn', 1, 'sms', '', '节点市场{{.currency}}预付余额{{.observed}}低于预警线{{.cap}}（最小货币单位）。', ARRAY['currency','observed','cap'], '2026-10-21 00:00:00+00'),
    ('market.prepaid.low.zh-cn', 1, 'email', '节点市场：{{.currency}} 预付余额低于预警线', '{{.currency}} 预付余额 {{.observed}} 已低于你设置的预警线 {{.cap}}（金额为最小货币单位，如分）。余额用完后供给将暂停调度，请及时充值。', ARRAY['currency','observed','cap'], '2026-10-21 00:00:00+00'),
    ('market.prepaid.exhausted.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}预付已用完，处置：{{.action}}。', ARRAY['offer','subscription','action'], '2026-10-21 00:00:00+00'),
    ('market.prepaid.exhausted.zh-cn', 1, 'email', '节点市场：{{.offer}} 预付已用完', '供给 {{.offer}}（订阅 {{.subscription}}）预付余额不足本期扣费，已按 {{.action}} 处置（pause=暂停调度，stop=停止服务）；订阅不会关闭，充值后自动恢复。', ARRAY['offer','subscription','action'], '2026-10-21 00:00:00+00'),
    ('market.prepaid.restored.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}已充值，调度已恢复。', ARRAY['offer','subscription','action'], '2026-10-21 00:00:00+00'),
    ('market.prepaid.restored.zh-cn', 1, 'email', '节点市场：{{.offer}} 已恢复', '供给 {{.offer}}（订阅 {{.subscription}}）已收到付款，{{.action}} 处置已解除，调度自动恢复。', ARRAY['offer','subscription','action'], '2026-10-21 00:00:00+00'),
    ('market.overdraft.warn.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}透支{{.observed}}{{.currency}}接近封顶{{.cap}}。', ARRAY['offer','subscription','currency','observed','cap'], '2026-10-21 00:00:00+00'),
    ('market.overdraft.warn.zh-cn', 1, 'email', '节点市场：{{.offer}} 透支接近封顶', '供给 {{.offer}}（订阅 {{.subscription}}）当前透支 {{.observed}}，封顶 {{.cap}}（{{.currency}}，最小货币单位）。到封顶后暂停调度，充值会先冲抵透支。', ARRAY['offer','subscription','currency','observed','cap'], '2026-10-21 00:00:00+00'),
    ('market.overdraft.capped.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}透支已到封顶{{.cap}}，处置：{{.action}}。', ARRAY['offer','subscription','observed','cap','action'], '2026-10-21 00:00:00+00'),
    ('market.overdraft.capped.zh-cn', 1, 'email', '节点市场：{{.offer}} 透支已到封顶', '供给 {{.offer}}（订阅 {{.subscription}}）透支 {{.observed}} 已到封顶 {{.cap}}（最小货币单位），已按 {{.action}} 处置。充值冲抵后自动恢复。', ARRAY['offer','subscription','observed','cap','action'], '2026-10-21 00:00:00+00'),
    ('market.node.overloaded.zh-cn', 1, 'sms', '', '节点市场节点{{.node}}（池{{.pool}}）超过承受力门槛{{.threshold}}，已从供给摘除。', ARRAY['node','pool','threshold'], '2026-10-21 00:00:00+00'),
    ('market.node.overloaded.zh-cn', 1, 'email', '节点市场：节点 {{.node}} 过载已摘除', '节点 {{.node}}（节点池 {{.pool}}）CPU 或内存连续超过门槛 {{.threshold}}（CPU/内存 %），已从使用该门槛的供给 DNS 中摘除，回落后自动恢复。', ARRAY['node','pool','threshold'], '2026-10-21 00:00:00+00'),
    ('market.node.recovered.zh-cn', 1, 'sms', '', '节点市场节点{{.node}}（池{{.pool}}）负载已回落，已恢复调度。', ARRAY['node','pool','threshold'], '2026-10-21 00:00:00+00'),
    ('market.node.recovered.zh-cn', 1, 'email', '节点市场：节点 {{.node}} 已恢复', '节点 {{.node}}（节点池 {{.pool}}）负载已连续低于门槛 {{.threshold}}（CPU/内存 %），已恢复到对应供给的 DNS。', ARRAY['node','pool','threshold'], '2026-10-21 00:00:00+00'),
    ('market.supply.all_overloaded.zh-cn', 1, 'sms', '', '节点市场节点池{{.pool}}全部节点过载（门槛{{.threshold}}），相关供给暂无解析。', ARRAY['pool','threshold'], '2026-10-21 00:00:00+00'),
    ('market.supply.all_overloaded.zh-cn', 1, 'email', '节点市场：节点池 {{.pool}} 全部过载', '节点池 {{.pool}} 在门槛 {{.threshold}}（CPU/内存 %）下所有节点都已过载，使用它的供给暂时没有 DNS 记录（不保留兜底）。有备用供给的站点会切过去；节点回落后自动恢复。', ARRAY['pool','threshold'], '2026-10-21 00:00:00+00'),
    ('market.plugin.unavailable.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}不再提供{{.plugins}}，已退回基础防护。', ARRAY['offer','subscription','plugins'], '2026-10-21 00:00:00+00'),
    ('market.plugin.unavailable.zh-cn', 1, 'email', '节点市场：{{.offer}} 插件不再提供', '供给 {{.offer}}（订阅 {{.subscription}}）的上游不再提供 {{.plugins}}，这些功能在该供给上已退回基础防护，站点照常服务。', ARRAY['offer','subscription','plugins'], '2026-10-21 00:00:00+00'),
    ('market.plugin.restored.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}已恢复提供{{.plugins}}。', ARRAY['offer','subscription','plugins'], '2026-10-21 00:00:00+00'),
    ('market.plugin.restored.zh-cn', 1, 'email', '节点市场：{{.offer}} 插件已恢复', '供给 {{.offer}}（订阅 {{.subscription}}）已恢复提供 {{.plugins}}。', ARRAY['offer','subscription','plugins'], '2026-10-21 00:00:00+00');
