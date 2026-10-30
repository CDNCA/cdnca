LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_524_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 523 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 523 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=523 AND
        migration_id='523_waf_geo_authority_drop' AND
        checksum_sha256='27ae91c7c12e67da41a79ac939e1c9590034fced21fa80e01702803a834f2b9d' AND
        down_checksum_sha256='e778d483115417a9f11e04004c08611826272fcbac1f9f34fc5c04f123aecaa2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN
            ('market.feedback.opened', 'market.feedback.updated')
       ) THEN
        RAISE EXCEPTION 'migration 524 requires the exact verified 523 release head' USING ERRCODE='P5240';
    END IF;
END;
$migration_524_up$;

-- 524（r136 u4d，C22 / MARKET-SUPPORT-01；分支本地 505、派单占位 555，merge-p10 接 control 头 523 改号 524）。
-- 节点市场订阅故障反馈单（同 ML-10 的 market.notice 通道、平台作用域、按事件订阅；邮件默认开、短信默认关）：
-- market.feedback.opened（给卖方）：订阅方在订阅上提交了故障反馈，需在约定时间内处理；
-- market.feedback.updated（给对方；平台介入时给双方）：回复或状态变化，action 说明是什么。
-- action：reply / in_progress / resolved / closed / reopened / escalated，平台介入加前缀 operator_。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.feedback.opened', true, true, true, 1, 24, true, true, false, now()),
    ('market.feedback.updated', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.feedback.opened.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}收到订阅方故障反馈（{{.category}}），请在 72 小时内处理。', ARRAY['offer','subscription','feedback','category'], '2026-10-25 00:00:00+00'),
    ('market.feedback.opened.zh-cn', 1, 'email', '节点市场：{{.offer}} 收到故障反馈', '订阅方在供给 {{.offer}}（订阅 {{.subscription}}）上提交了故障反馈，单号 {{.feedback}}，类别 {{.category}}（outage=中断，degraded=质量下降，config=配置问题，billing=计费问题，other=其他）。请在 72 小时内回复或标为处理中；超时未处理，订阅方可以把反馈单升级为争议。到节点市场「供货 → 故障反馈」查看并回复。', ARRAY['offer','subscription','feedback','category'], '2026-10-25 00:00:00+00'),
    ('market.feedback.updated.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}的故障反馈有更新（{{.action}}）。', ARRAY['offer','subscription','feedback','category','action'], '2026-10-25 00:00:00+00'),
    ('market.feedback.updated.zh-cn', 1, 'email', '节点市场：{{.offer}} 的故障反馈有更新', '供给 {{.offer}}（订阅 {{.subscription}}）的故障反馈单 {{.feedback}} 有更新：{{.action}}（reply=对方回复，in_progress=卖方处理中，resolved=卖方标为已解决，closed=已关闭，reopened=订阅方重新打开，escalated=订阅方已升级为争议；operator_ 开头为平台介入）。到节点市场查看对话。', ARRAY['offer','subscription','feedback','category','action'], '2026-10-25 00:00:00+00');
