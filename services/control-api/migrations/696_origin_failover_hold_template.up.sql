LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

-- 全部源站不可用时回源级别不变，原来套用 418 的
-- 「回源切换」模板，读成「从 主源 切换到 主源」。保持时改用这组模板（事件仍是 site.origin.failover，
-- 订阅、去重 origin-all-down/<site>/<sequence> 与重试不变）；真正切换仍用 418 的模板写前后级别。
DO $migration_696$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 695 OR
       (SELECT max(version) FROM schema_migrations) <> 695 OR
       EXISTS (SELECT 1 FROM notification_templates WHERE template_id='site.origin.failover.hold.zh-cn') THEN
        RAISE EXCEPTION 'migration 696 requires the exact verified 695 release head' USING ERRCODE='P6960';
    END IF;
END;
$migration_696$;

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('site.origin.failover.hold.zh-cn', 1, 'sms', '',
     '网站{{.domain}}全部源站不可用，保持当前回源级别{{.active_level}}。',
     ARRAY['domain','active_level'], clock_timestamp()),
    ('site.origin.failover.hold.zh-cn', 1, 'email', '全部源站不可用，保持当前回源级别：{{.domain}}',
     '网站 {{.domain}} 于 {{.occurred_at}} 全部源站不可用，保持当前回源级别 {{.active_level}}。回切方式：{{.failback_mode}}。请在控制台“网站设置 - 回源”查看各源站状态{{.action}}。',
     ARRAY['domain','occurred_at','active_level','failback_mode','action'], clock_timestamp());
