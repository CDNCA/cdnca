-- 633：主控数据库连接池告警（前驱 632 dns_provider_cloudns_namecheap_jdcloud）。
-- control-api 每 10 秒采样自己的数据库连接池（internal/poolmon，判定 libs/dbpoolmon 与 market 共用）：
-- 连续 3 次满载（使用 ≥ 上限 − 1）或平均等待 > 100 ms、或满载/排队时有请求放弃即告警，连续 3 次正常即恢复，
-- 15 分钟内反复只通知一次。通知 control.db_pool.saturated / control.db_pool.recovered 发给持
-- control.upgrades.read 或 platform.admin 的平台成员（与「系统维护」页同权限），短信+邮件 zh-cn v1，
-- 同时进管理员站内消息。告警由池外单独连接写入（池满时池内连接也要排队）。
LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_633_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 632 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 632 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=632 AND
        migration_id='632_dns_provider_cloudns_namecheap_jdcloud' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies
        WHERE event_type IN ('control.db_pool.saturated', 'control.db_pool.recovered')
       ) THEN
        RAISE EXCEPTION 'migration 633 requires the exact verified 632 release head' USING ERRCODE='P6330';
    END IF;
END;
$migration_633_up$;

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('control.db_pool.saturated', true, true, true, 1, 1, true, true, false, now()),
    ('control.db_pool.recovered', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('control.db_pool.saturated.zh-cn', 1, 'sms', '',
     '主控{{.instance}}数据库连接池已满载，请求在排队等待连接（使用{{.in_use}}/{{.max_conns}}），请尽快处理。',
     ARRAY['instance','in_use','max_conns','resident_conns','request_capacity','queued','avg_wait_ms','reasons','occurred_at'], '2026-11-05 00:00:00+00'),
    ('control.db_pool.saturated.zh-cn', 1, 'email', '主控数据库连接池满载：{{.instance}}',
     '主控 {{.instance}} 的数据库连接池在 {{.occurred_at}}（UTC）判定满载，请求在排队等待连接：使用中 {{.in_use}}/{{.max_conns}}，其中常驻连接（LISTEN、会话锁）{{.resident_conns}} 个，留给请求 {{.request_capacity}} 个；本周期排队 {{.queued}} 次，平均等待 {{.avg_wait_ms}} 毫秒，原因：{{.reasons}}（saturated=连接已用满，slow_acquire=平均等待超过 100 毫秒，canceled_acquire=请求等不到连接而放弃）。判定规则：每 10 秒采样，连续 3 次满载或平均等待超过 100 毫秒、或满载/排队时有请求放弃即告警，连续 3 次正常即恢复，15 分钟内反复只通知一次。请到「系统维护」页查看连接池最近 1 小时走势，排查长事务、慢查询或占用第二个连接的事务。',
     ARRAY['instance','in_use','max_conns','resident_conns','request_capacity','queued','avg_wait_ms','reasons','occurred_at'], '2026-11-05 00:00:00+00'),
    ('control.db_pool.recovered.zh-cn', 1, 'sms', '',
     '主控{{.instance}}数据库连接池{{if eq .cause "instance_restarted"}}告警已因主控重启关闭{{else}}已恢复正常{{end}}。',
     ARRAY['instance','since','cause','occurred_at'], '2026-11-05 00:00:00+00'),
    ('control.db_pool.recovered.zh-cn', 1, 'email', '主控数据库连接池{{if eq .cause "instance_restarted"}}告警已关闭{{else}}已恢复{{end}}：{{.instance}}',
     '{{if eq .cause "instance_restarted"}}主控 {{.instance}} 自 {{.since}}（UTC）起的数据库连接池告警在主控重启后关闭（{{.occurred_at}}，UTC）；重启后若仍满载会重新告警。{{else}}主控 {{.instance}} 自 {{.since}}（UTC）起的数据库连接池满载已于 {{.occurred_at}}（UTC）恢复：连续 3 次采样正常。{{end}}',
     ARRAY['instance','since','cause','occurred_at'], '2026-11-05 00:00:00+00');
