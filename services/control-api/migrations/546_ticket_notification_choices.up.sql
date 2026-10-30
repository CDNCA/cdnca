-- 546（fix-ticket2，用户 10-27）：工单通知可选。
-- ① notification_subscriptions.inbox_enabled：成员对每个事件自选是否收站内信（与已有的短信/邮件开关并列）。
--    默认 true：平台工单事件此前总是写站内信，默认保持原行为；租户工单事件（ticket.created/replied/status_changed）
--    从本迁移起也写成员的站内信（internal/notification InboxEventType）。
-- ② ticket.staff.overdue：超过首次响应时限（24 小时）仍无客服回复的工单，提醒持 tickets.manage 的平台成员，
--    每张工单只提醒一次（tickets.sla_reminded_at 去重，internal/tickets overdue.go）。
-- 前驱 545（security_ban_networks），守卫钉 545 校验和。
LOCK TABLE schema_migrations, notification_subscriptions, notification_event_policies, notification_templates, tickets
    IN ACCESS EXCLUSIVE MODE;

DO $migration_546_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 545 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 545 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=545 AND
        migration_id='545_security_ban_networks' AND
        checksum_sha256='7bd280330a3f7f50dea9beb05aafaa64e42ff961f27a41ef5e189c7fb42bc0ba' AND
        down_checksum_sha256='1f4eb68b60c5af8ebc55ae024feae11e0e55145d845db46b895d4f914055da03' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        (table_name, column_name) IN (('notification_subscriptions', 'inbox_enabled'), ('tickets', 'sla_reminded_at'))
       ) OR EXISTS (SELECT 1 FROM notification_event_policies WHERE event_type='ticket.staff.overdue') THEN
        RAISE EXCEPTION 'migration 546 requires the exact verified 545 release head' USING ERRCODE='P5460';
    END IF;
END;
$migration_546_up$;

ALTER TABLE notification_subscriptions ADD COLUMN inbox_enabled boolean NOT NULL DEFAULT true;

ALTER TABLE tickets ADD COLUMN sla_reminded_at timestamptz
    CHECK (sla_reminded_at IS NULL OR isfinite(sla_reminded_at));
-- 后台任务只扫待首次响应的工单。
CREATE INDEX tickets_sla_pending_546_idx ON tickets (created_at)
    WHERE first_response_at IS NULL AND sla_reminded_at IS NULL AND deleted_at IS NULL;

INSERT INTO notification_event_policies(event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours,
    supported, default_email, default_sms, updated_at)
VALUES ('ticket.staff.overdue', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('ticket_staff_overdue', 1, 'email', '工单 #{{.ticket_no}} 超时未响应',
     '用户 {{.username}} 的工单 #{{.ticket_no}}「{{.subject}}」已超过 24 小时没有客服回复，请尽快登录控制台处理。',
     ARRAY['ticket_no','subject','username'], '2026-10-27 00:00:00+00'),
    ('ticket_staff_overdue', 1, 'sms', '',
     '工单#{{.ticket_no}}超过24小时未回复，请尽快处理。', ARRAY['ticket_no'], '2026-10-27 00:00:00+00');
