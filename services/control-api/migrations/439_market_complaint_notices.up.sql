LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_439_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 438 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 438 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=438 AND
        migration_id='438_market_downstream_attacked' AND
        checksum_sha256='ae1a20624da0170d149465598480aa93c393d936d14fd8bd162dbe664ee0263b' AND
        down_checksum_sha256='ebb5be2fb4091cd4f94170b7901d7624be88ba94ff9119ed1371aa3b31b3a007' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type LIKE 'market.complaint.%'
       ) THEN
        RAISE EXCEPTION 'migration 439 requires the exact verified 438 release head' USING ERRCODE='P4390';
    END IF;
END;
$migration_439_up$;

-- 439（r136 ML-17，ADR 0012 §18.3/§23.2；占位，加载器要求连号故放在本分支头 429_market_notices + 1，合入时主会话改号）。
-- Stop complaint notices in the notification center (same path as 430):
-- market.complaint.resolved to the filer (marketplace.sell holders) with the
-- outcome and only its own target reference (U5); market.complaint.actioned
-- to the root buyer (marketplace.purchase) and to each seller between the
-- root and the filer (marketplace.sell), each with the reference it already
-- sees. Email on by default, SMS off.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.complaint.resolved', true, true, true, 1, 24, true, true, false, now()),
    ('market.complaint.actioned', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.complaint.resolved.zh-cn', 1, 'sms', '', '节点市场停止工单{{.complaint}}（下游编号{{.target}}）已处理：{{.outcome}}。', ARRAY['complaint','target','category','outcome','domain'], '2026-10-21 00:00:00+00'),
    ('market.complaint.resolved.zh-cn', 1, 'email', '节点市场：停止工单已处理（{{.outcome}}）', '你对下游编号 {{.target}} 提交的停止工单 {{.complaint}}（类别 {{.category}}）已由平台处理，结果：{{.outcome}}（rejected=驳回，warn=警告，pause=暂停该下游在你的节点上的调度，stop=停止服务，blacklist_domain=拉黑域名 {{.domain}}，released=已解除）。平台不提供下游的真实身份；如涉及费用请走争议流程。', ARRAY['complaint','target','category','outcome','domain'], '2026-10-21 00:00:00+00'),
    ('market.complaint.actioned.zh-cn', 1, 'sms', '', '节点市场订阅{{.subscription}}被平台处置：{{.outcome}}（工单{{.complaint}}）。', ARRAY['complaint','subscription','target','category','outcome','domain'], '2026-10-21 00:00:00+00'),
    ('market.complaint.actioned.zh-cn', 1, 'email', '节点市场：订阅被平台处置（{{.outcome}}）', '平台根据停止工单 {{.complaint}}（类别 {{.category}}）对订阅 {{.subscription}}（你看到的编号 {{.target}}）作出处置：{{.outcome}}（warn=警告，pause=暂停在相关供货商节点上的调度，stop=停止服务，blacklist_domain=拉黑域名 {{.domain}}，released=已解除）。如有异议请联系平台；费用问题走争议流程。', ARRAY['complaint','subscription','target','category','outcome','domain'], '2026-10-21 00:00:00+00');
