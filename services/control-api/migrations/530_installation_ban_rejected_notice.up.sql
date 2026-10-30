-- 530（r136 fz-x13；派单占位 536，分支本地写 530 以满足连号加载器，合入时按集成头改号，P530x 随号改）。
LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_530_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 529 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 529 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=529 AND
        migration_id='529_installation_ban_node_delivery' AND
        checksum_sha256='0c79b3aecee927617617c8e682e867a06bdf3a7bb9f5343a4ea69ef3e0ba1e97' AND
        down_checksum_sha256='177625b0ac94bb6dfebfa0b2cfbaacd54ca0b86ef503601a221993332ec14ca0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='installation_ban.rejected'
       ) THEN
        RAISE EXCEPTION 'migration 530 requires the exact verified 529 release head' USING ERRCODE='P5300';
    END IF;
END;
$migration_530_up$;

-- 安装封禁状态被节点永久拒绝（主会话 10-26 fz-x13 续派）：节点回执的拒绝原因属于
-- transport.PermanentReason 时，同一修订不会再下发，只有新修订才会发出，节点一直停在旧状态。
-- 原先只写 Error 日志；现在经通知中心告诉持 nodes.manage 的平台成员，
-- 每个（节点, 修订）只通知一次（internal/installationban rejected_alert.go）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('installation_ban.rejected', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('installation_ban.rejected.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}拒绝了授权状态（修订{{.revision}}），该修订不再重发，请尽快处理。',
     ARRAY['node_name','revision'], '2026-10-26 00:00:00+00'),
    ('installation_ban.rejected.zh-cn', 1, 'email', '节点拒绝授权状态：{{.node_name}}',
     '节点 {{.node_name}}（{{.node_ip}}）在 {{.occurred_at}}（UTC）拒绝应用主控下发的授权状态（修订 {{.revision}}，原因 {{.reason}}）。这是永久拒绝：同一修订不会再下发，节点保持原来的授权状态，直到授权方下发新的修订。请在主控「节点」页查看该节点的「授权凭据」列，并检查节点版本与 journalctl -u cdnca-edge-agent 中 installation ban 的报错；节点升级或修复后，下一次修订会自动送达。同一节点同一修订只通知一次。',
     ARRAY['node_name','node_ip','revision','reason','occurred_at'], '2026-10-26 00:00:00+00');
