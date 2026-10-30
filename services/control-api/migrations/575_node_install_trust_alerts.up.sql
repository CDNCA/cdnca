-- 575（fix-btenv5，占位：合入时由主会话按集成头改号与改钉前驱，P575x 随号改）。
LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_575_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 574 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 574 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=574 AND
        migration_id='574_api_key_scope_limit' AND
        checksum_sha256='45a11368fcfbac3b1337e4463cf6bdd138d0a84b29aa8789c3bcbeb15c6be69e' AND
        down_checksum_sha256='795df77e6316dc62b4fc987ca771482148c180822ee61f85a98f4fd4a97d3712' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='node.install_trust.failed'
       ) THEN
        RAISE EXCEPTION 'migration 575 requires the exact verified 574 release head' USING ERRCODE='P5750';
    END IF;
END;
$migration_575_up$;

-- 节点安装信任文档自动重发（主会话 10-28 13:2x 定）：control-api 启动时与每 10 分钟按管理端域名
-- 当前解析、control.env 下载端口与根 CA 核对 upgrade-trust.json，不一致即重新发布；连续 3 次
-- 解析或发布失败时通知持 nodes.manage 的平台成员，每个失败段只通知一次
-- （internal/nativebackup nodeinstalltrust_alert.go）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('node.install_trust.failed', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.install_trust.failed.zh-cn', 1, 'sms', '',
     '节点安装信任文档已连续{{.failures}}次无法按{{.download}}更新，新装节点可能连不上升级下载地址，请尽快处理。',
     ARRAY['download','failures'], '2026-10-28 00:00:00+00'),
    ('node.install_trust.failed.zh-cn', 1, 'email', '节点安装信任文档无法自动更新',
     '主控自 {{.since}}（UTC）起已连续 {{.failures}} 次无法核对或重新发布节点安装信任文档（升级下载地址 {{.download}}），最近一次在 {{.occurred_at}}（UTC），原因：{{.reason}}。已发布的文档保持不变，控制台复制的节点安装命令仍指向旧的下载地址。请检查主控能否解析管理端域名、解析结果是否为公网地址，以及 /etc/cdnca-control/control.env 中的升级下载地址与根 CA 文件；修复后最长 10 分钟自动重新发布，也可在主控运行 control-api native-backup publish-node-install-trust 立即发布。同一失败段只通知一次。',
     ARRAY['download','failures','reason','since','occurred_at'], '2026-10-28 00:00:00+00');
