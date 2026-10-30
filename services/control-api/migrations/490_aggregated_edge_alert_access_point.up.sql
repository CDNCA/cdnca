-- 490（r136 merge-p1，主会话 10-25 05:1x）：聚合边缘调度告警邮件模板正文里的「供给」改为「接入点」，
-- 与 aggedge-rename 的告警 alert_text / 审计文案统一。只改 420 写入的那一行模板正文，不改历史迁移、
-- 不升模板版本（入队代码固定取 version 1）。已入队/已发送的消息正文是入队时的快照，不受影响。
LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_490_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 489 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 489 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=489 AND
        migration_id='489_installation_ban_node_ticket' AND
        checksum_sha256='355e03eb8e87828a78801d2c4cbc17abcc654aeba92f78f62e147ba5177947da' AND
        down_checksum_sha256='a35456bba9f7bd3429b7c4872dfa006725cd3464505a6b5d474e12197aed8200' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM notification_templates WHERE template_id='aggregated_edge.schedule.alert.zh-cn' AND
        version=1 AND channel='email' AND
        body='站点 {{.site_domain}} 的线路 {{.line}}：{{.alert_text}}。源站状态：{{.origin}}。请打开调度页 {{.link}} 选择切到某个供给或保持当前指向（冻结时可解冻并切换或保持冻结）。'
       ) THEN
        RAISE EXCEPTION 'migration 490 requires the exact verified 489 release head' USING ERRCODE='P4900';
    END IF;
END;
$migration_490_up$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
UPDATE notification_templates
SET body='站点 {{.site_domain}} 的线路 {{.line}}：{{.alert_text}}。源站状态：{{.origin}}。请打开调度页 {{.link}} 选择切到某个接入点或保持当前指向（冻结时可解冻并切换或保持冻结）。'
WHERE template_id='aggregated_edge.schedule.alert.zh-cn' AND version=1 AND channel='email' AND
    body='站点 {{.site_domain}} 的线路 {{.line}}：{{.alert_text}}。源站状态：{{.origin}}。请打开调度页 {{.link}} 选择切到某个供给或保持当前指向（冻结时可解冻并切换或保持冻结）。';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
