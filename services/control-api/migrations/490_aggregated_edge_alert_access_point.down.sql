-- 490（r136 merge-p1）回退：聚合边缘调度告警邮件模板正文还原为 420 原文（「供给」）。
LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_490_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 490 OR
       (SELECT max(version) FROM schema_migrations) <> 490 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=490 AND
        migration_id='490_aggregated_edge_alert_access_point' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 490 down requires the exact verified migration head' USING ERRCODE='P4901';
    END IF;
END;
$migration_490_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
UPDATE notification_templates
SET body='站点 {{.site_domain}} 的线路 {{.line}}：{{.alert_text}}。源站状态：{{.origin}}。请打开调度页 {{.link}} 选择切到某个供给或保持当前指向（冻结时可解冻并切换或保持冻结）。'
WHERE template_id='aggregated_edge.schedule.alert.zh-cn' AND version=1 AND channel='email' AND
    body='站点 {{.site_domain}} 的线路 {{.line}}：{{.alert_text}}。源站状态：{{.origin}}。请打开调度页 {{.link}} 选择切到某个接入点或保持当前指向（冻结时可解冻并切换或保持冻结）。';
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
