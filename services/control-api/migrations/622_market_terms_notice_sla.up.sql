-- 622（前驱 621）。
-- 节点市场续费比较新旧条款计入 SLA（market renewalprice.go compareSLA）：只改 SLA 也发
-- market.terms.changed。v2 模板多一个变量 category，列出变化点（逗号分隔）：
--   price_up / price_down / price_mixed：价格涨 / 降 / 有涨有降；
--   limits_stricter / limits_looser / limits_mixed：限额或预付用完处置变严 / 变宽 / 有严有宽；
--   sla_added / sla_removed：新增 / 取消 SLA；sla_better / sla_worse / sla_mixed：SLA 变好 / 变差 / 改统计窗口等无法比较；
--   resale_on / resale_off、site_pause_on / site_pause_off：续费后转售权、同站自动暂停开 / 关（不影响续费条件）。
-- SLA 变差（含取消、无法比较）视同涨价。v1 保留，不改历史；旧版市场不带 category 时显示“-”。
LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_622_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 621 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 621 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=621 AND migration_id='621_certificate_order_outbox_failure' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR (SELECT count(*) FROM notification_templates WHERE template_id='market.terms.changed.zh-cn' AND version=1) <> 2
         OR EXISTS (SELECT 1 FROM notification_templates WHERE template_id='market.terms.changed.zh-cn' AND version=2) THEN
        RAISE EXCEPTION 'migration 622 requires the verified 621 release head with market.terms.changed v1 templates only'
            USING ERRCODE='P6220';
    END IF;
END;
$migration_622_up$;

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.terms.changed.zh-cn', 2, 'sms', '', '节点市场供给{{.offer}}的条款已变更（{{.category}}），续费时将{{.action}}（renew=按新条款续费，close=到期关闭）。', ARRAY['offer','subscription','action','category'], '2026-11-04 00:00:00+00'),
    ('market.terms.changed.zh-cn', 2, 'email', '节点市场：{{.offer}} 条款已变更', '卖方修改了供给 {{.offer}}（订阅 {{.subscription}}）的条款，变化点：{{.category}}（price_up/price_down=价格上涨/下降，limits_stricter/limits_looser=限额变严/变宽，sla_added/sla_removed=新增/取消 SLA，sla_better/sla_worse=SLA 变好/变差，*_mixed=有好有坏或无法比较，resale_on/resale_off=续费后可以/不再可以转售，site_pause_on/site_pause_off=续费后同站自动暂停开启/关闭）。限额变严、SLA 变差或取消视同涨价；价格和限额不变时，SLA 不变或变好按新条款续费；转售和同站暂停开关不影响续费条件，但续费后按新开关执行。按你设置的续费价格条件，本期到期时将 {{.action}}（renew=按新条款续费，close=不续费并关闭）。如需调整，请在到期前修改续费条件或取消订阅。', ARRAY['offer','subscription','action','category'], '2026-11-04 00:00:00+00');
