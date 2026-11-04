-- 625（r136 offerlife，用户 11-04；前驱 624 subline，主调度定号；主控迁移加载器要求连号）。
-- 卖方下架节点市场供给后在期订阅不再续费（market 076）：市场发 market.terms.changed，category=offer_delisted、
-- action=close、at=订阅到期时间（RFC 3339）。v3 模板多一个变量 at，offer_delisted 时专门说明"卖方已下架，到期后不再续费"，
-- 其余 category 与 v2 文案一致。v1/v2 保留不改；只装到 v2 的旧主控照常收这条，按 v2 显示"条款已变更，续费时将 close"。
LOCK TABLE schema_migrations, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_625_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 624 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 624 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=624 AND migration_id='624_market_subscribed_line_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR (SELECT count(*) FROM notification_templates WHERE template_id='market.terms.changed.zh-cn' AND version=2) <> 2
         OR EXISTS (SELECT 1 FROM notification_templates WHERE template_id='market.terms.changed.zh-cn' AND version=3) THEN
        RAISE EXCEPTION 'migration 625 requires the verified 624 release head with market.terms.changed v2 templates and no v3'
            USING ERRCODE='P6250';
    END IF;
END;
$migration_625_up$;

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.terms.changed.zh-cn', 3, 'sms', '', '{{if eq .category "offer_delisted"}}卖方已下架节点市场供给{{.offer}}，当前订阅照常服务到{{.at}}，到期后不再续费并关闭。{{else}}节点市场供给{{.offer}}的条款已变更（{{.category}}），续费时将{{.action}}（renew=按新条款续费，close=到期关闭）。{{end}}', ARRAY['offer','subscription','action','category','at'], '2026-11-04 00:00:00+00'),
    ('market.terms.changed.zh-cn', 3, 'email', '节点市场：{{.offer}} {{if eq .category "offer_delisted"}}已下架，到期后不再续费{{else}}条款已变更{{end}}', '{{if eq .category "offer_delisted"}}卖方已下架供给 {{.offer}}（订阅 {{.subscription}}）：已停止新购买；你的订阅按已付条款照常服务到 {{.at}}，到期后不再续费，订阅自动关闭，不再扣费。如需继续使用，请在到期前另选供给并迁移站点。{{else}}卖方修改了供给 {{.offer}}（订阅 {{.subscription}}）的条款，变化点：{{.category}}（price_up/price_down=价格上涨/下降，limits_stricter/limits_looser=限额变严/变宽，sla_added/sla_removed=新增/取消 SLA，sla_better/sla_worse=SLA 变好/变差，*_mixed=有好有坏或无法比较，resale_on/resale_off=续费后可以/不再可以转售，site_pause_on/site_pause_off=续费后同站自动暂停开启/关闭）。限额变严、SLA 变差或取消视同涨价；价格和限额不变时，SLA 不变或变好按新条款续费；转售和同站暂停开关不影响续费条件，但续费后按新开关执行。按你设置的续费价格条件，本期到期时将 {{.action}}（renew=按新条款续费，close=不续费并关闭）。如需调整，请在到期前修改续费条件或取消订阅。{{end}}', ARRAY['offer','subscription','action','category','at'], '2026-11-04 00:00:00+00');
