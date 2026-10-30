LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_438_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 437 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 437 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=437 AND
        migration_id='437_market_supply_tenant_plugins' AND
        checksum_sha256='b535964e274654e00a376c3a012990d39d4321e3fdfc576b1a7bd0a6ef655778' AND
        down_checksum_sha256='e8513641a2746a9dc4ef39547052c318bedde26d43123ac69d60388c60316c53' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='market.downstream.attacked'
       ) THEN
        RAISE EXCEPTION 'migration 438 requires the exact verified 437 release head' USING ERRCODE='P4380';
    END IF;
END;
$migration_438_up$;

-- 438（r136 ML-20，ADR 0012 §19.1/§23.2；占位，合入时主会话改号，集成头 431_market_supply_limits 之后）。
-- A reseller on a market subscription path learns that a site further down
-- was attacked, with ADR 0012 §18.2 visibility a (merge-batch9): the direct
-- seller of the root subscriber gets its own subscription, a seller further up
-- only the downstream number of its subscriber view; plus the window. Never
-- the site, its domain or the root subscriber's identity. Same delivery as the other market
-- notices (marketplace.sell holders, tenant_subscribed, email on, SMS off).
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('market.downstream.attacked', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.downstream.attacked.zh-cn', 1, 'sms', '', '节点市场：下游站点受到攻击（订阅{{.subscription}}，下游编号{{.downstream}}，窗口{{.window_start}}）。', ARRAY['subscription','downstream','window_start'], '2026-10-22 00:00:00+00'),
    ('market.downstream.attacked.zh-cn', 1, 'email', '节点市场：下游站点受到攻击', '经您转售的供给上，下游站点在窗口 {{.window_start}}（Unix 秒，5 分钟）内受到攻击，已由叶子节点处置。直接向您订阅的买方显示为您的订阅 {{.subscription}}；更下游的只给下游编号 {{.downstream}}（与订阅者视图一致；不适用的一项为 -）。站点身份与攻击详情只回传给该站点的所有者；同一下游每小时最多通知一次。', ARRAY['subscription','downstream','window_start'], '2026-10-22 00:00:00+00');
