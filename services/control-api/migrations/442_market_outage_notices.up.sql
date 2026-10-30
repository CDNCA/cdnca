LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_442_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 441 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 441 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=441 AND
        migration_id='441_market_commission_notices' AND
        checksum_sha256='2da9ce6b6eec59505b9494dd681cd62a5d9f9735881343fb0a73177121532ea5' AND
        down_checksum_sha256='07d1d9b974fc28fa8a3b9d8976143d828c75051e44b1e46a2fbdc30fdc66d481' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN
            ('market.supply.outage', 'market.supply.restored', 'market.supply.cancel_available')
       ) THEN
        RAISE EXCEPTION 'migration 442 requires the exact verified 441 release head' USING ERRCODE='P4420';
    END IF;
END;
$migration_442_up$;

-- 442（r136 ML-31，ADR 0012 §24；占位，合入时主会话改号）。供给 0 在线可用节点的 3 个市场通知
-- （同 ML-10 的 market.notice 通道、平台作用域、按事件订阅；邮件默认开、短信默认关）：
-- market.supply.outage（订阅方与卖方）、market.supply.restored（双方）、market.supply.cancel_available（订阅方：已满 T1 可无责取消）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.supply.outage', true, true, true, 1, 24, true, true, false, now()),
    ('market.supply.restored', true, true, true, 1, 24, true, true, false, now()),
    ('market.supply.cancel_available', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.supply.outage.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}已无在线可用节点，期间不计费，站点会切到备用供给或自有节点。', ARRAY['offer','subscription'], '2026-10-22 00:00:00+00'),
    ('market.supply.outage.zh-cn', 1, 'email', '节点市场：{{.offer}} 无在线可用节点', '供给 {{.offer}}（订阅 {{.subscription}}）当前没有在线可用节点。期间不计费：包天按离线时长冲抵到你在该供货方处的余额，按量无流量不扣。有备用供给或自有节点的站点会自动切过去；没有的请另订其他供给。持续 30 分钟后可在"我的订阅"一键无责取消。', ARRAY['offer','subscription'], '2026-10-22 00:00:00+00'),
    ('market.supply.restored.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}已恢复在线可用节点。', ARRAY['offer','subscription'], '2026-10-22 00:00:00+00'),
    ('market.supply.restored.zh-cn', 1, 'email', '节点市场：{{.offer}} 已恢复', '供给 {{.offer}}（订阅 {{.subscription}}）已恢复在线可用节点，离线期间的费用已冲抵到余额；站点按回切策略切回。', ARRAY['offer','subscription'], '2026-10-22 00:00:00+00'),
    ('market.supply.cancel_available.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}持续无在线可用节点，现在可无责取消，剩余时长退回该供货方处余额。', ARRAY['offer','subscription'], '2026-10-22 00:00:00+00'),
    ('market.supply.cancel_available.zh-cn', 1, 'email', '节点市场：{{.offer}} 可无责取消', '供给 {{.offer}}（订阅 {{.subscription}}）无在线可用节点已超过 30 分钟。你可以在"我的订阅"一键无责取消：立即生效，剩余已付时长退回你在该供货方处的余额（不原路退回）。恢复在线后此选项消失。', ARRAY['offer','subscription'], '2026-10-22 00:00:00+00');
