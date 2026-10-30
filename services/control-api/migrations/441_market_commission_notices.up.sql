LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_441_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 440 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 440 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=440 AND
        migration_id='440_market_node_actions' AND
        checksum_sha256='a449412615332b505ae6cb97239d00443cdfc3f809f601b7b6bb02b5e174569b' AND
        down_checksum_sha256='2635e5a3b6fedf85604c7136a02955f5ca2c73dc42da404e6224f056b9a06600' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type LIKE 'market.commission.%'
       ) THEN
        RAISE EXCEPTION 'migration 441 requires the exact verified 440 release head' USING ERRCODE='P4410';
    END IF;
END;
$migration_441_up$;

-- 441（r136 ML-27，ADR 0012 §21.3/§23.2；merge-batch9 新增，前一版 440_market_node_actions）。
-- Direct commission prepaid notices in the notification center (same path
-- as 430): the market signs them as the seller to every controller of the
-- seller customer (they share one balance). low: balance under the alert line
-- the seller set; exhausted: balance reached 0 and the customer's sold
-- subscriptions are paused (commission_prepaid hold); restored: balance back
-- above 0 and the holds released. Amounts are minor units. Email on by
-- default, SMS off.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.commission.low', true, true, true, 1, 24, true, true, false, now()),
    ('market.commission.exhausted', true, true, true, 1, 24, true, true, false, now()),
    ('market.commission.restored', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.commission.low.zh-cn', 1, 'sms', '', '节点市场{{.currency}}抽成预付余额{{.observed}}低于预警线{{.cap}}（最小货币单位）。', ARRAY['currency','observed','cap'], '2026-10-22 00:00:00+00'),
    ('market.commission.low.zh-cn', 1, 'email', '节点市场：{{.currency}} 抽成预付余额低于预警线', '{{.currency}} 抽成预付余额 {{.observed}} 已低于你设置的预警线 {{.cap}}（金额为最小货币单位，如分）。余额用完后你卖出的直结供给将暂停调度，请及时充值。', ARRAY['currency','observed','cap'], '2026-10-22 00:00:00+00'),
    ('market.commission.exhausted.zh-cn', 1, 'sms', '', '节点市场{{.currency}}抽成预付余额已用完，你卖出的直结供给已暂停调度，请充值。', ARRAY['currency','observed'], '2026-10-22 00:00:00+00'),
    ('market.commission.exhausted.zh-cn', 1, 'email', '节点市场：{{.currency}} 抽成预付余额已用完', '{{.currency}} 抽成预付余额已用完（当前 {{.observed}}，最小货币单位），你卖出的直结订阅已暂停调度（凭证不吊销）。充值到账后自动恢复。', ARRAY['currency','observed'], '2026-10-22 00:00:00+00'),
    ('market.commission.restored.zh-cn', 1, 'sms', '', '节点市场{{.currency}}抽成预付已充值，直结供给已恢复调度。', ARRAY['currency','observed'], '2026-10-22 00:00:00+00'),
    ('market.commission.restored.zh-cn', 1, 'email', '节点市场：{{.currency}} 抽成预付已恢复', '{{.currency}} 抽成预付余额已恢复为 {{.observed}}（最小货币单位），因余额用完而暂停的直结订阅已恢复调度。', ARRAY['currency','observed'], '2026-10-22 00:00:00+00');
