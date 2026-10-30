LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_445_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 444 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 444 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=444 AND
        migration_id='444_market_direct_topups' AND
        checksum_sha256='c3584641ecff4273d47c95983ca8932dea6a6ffaef47900fddfeb2a1c7fe3df6' AND
        down_checksum_sha256='ec709032b749decd863b5a7bef40d622bea6feb924b76de0fb55e0ad947a8e5a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN
            ('market.seller.deposit_mode', 'market.seller.deposit_shortfall', 'market.seller.default_compensated', 'market.seller.defaulted')
       ) THEN
        RAISE EXCEPTION 'migration 445 requires the exact verified 444 release head' USING ERRCODE='P4450';
    END IF;
END;
$migration_445_up$;

-- 445（r136 ml-direct-pay3，ADR 0015 §11；占位，合入时主会话改号）。节点市场防跑路保证金的 4 个市场通知
-- （同 ML-10 的 market.notice 通道、平台作用域、按事件订阅；邮件默认开、短信默认关）：
-- market.seller.deposit_mode（卖方：运营调整了单独保证金开关）、market.seller.deposit_shortfall（卖方：保证金不足，
-- 暂停新订阅与新充值）、market.seller.default_compensated（订阅方：供货方被判失联，平台用保证金赔付到平台余额）、
-- market.seller.defaulted（卖方：被判失联，保证金已用于赔付，供货权限暂停）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.seller.deposit_mode', true, true, true, 1, 24, true, true, false, now()),
    ('market.seller.deposit_shortfall', true, true, true, 1, 24, true, true, false, now()),
    ('market.seller.default_compensated', true, true, true, 1, 24, true, true, false, now()),
    ('market.seller.defaulted', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.seller.deposit_mode.zh-cn', 1, 'sms', '', '节点市场：平台已将你的防跑路保证金设置调整为{{.action}}（inherit 跟随全局/on 单独开启/off 单独关闭）。', ARRAY['action'], '2026-10-22 00:00:00+00'),
    ('market.seller.deposit_mode.zh-cn', 1, 'email', '节点市场：保证金设置已调整', '平台运营已将你的防跑路保证金设置调整为 {{.action}}（inherit = 跟随全局开关，on = 单独开启，off = 单独关闭）。开启时保证金不足会暂停新订阅与新充值，请在开发者平台“保证金”页查看应缴额并补缴。', ARRAY['action'], '2026-10-22 00:00:00+00'),
    ('market.seller.deposit_shortfall.zh-cn', 1, 'sms', '', '节点市场：你的保证金{{.observed}}{{.currency}}低于应缴{{.cap}}（最小货币单位），已暂停新订阅与新充值，请补缴。', ARRAY['currency','observed','cap'], '2026-10-22 00:00:00+00'),
    ('market.seller.deposit_shortfall.zh-cn', 1, 'email', '节点市场：保证金不足，请补缴', '你的防跑路保证金当前 {{.observed}}（{{.currency}}，最小货币单位，如分），低于应缴额 {{.cap}}。补足前你的报价不接受新订阅，订阅方也不能在线给你充值；已有订阅不受影响。请在开发者平台“保证金”页补缴。', ARRAY['currency','observed','cap'], '2026-10-22 00:00:00+00'),
    ('market.seller.default_compensated.zh-cn', 1, 'sms', '', '节点市场：供货方{{.peer}}被判失联，平台已用其保证金赔付{{.observed}}{{.currency}}到你的平台余额（你在其处余额{{.cap}}）。', ARRAY['peer','currency','observed','cap'], '2026-10-22 00:00:00+00'),
    ('market.seller.default_compensated.zh-cn', 1, 'email', '节点市场：{{.peer}} 失联赔付已到账', '供货方 {{.peer}} 被判定失联。平台按比例用其保证金赔付你 {{.observed}}（{{.currency}}，最小货币单位），已计入你的平台预付余额（不原路退回）；你在该供货方处原有余额 {{.cap}}，未赔付部分仍是你对该供货方的债权。', ARRAY['peer','currency','observed','cap'], '2026-10-22 00:00:00+00'),
    ('market.seller.defaulted.zh-cn', 1, 'sms', '', '节点市场：你被判定失联，保证金已用于赔付订阅方{{.observed}}{{.currency}}，供货权限已暂停。', ARRAY['currency','observed'], '2026-10-22 00:00:00+00'),
    ('market.seller.defaulted.zh-cn', 1, 'email', '节点市场：你已被判定失联', '你的主控长期离线或供给长期无在线节点，已被判定失联。平台已用你的保证金赔付订阅方共 {{.observed}}（{{.currency}}，最小货币单位），节点供货权限暂停、报价已下架，剩余保证金冻结至争议期结束后由运营裁定。如有异议请联系平台运营。', ARRAY['currency','observed'], '2026-10-22 00:00:00+00');
