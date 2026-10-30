LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_587_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 586 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 586 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=586 AND
        migration_id='586_plugin_installation_target_binding' AND
        checksum_sha256='36d17680071315b00035da5cb7accb75eb360e55bcd4330485a24141b87f5af6' AND
        down_checksum_sha256='b20a682775f47fe81728583de28f18d7e7c08b5404ccd8d9f34446572b26a395' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type = 'market.plugin.promo_charge'
       ) THEN
        RAISE EXCEPTION 'migration 587 requires the exact verified 586 release head' USING ERRCODE='P5870';
    END IF;
END;
$migration_587_up$;

-- 587（r136 fix-plugpromo；派单占位 606，本地 579，merge-p23 改号为 587）。
-- 插件限免转按月收费提醒（同 ML-10 的 market.notice 通道、平台作用域、按事件订阅；邮件默认开、短信默认关）：
-- market.plugin.promo_charge（给买方）：限免领取的插件将转为按月收费，到期前 7 天（d7）与 1 天（d1）各一次；
-- 变量 plugins=插件 ID，at=首次扣费时间，observed=每月价格（分），currency=币种。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.plugin.promo_charge', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.plugin.promo_charge.zh-cn', 1, 'sms', '', '限免插件{{.plugins}}将于{{.at}}转为按月收费，请保持余额充足。', ARRAY['plugins','at','observed','currency'], '2026-10-28 00:00:00+00'),
    ('market.plugin.promo_charge.zh-cn', 1, 'email', '插件市场：限免插件 {{.plugins}} 即将转为按月收费', '你领取的限免插件 {{.plugins}} 将于 {{.at}} 转为按月收费，每月 {{.observed}}（{{.currency}} 分），首次从预付余额扣款。余额不足时按按月插件的欠费规则处理：宽限期内照常使用，宽限期结束仍未支付则停用。不想继续使用可在「插件市场 → 我的插件」取消续费。', ARRAY['plugins','at','observed','currency'], '2026-10-28 00:00:00+00');
