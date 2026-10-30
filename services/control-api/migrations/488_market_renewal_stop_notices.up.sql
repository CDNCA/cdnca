LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_488_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 487 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 487 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=487 AND
        migration_id='487_tenant_member_password_reset_results' AND
        checksum_sha256='b78bfc9655330cfc9cfbbc96238af8df73871768947d8b151b0db11cb14d37dd' AND
        down_checksum_sha256='b315adc033b593623a1eba8c4d5e94fccd2aaee43aafbea0dcf0f61ea63dd5aa' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN
            ('market.renewal.stopped', 'market.renewal.resumed')
       ) THEN
        RAISE EXCEPTION 'migration 488 requires the exact verified 487 release head' USING ERRCODE='P4880';
    END IF;
END;
$migration_488_up$;

-- 488（r136 p0f-renew-frozen，Codex 审测 MKT-RENEW-FROZEN；占位：488 原预留 n23，合入时主会话按集成头改号并重钉前驱）。
-- 节点市场订阅停止续费 / 恢复续费（同 ML-10 的 market.notice 通道、平台作用域、按事件订阅；邮件默认开、短信默认关）：
-- market.renewal.stopped（订阅方与卖方）：卖方或订阅方被平台冻结、上游失效或没有有效授权，订阅不再续未来周期、不再扣日包费；
-- market.renewal.resumed（双方）：原因解除，下次续费从恢复时起算，停续期间不补扣。
-- action 为原因：buyer_frozen / seller_frozen / upstream_lost / no_grant。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.renewal.stopped', true, true, true, 1, 24, true, true, false, now()),
    ('market.renewal.resumed', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.renewal.stopped.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}已停止续费（原因 {{.action}}），不再扣日包费用。', ARRAY['offer','subscription','action'], '2026-10-24 00:00:00+00'),
    ('market.renewal.stopped.zh-cn', 1, 'email', '节点市场：{{.offer}} 已停止续费', '供给 {{.offer}}（订阅 {{.subscription}}）已停止续费，原因：{{.action}}（seller_frozen=卖方被平台冻结，buyer_frozen=订阅方被平台冻结，upstream_lost=上游供给失效，no_grant=没有有效授权）。从现在起不再续未来周期、不再扣日包费用；已发生的按量用量照常结算。原因解除后自动恢复续费，停续期间不补扣。', ARRAY['offer','subscription','action'], '2026-10-24 00:00:00+00'),
    ('market.renewal.resumed.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}已恢复续费。', ARRAY['offer','subscription','action'], '2026-10-24 00:00:00+00'),
    ('market.renewal.resumed.zh-cn', 1, 'email', '节点市场：{{.offer}} 已恢复续费', '供给 {{.offer}}（订阅 {{.subscription}}）停止续费的原因（{{.action}}）已解除，下次续费从现在起算，停续期间不补扣。', ARRAY['offer','subscription','action'], '2026-10-24 00:00:00+00');
