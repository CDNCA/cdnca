LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_558_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 557 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 557 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=557 AND
        migration_id='557_billing_bridge_services' AND
        checksum_sha256='1f79a73f20d519c178b8f4f36eb7655928565333ade345bccc11d53761494826' AND
        down_checksum_sha256='2116e730310230bcebfe1da9167dac35beb70e01c37d4d2266f8973102a74aca' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN
            ('market.renewal.compensated')
       ) THEN
        RAISE EXCEPTION 'migration 558 requires the exact verified 557 release head' USING ERRCODE='P5580';
    END IF;
END;
$migration_558_up$;

-- 558（r136 fix-nm03，市场链验收 NM03，用户 10-28 定按责任补偿；占位：前驱以集成头 557_billing_bridge_services 为准，合入时主会话统一连号重钉）。
-- 节点市场上游商业暂停的补偿通知（同 ML-10 的 market.notice 通道、平台作用域、按事件订阅；邮件默认开、短信默认关），
-- 补偿规则 upstream-pause/v1（market 062）：
--   market.renewal.compensated（订阅方与卖方）：订阅的全部供给因上游原因（上游欠费/超透支上限/欠平台佣金）暂停，
--   暂停结束时按暂停期间已付未服务的时长补偿一次（同一次暂停只补一次）：
--   action=extended 顺延到期时间（observed=顺延秒数，at=新的到期时间），不退现金；
--   action=refunded 订阅在暂停中终止，按秒退回（observed=退款金额，最小货币单位，currency 币种）。
-- 同时把 market.renewal.stopped / resumed 的 v2 模板补上 upstream_paused 原因的白话说明（v1 保留，不改历史）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.renewal.compensated', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.renewal.compensated.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}因上游暂停已按规则补偿（{{.action}}）。', ARRAY['offer','subscription','action','observed','currency','at'], '2026-10-28 00:00:00+00'),
    ('market.renewal.compensated.zh-cn', 1, 'email', '节点市场：{{.offer}} 上游暂停补偿', '供给 {{.offer}}（订阅 {{.subscription}}）的全部供给曾因上游原因暂停（上游欠费、超透支上限或欠平台佣金，不是订阅方自己的原因），暂停期间已停止续费。按补偿规则 upstream-pause/v1，暂停期间已付但未获服务的时长补偿一次：{{.action}}（extended=顺延到期时间 {{.observed}} 秒，新的到期时间 {{.at}}，不退现金；refunded=订阅已终止，按秒退回 {{.observed}}（{{.currency}} 最小货币单位）到订阅方在该卖方处的余额）。恢复后不补扣暂停期间的费用；同一次暂停只补偿一次。仍有部分供给可用时不属于暂停，不补偿。', ARRAY['offer','subscription','action','observed','currency','at'], '2026-10-28 00:00:00+00'),
    ('market.renewal.stopped.zh-cn', 2, 'sms', '', '节点市场供给{{.offer}}已停止续费（原因 {{.action}}），不再扣日包费用。', ARRAY['offer','subscription','action'], '2026-10-28 00:00:00+00'),
    ('market.renewal.stopped.zh-cn', 2, 'email', '节点市场：{{.offer}} 已停止续费', '供给 {{.offer}}（订阅 {{.subscription}}）已停止续费，原因：{{.action}}（seller_frozen=卖方被平台冻结，buyer_frozen=订阅方被平台冻结，upstream_lost=上游供给失效，no_grant=没有有效授权，upstream_paused=全部供给因上游欠费或欠平台佣金暂停）。从现在起不再续未来周期、不再扣日包费用；已发生的按量用量照常结算。原因解除后自动恢复续费，停续期间不补扣。upstream_paused：恢复时把暂停期间已付未服务的时长顺延到期时间，不退现金；暂停中订阅终止则按秒退款；同一次暂停只补一次。', ARRAY['offer','subscription','action'], '2026-10-28 00:00:00+00'),
    ('market.renewal.resumed.zh-cn', 2, 'sms', '', '节点市场供给{{.offer}}已恢复续费。', ARRAY['offer','subscription','action'], '2026-10-28 00:00:00+00'),
    ('market.renewal.resumed.zh-cn', 2, 'email', '节点市场：{{.offer}} 已恢复续费', '供给 {{.offer}}（订阅 {{.subscription}}）停止续费的原因（{{.action}}）已解除，下次续费从现在起算，停续期间不补扣。原因为 upstream_paused（上游暂停）时，暂停期间已付未服务的时长已顺延到期时间，另见补偿通知。', ARRAY['offer','subscription','action'], '2026-10-28 00:00:00+00');
