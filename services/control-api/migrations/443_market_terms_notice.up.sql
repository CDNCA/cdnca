LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_443_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 442 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 442 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=442 AND
        migration_id='442_market_outage_notices' AND
        checksum_sha256='b3be37fb49931831a49ace2a8df19d6b7eda13289ab9ba23ea7cafcc2138325b' AND
        down_checksum_sha256='58beb8d3dd25daf2dfc8e7adbf12edc1e07d83b357af0d1f8b6da0ca682ab18f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='market.terms.changed'
       ) THEN
        RAISE EXCEPTION 'migration 443 requires the exact verified 442 release head' USING ERRCODE='P4430';
    END IF;
END;
$migration_443_up$;

-- 443（r136 small-1035e C7a，占位：合入时由主会话改号，前一版 433_market_listing_batches）。
-- market.terms.changed: the seller changed an offer the buyer subscribes to
-- (10-21 02:10: stricter limits count as a price increase). Sent at the
-- change, before the renewal; action says whether the buyer's renewal price
-- condition will renew on the new terms or close the subscription.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.terms.changed', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.terms.changed.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}的条款已变更，续费时将{{.action}}（renew=按新条款续费，close=到期关闭）。', ARRAY['offer','subscription','action'], '2026-10-22 00:00:00+00'),
    ('market.terms.changed.zh-cn', 1, 'email', '节点市场：{{.offer}} 条款已变更', '卖方修改了供给 {{.offer}}（订阅 {{.subscription}}）的价格或限额（限额变严视同涨价）。按你设置的续费价格条件，本期到期时将 {{.action}}（renew=按新条款续费，close=不续费并关闭）。如需调整，请在到期前修改续费条件或取消订阅。', ARRAY['offer','subscription','action'], '2026-10-22 00:00:00+00');
