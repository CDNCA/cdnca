LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_407_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 406 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 406 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=406 AND
        migration_id='406_http_policy_referer_check' AND
        checksum_sha256='bf1d4b29b1422ac549d95266875ffd6cd4c12854830d8623b7cdc188606d7675' AND
        down_checksum_sha256='7949e0b3c479c53c23bd0295df87ef44ee8650f62bea6b4c28cbf09c6b40f86f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (SELECT 1 FROM notification_event_policies WHERE event_type='security.attack.detected') THEN
        RAISE EXCEPTION 'migration 407 requires the exact verified 406 release head' USING ERRCODE='P4070';
    END IF;
END;
$migration_407_up$;

-- ge-waf S7 (GoEdge parity: WAF notify action, done better): attack alerts.
-- The control plane aggregates enforced WAF / CC decisions (block, challenge,
-- temporary ban) per site over 5-minute windows (internal/attackalert). A site
-- with 1000 or more in one window tells its owner once; the next notice for
-- the site waits at least an hour. Never one message per request. Delivery
-- (on/off, channels) is this event's notification policy; email is on by
-- default like the other site monitor alerts.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, default_email, updated_at
) VALUES ('security.attack.detected', true, true, true, 1, 1, true, true, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('security.attack.detected.zh-cn', 1, 'sms', '',
     '网站{{.domain}}在{{.window_minutes}}分钟内拦截攻击{{.events}}次，来源IP {{.clients}}个，请登录控制台查看拦截日志。',
     ARRAY['domain','window_minutes','events','clients'], '2026-10-18 00:00:00+00'),
    ('security.attack.detected.zh-cn', 1, 'email', '攻击告警：{{.domain}}',
     '网站 {{.domain}} 在 {{.window_start}} 至 {{.window_end}}（{{.window_minutes}} 分钟）内被 WAF / CC 防护处理 {{.events}} 次：拦截 {{.blocked}} 次、人机验证 {{.challenged}} 次、临时封禁 {{.banned}} 次，来源 IP {{.clients}} 个，最多的来源 {{.top_client_ip}}，主要检测类型 {{.top_detector}}。请在控制台“拦截日志”查看明细；同一网站 {{.cooldown_minutes}} 分钟内不重复提醒。',
     ARRAY['domain','window_start','window_end','window_minutes','events','blocked','challenged','banned','clients',
           'top_client_ip','top_detector','cooldown_minutes'], '2026-10-18 00:00:00+00');

-- Evaluation cursor: the end of the last evaluated window (windows are
-- aligned, evaluated once, after ingestion settles).
CREATE TABLE attack_alert_cursor (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    evaluated_through timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

-- One row per site: the last notice, for the cooldown and the sequence of
-- source events (attack-alert/<site>/<sequence>).
CREATE TABLE attack_alert_site_states (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    last_notified_at timestamptz NOT NULL,
    last_window_end timestamptz NOT NULL,
    last_events bigint NOT NULL CHECK (last_events >= 1),
    updated_at timestamptz NOT NULL
);
