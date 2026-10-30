LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_452_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 451 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 451 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=451 AND
        migration_id='451_security_ip_lists' AND
        checksum_sha256='c36630cb599f465559434e1f8b2c0c72c99b7c19b3e591c36c9f76ae0a12fef5' AND
        down_checksum_sha256='2d1e3167789dabf7c6ba950e06f82f7b4ebdadd96b7c7043aba818674af40477' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='node.security.waf_ban'
       ) THEN
        RAISE EXCEPTION 'migration 452 requires the exact verified 451 release head' USING ERRCODE='P4520';
    END IF;
END;
$migration_452_up$;

-- 452（r136 small-1035j J1；占位，合入时改号）。
-- WAF automatic bans in the notification center: a node's WAF temporary_ban
-- (同 IP 超阈值自动拉黑 waf_settings.auto_block, or a WAF ban rule) that the
-- control plane folds into the ban list (internal/securityban sync.go) is
-- announced to the platform members holding nodes.manage, like the node
-- kernel bans (421). One message per (site, client, hour): the first ban of
-- the hour (internal/securityban waf_ban_alerts.go). Email on by default,
-- SMS off.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('node.security.waf_ban', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.security.waf_ban.zh-cn', 1, 'sms', '',
     '网站{{.site_domain}}的WAF自动封禁了客户端{{.client_ip}}，封禁{{.duration_seconds}}秒。',
     ARRAY['site_domain','client_ip','duration_seconds'], '2026-10-22 00:00:00+00'),
    ('node.security.waf_ban.zh-cn', 1, 'email', 'WAF 自动封禁：{{.site_domain}} {{.client_ip}}',
     '网站 {{.site_domain}} 的 WAF 在 {{.occurred_at}}（UTC）自动封禁了客户端 {{.client_ip}}，封禁 {{.duration_seconds}} 秒，已加入封禁名单并下发到服务该网站的全部节点。同一网站同一客户端每小时只通知一次，完整记录见封禁名单与安全事件。',
     ARRAY['site_domain','client_ip','duration_seconds','occurred_at'], '2026-10-22 00:00:00+00');
