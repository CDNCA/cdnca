LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_336_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 335 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 335 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=335 AND
        migration_id='335_site_runtime_observation_revision' AND
        checksum_sha256='8efc7dc791cd6b1b104e43c4034fb33cca34586fa753db97c1a2f76d2476e431' AND
        down_checksum_sha256='fba9c2b6ff80501081631bdce6b08ff284734bdfe1f1fa38fe7aa16d803394f4' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM notification_event_policies
        WHERE event_type='package.monitor.cc_rule_auto_switch' AND NOT supported
       ) OR EXISTS (
        SELECT 1 FROM notification_templates WHERE template_id='package.monitor.cc_rule_auto_switch.zh-cn'
       ) THEN
        RAISE EXCEPTION 'migration 336 requires the exact verified 335 release head' USING ERRCODE='P3360';
    END IF;
END;
$migration_336_up$;

-- FX65: a site's CC auto switch engaged (reported by each serving node,
-- internal/ccautoswitch). The site owner is notified under their own
-- subscription; email is on by default like the other package monitor alerts.
-- 201 switched the then unsupported event off; enable it like 305 did.
UPDATE notification_event_policies
SET supported=true, enabled=true, sms_enabled=true, email_enabled=true, default_email=true, updated_at=now()
WHERE event_type='package.monitor.cc_rule_auto_switch';

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('package.monitor.cc_rule_auto_switch.zh-cn', 1, 'sms', '',
     '网站{{.domain}}于{{.engaged_at}}请求量异常(每秒{{.trigger_qps}}次)，已自动切换CC防护规则，约{{.recover_minutes}}分钟无异常后自动恢复。',
     ARRAY['domain','engaged_at','trigger_qps','recover_minutes'], '2026-10-17 00:00:00+00'),
    ('package.monitor.cc_rule_auto_switch.zh-cn', 1, 'email', 'CC 防护自动切换：{{.domain}}',
     '网站 {{.domain}} 于 {{.engaged_at}} 触发 CC 自动切换：每秒请求 {{.trigger_qps}} 次（阈值 {{.qps_total}}），每秒 5xx {{.trigger_5xx}} 次（阈值 {{.qps_5xx}}）。系统已切换到自动切换规则，持续 {{.recover_minutes}} 分钟低于阈值后自动恢复默认防护。',
     ARRAY['domain','engaged_at','trigger_qps','qps_total','trigger_5xx','qps_5xx','recover_minutes'], '2026-10-17 00:00:00+00');

-- One row per site: the current deduplication window. Engagements of the site
-- from any node within 5 minutes of window_started_at are one notice;
-- sequence numbers the notices (source event cc-auto-switch/<site>/<sequence>).
CREATE TABLE cc_auto_switch_notification_windows (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    window_started_at timestamptz NOT NULL,
    last_engaged_at timestamptz NOT NULL CHECK (last_engaged_at >= window_started_at),
    first_event_id uuid NOT NULL,
    first_node_id uuid NOT NULL,
    updated_at timestamptz NOT NULL
);
