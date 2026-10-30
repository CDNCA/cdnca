LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_421_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 420 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 420 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=420 AND
        migration_id='420_aggregated_edge_fixed' AND
        checksum_sha256='917bc1485185055f4e8442da990375423819f87e942ba80432507a24e8dd9592' AND
        down_checksum_sha256='d6909aa87797a285e8843aaf0165337d06ee8798a37a16ed073265c42e874a26' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='node.security.event'
       ) THEN
        RAISE EXCEPTION 'migration 421 requires the exact verified 420 release head' USING ERRCODE='P4210';
    END IF;
END;
$migration_421_up$;

-- 421（r136 sec-events，BACKLOG-1035c A4；占位，预留 426，合入时改号）。
-- Node security events in the notification center: kernel bans a node made
-- on its own (DDoS new connection rate bans and empty connection bans, L4
-- guard kernel bans; node_event reports, ClickHouse node_security_events_v1)
-- are announced to the platform members holding nodes.manage. One message
-- per (node, source, kind, hour): the first event of the hour (control-api
-- internal/autodefense node_event_alerts.go). Email on by default, SMS off.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('node.security.event', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.security.event.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}({{.node_ip}})发生{{.event_kind}}：客户端{{.client_ip}}，{{.count}}次，封禁{{.duration_seconds}}秒。',
     ARRAY['node_name','node_ip','event_kind','client_ip','count','duration_seconds'], '2026-10-20 00:00:00+00'),
    ('node.security.event.zh-cn', 1, 'email', '节点安全事件：{{.node_name}} {{.event_kind}}',
     '节点 {{.node_name}}（{{.node_ip}}）在 {{.occurred_at}}（UTC）发生 {{.event_kind}}：客户端 {{.client_ip}}，计数 {{.count}}，封禁 {{.duration_seconds}} 秒。同一节点同类事件每小时只通知一次，完整记录见节点安全事件。',
     ARRAY['node_name','node_ip','event_kind','client_ip','count','duration_seconds','occurred_at'], '2026-10-20 00:00:00+00');
