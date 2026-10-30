LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_309_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 308 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 308 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=308 AND
        migration_id='308_package_auto_renew' AND
        checksum_sha256='cf00f85140ed657e76bcff2cbb0db8c5a5f284d82dbd459a2e0fbf2e2ef3a5df' AND
        down_checksum_sha256='3dd8a5febfb33f7676245c9b6f41f44d3d2ad6846456b0d3fe760aa6530d4b4b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 309 requires the exact verified 308 release head' USING ERRCODE='P3090';
    END IF;
END;
$migration_309_up$;

-- FX33: node availability alerts for platform members holding nodes.manage.
-- Enabled by default like the other supported events; SMS is still gated by
-- the global channel switch and the configured provider.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, updated_at
) VALUES
    ('node.availability.offline', true, true, true, 1, 1, true, now()),
    ('node.availability.recovered', true, true, true, 1, 1, true, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.availability.offline.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}({{.node_ip}})监控异常已暂停服务，原因{{.reason}}，时间{{.occurred_at}}。',
     ARRAY['node_name','node_ip','reason','occurred_at'], '2026-10-17 00:00:00+00'),
    ('node.availability.offline.zh-cn', 1, 'email', '节点监控告警：节点已离线',
     '节点{{.node_name}}（{{.node_ip}}）监控检测异常，已从解析中暂停。原因：{{.reason}}。时间：{{.occurred_at}}。',
     ARRAY['node_name','node_ip','reason','occurred_at'], '2026-10-17 00:00:00+00'),
    ('node.availability.recovered.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}({{.node_ip}})已恢复服务，原因{{.reason}}，时间{{.occurred_at}}。',
     ARRAY['node_name','node_ip','reason','occurred_at'], '2026-10-17 00:00:00+00'),
    ('node.availability.recovered.zh-cn', 1, 'email', '节点监控恢复：节点已恢复',
     '节点{{.node_name}}（{{.node_ip}}）监控恢复正常，已重新加入解析。原因：{{.reason}}。时间：{{.occurred_at}}。',
     ARRAY['node_name','node_ip','reason','occurred_at'], '2026-10-17 00:00:00+00');

