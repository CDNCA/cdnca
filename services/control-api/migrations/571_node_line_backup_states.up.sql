LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_571_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 570 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 570 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=570 AND
        migration_id='570_certificate_renewal_delivery' AND
        checksum_sha256='1e1a5d0171c7c74c0e1071cc935aec004f3cd2d33db21ea126f6f7d9722f0e1c' AND
        down_checksum_sha256='72e84282f1dadefb541e581ee0719b7ab28f1eba8a29b26bb530fedba4ac35aa' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_line_group_backup_states') IS NOT NULL OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN ('node.line_group.backup_ip_activated',
            'node.line_group.primary_ip_restored')
       ) THEN
        RAISE EXCEPTION 'migration 571 requires the exact verified 570 release head' USING ERRCODE='P5710';
    END IF;
END;
$migration_571_up$;

-- 571（fix-backupnotify，用户 10-27 22:4x；占位，合入时由主会话改号与改钉前驱，前驱暂钉集成头 552_usage_report_state）。
-- 备用 IP 是否启用原本只在视图 node_line_endpoint_published（501）里现算，没有状态也没有通知。
-- node_line_group_backup_states 记每个线路组 × 地址族是否正在发布备用 IP（normal / backup_active）与迁移时间：
-- 当前版本里有“备用且在线（未被系统摘除）且被发布”的端点即 backup_active，backup_addresses 为这些 IP；
-- 全部离线时视图兜底全发布的备用 IP 不算启用备用（节点离线告警已覆盖）。sequence 每次迁移 +1，
-- 评估器（internal/nodeserving line_backup.go，与节点监控同一 worker 周期）按 sequence CAS，
-- 在线判定沿用 node_serving_holds 的连续次数，不另设阈值。
-- 迁移时同事务入队 node.line_group.backup_ip_activated / node.line_group.primary_ip_restored，
-- 只发平台作用域里持 nodes.manage 的成员；重复提醒在状态已再迁移时撤回。线路组删除或该地址族不再存在时静默回 normal。
CREATE TABLE node_line_group_backup_states (
    tenant_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    address_family smallint NOT NULL CHECK (address_family IN (4, 6)),
    state text NOT NULL CHECK (state IN ('normal', 'backup_active')),
    config_revision bigint NOT NULL CHECK (config_revision > 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    backup_addresses inet[] NOT NULL DEFAULT '{}',
    changed_at timestamptz NOT NULL CHECK (isfinite(changed_at)),
    PRIMARY KEY (tenant_scope_id, line_group_id, address_family),
    FOREIGN KEY (tenant_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE CASCADE,
    CONSTRAINT node_line_group_backup_states_addresses_571_ck CHECK (
        (state = 'backup_active') = (cardinality(backup_addresses) > 0) AND cardinality(backup_addresses) <= 512)
);

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('node.line_group.backup_ip_activated', true, true, true, 1, 1, true, true, false, now()),
    ('node.line_group.primary_ip_restored', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.line_group.backup_ip_activated.zh-cn', 1, 'sms', '',
     '线路组{{.line_group_name}}的{{.address_family}}主 IP 不可用，已启用备用 IP {{.backup_addresses}}，时间{{.occurred_at}}。',
     ARRAY['line_group_name','address_family','backup_addresses','occurred_at'], '2026-10-27 00:00:00+00'),
    ('node.line_group.backup_ip_activated.zh-cn', 1, 'email', '线路组已启用备用 IP：{{.line_group_name}}',
     '线路组 {{.line_group_name}} 的 {{.address_family}} 主 IP 已被监控摘除，已在 {{.occurred_at}}（UTC）开始解析到备用 IP：{{.backup_addresses}}。主 IP 恢复后自动切回并另行通知。',
     ARRAY['line_group_name','address_family','backup_addresses','occurred_at'], '2026-10-27 00:00:00+00'),
    ('node.line_group.primary_ip_restored.zh-cn', 1, 'sms', '',
     '线路组{{.line_group_name}}的{{.address_family}}主 IP 已恢复，已停用备用 IP，时间{{.occurred_at}}。',
     ARRAY['line_group_name','address_family','occurred_at'], '2026-10-27 00:00:00+00'),
    ('node.line_group.primary_ip_restored.zh-cn', 1, 'email', '线路组已恢复主 IP：{{.line_group_name}}',
     '线路组 {{.line_group_name}} 的 {{.address_family}} 主 IP 已恢复，已在 {{.occurred_at}}（UTC）切回主 IP，备用 IP 不再解析。',
     ARRAY['line_group_name','address_family','occurred_at'], '2026-10-27 00:00:00+00');

REVOKE ALL ON node_line_group_backup_states FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON node_line_group_backup_states TO cdnca_control_app, cdnca_control_runtime;
