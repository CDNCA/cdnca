LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_469_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 468 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 468 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=468 AND
        migration_id='468_node_native_runtime' AND
        checksum_sha256='0e6ce3d3dc426695ab7c142fa2581f0e5cce0a2a754e14bfc7a6700a04b96dba' AND
        down_checksum_sha256='8a4e6bd6fabe1c56cc277f48d570d733def4555f97f4cff7616235d94625a587' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='security.escalate.cname_change_required'
       ) THEN
        RAISE EXCEPTION 'migration 469 requires the exact verified 468 release head' USING ERRCODE='P4690';
    END IF;
END;
$migration_469_up$;

-- 469（r136 esc-autocname）：攻击自动升级拆出站点级 CNAME 后，主控不能自动改站长解析
-- （泛域名 / 根域名 / 未托管 / 服务商报错或记录冲突）时通知站长手动修改（用户 10-22 19:00）。
-- 默认邮件开、短信关；同一次拆分同一原因只发一次（escalate.LineExecutor.recordCNAMEOutcome）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('security.escalate.cname_change_required', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('security.escalate.cname_change_required.zh-cn', 1, 'sms', '',
     '网站{{.domain}}已拆出独立CNAME，需要你把域名解析改为CNAME {{.cname}}，改好前攻击升级无法切换线路。原因：{{.reason}}',
     ARRAY['domain','cname','reason'], '2026-10-24 00:00:00+00'),
    ('security.escalate.cname_change_required.zh-cn', 1, 'email', '攻击自动升级：请修改 {{.domain}} 的 CNAME 解析',
     '为让网站 {{.domain}} 在遭受攻击时能单独切换线路，平台已为它拆出独立的 CNAME：{{.cname}}。平台没有自动修改你的域名解析，原因：{{.reason}}。请到你的 DNS 服务商把上述域名的记录改为 CNAME 指向 {{.cname}}，然后在控制台「攻击升级」点「我已修改」。改好之前，该网站的攻击升级不会切换线路。',
     ARRAY['domain','cname','reason'], '2026-10-24 00:00:00+00');
