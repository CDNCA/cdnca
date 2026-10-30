LOCK TABLE schema_migrations, sites, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_601_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 600 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 600 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=600 AND
        migration_id='600_aggregated_edge_owner_scope' AND
        checksum_sha256='f42271710f0966a3ff0290d90e71fd35d31884f6fceb986e7f8e36f60147950a' AND
        down_checksum_sha256='0f7ae94ba04bcfae97accd5f3802db3ee2583173ac091cac9f00ed951dfc7af3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='aggregated_edge.tenant.switch'
       ) THEN
        RAISE EXCEPTION 'migration 601 requires the exact verified 600 release head' USING ERRCODE='P6010';
    END IF;
END;
$migration_601_up$;

-- 601（r136 fix-chaintenant，ADR 0020 §5 第③期；主会话预留 control 601，前驱 600 = fix-edgeowner）：
-- 商家服务与用户自有第三方 CDN 自动切换的租户侧。
--   1. fallback_chain_tenant_choices：租户在用户端的选择（每站一行，无行=默认全开）。
--      auto_switch=false：本站不跑保底链（与管理员的 fallback_chain_site_overrides 分开存，
--      租户关掉不会覆盖、也不会被误当成管理员的单站设置；管理员开着、租户关着即不跑）。
--      use_own_cdn=false：自动切换时不用站点本人的第三方 CDN（只剩主控兜底）。
--      「回切方式」复用 aggregated_edge_site_schedules.failback，不在这里重复存。
--   2. 通知事件 aggregated_edge.tenant.switch（租户事件）：自动切走 / 自动回切 / 冻结时发给站点所属
--      租户中持 edge.tenant.read 的成员；订阅页可开关，默认邮件开、短信关。
CREATE TABLE fallback_chain_tenant_choices (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    auto_switch boolean NOT NULL DEFAULT true,
    use_own_cdn boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at))
);

REVOKE ALL ON fallback_chain_tenant_choices FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON fallback_chain_tenant_choices TO cdnca_control_app, cdnca_control_runtime;

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('aggregated_edge.tenant.switch', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('aggregated_edge.tenant.switch.zh-cn', 1, 'sms', '',
     '网站{{.site_domain}}：{{.alert_text}}（{{.switch_from}} → {{.switch_to}}），详情：{{.link}}',
     ARRAY['site_domain','alert_text','switch_from','switch_to','link'], '2026-10-29 00:00:00+00'),
    ('aggregated_edge.tenant.switch.zh-cn', 1, 'email', '网站 {{.site_domain}} 的线路已自动切换',
     '网站 {{.site_domain}}：{{.alert_text}}。切换前：{{.switch_from}}；切换后：{{.switch_to}}。可在控制台网站详情的「自动切换」查看切换记录、手动切换或切回：{{.link}}',
     ARRAY['site_domain','alert_text','switch_from','switch_to','link'], '2026-10-29 00:00:00+00');
