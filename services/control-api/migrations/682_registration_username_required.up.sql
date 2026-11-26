LOCK TABLE schema_migrations, platform_system_user_settings IN ACCESS EXCLUSIVE MODE;

-- 682（前驱 681_account_recovery_default_template）。
-- 升级保持既有行为：用户名必填；管理员可在「系统配置 → 账号与安全 → 用户注册」关闭。
-- 「用户名 要求填写」(settings.username_required) 在此前从未生效，注册始终要求用户名；页面默认不勾，
-- 所以已保存的 false 多半只是沿用默认，不代表管理员要关。本迁移把平台系统用户设置里 username_required
-- 为 false 或缺失的行改为 true，升级后行为不变，管理员此后再关才生效。
-- 只改 settings 这一项：revision 不变（注册成功/找回密码/验证码模板按 revision 发布，改 revision 会找不到
-- 已发布模板），updated_at / updated_by_user_id 不变（不是管理员的保存）。审计链由应用逐条计算哈希
-- （internal/audit），迁移不写 audit_events，说明即本注释。用户名设置只有平台级一行，没有租户级表。
DO $migration_682_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 681 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 681 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=681 AND
        migration_id='681_account_recovery_default_template' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 682 requires the exact verified 681 release head' USING ERRCODE='P6820';
    END IF;
END;
$migration_682_up$;

UPDATE platform_system_user_settings
SET settings = jsonb_set(settings, '{username_required}', 'true'::jsonb, true)
WHERE settings->'username_required' IS DISTINCT FROM 'true'::jsonb;
