-- 671 回退：secrets_fingerprints 允许的键回到 668 的六个。页面已保存 KYC 对象存储密钥时拒绝（回退会让
-- 已存密钥违反约束；先在页面清空这三项再回退）。settings jsonb 里的 kyc_* 普通字段保留，旧代码读取时忽略未知键。
LOCK TABLE schema_migrations, platform_system_user_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_671_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 671 OR
       (SELECT max(version) FROM schema_migrations) <> 671 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=671 AND
        migration_id='671_system_settings_kyc_object_secrets' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 671 down requires the exact verified migration head' USING ERRCODE='P6711';
    END IF;
    IF EXISTS (
        SELECT 1 FROM platform_system_user_settings WHERE secrets_fingerprints ?| ARRAY[
            'kyc_object_access_key_id','kyc_object_secret_access_key','kyc_object_session_token']
       ) THEN
        RAISE EXCEPTION 'migration 671 rollback would drop saved KYC object store secrets' USING ERRCODE='P6712';
    END IF;
END;
$migration_671_down$;

ALTER TABLE platform_system_user_settings
    DROP CONSTRAINT platform_system_user_settings_secrets_fingerprints_671,
    ADD CONSTRAINT platform_system_user_settings_secrets_fingerprints_check CHECK (
        secrets_fingerprints IS NULL OR jsonb_typeof(secrets_fingerprints) = 'object' AND
        secrets_fingerprints <> '{}'::jsonb AND
        secrets_fingerprints - ARRAY['captcha_secret_id','captcha_secret_key','captcha_app_secret',
                                     'captcha_turnstile_secret','kyc_api_key','kyc_callback_hmac_key'] = '{}'::jsonb
    );
