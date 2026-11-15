-- 671（实名认证服务其余配置页面可配）；前驱 670_security_activation_recovery_attempts。
-- 实名认证服务（KYC）其余配置在「系统配置 → 认证与支付」页面可配：服务名、服务端点、回调密钥 ID 与私有对象存储
-- 端点/区域/桶/前缀/KMS 密钥 ID 存进 platform_system_user_settings.settings（jsonb，不改表）；对象存储
-- Access Key ID / Secret Access Key / Session Token 与 668 的 KYC 两把密钥同样进页面密钥信封（明文只写、AES-GCM、
-- 只回是否已设置与指纹）。本迁移只把这三个名字加进 secrets_fingerprints 允许的键。
-- 页面没填的项运行时回退 IDENTITY_VERIFICATION_*。
LOCK TABLE schema_migrations, platform_system_user_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_671_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 670 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 670 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=670 AND
        migration_id='670_security_activation_recovery_attempts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='platform_system_user_settings'::regclass AND
        conname='platform_system_user_settings_secrets_fingerprints_check'
       ) OR EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='platform_system_user_settings'::regclass AND
        conname='platform_system_user_settings_secrets_fingerprints_671'
       ) THEN
        RAISE EXCEPTION 'migration 671 requires the exact verified 670 release head' USING ERRCODE='P6710';
    END IF;
END;
$migration_671_up$;

ALTER TABLE platform_system_user_settings
    DROP CONSTRAINT platform_system_user_settings_secrets_fingerprints_check,
    ADD CONSTRAINT platform_system_user_settings_secrets_fingerprints_671 CHECK (
        secrets_fingerprints IS NULL OR jsonb_typeof(secrets_fingerprints) = 'object' AND
        secrets_fingerprints <> '{}'::jsonb AND
        secrets_fingerprints - ARRAY['captcha_secret_id','captcha_secret_key','captcha_app_secret',
                                     'captcha_turnstile_secret','kyc_api_key','kyc_callback_hmac_key',
                                     'kyc_object_access_key_id','kyc_object_secret_access_key',
                                     'kyc_object_session_token'] = '{}'::jsonb
    );
