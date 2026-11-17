-- 673（实名认证证据签发端私钥进页面密钥信封）；前驱 672_upgrade_plan_schema_v3。
-- 实名认证证据签发端（mTLS issuer）在「系统配置 → 认证与支付 → 实名认证」页面可配：启用、监听地址、服务端证书链 PEM、
-- 客户端 CA PEM、工作负载身份、KMS 端点存进 platform_system_user_settings.settings（jsonb，不改表）；服务端私钥 PEM
-- 进页面密钥信封（668，明文只写、AES-GCM、只回是否已设置与指纹）。页面没填的项运行时回退 IDENTITY_VERIFICATION_ISSUER_*。
-- 本迁移：1) secrets_fingerprints 允许的键加入 kyc_issuer_server_private_key；
--         2) secrets_ciphertext 上限 16384 → 32768（私钥 PEM 最长 8192，与其余密钥同存一个信封时最坏情况超过原上限）。
LOCK TABLE schema_migrations, platform_system_user_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_673_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 672 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 672 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=672 AND
        migration_id='672_upgrade_plan_schema_v3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='platform_system_user_settings'::regclass AND
        conname='platform_system_user_settings_secrets_fingerprints_671'
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='platform_system_user_settings'::regclass AND
        conname='platform_system_user_settings_secrets_ciphertext_check'
       ) OR EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='platform_system_user_settings'::regclass AND
        conname IN ('platform_system_user_settings_secrets_fingerprints_673',
                    'platform_system_user_settings_secrets_ciphertext_673')
       ) THEN
        RAISE EXCEPTION 'migration 673 requires the exact verified 672 release head' USING ERRCODE='P6730';
    END IF;
END;
$migration_673_up$;

ALTER TABLE platform_system_user_settings
    DROP CONSTRAINT platform_system_user_settings_secrets_fingerprints_671,
    ADD CONSTRAINT platform_system_user_settings_secrets_fingerprints_673 CHECK (
        secrets_fingerprints IS NULL OR jsonb_typeof(secrets_fingerprints) = 'object' AND
        secrets_fingerprints <> '{}'::jsonb AND
        secrets_fingerprints - ARRAY['captcha_secret_id','captcha_secret_key','captcha_app_secret',
                                     'captcha_turnstile_secret','kyc_api_key','kyc_callback_hmac_key',
                                     'kyc_object_access_key_id','kyc_object_secret_access_key',
                                     'kyc_object_session_token','kyc_issuer_server_private_key'] = '{}'::jsonb
    ),
    DROP CONSTRAINT platform_system_user_settings_secrets_ciphertext_check,
    ADD CONSTRAINT platform_system_user_settings_secrets_ciphertext_673 CHECK (
        secrets_ciphertext IS NULL OR octet_length(secrets_ciphertext) BETWEEN 29 AND 32768
    );
