-- 673 回退：secrets_fingerprints 允许的键回到 671 的九个，secrets_ciphertext 上限回到 16384。页面已保存签发端私钥时拒绝
-- （回退会让已存密钥违反约束；先在页面清空该项再回退）；信封超过 16384 字节同样拒绝。settings jsonb 里的 kyc_issuer_*
-- 普通字段保留，旧代码读取时忽略未知键。
LOCK TABLE schema_migrations, platform_system_user_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_673_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 673 OR
       (SELECT max(version) FROM schema_migrations) <> 673 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=673 AND
        migration_id='673_system_settings_kyc_issuer_key' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 673 down requires the exact verified migration head' USING ERRCODE='P6731';
    END IF;
    IF EXISTS (
        SELECT 1 FROM platform_system_user_settings WHERE secrets_fingerprints ? 'kyc_issuer_server_private_key' OR
            octet_length(secrets_ciphertext) > 16384
       ) THEN
        RAISE EXCEPTION 'migration 673 rollback would drop the saved KYC evidence issuer private key' USING ERRCODE='P6732';
    END IF;
END;
$migration_673_down$;

ALTER TABLE platform_system_user_settings
    DROP CONSTRAINT platform_system_user_settings_secrets_ciphertext_673,
    ADD CONSTRAINT platform_system_user_settings_secrets_ciphertext_check CHECK (
        secrets_ciphertext IS NULL OR octet_length(secrets_ciphertext) BETWEEN 29 AND 16384
    ),
    DROP CONSTRAINT platform_system_user_settings_secrets_fingerprints_673,
    ADD CONSTRAINT platform_system_user_settings_secrets_fingerprints_671 CHECK (
        secrets_fingerprints IS NULL OR jsonb_typeof(secrets_fingerprints) = 'object' AND
        secrets_fingerprints <> '{}'::jsonb AND
        secrets_fingerprints - ARRAY['captcha_secret_id','captcha_secret_key','captcha_app_secret',
                                     'captcha_turnstile_secret','kyc_api_key','kyc_callback_hmac_key',
                                     'kyc_object_access_key_id','kyc_object_secret_access_key',
                                     'kyc_object_session_token'] = '{}'::jsonb
    );
