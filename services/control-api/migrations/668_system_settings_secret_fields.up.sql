-- 668（系统设置页直接填写的密钥改为加密保存）；前驱 667_system_mail_smtp_password。
-- 系统设置页直接填写的密钥，与 667 SMTP 密码相同：用 control-api 凭据钥匙串做 AES-GCM 信封（绑定平台 scope，
-- 各类独立域前缀），接口只返回是否已配置与指纹；原 *_reference 继续作为高级用法保留，同一密钥两者不同时存在
-- （由服务层保证）。
-- 1) platform_system_user_settings：人机验证 SecretId/SecretKey/AppSecretKey、注册用 Turnstile Secret 与实名认证服务（KYC）的 API Key、
--    回调签名密钥合为一个信封（JSON 对象），secrets_fingerprints 记每个已存密钥的指纹（键即字段名）。
--    KYC 两项存了就替换 IDENTITY_VERIFICATION_KYC_API_KEY / _CALLBACK_HMAC_BASE64，否则沿用环境变量。
--    认证方式/企业认证开关是否生效由 settings jsonb 里的 identity_policy_saved 标记（不改表；回退到 667 后旧代码忽略该键）。
-- 2) platform_system_mail_settings：HTTPS 短信网关（https_json）的令牌，运行时替换 NOTIFICATION_SMS_AUTH_TOKEN。
LOCK TABLE schema_migrations, platform_system_user_settings, platform_system_mail_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_668_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 667 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 667 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=667 AND
        migration_id='667_system_mail_smtp_password' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND (
            table_name='platform_system_user_settings' AND column_name='secrets_key_id' OR
            table_name='platform_system_mail_settings' AND column_name='sms_auth_token_key_id')
       ) THEN
        RAISE EXCEPTION 'migration 668 requires the exact verified 667 release head' USING ERRCODE='P6680';
    END IF;
END;
$migration_668_up$;

ALTER TABLE platform_system_user_settings
    ADD COLUMN secrets_key_id text CHECK (secrets_key_id IS NULL OR char_length(secrets_key_id) BETWEEN 1 AND 255),
    ADD COLUMN secrets_ciphertext bytea CHECK (
        secrets_ciphertext IS NULL OR octet_length(secrets_ciphertext) BETWEEN 29 AND 16384
    ),
    ADD COLUMN secrets_fingerprints jsonb CHECK (
        secrets_fingerprints IS NULL OR jsonb_typeof(secrets_fingerprints) = 'object' AND
        secrets_fingerprints <> '{}'::jsonb AND
        secrets_fingerprints - ARRAY['captcha_secret_id','captcha_secret_key','captcha_app_secret',
                                     'captcha_turnstile_secret','kyc_api_key','kyc_callback_hmac_key'] = '{}'::jsonb
    ),
    ADD CONSTRAINT platform_system_user_settings_secrets_668 CHECK (
        (secrets_key_id IS NULL) = (secrets_ciphertext IS NULL) AND
        (secrets_key_id IS NULL) = (secrets_fingerprints IS NULL)
    );

ALTER TABLE platform_system_mail_settings
    ADD COLUMN sms_auth_token_key_id text CHECK (sms_auth_token_key_id IS NULL OR char_length(sms_auth_token_key_id) BETWEEN 1 AND 255),
    ADD COLUMN sms_auth_token_ciphertext bytea CHECK (
        sms_auth_token_ciphertext IS NULL OR octet_length(sms_auth_token_ciphertext) BETWEEN 29 AND 8192
    ),
    ADD COLUMN sms_auth_token_fingerprint text CHECK (sms_auth_token_fingerprint IS NULL OR sms_auth_token_fingerprint ~ '^[0-9a-f]{16}$'),
    ADD CONSTRAINT platform_system_mail_settings_sms_auth_token_668 CHECK (
        (sms_auth_token_key_id IS NULL) = (sms_auth_token_ciphertext IS NULL) AND
        (sms_auth_token_key_id IS NULL) = (sms_auth_token_fingerprint IS NULL)
    );
