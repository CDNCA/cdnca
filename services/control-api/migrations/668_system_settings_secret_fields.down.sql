-- 668 回退：删掉系统设置页保存的人机验证密钥、实名认证服务凭据与 HTTPS 短信网关令牌列；已保存时拒绝
-- （回退会让人机验证、短信发送静默失去密钥）。
LOCK TABLE schema_migrations, platform_system_user_settings, platform_system_mail_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_668_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 668 OR
       (SELECT max(version) FROM schema_migrations) <> 668 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=668 AND
        migration_id='668_system_settings_secret_fields' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 668 down requires the exact verified migration head' USING ERRCODE='P6681';
    END IF;
    IF EXISTS (SELECT 1 FROM platform_system_user_settings WHERE secrets_key_id IS NOT NULL) OR
       EXISTS (SELECT 1 FROM platform_system_mail_settings WHERE sms_auth_token_key_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 668 rollback would drop saved settings page secrets' USING ERRCODE='P6682';
    END IF;
END;
$migration_668_down$;

ALTER TABLE platform_system_mail_settings
    DROP CONSTRAINT platform_system_mail_settings_sms_auth_token_668,
    DROP COLUMN sms_auth_token_fingerprint,
    DROP COLUMN sms_auth_token_ciphertext,
    DROP COLUMN sms_auth_token_key_id;

ALTER TABLE platform_system_user_settings
    DROP CONSTRAINT platform_system_user_settings_secrets_668,
    DROP COLUMN secrets_fingerprints,
    DROP COLUMN secrets_ciphertext,
    DROP COLUMN secrets_key_id;
