-- 667（系统设置页 SMTP 密码加密保存，修复填真实密码提示格式不正确）；前驱 666_tenant_members_restore。
-- 系统设置页直接填写的 SMTP 密码：与 455 官方邮件服务凭据相同，用 control-api 凭据钥匙串做一个 AES-GCM
-- 信封（绑定平台 scope），接口只返回是否已配置与指纹。settings.smtp_password_reference 继续作为高级用法保留，
-- 同一行两者不同时存在（由服务层保证）。
-- 同批新增的 SMTP 发件地址/发件人名称（smtp_from、smtp_from_name）存在 settings jsonb 里，不改表；
-- 回退到 666 后旧代码解码时忽略这两个键。
LOCK TABLE schema_migrations, platform_system_mail_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_667_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 666 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 666 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=666 AND
        migration_id='666_tenant_members_restore' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='platform_system_mail_settings' AND column_name='smtp_password_key_id'
       ) THEN
        RAISE EXCEPTION 'migration 667 requires the exact verified 666 release head' USING ERRCODE='P6670';
    END IF;
END;
$migration_667_up$;

ALTER TABLE platform_system_mail_settings
    ADD COLUMN smtp_password_key_id text CHECK (smtp_password_key_id IS NULL OR char_length(smtp_password_key_id) BETWEEN 1 AND 255),
    ADD COLUMN smtp_password_ciphertext bytea CHECK (
        smtp_password_ciphertext IS NULL OR octet_length(smtp_password_ciphertext) BETWEEN 29 AND 8192
    ),
    ADD COLUMN smtp_password_fingerprint text CHECK (smtp_password_fingerprint IS NULL OR smtp_password_fingerprint ~ '^[0-9a-f]{16}$'),
    ADD CONSTRAINT platform_system_mail_settings_smtp_password_667 CHECK (
        (smtp_password_key_id IS NULL) = (smtp_password_ciphertext IS NULL) AND
        (smtp_password_key_id IS NULL) = (smtp_password_fingerprint IS NULL)
    );
