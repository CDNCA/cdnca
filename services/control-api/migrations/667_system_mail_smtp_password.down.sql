-- 667 回退：删掉系统设置页保存的 SMTP 密码列；已保存密码时拒绝（回退会让 SMTP 发信静默失去密码）。
LOCK TABLE schema_migrations, platform_system_mail_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_667_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 667 OR
       (SELECT max(version) FROM schema_migrations) <> 667 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=667 AND
        migration_id='667_system_mail_smtp_password' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 667 down requires the exact verified migration head' USING ERRCODE='P6671';
    END IF;
    IF EXISTS (SELECT 1 FROM platform_system_mail_settings WHERE smtp_password_key_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 667 rollback would drop the saved SMTP password' USING ERRCODE='P6672';
    END IF;
END;
$migration_667_down$;

ALTER TABLE platform_system_mail_settings
    DROP CONSTRAINT platform_system_mail_settings_smtp_password_667,
    DROP COLUMN smtp_password_fingerprint,
    DROP COLUMN smtp_password_ciphertext,
    DROP COLUMN smtp_password_key_id;
