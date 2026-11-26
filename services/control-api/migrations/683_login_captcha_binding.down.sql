-- 683 回滚：去掉图形验证码的浏览器绑定摘要。682 及更早版本按来源 IP 消费，回滚后仍未过期的图形码
-- 照旧可按来源 IP 使用。
LOCK TABLE schema_migrations, identity_login_captchas IN ACCESS EXCLUSIVE MODE;

DO $migration_683_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 683 OR
       (SELECT max(version) FROM schema_migrations) <> 683 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=683 AND
        migration_id='683_login_captcha_binding' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 683 down requires the exact verified migration head' USING ERRCODE='P6831';
    END IF;
END;
$migration_683_down$;

ALTER TABLE identity_login_captchas
    DROP CONSTRAINT identity_login_captchas_binding_683_check,
    DROP COLUMN binding_digest;
