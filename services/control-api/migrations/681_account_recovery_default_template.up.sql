LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

-- 找回密码运行时启动时要求 ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID 引用一条
-- 无变量的默认模板（与 197 登录、659 注册同一做法）；重置链接由发送方附在正文后。
-- 平台在系统配置里发布的 platform_user_account_recovery（带 username）仍优先。
DO $migration_681$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 680 OR
       (SELECT max(version) FROM schema_migrations) <> 680 OR
       EXISTS (SELECT 1 FROM notification_templates WHERE template_id='account_recovery_email') THEN
        RAISE EXCEPTION 'migration 681 requires the exact verified 680 release head' USING ERRCODE='P6810';
    END IF;
END;
$migration_681$;

INSERT INTO notification_templates(template_id,version,channel,subject,body,variables,created_at) VALUES
    ('account_recovery_email',1,'email','找回密码','你正在找回账号密码。请在有效期内打开以下链接设置新密码；如果不是你本人操作，请忽略本邮件：',ARRAY[]::text[],clock_timestamp());
