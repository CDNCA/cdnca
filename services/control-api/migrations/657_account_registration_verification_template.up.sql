LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

-- The built-in registration (no Turnstile runtime) sends
-- its email / SMS verification code with this default template; a template
-- the platform publishes for platform_user_registration_verification still
-- takes precedence. The code is appended by the sender, as for 197.
DO $migration_657$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 656 OR
       (SELECT max(version) FROM schema_migrations) <> 656 OR
       EXISTS (SELECT 1 FROM notification_templates WHERE template_id='account_registration_verification') THEN
        RAISE EXCEPTION 'migration 657 requires the exact verified 656 release head' USING ERRCODE='P6570';
    END IF;
END;
$migration_657$;

INSERT INTO notification_templates(template_id,version,channel,subject,body,variables,created_at) VALUES
    ('account_registration_verification',1,'email','注册验证码','请使用以下验证码完成注册：',ARRAY[]::text[],clock_timestamp()),
    ('account_registration_verification',1,'sms','','您的注册验证码为：',ARRAY[]::text[],clock_timestamp());
