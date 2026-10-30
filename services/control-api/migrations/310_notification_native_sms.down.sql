LOCK TABLE schema_migrations, notification_outbox, platform_system_mail_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_310_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 310 OR
       (SELECT max(version) FROM schema_migrations) <> 310 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=310 AND
        migration_id='310_notification_native_sms' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 310 down requires the exact verified migration head' USING ERRCODE='P3101';
    END IF;
    -- A stored provider credential or undelivered template SMS must not be
    -- discarded silently; the operator clears the native provider first.
    IF EXISTS (SELECT 1 FROM platform_system_mail_settings WHERE sms_secret_key_id IS NOT NULL) OR
       EXISTS (SELECT 1 FROM notification_outbox
               WHERE template_params IS NOT NULL AND status IN ('pending','leased','accepted','unknown')) THEN
        RAISE EXCEPTION 'migration 310 rollback would discard native SMS credentials or pending template SMS'
            USING ERRCODE='P3101';
    END IF;
END;
$migration_310_down$;

ALTER TABLE platform_system_mail_settings
    DROP CONSTRAINT platform_system_mail_settings_sms_secret_309,
    DROP COLUMN sms_secret_fingerprint,
    DROP COLUMN sms_secret_ciphertext,
    DROP COLUMN sms_secret_key_id;

DROP TRIGGER notification_outbox_template_params_309 ON notification_outbox;
DROP FUNCTION protect_notification_outbox_template_params_309();
ALTER TABLE notification_outbox
    DROP CONSTRAINT notification_outbox_template_params_sms_309,
    DROP COLUMN template_params;
