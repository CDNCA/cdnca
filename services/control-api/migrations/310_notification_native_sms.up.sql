LOCK TABLE schema_migrations, notification_outbox, platform_system_mail_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_310_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 309 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 309 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=309 AND
        migration_id='309_node_availability_alerts' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 310 requires the exact verified 309 release head' USING ERRCODE='P3100';
    END IF;
END;
$migration_310_up$;

-- FX66: template-based SMS providers (aliyun, submail) send our template id
-- plus its variables instead of the rendered body. Only public template
-- variables are stored (sensitive context is rejected at enqueue), and only
-- for SMS rows; the payload is immutable like the rendered body.
ALTER TABLE notification_outbox
    ADD COLUMN template_params jsonb CHECK (
        template_params IS NULL OR (
            jsonb_typeof(template_params) = 'object' AND octet_length(template_params::text) <= 16384
        )
    ),
    ADD CONSTRAINT notification_outbox_template_params_sms_309 CHECK (template_params IS NULL OR channel = 'sms');

CREATE FUNCTION protect_notification_outbox_template_params_309()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.template_params IS DISTINCT FROM OLD.template_params THEN
        RAISE EXCEPTION 'notification outbox template params are immutable' USING ERRCODE='P3102';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notification_outbox_template_params_309
BEFORE UPDATE ON notification_outbox
FOR EACH ROW EXECUTE FUNCTION protect_notification_outbox_template_params_309();

REVOKE ALL ON FUNCTION protect_notification_outbox_template_params_309() FROM PUBLIC;

-- The native provider credential (AccessKeySecret / appkey) is stored as one
-- AES-GCM envelope under the control-api credential keyring; the settings
-- API only ever returns its fingerprint.
ALTER TABLE platform_system_mail_settings
    ADD COLUMN sms_secret_key_id text CHECK (sms_secret_key_id IS NULL OR char_length(sms_secret_key_id) BETWEEN 1 AND 255),
    ADD COLUMN sms_secret_ciphertext bytea CHECK (
        sms_secret_ciphertext IS NULL OR octet_length(sms_secret_ciphertext) BETWEEN 29 AND 8192
    ),
    ADD COLUMN sms_secret_fingerprint text CHECK (sms_secret_fingerprint IS NULL OR sms_secret_fingerprint ~ '^[0-9a-f]{16}$'),
    ADD CONSTRAINT platform_system_mail_settings_sms_secret_309 CHECK (
        (sms_secret_key_id IS NULL) = (sms_secret_ciphertext IS NULL) AND
        (sms_secret_key_id IS NULL) = (sms_secret_fingerprint IS NULL)
    );
