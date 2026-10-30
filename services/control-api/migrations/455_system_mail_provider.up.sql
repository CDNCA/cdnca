LOCK TABLE schema_migrations, platform_system_mail_settings, plugin_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_455_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 454 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 454 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=454 AND
        migration_id='454_official_rule_pack_default_on' AND
        checksum_sha256='69639d5375f465a4ab62f6152896b12a9fbbc7f7ee6ab43bc7d01b75e1364417' AND
        down_checksum_sha256='e70c492069624cabba009b0841025dedd6ca8a3ed304499d29b02c545aecc063' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='platform_system_mail_settings' AND column_name='mail_secret_key_id'
       ) THEN
        RAISE EXCEPTION 'migration 455 requires the exact verified 454 release head' USING ERRCODE='P4550';
    END IF;
END;
$migration_455_up$;

-- 455 (r136 mail-plugin; placeholder number, renumbered on merge). The system
-- mail sender: settings.mail_provider picks exactly one of the built-in SMTP
-- ("" / absent, unchanged), an official mail service (aliyun DirectMail,
-- sendgrid) or a third-party mail plugin (plugin:<plugin id>). The SMTP fields
-- stay in settings whatever is chosen, so switching back needs no re-entry.
-- An official service's credential (AccessKeySecret / API key) is one AES-GCM
-- envelope under the control-api credential keyring, bound to the provider it
-- was entered for; the settings API only ever returns its fingerprint.
ALTER TABLE platform_system_mail_settings
    ADD COLUMN mail_secret_key_id text CHECK (mail_secret_key_id IS NULL OR char_length(mail_secret_key_id) BETWEEN 1 AND 255),
    ADD COLUMN mail_secret_ciphertext bytea CHECK (
        mail_secret_ciphertext IS NULL OR octet_length(mail_secret_ciphertext) BETWEEN 29 AND 8192
    ),
    ADD COLUMN mail_secret_fingerprint text CHECK (mail_secret_fingerprint IS NULL OR mail_secret_fingerprint ~ '^[0-9a-f]{16}$'),
    ADD COLUMN mail_secret_provider text CHECK (mail_secret_provider IS NULL OR mail_secret_provider IN ('aliyun', 'sendgrid')),
    ADD CONSTRAINT platform_system_mail_settings_mail_secret_455 CHECK (
        (mail_secret_key_id IS NULL) = (mail_secret_ciphertext IS NULL) AND
        (mail_secret_key_id IS NULL) = (mail_secret_fingerprint IS NULL) AND
        (mail_secret_key_id IS NULL) = (mail_secret_provider IS NULL)
    );

-- Third-party plugins may provide kind mail (cdnca.provider/v1 mail send/health).
ALTER TABLE plugin_providers DROP CONSTRAINT plugin_providers_kinds_check;
ALTER TABLE plugin_providers ADD CONSTRAINT plugin_providers_kinds_check
    CHECK (cardinality(kinds) BETWEEN 1 AND 5 AND kinds <@ ARRAY['dns', 'icp', 'mail', 'payment', 'sms']::text[]);
