LOCK TABLE schema_migrations, platform_system_mail_settings, plugin_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_455_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 455 OR
       (SELECT max(version) FROM schema_migrations) <> 455 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=455 AND
        migration_id='455_system_mail_provider' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 455 down requires the exact verified migration head' USING ERRCODE='P4551';
    END IF;
    -- Rolling back would silently move system mail back to SMTP or drop a
    -- mail plugin: refuse while either is in use.
    IF EXISTS (SELECT 1 FROM platform_system_mail_settings
               WHERE mail_secret_key_id IS NOT NULL OR coalesce(settings->>'mail_provider', '') <> '') OR
       EXISTS (SELECT 1 FROM plugin_providers WHERE 'mail' = ANY(kinds)) THEN
        RAISE EXCEPTION 'migration 455 rollback would drop the chosen system mail provider' USING ERRCODE='P4552';
    END IF;
END;
$migration_455_down$;

ALTER TABLE plugin_providers DROP CONSTRAINT plugin_providers_kinds_check;
ALTER TABLE plugin_providers ADD CONSTRAINT plugin_providers_kinds_check
    CHECK (cardinality(kinds) BETWEEN 1 AND 4 AND kinds <@ ARRAY['dns', 'icp', 'payment', 'sms']::text[]);

ALTER TABLE platform_system_mail_settings
    DROP CONSTRAINT platform_system_mail_settings_mail_secret_455,
    DROP COLUMN mail_secret_provider,
    DROP COLUMN mail_secret_fingerprint,
    DROP COLUMN mail_secret_ciphertext,
    DROP COLUMN mail_secret_key_id;
