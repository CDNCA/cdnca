LOCK TABLE schema_migrations, notification_delivery_facts_108 IN ACCESS EXCLUSIVE MODE;

DO $migration_253$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 252 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 252 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=252 AND migration_id='252_identity_user_login_security'
          AND checksum_sha256='11333ecc36f8789b6783744e0f0aa18bac7aac536be88a0fa66de496b0d3a911'
          AND down_checksum_sha256='f11b93479c778cb8ce854d8e9810a74fc8372a7cc85b1a331ef031593211d16e'
          AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 253 requires the exact verified 252 head' USING ERRCODE='P2530';
    END IF;
END;
$migration_253$;

ALTER TABLE notification_delivery_facts_108
    ADD COLUMN recipient_address_masked text,
    ADD COLUMN provider_call_started_at timestamptz,
    ADD CONSTRAINT notification_dispatch_observation_253 CHECK (
        (recipient_address_masked IS NULL OR (
            provider_call_started_at IS NOT NULL AND char_length(recipient_address_masked) <= 254 AND
            recipient_address_masked ~ '^([A-Za-z0-9]?\*\*\*@[A-Za-z0-9.-]+|\*\*\*[0-9]{4})$'
        )) AND
        (provider_call_started_at IS NULL OR (
            isfinite(provider_call_started_at) AND attempt_number > 0 AND fact_kind IN (
                'provider_accepted','provider_unknown','provider_delivered',
                'retry_scheduled','permanent_failed','exhausted'
            )
        ))
    );
