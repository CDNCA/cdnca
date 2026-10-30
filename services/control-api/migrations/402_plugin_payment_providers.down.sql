LOCK TABLE schema_migrations, payment_channels, plugin_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_402_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 402 OR
       (SELECT max(version) FROM schema_migrations) <> 402 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=402 AND
        migration_id='402_plugin_payment_providers' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 402 down requires the exact verified migration head' USING ERRCODE='P4022';
    END IF;
    IF EXISTS (SELECT 1 FROM payment_channels WHERE provider = 'plugin') OR
       EXISTS (SELECT 1 FROM plugin_providers WHERE 'payment' = ANY(kinds)) THEN
        RAISE EXCEPTION 'migration 402 rollback would drop payment provider plugins in use' USING ERRCODE='P4023';
    END IF;
END;
$migration_402_down$;

ALTER TABLE payment_channels DROP CONSTRAINT payment_channels_plugin_config_402;
ALTER TABLE payment_channels DROP CONSTRAINT payment_channels_enabled_secrets_402;
ALTER TABLE payment_channels ADD CHECK (NOT enabled OR secret_key_id IS NOT NULL);
ALTER TABLE payment_channels DROP CONSTRAINT payment_channels_provider_check;
ALTER TABLE payment_channels ADD CONSTRAINT payment_channels_provider_check
    CHECK (provider IN ('alipay_official', 'wechat_official', 'epay', 'codepay', 'crypto'));
DROP TRIGGER plugin_providers_payment_gate_402 ON plugin_providers;
DROP FUNCTION plugin_providers_payment_gate_402();
ALTER TABLE plugin_providers DROP CONSTRAINT plugin_providers_payment_confirmation_402,
    DROP COLUMN payment_step_up_proof_id, DROP COLUMN payment_confirmed_at, DROP COLUMN payment_confirmed_by_user_id;
ALTER TABLE plugin_providers DROP CONSTRAINT plugin_providers_kinds_check;
ALTER TABLE plugin_providers ADD CONSTRAINT plugin_providers_kinds_check
    CHECK (cardinality(kinds) BETWEEN 1 AND 3 AND kinds <@ ARRAY['dns', 'icp', 'sms']::text[]);
