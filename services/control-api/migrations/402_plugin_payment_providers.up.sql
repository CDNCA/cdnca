LOCK TABLE schema_migrations, payment_channels, plugin_providers IN ACCESS EXCLUSIVE MODE;

DO $migration_402_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 401 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 401 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=401 AND
        migration_id='401_node_market_probe_role' AND
        checksum_sha256='942285d0f81c261d36056e8cc84c4545554bbd062c229f9038ab68d14a26efce' AND
        down_checksum_sha256='dbb2e5d211afb1e0156bfa3d6ed8f52e0c829e8239c66979f743addfd85140cb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.plugin_providers') IS NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='plugin_providers' AND column_name='payment_confirmed_at'
       ) THEN
        RAISE EXCEPTION 'migration 402 requires the exact verified 401 release head' USING ERRCODE='P4020';
    END IF;
END;
$migration_402_up$;

-- 402（r136 pa23-payment，合入时接在 397_plugin_providers 之后）。
-- PA-23 (ADR 0007 §8.2): a third-party payment provider plugin. Its
-- declaration may provide kind payment; it becomes a collection channel
-- (payment_channels.provider = 'plugin', config {plugin_id, merchant_id}).
-- Payment is a high-risk permission: an administrator enables such a plugin
-- only with a fresh MFA step-up and an explicit acknowledgement of the risk
-- notice (payment_confirmed_*); the trigger refuses enabling a payment
-- provider without them. Every fact the plugin reports is only a claim:
-- control-api binds it to its own order and confirms it with the plugin's
-- query before crediting (paymentchannel).
ALTER TABLE plugin_providers DROP CONSTRAINT plugin_providers_kinds_check;
ALTER TABLE plugin_providers ADD CONSTRAINT plugin_providers_kinds_check
    CHECK (cardinality(kinds) BETWEEN 1 AND 4 AND kinds <@ ARRAY['dns', 'icp', 'payment', 'sms']::text[]);
ALTER TABLE plugin_providers
    ADD COLUMN payment_confirmed_by_user_id uuid,
    ADD COLUMN payment_confirmed_at timestamptz,
    ADD COLUMN payment_step_up_proof_id uuid,
    ADD CONSTRAINT plugin_providers_payment_confirmation_402 CHECK (
        (payment_confirmed_at IS NULL) = (payment_confirmed_by_user_id IS NULL) AND
        (payment_confirmed_at IS NULL) = (payment_step_up_proof_id IS NULL));

-- Enabling a payment provider needs the high-risk confirmation recorded in
-- the same write with a step-up proof not used before on this row. New
-- declaration bytes (an upgrade may point at another service) turn a
-- payment provider off and drop its confirmation: the administrator
-- confirms the new version again after its contract passed.
CREATE FUNCTION plugin_providers_payment_gate_402() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.declaration_sha256 IS DISTINCT FROM OLD.declaration_sha256 AND
       ('payment' = ANY(NEW.kinds) OR 'payment' = ANY(OLD.kinds)) THEN
        NEW.enabled := false;
    END IF;
    IF NOT NEW.enabled THEN
        NEW.payment_confirmed_by_user_id := NULL;
        NEW.payment_confirmed_at := NULL;
        NEW.payment_step_up_proof_id := NULL;
        RETURN NEW;
    END IF;
    IF NEW.enabled AND 'payment' = ANY(NEW.kinds) AND (TG_OP = 'INSERT' OR NOT OLD.enabled) AND (
        NEW.payment_confirmed_at IS NULL OR NEW.payment_confirmed_by_user_id IS DISTINCT FROM NEW.enabled_by_user_id OR
        NEW.payment_confirmed_at IS DISTINCT FROM NEW.enabled_at OR
        (TG_OP = 'UPDATE' AND NEW.payment_step_up_proof_id IS NOT DISTINCT FROM OLD.payment_step_up_proof_id)) THEN
        RAISE EXCEPTION 'payment provider plugin % needs a high-risk confirmation to be enabled', NEW.plugin_id
            USING ERRCODE = 'P4021';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER plugin_providers_payment_gate_402 BEFORE INSERT OR UPDATE ON plugin_providers
    FOR EACH ROW EXECUTE FUNCTION plugin_providers_payment_gate_402();

ALTER TABLE payment_channels DROP CONSTRAINT payment_channels_provider_check;
ALTER TABLE payment_channels ADD CONSTRAINT payment_channels_provider_check
    CHECK (provider IN ('alipay_official', 'wechat_official', 'epay', 'codepay', 'crypto', 'plugin'));
-- A plugin channel holds no credentials (the plugin keeps them), so the
-- 298 "enabled needs sealed secrets" rule exempts it; the unnamed 298 check
-- is found by its definition.
DO $migration_402_secrets$
DECLARE
    found text;
BEGIN
    SELECT conname INTO found FROM pg_constraint
    WHERE conrelid = 'payment_channels'::regclass AND contype = 'c' AND
        pg_get_constraintdef(oid) = 'CHECK (((NOT enabled) OR (secret_key_id IS NOT NULL)))';
    IF found IS NULL THEN
        RAISE EXCEPTION 'migration 402: payment_channels secret check not found' USING ERRCODE='P4024';
    END IF;
    EXECUTE format('ALTER TABLE payment_channels DROP CONSTRAINT %I', found);
END;
$migration_402_secrets$;
ALTER TABLE payment_channels ADD CONSTRAINT payment_channels_enabled_secrets_402
    CHECK (NOT enabled OR provider = 'plugin' OR secret_key_id IS NOT NULL);
-- A plugin channel names its plugin (and the merchant it collects into).
ALTER TABLE payment_channels ADD CONSTRAINT payment_channels_plugin_config_402 CHECK (
    provider <> 'plugin' OR (coalesce(config->>'plugin_id', '') ~ '^[a-z0-9]+([.-][a-z0-9]+)+$' AND
        char_length(config->>'plugin_id') BETWEEN 3 AND 128 AND
        coalesce(config->>'merchant_id', '') ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'));
