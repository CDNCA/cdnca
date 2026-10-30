LOCK TABLE schema_migrations, security_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_405_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 404 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 404 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=404 AND
        migration_id='404_payment_plugin_reconciliation' AND
        checksum_sha256='83d1db6e59f5da39d7bb99692fb1b144a7566d1b61c351c9024d07e5617d075c' AND
        down_checksum_sha256='d3a99945f04d709752864554794211e6ab7e6527154c12d4caf503713391e2f2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='security_policies' AND column_name='waf_settings'
       ) THEN
        RAISE EXCEPTION 'migration 405 requires the exact verified 404 release head' USING ERRCODE='P4050';
    END IF;
END;
$migration_405_up$;

-- ge-waf (GoEdge parity G1): a WAF policy's policy-level settings
-- (securitypolicy.WAFSettings) - observe mode (every decision recorded as log,
-- nothing enforced) and auto block (ban a client after repeated block /
-- challenge decisions). NULL is defend mode without auto block. The policy
-- version documents carry the same object.
ALTER TABLE security_policies
    ADD COLUMN waf_settings jsonb,
    ADD CONSTRAINT security_policies_waf_settings_405
        CHECK (waf_settings IS NULL OR kind = 'waf' AND jsonb_typeof(waf_settings) = 'object');
