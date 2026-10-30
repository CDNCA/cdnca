LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_419_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 418 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 418 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=418 AND
        migration_id='418_origin_failover' AND
        checksum_sha256='d4ed3c4729f80045e344c73b1b1ddb118b79828491efdab96ecac060eaad4bc8' AND
        down_checksum_sha256='81f58c2b98fc58dc33b1e42874b00e83edde3fb8177d97cc0ce9121fe0e04ead' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 419 requires the exact verified 418 release head' USING ERRCODE='P4190';
    END IF;
END;
$migration_419_up$;

-- 419 (r136 rule-seed-publish, number reserved by the batch ledger; the
-- head is 417 = pack-suspend, whose checksums are added on merge). The
-- official system rule packs (license migration 097: system/bot-*,
-- system/cc-404-burst, system/waf-*) are free and downloaded with the core, but a system pack without a platform row is
-- locked to the platform (rulepack.Effective), so a site owner could not
-- switch one on. A platform row is written by the control plane itself:
-- updated_by_user_id becomes nullable for system rows only, and
-- rulepackcontrol opens each official pack once (state inherit = still
-- disabled, allow_lower = tenants and their sites may enable it and change
-- its action parameter). An administrator's row is never changed.
ALTER TABLE rule_pack_enablements
    ALTER COLUMN updated_by_user_id DROP NOT NULL,
    ADD CONSTRAINT rule_pack_enablements_system_row_419 CHECK (updated_by_user_id IS NOT NULL OR
        level = 'platform' AND rule_id IS NULL AND state = 'inherit' AND allow_lower AND priority IS NULL AND params IS NULL);
