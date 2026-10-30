LOCK TABLE schema_migrations, domain_ownerships IN ACCESS EXCLUSIVE MODE;

DO $migration_322_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 321 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 321 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=321 AND
        migration_id='321_node_availability_alert_states' AND
        checksum_sha256='acd73fe79225092cea6a792821943581292c8c5a566aee452749c0b111546117' AND
        down_checksum_sha256='52135be11ac5e4570e63da1ec438295b29e528df73842915be486982e412f99c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.domain_ownerships') IS NULL OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='domain_ownerships' AND column_name='next_check_at') THEN
        RAISE EXCEPTION 'migration 322 requires the exact verified 321 release head' USING ERRCODE='P3220';
    END IF;
END;
$migration_322_up$;

-- User decision 10-17: a domain ownership proof stays valid once verified.
-- The 30-day recheck, its failure counter and the expiry it led to are gone;
-- only a platform administrator's revoke (or a DNS TXT proof superseding an
-- HTTP file proof) ends a verified proof. Proofs a recheck had expired stay
-- expired; their owner verifies again.
DROP INDEX domain_ownerships_due_299_idx;
ALTER TABLE domain_ownerships DROP COLUMN next_check_at, DROP COLUMN consecutive_failures;
ALTER TABLE domain_ownerships ADD CONSTRAINT domain_ownerships_verified_at_322
    CHECK (status <> 'verified' OR verified_at IS NOT NULL);
