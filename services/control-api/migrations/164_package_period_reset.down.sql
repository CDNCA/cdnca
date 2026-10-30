LOCK TABLE schema_migrations,package_period_reset_recovery_outbox_164,
    package_period_reset_facts_164,package_period_reset_claims_164 IN ACCESS EXCLUSIVE MODE;

DO $migration_164$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>164 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>164 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=164 AND migration_id='164_package_period_reset' AND
              checksum_sha256='79f38f20d69e4d2e922b77263bfb5b86a242c117f8c19afd38bf37104401dd60' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=163 AND migration_id='163_account_registration_challenge' AND
              checksum_sha256='a3fb276eb890cfcb8e526c3b1b7539d5b970d35c4e465422184308e0d0c9d799' AND
              down_checksum_sha256='b3dfc2d6f8b8e04dc41e9d7b04349306d9345f5fcb7d1d1156e3a7f15f075dc8' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 164 rollback requires the exact verified 164 head'
            USING ERRCODE='P1640';
    END IF;
    IF EXISTS(SELECT 1 FROM package_period_reset_recovery_outbox_164) OR
       EXISTS(SELECT 1 FROM package_period_reset_facts_164) OR
       EXISTS(SELECT 1 FROM package_period_reset_claims_164) THEN
        RAISE EXCEPTION 'migration 164 rollback would discard package period reset facts'
            USING ERRCODE='P1644';
    END IF;
END;
$migration_164$;

DROP TRIGGER package_period_reset_outbox_no_truncate_164 ON package_period_reset_recovery_outbox_164;
DROP TRIGGER package_period_reset_outbox_immutable_164 ON package_period_reset_recovery_outbox_164;
DROP TRIGGER package_period_reset_fact_no_truncate_164 ON package_period_reset_facts_164;
DROP TRIGGER package_period_reset_fact_immutable_164 ON package_period_reset_facts_164;
DROP TRIGGER package_period_reset_claim_no_truncate_164 ON package_period_reset_claims_164;
DROP TRIGGER package_period_reset_claim_guard_164 ON package_period_reset_claims_164;
DROP FUNCTION prevent_package_period_reset_fact_mutation_164();
DROP FUNCTION guard_package_period_reset_claim_164();
DROP FUNCTION package_period_reset_claim_single_winner_164(
    uuid,text,uuid,timestamptz,interval,bytea,bigint,bigint
);
DROP TABLE package_period_reset_recovery_outbox_164;
DROP TABLE package_period_reset_facts_164;
DROP TABLE package_period_reset_claims_164;
