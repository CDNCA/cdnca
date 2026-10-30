LOCK TABLE schema_migrations,account_registration_proofs_162 IN ACCESS EXCLUSIVE MODE;

DO $migration_162$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>162 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>162 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=162 AND migration_id='162_account_registration_proof' AND
              checksum_sha256='41cae1972e4772c40b983b40def090b06e2abd741fc2265a894a9c91b097acde' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=161 AND migration_id='161_recharge_identity_eligibility' AND
              checksum_sha256='67edc7f614f05c0bd69551ae43d9b52bdd7e0a4b1c16c655adb76aa0a5bba4d6' AND
              down_checksum_sha256='8043517489d8adffe1023313c89730c459284252c647c4ba838c3b897087236d' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 162 rollback requires the exact verified 162 head'
            USING ERRCODE='P1620';
    END IF;
    IF EXISTS(SELECT 1 FROM account_registration_proofs_162) THEN
        RAISE EXCEPTION 'migration 162 rollback would discard account registration proof facts'
            USING ERRCODE='P1621';
    END IF;
END;
$migration_162$;

DROP TABLE account_registration_proofs_162;
