LOCK TABLE schema_migrations,account_registration_challenge_dispatch_claims_163,
    account_registration_challenge_verify_receipts_163,account_registration_challenges_163,
    account_registration_challenge_writes_163 IN ACCESS EXCLUSIVE MODE;

DO $migration_163$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>163 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>163 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=163 AND migration_id='163_account_registration_challenge' AND
              checksum_sha256='a3fb276eb890cfcb8e526c3b1b7539d5b970d35c4e465422184308e0d0c9d799' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=162 AND migration_id='162_account_registration_proof' AND
              checksum_sha256='41cae1972e4772c40b983b40def090b06e2abd741fc2265a894a9c91b097acde' AND
              down_checksum_sha256='581d71f285f6e2fbbcc60e4bbad675618def5eaadb5f2ac63e0b8898c0c8e830' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 163 rollback requires the exact verified 163 head'
            USING ERRCODE='P1630';
    END IF;
    IF EXISTS(SELECT 1 FROM account_registration_challenge_dispatch_claims_163) OR
       EXISTS(SELECT 1 FROM account_registration_challenge_verify_receipts_163) OR
       EXISTS(SELECT 1 FROM account_registration_challenges_163) OR
       EXISTS(SELECT 1 FROM account_registration_challenge_writes_163) THEN
        RAISE EXCEPTION 'migration 163 rollback would discard account registration challenge facts'
            USING ERRCODE='P1631';
    END IF;
END;
$migration_163$;

DROP TABLE account_registration_challenge_dispatch_claims_163;
DROP TABLE account_registration_challenge_verify_receipts_163;
DROP TABLE account_registration_challenges_163;
DROP TABLE account_registration_challenge_writes_163;
