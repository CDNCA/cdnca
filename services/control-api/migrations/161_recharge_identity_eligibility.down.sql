LOCK TABLE schema_migrations,recharge_identity_policy_heads_v1,
    recharge_identity_policy_revisions_v1,identity_verification_cases IN ACCESS EXCLUSIVE MODE;

DO $migration_161$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>161 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>161 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=161 AND migration_id='161_recharge_identity_eligibility' AND
              checksum_sha256='67edc7f614f05c0bd69551ae43d9b52bdd7e0a4b1c16c655adb76aa0a5bba4d6' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=160 AND migration_id='160_site_tls_protocols' AND
              checksum_sha256='697dfe854b2e4423d799348e35776ab406f303a104a52c232ff2d5af0db1fe7f' AND
              down_checksum_sha256='9c55509f60c8e2c04d81fa4ac4be2c58deac5d520abe31cfec02072e3925e07e' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 161 rollback requires the exact verified 161 head'
            USING ERRCODE='P1610';
    END IF;
    IF EXISTS(SELECT 1 FROM recharge_identity_policy_heads_v1) OR
       EXISTS(SELECT 1 FROM recharge_identity_policy_revisions_v1) THEN
        RAISE EXCEPTION 'migration 161 rollback would discard recharge identity policy facts'
            USING ERRCODE='P1612';
    END IF;
END;
$migration_161$;

DROP TRIGGER identity_verification_cases_recharge_lock_161 ON identity_verification_cases;
DROP TRIGGER recharge_identity_policy_head_truncate_161 ON recharge_identity_policy_heads_v1;
DROP TRIGGER recharge_identity_policy_revision_truncate_161 ON recharge_identity_policy_revisions_v1;
DROP TRIGGER recharge_identity_policy_head_guard_161 ON recharge_identity_policy_heads_v1;
DROP TRIGGER recharge_identity_policy_head_lock_161 ON recharge_identity_policy_heads_v1;
DROP TRIGGER recharge_identity_policy_revision_guard_161 ON recharge_identity_policy_revisions_v1;
DROP TRIGGER recharge_identity_policy_revision_lock_161 ON recharge_identity_policy_revisions_v1;
DROP FUNCTION prevent_recharge_identity_policy_truncate_161();
DROP FUNCTION lock_recharge_identity_subject_161();
DROP FUNCTION guard_recharge_identity_policy_head_161();
DROP FUNCTION guard_recharge_identity_policy_revision_161();
DROP FUNCTION lock_recharge_identity_policy_161();
DROP TABLE recharge_identity_policy_heads_v1;
DROP TABLE recharge_identity_policy_revisions_v1;
