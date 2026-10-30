LOCK TABLE schema_migrations,runtime_patch_policy_heads_156,
    runtime_patch_policy_receipts_156,runtime_patch_policy_candidates_156 IN ACCESS EXCLUSIVE MODE;

DO $migration_156$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>156 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>156 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=156 AND migration_id='156_runtime_patch_policy' AND
              checksum_sha256='34cc982875f728e86af11479e9f49a5326a1fff85fe2d6b91efe4c0b84448788' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=155 AND migration_id='155_dns_provider_retry_states' AND
              checksum_sha256='d19d14aee41a7b17ba69cb02e4d0a6d256496b1d84ce8a9f7eb376796de51e48' AND
              down_checksum_sha256='db2bd655adda8eab882f08957fa5fa1a31233c87f36ab0555eff48bd46fc661b' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=154 AND migration_id='154_control_upgrade_systemd_repository' AND
              checksum_sha256='b3925e3c4a28ad73a9487aae6356c39dddc11291064d2f691d4d76a58ad7278a' AND
              down_checksum_sha256='85c925f408b65ce15c79a4bab9fb81ad6d9e2e8fb0feeb99c612426cbd35070f' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 156 rollback requires the exact verified 156 head'
            USING ERRCODE='P1560';
    END IF;
    IF EXISTS(SELECT 1 FROM runtime_patch_policy_heads_156) OR
       EXISTS(SELECT 1 FROM runtime_patch_policy_receipts_156) OR
       EXISTS(SELECT 1 FROM runtime_patch_policy_candidates_156) THEN
        RAISE EXCEPTION 'migration 156 rollback would discard runtime patch policy facts'
            USING ERRCODE='P1562';
    END IF;
END;
$migration_156$;

DROP TRIGGER runtime_patch_policy_head_truncate_156 ON runtime_patch_policy_heads_156;
DROP TRIGGER runtime_patch_policy_receipt_truncate_156 ON runtime_patch_policy_receipts_156;
DROP TRIGGER runtime_patch_policy_candidate_truncate_156 ON runtime_patch_policy_candidates_156;
DROP TRIGGER runtime_patch_policy_head_guard_156 ON runtime_patch_policy_heads_156;
DROP TRIGGER runtime_patch_policy_receipt_guard_156 ON runtime_patch_policy_receipts_156;
DROP TRIGGER runtime_patch_policy_candidate_guard_156 ON runtime_patch_policy_candidates_156;
DROP FUNCTION commit_runtime_patch_policy_156(text,text,text,text,bigint,boolean,bigint,bytea,bytea,bytea,bigint,text,text,bigint,text,bytea,bytea,bigint,bytea,bigint,bytea,bytea,bytea,bytea,bytea,bytea,bytea);
DROP FUNCTION append_runtime_patch_policy_receipt_156(text,text,text,text,text,bytea,bytea);
DROP FUNCTION prevent_runtime_patch_policy_truncate_156();
DROP FUNCTION guard_runtime_patch_policy_head_156();
DROP FUNCTION guard_runtime_patch_policy_receipt_156();
DROP FUNCTION guard_runtime_patch_policy_candidate_156();
DROP TABLE runtime_patch_policy_heads_156;
DROP TABLE runtime_patch_policy_receipts_156;
DROP TABLE runtime_patch_policy_candidates_156;
