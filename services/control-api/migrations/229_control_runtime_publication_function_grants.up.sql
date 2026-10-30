LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_229_guard$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 228 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 228 OR
       EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR
                 checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR
                 down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
                 metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR
       NOT EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE version=228 AND migration_id='228_edge_publication_rollback_contract'
             AND checksum_sha256='67248b97c997d74137e9fc0cfd5df7195c9406ae293e1d019108a4758831dd3a'
             AND down_checksum_sha256='48e06362609fbaafa6e964692b7dac7aaa332c45d470d24a2e177d2f662f3a5f'
             AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 229 requires the exact verified 228 release head'
            USING ERRCODE='P2290';
    END IF;

    IF to_regprocedure('package_monitor_site_binding_digest_114(uuid,uuid,uuid,uuid,bigint,timestamptz)') IS NULL OR
       to_regprocedure('record_security_policy_activation_recovery_pending_095(uuid)') IS NULL OR
       to_regprocedure('record_security_policy_activation_recovery_proofs_095()') IS NULL THEN
        RAISE EXCEPTION 'migration 229 requires the publication and security recovery functions from migrations 095 and 114'
            USING ERRCODE='P2291';
    END IF;
END;
$migration_229_guard$;

GRANT EXECUTE ON FUNCTION package_monitor_site_binding_digest_114(uuid,uuid,uuid,uuid,bigint,timestamptz)
    TO cdnca_control_runtime;
GRANT EXECUTE ON FUNCTION record_security_policy_activation_recovery_pending_095(uuid)
    TO cdnca_control_runtime;
GRANT EXECUTE ON FUNCTION record_security_policy_activation_recovery_proofs_095()
    TO cdnca_control_runtime;
