LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_229_down_guard$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 229 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 229 OR
       EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR
                 checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR
                 down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
                 metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR
       NOT EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE version=229 AND migration_id='229_control_runtime_publication_function_grants'
             AND checksum_sha256='2f7ba254e3c0599c8160ebe06940a1059a9975965baa2331c2f5d1b5818180a1'
             AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR
       NOT EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE version=228 AND migration_id='228_edge_publication_rollback_contract'
             AND checksum_sha256='67248b97c997d74137e9fc0cfd5df7195c9406ae293e1d019108a4758831dd3a'
             AND down_checksum_sha256='48e06362609fbaafa6e964692b7dac7aaa332c45d470d24a2e177d2f662f3a5f'
             AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 229 rollback requires the exact verified 229 release head'
            USING ERRCODE='P2292';
    END IF;
END;
$migration_229_down_guard$;

REVOKE EXECUTE ON FUNCTION package_monitor_site_binding_digest_114(uuid,uuid,uuid,uuid,bigint,timestamptz)
    FROM cdnca_control_runtime;
REVOKE EXECUTE ON FUNCTION record_security_policy_activation_recovery_pending_095(uuid)
    FROM cdnca_control_runtime;
REVOKE EXECUTE ON FUNCTION record_security_policy_activation_recovery_proofs_095()
    FROM cdnca_control_runtime;
