LOCK TABLE schema_migrations,package_period_reset_workload_authority_bindings_165 IN ACCESS EXCLUSIVE MODE;

DO $migration_165$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>165 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>165 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=165 AND migration_id='165_package_period_reset_workload_authority' AND
              checksum_sha256='8cbf3c38d4619f7f4a52b4a90c530b51cef452037e26e5a7f28b44fcdc74c915' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=164 AND migration_id='164_package_period_reset' AND
              checksum_sha256='79f38f20d69e4d2e922b77263bfb5b86a242c117f8c19afd38bf37104401dd60' AND
              down_checksum_sha256='0a711b4313ef1e750e333e564a94359dfc57ffd853697ec5e33dd05670bbe758' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 165 rollback requires the exact verified 165 head'
            USING ERRCODE='P1650';
    END IF;
    IF EXISTS(SELECT 1 FROM package_period_reset_workload_authority_bindings_165) THEN
        RAISE EXCEPTION 'migration 165 rollback would discard package period reset workload authority facts'
            USING ERRCODE='P1652';
    END IF;
END;
$migration_165$;

DROP TRIGGER package_period_reset_workload_authority_binding_no_truncate_165
    ON package_period_reset_workload_authority_bindings_165;
DROP TRIGGER package_period_reset_workload_authority_binding_guard_165
    ON package_period_reset_workload_authority_bindings_165;
DROP FUNCTION protect_package_period_reset_workload_authority_binding_165();
DROP TABLE package_period_reset_workload_authority_bindings_165;
