LOCK TABLE schema_migrations,access_scopes,dns_zones,dns_providers,
    dns_provider_retry_states IN ACCESS EXCLUSIVE MODE;

DO $migration_155$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>155 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>155 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=155 AND migration_id='155_dns_provider_retry_states' AND
              checksum_sha256='d19d14aee41a7b17ba69cb02e4d0a6d256496b1d84ce8a9f7eb376796de51e48' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=154 AND migration_id='154_control_upgrade_systemd_repository' AND
              checksum_sha256='b3925e3c4a28ad73a9487aae6356c39dddc11291064d2f691d4d76a58ad7278a' AND
              down_checksum_sha256='85c925f408b65ce15c79a4bab9fb81ad6d9e2e8fb0feeb99c612426cbd35070f' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('dns_provider_retry_states') IS NULL OR
         to_regprocedure('guard_dns_provider_retry_state_scope_155()') IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='dns_zones'::regclass AND conname='dns_zones_scope_zone_provider_155'
    ) THEN
        RAISE EXCEPTION 'migration 155 rollback requires the exact verified 155 head'
            USING ERRCODE='P1550';
    END IF;
    IF EXISTS(SELECT 1 FROM dns_provider_retry_states) THEN
        RAISE EXCEPTION 'migration 155 rollback would discard durable DNS provider retry state'
            USING ERRCODE='P1552';
    END IF;
END;
$migration_155$;

DROP TRIGGER dns_provider_retry_state_scope_guard_155 ON dns_provider_retry_states;
DROP FUNCTION guard_dns_provider_retry_state_scope_155();
DROP TABLE dns_provider_retry_states;
ALTER TABLE dns_zones
    DROP CONSTRAINT dns_zones_scope_zone_provider_155;
