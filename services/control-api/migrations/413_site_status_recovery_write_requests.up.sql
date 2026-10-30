LOCK TABLE schema_migrations,site_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_413_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 412 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 412 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=412 AND
        migration_id='412_cname_intent_survives_site_edits' AND
        checksum_sha256='61ec73bfe6e8bc680783dce2662b73d5ebd595468c7d4b31548a7cedcfd8a4ef' AND
        down_checksum_sha256='878d2e63bd89c499d1c59cf4567c27930816e388e0d1e7f5378cf5b8e98f167e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 413 requires the exact verified 412 release head' USING ERRCODE='P4130';
    END IF;
END;
$migration_413_up$;

-- 413（r136 testdebt11；占位 = 集成头 404 + 2，合入时改号）。
-- Site status recovery (platform unlock, renewal, traffic top-up) records its
-- idempotent write as site.status_recovery.<trigger>; 010 only allowed
-- site.unlock, so every platform unlock failed with 23514 (HTTP 500).
ALTER TABLE site_write_requests
    DROP CONSTRAINT site_write_requests_operation_check,
    ADD CONSTRAINT site_write_requests_operation_check CHECK (
        operation IN ('site.create', 'site.update', 'site.delete', 'site.lock', 'site.unlock',
                      'site.status_recovery.unlock', 'site.status_recovery.renewal',
                      'site.status_recovery.traffic_top_up')
    );
