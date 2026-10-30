LOCK TABLE schema_migrations,site_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_413_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 413 OR
       (SELECT max(version) FROM schema_migrations) <> 413 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=413 AND
        migration_id='413_site_status_recovery_write_requests' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 413 down requires the exact verified migration head' USING ERRCODE='P4131';
    END IF;
    IF EXISTS (SELECT 1 FROM site_write_requests WHERE operation LIKE 'site.status_recovery.%') THEN
        RAISE EXCEPTION 'migration 413 rollback would discard site status recovery writes' USING ERRCODE='P4132';
    END IF;
END;
$migration_413_down$;

ALTER TABLE site_write_requests
    DROP CONSTRAINT site_write_requests_operation_check,
    ADD CONSTRAINT site_write_requests_operation_check CHECK (
        operation IN ('site.create', 'site.update', 'site.delete', 'site.lock', 'site.unlock')
    );
