LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_465_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 465 OR
       (SELECT max(version) FROM schema_migrations) <> 465 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=465 AND
        migration_id='465_package_cname_sync' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 465 down requires the exact verified migration head' USING ERRCODE='P4651';
    END IF;
END;
$migration_465_down$;

DROP TABLE package_cname_sync_items;
DROP TABLE package_cname_sync_jobs;
