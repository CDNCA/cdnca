LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_258_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 258 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 258 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 258 AND migration_id = '258_certificate_user_defaults' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 258 rollback requires the exact verified 258 release head'
            USING ERRCODE = 'P2581';
    END IF;
END;
$migration_258_down$;

DROP INDEX certificate_default_write_requests_scope_created_idx;
DROP TABLE certificate_default_write_requests;
DROP TABLE certificate_user_defaults;
