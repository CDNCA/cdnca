LOCK TABLE schema_migrations, users IN ACCESS EXCLUSIVE MODE;

DO $migration_251_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 251 OR
       (SELECT max(version) FROM schema_migrations) <> 251 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=251 AND migration_id='251_identity_user_metadata'
          AND checksum_sha256='88a8577382a5aff3c70e737f0eea4ec9781d8b0d54f250a2442a4ed9d9b5bbd4' AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 251 rollback requires the exact verified 251 head' USING ERRCODE='P2510';
    END IF;
    IF EXISTS (SELECT 1 FROM users WHERE remark IS NOT NULL OR qq IS NOT NULL) THEN
        RAISE EXCEPTION 'retain migration 251 during binary rollback to preserve user metadata' USING ERRCODE='P2511';
    END IF;
END;
$migration_251_down$;

ALTER TABLE users DROP COLUMN remark, DROP COLUMN qq;
