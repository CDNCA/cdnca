LOCK TABLE schema_migrations, l4_stream_user_defaults
IN ACCESS EXCLUSIVE MODE;

DO $migration_237_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 237 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 237 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 237 AND migration_id = '237_l4_stream_user_defaults_lock_grant' AND
              checksum_sha256 = 'e45850337ba6918c65ee6887926cd991644025e8bf8aad12353081b7fdb2611a' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.l4_stream_user_defaults') IS NULL THEN
        RAISE EXCEPTION 'migration 237 rollback requires the exact verified 237 release head'
            USING ERRCODE = 'P2371';
    END IF;
END;
$migration_237_down$;

DO $l4_stream_user_defaults_lock_revoke$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        REVOKE UPDATE ON l4_stream_user_defaults FROM cdnca_control_app;
    END IF;
END;
$l4_stream_user_defaults_lock_revoke$;
