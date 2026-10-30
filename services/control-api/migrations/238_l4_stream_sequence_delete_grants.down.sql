LOCK TABLE schema_migrations, l4_stream_group_display_id_sequences,
    l4_stream_user_default_display_id_sequences
IN ACCESS EXCLUSIVE MODE;

DO $migration_238_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 238 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 238 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 238 AND migration_id = '238_l4_stream_sequence_delete_grants' AND
              checksum_sha256 = '1408c479408d540459eb5d78d7ae98c75c6382b6a40c330170a4c0976f5a28f7' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.l4_stream_group_display_id_sequences') IS NULL OR
          to_regclass(current_schema() || '.l4_stream_user_default_display_id_sequences') IS NULL THEN
        RAISE EXCEPTION 'migration 238 rollback requires the exact verified 238 release head'
            USING ERRCODE = 'P2381';
    END IF;
END;
$migration_238_down$;

DO $l4_stream_sequence_delete_revoke$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        REVOKE DELETE ON l4_stream_group_display_id_sequences FROM cdnca_control_app;
        REVOKE DELETE ON l4_stream_user_default_display_id_sequences FROM cdnca_control_app;
    END IF;
END;
$l4_stream_sequence_delete_revoke$;
