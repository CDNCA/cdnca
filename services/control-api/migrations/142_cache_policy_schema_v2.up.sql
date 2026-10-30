LOCK TABLE schema_migrations, cache_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_142$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 141 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 141 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 141 AND migration_id = '141_platform_global_announcements' AND
              checksum_sha256 = 'd078248a163d03698eb559bec8c45b5f7ebc6b682603ed6e1f6448958c26af7f' AND
              down_checksum_sha256 = '5d7a9b8201d9bd9b425284aa8bc6a96e54180c23bc233a913e44f2a5ac241da5' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 142 requires the exact verified 141 release head'
            USING ERRCODE = 'P1420';
    END IF;
END;
$migration_142$;

ALTER TABLE cache_policy_revisions
    ADD COLUMN schema_version smallint NOT NULL DEFAULT 1,
    ADD CONSTRAINT cache_policy_revisions_schema_version_142_check
        CHECK (schema_version IN (1,2));
