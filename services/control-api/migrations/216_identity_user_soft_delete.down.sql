LOCK TABLE schema_migrations, identity_user_deletions IN ACCESS EXCLUSIVE MODE;

DO $migration_216_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>216 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>216 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=216 AND migration_id='216_identity_user_soft_delete' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (SELECT 1 FROM identity_user_deletions) THEN
        RAISE EXCEPTION 'migration 216 rollback would discard user deletion facts'
            USING ERRCODE='P2162';
    END IF;
END;
$migration_216_down$;

DROP TRIGGER identity_user_deletions_truncate_guard_216 ON identity_user_deletions;
DROP TRIGGER identity_user_deletions_guard_216 ON identity_user_deletions;
DROP FUNCTION guard_identity_user_deletions_216();
DROP TABLE identity_user_deletions;
