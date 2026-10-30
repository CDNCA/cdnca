LOCK TABLE schema_migrations, users IN ACCESS EXCLUSIVE MODE;

DO $migration_209_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>209 OR
       (SELECT max(version) FROM schema_migrations)<>209 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=209 AND migration_id='209_user_display_ids' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 209 rollback requires the exact verified 209 release head'
            USING ERRCODE='P2090';
    END IF;
END;
$migration_209_down$;

ALTER TABLE users
    DROP CONSTRAINT users_display_id_unique,
    DROP CONSTRAINT users_display_id_positive,
    DROP COLUMN display_id;

DROP SEQUENCE IF EXISTS users_display_id_seq;

