LOCK TABLE schema_migrations, users IN ACCESS EXCLUSIVE MODE;

DO $migration_209$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>208 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>208 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=208 AND migration_id='208_analytics_access_source_window_contributions' AND
              checksum_sha256='b7a561576842b5010958fe91fc16d2795ecb38f6720386d53bcfa8e9063001c8' AND
              down_checksum_sha256='4551e6264608092ed7084b1ca75217c2410af05a8b0c440015995f8e0e1eb269' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='users' AND column_name='display_id'
    ) OR to_regclass(current_schema() || '.users_display_id_seq') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 209 requires the exact verified 208 release head and an untouched user display ID schema'
            USING ERRCODE='P2090';
    END IF;
END;
$migration_209$;

CREATE SEQUENCE users_display_id_seq AS bigint MINVALUE 1 NO MAXVALUE NO CYCLE;

ALTER TABLE users ADD COLUMN display_id bigint;

WITH ranked AS (
    SELECT id, row_number() OVER (ORDER BY created_at, id) AS display_id
    FROM users
)
UPDATE users
SET display_id=ranked.display_id
FROM ranked
WHERE users.id=ranked.id;

SELECT setval(
    'users_display_id_seq',
    COALESCE((SELECT max(display_id) FROM users),0)+1,
    false
);

ALTER TABLE users
    ALTER COLUMN display_id SET DEFAULT nextval('users_display_id_seq'),
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT users_display_id_positive CHECK (display_id > 0),
    ADD CONSTRAINT users_display_id_unique UNIQUE (display_id);

ALTER SEQUENCE users_display_id_seq OWNED BY users.display_id;

GRANT USAGE, SELECT ON SEQUENCE users_display_id_seq TO cdnca_control_app;

