LOCK TABLE schema_migrations, access_scopes, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_210$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>209 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>209 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=209 AND migration_id='209_user_display_ids' AND
              checksum_sha256='316e8c58b30ebe37746bd1653f9f396b2231e520945c0639fadabfab28a6b043' AND
              down_checksum_sha256='7a9691116088db148b1154834996f5f400580f48143ba704f10c11274a804957' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='display_id'
    ) OR to_regclass(current_schema() || '.site_display_id_sequences') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 210 requires the exact verified 209 release head and an untouched site display ID schema'
            USING ERRCODE='P2100';
    END IF;
END;
$migration_210$;

CREATE TABLE site_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK (next_value > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE sites ADD COLUMN display_id bigint;

WITH ranked AS (
    SELECT id, scope_id,
           row_number() OVER (PARTITION BY scope_id ORDER BY created_at, id) AS display_id
    FROM sites
)
UPDATE sites
SET display_id=ranked.display_id
FROM ranked
WHERE sites.id=ranked.id;

INSERT INTO site_display_id_sequences(scope_id,next_value)
SELECT scope.id, COALESCE(max(site.display_id),0)+1
FROM access_scopes scope
LEFT JOIN sites site ON site.scope_id=scope.id
WHERE scope.kind='tenant'
GROUP BY scope.id;

ALTER TABLE sites
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT sites_display_id_positive CHECK (display_id > 0),
    ADD CONSTRAINT sites_scope_display_id_unique UNIQUE (scope_id,display_id);

GRANT SELECT, INSERT, UPDATE ON TABLE site_display_id_sequences TO cdnca_control_app;

