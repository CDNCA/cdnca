LOCK TABLE schema_migrations, access_scopes, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_211$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>210 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>210 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=210 AND migration_id='210_site_display_ids' AND
              checksum_sha256='50bab1bb882ec577b5248ebd5e4bbca44a8daa6c843a22a3713a3cfb4b47d83e' AND
              down_checksum_sha256='5cd72bd4d48abe99d06fb1a3c3261b3b7c92d49283590f3d502ac82404ddb964' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='nodes' AND column_name='display_id'
    ) OR to_regclass(current_schema() || '.node_display_id_sequences') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 211 requires the exact verified 210 release head and an untouched node display ID schema'
            USING ERRCODE='P2110';
    END IF;
END;
$migration_211$;

CREATE TABLE node_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK (next_value > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE nodes ADD COLUMN display_id bigint;

WITH ranked AS (
    SELECT id, scope_id,
           row_number() OVER (PARTITION BY scope_id ORDER BY created_at, id) AS display_id
    FROM nodes
)
UPDATE nodes
SET display_id=ranked.display_id
FROM ranked
WHERE nodes.id=ranked.id;

INSERT INTO node_display_id_sequences(scope_id,next_value)
SELECT scope.id, COALESCE(max(node.display_id),0)+1
FROM access_scopes scope
LEFT JOIN nodes node ON node.scope_id=scope.id
WHERE scope.kind='platform'
GROUP BY scope.id;

ALTER TABLE nodes
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT nodes_display_id_positive CHECK (display_id > 0),
    ADD CONSTRAINT nodes_scope_display_id_unique UNIQUE (scope_id,display_id);

GRANT SELECT, INSERT, UPDATE ON TABLE node_display_id_sequences TO cdnca_control_app;
