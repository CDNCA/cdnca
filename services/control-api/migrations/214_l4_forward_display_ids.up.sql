LOCK TABLE schema_migrations, access_scopes, l4_forwards, l4_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_214$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>213 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>213 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=213 AND migration_id='213_certificate_cache_display_ids' AND
              checksum_sha256='d09c119ca14d7f0363ebbfa55b6440aaa234f751f2316847028a7d2723eeacc8' AND
              down_checksum_sha256='ddcb4224072b95ef397cd136b17c3e8c293a013406af477e34edcbef6f46198c' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='l4_forwards' AND column_name='display_id'
    ) OR to_regclass(current_schema() || '.l4_forward_display_id_sequences') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 214 requires the exact verified 213 release head and an untouched L4 display ID schema'
            USING ERRCODE='P2140';
    END IF;
END;
$migration_214$;

CREATE TABLE l4_forward_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK(next_value>0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE l4_forwards ADD COLUMN display_id bigint;
ALTER TABLE l4_forwards DISABLE TRIGGER l4_forwards_bump_edge_configuration_revision;

WITH ranked AS (
    SELECT id,scope_id,
           row_number() OVER(PARTITION BY scope_id ORDER BY created_at,id) AS display_id
    FROM l4_forwards
)
UPDATE l4_forwards SET display_id=ranked.display_id FROM ranked
WHERE l4_forwards.scope_id=ranked.scope_id AND l4_forwards.id=ranked.id;

UPDATE l4_write_requests request
SET response_body=request.response_body || jsonb_build_object('display_id',forward.display_id::text)
FROM l4_forwards forward
WHERE request.resource_id=forward.id AND request.completed_at IS NOT NULL AND
      request.response_body IS NOT NULL AND request.operation IN ('stream.create','stream.update');

ALTER TABLE l4_forwards ENABLE TRIGGER l4_forwards_bump_edge_configuration_revision;

INSERT INTO l4_forward_display_id_sequences(scope_id,next_value)
SELECT scope.id,COALESCE(max(forward.display_id),0)+1 FROM access_scopes scope
LEFT JOIN l4_forwards forward ON forward.scope_id=scope.id
WHERE scope.kind='tenant' GROUP BY scope.id;

ALTER TABLE l4_forwards
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT l4_forwards_display_id_positive CHECK(display_id>0),
    ADD CONSTRAINT l4_forwards_scope_display_id_unique UNIQUE(scope_id,display_id);

CREATE FUNCTION protect_l4_forward_display_id_214()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS DISTINCT FROM OLD.display_id THEN
        RAISE EXCEPTION 'L4 forward display ID is immutable' USING ERRCODE='P2142';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION allocate_l4_forward_display_id_214()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS NOT NULL THEN
        RAISE EXCEPTION 'L4 forward display ID is allocator-owned' USING ERRCODE='P2141';
    END IF;
    INSERT INTO l4_forward_display_id_sequences(scope_id,next_value,updated_at)
    VALUES(NEW.scope_id,2,now())
    ON CONFLICT(scope_id) DO UPDATE
    SET next_value=l4_forward_display_id_sequences.next_value+1,updated_at=now()
    RETURNING next_value-1 INTO NEW.display_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER l4_forwards_display_id_214 BEFORE INSERT ON l4_forwards
FOR EACH ROW EXECUTE FUNCTION allocate_l4_forward_display_id_214();
CREATE TRIGGER l4_forwards_display_id_immutable_214 BEFORE UPDATE ON l4_forwards
FOR EACH ROW EXECUTE FUNCTION protect_l4_forward_display_id_214();

REVOKE ALL ON FUNCTION allocate_l4_forward_display_id_214(),
    protect_l4_forward_display_id_214() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON l4_forward_display_id_sequences TO cdnca_control_app;
