LOCK TABLE schema_migrations, access_scopes, node_line_groups, node_scheduling_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_215$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>214 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>214 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=214 AND migration_id='214_l4_forward_display_ids' AND
              checksum_sha256='0e9a89ca9fc14ed72d72d937e19c166d8c3de6e2c2daca12d23924515186063e' AND
              down_checksum_sha256='07055d134e57886af3a1597da91346dd416ca163c9ef6a7cdc52c0ad77d1e673' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='node_line_groups' AND column_name='display_id'
    ) OR to_regclass(current_schema() || '.node_line_group_display_id_sequences') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 215 requires the exact verified 214 release head and an untouched line-group display ID schema'
            USING ERRCODE='P2150';
    END IF;
END;
$migration_215$;

CREATE TABLE node_line_group_display_id_sequences (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK(next_value>0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE node_line_groups ADD COLUMN display_id bigint;

WITH ranked AS (
    SELECT id,tenant_scope_id,
           row_number() OVER(PARTITION BY tenant_scope_id ORDER BY created_at,id) AS display_id
    FROM node_line_groups
)
UPDATE node_line_groups SET display_id=ranked.display_id FROM ranked
WHERE node_line_groups.tenant_scope_id=ranked.tenant_scope_id AND node_line_groups.id=ranked.id;

ALTER TABLE node_scheduling_write_requests DISABLE TRIGGER node_scheduling_write_requests_state;
UPDATE node_scheduling_write_requests request
SET response_body=jsonb_set(request.response_body,'{group,display_id}',to_jsonb(line_group.display_id::text),true)
FROM node_line_groups line_group
WHERE request.tenant_scope_id=line_group.tenant_scope_id AND request.target_group_id=line_group.id AND
      request.completed_at IS NOT NULL AND request.response_body IS NOT NULL AND
      jsonb_typeof(request.response_body->'group')='object';
ALTER TABLE node_scheduling_write_requests ENABLE TRIGGER node_scheduling_write_requests_state;

INSERT INTO node_line_group_display_id_sequences(tenant_scope_id,next_value)
SELECT scope.id,COALESCE(max(line_group.display_id),0)+1 FROM access_scopes scope
LEFT JOIN node_line_groups line_group ON line_group.tenant_scope_id=scope.id
WHERE scope.kind='tenant' GROUP BY scope.id;

ALTER TABLE node_line_groups
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT node_line_groups_display_id_positive CHECK(display_id>0),
    ADD CONSTRAINT node_line_groups_scope_display_id_unique UNIQUE(tenant_scope_id,display_id);

CREATE FUNCTION protect_node_line_group_display_id_215()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS DISTINCT FROM OLD.display_id THEN
        RAISE EXCEPTION 'node line-group display ID is immutable' USING ERRCODE='P2152';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION allocate_node_line_group_display_id_215()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS NOT NULL THEN
        RAISE EXCEPTION 'node line-group display ID is allocator-owned' USING ERRCODE='P2151';
    END IF;
    INSERT INTO node_line_group_display_id_sequences(tenant_scope_id,next_value,updated_at)
    VALUES(NEW.tenant_scope_id,2,now())
    ON CONFLICT(tenant_scope_id) DO UPDATE
    SET next_value=node_line_group_display_id_sequences.next_value+1,updated_at=now()
    RETURNING next_value-1 INTO NEW.display_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_line_groups_display_id_215 BEFORE INSERT ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION allocate_node_line_group_display_id_215();
CREATE TRIGGER node_line_groups_display_id_immutable_215 BEFORE UPDATE ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION protect_node_line_group_display_id_215();

REVOKE ALL ON FUNCTION allocate_node_line_group_display_id_215(),
    protect_node_line_group_display_id_215() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON node_line_group_display_id_sequences TO cdnca_control_app;
