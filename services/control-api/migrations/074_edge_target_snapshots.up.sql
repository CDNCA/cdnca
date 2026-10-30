LOCK TABLE node_line_endpoints IN ACCESS EXCLUSIVE MODE;

ALTER TABLE node_line_endpoints
    ADD COLUMN node_id uuid;

ALTER TABLE node_line_endpoints
    ADD CONSTRAINT node_line_endpoints_node_scope_fk
    FOREIGN KEY (tenant_scope_id, node_id)
    REFERENCES nodes(scope_id, id) ON DELETE RESTRICT;

CREATE INDEX node_line_endpoints_node_idx
    ON node_line_endpoints (tenant_scope_id, node_id)
    WHERE node_id IS NOT NULL;

CREATE TABLE edge_target_snapshots (
    id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    source_line_group_id uuid NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    source_configuration_digest bytea NOT NULL CHECK (octet_length(source_configuration_digest) = 32),
    node_set_digest bytea NOT NULL CHECK (octet_length(node_set_digest) = 32),
    node_count integer NOT NULL CHECK (node_count BETWEEN 1 AND 10000),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, id, revision),
    UNIQUE (tenant_scope_id, source_line_group_id, source_revision),
    FOREIGN KEY (tenant_scope_id, source_line_group_id, source_revision)
        REFERENCES node_line_group_revisions(tenant_scope_id, line_group_id, revision)
        ON DELETE RESTRICT,
    CHECK (isfinite(created_at))
);

CREATE INDEX edge_target_snapshots_source_idx
    ON edge_target_snapshots (tenant_scope_id, source_line_group_id, source_revision);

CREATE TABLE edge_target_snapshot_nodes (
    tenant_scope_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    snapshot_revision bigint NOT NULL CHECK (snapshot_revision > 0),
    node_id uuid NOT NULL,
    PRIMARY KEY (tenant_scope_id, snapshot_id, snapshot_revision, node_id),
    FOREIGN KEY (tenant_scope_id, snapshot_id, snapshot_revision)
        REFERENCES edge_target_snapshots(tenant_scope_id, id, revision)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, node_id)
        REFERENCES nodes(scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX edge_target_snapshot_nodes_node_idx
    ON edge_target_snapshot_nodes (tenant_scope_id, node_id, snapshot_id, snapshot_revision);

CREATE FUNCTION protect_edge_target_snapshot_074()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    source_sealed_at timestamptz;
    previous_revision bigint;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'edge target snapshots are immutable' USING ERRCODE = 'P0001';
    END IF;
    SELECT sealed_at INTO source_sealed_at
    FROM node_line_group_revisions
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND line_group_id = NEW.source_line_group_id
      AND revision = NEW.source_revision
    FOR SHARE;
    IF source_sealed_at IS NULL THEN
        RAISE EXCEPTION 'edge target snapshot requires a sealed source revision' USING ERRCODE = 'P0001';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        NEW.tenant_scope_id::text || ':' || NEW.id::text, 0));
    IF EXISTS (
        SELECT 1 FROM edge_target_snapshots
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND id = NEW.id AND revision = NEW.revision
    ) THEN
        RETURN NEW;
    END IF;
    SELECT max(revision) INTO previous_revision
    FROM edge_target_snapshots
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.id;
    IF previous_revision IS NULL AND NEW.revision <> 1 THEN
        RAISE EXCEPTION 'edge target snapshot revisions must start at one' USING ERRCODE = 'P0001';
    END IF;
    IF previous_revision IS NOT NULL AND NEW.revision <> previous_revision + 1 THEN
        RAISE EXCEPTION 'edge target snapshot revisions must advance by one' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_target_snapshots_immutable_074
BEFORE INSERT OR UPDATE OR DELETE ON edge_target_snapshots
FOR EACH ROW EXECUTE FUNCTION protect_edge_target_snapshot_074();

CREATE TRIGGER edge_target_snapshots_prevent_truncate_074
BEFORE TRUNCATE ON edge_target_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION protect_edge_target_snapshot_074();

CREATE FUNCTION protect_edge_target_snapshot_nodes_074()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'edge target snapshot node facts are immutable' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_target_snapshot_nodes_immutable_074
BEFORE INSERT OR UPDATE OR DELETE ON edge_target_snapshot_nodes
FOR EACH ROW EXECUTE FUNCTION protect_edge_target_snapshot_nodes_074();

CREATE TRIGGER edge_target_snapshot_nodes_prevent_truncate_074
BEFORE TRUNCATE ON edge_target_snapshot_nodes
FOR EACH STATEMENT EXECUTE FUNCTION protect_edge_target_snapshot_nodes_074();

CREATE FUNCTION assert_edge_target_snapshot_complete_074()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_count integer;
    actual_count integer;
BEGIN
    SELECT node_count INTO expected_count
    FROM edge_target_snapshots
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND id = NEW.snapshot_id
      AND revision = NEW.snapshot_revision;
    SELECT count(*) INTO actual_count
    FROM edge_target_snapshot_nodes
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND snapshot_id = NEW.snapshot_id
      AND snapshot_revision = NEW.snapshot_revision;
    IF expected_count IS NULL OR expected_count <> actual_count THEN
        RAISE EXCEPTION 'edge target snapshot node set is incomplete' USING ERRCODE = 'P0001';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE FUNCTION assert_edge_target_snapshot_parent_complete_074()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actual_count integer;
BEGIN
    SELECT count(*) INTO actual_count
    FROM edge_target_snapshot_nodes
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND snapshot_id = NEW.id
      AND snapshot_revision = NEW.revision;
    IF NEW.node_count <> actual_count THEN
        RAISE EXCEPTION 'edge target snapshot node set is incomplete' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER edge_target_snapshots_complete_074
AFTER INSERT ON edge_target_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_edge_target_snapshot_parent_complete_074();

CREATE CONSTRAINT TRIGGER edge_target_snapshot_nodes_complete_074
AFTER INSERT OR UPDATE OR DELETE ON edge_target_snapshot_nodes
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_edge_target_snapshot_complete_074();
