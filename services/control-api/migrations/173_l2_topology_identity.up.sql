LOCK TABLE schema_migrations,edge_target_snapshots,edge_target_snapshot_nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_173$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>172 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>172 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=172 AND migration_id='172_edge_rollout_cohorts' AND
              checksum_sha256='3107d44d94e8a55de68dc14d12733e3d6bdac5e8fa9d9aa581f83a8faa9bfd0e' AND
              down_checksum_sha256='df8e73667aa2a17ee8969b8552cba8759d08005418c3977dea8127a29ab9925c' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 173 requires the exact verified 172 release head' USING ERRCODE='P1730';
    END IF;
END;
$migration_173$;

ALTER TABLE edge_target_snapshots
    DROP CONSTRAINT IF EXISTS edge_target_snapshots_tenant_scope_id_source_line_group_id_source_revision_key;

CREATE INDEX edge_target_snapshots_source_revision_idx
    ON edge_target_snapshots (tenant_scope_id, source_line_group_id, source_revision, revision DESC);

CREATE TABLE edge_target_snapshot_identities (
    tenant_scope_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    snapshot_revision bigint NOT NULL CHECK (snapshot_revision > 0),
    identity_id uuid NOT NULL,
    topology_revision bigint NOT NULL CHECK (topology_revision > 0),
    node_id uuid NOT NULL,
    tier text NOT NULL CHECK (tier IN ('l1','l2')),
    source_line_group_id uuid NOT NULL,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    endpoint_id uuid,
    mtls_identity_sha256 bytea NOT NULL CHECK (octet_length(mtls_identity_sha256)=32),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, snapshot_id, snapshot_revision, identity_id, tier),
    FOREIGN KEY (tenant_scope_id, snapshot_id, snapshot_revision)
        REFERENCES edge_target_snapshots(tenant_scope_id, id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, node_id)
        REFERENCES nodes(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, source_line_group_id, source_revision, endpoint_id)
        REFERENCES node_line_endpoints(tenant_scope_id, line_group_id, config_revision, id)
        ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, snapshot_id, snapshot_revision, endpoint_id),
    CHECK (
        (tier='l1' AND endpoint_id IS NULL AND identity_id=node_id) OR
        (tier='l2' AND endpoint_id IS NOT NULL AND identity_id=endpoint_id)
    ),
    CHECK (isfinite(created_at))
);

CREATE INDEX edge_target_snapshot_identities_node_idx
    ON edge_target_snapshot_identities (tenant_scope_id, node_id, snapshot_id, snapshot_revision);
CREATE INDEX edge_target_snapshot_identities_endpoint_idx
    ON edge_target_snapshot_identities (tenant_scope_id, endpoint_id, snapshot_id, snapshot_revision)
    WHERE endpoint_id IS NOT NULL;

CREATE FUNCTION protect_edge_target_snapshot_identity_173()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'edge target snapshot identity facts are immutable' USING ERRCODE='P1731';
    END IF;
    IF NEW.topology_revision <> NEW.snapshot_revision OR
       NEW.source_line_group_id IS NULL OR NEW.source_revision < 1 THEN
        RAISE EXCEPTION 'edge target snapshot identity topology binding is invalid' USING ERRCODE='P1732';
    END IF;
    IF NEW.tier='l1' AND NOT EXISTS (
        SELECT 1 FROM edge_target_snapshot_nodes target
        WHERE target.tenant_scope_id=NEW.tenant_scope_id
          AND target.snapshot_id=NEW.snapshot_id
          AND target.snapshot_revision=NEW.snapshot_revision
          AND target.node_id=NEW.node_id
    ) THEN
        RAISE EXCEPTION 'L1 identity is not a member of the target snapshot' USING ERRCODE='P1734';
    END IF;
    IF NEW.tier='l2' AND NOT EXISTS (
        SELECT 1 FROM node_line_endpoints endpoint
        WHERE endpoint.tenant_scope_id=NEW.tenant_scope_id
          AND endpoint.line_group_id=NEW.source_line_group_id
          AND endpoint.config_revision=NEW.source_revision
          AND endpoint.id=NEW.endpoint_id
          AND endpoint.node_id=NEW.node_id
    ) THEN
        RAISE EXCEPTION 'L2 identity does not match the source endpoint node' USING ERRCODE='P1735';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_target_snapshot_identities_immutable_173
BEFORE INSERT OR UPDATE OR DELETE ON edge_target_snapshot_identities
FOR EACH ROW EXECUTE FUNCTION protect_edge_target_snapshot_identity_173();

CREATE TRIGGER edge_target_snapshot_identities_prevent_truncate_173
BEFORE TRUNCATE ON edge_target_snapshot_identities
FOR EACH STATEMENT EXECUTE FUNCTION protect_edge_target_snapshot_identity_173();

COMMENT ON TABLE edge_target_snapshot_identities IS
    'Immutable L1/L2 node identity facts bound to one target snapshot and topology revision';
