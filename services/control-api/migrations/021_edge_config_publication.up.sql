CREATE TABLE edge_configuration_scopes (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    updated_at timestamptz NOT NULL
);

INSERT INTO edge_configuration_scopes (scope_id, source_revision, updated_at)
SELECT id, 1, CURRENT_TIMESTAMP
FROM access_scopes
WHERE kind = 'tenant';

CREATE FUNCTION advance_edge_configuration_scope_revision(target_scope_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO edge_configuration_scopes (scope_id, source_revision, updated_at)
    VALUES (target_scope_id, 1, CURRENT_TIMESTAMP)
    ON CONFLICT (scope_id) DO UPDATE
    SET source_revision = edge_configuration_scopes.source_revision + 1,
        updated_at = EXCLUDED.updated_at;
END;
$$;

CREATE FUNCTION bump_edge_configuration_scope_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM advance_edge_configuration_scope_revision(
        CASE WHEN TG_OP = 'DELETE' THEN OLD.scope_id ELSE NEW.scope_id END
    );
    RETURN NULL;
END;
$$;

CREATE FUNCTION bump_edge_configuration_revision_for_site_child()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_site_id uuid;
    target_scope_id uuid;
BEGIN
    target_site_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.site_id ELSE NEW.site_id END;
    SELECT scope_id INTO target_scope_id FROM sites WHERE id = target_site_id;
    IF FOUND THEN
        PERFORM advance_edge_configuration_scope_revision(target_scope_id);
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.site_id IS DISTINCT FROM NEW.site_id THEN
        SELECT scope_id INTO target_scope_id FROM sites WHERE id = OLD.site_id;
        IF FOUND THEN
            PERFORM advance_edge_configuration_scope_revision(target_scope_id);
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER sites_bump_edge_configuration_revision
AFTER INSERT OR UPDATE OR DELETE ON sites
FOR EACH ROW EXECUTE FUNCTION bump_edge_configuration_scope_revision();

CREATE TRIGGER l4_forwards_bump_edge_configuration_revision
AFTER INSERT OR UPDATE OR DELETE ON l4_forwards
FOR EACH ROW EXECUTE FUNCTION bump_edge_configuration_scope_revision();

CREATE TRIGGER site_origin_pools_bump_edge_configuration_revision
AFTER INSERT OR UPDATE OR DELETE ON site_origin_pools
FOR EACH ROW EXECUTE FUNCTION bump_edge_configuration_revision_for_site_child();

CREATE TRIGGER site_origins_bump_edge_configuration_revision
AFTER INSERT OR UPDATE OR DELETE ON site_origins
FOR EACH ROW EXECUTE FUNCTION bump_edge_configuration_revision_for_site_child();

CREATE TABLE edge_config_publications (
    id uuid PRIMARY KEY,
    configuration_scope_id uuid NOT NULL REFERENCES edge_configuration_scopes(scope_id) ON DELETE RESTRICT,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 96 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    canonical_snapshot_sha256 bytea NOT NULL CHECK (octet_length(canonical_snapshot_sha256) = 32),
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    config_version_id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    node_count integer NOT NULL CHECK (node_count > 0),
    created_at timestamptz NOT NULL,
    UNIQUE (configuration_scope_id, idempotency_key),
    UNIQUE (configuration_scope_id, request_id),
    UNIQUE (config_version_id),
    UNIQUE (rollout_id),
    FOREIGN KEY (configuration_scope_id, config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (configuration_scope_id, rollout_id)
        REFERENCES rollouts(configuration_scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX edge_config_publications_scope_created_idx
    ON edge_config_publications (configuration_scope_id, created_at DESC, id DESC);

CREATE FUNCTION prevent_edge_config_publication_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'edge config publications are append-only';
END;
$$;

CREATE TRIGGER edge_config_publications_append_only
BEFORE UPDATE OR DELETE ON edge_config_publications
FOR EACH ROW EXECUTE FUNCTION prevent_edge_config_publication_mutation();
