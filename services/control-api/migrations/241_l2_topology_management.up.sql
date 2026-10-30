LOCK TABLE schema_migrations, access_scopes, users, memberships, nodes
IN ACCESS EXCLUSIVE MODE;

DO $migration_241_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 240 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 240 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 240 AND migration_id = '240_node_monitoring_compatibility_fields' AND
              checksum_sha256 = 'b5a841e06c3d75024dfa9ca8c05b2bc08324b0990b7d1a4a53c8dd6564e61390' AND
              down_checksum_sha256 = '40aab73c4220c2bdb5296ac6ae81443d46fcaf67075720e09ac5b75f4fb898ca' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.l2_topology_configs') IS NOT NULL OR
            to_regclass(current_schema() || '.l2_topology_conditions') IS NOT NULL OR
            to_regclass(current_schema() || '.l2_topology_nodes') IS NOT NULL OR
            to_regclass(current_schema() || '.l2_topology_write_requests') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 241 requires the exact verified 240 release head and an untouched L2 topology schema'
            USING ERRCODE = 'P2410';
    END IF;
END;
$migration_241_up$;

ALTER TABLE nodes
    ADD CONSTRAINT nodes_scope_id_241_unique UNIQUE (scope_id, id);

CREATE TABLE l2_topology_configs (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    display_id bigint GENERATED ALWAYS AS IDENTITY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128 AND name !~ '[[:cntrl:]]'),
    region text NOT NULL CHECK (region = btrim(region) AND char_length(region) BETWEEN 1 AND 64 AND region !~ '[[:cntrl:]]'),
    remark text NOT NULL DEFAULT '' CHECK (remark = btrim(remark) AND char_length(remark) <= 1024 AND remark !~ '[[:cntrl:]]'),
    mode text NOT NULL CHECK (mode IN ('cache', 'global')),
    load_method text NOT NULL CHECK (load_method IN ('rr', 'url_hash')),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    deleted_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    CONSTRAINT l2_topology_configs_scope_id_241_unique UNIQUE (tenant_scope_id, id),
    CONSTRAINT l2_topology_configs_scope_display_241_unique UNIQUE (tenant_scope_id, display_id),
    CONSTRAINT l2_topology_configs_time_241_check CHECK (
        isfinite(created_at) AND isfinite(updated_at) AND updated_at >= created_at AND
        (deleted_at IS NULL AND deleted_by_user_id IS NULL OR
         deleted_at IS NOT NULL AND deleted_by_user_id IS NOT NULL AND isfinite(deleted_at) AND deleted_at >= created_at)
    )
);

CREATE UNIQUE INDEX l2_topology_configs_scope_name_241_idx
    ON l2_topology_configs(tenant_scope_id, lower(name)) WHERE deleted_at IS NULL;

CREATE TABLE l2_topology_conditions (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    display_id bigint GENERATED ALWAYS AS IDENTITY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128 AND name !~ '[[:cntrl:]]'),
    remark text NOT NULL DEFAULT '' CHECK (remark = btrim(remark) AND char_length(remark) <= 1024 AND remark !~ '[[:cntrl:]]'),
    rules jsonb NOT NULL CHECK (jsonb_typeof(rules) = 'array' AND jsonb_array_length(rules) BETWEEN 1 AND 32),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    deleted_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    CONSTRAINT l2_topology_conditions_scope_id_241_unique UNIQUE (tenant_scope_id, id),
    CONSTRAINT l2_topology_conditions_scope_display_241_unique UNIQUE (tenant_scope_id, display_id),
    CONSTRAINT l2_topology_conditions_time_241_check CHECK (
        isfinite(created_at) AND isfinite(updated_at) AND updated_at >= created_at AND
        (deleted_at IS NULL AND deleted_by_user_id IS NULL OR
         deleted_at IS NOT NULL AND deleted_by_user_id IS NOT NULL AND isfinite(deleted_at) AND deleted_at >= created_at)
    )
);

CREATE UNIQUE INDEX l2_topology_conditions_scope_name_241_idx
    ON l2_topology_conditions(tenant_scope_id, lower(name)) WHERE deleted_at IS NULL;

CREATE TABLE l2_topology_nodes (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    display_id bigint GENERATED ALWAYS AS IDENTITY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    config_id uuid NOT NULL,
    node_id uuid NOT NULL,
    condition_id uuid,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    enabled boolean NOT NULL DEFAULT true,
    weight integer NOT NULL DEFAULT 100 CHECK (weight BETWEEN 1 AND 100),
    sort_order integer NOT NULL DEFAULT 0 CHECK (sort_order BETWEEN 0 AND 999999),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    deleted_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    FOREIGN KEY (tenant_scope_id, config_id)
        REFERENCES l2_topology_configs(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, condition_id)
        REFERENCES l2_topology_conditions(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, node_id)
        REFERENCES nodes(scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT l2_topology_nodes_scope_display_241_unique UNIQUE (tenant_scope_id, display_id),
    CONSTRAINT l2_topology_nodes_time_241_check CHECK (
        isfinite(created_at) AND isfinite(updated_at) AND updated_at >= created_at AND
        (deleted_at IS NULL AND deleted_by_user_id IS NULL OR
         deleted_at IS NOT NULL AND deleted_by_user_id IS NOT NULL AND isfinite(deleted_at) AND deleted_at >= created_at)
    )
);

CREATE UNIQUE INDEX l2_topology_nodes_scope_node_active_241_idx
    ON l2_topology_nodes(tenant_scope_id, node_id) WHERE deleted_at IS NULL;
CREATE INDEX l2_topology_nodes_scope_config_sort_241_idx
    ON l2_topology_nodes(tenant_scope_id, config_id, sort_order, display_id) WHERE deleted_at IS NULL;

CREATE TABLE l2_topology_write_requests (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'node_scheduling.l2_config.create', 'node_scheduling.l2_config.update', 'node_scheduling.l2_config.delete',
        'node_scheduling.l2_condition.create', 'node_scheduling.l2_condition.update', 'node_scheduling.l2_condition.delete',
        'node_scheduling.l2_node.add', 'node_scheduling.l2_node.update', 'node_scheduling.l2_node.delete'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at) AND completed_at >= created_at),
    CONSTRAINT l2_topology_write_requests_identity_241_unique
        UNIQUE (tenant_scope_id, actor_user_id, operation, idempotency_key),
    CONSTRAINT l2_topology_write_requests_completion_241_check CHECK (
        completed_at IS NULL AND response_body IS NULL OR completed_at IS NOT NULL AND response_body IS NOT NULL
    )
);

CREATE FUNCTION protect_l2_topology_write_request_241()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL AND
       OLD.response_body IS NULL AND NEW.response_body IS NOT NULL AND
       NEW.id IS NOT DISTINCT FROM OLD.id AND NEW.tenant_scope_id IS NOT DISTINCT FROM OLD.tenant_scope_id AND
       NEW.actor_scope_id IS NOT DISTINCT FROM OLD.actor_scope_id AND NEW.actor_user_id IS NOT DISTINCT FROM OLD.actor_user_id AND
       NEW.operation IS NOT DISTINCT FROM OLD.operation AND NEW.idempotency_key IS NOT DISTINCT FROM OLD.idempotency_key AND
       NEW.request_digest IS NOT DISTINCT FROM OLD.request_digest AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'L2 topology write requests are immutable';
END;
$$;

CREATE TRIGGER l2_topology_write_requests_immutable_241
BEFORE UPDATE OR DELETE ON l2_topology_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_l2_topology_write_request_241();
CREATE TRIGGER l2_topology_write_requests_truncate_241
BEFORE TRUNCATE ON l2_topology_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_l2_topology_write_request_241();

DO $l2_topology_runtime_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT SELECT, INSERT, UPDATE ON l2_topology_configs, l2_topology_conditions,
            l2_topology_nodes, l2_topology_write_requests TO cdnca_control_app;
        GRANT USAGE, SELECT ON SEQUENCE l2_topology_configs_display_id_seq,
            l2_topology_conditions_display_id_seq, l2_topology_nodes_display_id_seq TO cdnca_control_app;
    END IF;
END;
$l2_topology_runtime_grants$;
