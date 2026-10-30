INSERT INTO permissions (name, description) VALUES
    ('node_scheduling.read', 'Read tenant node line groups and scheduling state'),
    ('node_scheduling.manage', 'Create and revise tenant node line groups and scheduling policy');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
JOIN access_scopes scope ON scope.id = roles.scope_id AND scope.kind = 'tenant'
CROSS JOIN permissions
WHERE roles.system_role
  AND permissions.name IN ('node_scheduling.read', 'node_scheduling.manage')
  AND (
      roles.name = 'tenant_owner' OR
      (roles.name = 'tenant_viewer' AND permissions.name = 'node_scheduling.read')
  )
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_node_scheduling_permissions_to_system_role()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.system_role
       AND NEW.name IN ('tenant_owner', 'tenant_viewer')
       AND EXISTS (
           SELECT 1 FROM access_scopes
           WHERE id = NEW.scope_id AND kind = 'tenant'
       ) THEN
        INSERT INTO role_permissions (role_id, permission_name)
        SELECT NEW.id, permission.name
        FROM permissions permission
        WHERE permission.name = 'node_scheduling.read'
           OR (NEW.name = 'tenant_owner' AND permission.name = 'node_scheduling.manage')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_node_scheduling_permissions
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_node_scheduling_permissions_to_system_role();

CREATE FUNCTION assert_node_scheduling_tenant_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actual_kind text;
BEGIN
    SELECT kind INTO actual_kind FROM access_scopes WHERE id = NEW.tenant_scope_id;
    IF actual_kind IS DISTINCT FROM 'tenant' THEN
        RAISE EXCEPTION 'node scheduling scope must be a tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE node_line_groups (
    id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (
        name = btrim(name)
        AND octet_length(name) BETWEEN 1 AND 128
        AND name !~ '[[:cntrl:]]'
    ),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    created_by_user_id uuid NOT NULL,
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, updated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    PRIMARY KEY (tenant_scope_id, id),
    CHECK (updated_at >= created_at),
    CONSTRAINT node_line_groups_finite_time CHECK (
        isfinite(created_at) AND isfinite(updated_at)
    )
);

CREATE TRIGGER node_line_groups_tenant_scope
BEFORE INSERT OR UPDATE OF tenant_scope_id ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION assert_node_scheduling_tenant_scope();

CREATE UNIQUE INDEX node_line_groups_tenant_name_idx
    ON node_line_groups (tenant_scope_id, lower(name));
CREATE INDEX node_line_groups_tenant_created_idx
    ON node_line_groups (tenant_scope_id, created_at DESC, id DESC);

CREATE TABLE node_line_group_revisions (
    line_group_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL CHECK (
        name = btrim(name)
        AND octet_length(name) BETWEEN 1 AND 128
        AND name !~ '[[:cntrl:]]'
    ),
    probe_interval_ms integer NOT NULL CHECK (probe_interval_ms BETWEEN 1000 AND 300000),
    probe_timeout_ms integer NOT NULL CHECK (
        probe_timeout_ms BETWEEN 100 AND 60000
        AND probe_timeout_ms <= probe_interval_ms
    ),
    failure_threshold smallint NOT NULL CHECK (failure_threshold BETWEEN 1 AND 20),
    recovery_threshold smallint NOT NULL CHECK (recovery_threshold BETWEEN 1 AND 20),
    failure_debounce_ms integer NOT NULL CHECK (failure_debounce_ms BETWEEN 0 AND 3600000),
    recovery_debounce_ms integer NOT NULL CHECK (recovery_debounce_ms BETWEEN 0 AND 3600000),
    endpoint_count integer NOT NULL CHECK (endpoint_count BETWEEN 1 AND 512),
    configuration_digest bytea NOT NULL CHECK (octet_length(configuration_digest) = 32),
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    sealed_at timestamptz,
    PRIMARY KEY (tenant_scope_id, line_group_id, revision),
    FOREIGN KEY (tenant_scope_id, line_group_id)
        REFERENCES node_line_groups(tenant_scope_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (sealed_at IS NULL OR sealed_at >= created_at),
    CONSTRAINT node_line_group_revisions_finite_time CHECK (
        isfinite(created_at) AND (sealed_at IS NULL OR isfinite(sealed_at))
    )
);

ALTER TABLE node_line_groups
    ADD CONSTRAINT node_line_groups_current_revision_fk
    FOREIGN KEY (tenant_scope_id, id, current_revision)
    REFERENCES node_line_group_revisions(tenant_scope_id, line_group_id, revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE node_line_endpoints (
    id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    config_revision bigint NOT NULL CHECK (config_revision > 0),
    address inet NOT NULL CONSTRAINT node_line_endpoints_address_host CHECK (
        (family(address) = 4 AND masklen(address) = 32) OR
        (family(address) = 6 AND masklen(address) = 128
         AND NOT (address <<= '::ffff:0:0/96'::inet))
    ),
    address_family smallint NOT NULL CHECK (address_family IN (4, 6)),
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    region text NOT NULL DEFAULT '' CHECK (
        region = btrim(region)
        AND octet_length(region) <= 64
        AND region !~ '[[:cntrl:]]'
    ),
    carrier text NOT NULL DEFAULT '' CHECK (
        carrier = btrim(carrier)
        AND octet_length(carrier) <= 64
        AND carrier !~ '[[:cntrl:]]'
    ),
    priority integer NOT NULL CHECK (priority BETWEEN 0 AND 65535),
    weight smallint NOT NULL CONSTRAINT node_line_endpoints_weight_bounds
        CHECK (weight BETWEEN 1 AND 100),
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant_scope_id, line_group_id, config_revision, id),
    UNIQUE (tenant_scope_id, line_group_id, config_revision, address, port),
    FOREIGN KEY (tenant_scope_id, line_group_id, config_revision)
        REFERENCES node_line_group_revisions(tenant_scope_id, line_group_id, revision)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (family(address) = address_family)
);

CREATE INDEX node_line_endpoints_selection_idx
    ON node_line_endpoints (
        tenant_scope_id, line_group_id, config_revision,
        enabled, region, carrier, priority, id
    );

CREATE TABLE node_line_endpoint_health (
    tenant_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    config_revision bigint NOT NULL CHECK (config_revision > 0),
    endpoint_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('unknown', 'healthy', 'unhealthy')),
    consecutive_successes smallint NOT NULL CHECK (consecutive_successes BETWEEN 0 AND 20),
    consecutive_failures smallint NOT NULL CHECK (consecutive_failures BETWEEN 0 AND 20),
    streak_started_at timestamptz,
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    last_observed_at timestamptz,
    last_received_at timestamptz,
    last_probe_digest bytea CHECK (
        last_probe_digest IS NULL OR octet_length(last_probe_digest) = 32
    ),
    last_probe_healthy boolean,
    last_changed_at timestamptz NOT NULL,
    row_revision bigint NOT NULL CHECK (row_revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, line_group_id, config_revision, endpoint_id),
    FOREIGN KEY (tenant_scope_id, line_group_id, config_revision, endpoint_id)
        REFERENCES node_line_endpoints(tenant_scope_id, line_group_id, config_revision, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (NOT (consecutive_successes > 0 AND consecutive_failures > 0)),
    CHECK (
        (last_sequence = 0 AND last_observed_at IS NULL AND last_received_at IS NULL
            AND last_probe_digest IS NULL AND last_probe_healthy IS NULL
            AND streak_started_at IS NULL AND status = 'unknown') OR
        (last_sequence > 0 AND last_observed_at IS NOT NULL AND last_received_at IS NOT NULL
            AND last_probe_digest IS NOT NULL AND last_probe_healthy IS NOT NULL
            AND streak_started_at IS NOT NULL)
    ),
    CONSTRAINT node_line_endpoint_health_time_bounds CHECK (
        last_observed_at IS NULL OR
        (last_observed_at >= last_received_at - interval '24 hours'
         AND last_observed_at <= last_received_at + interval '5 minutes')
    ),
    CHECK (last_changed_at >= created_at AND updated_at >= created_at),
    CONSTRAINT node_line_endpoint_health_finite_time CHECK (
        isfinite(last_changed_at) AND isfinite(created_at) AND isfinite(updated_at)
        AND (streak_started_at IS NULL OR isfinite(streak_started_at))
        AND (last_observed_at IS NULL OR isfinite(last_observed_at))
        AND (last_received_at IS NULL OR isfinite(last_received_at))
    )
);

CREATE INDEX node_line_endpoint_health_selection_idx
    ON node_line_endpoint_health (
        tenant_scope_id, line_group_id, config_revision, status, endpoint_id
    );

CREATE TABLE node_scheduling_write_requests (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation = 'node_scheduling.group.put'),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    target_group_id uuid NOT NULL,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, target_group_id)
        REFERENCES node_line_groups(tenant_scope_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (tenant_scope_id, actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at >= created_at)
    ),
    CONSTRAINT node_scheduling_write_requests_finite_time CHECK (
        isfinite(created_at) AND (completed_at IS NULL OR isfinite(completed_at))
    )
);

CREATE INDEX node_scheduling_write_requests_tenant_created_idx
    ON node_scheduling_write_requests (tenant_scope_id, created_at DESC, id DESC);

CREATE FUNCTION protect_node_scheduling_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'node scheduling write requests are immutable';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.response_body IS NOT NULL THEN
            RAISE EXCEPTION 'node scheduling write requests must start unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.target_group_id IS DISTINCT FROM OLD.target_group_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'node scheduling write request facts are immutable';
    END IF;
    IF OLD.completed_at IS NOT NULL OR OLD.response_body IS NOT NULL THEN
        RAISE EXCEPTION 'completed node scheduling write requests are immutable';
    END IF;
    IF NEW.completed_at IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'node scheduling write request completion must be atomic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_scheduling_write_requests_state
BEFORE INSERT OR UPDATE OR DELETE ON node_scheduling_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_node_scheduling_write_request();

CREATE TRIGGER node_scheduling_write_requests_prevent_truncate
BEFORE TRUNCATE ON node_scheduling_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_scheduling_write_request();

CREATE FUNCTION protect_node_line_group()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'node line groups cannot be physically deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_revision <> 1 THEN
            RAISE EXCEPTION 'node line group initial revision must be one';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.current_revision <> OLD.current_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'node line group revision must advance by one';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_line_groups_protect_revision
BEFORE INSERT OR UPDATE OR DELETE ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION protect_node_line_group();

CREATE TRIGGER node_line_groups_prevent_truncate
BEFORE TRUNCATE ON node_line_groups
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_line_group();

CREATE FUNCTION protect_node_line_group_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.sealed_at IS NOT NULL THEN
            RAISE EXCEPTION 'node line group revisions must start unsealed';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE'
       AND OLD.sealed_at IS NULL
       AND NEW.sealed_at IS NOT NULL
       AND NEW.line_group_id IS NOT DISTINCT FROM OLD.line_group_id
       AND NEW.tenant_scope_id IS NOT DISTINCT FROM OLD.tenant_scope_id
       AND NEW.revision IS NOT DISTINCT FROM OLD.revision
       AND NEW.name IS NOT DISTINCT FROM OLD.name
       AND NEW.probe_interval_ms IS NOT DISTINCT FROM OLD.probe_interval_ms
       AND NEW.probe_timeout_ms IS NOT DISTINCT FROM OLD.probe_timeout_ms
       AND NEW.failure_threshold IS NOT DISTINCT FROM OLD.failure_threshold
       AND NEW.recovery_threshold IS NOT DISTINCT FROM OLD.recovery_threshold
       AND NEW.failure_debounce_ms IS NOT DISTINCT FROM OLD.failure_debounce_ms
       AND NEW.recovery_debounce_ms IS NOT DISTINCT FROM OLD.recovery_debounce_ms
       AND NEW.endpoint_count IS NOT DISTINCT FROM OLD.endpoint_count
       AND NEW.configuration_digest IS NOT DISTINCT FROM OLD.configuration_digest
       AND NEW.created_by_user_id IS NOT DISTINCT FROM OLD.created_by_user_id
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'node line group revisions are immutable after sealing';
END;
$$;

CREATE TRIGGER node_line_group_revisions_immutable
BEFORE INSERT OR UPDATE OR DELETE ON node_line_group_revisions
FOR EACH ROW EXECUTE FUNCTION protect_node_line_group_revision();

CREATE TRIGGER node_line_group_revisions_prevent_truncate
BEFORE TRUNCATE ON node_line_group_revisions
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_line_group_revision();

CREATE FUNCTION protect_node_line_endpoint()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot_sealed_at timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'node line endpoints are immutable';
    END IF;
    SELECT sealed_at INTO snapshot_sealed_at
    FROM node_line_group_revisions
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND line_group_id = NEW.line_group_id
      AND revision = NEW.config_revision
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'node line endpoint requires an existing unsealed node line group revision';
    END IF;
    IF snapshot_sealed_at IS NOT NULL THEN
        RAISE EXCEPTION 'cannot add an endpoint to a sealed node line group revision';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_line_endpoints_immutable
BEFORE INSERT OR UPDATE OR DELETE ON node_line_endpoints
FOR EACH ROW EXECUTE FUNCTION protect_node_line_endpoint();

CREATE TRIGGER node_line_endpoints_prevent_truncate
BEFORE TRUNCATE ON node_line_endpoints
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_line_endpoint();

CREATE FUNCTION assert_node_line_group_current_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_count integer;
    actual_count integer;
    actual_health_count integer;
    snapshot_name text;
    snapshot_sealed_at timestamptz;
BEGIN
    SELECT endpoint_count, name, sealed_at INTO expected_count, snapshot_name, snapshot_sealed_at
    FROM node_line_group_revisions
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND line_group_id = NEW.id
      AND revision = NEW.current_revision;
    SELECT count(*) INTO actual_count
    FROM node_line_endpoints
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND line_group_id = NEW.id
      AND config_revision = NEW.current_revision;
    SELECT count(*) INTO actual_health_count
    FROM node_line_endpoint_health
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND line_group_id = NEW.id
      AND config_revision = NEW.current_revision;
    IF snapshot_sealed_at IS NULL OR snapshot_name IS DISTINCT FROM NEW.name
       OR expected_count IS DISTINCT FROM actual_count
       OR expected_count IS DISTINCT FROM actual_health_count OR actual_count < 1 THEN
        RAISE EXCEPTION 'current node line group revision must be sealed and non-empty';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER node_line_groups_current_snapshot
AFTER INSERT OR UPDATE OF current_revision ON node_line_groups
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_node_line_group_current_snapshot();

CREATE FUNCTION protect_node_line_endpoint_health()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot_sealed_at timestamptz;
    snapshot_created_at timestamptz;
    failure_threshold_value integer;
    recovery_threshold_value integer;
    failure_debounce_value integer;
    recovery_debounce_value integer;
    expected_successes integer;
    expected_failures integer;
    expected_status text;
    expected_streak_started_at timestamptz;
    expected_last_changed_at timestamptz;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'node endpoint health rows cannot be deleted';
    END IF;
    SELECT sealed_at,created_at,failure_threshold,recovery_threshold,
           failure_debounce_ms,recovery_debounce_ms
      INTO snapshot_sealed_at,snapshot_created_at,failure_threshold_value,recovery_threshold_value,
           failure_debounce_value,recovery_debounce_value
    FROM node_line_group_revisions
    WHERE tenant_scope_id=NEW.tenant_scope_id
      AND line_group_id=NEW.line_group_id
      AND revision=NEW.config_revision
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'node endpoint health requires an unsealed node line group revision';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF snapshot_sealed_at IS NOT NULL THEN
            RAISE EXCEPTION 'cannot add health to a sealed node line group revision';
        END IF;
        IF NEW.status <> 'unknown'
           OR NEW.consecutive_successes <> 0 OR NEW.consecutive_failures <> 0
           OR NEW.streak_started_at IS NOT NULL OR NEW.last_sequence <> 0
           OR NEW.last_observed_at IS NOT NULL OR NEW.last_received_at IS NOT NULL
           OR NEW.last_probe_digest IS NOT NULL OR NEW.last_probe_healthy IS NOT NULL
           OR NEW.created_at IS DISTINCT FROM snapshot_created_at
           OR NEW.last_changed_at IS DISTINCT FROM NEW.created_at
           OR NEW.row_revision <> 1 OR NEW.updated_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'node endpoint health must start in the exact initial state';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.line_group_id IS DISTINCT FROM OLD.line_group_id
       OR NEW.config_revision IS DISTINCT FROM OLD.config_revision
       OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.last_sequence <= OLD.last_sequence
       OR NEW.row_revision <> OLD.row_revision + 1
       OR NEW.last_observed_at IS NULL OR NEW.last_received_at IS NULL
       OR NEW.last_probe_digest IS NULL OR NEW.last_probe_healthy IS NULL
       OR NEW.last_probe_digest IS NOT DISTINCT FROM OLD.last_probe_digest
       OR (OLD.last_observed_at IS NOT NULL AND NEW.last_observed_at <= OLD.last_observed_at)
       OR (OLD.last_received_at IS NOT NULL AND NEW.last_received_at < OLD.last_received_at)
       OR NEW.last_observed_at < NEW.created_at OR NEW.last_received_at < NEW.created_at
       OR NEW.updated_at IS DISTINCT FROM NEW.last_received_at
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'node endpoint health update must be monotonic';
    END IF;

    expected_status := OLD.status;
    expected_last_changed_at := OLD.last_changed_at;
    IF NEW.last_probe_healthy THEN
        expected_successes := least(OLD.consecutive_successes + 1, recovery_threshold_value);
        expected_failures := 0;
        IF OLD.consecutive_successes = 0 THEN
            expected_streak_started_at := NEW.last_observed_at;
        ELSE
            expected_streak_started_at := OLD.streak_started_at;
        END IF;
        IF OLD.status <> 'healthy'
           AND expected_successes >= recovery_threshold_value
           AND NEW.last_observed_at - expected_streak_started_at >=
               recovery_debounce_value * interval '1 millisecond' THEN
            expected_status := 'healthy';
            expected_last_changed_at := NEW.last_observed_at;
        END IF;
    ELSE
        expected_successes := 0;
        expected_failures := least(OLD.consecutive_failures + 1, failure_threshold_value);
        IF OLD.consecutive_failures = 0 THEN
            expected_streak_started_at := NEW.last_observed_at;
        ELSE
            expected_streak_started_at := OLD.streak_started_at;
        END IF;
        IF OLD.status <> 'unhealthy'
           AND expected_failures >= failure_threshold_value
           AND NEW.last_observed_at - expected_streak_started_at >=
               failure_debounce_value * interval '1 millisecond' THEN
            expected_status := 'unhealthy';
            expected_last_changed_at := NEW.last_observed_at;
        END IF;
    END IF;
    IF NEW.status IS DISTINCT FROM expected_status
       OR NEW.consecutive_successes IS DISTINCT FROM expected_successes
       OR NEW.consecutive_failures IS DISTINCT FROM expected_failures
       OR NEW.streak_started_at IS DISTINCT FROM expected_streak_started_at
       OR NEW.last_changed_at IS DISTINCT FROM expected_last_changed_at THEN
        RAISE EXCEPTION 'node endpoint health update does not match its health policy';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_line_endpoint_health_monotonic
BEFORE INSERT OR UPDATE OR DELETE ON node_line_endpoint_health
FOR EACH ROW EXECUTE FUNCTION protect_node_line_endpoint_health();

CREATE TRIGGER node_line_endpoint_health_prevent_truncate
BEFORE TRUNCATE ON node_line_endpoint_health
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_line_endpoint_health();

CREATE FUNCTION assert_node_line_group_revision_health_complete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    endpoint_rows integer;
    health_rows integer;
BEGIN
    IF NEW.sealed_at IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT count(*) INTO endpoint_rows
    FROM node_line_endpoints
    WHERE tenant_scope_id=NEW.tenant_scope_id
      AND line_group_id=NEW.line_group_id
      AND config_revision=NEW.revision;
    SELECT count(*) INTO health_rows
    FROM node_line_endpoint_health
    WHERE tenant_scope_id=NEW.tenant_scope_id
      AND line_group_id=NEW.line_group_id
      AND config_revision=NEW.revision;
    IF endpoint_rows IS DISTINCT FROM NEW.endpoint_count
       OR health_rows IS DISTINCT FROM NEW.endpoint_count
       OR EXISTS (
           SELECT 1
           FROM node_line_endpoints endpoint
           LEFT JOIN node_line_endpoint_health health
             ON health.tenant_scope_id=endpoint.tenant_scope_id
            AND health.line_group_id=endpoint.line_group_id
            AND health.config_revision=endpoint.config_revision
            AND health.endpoint_id=endpoint.id
           WHERE endpoint.tenant_scope_id=NEW.tenant_scope_id
             AND endpoint.line_group_id=NEW.line_group_id
             AND endpoint.config_revision=NEW.revision
             AND health.endpoint_id IS NULL
       ) THEN
        RAISE EXCEPTION 'sealed node line group revision requires exactly one initial health row per endpoint';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER node_line_group_revisions_health_complete
AFTER INSERT OR UPDATE ON node_line_group_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_node_line_group_revision_health_complete();
