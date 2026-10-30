INSERT INTO permissions (name, description) VALUES
    ('traffic_packages.read', 'Read traffic package products, grants, balances, and usage'),
    ('traffic_packages.manage', 'Manage versioned traffic package products'),
    ('traffic_packages.consume', 'Consume traffic package grants from a trusted workload'),
    ('traffic_packages.usage_refund', 'Refund traffic package usage from a trusted workload'),
    ('traffic_packages.expire', 'Expire due traffic package grants from a trusted workload'),
    ('traffic_packages.reverse', 'Reverse traffic package grants from a trusted workload');

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id
CROSS JOIN (VALUES
    ('traffic_packages.read'),
    ('traffic_packages.manage')
) AS permission(name)
WHERE role.system_role AND scope.kind = 'platform' AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, 'traffic_packages.read'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id
WHERE role.system_role AND scope.kind = 'tenant'
  AND role.name IN ('tenant_owner', 'tenant_viewer')
ON CONFLICT DO NOTHING;

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required)
VALUES ('traffic_packages.read', false);

CREATE FUNCTION project_traffic_package_system_role_permissions()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO target_scope_kind FROM access_scopes WHERE id = NEW.scope_id;
    IF target_scope_kind = 'platform' AND NEW.name = 'platform_owner' THEN
        INSERT INTO role_permissions (role_id, permission_name) VALUES
            (NEW.id, 'traffic_packages.read'),
            (NEW.id, 'traffic_packages.manage');
    ELSIF target_scope_kind = 'tenant' AND NEW.name IN ('tenant_owner', 'tenant_viewer') THEN
        INSERT INTO role_permissions (role_id, permission_name)
        VALUES (NEW.id, 'traffic_packages.read');
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_project_traffic_package_permissions
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION project_traffic_package_system_role_permissions();

CREATE FUNCTION valid_traffic_package_workload_permissions(value text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT cardinality(value) BETWEEN 1 AND 4
       AND value <@ ARRAY[
           'traffic_packages.consume',
           'traffic_packages.expire',
           'traffic_packages.reverse',
           'traffic_packages.usage_refund'
       ]::text[]
       AND value = ARRAY(SELECT DISTINCT permission FROM unnest(value) permission ORDER BY permission)
$$;

CREATE TABLE traffic_package_workload_bindings (
    id uuid PRIMARY KEY,
    issuer text NOT NULL CHECK (
        issuer = btrim(issuer) AND octet_length(issuer) BETWEEN 1 AND 256
        AND issuer !~ '[[:cntrl:]]'
    ),
    credential_reference text NOT NULL CHECK (
        credential_reference = btrim(credential_reference)
        AND octet_length(credential_reference) BETWEEN 1 AND 256
        AND credential_reference !~ '[[:cntrl:]]'
    ),
    subject text NOT NULL CHECK (
        octet_length(subject) BETWEEN 1 AND 128
        AND subject ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    audience text NOT NULL CHECK (audience = 'traffic-package-workload'),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    permissions text[] NOT NULL CHECK (valid_traffic_package_workload_permissions(permissions)),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    revision bigint NOT NULL CHECK (revision > 0),
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > not_before),
    revoked_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (issuer, credential_reference),
    CHECK (created_at <= updated_at),
    CHECK (
        (status = 'active' AND revoked_at IS NULL) OR
        (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= created_at)
    )
);

CREATE INDEX traffic_package_workload_bindings_actor_idx
    ON traffic_package_workload_bindings (actor_scope_id, actor_user_id);

CREATE FUNCTION protect_traffic_package_workload_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
    target_user_status text;
    target_membership_status text;
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'traffic package workload bindings cannot be truncated';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'traffic package workload bindings cannot be deleted';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'active' OR NEW.revision <> 1 OR NEW.revoked_at IS NOT NULL
           OR NEW.updated_at <> NEW.created_at THEN
            RAISE EXCEPTION 'traffic package workload binding must start active at revision 1';
        END IF;
        SELECT scope.kind, actor.status, membership.status
          INTO target_scope_kind, target_user_status, target_membership_status
        FROM access_scopes scope
        JOIN memberships membership ON membership.scope_id = scope.id
        JOIN users actor ON actor.id = membership.user_id
        WHERE scope.id = NEW.actor_scope_id AND actor.id = NEW.actor_user_id;
        IF target_scope_kind IS DISTINCT FROM 'platform'
           OR target_user_status IS DISTINCT FROM 'active'
           OR target_membership_status IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION 'traffic package workload binding requires an active platform actor';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status <> 'active' OR NEW.status <> 'revoked'
       OR NEW.revision <> OLD.revision + 1
       OR NEW.revoked_at IS NULL OR NEW.revoked_at < OLD.created_at
       OR NEW.updated_at <> NEW.revoked_at OR NEW.updated_at < OLD.updated_at
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.issuer IS DISTINCT FROM OLD.issuer
       OR NEW.credential_reference IS DISTINCT FROM OLD.credential_reference
       OR NEW.subject IS DISTINCT FROM OLD.subject
       OR NEW.audience IS DISTINCT FROM OLD.audience
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.permissions IS DISTINCT FROM OLD.permissions
       OR NEW.not_before IS DISTINCT FROM OLD.not_before
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'traffic package workload binding only permits one-way revocation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_workload_bindings_protect
BEFORE INSERT OR UPDATE OR DELETE ON traffic_package_workload_bindings
FOR EACH ROW EXECUTE FUNCTION protect_traffic_package_workload_binding();
CREATE TRIGGER traffic_package_workload_bindings_no_truncate
BEFORE TRUNCATE ON traffic_package_workload_bindings
FOR EACH STATEMENT EXECUTE FUNCTION protect_traffic_package_workload_binding();

CREATE FUNCTION traffic_package_workload_permission_for_operation(value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE value
        WHEN 'consume' THEN 'traffic_packages.consume'
        WHEN 'refund' THEN 'traffic_packages.usage_refund'
        WHEN 'expire' THEN 'traffic_packages.expire'
        WHEN 'reverse' THEN 'traffic_packages.reverse'
    END
$$;

CREATE TABLE traffic_package_workload_requests (
    id uuid PRIMARY KEY,
    binding_id uuid NOT NULL REFERENCES traffic_package_workload_bindings(id) ON DELETE RESTRICT,
    issuer text NOT NULL,
    credential_reference text NOT NULL,
    subject text NOT NULL,
    audience text NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    bucket_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    currency text NOT NULL,
    metering_scope text NOT NULL,
    metering_version text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('consume', 'refund', 'reverse')),
    permission text NOT NULL CHECK (
        permission = traffic_package_workload_permission_for_operation(operation)
    ),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    occurred_at timestamptz NOT NULL,
    result text CHECK (result IN ('succeeded', 'insufficient_traffic', 'expiry_backlog')),
    event_id uuid REFERENCES traffic_package_events(id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    automatic_expired_count integer CHECK (automatic_expired_count BETWEEN 0 AND 100),
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, currency, metering_scope, metering_version, bucket_id)
        REFERENCES traffic_package_buckets(tenant_scope_id, currency, metering_scope, metering_version, id)
        ON DELETE RESTRICT,
    UNIQUE (binding_id, tenant_scope_id, operation, idempotency_key),
    UNIQUE (event_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (result IS NULL AND event_id IS NULL AND automatic_expired_count IS NULL
            AND completed_at IS NULL) OR
        (result = 'succeeded' AND event_id IS NOT NULL
            AND automatic_expired_count IS NOT NULL AND completed_at >= occurred_at) OR
        (result = 'insufficient_traffic' AND operation = 'consume'
            AND event_id IS NULL AND automatic_expired_count IS NOT NULL
            AND completed_at >= occurred_at) OR
        (result = 'expiry_backlog' AND event_id IS NULL
            AND automatic_expired_count IS NOT NULL
            AND completed_at >= occurred_at)
    )
);

CREATE FUNCTION protect_traffic_package_workload_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'traffic package workload requests cannot be truncated';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'traffic package workload requests cannot be deleted';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.result IS NOT NULL OR NEW.event_id IS NOT NULL
           OR NEW.automatic_expired_count IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'traffic package workload request must start unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.result IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
       OR NEW.issuer IS DISTINCT FROM OLD.issuer
       OR NEW.credential_reference IS DISTINCT FROM OLD.credential_reference
       OR NEW.subject IS DISTINCT FROM OLD.subject
       OR NEW.audience IS DISTINCT FROM OLD.audience
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.bucket_id IS DISTINCT FROM OLD.bucket_id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.metering_scope IS DISTINCT FROM OLD.metering_scope
       OR NEW.metering_version IS DISTINCT FROM OLD.metering_version
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.permission IS DISTINCT FROM OLD.permission
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
       OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
       OR NEW.result IS NULL OR NEW.automatic_expired_count IS NULL
       OR NEW.completed_at IS NULL THEN
        RAISE EXCEPTION 'traffic package workload request must complete exactly once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_workload_requests_protect
BEFORE INSERT OR UPDATE OR DELETE ON traffic_package_workload_requests
FOR EACH ROW EXECUTE FUNCTION protect_traffic_package_workload_request();
CREATE TRIGGER traffic_package_workload_requests_no_truncate
BEFORE TRUNCATE ON traffic_package_workload_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_traffic_package_workload_request();

ALTER TABLE traffic_package_events
    ADD COLUMN workload_binding_id uuid
        REFERENCES traffic_package_workload_bindings(id) ON DELETE RESTRICT,
    ADD COLUMN workload_permission text,
    ADD COLUMN workload_cause text CHECK (workload_cause IN ('explicit', 'automatic')),
    ADD COLUMN workload_parent_request_id uuid,
    ADD CONSTRAINT traffic_package_events_workload_source_check CHECK (
        (workload_binding_id IS NULL AND workload_permission IS NULL
            AND workload_cause IS NULL AND workload_parent_request_id IS NULL) OR
        (workload_binding_id IS NOT NULL AND workload_permission IN (
            'traffic_packages.consume',
            'traffic_packages.usage_refund',
            'traffic_packages.expire',
            'traffic_packages.reverse'
        ) AND (
            (operation = 'expire' AND workload_cause IS NOT NULL
                AND workload_parent_request_id IS NOT NULL) OR
            (operation <> 'expire' AND workload_cause IS NULL
                AND workload_parent_request_id IS NULL)
        ))
    );

ALTER TABLE traffic_package_ledger_entries
    ADD COLUMN workload_binding_id uuid
        REFERENCES traffic_package_workload_bindings(id) ON DELETE RESTRICT,
    ADD COLUMN workload_permission text,
    ADD COLUMN workload_cause text CHECK (workload_cause IN ('explicit', 'automatic')),
    ADD COLUMN workload_parent_request_id uuid,
    ADD CONSTRAINT traffic_package_ledger_entries_workload_source_check CHECK (
        (workload_binding_id IS NULL AND workload_permission IS NULL
            AND workload_cause IS NULL AND workload_parent_request_id IS NULL) OR
        (workload_binding_id IS NOT NULL AND workload_permission IN (
            'traffic_packages.consume',
            'traffic_packages.usage_refund',
            'traffic_packages.expire',
            'traffic_packages.reverse'
        ))
    );

CREATE INDEX traffic_package_events_workload_binding_idx
    ON traffic_package_events (workload_binding_id)
    WHERE workload_binding_id IS NOT NULL;
CREATE INDEX traffic_package_ledger_entries_workload_binding_idx
    ON traffic_package_ledger_entries (workload_binding_id)
    WHERE workload_binding_id IS NOT NULL;

CREATE TABLE traffic_package_product_catalog_watermarks (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    current_version bigint NOT NULL CHECK (current_version >= 0)
);

CREATE TABLE traffic_package_product_catalog_versions (
    catalog_version bigint PRIMARY KEY CHECK (catalog_version > 0),
    product_snapshot_id uuid NOT NULL UNIQUE
        REFERENCES traffic_package_product_snapshots(id) ON DELETE RESTRICT
);

LOCK TABLE traffic_package_product_snapshots,
    traffic_package_product_catalog_watermarks,
    traffic_package_product_catalog_versions
IN ACCESS EXCLUSIVE MODE;

INSERT INTO traffic_package_product_catalog_versions (catalog_version, product_snapshot_id)
SELECT row_number() OVER (ORDER BY created_at, product_id, revision, id), id
FROM traffic_package_product_snapshots;

INSERT INTO traffic_package_product_catalog_watermarks (singleton, current_version)
SELECT true, count(*) FROM traffic_package_product_catalog_versions;

CREATE FUNCTION append_traffic_package_product_catalog_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    allocated_version bigint;
BEGIN
    UPDATE traffic_package_product_catalog_watermarks
    SET current_version = current_version + 1
    WHERE singleton
    RETURNING current_version INTO allocated_version;
    IF allocated_version IS NULL THEN
        RAISE EXCEPTION 'traffic package product catalog watermark is unavailable';
    END IF;
    INSERT INTO traffic_package_product_catalog_versions (catalog_version, product_snapshot_id)
    VALUES (allocated_version, NEW.id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_product_snapshots_append_catalog_version
AFTER INSERT ON traffic_package_product_snapshots
FOR EACH ROW EXECUTE FUNCTION append_traffic_package_product_catalog_version();

CREATE TRIGGER traffic_package_product_catalog_versions_append_only
BEFORE UPDATE OR DELETE ON traffic_package_product_catalog_versions
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_product_catalog_versions_no_truncate
BEFORE TRUNCATE ON traffic_package_product_catalog_versions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();

CREATE TABLE tenant_traffic_package_usage_watermarks (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    current_version bigint NOT NULL CHECK (current_version >= 0)
);

CREATE TABLE traffic_package_usage_event_versions (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    usage_version bigint NOT NULL CHECK (usage_version > 0),
    event_id uuid NOT NULL UNIQUE REFERENCES traffic_package_events(id) ON DELETE RESTRICT,
    PRIMARY KEY (tenant_scope_id, usage_version)
);

LOCK TABLE traffic_package_events,
    tenant_traffic_package_usage_watermarks,
    traffic_package_usage_event_versions
IN ACCESS EXCLUSIVE MODE;

INSERT INTO traffic_package_usage_event_versions (tenant_scope_id, usage_version, event_id)
SELECT tenant_scope_id,
       row_number() OVER (PARTITION BY tenant_scope_id ORDER BY created_at, id),
       id
FROM traffic_package_events;

INSERT INTO tenant_traffic_package_usage_watermarks (tenant_scope_id, current_version)
SELECT tenant_scope_id, max(usage_version)
FROM traffic_package_usage_event_versions
GROUP BY tenant_scope_id;

CREATE FUNCTION append_traffic_package_usage_event_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    allocated_version bigint;
BEGIN
    INSERT INTO tenant_traffic_package_usage_watermarks (tenant_scope_id, current_version)
    VALUES (NEW.tenant_scope_id, 0)
    ON CONFLICT (tenant_scope_id) DO NOTHING;
    UPDATE tenant_traffic_package_usage_watermarks
    SET current_version = current_version + 1
    WHERE tenant_scope_id = NEW.tenant_scope_id
    RETURNING current_version INTO allocated_version;
    IF allocated_version IS NULL THEN
        RAISE EXCEPTION 'traffic package usage watermark is unavailable';
    END IF;
    INSERT INTO traffic_package_usage_event_versions (tenant_scope_id, usage_version, event_id)
    VALUES (NEW.tenant_scope_id, allocated_version, NEW.id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_events_append_usage_version
AFTER INSERT ON traffic_package_events
FOR EACH ROW EXECUTE FUNCTION append_traffic_package_usage_event_version();

CREATE TRIGGER traffic_package_usage_event_versions_append_only
BEFORE UPDATE OR DELETE ON traffic_package_usage_event_versions
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_usage_event_versions_no_truncate
BEFORE TRUNCATE ON traffic_package_usage_event_versions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();

CREATE TABLE tenant_traffic_package_state_watermarks (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    current_version bigint NOT NULL CHECK (current_version >= 0)
);

CREATE TABLE traffic_package_grant_state_versions (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    state_version bigint NOT NULL CHECK (state_version > 0),
    grant_id uuid NOT NULL REFERENCES traffic_package_grants(id) ON DELETE RESTRICT,
    grant_revision bigint NOT NULL CHECK (grant_revision > 0),
    remaining_bytes bigint NOT NULL CHECK (remaining_bytes >= 0),
    status text NOT NULL CHECK (status IN ('active', 'exhausted', 'expired', 'reversed')),
    updated_at timestamptz NOT NULL,
    source_ledger_entry_id uuid NOT NULL
        REFERENCES traffic_package_ledger_entries(id) ON DELETE RESTRICT,
    PRIMARY KEY (tenant_scope_id, state_version),
    UNIQUE (source_ledger_entry_id),
    UNIQUE (tenant_scope_id, grant_id, grant_revision)
);

CREATE INDEX traffic_package_grant_state_versions_lookup_idx
    ON traffic_package_grant_state_versions (tenant_scope_id, grant_id, state_version DESC);

LOCK TABLE traffic_package_grants,
    traffic_package_events,
    traffic_package_ledger_entries,
    tenant_traffic_package_state_watermarks,
    traffic_package_grant_state_versions
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM traffic_package_grants package_grant
        LEFT JOIN LATERAL (
            SELECT count(*) AS entry_count,
                   min(entry.grant_revision) AS minimum_revision,
                   max(entry.grant_revision) AS maximum_revision
            FROM traffic_package_ledger_entries entry
            WHERE entry.grant_id = package_grant.id
        ) history ON true
        WHERE history.entry_count <> package_grant.revision
           OR history.minimum_revision IS DISTINCT FROM 1
           OR history.maximum_revision IS DISTINCT FROM package_grant.revision
    ) THEN
        RAISE EXCEPTION 'traffic package grant history is not contiguous before migration 066';
    END IF;
END;
$$;

CREATE TEMPORARY TABLE traffic_package_state_backfill (
    tenant_scope_id uuid NOT NULL,
    state_version bigint NOT NULL,
    grant_id uuid NOT NULL,
    grant_revision bigint NOT NULL,
    remaining_bytes bigint NOT NULL,
    status text NOT NULL,
    updated_at timestamptz NOT NULL,
    source_ledger_entry_id uuid NOT NULL,
    PRIMARY KEY (tenant_scope_id, state_version)
) ON COMMIT DROP;

INSERT INTO traffic_package_state_backfill (
    tenant_scope_id, state_version, grant_id, grant_revision, remaining_bytes,
    status, updated_at, source_ledger_entry_id
)
SELECT entry.tenant_scope_id,
       row_number() OVER (
           PARTITION BY entry.tenant_scope_id
           ORDER BY entry.grant_revision, entry.created_at, entry.grant_id,
                    entry.event_id, entry.allocation_order, entry.id
       ),
       entry.grant_id,
       entry.grant_revision,
       entry.remaining_after_bytes,
       CASE event.operation
           WHEN 'grant' THEN 'active'
           WHEN 'consume' THEN CASE WHEN entry.remaining_after_bytes = 0 THEN 'exhausted' ELSE 'active' END
           WHEN 'refund' THEN CASE WHEN entry.created_at >= package_grant.expires_at THEN 'expired' ELSE 'active' END
           WHEN 'expire' THEN 'expired'
           WHEN 'reverse' THEN 'reversed'
       END,
       entry.created_at,
       entry.id
FROM traffic_package_ledger_entries entry
JOIN traffic_package_events event ON event.id = entry.event_id
JOIN traffic_package_grants package_grant ON package_grant.id = entry.grant_id;

INSERT INTO traffic_package_grant_state_versions (
    tenant_scope_id, state_version, grant_id, grant_revision, remaining_bytes,
    status, updated_at, source_ledger_entry_id
)
SELECT tenant_scope_id, state_version, grant_id, grant_revision, remaining_bytes,
       status, updated_at, source_ledger_entry_id
FROM traffic_package_state_backfill;

INSERT INTO tenant_traffic_package_state_watermarks (tenant_scope_id, current_version)
SELECT tenant_scope_id, max(state_version)
FROM traffic_package_state_backfill
GROUP BY tenant_scope_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM traffic_package_grants package_grant
        LEFT JOIN traffic_package_grant_state_versions state
          ON state.tenant_scope_id = package_grant.tenant_scope_id
         AND state.grant_id = package_grant.id
         AND state.grant_revision = package_grant.revision
        WHERE state.source_ledger_entry_id IS NULL
           OR state.remaining_bytes IS DISTINCT FROM package_grant.remaining_bytes
           OR state.status IS DISTINCT FROM package_grant.status
           OR state.updated_at IS DISTINCT FROM package_grant.updated_at
    ) THEN
        RAISE EXCEPTION 'traffic package grant state backfill does not match current grants';
    END IF;
END;
$$;

CREATE FUNCTION append_traffic_package_grant_state_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_grant traffic_package_grants%ROWTYPE;
    source_event traffic_package_events%ROWTYPE;
    allocated_version bigint;
BEGIN
    SELECT * INTO current_grant FROM traffic_package_grants WHERE id = NEW.grant_id;
    SELECT * INTO source_event FROM traffic_package_events WHERE id = NEW.event_id;
    IF current_grant.id IS NULL OR source_event.id IS NULL
       OR current_grant.tenant_scope_id IS DISTINCT FROM NEW.tenant_scope_id
       OR current_grant.bucket_id IS DISTINCT FROM NEW.bucket_id
       OR current_grant.currency IS DISTINCT FROM NEW.currency
       OR current_grant.metering_scope IS DISTINCT FROM NEW.metering_scope
       OR current_grant.metering_version IS DISTINCT FROM NEW.metering_version
       OR current_grant.revision IS DISTINCT FROM NEW.grant_revision
       OR current_grant.remaining_bytes IS DISTINCT FROM NEW.remaining_after_bytes
       OR current_grant.updated_at IS DISTINCT FROM NEW.created_at
       OR source_event.tenant_scope_id IS DISTINCT FROM NEW.tenant_scope_id
       OR source_event.bucket_id IS DISTINCT FROM NEW.bucket_id
       OR source_event.currency IS DISTINCT FROM NEW.currency
       OR source_event.metering_scope IS DISTINCT FROM NEW.metering_scope
       OR source_event.metering_version IS DISTINCT FROM NEW.metering_version THEN
        RAISE EXCEPTION 'traffic package ledger entry does not match current grant state';
    END IF;
    IF (source_event.operation = 'grant' AND
            (NEW.grant_revision <> 1 OR current_grant.status <> 'active'))
       OR (source_event.operation = 'consume' AND current_grant.status NOT IN ('active', 'exhausted'))
       OR (source_event.operation = 'refund' AND current_grant.status NOT IN ('active', 'expired'))
       OR (source_event.operation = 'expire' AND current_grant.status <> 'expired')
       OR (source_event.operation = 'reverse' AND current_grant.status <> 'reversed') THEN
        RAISE EXCEPTION 'traffic package ledger operation does not match current grant status';
    END IF;
    INSERT INTO tenant_traffic_package_state_watermarks (tenant_scope_id, current_version)
    VALUES (NEW.tenant_scope_id, 0)
    ON CONFLICT (tenant_scope_id) DO NOTHING;
    UPDATE tenant_traffic_package_state_watermarks
    SET current_version = current_version + 1
    WHERE tenant_scope_id = NEW.tenant_scope_id
    RETURNING current_version INTO allocated_version;
    IF allocated_version IS NULL THEN
        RAISE EXCEPTION 'traffic package state watermark is unavailable';
    END IF;
    INSERT INTO traffic_package_grant_state_versions (
        tenant_scope_id, state_version, grant_id, grant_revision, remaining_bytes,
        status, updated_at, source_ledger_entry_id
    ) VALUES (
        NEW.tenant_scope_id, allocated_version, NEW.grant_id, NEW.grant_revision,
        NEW.remaining_after_bytes, current_grant.status, current_grant.updated_at, NEW.id
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_ledger_entries_append_state
AFTER INSERT ON traffic_package_ledger_entries
FOR EACH ROW EXECUTE FUNCTION append_traffic_package_grant_state_version();

CREATE FUNCTION assert_traffic_package_grant_state_captured()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    matching_states bigint;
BEGIN
    SELECT count(*) INTO matching_states
    FROM traffic_package_grant_state_versions state
    JOIN traffic_package_ledger_entries entry
      ON entry.id = state.source_ledger_entry_id
     AND entry.tenant_scope_id = state.tenant_scope_id
     AND entry.grant_id = state.grant_id
     AND entry.grant_revision = state.grant_revision
     AND entry.remaining_after_bytes = state.remaining_bytes
     AND entry.created_at = state.updated_at
    WHERE state.tenant_scope_id = NEW.tenant_scope_id
      AND state.grant_id = NEW.id
      AND state.grant_revision = NEW.revision
      AND state.remaining_bytes = NEW.remaining_bytes
      AND state.status = NEW.status
      AND state.updated_at = NEW.updated_at;
    IF matching_states <> 1 THEN
        RAISE EXCEPTION 'traffic package grant current revision lacks exact source-bound state';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_grants_state_captured
AFTER INSERT OR UPDATE ON traffic_package_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_grant_state_captured();

CREATE TRIGGER traffic_package_grant_state_versions_append_only
BEFORE UPDATE OR DELETE ON traffic_package_grant_state_versions
FOR EACH ROW EXECUTE FUNCTION prevent_traffic_package_append_mutation();
CREATE TRIGGER traffic_package_grant_state_versions_no_truncate
BEFORE TRUNCATE ON traffic_package_grant_state_versions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_traffic_package_append_mutation();

CREATE FUNCTION protect_traffic_package_watermark()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'traffic package watermarks cannot be truncated';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'traffic package watermarks cannot be deleted';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.current_version <> 0 THEN
            RAISE EXCEPTION 'traffic package watermark must start at zero';
        END IF;
        RETURN NEW;
    END IF;
    IF (to_jsonb(NEW) - 'current_version') IS DISTINCT FROM
       (to_jsonb(OLD) - 'current_version')
       OR NEW.current_version <> OLD.current_version + 1 THEN
        RAISE EXCEPTION 'traffic package watermark must advance exactly once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_product_catalog_watermarks_protect
BEFORE INSERT OR UPDATE OR DELETE ON traffic_package_product_catalog_watermarks
FOR EACH ROW EXECUTE FUNCTION protect_traffic_package_watermark();
CREATE TRIGGER traffic_package_product_catalog_watermarks_no_truncate
BEFORE TRUNCATE ON traffic_package_product_catalog_watermarks
FOR EACH STATEMENT EXECUTE FUNCTION protect_traffic_package_watermark();
CREATE TRIGGER tenant_traffic_package_usage_watermarks_protect
BEFORE INSERT OR UPDATE OR DELETE ON tenant_traffic_package_usage_watermarks
FOR EACH ROW EXECUTE FUNCTION protect_traffic_package_watermark();
CREATE TRIGGER tenant_traffic_package_usage_watermarks_no_truncate
BEFORE TRUNCATE ON tenant_traffic_package_usage_watermarks
FOR EACH STATEMENT EXECUTE FUNCTION protect_traffic_package_watermark();
CREATE TRIGGER tenant_traffic_package_state_watermarks_protect
BEFORE INSERT OR UPDATE OR DELETE ON tenant_traffic_package_state_watermarks
FOR EACH ROW EXECUTE FUNCTION protect_traffic_package_watermark();
CREATE TRIGGER tenant_traffic_package_state_watermarks_no_truncate
BEFORE TRUNCATE ON tenant_traffic_package_state_watermarks
FOR EACH STATEMENT EXECUTE FUNCTION protect_traffic_package_watermark();

CREATE FUNCTION assert_traffic_package_product_catalog_watermark()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    watermark bigint;
    version_count bigint;
    minimum_version bigint;
    maximum_version bigint;
    source_count bigint;
BEGIN
    SELECT current_version INTO watermark
    FROM traffic_package_product_catalog_watermarks WHERE singleton;
    SELECT count(*), min(catalog_version), max(catalog_version)
      INTO version_count, minimum_version, maximum_version
    FROM traffic_package_product_catalog_versions;
    SELECT count(*) INTO source_count FROM traffic_package_product_snapshots;
    IF watermark IS NULL OR watermark <> version_count OR version_count <> source_count
       OR (version_count > 0 AND (minimum_version <> 1 OR maximum_version <> watermark)) THEN
        RAISE EXCEPTION 'traffic package product catalog watermark is inconsistent';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_product_snapshots_catalog_captured
AFTER INSERT ON traffic_package_product_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_product_catalog_watermark();
CREATE CONSTRAINT TRIGGER traffic_package_product_catalog_versions_watermark_consistent
AFTER INSERT ON traffic_package_product_catalog_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_product_catalog_watermark();
CREATE CONSTRAINT TRIGGER traffic_package_product_catalog_watermark_consistent
AFTER INSERT OR UPDATE ON traffic_package_product_catalog_watermarks
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_product_catalog_watermark();

CREATE FUNCTION assert_traffic_package_usage_watermark()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_tenant uuid;
    watermark bigint;
    version_count bigint;
    minimum_version bigint;
    maximum_version bigint;
    source_count bigint;
BEGIN
    target_tenant := NEW.tenant_scope_id;
    SELECT current_version INTO watermark
    FROM tenant_traffic_package_usage_watermarks
    WHERE tenant_scope_id = target_tenant;
    SELECT count(*), min(usage_version), max(usage_version)
      INTO version_count, minimum_version, maximum_version
    FROM traffic_package_usage_event_versions
    WHERE tenant_scope_id = target_tenant;
    SELECT count(*) INTO source_count
    FROM traffic_package_events WHERE tenant_scope_id = target_tenant;
    IF watermark IS NULL OR watermark <> version_count OR version_count <> source_count
       OR (version_count > 0 AND (minimum_version <> 1 OR maximum_version <> watermark))
       OR EXISTS (
           SELECT 1
           FROM traffic_package_usage_event_versions version
           JOIN traffic_package_events event ON event.id = version.event_id
           WHERE version.tenant_scope_id = target_tenant
             AND event.tenant_scope_id IS DISTINCT FROM version.tenant_scope_id
       ) THEN
        RAISE EXCEPTION 'traffic package usage watermark is inconsistent';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_events_usage_captured
AFTER INSERT ON traffic_package_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_usage_watermark();
CREATE CONSTRAINT TRIGGER traffic_package_usage_event_versions_watermark_consistent
AFTER INSERT ON traffic_package_usage_event_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_usage_watermark();
CREATE CONSTRAINT TRIGGER tenant_traffic_package_usage_watermark_consistent
AFTER INSERT OR UPDATE ON tenant_traffic_package_usage_watermarks
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_usage_watermark();

CREATE FUNCTION validate_traffic_package_grant_state_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    source_operation text;
    source_tenant uuid;
    source_grant uuid;
    source_revision bigint;
    source_remaining bigint;
    source_updated_at timestamptz;
    source_expires_at timestamptz;
    expected_status text;
BEGIN
    SELECT event.operation, entry.tenant_scope_id, entry.grant_id, entry.grant_revision,
           entry.remaining_after_bytes, entry.created_at, package_grant.expires_at
      INTO source_operation, source_tenant, source_grant, source_revision,
           source_remaining, source_updated_at, source_expires_at
    FROM traffic_package_ledger_entries entry
    JOIN traffic_package_events event ON event.id = entry.event_id
    JOIN traffic_package_grants package_grant ON package_grant.id = entry.grant_id
    WHERE entry.id = NEW.source_ledger_entry_id;
    expected_status := CASE source_operation
        WHEN 'grant' THEN 'active'
        WHEN 'consume' THEN CASE WHEN source_remaining = 0 THEN 'exhausted' ELSE 'active' END
        WHEN 'refund' THEN CASE WHEN source_updated_at >= source_expires_at THEN 'expired' ELSE 'active' END
        WHEN 'expire' THEN 'expired'
        WHEN 'reverse' THEN 'reversed'
    END;
    IF source_tenant IS DISTINCT FROM NEW.tenant_scope_id
       OR source_grant IS DISTINCT FROM NEW.grant_id
       OR source_revision IS DISTINCT FROM NEW.grant_revision
       OR source_remaining IS DISTINCT FROM NEW.remaining_bytes
       OR source_updated_at IS DISTINCT FROM NEW.updated_at
       OR expected_status IS DISTINCT FROM NEW.status THEN
        RAISE EXCEPTION 'traffic package grant state version does not match its source ledger entry';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_grant_state_versions_validate_source
BEFORE INSERT ON traffic_package_grant_state_versions
FOR EACH ROW EXECUTE FUNCTION validate_traffic_package_grant_state_version();

CREATE FUNCTION assert_traffic_package_state_watermark()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_tenant uuid;
    watermark bigint;
    version_count bigint;
    minimum_version bigint;
    maximum_version bigint;
    source_count bigint;
BEGIN
    target_tenant := NEW.tenant_scope_id;
    SELECT current_version INTO watermark
    FROM tenant_traffic_package_state_watermarks
    WHERE tenant_scope_id = target_tenant;
    SELECT count(*), min(state_version), max(state_version)
      INTO version_count, minimum_version, maximum_version
    FROM traffic_package_grant_state_versions
    WHERE tenant_scope_id = target_tenant;
    SELECT count(*) INTO source_count
    FROM traffic_package_ledger_entries WHERE tenant_scope_id = target_tenant;
    IF watermark IS NULL OR watermark <> version_count OR version_count <> source_count
       OR (version_count > 0 AND (minimum_version <> 1 OR maximum_version <> watermark)) THEN
        RAISE EXCEPTION 'traffic package grant state watermark is inconsistent';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_grant_state_versions_watermark_consistent
AFTER INSERT ON traffic_package_grant_state_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_state_watermark();
CREATE CONSTRAINT TRIGGER tenant_traffic_package_state_watermark_consistent
AFTER INSERT OR UPDATE ON tenant_traffic_package_state_watermarks
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_state_watermark();

CREATE FUNCTION assert_traffic_package_workload_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_request traffic_package_workload_requests%ROWTYPE;
    matching_binding bigint;
    matching_event bigint;
    automatic_events bigint;
BEGIN
    SELECT * INTO current_request
    FROM traffic_package_workload_requests WHERE id = NEW.id;
    SELECT count(*) INTO matching_binding
    FROM traffic_package_workload_bindings binding
    WHERE binding.id = current_request.binding_id
      AND binding.issuer = current_request.issuer
      AND binding.credential_reference = current_request.credential_reference
      AND binding.subject = current_request.subject
      AND binding.audience = current_request.audience
      AND binding.actor_scope_id = current_request.actor_scope_id
      AND binding.actor_user_id = current_request.actor_user_id
      AND current_request.permission = ANY(binding.permissions)
      AND binding.status = 'active'
      AND binding.revoked_at IS NULL
      AND binding.not_before <= current_request.occurred_at
      AND binding.expires_at > current_request.occurred_at;
    IF matching_binding <> 1 OR current_request.result IS NULL
       OR current_request.automatic_expired_count IS NULL
       OR current_request.completed_at IS NULL THEN
        RAISE EXCEPTION 'traffic package workload request binding is inconsistent';
    END IF;
    SELECT count(*) INTO matching_event
    FROM traffic_package_events event
    WHERE event.id = current_request.event_id
      AND event.bucket_id = current_request.bucket_id
      AND event.tenant_scope_id = current_request.tenant_scope_id
      AND event.operation = current_request.operation
      AND event.actor_scope_id = current_request.actor_scope_id
      AND event.actor_user_id = current_request.actor_user_id
      AND event.workload_binding_id = current_request.binding_id
      AND event.workload_permission = current_request.permission
      AND event.workload_cause IS NULL
      AND event.workload_parent_request_id IS NULL
      AND event.idempotency_key = current_request.idempotency_key
      AND event.request_digest = current_request.request_digest
      AND event.request_id = current_request.request_id
      AND event.trace_id = current_request.trace_id
      AND event.created_at = current_request.occurred_at;
    IF (current_request.result = 'succeeded' AND matching_event <> 1)
       OR (current_request.result IN ('insufficient_traffic', 'expiry_backlog')
           AND matching_event <> 0) THEN
        RAISE EXCEPTION 'traffic package workload request result is inconsistent';
    END IF;
    SELECT count(*) INTO automatic_events
    FROM traffic_package_events event
    WHERE event.workload_cause = 'automatic'
      AND event.workload_parent_request_id = current_request.id;
    IF automatic_events <> current_request.automatic_expired_count THEN
        RAISE EXCEPTION 'traffic package workload request automatic expiry count is inconsistent';
    END IF;
    IF current_request.result = 'expiry_backlog' AND (
           current_request.automatic_expired_count <> 100 OR NOT EXISTS (
               SELECT 1 FROM traffic_package_grants package_grant
               WHERE package_grant.bucket_id = current_request.bucket_id
                 AND package_grant.status IN ('active', 'exhausted')
                 AND package_grant.expires_at <= current_request.occurred_at
           )
       ) THEN
        RAISE EXCEPTION 'traffic package workload request backlog result is inconsistent';
    ELSIF current_request.result <> 'expiry_backlog' AND EXISTS (
        SELECT 1 FROM traffic_package_grants package_grant
        WHERE package_grant.bucket_id = current_request.bucket_id
          AND package_grant.status IN ('active', 'exhausted')
          AND package_grant.expires_at <= current_request.occurred_at
    ) THEN
        RAISE EXCEPTION 'traffic package workload request completed before expiry backlog was drained';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_workload_requests_consistent
AFTER INSERT OR UPDATE ON traffic_package_workload_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_workload_request();

CREATE FUNCTION assert_traffic_package_workload_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    binding_permissions text[];
    binding_scope uuid;
    binding_user uuid;
    binding_status text;
    binding_revoked_at timestamptz;
    binding_not_before timestamptz;
    binding_expires_at timestamptz;
    ledger_count bigint;
    audit_count bigint;
    parent_count bigint;
    parent_operation text;
    parent_expired_count integer;
    parent_due_before timestamptz;
    grant_expires_at timestamptz;
BEGIN
    IF NEW.workload_binding_id IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT permissions, actor_scope_id, actor_user_id, status, revoked_at,
           not_before, expires_at
      INTO binding_permissions, binding_scope, binding_user, binding_status,
           binding_revoked_at, binding_not_before, binding_expires_at
    FROM traffic_package_workload_bindings
    WHERE id = NEW.workload_binding_id;
    IF binding_scope IS DISTINCT FROM NEW.actor_scope_id
       OR binding_user IS DISTINCT FROM NEW.actor_user_id
       OR binding_status IS DISTINCT FROM 'active'
       OR binding_revoked_at IS NOT NULL
       OR binding_not_before > NEW.created_at
       OR binding_expires_at <= NEW.created_at
       OR NOT (NEW.workload_permission = ANY(binding_permissions))
       OR (NEW.operation <> 'expire' AND (
           NEW.workload_permission IS DISTINCT FROM
               traffic_package_workload_permission_for_operation(NEW.operation)
           OR NEW.workload_cause IS NOT NULL
           OR NEW.workload_parent_request_id IS NOT NULL
       )) THEN
        RAISE EXCEPTION 'traffic package event workload binding is inconsistent';
    END IF;
    IF NEW.operation <> 'expire' THEN
        SELECT count(*) INTO parent_count
        FROM traffic_package_workload_requests request
        WHERE request.result = 'succeeded'
          AND request.event_id = NEW.id
          AND request.binding_id = NEW.workload_binding_id
          AND request.actor_scope_id = NEW.actor_scope_id
          AND request.actor_user_id = NEW.actor_user_id
          AND request.bucket_id = NEW.bucket_id
          AND request.tenant_scope_id = NEW.tenant_scope_id
          AND request.operation = NEW.operation
          AND request.permission = NEW.workload_permission
          AND request.idempotency_key = NEW.idempotency_key
          AND request.request_digest = NEW.request_digest
          AND request.request_id = NEW.request_id
          AND request.trace_id = NEW.trace_id
          AND request.occurred_at = NEW.created_at
          AND request.completed_at IS NOT NULL;
        IF parent_count <> 1 THEN
            RAISE EXCEPTION 'traffic package primary workload request provenance is inconsistent';
        END IF;
    ELSIF NEW.workload_cause = 'explicit' THEN
        SELECT count(*), max(request.expired_count), max(request.due_before)
          INTO parent_count, parent_expired_count, parent_due_before
        FROM traffic_package_expire_requests request
        WHERE request.id = NEW.workload_parent_request_id
          AND request.binding_id = NEW.workload_binding_id
          AND request.actor_scope_id = NEW.actor_scope_id
          AND request.actor_user_id = NEW.actor_user_id
          AND request.bucket_id = NEW.bucket_id
          AND request.tenant_scope_id = NEW.tenant_scope_id
          AND request.request_id = NEW.request_id
          AND request.trace_id = NEW.trace_id
          AND request.created_at = NEW.created_at
          AND request.completed_at IS NOT NULL
          AND request.expired_count IS NOT NULL;
        IF NEW.workload_permission <> 'traffic_packages.expire' OR parent_count <> 1 OR
           parent_expired_count <> (
               SELECT count(*) FROM traffic_package_events event
               WHERE event.workload_cause = 'explicit'
                 AND event.workload_parent_request_id = NEW.workload_parent_request_id
           ) THEN
            RAISE EXCEPTION 'traffic package explicit expiry provenance is inconsistent';
        END IF;
        SELECT max(package_grant.expires_at) INTO grant_expires_at
        FROM traffic_package_ledger_entries entry
        JOIN traffic_package_grants package_grant ON package_grant.id = entry.grant_id
        WHERE entry.event_id = NEW.id;
        IF grant_expires_at IS NULL OR grant_expires_at > parent_due_before THEN
            RAISE EXCEPTION 'traffic package explicit expiry due boundary is inconsistent';
        END IF;
        parent_operation := 'expire';
    ELSIF NEW.workload_cause = 'automatic' THEN
        SELECT count(*), max(request.operation), max(request.automatic_expired_count),
               max(request.occurred_at)
          INTO parent_count, parent_operation, parent_expired_count, parent_due_before
        FROM traffic_package_workload_requests request
        WHERE request.id = NEW.workload_parent_request_id
          AND request.binding_id = NEW.workload_binding_id
          AND request.actor_scope_id = NEW.actor_scope_id
          AND request.actor_user_id = NEW.actor_user_id
          AND request.bucket_id = NEW.bucket_id
          AND request.tenant_scope_id = NEW.tenant_scope_id
          AND request.permission = NEW.workload_permission
          AND request.request_id = NEW.request_id
          AND request.trace_id = NEW.trace_id
          AND request.occurred_at = NEW.created_at
          AND request.result IS NOT NULL
          AND request.completed_at IS NOT NULL;
        IF parent_count <> 1 OR parent_operation NOT IN ('consume', 'refund', 'reverse') OR
           NEW.workload_permission IS DISTINCT FROM
               traffic_package_workload_permission_for_operation(parent_operation) OR
           parent_expired_count <> (
               SELECT count(*) FROM traffic_package_events event
               WHERE event.workload_cause = 'automatic'
                 AND event.workload_parent_request_id = NEW.workload_parent_request_id
           ) THEN
            RAISE EXCEPTION 'traffic package automatic expiry provenance is inconsistent';
        END IF;
        SELECT max(package_grant.expires_at) INTO grant_expires_at
        FROM traffic_package_ledger_entries entry
        JOIN traffic_package_grants package_grant ON package_grant.id = entry.grant_id
        WHERE entry.event_id = NEW.id;
        IF grant_expires_at IS NULL OR grant_expires_at > parent_due_before THEN
            RAISE EXCEPTION 'traffic package automatic expiry due boundary is inconsistent';
        END IF;
    ELSE
        RAISE EXCEPTION 'traffic package expiry provenance is missing';
    END IF;
    SELECT count(*) INTO ledger_count
    FROM traffic_package_ledger_entries entry
    WHERE entry.event_id = NEW.id
      AND entry.workload_binding_id = NEW.workload_binding_id
      AND entry.workload_permission = NEW.workload_permission
      AND entry.workload_cause IS NOT DISTINCT FROM NEW.workload_cause
      AND entry.workload_parent_request_id IS NOT DISTINCT FROM NEW.workload_parent_request_id;
    IF ledger_count = 0 OR ledger_count <> (
        SELECT count(*) FROM traffic_package_ledger_entries WHERE event_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'traffic package ledger workload binding is inconsistent';
    END IF;
    SELECT count(*) INTO audit_count
    FROM audit_events event
    WHERE event.scope_id = NEW.tenant_scope_id
      AND event.actor_user_id = NEW.actor_user_id
      AND event.action = 'traffic_package.' || NEW.operation
      AND event.resource_type = 'traffic_package_event'
      AND event.resource_id = NEW.id::text
      AND event.request_id = NEW.request_id
      AND event.result = 'success'
      AND event.payload ->> 'workload_binding_id' = NEW.workload_binding_id::text
      AND event.payload ->> 'workload_permission' = NEW.workload_permission
      AND event.payload ->> 'trace_id' = NEW.trace_id
      AND (
          (NEW.operation <> 'expire'
              AND NOT (event.payload ? 'workload_cause')
              AND NOT (event.payload ? 'workload_parent_request_id')
              AND NOT (event.payload ? 'workload_parent_operation')
              AND NOT (event.payload ? 'expire_request_id')) OR
          (NEW.operation = 'expire'
              AND event.payload ->> 'workload_cause' = NEW.workload_cause
              AND event.payload ->> 'workload_parent_request_id' =
                  NEW.workload_parent_request_id::text
              AND event.payload ->> 'workload_parent_operation' = parent_operation
              AND (
                  (NEW.workload_cause = 'explicit'
                      AND event.payload ->> 'expire_request_id' =
                          NEW.workload_parent_request_id::text) OR
                  (NEW.workload_cause = 'automatic'
                      AND (NOT (event.payload ? 'expire_request_id')
                           OR event.payload -> 'expire_request_id' = 'null'::jsonb))
              ))
      );
    IF audit_count <> 1 THEN
        RAISE EXCEPTION 'traffic package audit workload binding is inconsistent';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_events_workload_consistent
AFTER INSERT ON traffic_package_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_workload_event();

CREATE FUNCTION assert_traffic_package_workload_ledger_entry()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM traffic_package_events event
        WHERE event.id = NEW.event_id
          AND event.workload_binding_id IS NOT DISTINCT FROM NEW.workload_binding_id
          AND event.workload_permission IS NOT DISTINCT FROM NEW.workload_permission
          AND event.workload_cause IS NOT DISTINCT FROM NEW.workload_cause
          AND event.workload_parent_request_id IS NOT DISTINCT FROM NEW.workload_parent_request_id
    ) THEN
        RAISE EXCEPTION 'traffic package ledger entry does not match event workload source';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_ledger_entries_workload_consistent
AFTER INSERT ON traffic_package_ledger_entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_workload_ledger_entry();

CREATE FUNCTION assert_traffic_package_workload_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    source_event traffic_package_events%ROWTYPE;
    expected_parent_operation text;
    matching_audits bigint;
BEGIN
    IF NEW.resource_type <> 'traffic_package_event'
       OR NEW.action NOT IN (
           'traffic_package.consume',
           'traffic_package.refund',
           'traffic_package.reverse',
           'traffic_package.expire'
       ) THEN
        RETURN NULL;
    END IF;
    SELECT * INTO source_event
    FROM traffic_package_events event
    WHERE event.id::text = NEW.resource_id;
    IF source_event.id IS NULL THEN
        RAISE EXCEPTION 'traffic package audit source event is missing';
    END IF;
    IF source_event.workload_binding_id IS NULL THEN
        IF NEW.payload ? 'workload_binding_id'
           OR NEW.payload ? 'workload_permission'
           OR NEW.payload ? 'workload_cause'
           OR NEW.payload ? 'workload_parent_request_id'
           OR NEW.payload ? 'workload_parent_operation'
           OR NEW.payload ? 'expire_request_id' THEN
            RAISE EXCEPTION 'non-workload traffic package audit claims workload provenance';
        END IF;
        RETURN NULL;
    END IF;
    IF NEW.scope_id IS DISTINCT FROM source_event.tenant_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM source_event.actor_user_id
       OR NEW.action IS DISTINCT FROM 'traffic_package.' || source_event.operation
       OR NEW.request_id IS DISTINCT FROM source_event.request_id
       OR NEW.result IS DISTINCT FROM 'success'
       OR NEW.payload ->> 'workload_binding_id' IS DISTINCT FROM
           source_event.workload_binding_id::text
       OR NEW.payload ->> 'workload_permission' IS DISTINCT FROM
           source_event.workload_permission
       OR NEW.payload ->> 'trace_id' IS DISTINCT FROM source_event.trace_id THEN
        RAISE EXCEPTION 'traffic package workload audit source is inconsistent';
    END IF;
    IF source_event.operation = 'expire' THEN
        IF source_event.workload_cause = 'explicit' THEN
            expected_parent_operation := 'expire';
            IF NEW.payload ->> 'expire_request_id' IS DISTINCT FROM
               source_event.workload_parent_request_id::text THEN
                RAISE EXCEPTION 'traffic package explicit expiry audit source is inconsistent';
            END IF;
        ELSIF source_event.workload_cause = 'automatic' THEN
            SELECT request.operation INTO expected_parent_operation
            FROM traffic_package_workload_requests request
            WHERE request.id = source_event.workload_parent_request_id;
            IF NEW.payload ? 'expire_request_id'
               AND NEW.payload -> 'expire_request_id' <> 'null'::jsonb THEN
                RAISE EXCEPTION 'traffic package automatic expiry audit source is inconsistent';
            END IF;
        ELSE
            RAISE EXCEPTION 'traffic package expiry audit provenance is missing';
        END IF;
        IF NEW.payload ->> 'workload_cause' IS DISTINCT FROM source_event.workload_cause
           OR NEW.payload ->> 'workload_parent_request_id' IS DISTINCT FROM
               source_event.workload_parent_request_id::text
           OR NEW.payload ->> 'workload_parent_operation' IS DISTINCT FROM
               expected_parent_operation THEN
            RAISE EXCEPTION 'traffic package expiry audit provenance is inconsistent';
        END IF;
    ELSIF NEW.payload ? 'workload_cause'
          OR NEW.payload ? 'workload_parent_request_id'
          OR NEW.payload ? 'workload_parent_operation'
          OR NEW.payload ? 'expire_request_id' THEN
        RAISE EXCEPTION 'traffic package primary workload audit provenance is inconsistent';
    END IF;
    SELECT count(*) INTO matching_audits
    FROM audit_events event
    WHERE event.scope_id = source_event.tenant_scope_id
      AND event.action = 'traffic_package.' || source_event.operation
      AND event.resource_type = 'traffic_package_event'
      AND event.resource_id = source_event.id::text;
    IF matching_audits <> 1 THEN
        RAISE EXCEPTION 'traffic package workload audit must be one-to-one with its event';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER audit_events_traffic_package_workload_consistent
AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_workload_audit();

CREATE TABLE traffic_package_expire_requests (
    id uuid PRIMARY KEY,
    binding_id uuid NOT NULL REFERENCES traffic_package_workload_bindings(id) ON DELETE RESTRICT,
    issuer text NOT NULL,
    credential_reference text NOT NULL,
    subject text NOT NULL,
    audience text NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    bucket_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    currency text NOT NULL,
    metering_scope text NOT NULL,
    metering_version text NOT NULL,
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    due_before timestamptz NOT NULL,
    batch_limit integer NOT NULL CHECK (batch_limit BETWEEN 1 AND 100),
    expired_count integer CHECK (expired_count BETWEEN 0 AND batch_limit),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128
        AND trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, currency, metering_scope, metering_version, bucket_id)
        REFERENCES traffic_package_buckets(tenant_scope_id, currency, metering_scope, metering_version, id)
        ON DELETE RESTRICT,
    UNIQUE (binding_id, idempotency_key),
    CHECK (
        (completed_at IS NULL AND expired_count IS NULL) OR
        (completed_at IS NOT NULL AND expired_count IS NOT NULL AND completed_at >= created_at)
    )
);

CREATE FUNCTION protect_traffic_package_expire_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'traffic package expire requests cannot be truncated';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'traffic package expire requests cannot be deleted';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.expired_count IS NOT NULL THEN
            RAISE EXCEPTION 'traffic package expire request must start unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.completed_at IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
       OR NEW.issuer IS DISTINCT FROM OLD.issuer
       OR NEW.credential_reference IS DISTINCT FROM OLD.credential_reference
       OR NEW.subject IS DISTINCT FROM OLD.subject
       OR NEW.audience IS DISTINCT FROM OLD.audience
       OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.bucket_id IS DISTINCT FROM OLD.bucket_id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.metering_scope IS DISTINCT FROM OLD.metering_scope
       OR NEW.metering_version IS DISTINCT FROM OLD.metering_version
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.due_before IS DISTINCT FROM OLD.due_before
       OR NEW.batch_limit IS DISTINCT FROM OLD.batch_limit
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.completed_at IS NULL OR NEW.expired_count IS NULL
       OR NEW.completed_at < OLD.created_at THEN
        RAISE EXCEPTION 'traffic package expire request must complete exactly once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER traffic_package_expire_requests_protect
BEFORE INSERT OR UPDATE OR DELETE ON traffic_package_expire_requests
FOR EACH ROW EXECUTE FUNCTION protect_traffic_package_expire_request();
CREATE TRIGGER traffic_package_expire_requests_no_truncate
BEFORE TRUNCATE ON traffic_package_expire_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_traffic_package_expire_request();

CREATE FUNCTION assert_traffic_package_expire_request_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_request traffic_package_expire_requests%ROWTYPE;
    matching_binding bigint;
    matching_events bigint;
BEGIN
    SELECT * INTO current_request
    FROM traffic_package_expire_requests WHERE id = NEW.id;
    SELECT count(*) INTO matching_binding
    FROM traffic_package_workload_bindings binding
    WHERE binding.id = current_request.binding_id
      AND binding.issuer = current_request.issuer
      AND binding.credential_reference = current_request.credential_reference
      AND binding.subject = current_request.subject
      AND binding.audience = current_request.audience
      AND binding.actor_scope_id = current_request.actor_scope_id
      AND binding.actor_user_id = current_request.actor_user_id
      AND 'traffic_packages.expire' = ANY(binding.permissions)
      AND binding.status = 'active'
      AND binding.revoked_at IS NULL
      AND binding.not_before <= current_request.created_at
      AND binding.expires_at > current_request.created_at;
    IF matching_binding <> 1 OR current_request.completed_at IS NULL
       OR current_request.expired_count IS NULL THEN
        RAISE EXCEPTION 'traffic package expire request binding is inconsistent';
    END IF;
    SELECT count(*) INTO matching_events
    FROM traffic_package_events event
    JOIN audit_events audit_event
      ON audit_event.scope_id = event.tenant_scope_id
     AND audit_event.action = 'traffic_package.expire'
     AND audit_event.resource_type = 'traffic_package_event'
     AND audit_event.resource_id = event.id::text
     AND audit_event.payload ->> 'expire_request_id' = current_request.id::text
    WHERE event.workload_binding_id = current_request.binding_id
      AND event.workload_permission = 'traffic_packages.expire'
      AND event.workload_cause = 'explicit'
      AND event.workload_parent_request_id = current_request.id
      AND event.tenant_scope_id = current_request.tenant_scope_id
      AND event.bucket_id = current_request.bucket_id;
    IF matching_events <> current_request.expired_count THEN
        RAISE EXCEPTION 'traffic package expire request result is inconsistent';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER traffic_package_expire_requests_binding_consistent
AFTER INSERT OR UPDATE ON traffic_package_expire_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_traffic_package_expire_request_binding();

DO $$
DECLARE
    catalog_watermark bigint;
    catalog_count bigint;
BEGIN
    SELECT current_version INTO catalog_watermark
    FROM traffic_package_product_catalog_watermarks WHERE singleton;
    SELECT count(*) INTO catalog_count FROM traffic_package_product_catalog_versions;
    IF catalog_watermark IS DISTINCT FROM catalog_count
       OR catalog_count <> (SELECT count(*) FROM traffic_package_product_snapshots)
       OR EXISTS (
           SELECT 1
           FROM traffic_package_events event
           LEFT JOIN traffic_package_usage_event_versions version ON version.event_id = event.id
           WHERE version.event_id IS NULL OR version.tenant_scope_id <> event.tenant_scope_id
       )
       OR EXISTS (
           SELECT 1
           FROM traffic_package_ledger_entries entry
           LEFT JOIN traffic_package_grant_state_versions state
             ON state.source_ledger_entry_id = entry.id
           WHERE state.source_ledger_entry_id IS NULL
              OR state.tenant_scope_id <> entry.tenant_scope_id
       ) THEN
        RAISE EXCEPTION 'traffic package migration 066 projection backfill is inconsistent';
    END IF;
END;
$$;
