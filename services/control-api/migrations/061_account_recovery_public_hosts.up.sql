CREATE FUNCTION account_recovery_public_hostname_valid(candidate text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT octet_length(candidate) = char_length(candidate)
       AND char_length(candidate) BETWEEN 3 AND 253
       AND candidate = lower(candidate)
       AND candidate ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:[.][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
       AND candidate !~ '^[0-9]+(?:[.][0-9]+)+$'
       AND candidate !~ '(^|[.])(localhost|local|internal)$'
       AND NOT EXISTS (
           SELECT 1
           FROM regexp_split_to_table(candidate, '[.]') AS label
           WHERE char_length(label) > 63
       );
$$;

CREATE TABLE account_recovery_public_host_revisions (
    hostname text NOT NULL CHECK (account_recovery_public_hostname_valid(hostname)),
    revision bigint NOT NULL CHECK (revision > 0),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('active', 'inactive')),
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    trace_id text NOT NULL CHECK (
        trace_id ~ '^[0-9a-f]{32}$' AND trace_id <> repeat('0', 32)
    ),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (hostname, revision),
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (hostname, revision, tenant_id, tenant_scope_id, state)
);

CREATE TABLE account_recovery_public_hosts (
    hostname text PRIMARY KEY CHECK (account_recovery_public_hostname_valid(hostname)),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('active', 'inactive')),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (hostname, current_revision, tenant_id, tenant_scope_id, state)
        REFERENCES account_recovery_public_host_revisions(
            hostname, revision, tenant_id, tenant_scope_id, state
        ) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at)
);

CREATE INDEX account_recovery_public_hosts_active_tenant_idx
    ON account_recovery_public_hosts (tenant_id, tenant_scope_id, hostname)
    WHERE state = 'active';

CREATE FUNCTION validate_account_recovery_public_host_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_status text;
    actor_allowed boolean;
    head_revision bigint;
BEGIN
    SELECT tenant.status INTO target_status
    FROM access_scopes scope
    JOIN tenants tenant ON tenant.id = scope.tenant_id
    WHERE scope.id = NEW.tenant_scope_id
      AND scope.tenant_id = NEW.tenant_id
      AND scope.kind = 'tenant';
    IF NOT FOUND OR (NEW.state = 'active' AND target_status <> 'active') THEN
        RAISE EXCEPTION 'invalid account recovery public host target';
    END IF;

    SELECT account.status = 'active' AND membership.status = 'active' AND
           (actor_scope.kind = 'platform' OR actor_scope.id = NEW.tenant_scope_id)
      INTO actor_allowed
    FROM access_scopes actor_scope
    JOIN memberships membership
      ON membership.scope_id = actor_scope.id
     AND membership.user_id = NEW.actor_user_id
    JOIN users account ON account.id = membership.user_id
    WHERE actor_scope.id = NEW.actor_scope_id;
    IF actor_allowed IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid account recovery public host actor';
    END IF;

    IF NEW.revision = 1 THEN
        IF EXISTS (
            SELECT 1 FROM account_recovery_public_hosts WHERE hostname = NEW.hostname
        ) THEN
            RAISE EXCEPTION 'account recovery public host already exists';
        END IF;
    ELSE
        SELECT current_revision INTO head_revision
        FROM account_recovery_public_hosts
        WHERE hostname = NEW.hostname
        FOR UPDATE;
        IF head_revision IS NULL OR NEW.revision <> head_revision + 1 THEN
            RAISE EXCEPTION 'account recovery public host revision is not contiguous';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_public_host_revisions_validate
BEFORE INSERT ON account_recovery_public_host_revisions
FOR EACH ROW EXECUTE FUNCTION validate_account_recovery_public_host_revision();

CREATE FUNCTION validate_account_recovery_public_host_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_revision <> 1 THEN
            RAISE EXCEPTION 'account recovery public host must start at revision one';
        END IF;
    ELSE
        IF NEW.hostname IS DISTINCT FROM OLD.hostname OR
           NEW.created_at IS DISTINCT FROM OLD.created_at OR
           NEW.current_revision <> OLD.current_revision + 1 OR
           NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'invalid account recovery public host projection update';
        END IF;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM account_recovery_public_host_revisions revision
        WHERE revision.hostname = NEW.hostname
          AND revision.revision = NEW.current_revision
          AND revision.tenant_id = NEW.tenant_id
          AND revision.tenant_scope_id = NEW.tenant_scope_id
          AND revision.state = NEW.state
    ) THEN
        RAISE EXCEPTION 'account recovery public host projection lacks revision fact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_public_hosts_validate
BEFORE INSERT OR UPDATE ON account_recovery_public_hosts
FOR EACH ROW EXECUTE FUNCTION validate_account_recovery_public_host_projection();

CREATE FUNCTION require_account_recovery_public_host_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM account_recovery_public_hosts binding
        WHERE binding.hostname = NEW.hostname
          AND binding.current_revision = NEW.revision
          AND binding.tenant_id = NEW.tenant_id
          AND binding.tenant_scope_id = NEW.tenant_scope_id
          AND binding.state = NEW.state
    ) THEN
        RAISE EXCEPTION 'account recovery public host revision was not projected';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER account_recovery_public_host_revision_projection_required
AFTER INSERT ON account_recovery_public_host_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_account_recovery_public_host_projection();

CREATE FUNCTION prevent_account_recovery_public_host_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'account recovery public host revisions are append-only';
END;
$$;

CREATE TRIGGER account_recovery_public_host_revisions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON account_recovery_public_host_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_recovery_public_host_fact_mutation();

CREATE FUNCTION prevent_account_recovery_public_host_removal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'account recovery public host projections cannot be deleted or truncated';
END;
$$;

CREATE TRIGGER account_recovery_public_hosts_no_delete
BEFORE DELETE OR TRUNCATE ON account_recovery_public_hosts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_recovery_public_host_removal();
