CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    display_name text NOT NULL CHECK (display_name = btrim(display_name) AND display_name <> ''),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
    default_timezone text NOT NULL DEFAULT 'UTC',
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE access_scopes (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('platform', 'tenant')),
    tenant_id uuid REFERENCES tenants(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (kind = 'platform' AND tenant_id IS NULL) OR
        (kind = 'tenant' AND tenant_id IS NOT NULL)
    ),
    UNIQUE (tenant_id)
);

CREATE UNIQUE INDEX access_scopes_single_platform_idx
    ON access_scopes ((kind)) WHERE kind = 'platform';

CREATE TABLE users (
    id uuid PRIMARY KEY,
    username text NOT NULL CHECK (
        username = lower(btrim(username)) AND
        length(username) BETWEEN 3 AND 128
    ),
    display_name text NOT NULL CHECK (display_name = btrim(display_name) AND display_name <> ''),
    password_hash text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_username_lower_idx ON users (lower(username));

CREATE TABLE memberships (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_id, user_id)
);

CREATE TABLE permissions (
    name text PRIMARY KEY CHECK (name = lower(btrim(name)) AND name <> ''),
    description text NOT NULL
);

INSERT INTO permissions (name, description) VALUES
    ('identity.self.read', 'Read the current authenticated identity'),
    ('identity.users.manage', 'Manage users and memberships'),
    ('identity.roles.manage', 'Manage roles and permission assignments'),
    ('platform.admin', 'Administer all platform-scoped control-plane resources');

CREATE TABLE roles (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name = lower(btrim(name)) AND name <> ''),
    description text NOT NULL DEFAULT '',
    system_role boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, name),
    UNIQUE (scope_id, id)
);

CREATE TABLE role_permissions (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_name text NOT NULL REFERENCES permissions(name) ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission_name)
);

CREATE TABLE role_assignments (
    scope_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_id, user_id, role_id),
    FOREIGN KEY (scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (scope_id, role_id)
        REFERENCES roles(scope_id, id) ON DELETE CASCADE
);

CREATE TABLE auth_sessions (
    id uuid PRIMARY KEY,
    family_id uuid NOT NULL,
    parent_id uuid,
    replaced_by_id uuid,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL,
    refresh_token_hash bytea NOT NULL UNIQUE CHECK (octet_length(refresh_token_hash) = 32),
    user_agent text NOT NULL DEFAULT '',
    source_ip inet,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    revocation_reason text,
    FOREIGN KEY (scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at),
    CHECK ((revoked_at IS NULL AND revocation_reason IS NULL) OR
           (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL))
);

ALTER TABLE auth_sessions
    ADD CONSTRAINT auth_sessions_parent_fk
        FOREIGN KEY (parent_id) REFERENCES auth_sessions(id) ON DELETE RESTRICT,
    ADD CONSTRAINT auth_sessions_replaced_by_fk
        FOREIGN KEY (replaced_by_id) REFERENCES auth_sessions(id) ON DELETE RESTRICT;

CREATE INDEX auth_sessions_family_idx ON auth_sessions (family_id);
CREATE INDEX auth_sessions_user_scope_idx ON auth_sessions (user_id, scope_id);
CREATE INDEX auth_sessions_active_expiry_idx ON auth_sessions (expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    stream_position bigint NOT NULL CHECK (stream_position > 0),
    actor_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (action <> ''),
    resource_type text NOT NULL CHECK (resource_type <> ''),
    resource_id text NOT NULL CHECK (resource_id <> ''),
    request_id text NOT NULL CHECK (request_id <> ''),
    result text NOT NULL CHECK (result IN ('success', 'denied', 'failure')),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    previous_hash bytea,
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    occurred_at timestamptz NOT NULL,
    UNIQUE (scope_id, stream_position),
    CHECK (
        (stream_position = 1 AND previous_hash IS NULL) OR
        (stream_position > 1 AND octet_length(previous_hash) = 32)
    )
);

CREATE INDEX audit_events_scope_time_idx ON audit_events (scope_id, occurred_at DESC);

CREATE FUNCTION prevent_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_audit_event_mutation();
