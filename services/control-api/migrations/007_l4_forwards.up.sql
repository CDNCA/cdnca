INSERT INTO permissions (name, description) VALUES
    ('streams.read', 'Read layer-four forwarding rules in the active tenant scope'),
    ('streams.manage', 'Create, edit, and delete layer-four forwarding rules in the active tenant scope');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
CROSS JOIN permissions
WHERE roles.system_role
  AND permissions.name IN ('streams.read', 'streams.manage')
  AND (
      (roles.name = 'tenant_owner') OR
      (roles.name = 'tenant_viewer' AND permissions.name = 'streams.read')
  )
ON CONFLICT DO NOTHING;

CREATE TABLE l4_forwards (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    protocol text NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    listen_address text NOT NULL DEFAULT '*' CHECK (listen_address = '*'),
    listen_port integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    upstream_address inet NOT NULL,
    upstream_port integer NOT NULL CHECK (upstream_port BETWEEN 1 AND 65535),
    connect_timeout_ms integer NOT NULL CHECK (connect_timeout_ms BETWEEN 50 AND 30000),
    response_timeout_ms integer NOT NULL CHECK (response_timeout_ms BETWEEN 100 AND 600000),
    proxy_protocol_v1 boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    FOREIGN KEY (scope_id, owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (protocol = 'tcp' OR NOT proxy_protocol_v1)
);

CREATE UNIQUE INDEX l4_forwards_protocol_port_active_idx
    ON l4_forwards (protocol, listen_port) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX l4_forwards_scope_name_lower_active_idx
    ON l4_forwards (scope_id, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX l4_forwards_scope_created_active_idx
    ON l4_forwards (scope_id, created_at DESC, id DESC) WHERE deleted_at IS NULL;
CREATE INDEX l4_forwards_owner_created_active_idx
    ON l4_forwards (owner_user_id, created_at DESC, id DESC) WHERE deleted_at IS NULL;

CREATE TABLE l4_scope_publish_counters (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    current_version bigint NOT NULL CHECK (current_version > 0)
);

CREATE TABLE l4_publish_intents (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    stream_id uuid NOT NULL REFERENCES l4_forwards(id) ON DELETE RESTRICT,
    version bigint NOT NULL CHECK (version > 0),
    operation text NOT NULL CHECK (operation IN ('create', 'update', 'delete')),
    desired_state text NOT NULL CHECK (desired_state IN ('enabled', 'disabled', 'deleted')),
    resource_revision bigint NOT NULL CHECK (resource_revision > 0),
    runtime_spec jsonb NOT NULL CHECK (jsonb_typeof(runtime_spec) = 'object'),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, version)
);

CREATE FUNCTION prevent_l4_publish_intent_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'l4_publish_intents is append-only';
END;
$$;

CREATE TRIGGER l4_publish_intents_append_only
BEFORE UPDATE OR DELETE ON l4_publish_intents
FOR EACH ROW EXECUTE FUNCTION prevent_l4_publish_intent_mutation();

CREATE TABLE l4_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('stream.create', 'stream.update', 'stream.delete')),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_status IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_status IS NOT NULL AND resource_id IS NOT NULL)
    )
);

CREATE INDEX l4_write_requests_scope_created_idx
    ON l4_write_requests (target_scope_id, created_at DESC);
