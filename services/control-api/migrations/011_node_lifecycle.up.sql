INSERT INTO permissions (name, description) VALUES
    ('nodes.read', 'Read platform node inventory and lifecycle state'),
    ('nodes.manage', 'Manage platform node metadata and administrative lifecycle state');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
JOIN permissions ON permissions.name IN ('nodes.read', 'nodes.manage')
WHERE roles.system_role AND roles.name = 'platform_owner'
ON CONFLICT DO NOTHING;

CREATE TABLE node_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('node.update', 'node.batch_admin_state')),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX node_write_requests_scope_created_idx
    ON node_write_requests (actor_scope_id, created_at DESC);
