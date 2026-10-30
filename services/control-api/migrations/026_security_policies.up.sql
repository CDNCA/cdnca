INSERT INTO permissions (name, description) VALUES
    ('security_policies.read', 'Read tenant WAF, CC, and ACL security policies'),
    ('security_policies.manage', 'Create, edit, evaluate, and delete tenant WAF, CC, and ACL security policies');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
CROSS JOIN permissions
WHERE roles.system_role
  AND (
      (roles.name = 'platform_owner' AND permissions.name IN ('security_policies.read', 'security_policies.manage')) OR
      (roles.name = 'tenant_owner' AND permissions.name IN ('security_policies.read', 'security_policies.manage')) OR
      (roles.name = 'tenant_viewer' AND permissions.name = 'security_policies.read')
  )
ON CONFLICT DO NOTHING;

CREATE TABLE security_policies (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('cc', 'acl')),
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    enabled boolean NOT NULL DEFAULT true,
    default_action text NOT NULL CHECK (default_action IN ('allow', 'block')),
    rules jsonb NOT NULL CHECK (jsonb_typeof(rules) = 'array' AND jsonb_array_length(rules) BETWEEN 1 AND 100),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    FOREIGN KEY (scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX security_policies_scope_kind_name_active_idx
    ON security_policies (scope_id, kind, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX security_policies_scope_created_active_idx
    ON security_policies (scope_id, created_at DESC, id DESC) WHERE deleted_at IS NULL;
CREATE INDEX security_policies_owner_created_active_idx
    ON security_policies (owner_user_id, created_at DESC, id DESC) WHERE deleted_at IS NULL;

CREATE TABLE security_policy_versions (
    policy_id uuid NOT NULL REFERENCES security_policies(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (policy_id, revision)
);

CREATE TABLE security_policy_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'security_policy.create', 'security_policy.update', 'security_policy.delete'
    )),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid REFERENCES security_policies(id) ON DELETE RESTRICT,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX security_policy_write_requests_scope_created_idx
    ON security_policy_write_requests (target_scope_id, created_at DESC);
