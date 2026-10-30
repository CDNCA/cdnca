INSERT INTO permissions (name, description) VALUES
    ('url_auth_policies.read', 'Read tenant URL authentication policies'),
    ('url_auth_policies.manage', 'Create, edit, rotate, revoke, and disable tenant URL authentication policies');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
CROSS JOIN permissions
WHERE roles.system_role
  AND (
      (roles.name = 'platform_owner' AND permissions.name IN ('url_auth_policies.read', 'url_auth_policies.manage')) OR
      (roles.name = 'tenant_owner' AND permissions.name IN ('url_auth_policies.read', 'url_auth_policies.manage')) OR
      (roles.name = 'tenant_viewer' AND permissions.name = 'url_auth_policies.read')
  )
ON CONFLICT DO NOTHING;

CREATE TABLE url_auth_policies (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT true,
    algorithm text NOT NULL CHECK (algorithm = 'hmac-sha256'),
    migration_marker text CHECK (migration_marker IN ('cdnfly_type_a_md5', 'cdnfly_type_b_md5')),
    signature_parameter text NOT NULL,
    expiration_parameter text NOT NULL,
    key_id_parameter text NOT NULL,
    bind_client_ip boolean NOT NULL DEFAULT false,
    max_clock_skew_seconds integer NOT NULL CHECK (max_clock_skew_seconds BETWEEN 0 AND 300),
    max_validity_seconds integer NOT NULL CHECK (max_validity_seconds BETWEEN 1 AND 86400),
    max_signature_uses integer NOT NULL CHECK (max_signature_uses BETWEEN 0 AND 1000000),
    excluded_query_parameters text[] NOT NULL DEFAULT ARRAY[]::text[],
    trusted_proxy_cidrs text[] NOT NULL DEFAULT ARRAY[]::text[],
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (scope_id, site_id),
    UNIQUE (scope_id, id),
    CHECK (signature_parameter <> expiration_parameter),
    CHECK (signature_parameter <> key_id_parameter),
    CHECK (expiration_parameter <> key_id_parameter),
    CHECK (cardinality(excluded_query_parameters) <= 32),
    CHECK (cardinality(trusted_proxy_cidrs) <= 64)
);

CREATE UNIQUE INDEX url_auth_policies_scope_name_lower_idx
    ON url_auth_policies (scope_id, lower(name));
CREATE INDEX url_auth_policies_scope_created_idx
    ON url_auth_policies (scope_id, created_at DESC, id DESC);

CREATE TABLE url_auth_policy_keys (
    policy_id uuid NOT NULL REFERENCES url_auth_policies(id) ON DELETE RESTRICT,
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
    role text NOT NULL CHECK (role IN ('current', 'previous', 'revoked')),
    kek_key_id text NOT NULL CHECK (char_length(kek_key_id) BETWEEN 1 AND 128),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 16),
    secret_digest bytea NOT NULL CHECK (octet_length(secret_digest) = 32),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (policy_id, key_id),
    CHECK ((role = 'revoked' AND revoked_at IS NOT NULL) OR (role <> 'revoked' AND revoked_at IS NULL))
);

CREATE UNIQUE INDEX url_auth_policy_keys_one_current_idx
    ON url_auth_policy_keys (policy_id) WHERE role = 'current';
CREATE UNIQUE INDEX url_auth_policy_keys_one_previous_idx
    ON url_auth_policy_keys (policy_id) WHERE role = 'previous';

CREATE TABLE url_auth_policy_versions (
    policy_id uuid NOT NULL REFERENCES url_auth_policies(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    edge_snapshot bytea NOT NULL CHECK (octet_length(edge_snapshot) > 0),
    snapshot_sha256 bytea NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (policy_id, revision)
);

CREATE TABLE url_auth_policy_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'url_auth_policy.create', 'url_auth_policy.update',
        'url_auth_policy.rotate', 'url_auth_policy.revoke'
    )),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid REFERENCES url_auth_policies(id) ON DELETE RESTRICT,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX url_auth_policy_write_requests_scope_created_idx
    ON url_auth_policy_write_requests (target_scope_id, created_at DESC);
