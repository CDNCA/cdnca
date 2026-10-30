ALTER TABLE users
    ADD COLUMN email text,
    ADD COLUMN phone text,
    ADD CONSTRAINT users_email_normalized_check CHECK (
        email IS NULL OR (
            email = lower(btrim(email)) AND
            char_length(email) BETWEEN 3 AND 254
        )
    ),
    ADD CONSTRAINT users_phone_normalized_check CHECK (
        phone IS NULL OR (
            phone = btrim(phone) AND
            phone ~ '^\+?[0-9]{6,20}$'
        )
    );

INSERT INTO permissions (name, description) VALUES
    ('identity.self.update', 'Update the current authenticated user profile'),
    ('identity.password.change', 'Re-authenticate and change the current user password');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
CROSS JOIN permissions
WHERE roles.system_role
  AND (
      (roles.name = 'platform_owner' AND permissions.name IN ('identity.self.update', 'identity.password.change')) OR
      (roles.name IN ('tenant_owner', 'tenant_viewer') AND permissions.name IN (
          'identity.self.update', 'identity.password.change'
      ))
  )
ON CONFLICT DO NOTHING;

CREATE TABLE identity_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'identity.user.create',
        'identity.user.update',
        'identity.self.update'
    )),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    secret_hash text,
    resource_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (operation = 'identity.user.create' AND secret_hash IS NOT NULL) OR
        (operation <> 'identity.user.create' AND secret_hash IS NULL)
    ),
    CHECK (
        (completed_at IS NULL AND response_status IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_status IS NOT NULL AND resource_id IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX identity_write_requests_scope_created_idx
    ON identity_write_requests (actor_scope_id, created_at DESC);
CREATE INDEX users_status_created_idx ON users (status, created_at DESC, id DESC);
