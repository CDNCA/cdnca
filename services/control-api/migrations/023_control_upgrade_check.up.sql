INSERT INTO permissions (name, description) VALUES
    ('control.upgrades.check', 'Check whether this control-plane installation is eligible for an upgrade');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, 'control.upgrades.check'
FROM roles
WHERE roles.system_role AND roles.name = 'platform_owner'
ON CONFLICT DO NOTHING;

CREATE TABLE control_upgrade_check_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation = 'control.upgrade.check'),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_status integer CHECK (response_status = 200),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_status IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_status = 200 AND response_body IS NOT NULL)
    )
);

CREATE INDEX control_upgrade_check_requests_scope_created_idx
    ON control_upgrade_check_requests (actor_scope_id, created_at DESC);
