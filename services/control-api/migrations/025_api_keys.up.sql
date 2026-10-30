INSERT INTO permissions (name, description) VALUES
    ('api_keys.self.manage', 'Manage API keys owned by the current tenant user'),
    ('api_keys.admin.manage', 'Create pending API keys and revoke API keys for tenant users');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
CROSS JOIN permissions
WHERE roles.system_role
  AND (
      (roles.name = 'platform_owner' AND permissions.name = 'api_keys.admin.manage') OR
      (roles.name IN ('tenant_owner', 'tenant_viewer') AND permissions.name = 'api_keys.self.manage')
  )
ON CONFLICT DO NOTHING;

ALTER TABLE access_scopes
    ADD CONSTRAINT access_scopes_id_tenant_unique UNIQUE (id, tenant_id);

CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    key_id text NOT NULL UNIQUE CHECK (key_id ~ '^cfk_[A-Za-z0-9_-]{22}$'),
    key_prefix text NOT NULL UNIQUE CHECK (key_prefix = key_id || '.'),
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    scopes text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 32),
    secret_digest bytea CHECK (secret_digest IS NULL OR octet_length(secret_digest) = 32),
    status text NOT NULL CHECK (status IN ('pending_activation', 'active', 'revoked')),
    pending_expires_at timestamptz,
    expires_at timestamptz,
    last_used_at timestamptz,
    activated_at timestamptz,
    revoked_at timestamptz,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    revoked_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (status = 'pending_activation' AND secret_digest IS NULL AND pending_expires_at IS NOT NULL
            AND activated_at IS NULL AND revoked_at IS NULL AND revoked_by_user_id IS NULL) OR
        (status = 'active' AND secret_digest IS NOT NULL AND pending_expires_at IS NULL
            AND activated_at IS NOT NULL AND revoked_at IS NULL AND revoked_by_user_id IS NULL) OR
        (status = 'revoked' AND pending_expires_at IS NULL
            AND revoked_at IS NOT NULL AND revoked_by_user_id IS NOT NULL)
    ),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (updated_at >= created_at),
    CHECK (pending_expires_at IS NULL OR pending_expires_at > created_at),
    CHECK (activated_at IS NULL OR activated_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (
        last_used_at IS NULL OR (
            activated_at IS NOT NULL AND last_used_at >= activated_at AND
            (expires_at IS NULL OR last_used_at < expires_at)
        )
    )
);

CREATE INDEX api_keys_user_created_idx ON api_keys (scope_id, user_id, created_at DESC, id DESC);
CREATE INDEX api_keys_active_expiry_idx ON api_keys (key_id, expires_at) WHERE status = 'active';

CREATE FUNCTION protect_api_key_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'API keys cannot be deleted or truncated';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'revoked' OR NEW.revision <> 1 OR
           NEW.updated_at IS DISTINCT FROM NEW.created_at OR NEW.last_used_at IS NOT NULL OR
           (NEW.status = 'pending_activation' AND NEW.pending_expires_at <= NEW.created_at) OR
           (NEW.status = 'active' AND NEW.activated_at IS DISTINCT FROM NEW.created_at) THEN
            RAISE EXCEPTION 'invalid API key creation facts';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.key_id IS DISTINCT FROM OLD.key_id OR
       NEW.key_prefix IS DISTINCT FROM OLD.key_prefix OR
       NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
       NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
       NEW.user_id IS DISTINCT FROM OLD.user_id OR
       NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'API key identity and creation facts are immutable';
    END IF;
    IF OLD.status = 'revoked' THEN
        RAISE EXCEPTION 'revoked API key is immutable';
    END IF;

    IF NEW.last_used_at IS DISTINCT FROM OLD.last_used_at THEN
        IF NEW.name IS DISTINCT FROM OLD.name OR
           NEW.scopes IS DISTINCT FROM OLD.scopes OR
           NEW.secret_digest IS DISTINCT FROM OLD.secret_digest OR
           NEW.status IS DISTINCT FROM OLD.status OR
           NEW.pending_expires_at IS DISTINCT FROM OLD.pending_expires_at OR
           NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
           NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
           NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR
           NEW.revoked_by_user_id IS DISTINCT FROM OLD.revoked_by_user_id OR
           NEW.revision IS DISTINCT FROM OLD.revision OR
           NEW.updated_at IS DISTINCT FROM OLD.updated_at OR
           NEW.status <> 'active' OR NEW.last_used_at IS NULL OR
           (OLD.last_used_at IS NOT NULL AND NEW.last_used_at <= OLD.last_used_at) OR
           NEW.activated_at IS NULL OR NEW.last_used_at < NEW.activated_at OR
           (NEW.expires_at IS NOT NULL AND
               (transaction_timestamp() >= NEW.expires_at OR NEW.last_used_at >= NEW.expires_at)) THEN
            RAISE EXCEPTION 'API key usage update must be isolated, active, unexpired, and strictly monotonic';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'API key lifecycle revision and timestamps must advance monotonically';
    END IF;

    IF OLD.status = 'pending_activation' AND NEW.status = 'active' THEN
        IF OLD.secret_digest IS NOT NULL OR NEW.secret_digest IS NULL OR
           NEW.pending_expires_at IS NOT NULL OR
           NEW.name IS DISTINCT FROM OLD.name OR NEW.scopes IS DISTINCT FROM OLD.scopes OR
           NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
           NEW.activated_at IS NULL OR NEW.activated_at IS DISTINCT FROM NEW.updated_at OR
           NEW.activated_at < OLD.updated_at OR NEW.activated_at >= OLD.pending_expires_at OR
           transaction_timestamp() >= OLD.pending_expires_at OR
           (NEW.expires_at IS NOT NULL AND NEW.activated_at >= NEW.expires_at) OR
           (NEW.expires_at IS NOT NULL AND transaction_timestamp() >= NEW.expires_at) OR
           NEW.revoked_at IS NOT NULL OR NEW.revoked_by_user_id IS NOT NULL THEN
            RAISE EXCEPTION 'invalid API key activation transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'active' AND NEW.status = 'active' AND
       NEW.secret_digest IS NOT DISTINCT FROM OLD.secret_digest THEN
        IF (NEW.name IS NOT DISTINCT FROM OLD.name AND
            NEW.scopes IS NOT DISTINCT FROM OLD.scopes AND
            NEW.expires_at IS NOT DISTINCT FROM OLD.expires_at) OR
           NEW.pending_expires_at IS NOT NULL OR
           NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
           NEW.revoked_at IS NOT NULL OR NEW.revoked_by_user_id IS NOT NULL OR
           (NEW.expires_at IS NOT NULL AND NEW.updated_at >= NEW.expires_at) THEN
            RAISE EXCEPTION 'invalid API key metadata update';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'active' AND NEW.status = 'active' AND
       NEW.secret_digest IS DISTINCT FROM OLD.secret_digest THEN
        IF NEW.secret_digest IS NULL OR NEW.name IS DISTINCT FROM OLD.name OR
           NEW.scopes IS DISTINCT FROM OLD.scopes OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
           NEW.pending_expires_at IS NOT NULL OR
           NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
           NEW.revoked_at IS NOT NULL OR NEW.revoked_by_user_id IS NOT NULL OR
           (OLD.expires_at IS NOT NULL AND transaction_timestamp() >= OLD.expires_at) OR
           (NEW.expires_at IS NOT NULL AND NEW.updated_at >= NEW.expires_at) THEN
            RAISE EXCEPTION 'invalid API key rotation transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status IN ('pending_activation', 'active') AND NEW.status = 'revoked' THEN
        IF NEW.secret_digest IS DISTINCT FROM OLD.secret_digest OR
           NEW.name IS DISTINCT FROM OLD.name OR NEW.scopes IS DISTINCT FROM OLD.scopes OR
           NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
           NEW.pending_expires_at IS NOT NULL OR
           NEW.activated_at IS DISTINCT FROM OLD.activated_at OR
           NEW.revoked_at IS NULL OR NEW.revoked_at IS DISTINCT FROM NEW.updated_at OR
           NEW.revoked_at < COALESCE(OLD.last_used_at, OLD.activated_at, OLD.updated_at) OR
           NEW.revoked_by_user_id IS NULL THEN
            RAISE EXCEPTION 'invalid API key revocation transition';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid API key lifecycle transition';
END;
$$;

CREATE TRIGGER api_keys_lifecycle_protected
BEFORE INSERT OR UPDATE OR DELETE ON api_keys
FOR EACH ROW EXECUTE FUNCTION protect_api_key_lifecycle();

CREATE TRIGGER api_keys_no_truncate
BEFORE TRUNCATE ON api_keys
FOR EACH STATEMENT EXECUTE FUNCTION protect_api_key_lifecycle();

CREATE TABLE api_key_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    target_scope_id uuid NOT NULL,
    target_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'api_key.self.create',
        'api_key.self.update',
        'api_key.self.activate',
        'api_key.self.rotate',
        'api_key.self.revoke',
        'api_key.admin.create_pending',
        'api_key.admin.revoke'
    )),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid REFERENCES api_keys(id) ON DELETE RESTRICT,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_scope_id, target_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_body IS NOT NULL
            AND completed_at >= created_at)
    )
);

CREATE INDEX api_key_write_requests_scope_created_idx
    ON api_key_write_requests (target_scope_id, created_at DESC);

CREATE FUNCTION protect_api_key_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actor_valid boolean;
    target_valid boolean;
    resource_status text;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'API key write requests cannot be deleted or truncated';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.resource_id IS NOT NULL OR NEW.response_body IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'API key write request must start unfinished';
        END IF;

        SELECT scope.kind = 'tenant' AND tenant.status = 'active' AND
               target_user.status = 'active' AND target_membership.status = 'active'
          INTO target_valid
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id
        JOIN memberships target_membership
          ON target_membership.scope_id = scope.id AND target_membership.user_id = NEW.target_user_id
        JOIN users target_user ON target_user.id = target_membership.user_id
        WHERE scope.id = NEW.target_scope_id;

        IF NEW.operation LIKE 'api_key.self.%' THEN
            actor_valid := NEW.actor_user_id = NEW.target_user_id AND
                NEW.actor_scope_id = NEW.target_scope_id AND EXISTS (
                    SELECT 1
                    FROM role_assignments assignment
                    JOIN role_permissions permission ON permission.role_id = assignment.role_id
                    WHERE assignment.scope_id = NEW.actor_scope_id
                      AND assignment.user_id = NEW.actor_user_id
                      AND permission.permission_name = 'api_keys.self.manage'
                );
        ELSE
            SELECT scope.kind = 'platform' AND actor_user.status = 'active' AND
                   actor_membership.status = 'active' AND EXISTS (
                       SELECT 1
                       FROM role_assignments assignment
                       JOIN role_permissions permission ON permission.role_id = assignment.role_id
                       WHERE assignment.scope_id = NEW.actor_scope_id
                         AND assignment.user_id = NEW.actor_user_id
                         AND permission.permission_name = 'api_keys.admin.manage'
                   )
              INTO actor_valid
            FROM access_scopes scope
            JOIN memberships actor_membership
              ON actor_membership.scope_id = scope.id AND actor_membership.user_id = NEW.actor_user_id
            JOIN users actor_user ON actor_user.id = actor_membership.user_id
            WHERE scope.id = NEW.actor_scope_id;
            actor_valid := actor_valid AND NEW.actor_user_id <> NEW.target_user_id;
        END IF;

        IF actor_valid IS DISTINCT FROM true OR target_valid IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'invalid API key write request principal boundary';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'completed API key write request is immutable';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR
       NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id OR
       NEW.target_scope_id IS DISTINCT FROM OLD.target_scope_id OR
       NEW.target_user_id IS DISTINCT FROM OLD.target_user_id OR
       NEW.operation IS DISTINCT FROM OLD.operation OR
       NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
       NEW.request_digest IS DISTINCT FROM OLD.request_digest OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.resource_id IS NULL OR NEW.response_body IS NULL OR NEW.completed_at IS NULL OR
       NEW.completed_at < OLD.created_at OR
       NEW.response_body->>'id' IS DISTINCT FROM NEW.resource_id::text OR
       NEW.response_body::text ~* '"[^\"]*secret[^\"]*"[[:space:]]*:' THEN
        RAISE EXCEPTION 'API key write request must complete atomically without secret material';
    END IF;

    SELECT status INTO resource_status
    FROM api_keys
    WHERE id = NEW.resource_id AND scope_id = NEW.target_scope_id AND user_id = NEW.target_user_id;
    IF resource_status IS NULL OR
       (NEW.operation IN ('api_key.self.create', 'api_key.self.update',
                          'api_key.self.activate', 'api_key.self.rotate') AND resource_status <> 'active') OR
       (NEW.operation = 'api_key.admin.create_pending' AND resource_status <> 'pending_activation') OR
       (NEW.operation IN ('api_key.self.revoke', 'api_key.admin.revoke') AND resource_status <> 'revoked') THEN
        RAISE EXCEPTION 'API key write request resource does not match its target and operation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER api_key_write_requests_protected
BEFORE INSERT OR UPDATE OR DELETE ON api_key_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_api_key_write_request();

CREATE TRIGGER api_key_write_requests_no_truncate
BEFORE TRUNCATE ON api_key_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_api_key_write_request();
