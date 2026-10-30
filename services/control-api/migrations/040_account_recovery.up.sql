CREATE TABLE account_recovery_write_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN ('request', 'reset')),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (octet_length(request_id) BETWEEN 1 AND 128),
    trace_id text NOT NULL CHECK (octet_length(trace_id) BETWEEN 1 AND 128),
    resource_id uuid,
    response_code text CHECK (response_code IN (
        'accepted', 'rate_limited', 'completed', 'invalid_token',
        'password_reused', 'principal_changed'
    )),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (scope_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_code IS NULL AND resource_id IS NULL) OR
        (completed_at IS NOT NULL AND response_code IS NOT NULL AND completed_at >= created_at)
    )
);

CREATE INDEX account_recovery_write_requests_created_idx
    ON account_recovery_write_requests (scope_id, created_at DESC);

CREATE TABLE account_recovery_challenges (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    password_revision bigint NOT NULL CHECK (password_revision > 0),
    issued_by_write_id uuid NOT NULL UNIQUE REFERENCES account_recovery_write_requests(id) ON DELETE RESTRICT,
    completion_write_id uuid UNIQUE REFERENCES account_recovery_write_requests(id) ON DELETE RESTRICT,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    consumed_at timestamptz,
    revoked_at timestamptz,
    terminal_reason text CHECK (terminal_reason IN ('consumed', 'superseded', 'principal_changed')),
    FOREIGN KEY (scope_id, user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (consumed_at IS NULL AND revoked_at IS NULL AND terminal_reason IS NULL AND completion_write_id IS NULL) OR
        (consumed_at IS NOT NULL AND revoked_at IS NULL AND terminal_reason = 'consumed' AND completion_write_id IS NOT NULL) OR
        (consumed_at IS NULL AND revoked_at IS NOT NULL AND terminal_reason IN ('superseded', 'principal_changed') AND completion_write_id IS NULL)
    )
);

CREATE INDEX account_recovery_challenges_user_active_idx
    ON account_recovery_challenges (scope_id, user_id, issued_at DESC)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX account_recovery_challenges_expiry_idx
    ON account_recovery_challenges (expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE account_recovery_rate_windows (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    identifier_kind text NOT NULL CHECK (identifier_kind IN ('subject', 'source')),
    identifier_digest bytea NOT NULL CHECK (octet_length(identifier_digest) = 32),
    window_started_at timestamptz NOT NULL,
    request_count integer NOT NULL CHECK (request_count > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (scope_id, identifier_kind, identifier_digest, window_started_at)
);

CREATE INDEX account_recovery_rate_windows_cleanup_idx
    ON account_recovery_rate_windows (window_started_at);

CREATE FUNCTION validate_account_recovery_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.scope_id AND scope.kind = 'tenant'
          AND scope.tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'account recovery requires the matching tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_write_requests_scope
BEFORE INSERT ON account_recovery_write_requests
FOR EACH ROW EXECUTE FUNCTION validate_account_recovery_scope();
CREATE TRIGGER account_recovery_rate_windows_scope
BEFORE INSERT ON account_recovery_rate_windows
FOR EACH ROW EXECUTE FUNCTION validate_account_recovery_scope();

CREATE FUNCTION validate_account_recovery_challenge_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.scope_id AND scope.kind = 'tenant'
          AND scope.tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'account recovery requires the matching tenant scope';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM users user_row
        JOIN memberships membership
          ON membership.user_id = user_row.id AND membership.scope_id = NEW.scope_id
        JOIN account_recovery_write_requests write_request
          ON write_request.id = NEW.issued_by_write_id
        WHERE user_row.id = NEW.user_id
          AND user_row.status = 'active' AND membership.status = 'active'
          AND user_row.revision = NEW.password_revision
          AND write_request.tenant_id = NEW.tenant_id
          AND write_request.scope_id = NEW.scope_id
          AND write_request.operation = 'request'
          AND write_request.completed_at IS NULL
          AND write_request.created_at = NEW.issued_at
    ) THEN
        RAISE EXCEPTION 'invalid account recovery challenge issuance';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_challenges_validate_insert
BEFORE INSERT ON account_recovery_challenges
FOR EACH ROW EXECUTE FUNCTION validate_account_recovery_challenge_insert();

CREATE FUNCTION protect_account_recovery_challenge()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'account recovery facts are append-only';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'account recovery challenge transition is already terminal';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
       NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
       NEW.user_id IS DISTINCT FROM OLD.user_id OR
       NEW.token_digest IS DISTINCT FROM OLD.token_digest OR
       NEW.subject_digest IS DISTINCT FROM OLD.subject_digest OR
       NEW.password_revision IS DISTINCT FROM OLD.password_revision OR
       NEW.issued_by_write_id IS DISTINCT FROM OLD.issued_by_write_id OR
       NEW.issued_at IS DISTINCT FROM OLD.issued_at OR
       NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'account recovery facts are append-only';
    END IF;

    IF NEW.consumed_at IS NOT NULL AND NEW.revoked_at IS NULL AND
       NEW.terminal_reason = 'consumed' AND NEW.completion_write_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1
            FROM account_recovery_write_requests write_request
            JOIN users user_row ON user_row.id = OLD.user_id
            WHERE write_request.id = NEW.completion_write_id
              AND write_request.tenant_id = OLD.tenant_id
              AND write_request.scope_id = OLD.scope_id
              AND write_request.operation = 'reset'
              AND write_request.completed_at IS NULL
              AND user_row.revision = OLD.password_revision + 1
              AND user_row.updated_at = NEW.consumed_at
              AND NOT EXISTS (
                  SELECT 1 FROM auth_sessions session
                  WHERE session.user_id = OLD.user_id AND session.revoked_at IS NULL
              )
              AND EXISTS (
                  SELECT 1 FROM audit_events event
                  WHERE event.scope_id = OLD.scope_id
                    AND event.action = 'identity.account_recovery.reset'
                    AND event.resource_type = 'account_recovery_challenge'
                    AND event.resource_id = OLD.id::text
                    AND event.request_id = write_request.request_id
                    AND event.result = 'success'
              )
        ) THEN
            RAISE EXCEPTION 'account recovery challenge transition is not authorized';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.consumed_at IS NULL AND NEW.revoked_at IS NOT NULL AND
       NEW.completion_write_id IS NULL AND NEW.terminal_reason = 'superseded' THEN
        IF NOT EXISTS (
            SELECT 1 FROM account_recovery_challenges replacement
            WHERE replacement.id <> OLD.id
              AND replacement.scope_id = OLD.scope_id
              AND replacement.user_id = OLD.user_id
              AND replacement.issued_at = NEW.revoked_at
              AND replacement.consumed_at IS NULL
              AND replacement.revoked_at IS NULL
        ) THEN
            RAISE EXCEPTION 'account recovery challenge transition is not authorized';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.consumed_at IS NULL AND NEW.revoked_at IS NOT NULL AND
       NEW.completion_write_id IS NULL AND NEW.terminal_reason = 'principal_changed' THEN
        IF EXISTS (
            SELECT 1 FROM users user_row
            JOIN memberships membership
              ON membership.user_id = user_row.id AND membership.scope_id = OLD.scope_id
            WHERE user_row.id = OLD.user_id AND user_row.status = 'active'
              AND membership.status = 'active'
              AND user_row.revision = OLD.password_revision
        ) THEN
            RAISE EXCEPTION 'account recovery challenge transition is not authorized';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'account recovery challenge transition is not authorized';
END;
$$;

CREATE TRIGGER account_recovery_challenges_protected
BEFORE UPDATE OR DELETE ON account_recovery_challenges
FOR EACH ROW EXECUTE FUNCTION protect_account_recovery_challenge();

CREATE FUNCTION protect_account_recovery_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_action text;
    expected_result text;
BEGIN
    IF TG_OP = 'DELETE' OR OLD.completed_at IS NOT NULL OR
       NEW.id IS DISTINCT FROM OLD.id OR
       NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
       NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
       NEW.operation IS DISTINCT FROM OLD.operation OR
       NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
       NEW.request_digest IS DISTINCT FROM OLD.request_digest OR
       NEW.request_id IS DISTINCT FROM OLD.request_id OR
       NEW.trace_id IS DISTINCT FROM OLD.trace_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.completed_at IS NULL OR NEW.response_code IS NULL THEN
        RAISE EXCEPTION 'account recovery write requests are protected';
    END IF;

    expected_action := CASE NEW.operation
        WHEN 'request' THEN 'identity.account_recovery.request'
        ELSE 'identity.account_recovery.reset'
    END;
    expected_result := CASE NEW.response_code
        WHEN 'accepted' THEN 'success'
        WHEN 'completed' THEN 'success'
        ELSE 'denied'
    END;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id = NEW.scope_id
          AND event.action = expected_action
          AND event.request_id = NEW.request_id
          AND event.result = expected_result
          AND (
              (NEW.operation = 'request' AND
               event.resource_type = 'account_recovery_request' AND
               event.resource_id = NEW.id::text) OR
              (NEW.operation = 'reset' AND NEW.resource_id IS NULL AND
               event.resource_type = 'account_recovery_request' AND
               event.resource_id = NEW.id::text) OR
              (NEW.operation = 'reset' AND NEW.resource_id IS NOT NULL AND
               event.resource_type = 'account_recovery_challenge' AND
               event.resource_id = NEW.resource_id::text)
          )
    ) THEN
        RAISE EXCEPTION 'account recovery write completion requires audit';
    END IF;
    IF NEW.response_code = 'completed' AND NOT EXISTS (
        SELECT 1 FROM account_recovery_challenges challenge
        WHERE challenge.id = NEW.resource_id
          AND challenge.completion_write_id = NEW.id
          AND challenge.consumed_at = NEW.completed_at
          AND challenge.terminal_reason = 'consumed'
    ) THEN
        RAISE EXCEPTION 'account recovery write completion requires consumed challenge';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_write_requests_protected
BEFORE UPDATE OR DELETE ON account_recovery_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_account_recovery_write_request();

CREATE FUNCTION protect_account_recovery_rate_window()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
       NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
       NEW.identifier_kind IS DISTINCT FROM OLD.identifier_kind OR
       NEW.identifier_digest IS DISTINCT FROM OLD.identifier_digest OR
       NEW.window_started_at IS DISTINCT FROM OLD.window_started_at OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.request_count <> OLD.request_count + 1 OR
       NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'account recovery rate windows are protected';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_recovery_rate_windows_protected
BEFORE UPDATE OR DELETE ON account_recovery_rate_windows
FOR EACH ROW EXECUTE FUNCTION protect_account_recovery_rate_window();

CREATE FUNCTION prevent_account_recovery_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'account recovery facts cannot be truncated';
END;
$$;

CREATE TRIGGER account_recovery_challenges_no_truncate
BEFORE TRUNCATE ON account_recovery_challenges
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_recovery_truncate();
CREATE TRIGGER account_recovery_write_requests_no_truncate
BEFORE TRUNCATE ON account_recovery_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_recovery_truncate();
CREATE TRIGGER account_recovery_rate_windows_no_truncate
BEFORE TRUNCATE ON account_recovery_rate_windows
FOR EACH STATEMENT EXECUTE FUNCTION prevent_account_recovery_truncate();
