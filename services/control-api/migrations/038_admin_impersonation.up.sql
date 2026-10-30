INSERT INTO permissions (name, description) VALUES
    ('identity.impersonation.manage', 'Create and revoke short-lived tenant impersonation grants');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, 'identity.impersonation.manage'
FROM roles
WHERE roles.system_role AND roles.name = 'platform_owner'
ON CONFLICT DO NOTHING;

CREATE TABLE admin_impersonation_grants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    primary_auth_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
    subject_user_id uuid NOT NULL,
    code_digest bytea NOT NULL UNIQUE CHECK (octet_length(code_digest) = 32),
    subject_permissions_digest bytea NOT NULL CHECK (octet_length(subject_permissions_digest) = 32),
    ticket text NOT NULL CHECK (
        ticket = btrim(ticket) AND char_length(ticket) BETWEEN 1 AND 128 AND
        ticket !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN ticket) = 0 AND position(U&'\2029' IN ticket) = 0
    ),
    reason text NOT NULL CHECK (
        reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 1024 AND
        reason !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN reason) = 0 AND position(U&'\2029' IN reason) = 0
    ),
    step_up_method text NOT NULL CHECK (step_up_method IN ('totp', 'webauthn')),
    step_up_evidence_id text NOT NULL CHECK (
        step_up_evidence_id = btrim(step_up_evidence_id) AND
        char_length(step_up_evidence_id) BETWEEN 1 AND 128 AND
        step_up_evidence_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN step_up_evidence_id) = 0 AND position(U&'\2029' IN step_up_evidence_id) = 0
    ),
    step_up_at timestamptz NOT NULL,
    step_up_expires_at timestamptz NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN request_id) = 0 AND position(U&'\2029' IN request_id) = 0
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN trace_id) = 0 AND position(U&'\2029' IN trace_id) = 0
    ),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, subject_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id, actor_user_id, idempotency_key),
    UNIQUE (actor_scope_id, step_up_evidence_id),
    UNIQUE (id, tenant_id, tenant_scope_id, actor_user_id, actor_scope_id, subject_user_id),
    CHECK (actor_user_id <> subject_user_id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '2 minutes'),
    CHECK (
        step_up_at <= created_at AND step_up_at >= created_at - interval '5 minutes' AND
        step_up_expires_at > created_at AND
        step_up_expires_at <= step_up_at + interval '5 minutes'
    )
);

CREATE INDEX admin_impersonation_grants_tenant_created_idx
    ON admin_impersonation_grants (tenant_scope_id, created_at DESC, id DESC);
CREATE INDEX admin_impersonation_grants_subject_created_idx
    ON admin_impersonation_grants (tenant_scope_id, subject_user_id, created_at DESC);
CREATE INDEX admin_impersonation_grants_primary_session_idx
    ON admin_impersonation_grants (primary_auth_session_id);

CREATE TABLE admin_impersonation_sessions (
    id uuid PRIMARY KEY,
    grant_id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    subject_permissions_digest bytea NOT NULL CHECK (octet_length(subject_permissions_digest) = 32),
    exchange_idempotency_key text NOT NULL CHECK (
        exchange_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    exchange_request_digest bytea NOT NULL CHECK (octet_length(exchange_request_digest) = 32),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN request_id) = 0 AND position(U&'\2029' IN request_id) = 0
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN trace_id) = 0 AND position(U&'\2029' IN trace_id) = 0
    ),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (grant_id, tenant_id, tenant_scope_id, actor_user_id, actor_scope_id, subject_user_id)
        REFERENCES admin_impersonation_grants(
            id, tenant_id, tenant_scope_id, actor_user_id, actor_scope_id, subject_user_id
        ) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, exchange_idempotency_key),
    UNIQUE (id, grant_id, tenant_id, tenant_scope_id, actor_user_id, actor_scope_id, subject_user_id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes')
);

CREATE INDEX admin_impersonation_sessions_tenant_expiry_idx
    ON admin_impersonation_sessions (tenant_scope_id, expires_at, id);

CREATE TABLE admin_impersonation_revocations (
    id uuid PRIMARY KEY,
    grant_id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    original_actor_user_id uuid NOT NULL,
    original_actor_scope_id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    revoked_by_user_id uuid NOT NULL,
    revoked_by_scope_id uuid NOT NULL,
    reason text NOT NULL CHECK (
        reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 512 AND
        reason !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN reason) = 0 AND position(U&'\2029' IN reason) = 0
    ),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN request_id) = 0 AND position(U&'\2029' IN request_id) = 0
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN trace_id) = 0 AND position(U&'\2029' IN trace_id) = 0
    ),
    revoked_at timestamptz NOT NULL,
    FOREIGN KEY (
        grant_id, tenant_id, tenant_scope_id, original_actor_user_id,
        original_actor_scope_id, subject_user_id
    ) REFERENCES admin_impersonation_grants(
        id, tenant_id, tenant_scope_id, actor_user_id, actor_scope_id, subject_user_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (revoked_by_scope_id, revoked_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (revoked_by_scope_id, revoked_by_user_id, idempotency_key)
);

CREATE INDEX admin_impersonation_revocations_tenant_time_idx
    ON admin_impersonation_revocations (tenant_scope_id, revoked_at DESC, id DESC);

CREATE FUNCTION assert_admin_impersonation_grant_principals()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actor_kind text;
    actor_active boolean;
    actor_permitted boolean;
    primary_session_valid boolean;
    target_kind text;
    target_active boolean;
BEGIN
    SELECT scope.kind,
           tenant.status = 'active' AND subject.status = 'active' AND membership.status = 'active'
      INTO target_kind, target_active
    FROM access_scopes scope
    JOIN tenants tenant ON tenant.id = scope.tenant_id
    JOIN memberships membership ON membership.scope_id = scope.id AND membership.user_id = NEW.subject_user_id
    JOIN users subject ON subject.id = membership.user_id
    WHERE scope.id = NEW.tenant_scope_id AND scope.tenant_id = NEW.tenant_id;

    SELECT scope.kind,
           actor.status = 'active' AND membership.status = 'active',
           EXISTS (
               SELECT 1
               FROM role_assignments assignment
               JOIN role_permissions permission ON permission.role_id = assignment.role_id
               WHERE assignment.scope_id = NEW.actor_scope_id
                 AND assignment.user_id = NEW.actor_user_id
                 AND permission.permission_name = 'identity.impersonation.manage'
           )
      INTO actor_kind, actor_active, actor_permitted
    FROM access_scopes scope
    JOIN memberships membership ON membership.scope_id = scope.id AND membership.user_id = NEW.actor_user_id
    JOIN users actor ON actor.id = membership.user_id
    WHERE scope.id = NEW.actor_scope_id;

    SELECT auth_session.user_id = NEW.actor_user_id AND
           auth_session.scope_id = NEW.actor_scope_id AND
           auth_session.revoked_at IS NULL AND
           NEW.created_at >= auth_session.created_at AND
           NEW.created_at < auth_session.expires_at
      INTO primary_session_valid
    FROM auth_sessions auth_session
    WHERE auth_session.id = NEW.primary_auth_session_id
    FOR UPDATE OF auth_session;

    IF target_kind IS DISTINCT FROM 'tenant' OR target_active IS DISTINCT FROM true OR
       actor_kind IS DISTINCT FROM 'platform' OR actor_active IS DISTINCT FROM true OR
       actor_permitted IS DISTINCT FROM true OR primary_session_valid IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'invalid admin impersonation principals';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER admin_impersonation_grants_validate_principals
BEFORE INSERT ON admin_impersonation_grants
FOR EACH ROW EXECUTE FUNCTION assert_admin_impersonation_grant_principals();

CREATE FUNCTION assert_admin_impersonation_session_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    grant_created_at timestamptz;
    grant_expires_at timestamptz;
    grant_permissions_digest bytea;
    actor_active boolean;
    actor_permitted boolean;
    target_active boolean;
BEGIN
    SELECT grant_row.created_at, grant_row.expires_at, grant_row.subject_permissions_digest,
           actor.status = 'active' AND actor_membership.status = 'active' AND actor_scope.kind = 'platform',
           EXISTS (
               SELECT 1
               FROM role_assignments assignment
               JOIN role_permissions permission ON permission.role_id = assignment.role_id
               WHERE assignment.scope_id = NEW.actor_scope_id
                 AND assignment.user_id = NEW.actor_user_id
                 AND permission.permission_name = 'identity.impersonation.manage'
           ),
           tenant.status = 'active' AND subject.status = 'active' AND
               subject_membership.status = 'active' AND subject_scope.kind = 'tenant'
      INTO grant_created_at, grant_expires_at, grant_permissions_digest,
           actor_active, actor_permitted, target_active
    FROM admin_impersonation_grants grant_row
    JOIN access_scopes actor_scope ON actor_scope.id = NEW.actor_scope_id
    JOIN memberships actor_membership
      ON actor_membership.scope_id = NEW.actor_scope_id AND actor_membership.user_id = NEW.actor_user_id
    JOIN users actor ON actor.id = NEW.actor_user_id
    JOIN access_scopes subject_scope
      ON subject_scope.id = NEW.tenant_scope_id AND subject_scope.tenant_id = NEW.tenant_id
    JOIN tenants tenant ON tenant.id = NEW.tenant_id
    JOIN memberships subject_membership
      ON subject_membership.scope_id = NEW.tenant_scope_id AND
         subject_membership.user_id = NEW.subject_user_id
    JOIN users subject ON subject.id = NEW.subject_user_id
    WHERE grant_row.id = NEW.grant_id;

    IF grant_created_at IS NULL OR NEW.created_at < grant_created_at OR NEW.created_at >= grant_expires_at OR
       NEW.subject_permissions_digest IS DISTINCT FROM grant_permissions_digest OR
       actor_active IS DISTINCT FROM true OR actor_permitted IS DISTINCT FROM true OR
       target_active IS DISTINCT FROM true OR EXISTS (
           SELECT 1 FROM admin_impersonation_revocations WHERE grant_id = NEW.grant_id
       ) THEN
        RAISE EXCEPTION 'invalid admin impersonation session fact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER admin_impersonation_sessions_validate_fact
BEFORE INSERT ON admin_impersonation_sessions
FOR EACH ROW EXECUTE FUNCTION assert_admin_impersonation_session_fact();

CREATE FUNCTION assert_admin_impersonation_revoker()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_kind text;
    active boolean;
    permitted boolean;
    grant_created_at timestamptz;
BEGIN
    SELECT scope.kind,
           actor.status = 'active' AND membership.status = 'active',
           EXISTS (
               SELECT 1
               FROM role_assignments assignment
               JOIN role_permissions permission ON permission.role_id = assignment.role_id
               WHERE assignment.scope_id = NEW.revoked_by_scope_id
                 AND assignment.user_id = NEW.revoked_by_user_id
                 AND permission.permission_name = 'identity.impersonation.manage'
           )
      INTO scope_kind, active, permitted
    FROM access_scopes scope
    JOIN memberships membership ON membership.scope_id = scope.id AND membership.user_id = NEW.revoked_by_user_id
    JOIN users actor ON actor.id = membership.user_id
    WHERE scope.id = NEW.revoked_by_scope_id;

    SELECT created_at INTO grant_created_at
    FROM admin_impersonation_grants WHERE id = NEW.grant_id;

    IF scope_kind IS DISTINCT FROM 'platform' OR active IS DISTINCT FROM true OR
       permitted IS DISTINCT FROM true OR grant_created_at IS NULL OR NEW.revoked_at < grant_created_at THEN
        RAISE EXCEPTION 'invalid admin impersonation revoker';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER admin_impersonation_revocations_validate_revoker
BEFORE INSERT ON admin_impersonation_revocations
FOR EACH ROW EXECUTE FUNCTION assert_admin_impersonation_revoker();

CREATE FUNCTION prevent_admin_impersonation_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'admin impersonation authorization facts are append-only';
END;
$$;

CREATE TRIGGER admin_impersonation_grants_append_only
BEFORE UPDATE OR DELETE ON admin_impersonation_grants
FOR EACH ROW EXECUTE FUNCTION prevent_admin_impersonation_fact_mutation();
CREATE TRIGGER admin_impersonation_grants_no_truncate
BEFORE TRUNCATE ON admin_impersonation_grants
FOR EACH STATEMENT EXECUTE FUNCTION prevent_admin_impersonation_fact_mutation();

CREATE TRIGGER admin_impersonation_sessions_append_only
BEFORE UPDATE OR DELETE ON admin_impersonation_sessions
FOR EACH ROW EXECUTE FUNCTION prevent_admin_impersonation_fact_mutation();
CREATE TRIGGER admin_impersonation_sessions_no_truncate
BEFORE TRUNCATE ON admin_impersonation_sessions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_admin_impersonation_fact_mutation();

CREATE TRIGGER admin_impersonation_revocations_append_only
BEFORE UPDATE OR DELETE ON admin_impersonation_revocations
FOR EACH ROW EXECUTE FUNCTION prevent_admin_impersonation_fact_mutation();
CREATE TRIGGER admin_impersonation_revocations_no_truncate
BEFORE TRUNCATE ON admin_impersonation_revocations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_admin_impersonation_fact_mutation();
