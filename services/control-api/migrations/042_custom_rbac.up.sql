ALTER TABLE mfa_step_up_uses
    ADD COLUMN resource_binding_sha256 bytea
    CHECK (resource_binding_sha256 IS NULL OR octet_length(resource_binding_sha256) = 32);

CREATE TABLE custom_rbac_permission_catalog (
    permission_name text PRIMARY KEY REFERENCES permissions(name) ON DELETE RESTRICT,
    step_up_required boolean NOT NULL DEFAULT false
);

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('identity.self.read', false),
    ('identity.self.update', false),
    ('identity.password.change', false),
    ('identity.users.manage', true),
    ('identity.roles.manage', true),
    ('sites.read', false),
    ('sites.manage', false),
    ('dns.read', false),
    ('dns.manage', false),
    ('certificates.read', false),
    ('certificates.manage', true),
    ('streams.read', false),
    ('streams.manage', false),
    ('billing.account.read', false),
    ('api_keys.self.manage', true),
    ('security_policies.read', false),
    ('security_policies.manage', true),
    ('url_auth_policies.read', false),
    ('url_auth_policies.manage', true),
    ('node_scheduling.read', false),
    ('node_scheduling.manage', false),
    ('identity_verification.self.manage', false),
    ('identity_verification.read', false),
    ('identity_verification.review', true);

CREATE TABLE custom_rbac_system_role_permission_additions (
    role_id uuid NOT NULL,
    permission_name text NOT NULL,
    PRIMARY KEY (role_id, permission_name),
    CONSTRAINT custom_rbac_system_role_addition_permission_fk
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE CASCADE
);

WITH additions AS (
    INSERT INTO role_permissions (role_id, permission_name)
    SELECT role.id, 'identity.roles.manage'
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.system_role AND role.name = 'tenant_owner' AND scope.kind = 'tenant'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO custom_rbac_system_role_permission_additions (role_id, permission_name)
SELECT role_id, permission_name FROM additions;

CREATE TABLE custom_roles (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    current_revision bigint NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
    current_name text NOT NULL CHECK (
        current_name = lower(btrim(current_name)) AND
        char_length(current_name) BETWEEN 1 AND 128 AND
        current_name !~ '[[:cntrl:]]'
    ),
    created_by_user_id uuid NOT NULL,
    created_by_scope_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deactivated_at timestamptz,
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, id, tenant_id),
    CHECK (created_by_scope_id = tenant_scope_id),
    CHECK (updated_at >= created_at),
    CHECK (deactivated_at IS NULL OR deactivated_at >= created_at)
);

CREATE UNIQUE INDEX custom_roles_active_name_idx
    ON custom_roles (tenant_scope_id, current_name) WHERE deactivated_at IS NULL;

CREATE TABLE custom_role_revisions (
    role_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    name text NOT NULL CHECK (
        name = lower(btrim(name)) AND char_length(name) BETWEEN 1 AND 128 AND
        name !~ '[[:cntrl:]]'
    ),
    permissions text[] NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 128),
    action text NOT NULL CHECK (action IN (
        'identity.custom_role.create',
        'identity.custom_role.rename',
        'identity.custom_role.publish'
    )),
    created_by_user_id uuid NOT NULL,
    created_by_scope_id uuid NOT NULL,
    step_up_proof_id uuid,
    step_up_method text CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn')),
    step_up_verified_at timestamptz,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (role_id, revision),
    FOREIGN KEY (tenant_scope_id, role_id, tenant_id)
        REFERENCES custom_roles(tenant_scope_id, id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, role_id, revision, tenant_id),
    CHECK (created_by_scope_id = tenant_scope_id),
    CHECK (
        (step_up_proof_id IS NULL AND step_up_method IS NULL AND step_up_verified_at IS NULL) OR
        (step_up_proof_id IS NOT NULL AND step_up_method IS NOT NULL AND step_up_verified_at IS NOT NULL)
    ),
    CHECK (step_up_verified_at IS NULL OR
        (step_up_verified_at <= created_at AND step_up_verified_at >= created_at - interval '5 minutes'))
);

CREATE TABLE custom_role_deactivations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    role_id uuid NOT NULL UNIQUE,
    role_revision bigint NOT NULL,
    deactivated_by_user_id uuid NOT NULL,
    deactivated_by_scope_id uuid NOT NULL,
    step_up_proof_id uuid,
    step_up_method text CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn')),
    step_up_verified_at timestamptz,
    deactivated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, role_id, role_revision, tenant_id)
        REFERENCES custom_role_revisions(tenant_scope_id, role_id, revision, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (deactivated_by_scope_id, deactivated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (deactivated_by_scope_id = tenant_scope_id),
    CHECK (
        (step_up_proof_id IS NULL AND step_up_method IS NULL AND step_up_verified_at IS NULL) OR
        (step_up_proof_id IS NOT NULL AND step_up_method IS NOT NULL AND step_up_verified_at IS NOT NULL)
    ),
    CHECK (step_up_verified_at IS NULL OR
        (step_up_verified_at <= deactivated_at AND
         step_up_verified_at >= deactivated_at - interval '5 minutes'))
);

CREATE TABLE custom_role_grants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    role_id uuid NOT NULL,
    role_revision bigint NOT NULL,
    subject_user_id uuid NOT NULL,
    granted_by_user_id uuid NOT NULL,
    granted_by_scope_id uuid NOT NULL,
    step_up_proof_id uuid,
    step_up_method text CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn')),
    step_up_verified_at timestamptz,
    granted_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, role_id, role_revision, tenant_id)
        REFERENCES custom_role_revisions(tenant_scope_id, role_id, revision, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, subject_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (granted_by_scope_id, granted_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (id, tenant_id, tenant_scope_id, role_id, role_revision, subject_user_id),
    CHECK (granted_by_scope_id = tenant_scope_id),
    CHECK (subject_user_id <> granted_by_user_id),
    CHECK (
        (step_up_proof_id IS NULL AND step_up_method IS NULL AND step_up_verified_at IS NULL) OR
        (step_up_proof_id IS NOT NULL AND step_up_method IS NOT NULL AND step_up_verified_at IS NOT NULL)
    ),
    CHECK (step_up_verified_at IS NULL OR
        (step_up_verified_at <= granted_at AND step_up_verified_at >= granted_at - interval '5 minutes'))
);

CREATE INDEX custom_role_grants_subject_idx
    ON custom_role_grants (tenant_scope_id, subject_user_id, granted_at DESC, id DESC);

CREATE TABLE custom_role_grant_revocations (
    id uuid PRIMARY KEY,
    grant_id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    role_id uuid NOT NULL,
    role_revision bigint NOT NULL,
    subject_user_id uuid NOT NULL,
    revoked_by_user_id uuid NOT NULL,
    revoked_by_scope_id uuid NOT NULL,
    step_up_proof_id uuid,
    step_up_method text CHECK (step_up_method IN ('totp', 'recovery_code', 'webauthn')),
    step_up_verified_at timestamptz,
    revoked_at timestamptz NOT NULL,
    FOREIGN KEY (grant_id, tenant_id, tenant_scope_id, role_id, role_revision, subject_user_id)
        REFERENCES custom_role_grants(
            id, tenant_id, tenant_scope_id, role_id, role_revision, subject_user_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (revoked_by_scope_id, revoked_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (revoked_by_scope_id = tenant_scope_id),
    CHECK (
        (step_up_proof_id IS NULL AND step_up_method IS NULL AND step_up_verified_at IS NULL) OR
        (step_up_proof_id IS NOT NULL AND step_up_method IS NOT NULL AND step_up_verified_at IS NOT NULL)
    ),
    CHECK (step_up_verified_at IS NULL OR
        (step_up_verified_at <= revoked_at AND step_up_verified_at >= revoked_at - interval '5 minutes'))
);

CREATE TABLE custom_rbac_write_requests (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'identity.custom_role.create',
        'identity.custom_role.rename',
        'identity.custom_role.publish',
        'identity.custom_role.deactivate',
        'identity.custom_role.assign',
        'identity.custom_role.revoke'
    )),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]'
    ),
    trace_id text NOT NULL CHECK (
        trace_id = btrim(trace_id) AND char_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id !~ '[[:cntrl:]]'
    ),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id, actor_user_id, operation, idempotency_key),
    CHECK (actor_scope_id = tenant_scope_id)
);

CREATE FUNCTION custom_rbac_effective_permissions(requested_scope_id uuid, requested_user_id uuid)
RETURNS TABLE(permission_name text)
LANGUAGE sql
STABLE
AS $$
    SELECT DISTINCT effective.permission_name
    FROM (
        SELECT role_permission.permission_name
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
        JOIN memberships membership
          ON membership.scope_id = scope.id AND membership.user_id = requested_user_id
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        JOIN role_assignments assignment
          ON assignment.scope_id = scope.id AND assignment.user_id = membership.user_id
        JOIN roles role ON role.id = assignment.role_id AND role.scope_id = scope.id
        JOIN role_permissions role_permission ON role_permission.role_id = role.id
        WHERE scope.id = requested_scope_id AND scope.kind = 'tenant'
          AND role_permission.permission_name NOT IN (
              'platform.admin', 'identity.impersonation.manage', 'billing.adjustments.manage',
              'api_keys.admin.manage', 'packages.manage', 'package_subscriptions.read',
              'package_subscriptions.manage', 'nodes.read', 'nodes.manage',
              'control.upgrades.check', 'node_ca.manage', 'system_configuration.read',
              'system_configuration.manage'
          )
        UNION ALL
        SELECT unnest(revision.permissions)
        FROM access_scopes scope
        JOIN tenants tenant ON tenant.id = scope.tenant_id AND tenant.status = 'active'
        JOIN memberships membership
          ON membership.scope_id = scope.id AND membership.user_id = requested_user_id
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        JOIN custom_role_grants grant_row
          ON grant_row.tenant_scope_id = scope.id AND grant_row.subject_user_id = membership.user_id
        JOIN custom_roles role
          ON role.id = grant_row.role_id AND role.tenant_scope_id = scope.id
         AND role.deactivated_at IS NULL
        JOIN custom_role_revisions revision
          ON revision.role_id = role.id AND revision.revision = role.current_revision
        LEFT JOIN custom_role_grant_revocations revocation ON revocation.grant_id = grant_row.id
        WHERE scope.id = requested_scope_id AND scope.kind = 'tenant' AND revocation.id IS NULL
    ) effective;
$$;

CREATE FUNCTION custom_rbac_actor_can_manage(scope_id uuid, user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM custom_rbac_effective_permissions(scope_id, user_id)
        WHERE permission_name = 'identity.roles.manage'
    );
$$;

CREATE FUNCTION validate_custom_role_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    role_head bigint;
    role_inactive boolean;
    role_name text;
    previous_permissions text[];
    requires_step_up boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'custom-rbac-tenant:' || NEW.tenant_scope_id::text, 0));
    SELECT current_revision, deactivated_at IS NOT NULL, current_name
      INTO role_head, role_inactive, role_name
    FROM custom_roles
    WHERE id = NEW.role_id AND tenant_scope_id = NEW.tenant_scope_id AND tenant_id = NEW.tenant_id
    FOR UPDATE;
    IF role_head > 0 THEN
        SELECT permissions INTO previous_permissions
        FROM custom_role_revisions
        WHERE role_id = NEW.role_id AND revision = role_head;
    END IF;

    IF role_head IS NULL OR role_inactive OR NEW.revision <> role_head + 1 OR
       (NEW.revision = 1 AND NEW.action <> 'identity.custom_role.create') OR
       (NEW.revision > 1 AND NEW.action = 'identity.custom_role.create') OR
       (NEW.action = 'identity.custom_role.create' AND NEW.name <> role_name) OR
       (NEW.action = 'identity.custom_role.rename' AND (
            NEW.revision = 1 OR NEW.name = role_name OR
            NEW.permissions IS DISTINCT FROM previous_permissions
       )) OR
       (NEW.action = 'identity.custom_role.publish' AND NEW.name <> role_name) OR
       NEW.permissions IS DISTINCT FROM ARRAY(
           SELECT DISTINCT requested.permission
           FROM unnest(NEW.permissions) AS requested(permission)
           ORDER BY requested.permission
       ) OR EXISTS (
           SELECT 1 FROM unnest(NEW.permissions) AS requested(permission)
           WHERE requested.permission IS NULL OR
                 requested.permission <> lower(btrim(requested.permission)) OR
                 requested.permission = '' OR requested.permission ~ '[[:cntrl:]]'
       ) OR EXISTS (
           SELECT requested.permission FROM unnest(NEW.permissions) AS requested(permission)
           EXCEPT SELECT permission_name FROM custom_rbac_permission_catalog
       ) OR custom_rbac_actor_can_manage(NEW.tenant_scope_id, NEW.created_by_user_id) IS DISTINCT FROM true OR
       EXISTS (
           SELECT requested.permission FROM unnest(NEW.permissions) AS requested(permission)
           EXCEPT SELECT permission_name
                  FROM custom_rbac_effective_permissions(NEW.tenant_scope_id, NEW.created_by_user_id)
       ) THEN
        RAISE EXCEPTION 'invalid custom role revision';
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM custom_rbac_permission_catalog
        WHERE step_up_required AND (
            permission_name = ANY(NEW.permissions) OR
            (NEW.action = 'identity.custom_role.publish' AND
             permission_name = ANY(previous_permissions))
        )
    ) INTO requires_step_up;
    IF NEW.action IN ('identity.custom_role.create', 'identity.custom_role.publish') AND
       requires_step_up AND NEW.step_up_proof_id IS NULL THEN
        RAISE EXCEPTION 'custom role revision requires step-up proof';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_role_revisions_validate
BEFORE INSERT ON custom_role_revisions
FOR EACH ROW EXECUTE FUNCTION validate_custom_role_revision();

CREATE FUNCTION validate_custom_role_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    projected_name text;
BEGIN
    IF ROW(NEW.id, NEW.tenant_id, NEW.tenant_scope_id, NEW.created_by_user_id,
           NEW.created_by_scope_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.tenant_scope_id, OLD.created_by_user_id,
           OLD.created_by_scope_id, OLD.created_at) OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'immutable custom role identity changed';
    END IF;

    IF NEW.current_revision = OLD.current_revision + 1 AND
       NEW.deactivated_at IS NOT DISTINCT FROM OLD.deactivated_at THEN
        SELECT name INTO projected_name FROM custom_role_revisions
        WHERE role_id = NEW.id AND revision = NEW.current_revision;
        IF projected_name IS DISTINCT FROM NEW.current_name THEN
            RAISE EXCEPTION 'invalid custom role revision projection';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.current_revision = OLD.current_revision AND NEW.current_name = OLD.current_name AND
       OLD.deactivated_at IS NULL AND NEW.deactivated_at IS NOT NULL AND
       NEW.updated_at = NEW.deactivated_at AND EXISTS (
           SELECT 1 FROM custom_role_deactivations deactivation
           WHERE deactivation.role_id = NEW.id AND
                 deactivation.role_revision = NEW.current_revision AND
                 deactivation.deactivated_at = NEW.deactivated_at
       ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid custom role projection transition';
END;
$$;

CREATE TRIGGER custom_roles_projection_guard
BEFORE UPDATE ON custom_roles
FOR EACH ROW EXECUTE FUNCTION validate_custom_role_projection();

CREATE FUNCTION validate_custom_role_deactivation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    role_row custom_roles%ROWTYPE;
    requires_step_up boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'custom-rbac-tenant:' || NEW.tenant_scope_id::text, 0));
    SELECT * INTO role_row FROM custom_roles
    WHERE id = NEW.role_id AND tenant_scope_id = NEW.tenant_scope_id FOR UPDATE;
    SELECT EXISTS (
        SELECT 1 FROM custom_role_revisions revision
        JOIN custom_rbac_permission_catalog catalog
          ON catalog.permission_name = ANY(revision.permissions) AND catalog.step_up_required
        WHERE revision.role_id = NEW.role_id AND revision.revision = NEW.role_revision
    ) INTO requires_step_up;
    IF role_row.id IS NULL OR role_row.tenant_id <> NEW.tenant_id OR
       role_row.current_revision <> NEW.role_revision OR role_row.deactivated_at IS NOT NULL OR
       custom_rbac_actor_can_manage(NEW.tenant_scope_id, NEW.deactivated_by_user_id) IS DISTINCT FROM true OR
       (requires_step_up AND NEW.step_up_proof_id IS NULL) THEN
        RAISE EXCEPTION 'invalid custom role deactivation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_role_deactivations_validate
BEFORE INSERT ON custom_role_deactivations
FOR EACH ROW EXECUTE FUNCTION validate_custom_role_deactivation();

CREATE FUNCTION apply_custom_role_deactivation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE custom_roles
    SET deactivated_at = NEW.deactivated_at, updated_at = NEW.deactivated_at
    WHERE id = NEW.role_id AND tenant_scope_id = NEW.tenant_scope_id AND
          current_revision = NEW.role_revision AND deactivated_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'custom role deactivation lost compare-and-swap';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_role_deactivations_apply
AFTER INSERT ON custom_role_deactivations
FOR EACH ROW EXECUTE FUNCTION apply_custom_role_deactivation();

CREATE FUNCTION validate_custom_role_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    role_active boolean;
    subject_active boolean;
    requires_step_up boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'custom-rbac-tenant:' || NEW.tenant_scope_id::text, 0));
    SELECT role.deactivated_at IS NULL AND role.current_revision = NEW.role_revision
      INTO role_active
    FROM custom_roles role
    WHERE role.id = NEW.role_id AND role.tenant_scope_id = NEW.tenant_scope_id AND
          role.tenant_id = NEW.tenant_id;
    SELECT tenant.status = 'active' AND account.status = 'active' AND membership.status = 'active'
      INTO subject_active
    FROM access_scopes scope
    JOIN tenants tenant ON tenant.id = scope.tenant_id
    JOIN memberships membership
      ON membership.scope_id = scope.id AND membership.user_id = NEW.subject_user_id
    JOIN users account ON account.id = membership.user_id
    WHERE scope.id = NEW.tenant_scope_id AND scope.kind = 'tenant' AND scope.tenant_id = NEW.tenant_id;
    SELECT EXISTS (
        SELECT 1 FROM custom_role_revisions revision
        JOIN custom_rbac_permission_catalog catalog
          ON catalog.permission_name = ANY(revision.permissions) AND catalog.step_up_required
        WHERE revision.role_id = NEW.role_id AND revision.revision = NEW.role_revision
    ) INTO requires_step_up;
    IF role_active IS DISTINCT FROM true OR subject_active IS DISTINCT FROM true OR
       custom_rbac_actor_can_manage(NEW.tenant_scope_id, NEW.granted_by_user_id) IS DISTINCT FROM true OR
       EXISTS (
           SELECT requested.permission FROM custom_role_revisions revision,
                  unnest(revision.permissions) AS requested(permission)
           WHERE revision.role_id = NEW.role_id AND revision.revision = NEW.role_revision
           EXCEPT SELECT permission_name
                  FROM custom_rbac_effective_permissions(NEW.tenant_scope_id, NEW.granted_by_user_id)
       ) OR (requires_step_up AND NEW.step_up_proof_id IS NULL) OR EXISTS (
           SELECT 1 FROM custom_role_grants existing
           WHERE existing.tenant_scope_id = NEW.tenant_scope_id AND
                 existing.subject_user_id = NEW.subject_user_id AND existing.role_id = NEW.role_id AND
                 NOT EXISTS (SELECT 1 FROM custom_role_grant_revocations revoked
                             WHERE revoked.grant_id = existing.id)
       ) THEN
        RAISE EXCEPTION 'invalid custom role grant';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_role_grants_validate
BEFORE INSERT ON custom_role_grants
FOR EACH ROW EXECUTE FUNCTION validate_custom_role_grant();

CREATE FUNCTION validate_custom_role_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    requires_step_up boolean;
    grant_time timestamptz;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'custom-rbac-tenant:' || NEW.tenant_scope_id::text, 0));
    SELECT granted_at INTO grant_time FROM custom_role_grants WHERE id = NEW.grant_id;
    SELECT EXISTS (
        SELECT 1 FROM custom_role_revisions revision
        JOIN custom_rbac_permission_catalog catalog
          ON catalog.permission_name = ANY(revision.permissions) AND catalog.step_up_required
        WHERE revision.role_id = NEW.role_id AND revision.revision = NEW.role_revision
    ) INTO requires_step_up;
    IF grant_time IS NULL OR NEW.revoked_at < grant_time OR
       custom_rbac_actor_can_manage(NEW.tenant_scope_id, NEW.revoked_by_user_id) IS DISTINCT FROM true OR
       (requires_step_up AND NEW.step_up_proof_id IS NULL) THEN
        RAISE EXCEPTION 'invalid custom role grant revocation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_role_grant_revocations_validate
BEFORE INSERT ON custom_role_grant_revocations
FOR EACH ROW EXECUTE FUNCTION validate_custom_role_revocation();

CREATE FUNCTION project_custom_role_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO roles (id, scope_id, name, description, system_role, created_at)
    VALUES (NEW.id, NEW.tenant_scope_id, NEW.current_name, 'Custom tenant role', false, NEW.created_at);
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_roles_project_insert
AFTER INSERT ON custom_roles
FOR EACH ROW EXECUTE FUNCTION project_custom_role_insert();

CREATE FUNCTION project_custom_role_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.current_revision <> OLD.current_revision THEN
        UPDATE roles SET name = NEW.current_name
        WHERE id = NEW.id AND scope_id = NEW.tenant_scope_id;
        DELETE FROM role_permissions WHERE role_id = NEW.id;
        INSERT INTO role_permissions (role_id, permission_name)
        SELECT NEW.id, unnest(revision.permissions)
        FROM custom_role_revisions revision
        WHERE revision.role_id = NEW.id AND revision.revision = NEW.current_revision;
    END IF;
    IF OLD.deactivated_at IS NULL AND NEW.deactivated_at IS NOT NULL THEN
        DELETE FROM role_assignments
        WHERE scope_id = NEW.tenant_scope_id AND role_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_roles_project_update
AFTER UPDATE ON custom_roles
FOR EACH ROW EXECUTE FUNCTION project_custom_role_update();

CREATE FUNCTION project_custom_role_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO role_assignments (scope_id, user_id, role_id, assigned_at)
    VALUES (NEW.tenant_scope_id, NEW.subject_user_id, NEW.role_id, NEW.granted_at);
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_role_grants_project_insert
AFTER INSERT ON custom_role_grants
FOR EACH ROW EXECUTE FUNCTION project_custom_role_grant();

CREATE FUNCTION project_custom_role_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM custom_role_grants grant_row
        WHERE grant_row.tenant_scope_id = NEW.tenant_scope_id
          AND grant_row.subject_user_id = NEW.subject_user_id
          AND grant_row.role_id = NEW.role_id
          AND NOT EXISTS (
              SELECT 1 FROM custom_role_grant_revocations revocation
              WHERE revocation.grant_id = grant_row.id
          )
    ) THEN
        DELETE FROM role_assignments
        WHERE scope_id = NEW.tenant_scope_id
          AND user_id = NEW.subject_user_id AND role_id = NEW.role_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_role_grant_revocations_project_insert
AFTER INSERT ON custom_role_grant_revocations
FOR EACH ROW EXECUTE FUNCTION project_custom_role_revocation();

CREATE FUNCTION prevent_custom_rbac_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'custom RBAC authorization facts are append-only';
END;
$$;

CREATE TRIGGER custom_role_revisions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_role_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();
CREATE TRIGGER custom_role_deactivations_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_role_deactivations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();
CREATE TRIGGER custom_role_grants_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_role_grants
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();
CREATE TRIGGER custom_role_grant_revocations_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_role_grant_revocations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();
CREATE TRIGGER custom_rbac_write_requests_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_rbac_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();

CREATE FUNCTION protect_custom_rbac_permission_catalog()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (
            SELECT 1 FROM custom_role_revisions revision
            WHERE OLD.permission_name = ANY(revision.permissions)
        ) THEN
            RAISE EXCEPTION 'referenced custom RBAC permissions cannot be deleted';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'custom RBAC permission catalog cannot be updated or truncated';
END;
$$;

CREATE TRIGGER custom_rbac_permission_catalog_no_update_or_truncate
BEFORE UPDATE OR TRUNCATE ON custom_rbac_permission_catalog
FOR EACH STATEMENT EXECUTE FUNCTION protect_custom_rbac_permission_catalog();
CREATE TRIGGER custom_rbac_permission_catalog_delete_guard
BEFORE DELETE ON custom_rbac_permission_catalog
FOR EACH ROW EXECUTE FUNCTION protect_custom_rbac_permission_catalog();

CREATE FUNCTION prevent_custom_role_removal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'custom roles cannot be deleted or truncated';
END;
$$;

CREATE TRIGGER custom_roles_no_delete
BEFORE DELETE OR TRUNCATE ON custom_roles
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_role_removal();

CREATE FUNCTION guard_system_role_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NOT NEW.system_role AND pg_trigger_depth() < 2 THEN
            RAISE EXCEPTION 'custom roles must be created through custom RBAC facts';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.system_role OR (TG_OP = 'UPDATE' AND NEW.system_role IS DISTINCT FROM OLD.system_role) THEN
        RAISE EXCEPTION 'system roles are immutable';
    END IF;
    IF EXISTS (SELECT 1 FROM custom_roles WHERE id = OLD.id) AND pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'custom role projection is protected';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_system_role_guard
BEFORE INSERT OR UPDATE OR DELETE ON roles
FOR EACH ROW EXECUTE FUNCTION guard_system_role_mutation();

CREATE FUNCTION guard_system_role_permission_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_role_id uuid;
    target_system_role boolean;
    target_role_name text;
    target_permission_name text;
    scope_kind text;
    protected_permission boolean;
BEGIN
    target_role_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END;
    target_permission_name := CASE
        WHEN TG_OP = 'DELETE' THEN OLD.permission_name ELSE NEW.permission_name
    END;
    SELECT role.system_role, role.name, scope.kind
      INTO target_system_role, target_role_name, scope_kind
    FROM roles role JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.id = target_role_id;
    IF NOT target_system_role THEN
        IF EXISTS (SELECT 1 FROM custom_roles WHERE id = target_role_id) AND pg_trigger_depth() < 2 THEN
            RAISE EXCEPTION 'custom role permission projection is protected';
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM custom_rbac_permission_catalog
        WHERE permission_name = target_permission_name
    ) INTO protected_permission;

    IF TG_OP = 'UPDATE' OR (TG_OP = 'DELETE' AND protected_permission) THEN
        RAISE EXCEPTION 'system role permissions are immutable';
    END IF;
    IF TG_OP = 'INSERT' AND scope_kind = 'tenant' AND
       (NEW.permission_name IN (
            'platform.admin', 'identity.impersonation.manage', 'billing.adjustments.manage',
            'api_keys.admin.manage', 'packages.manage', 'package_subscriptions.read',
            'package_subscriptions.manage', 'nodes.read', 'nodes.manage',
            'control.upgrades.check', 'node_ca.manage', 'system_configuration.read',
            'system_configuration.manage'
        ) OR (target_role_name = 'tenant_viewer' AND
              NEW.permission_name NOT LIKE '%.read' AND
              NEW.permission_name NOT IN (
                  'identity.self.update', 'identity.password.change', 'api_keys.self.manage',
                  'identity_verification.self.manage', 'promotions.quote', 'promotions.redeem'
              ))) THEN
        RAISE EXCEPTION 'invalid tenant system role permission';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER role_permissions_system_role_guard
BEFORE INSERT OR UPDATE OR DELETE ON role_permissions
FOR EACH ROW EXECUTE FUNCTION guard_system_role_permission_mutation();

CREATE FUNCTION grant_custom_rbac_manage_to_tenant_owner()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.system_role AND NEW.name = 'tenant_owner' AND EXISTS (
        SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'tenant'
    ) THEN
        INSERT INTO role_permissions (role_id, permission_name)
        VALUES (NEW.id, 'identity.roles.manage')
        ON CONFLICT DO NOTHING;
        INSERT INTO custom_rbac_system_role_permission_additions (role_id, permission_name)
        VALUES (NEW.id, 'identity.roles.manage')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_tenant_owner_custom_rbac_manage
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_custom_rbac_manage_to_tenant_owner();

CREATE FUNCTION lock_custom_rbac_identity_assignment()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'custom-rbac-tenant:' || (CASE WHEN TG_OP = 'DELETE' THEN OLD.scope_id ELSE NEW.scope_id END)::text, 0));
    IF EXISTS (
        SELECT 1 FROM custom_roles
        WHERE id = (CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END)
    ) AND pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'custom role assignment projection is protected';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER role_assignments_custom_rbac_lock
BEFORE INSERT OR UPDATE OR DELETE ON role_assignments
FOR EACH ROW EXECUTE FUNCTION lock_custom_rbac_identity_assignment();

CREATE TRIGGER custom_rbac_audit_no_truncate
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_event_mutation();
