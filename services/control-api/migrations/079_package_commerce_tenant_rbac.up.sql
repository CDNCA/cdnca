LOCK TABLE access_scopes,
    roles,
    role_permissions,
    permissions,
    custom_rbac_permission_catalog,
    custom_roles,
    custom_role_revisions,
    custom_role_grants,
    custom_role_grant_revocations
IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    effective_function oid := to_regprocedure('custom_rbac_effective_permissions(uuid,uuid)');
    guard_function oid := to_regprocedure('guard_system_role_permission_mutation()');
    revision_function oid := to_regprocedure('validate_custom_role_revision()');
    grant_function oid := to_regprocedure('validate_custom_role_grant()');
    assignment_function oid := to_regprocedure('lock_custom_rbac_identity_assignment()');
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 78 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 78 THEN
        RAISE EXCEPTION 'package commerce tenant RBAC requires frozen migration head 078'
            USING ERRCODE = 'P7900';
    END IF;
    IF (SELECT count(*) FROM permissions
        WHERE name IN ('package_subscriptions.read', 'package_subscriptions.manage')) <> 2 OR
       EXISTS (
           SELECT 1 FROM custom_rbac_permission_catalog
           WHERE permission_name IN (
               'package_subscriptions.read', 'package_subscriptions.manage'
           )
       ) THEN
        RAISE EXCEPTION 'package commerce tenant RBAC permission baseline is invalid'
            USING ERRCODE = 'P7900';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM role_permissions permission
        JOIN roles role ON role.id = permission.role_id
        JOIN access_scopes scope ON scope.id = role.scope_id
        WHERE permission.permission_name IN (
              'package_subscriptions.read', 'package_subscriptions.manage'
          ) AND NOT (
              role.system_role AND scope.kind = 'platform' AND role.name = 'platform_owner'
          )
    ) OR EXISTS (
        SELECT 1
        FROM custom_role_revisions revision
        WHERE revision.permissions && ARRAY[
            'package_subscriptions.read', 'package_subscriptions.manage'
        ]::text[]
    ) THEN
        RAISE EXCEPTION 'unexpected tenant package subscription grants precede migration 079'
            USING ERRCODE = 'P7900';
    END IF;
    IF effective_function IS NULL OR guard_function IS NULL OR revision_function IS NULL OR
       grant_function IS NULL OR assignment_function IS NULL OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        WHERE procedure.oid = effective_function
          AND procedure.provolatile = 's'
          AND NOT procedure.prosecdef
          AND procedure.prosrc LIKE '%package_subscriptions.read%package_subscriptions.manage%'
          AND procedure.prosrc LIKE '%role_permission.permission_name NOT IN%'
          AND procedure.prosrc LIKE '%LEFT JOIN custom_role_grant_revocations%'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        WHERE procedure.oid = guard_function
          AND procedure.provolatile = 'v'
          AND NOT procedure.prosecdef
          AND procedure.prosrc LIKE '%system role permissions are immutable%'
          AND procedure.prosrc LIKE '%package_subscriptions.read%package_subscriptions.manage%'
          AND procedure.prosrc LIKE '%identity_verification.self.manage%'
          AND procedure.prosrc LIKE '%promotions.quote%promotions.redeem%'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        WHERE procedure.oid = revision_function
          AND procedure.provolatile = 'v'
          AND NOT procedure.prosecdef
          AND procedure.prosrc LIKE '%custom_rbac_effective_permissions(NEW.tenant_scope_id, NEW.created_by_user_id)%'
          AND procedure.prosrc LIKE '%custom role revision requires step-up proof%'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        WHERE procedure.oid = grant_function
          AND procedure.provolatile = 'v'
          AND NOT procedure.prosecdef
          AND procedure.prosrc LIKE '%custom_rbac_effective_permissions(NEW.tenant_scope_id, NEW.granted_by_user_id)%'
          AND procedure.prosrc LIKE '%invalid custom role grant%'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_proc procedure
        WHERE procedure.oid = assignment_function
          AND procedure.provolatile = 'v'
          AND NOT procedure.prosecdef
          AND procedure.prosrc LIKE '%custom role assignment projection is protected%'
    ) THEN
        RAISE EXCEPTION 'custom RBAC function baseline is invalid'
            USING ERRCODE = 'P7900';
    END IF;
END;
$$;

CREATE TABLE package_commerce_tenant_rbac_catalog_additions_079 (
    permission_name text PRIMARY KEY CHECK (
        permission_name IN ('package_subscriptions.read', 'package_subscriptions.manage')
    ),
    source_migration smallint NOT NULL DEFAULT 79 CHECK (source_migration = 79),
    FOREIGN KEY (permission_name)
        REFERENCES custom_rbac_permission_catalog(permission_name) ON DELETE RESTRICT
);

WITH additions AS (
    INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
        ('package_subscriptions.read', false),
        ('package_subscriptions.manage', false)
    RETURNING permission_name
)
INSERT INTO package_commerce_tenant_rbac_catalog_additions_079 (permission_name)
SELECT permission_name FROM additions;

CREATE TABLE package_commerce_tenant_rbac_grant_additions_079 (
    role_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    permission_name text NOT NULL CHECK (
        permission_name IN ('package_subscriptions.read', 'package_subscriptions.manage')
    ),
    source_migration smallint NOT NULL DEFAULT 79 CHECK (source_migration = 79),
    PRIMARY KEY (role_id, permission_name),
    FOREIGN KEY (tenant_scope_id, role_id)
        REFERENCES roles(scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT package_commerce_tenant_rbac_grant_role_permission_fk
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE RESTRICT,
    CHECK (tenant_scope_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

CREATE OR REPLACE FUNCTION custom_rbac_effective_permissions(requested_scope_id uuid, requested_user_id uuid)
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
              'api_keys.admin.manage', 'packages.manage', 'nodes.read', 'nodes.manage',
              'control.upgrades.check', 'node_ca.manage', 'system_configuration.read',
              'system_configuration.manage'
          )
          AND (
              role_permission.permission_name NOT IN (
                  'package_subscriptions.read', 'package_subscriptions.manage'
              ) OR
              (role.system_role AND role.name = 'tenant_owner') OR
              (role.system_role AND role.name = 'tenant_viewer' AND
               role_permission.permission_name = 'package_subscriptions.read')
          )
        UNION ALL
        SELECT custom_permission.permission_name
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
        CROSS JOIN LATERAL unnest(revision.permissions) AS custom_permission(permission_name)
        LEFT JOIN custom_role_grant_revocations revocation ON revocation.grant_id = grant_row.id
        WHERE scope.id = requested_scope_id AND scope.kind = 'tenant' AND revocation.id IS NULL
          AND NOT (
              custom_permission.permission_name = 'package_subscriptions.manage' AND EXISTS (
                  SELECT 1
                  FROM role_assignments viewer_assignment
                  JOIN roles viewer_role
                    ON viewer_role.id = viewer_assignment.role_id
                   AND viewer_role.scope_id = scope.id
                   AND viewer_role.system_role
                   AND viewer_role.name = 'tenant_viewer'
                  WHERE viewer_assignment.scope_id = scope.id
                    AND viewer_assignment.user_id = requested_user_id
              )
          )
    ) effective;
$$;

CREATE OR REPLACE FUNCTION validate_custom_role_revision()
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
       ) OR (
           'package_subscriptions.manage' = ANY(NEW.permissions) AND EXISTS (
               SELECT 1
               FROM custom_role_grants grant_row
               JOIN role_assignments viewer_assignment
                 ON viewer_assignment.scope_id = grant_row.tenant_scope_id
                AND viewer_assignment.user_id = grant_row.subject_user_id
               JOIN roles viewer_role
                 ON viewer_role.id = viewer_assignment.role_id
                AND viewer_role.scope_id = grant_row.tenant_scope_id
                AND viewer_role.system_role
                AND viewer_role.name = 'tenant_viewer'
               LEFT JOIN custom_role_grant_revocations revocation
                 ON revocation.grant_id = grant_row.id
               WHERE grant_row.role_id = NEW.role_id
                 AND grant_row.tenant_scope_id = NEW.tenant_scope_id
                 AND revocation.id IS NULL
           )
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

CREATE OR REPLACE FUNCTION validate_custom_role_grant()
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
       ) OR EXISTS (
           SELECT 1
           FROM custom_role_revisions revision
           JOIN role_assignments viewer_assignment
             ON viewer_assignment.scope_id = NEW.tenant_scope_id
            AND viewer_assignment.user_id = NEW.subject_user_id
           JOIN roles viewer_role
             ON viewer_role.id = viewer_assignment.role_id
            AND viewer_role.scope_id = NEW.tenant_scope_id
            AND viewer_role.system_role
            AND viewer_role.name = 'tenant_viewer'
           WHERE revision.role_id = NEW.role_id
             AND revision.revision = NEW.role_revision
             AND 'package_subscriptions.manage' = ANY(revision.permissions)
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

CREATE OR REPLACE FUNCTION lock_custom_rbac_identity_assignment()
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
    IF TG_OP <> 'DELETE' AND EXISTS (
        SELECT 1
        FROM roles assigned_role
        JOIN access_scopes scope ON scope.id = assigned_role.scope_id
        JOIN role_assignments existing
          ON existing.scope_id = NEW.scope_id
         AND existing.user_id = NEW.user_id
        JOIN roles existing_role
          ON existing_role.id = existing.role_id
         AND existing_role.scope_id = existing.scope_id
        WHERE assigned_role.id = NEW.role_id
          AND assigned_role.scope_id = NEW.scope_id
          AND assigned_role.system_role
          AND assigned_role.name IN ('tenant_owner', 'tenant_viewer')
          AND scope.kind = 'tenant'
          AND existing_role.system_role
          AND existing_role.name IN ('tenant_owner', 'tenant_viewer')
          AND existing_role.name <> assigned_role.name
          AND (TG_OP <> 'UPDATE' OR existing.role_id <> OLD.role_id)
    ) THEN
        RAISE EXCEPTION 'tenant owner and viewer assignments are mutually exclusive'
            USING ERRCODE = '42501';
    END IF;
    IF TG_OP <> 'DELETE' AND EXISTS (
        SELECT 1
        FROM roles viewer_role
        JOIN custom_role_grants grant_row
          ON grant_row.tenant_scope_id = NEW.scope_id
         AND grant_row.subject_user_id = NEW.user_id
        JOIN custom_roles custom_role
          ON custom_role.id = grant_row.role_id
         AND custom_role.tenant_scope_id = NEW.scope_id
         AND custom_role.deactivated_at IS NULL
        JOIN custom_role_revisions revision
          ON revision.role_id = custom_role.id
         AND revision.revision = custom_role.current_revision
        LEFT JOIN custom_role_grant_revocations revocation
          ON revocation.grant_id = grant_row.id
        WHERE viewer_role.id = NEW.role_id
          AND viewer_role.scope_id = NEW.scope_id
          AND viewer_role.system_role
          AND viewer_role.name = 'tenant_viewer'
          AND revocation.id IS NULL
          AND 'package_subscriptions.manage' = ANY(revision.permissions)
    ) THEN
        RAISE EXCEPTION 'tenant viewer cannot receive package subscription management'
            USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION guard_system_role_permission_mutation()
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
            'api_keys.admin.manage', 'packages.manage', 'nodes.read', 'nodes.manage',
            'control.upgrades.check', 'node_ca.manage', 'system_configuration.read',
            'system_configuration.manage'
        ) OR
        (NEW.permission_name = 'package_subscriptions.read' AND
         target_role_name NOT IN ('tenant_owner', 'tenant_viewer')) OR
        (NEW.permission_name = 'package_subscriptions.manage' AND
         target_role_name <> 'tenant_owner') OR
        (target_role_name = 'tenant_viewer' AND
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

WITH additions AS (
    INSERT INTO role_permissions (role_id, permission_name)
    SELECT role.id, permission.name
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id
    CROSS JOIN (VALUES
        ('package_subscriptions.read'),
        ('package_subscriptions.manage')
    ) AS permission(name)
    WHERE role.system_role AND scope.kind = 'tenant' AND role.name = 'tenant_owner'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO package_commerce_tenant_rbac_grant_additions_079 (
    role_id, tenant_scope_id, permission_name
)
SELECT additions.role_id, role.scope_id, additions.permission_name
FROM additions
JOIN roles role ON role.id = additions.role_id;

WITH additions AS (
    INSERT INTO role_permissions (role_id, permission_name)
    SELECT role.id, 'package_subscriptions.read'
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id
    WHERE role.system_role AND scope.kind = 'tenant' AND role.name = 'tenant_viewer'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO package_commerce_tenant_rbac_grant_additions_079 (
    role_id, tenant_scope_id, permission_name
)
SELECT additions.role_id, role.scope_id, additions.permission_name
FROM additions
JOIN roles role ON role.id = additions.role_id;

CREATE FUNCTION protect_package_commerce_tenant_rbac_provenance_079()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF pg_trigger_depth() < 2 THEN
            RAISE EXCEPTION 'package commerce tenant RBAC provenance is projection controlled'
                USING ERRCODE = 'P7901';
        END IF;
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'package commerce tenant RBAC provenance is append-only'
        USING ERRCODE = 'P7901';
END;
$$;

CREATE TRIGGER package_commerce_tenant_rbac_catalog_protect_079
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON package_commerce_tenant_rbac_catalog_additions_079
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_commerce_tenant_rbac_provenance_079();
CREATE TRIGGER package_commerce_tenant_rbac_grants_protect_079
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON package_commerce_tenant_rbac_grant_additions_079
FOR EACH STATEMENT EXECUTE FUNCTION protect_package_commerce_tenant_rbac_provenance_079();
ALTER TABLE package_commerce_tenant_rbac_catalog_additions_079
    ENABLE ALWAYS TRIGGER package_commerce_tenant_rbac_catalog_protect_079;
ALTER TABLE package_commerce_tenant_rbac_grant_additions_079
    ENABLE ALWAYS TRIGGER package_commerce_tenant_rbac_grants_protect_079;

CREATE FUNCTION protect_package_commerce_tenant_rbac_catalog_079()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.permission_name IN ('package_subscriptions.read', 'package_subscriptions.manage') THEN
        RAISE EXCEPTION 'migration 079 package commerce RBAC catalog rows cannot be deleted'
            USING ERRCODE = 'P7901';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER package_commerce_tenant_rbac_catalog_delete_guard_079
BEFORE DELETE ON custom_rbac_permission_catalog
FOR EACH ROW EXECUTE FUNCTION protect_package_commerce_tenant_rbac_catalog_079();
ALTER TABLE custom_rbac_permission_catalog
    ENABLE ALWAYS TRIGGER package_commerce_tenant_rbac_catalog_delete_guard_079;

CREATE FUNCTION protect_package_commerce_tenant_scope_classification_079()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.kind, NEW.tenant_id) IS DISTINCT FROM ROW(OLD.kind, OLD.tenant_id) AND EXISTS (
        SELECT 1
        FROM package_commerce_tenant_rbac_grant_additions_079 addition
        WHERE addition.tenant_scope_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'scope classification with package commerce RBAC grants is immutable'
            USING ERRCODE = 'P7901';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER access_scopes_protect_package_commerce_classification_079
BEFORE UPDATE OF kind, tenant_id ON access_scopes
FOR EACH ROW EXECUTE FUNCTION protect_package_commerce_tenant_scope_classification_079();
ALTER TABLE access_scopes
    ENABLE ALWAYS TRIGGER access_scopes_protect_package_commerce_classification_079;

CREATE FUNCTION project_package_commerce_tenant_system_role_permissions_079()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO target_scope_kind
    FROM access_scopes
    WHERE id = NEW.scope_id
    FOR SHARE;
    IF target_scope_kind IS DISTINCT FROM 'tenant' OR
       NEW.name NOT IN ('tenant_owner', 'tenant_viewer') THEN
        RETURN NEW;
    END IF;

    WITH additions AS (
        INSERT INTO role_permissions (role_id, permission_name)
        SELECT NEW.id, permission.name
        FROM (VALUES
            ('package_subscriptions.read'),
            ('package_subscriptions.manage')
        ) AS permission(name)
        WHERE NEW.name = 'tenant_owner' OR permission.name = 'package_subscriptions.read'
        ON CONFLICT DO NOTHING
        RETURNING role_id, permission_name
    )
    INSERT INTO package_commerce_tenant_rbac_grant_additions_079 (
        role_id, tenant_scope_id, permission_name
    )
    SELECT role_id, NEW.scope_id, permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_project_package_commerce_permissions_079
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION project_package_commerce_tenant_system_role_permissions_079();

DO $$
BEGIN
    IF (SELECT count(*) FROM package_commerce_tenant_rbac_catalog_additions_079) <> 2 OR
       EXISTS (
           SELECT 1
           FROM custom_rbac_permission_catalog catalog
           WHERE catalog.permission_name IN (
               'package_subscriptions.read', 'package_subscriptions.manage'
           ) AND catalog.step_up_required
       ) OR EXISTS (
           SELECT 1
           FROM roles role
           JOIN access_scopes scope ON scope.id = role.scope_id
           LEFT JOIN role_permissions read_permission
             ON read_permission.role_id = role.id
            AND read_permission.permission_name = 'package_subscriptions.read'
           LEFT JOIN role_permissions manage_permission
             ON manage_permission.role_id = role.id
            AND manage_permission.permission_name = 'package_subscriptions.manage'
           WHERE role.system_role AND scope.kind = 'tenant'
             AND (
                 (role.name = 'tenant_owner' AND
                  (read_permission.role_id IS NULL OR manage_permission.role_id IS NULL)) OR
                 (role.name = 'tenant_viewer' AND
                  (read_permission.role_id IS NULL OR manage_permission.role_id IS NOT NULL)) OR
                 (role.name NOT IN ('tenant_owner', 'tenant_viewer') AND
                  (read_permission.role_id IS NOT NULL OR manage_permission.role_id IS NOT NULL))
             )
       ) OR EXISTS (
           SELECT 1
           FROM package_commerce_tenant_rbac_grant_additions_079 addition
           JOIN roles role ON role.id = addition.role_id AND role.scope_id = addition.tenant_scope_id
           JOIN access_scopes scope ON scope.id = role.scope_id
           WHERE addition.source_migration <> 79 OR NOT role.system_role OR scope.kind <> 'tenant' OR
                 NOT (
                     (role.name = 'tenant_owner' AND addition.permission_name IN (
                         'package_subscriptions.read', 'package_subscriptions.manage'
                     )) OR
                     (role.name = 'tenant_viewer' AND
                      addition.permission_name = 'package_subscriptions.read')
                 )
       ) THEN
        RAISE EXCEPTION 'package commerce tenant RBAC projection is incomplete'
            USING ERRCODE = 'P7900';
    END IF;
END;
$$;

REVOKE ALL ON TABLE package_commerce_tenant_rbac_catalog_additions_079 FROM PUBLIC;
REVOKE ALL ON TABLE package_commerce_tenant_rbac_grant_additions_079 FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_commerce_tenant_rbac_provenance_079() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_commerce_tenant_rbac_catalog_079() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_commerce_tenant_scope_classification_079() FROM PUBLIC;
REVOKE ALL ON FUNCTION project_package_commerce_tenant_system_role_permissions_079() FROM PUBLIC;
GRANT SELECT ON TABLE package_commerce_tenant_rbac_catalog_additions_079 TO CURRENT_USER;
GRANT SELECT ON TABLE package_commerce_tenant_rbac_grant_additions_079 TO CURRENT_USER;
