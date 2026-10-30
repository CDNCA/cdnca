LOCK TABLE schema_migrations, access_scopes, roles, role_permissions,
    permissions, custom_rbac_permission_catalog
IN ACCESS EXCLUSIVE MODE;

DO $migration_230$
DECLARE
    permission_guard oid := to_regprocedure('guard_system_role_permission_mutation()');
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 229 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 229 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 229 AND migration_id = '229_control_runtime_publication_function_grants' AND
              checksum_sha256 = '2f7ba254e3c0599c8160ebe06940a1059a9975965baa2331c2f5d1b5818180a1' AND
              down_checksum_sha256 = '231ed7fa9f14f06b9cb1d029df30791097595c5a7307d5627e039b44e17bc4db' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR (SELECT count(*) FROM permissions
             WHERE name IN ('security_policies.read', 'security_policies.manage')) <> 2 OR
       (SELECT count(*) FROM custom_rbac_permission_catalog
             WHERE permission_name = 'security_policies.read' AND NOT step_up_required) <> 1 OR
       (SELECT count(*) FROM custom_rbac_permission_catalog
             WHERE permission_name = 'security_policies.manage' AND step_up_required) <> 1 OR
       permission_guard IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_proc
        WHERE oid = permission_guard AND provolatile = 'v' AND NOT prosecdef AND
              prosrc LIKE '%custom_rbac_permission_catalog%' AND
              prosrc LIKE '%system role permissions are immutable%' AND
              prosrc LIKE '%target_role_name = ''tenant_viewer''%'
       ) OR EXISTS (
        SELECT 1
        FROM role_permissions grant_row
        JOIN roles role ON role.id = grant_row.role_id
        JOIN access_scopes scope ON scope.id = role.scope_id
        WHERE scope.kind = 'tenant' AND role.system_role AND role.name = 'tenant_viewer' AND
              grant_row.permission_name = 'security_policies.manage'
       ) THEN
        RAISE EXCEPTION 'migration 230 requires the exact verified 229 head and canonical security policy RBAC baseline'
            USING ERRCODE = 'P2300';
    END IF;
END;
$migration_230$;

CREATE TABLE security_policy_system_role_grant_additions_230 (
    role_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    permission_name text NOT NULL CHECK (
        permission_name IN ('security_policies.read', 'security_policies.manage')
    ),
    source_migration smallint NOT NULL DEFAULT 230 CHECK (source_migration = 230),
    PRIMARY KEY (role_id, permission_name),
    FOREIGN KEY (tenant_scope_id, role_id)
        REFERENCES roles(scope_id, id) ON DELETE RESTRICT,
    CONSTRAINT security_policy_system_role_grant_permission_fk_230
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE RESTRICT
);

WITH additions AS (
    INSERT INTO role_permissions (role_id, permission_name)
    SELECT role.id, permission.name
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id
    CROSS JOIN (VALUES
        ('security_policies.read'),
        ('security_policies.manage')
    ) AS permission(name)
    WHERE role.system_role AND scope.kind = 'tenant' AND
          role.name IN ('tenant_owner', 'tenant_viewer') AND
          (role.name = 'tenant_owner' OR permission.name = 'security_policies.read')
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO security_policy_system_role_grant_additions_230 (
    role_id, tenant_scope_id, permission_name
)
SELECT additions.role_id, role.scope_id, additions.permission_name
FROM additions
JOIN roles role ON role.id = additions.role_id;

CREATE FUNCTION protect_security_policy_system_role_provenance_230()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND pg_trigger_depth() >= 2 THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'migration 230 security policy role provenance is projection controlled'
        USING ERRCODE = 'P2301';
END;
$$;

CREATE TRIGGER security_policy_system_role_grants_protect_230
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
ON security_policy_system_role_grant_additions_230
FOR EACH STATEMENT EXECUTE FUNCTION protect_security_policy_system_role_provenance_230();
ALTER TABLE security_policy_system_role_grant_additions_230
    ENABLE ALWAYS TRIGGER security_policy_system_role_grants_protect_230;

CREATE FUNCTION project_security_policy_system_role_permissions_230()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
BEGIN
    IF NOT NEW.system_role OR NEW.name NOT IN ('tenant_owner', 'tenant_viewer') THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO target_scope_kind
    FROM access_scopes
    WHERE id = NEW.scope_id
    FOR SHARE;
    IF target_scope_kind IS DISTINCT FROM 'tenant' THEN
        RETURN NEW;
    END IF;

    WITH additions AS (
        INSERT INTO role_permissions (role_id, permission_name)
        SELECT NEW.id, permission.name
        FROM (VALUES
            ('security_policies.read'),
            ('security_policies.manage')
        ) AS permission(name)
        WHERE NEW.name = 'tenant_owner' OR permission.name = 'security_policies.read'
        ON CONFLICT DO NOTHING
        RETURNING role_id, permission_name
    )
    INSERT INTO security_policy_system_role_grant_additions_230 (
        role_id, tenant_scope_id, permission_name
    )
    SELECT role_id, NEW.scope_id, permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_project_security_policy_permissions_230
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION project_security_policy_system_role_permissions_230();

DO $migration_230_verify$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM roles role
        JOIN access_scopes scope ON scope.id = role.scope_id
        LEFT JOIN role_permissions read_permission
          ON read_permission.role_id = role.id AND
             read_permission.permission_name = 'security_policies.read'
        LEFT JOIN role_permissions manage_permission
          ON manage_permission.role_id = role.id AND
             manage_permission.permission_name = 'security_policies.manage'
        WHERE role.system_role AND scope.kind = 'tenant' AND
              role.name IN ('tenant_owner', 'tenant_viewer') AND (
                  read_permission.role_id IS NULL OR
                  (role.name = 'tenant_owner' AND manage_permission.role_id IS NULL) OR
                  (role.name = 'tenant_viewer' AND manage_permission.role_id IS NOT NULL)
              )
    ) OR EXISTS (
        SELECT 1
        FROM security_policy_system_role_grant_additions_230 addition
        JOIN roles role
          ON role.id = addition.role_id AND role.scope_id = addition.tenant_scope_id
        JOIN access_scopes scope ON scope.id = role.scope_id
        LEFT JOIN role_permissions grant_row
          ON grant_row.role_id = addition.role_id AND
             grant_row.permission_name = addition.permission_name
        WHERE addition.source_migration <> 230 OR grant_row.role_id IS NULL OR
              NOT role.system_role OR scope.kind <> 'tenant' OR
              NOT (
                  (role.name = 'tenant_owner' AND addition.permission_name IN (
                      'security_policies.read', 'security_policies.manage'
                  )) OR
                  (role.name = 'tenant_viewer' AND
                   addition.permission_name = 'security_policies.read')
              )
    ) THEN
        RAISE EXCEPTION 'migration 230 security policy role projection is incomplete'
            USING ERRCODE = 'P2300';
    END IF;
END;
$migration_230_verify$;

REVOKE ALL ON TABLE security_policy_system_role_grant_additions_230 FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_security_policy_system_role_provenance_230() FROM PUBLIC;
REVOKE ALL ON FUNCTION project_security_policy_system_role_permissions_230() FROM PUBLIC;
GRANT SELECT ON TABLE security_policy_system_role_grant_additions_230 TO CURRENT_USER;
