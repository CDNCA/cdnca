LOCK TABLE schema_migrations, access_scopes, roles, role_permissions,
    permissions, custom_rbac_permission_catalog,
    security_policy_system_role_grant_additions_230
IN ACCESS EXCLUSIVE MODE;

DO $migration_230_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 230 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 230 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 230 AND migration_id = '230_security_policy_system_role_projection' AND
              checksum_sha256 = '5a754062f0248ba9f8138cb3240f58a921968dc1526e551a78d5fcfc8e009551' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 229 AND migration_id = '229_control_runtime_publication_function_grants' AND
              checksum_sha256 = '2f7ba254e3c0599c8160ebe06940a1059a9975965baa2331c2f5d1b5818180a1' AND
              down_checksum_sha256 = '231ed7fa9f14f06b9cb1d029df30791097595c5a7307d5627e039b44e17bc4db' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regprocedure('project_security_policy_system_role_permissions_230()') IS NULL OR
          to_regprocedure('protect_security_policy_system_role_provenance_230()') IS NULL OR
          NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgrelid = 'roles'::regclass AND
                  tgname = 'roles_project_security_policy_permissions_230' AND NOT tgisinternal
          ) OR NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgrelid = 'role_permissions'::regclass AND
                  tgname = 'role_permissions_system_role_guard' AND NOT tgisinternal
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
        RAISE EXCEPTION 'migration 230 rollback requires the exact verified projection state'
            USING ERRCODE = 'P2302';
    END IF;
END;
$migration_230_down$;

DROP TRIGGER roles_project_security_policy_permissions_230 ON roles;
DROP FUNCTION project_security_policy_system_role_permissions_230();
DROP TRIGGER security_policy_system_role_grants_protect_230
    ON security_policy_system_role_grant_additions_230;
DROP FUNCTION protect_security_policy_system_role_provenance_230();

ALTER TABLE security_policy_system_role_grant_additions_230
    DROP CONSTRAINT security_policy_system_role_grant_permission_fk_230;
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions grant_row
USING security_policy_system_role_grant_additions_230 addition
WHERE grant_row.role_id = addition.role_id AND
      grant_row.permission_name = addition.permission_name AND
      addition.source_migration = 230;
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;

DROP TABLE security_policy_system_role_grant_additions_230;
