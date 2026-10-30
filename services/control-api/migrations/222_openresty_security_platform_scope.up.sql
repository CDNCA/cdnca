LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_222$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 221 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 221 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 221 AND migration_id = '221_tenant_display_ids' AND
              checksum_sha256 = 'f15a1d7c1f22e2dd5e42032d386399791c000d3b7fed63bfcc2359e111d7b51a' AND
              down_checksum_sha256 = '40c91bbd390cf9d19ccba4dc3c948ea83ca4cc7a2551b67ebf49e7cf76966fc3' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR (SELECT count(*) FROM permissions
             WHERE name IN ('openresty_security.read', 'openresty_security.manage')) <> 2 THEN
        RAISE EXCEPTION 'migration 222 requires the exact verified 221 release head and the canonical OpenResty security permissions'
            USING ERRCODE = 'P2220';
    END IF;
END;
$migration_222$;

DELETE FROM role_permissions assignment
USING roles role, access_scopes scope
WHERE assignment.role_id = role.id AND role.scope_id = scope.id AND
      scope.kind = 'tenant' AND role.system_role AND role.name = 'tenant_owner' AND
      assignment.permission_name IN ('openresty_security.read', 'openresty_security.manage');
