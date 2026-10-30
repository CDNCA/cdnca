LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions
    IN ACCESS EXCLUSIVE MODE;

DO $migration_186$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 185 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 185 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=185 AND migration_id='185_plugin_webhook_canonical_body_brace_fix' AND
              checksum_sha256='96832a834af03cb703ba89f4f247d5559d75a17089047a181ed698c8de9bb85f' AND
              down_checksum_sha256='fe98212bbb6fc763a2c2f6efba61aa9007f7de5371271e8ceed64833f6e18ef9' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 186 requires the exact verified 185 release head'
            USING ERRCODE='P1860';
    END IF;
END;
$migration_186$;

CREATE OR REPLACE FUNCTION grant_site_domain_permissions_148()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system_role AND NEW.name IN ('platform_owner','tenant_owner') THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'sites.export') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

DELETE FROM role_permissions AS grant_row
USING roles AS role
WHERE grant_row.role_id=role.id
  AND grant_row.permission_name='sites.export'
  AND role.system_role
  AND role.name='tenant_viewer';

REVOKE ALL ON FUNCTION grant_site_domain_permissions_148() FROM PUBLIC;
