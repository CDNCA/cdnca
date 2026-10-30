LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions
    IN ACCESS EXCLUSIVE MODE;

DO $migration_186_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 186 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 186 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=186 AND migration_id='186_site_domain_export_rbac' AND
              checksum_sha256='fa30f9adc3f68d6bddca97311f1345fb39327cb06cb28e8d640ee824e4466203' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=185 AND migration_id='185_plugin_webhook_canonical_body_brace_fix' AND
              checksum_sha256='96832a834af03cb703ba89f4f247d5559d75a17089047a181ed698c8de9bb85f' AND
              down_checksum_sha256='fe98212bbb6fc763a2c2f6efba61aa9007f7de5371271e8ceed64833f6e18ef9' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 186 rollback requires the exact verified 186 and 185 release heads'
            USING ERRCODE='P1860';
    END IF;
END;
$migration_186_down$;

CREATE OR REPLACE FUNCTION grant_site_domain_permissions_148()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system_role AND NEW.name IN ('platform_owner','tenant_owner','tenant_viewer') THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'sites.export') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

INSERT INTO role_permissions(role_id,permission_name)
SELECT id,'sites.export' FROM roles
WHERE system_role AND name IN ('platform_owner','tenant_owner','tenant_viewer')
ON CONFLICT DO NOTHING;

REVOKE ALL ON FUNCTION grant_site_domain_permissions_148() FROM PUBLIC;
