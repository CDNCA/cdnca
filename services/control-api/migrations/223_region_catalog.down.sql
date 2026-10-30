LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions, nodes, region_catalog IN ACCESS EXCLUSIVE MODE;

DO $migration_223_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 223 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 223 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 223 AND migration_id = '223_region_catalog' AND
              checksum_sha256 = '75fdb6a530e0f3369c235aa4d45e0ebcd24be9ac2ee16b5e733ce047eaf7f719' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 222 AND migration_id = '222_openresty_security_platform_scope' AND
              checksum_sha256 = '9608c52faf69e6ef329dd57e752727c6e83880b6091c88437c5277bcae16f2fc' AND
              down_checksum_sha256 = 'dab33f6c9a728f05872b856f3e6f6788de49fd30dfc2af0ed8976b0915525b13' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 223 rollback requires the exact verified 223 release head'
            USING ERRCODE = 'P2230';
    END IF;
END;
$migration_223_down$;

DO $region_catalog_runtime_revokes$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        REVOKE SELECT, INSERT ON region_catalog FROM cdnca_control_app;
        REVOKE USAGE, SELECT ON SEQUENCE region_catalog_display_id_seq FROM cdnca_control_app;
    END IF;
END;
$region_catalog_runtime_revokes$;

DROP TRIGGER nodes_region_catalog_sync_223 ON nodes;
DROP FUNCTION sync_node_region_catalog_223();

DROP TRIGGER region_catalog_display_id_immutable_223 ON region_catalog;
DROP FUNCTION protect_region_catalog_display_id_223();
DROP TRIGGER region_catalog_platform_scope_223 ON region_catalog;
DROP FUNCTION validate_region_catalog_platform_scope_223();

DROP TABLE region_catalog;
DROP SEQUENCE region_catalog_display_id_seq;

DELETE FROM role_permissions WHERE permission_name = 'regions.read';
DELETE FROM permissions WHERE name = 'regions.read';
