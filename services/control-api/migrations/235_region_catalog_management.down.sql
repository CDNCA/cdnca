LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions,
    nodes, region_catalog, region_catalog_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_235_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 235 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 235 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 235 AND migration_id = '235_region_catalog_management' AND
              checksum_sha256 = '165c59e45df388ca3105f7627e617aab7b5bdd59fcc2557d63148ee5003b0f8d' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR (SELECT count(*) FROM information_schema.columns
             WHERE table_schema=current_schema() AND table_name='region_catalog' AND
                   column_name IN ('description','l2_check_port','sort_order','revision')) <> 4 OR
          to_regprocedure(current_schema() || '.protect_region_catalog_management_235()') IS NULL OR
          to_regprocedure(current_schema() || '.protect_region_catalog_write_request_235()') IS NULL THEN
        RAISE EXCEPTION 'migration 235 rollback requires the exact verified 235 release head'
            USING ERRCODE = 'P2353';
    END IF;
    IF EXISTS (
        SELECT 1 FROM region_catalog
        WHERE description <> '' OR l2_check_port <> 80 OR sort_order <> 100 OR revision <> 1
    ) OR EXISTS (SELECT 1 FROM region_catalog_write_requests) THEN
        RAISE EXCEPTION 'migration 235 rollback cannot discard region changes or idempotency receipts'
            USING ERRCODE = 'P2353';
    END IF;
END;
$migration_235_down$;

DO $region_catalog_management_runtime_revokes$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        REVOKE SELECT, INSERT, UPDATE ON region_catalog_write_requests FROM cdnca_control_app;
        REVOKE UPDATE, DELETE ON region_catalog FROM cdnca_control_app;
    END IF;
END;
$region_catalog_management_runtime_revokes$;

DROP TRIGGER region_catalog_write_requests_truncate_235 ON region_catalog_write_requests;
DROP TRIGGER region_catalog_write_requests_immutable_235 ON region_catalog_write_requests;
DROP FUNCTION protect_region_catalog_write_request_235();
DROP TABLE region_catalog_write_requests;

DROP TRIGGER region_catalog_management_truncate_235 ON region_catalog;
DROP TRIGGER region_catalog_management_delete_235 ON region_catalog;
DROP TRIGGER region_catalog_management_update_235 ON region_catalog;
DROP FUNCTION protect_region_catalog_management_235();

DROP INDEX region_catalog_scope_sort_235_idx;
ALTER TABLE region_catalog
    DROP CONSTRAINT region_catalog_revision_235_check,
    DROP CONSTRAINT region_catalog_sort_order_235_check,
    DROP CONSTRAINT region_catalog_l2_check_port_235_check,
    DROP CONSTRAINT region_catalog_description_235_check,
    DROP COLUMN revision,
    DROP COLUMN sort_order,
    DROP COLUMN l2_check_port,
    DROP COLUMN description;

DELETE FROM role_permissions WHERE permission_name = 'regions.manage';
DELETE FROM permissions WHERE name = 'regions.manage';
