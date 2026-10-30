LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions,
    site_domain_facts, site_domain_export_snapshots, site_domain_export_rows
    IN ACCESS EXCLUSIVE MODE;

DO $migration_148$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 148 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 148 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 148 AND migration_id = '148_site_domains' AND
              checksum_sha256 = '18e34a28e5f078b55e4143a497376643bad4b8414a13bdd05d97c4be04d62ec4' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 147 AND migration_id = '147_site_capture_policy' AND
              checksum_sha256 = '353df42d5169317c797469af9341f827d16f51ba7312b2f4185326bc4934cab0' AND
              down_checksum_sha256 = 'e536c664a82d23e7b61d89380c69f22476770e5eaa0a5c3bd69de6bad3c02ede' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 148 rollback requires the exact verified 148 head'
            USING ERRCODE = 'P1480';
    END IF;
    IF EXISTS (SELECT 1 FROM site_domain_facts) THEN
        RAISE EXCEPTION 'migration 148 rollback would discard historical site domain facts'
            USING ERRCODE = 'P1484';
    END IF;
    IF EXISTS (SELECT 1 FROM site_domain_export_snapshots) OR
       EXISTS (SELECT 1 FROM site_domain_export_rows) THEN
        RAISE EXCEPTION 'migration 148 rollback would discard immutable export snapshots'
            USING ERRCODE = 'P1485';
    END IF;
    IF EXISTS (
        SELECT 1 FROM role_permissions AS grant_row
        JOIN roles AS role ON role.id=grant_row.role_id
        WHERE grant_row.permission_name='sites.export' AND NOT role.system_role
    ) THEN
        RAISE EXCEPTION 'migration 148 rollback requires all non-system grants to be removed'
            USING ERRCODE = 'P1486';
    END IF;
END;
$migration_148$;

DROP TRIGGER site_domain_export_rows_immutable_148 ON site_domain_export_rows;
DROP TRIGGER site_domain_export_snapshots_immutable_148 ON site_domain_export_snapshots;
DROP TRIGGER site_domain_facts_immutable_148 ON site_domain_facts;
DROP TRIGGER site_domain_facts_overlap_148 ON site_domain_facts;
DROP TRIGGER roles_site_domain_permissions_148 ON roles;

DROP TABLE site_domain_export_rows;
DROP TABLE site_domain_export_snapshots;
DROP TABLE site_domain_facts;

DROP FUNCTION protect_site_domain_immutable_148();
DROP FUNCTION guard_site_domain_fact_148();
DROP FUNCTION grant_site_domain_permissions_148();

DELETE FROM role_permissions WHERE permission_name='sites.export';
DELETE FROM custom_rbac_permission_catalog WHERE permission_name='sites.export';
DELETE FROM permissions WHERE name='sites.export';

-- version = 147 AND migration_id = '147_site_capture_policy'
