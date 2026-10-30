LOCK TABLE schema_migrations, tenants IN ACCESS EXCLUSIVE MODE;

DO $migration_221_down$
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
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 220 AND migration_id = '220_error_page_scope_overrides' AND
              checksum_sha256 = '340dc49da585b3f9e2f85da9ffeb42ba7a5e184a48c8b157a88ad27fd26cf713' AND
              down_checksum_sha256 = '4567747996feb94eb56bf01f31ac1875b141485c381b6c2e6fe90b7c08d78493' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 221 rollback requires the exact verified 221 release head'
            USING ERRCODE = 'P2210';
    END IF;
END;
$migration_221_down$;

REVOKE USAGE, SELECT ON SEQUENCE tenants_display_id_seq FROM cdnca_control_app;

DROP TRIGGER tenants_display_id_immutable_221 ON tenants;
DROP FUNCTION protect_tenant_display_id_221();

ALTER SEQUENCE tenants_display_id_seq OWNED BY NONE;

ALTER TABLE tenants
    DROP CONSTRAINT tenants_display_id_unique,
    DROP CONSTRAINT tenants_display_id_positive,
    DROP COLUMN display_id;

DROP SEQUENCE tenants_display_id_seq;
