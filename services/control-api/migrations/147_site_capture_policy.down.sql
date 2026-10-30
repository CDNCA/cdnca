LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions,
    site_capture_policy_revisions, site_capture_policy_heads, site_capture_policy_receipts
    IN ACCESS EXCLUSIVE MODE;

DO $migration_147$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 147 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 147 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 147 AND migration_id = '147_site_capture_policy' AND
              checksum_sha256 = '353df42d5169317c797469af9341f827d16f51ba7312b2f4185326bc4934cab0' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 146 AND migration_id = '146_package_cycle_enforcement' AND
              checksum_sha256 = '9763f9d3bbba5f12560e3254e2ab22281fb0d0e63b3b412e807b121ef3643a25' AND
              down_checksum_sha256 = '1d9986f1c21d13957a57b00c63c7c06b0f7a5497c53df19695d6c2ad1a8b16ad' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 147 rollback requires the exact verified 147 head'
            USING ERRCODE = 'P1470';
    END IF;
    IF EXISTS (SELECT 1 FROM site_capture_policy_heads) OR
       EXISTS (SELECT 1 FROM site_capture_policy_revisions) OR
       EXISTS (SELECT 1 FROM site_capture_policy_receipts) THEN
        RAISE EXCEPTION 'migration 147 rollback would discard site capture policy facts'
            USING ERRCODE = 'P1477';
    END IF;
    IF EXISTS (
        SELECT 1 FROM role_permissions AS grant_row
        JOIN roles AS role ON role.id=grant_row.role_id
        WHERE grant_row.permission_name IN ('site_capture.read','site_capture.manage')
          AND NOT role.system_role
    ) THEN
        RAISE EXCEPTION 'migration 147 rollback requires all non-system grants to be removed'
            USING ERRCODE = 'P1478';
    END IF;
END;
$migration_147$;

DROP TRIGGER site_capture_policy_receipts_no_truncate_147 ON site_capture_policy_receipts;
DROP TRIGGER site_capture_policy_heads_no_truncate_147 ON site_capture_policy_heads;
DROP TRIGGER site_capture_policy_revisions_no_truncate_147 ON site_capture_policy_revisions;
DROP TRIGGER site_capture_policy_receipts_guard_147 ON site_capture_policy_receipts;
DROP TRIGGER site_capture_policy_heads_guard_147 ON site_capture_policy_heads;
DROP TRIGGER site_capture_policy_revisions_immutable_147 ON site_capture_policy_revisions;
DROP TRIGGER roles_site_capture_permissions_147 ON roles;

DROP TABLE site_capture_policy_receipts;
DROP TABLE site_capture_policy_heads;
DROP TABLE site_capture_policy_revisions;

DROP FUNCTION prevent_site_capture_truncate_147();
DROP FUNCTION guard_site_capture_receipt_147();
DROP FUNCTION guard_site_capture_head_147();
DROP FUNCTION protect_site_capture_revision_147();
DROP FUNCTION grant_site_capture_permissions_147();

DELETE FROM role_permissions
WHERE permission_name IN ('site_capture.read','site_capture.manage');
DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('site_capture.read','site_capture.manage');
DELETE FROM permissions
WHERE name IN ('site_capture.read','site_capture.manage');
