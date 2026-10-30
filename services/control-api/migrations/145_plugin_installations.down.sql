LOCK TABLE schema_migrations, plugin_installation_receipts, plugin_installation_heads,
    permissions, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_145$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 145 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 145 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 145 AND migration_id = '145_plugin_installations' AND
              checksum_sha256 = 'c2a8d53baacfd5cf0d0229e70b1cb90238cfedf08b08ccc2118a071d569cf163' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 145 rollback requires the exact verified 145 head'
            USING ERRCODE = 'P1450';
    END IF;
    IF EXISTS (SELECT 1 FROM plugin_installation_receipts) OR
       EXISTS (SELECT 1 FROM plugin_installation_heads) OR EXISTS (
        SELECT 1 FROM role_permissions
        WHERE permission_name IN ('plugin_installations.read','plugin_installations.manage')
    ) THEN
        RAISE EXCEPTION 'migration 145 rollback would discard plugin installation facts'
            USING ERRCODE = 'P1457';
    END IF;
END;
$migration_145$;

DROP TRIGGER plugin_installation_receipts_no_truncate_145 ON plugin_installation_receipts;
DROP TRIGGER plugin_installation_heads_no_truncate_145 ON plugin_installation_heads;
DROP FUNCTION prevent_plugin_installation_truncate_145();
DROP TRIGGER plugin_installation_receipts_append_only_145 ON plugin_installation_receipts;
DROP FUNCTION protect_plugin_installation_receipt_145();
DROP TRIGGER plugin_installation_heads_no_delete_145 ON plugin_installation_heads;
DROP FUNCTION protect_plugin_installation_head_delete_145();
DROP TRIGGER plugin_installation_heads_transition_145 ON plugin_installation_heads;
DROP FUNCTION validate_plugin_installation_head_145();

DROP TABLE plugin_installation_receipts;
DROP TABLE plugin_installation_heads;
DROP FUNCTION valid_plugin_installation_scopes_145(text[]);

DELETE FROM permissions WHERE name IN ('plugin_installations.read','plugin_installations.manage');
