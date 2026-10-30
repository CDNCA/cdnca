LOCK TABLE schema_migrations, cdn_provider_accounts, site_supply_cdn_configs, site_supply_bindings,
    cdn_zone_imports, cdn_import_sites, cdn_import_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_362_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 362 OR
       (SELECT max(version) FROM schema_migrations) <> 362 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=362 AND
        migration_id='362_aggregated_edge_import' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 362 down requires the exact verified migration head' USING ERRCODE='P3624';
    END IF;
    -- Imports hold the member's read-only tokens and the record of which DNS
    -- records the migrate wizard changed; drop them first.
    IF EXISTS (SELECT 1 FROM cdn_zone_imports) OR
       EXISTS (SELECT 1 FROM cdn_provider_accounts WHERE access = 'read_only') THEN
        RAISE EXCEPTION 'migration 362 rollback would discard imported zones or read-only accounts'
            USING ERRCODE='P3625';
    END IF;
END;
$migration_362_down$;

DROP TRIGGER site_supply_binding_import_guard_362 ON site_supply_bindings;
DROP FUNCTION site_supply_binding_import_guard_362();
DROP TABLE cdn_import_migrations;
DROP TABLE cdn_import_sites;
DROP TABLE cdn_zone_imports;
DROP TRIGGER site_supply_cdn_config_account_362 ON site_supply_cdn_configs;
DROP FUNCTION site_supply_cdn_config_account_362();
DROP TRIGGER cdn_provider_account_access_362 ON cdn_provider_accounts;
DROP FUNCTION cdn_provider_account_access_362();
ALTER TABLE cdn_provider_accounts DROP COLUMN access;
