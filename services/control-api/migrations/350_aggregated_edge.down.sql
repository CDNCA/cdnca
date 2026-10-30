LOCK TABLE schema_migrations, permissions, roles, role_permissions, site_supplies, cdn_provider_accounts,
    site_supply_cdn_configs, site_supply_cdn_sites, site_supply_cdn_resources, aggregated_edge_runtime
    IN ACCESS EXCLUSIVE MODE;

DO $migration_350_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 350 OR
       (SELECT max(version) FROM schema_migrations) <> 350 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=350 AND
        migration_id='350_aggregated_edge' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 350 down requires the exact verified migration head' USING ERRCODE='P3501';
    END IF;
    -- Bound CDN accounts hold the member's credentials and the resource map is
    -- the only record of what was created in the member's vendor account:
    -- dropping either would orphan vendor-side objects. Unbind first.
    IF EXISTS (SELECT 1 FROM cdn_provider_accounts) OR EXISTS (SELECT 1 FROM site_supply_cdn_configs) OR
       EXISTS (SELECT 1 FROM site_supplies WHERE kind = 'third_party_cdn') THEN
        RAISE EXCEPTION 'migration 350 rollback would discard third-party CDN accounts or supplies'
            USING ERRCODE='P3503';
    END IF;
END;
$migration_350_down$;

DROP TABLE aggregated_edge_runtime;
DROP TABLE site_supply_cdn_resources;
DROP TABLE site_supply_cdn_sites;
DROP TABLE site_supply_cdn_configs;
DROP TRIGGER cdn_provider_account_credential_fence_350 ON cdn_provider_accounts;
DROP TABLE cdn_provider_accounts;
DROP FUNCTION cdn_provider_account_credential_fence_350();

DELETE FROM role_permissions WHERE permission_name = 'edge.aggregated.manage';
DELETE FROM permissions WHERE name = 'edge.aggregated.manage';
