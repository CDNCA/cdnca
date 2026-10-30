LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_285_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 285 OR
       (SELECT max(version) FROM schema_migrations) <> 285 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=285 AND
        migration_id='285_site_supply_binding' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 285 down requires the exact verified migration head' USING ERRCODE='P2850';
    END IF;
END;
$migration_285_down$;

-- Market and third-party bindings are dropped; local node group bindings
-- were never copied, so sites keep serving from their node groups.
DROP VIEW site_supply_bindings_effective;
DROP TABLE site_supply_config_revisions;
DROP TABLE site_supply_leaf_sites;
DROP TABLE site_supply_bindings;
DROP TABLE site_supplies;
