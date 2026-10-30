LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_437_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 437 OR
       (SELECT max(version) FROM schema_migrations) <> 437 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=437 AND
        migration_id='437_market_supply_tenant_plugins' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 437 down requires the exact verified migration head' USING ERRCODE='P4371';
    END IF;
END;
$migration_437_down$;

DROP TABLE market_supply_tenant_plugins;
