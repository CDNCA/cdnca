LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_432_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 432 OR
       (SELECT max(version) FROM schema_migrations) <> 432 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=432 AND
        migration_id='432_market_supply_slot_states' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 432 down requires the exact verified migration head' USING ERRCODE='P4321';
    END IF;
END;
$migration_432_down$;

-- A cache the leaf refills from the market: nothing to keep.
DROP TABLE market_supply_slot_state_sync;
DROP TABLE market_supply_slot_states;
