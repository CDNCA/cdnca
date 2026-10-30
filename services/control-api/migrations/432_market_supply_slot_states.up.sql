LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_432_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 431 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 431 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=431 AND
        migration_id='431_market_supply_limits' AND
        checksum_sha256='203f0861c0bfb8c347e7b680848d437bd25a541ae3721a6b5d811038949c7f69' AND
        down_checksum_sha256='af5fb82e49b0961644203583fdf0e00bdc4d55a60dc0cf5f7fa181003b81de3f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.market_supply_slot_states') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 432 requires the exact verified 431 release head' USING ERRCODE='P4320';
    END IF;
END;
$migration_432_up$;

-- 432（r136 ML-18b，ADR 0012 §18.4，用户 U3 10-21 22:40；merge-batch8 由 429 占位改号，守卫指向 431）。
-- The leaf's cache of the market's slot states (GET /v1/leaf/subscription-states):
-- one row per local market key (marketsupply.Key = subscription path + node
-- pool), normal / stopped (unpaid or a platform ticket) / cancelled. A
-- seller may not take an in-use supply to zero online nodes while a slot is
-- normal. The snapshot is replaced as a whole; fetched_at in the single
-- market_supply_slot_state_sync row says how fresh it is (stale = every
-- subscription counts as normal: refuse while the market is unreachable).
CREATE TABLE market_supply_slot_states (
    market_key text PRIMARY KEY CHECK (market_key ~ '^[0-9a-f]{24}$'),
    state text NOT NULL CHECK (state IN ('normal', 'stopped', 'cancelled'))
);

CREATE TABLE market_supply_slot_state_sync (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    fetched_at timestamptz NOT NULL,
    market_as_of timestamptz NOT NULL
);
