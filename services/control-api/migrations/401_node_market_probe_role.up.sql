LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_401_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 400 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 400 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=400 AND
        migration_id='400_node_networks_republication' AND
        checksum_sha256='7dfc53b4b0f54af75c347de956477a80bbc7df189f086e98c2c25cbe98f6db61' AND
        down_checksum_sha256='9a52560e0f8b09a9b9c8d962a63117ed85015b49d4a8db76d3ebf9c7d5635dd5' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='node_presence' AND column_name='market_probe_role'
       ) THEN
        RAISE EXCEPTION 'migration 401 requires the exact verified 400 release head' USING ERRCODE='P4010';
    END IF;
END;
$migration_401_up$;

-- 401（r136 f15-probe-proto，占位：合入时改为当时头+1）。
-- The market probe role of the latest heartbeat (EdgeRuntimeStatus.market_probe
-- = 6): probe_only (market_probe.enabled), join_market (also
-- market_probe.join_market) or disabled. NULL means the Agent did not report
-- it (older Agent, UNSPECIFIED): unknown, never treated as join_market. Only
-- join_market nodes are reported to the node market for an offer's pool.
ALTER TABLE node_presence ADD COLUMN market_probe_role text
    CONSTRAINT node_presence_market_probe_role_401_check
    CHECK (market_probe_role IN ('probe_only', 'join_market', 'disabled'));
