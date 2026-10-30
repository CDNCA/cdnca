LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_592_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 591 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 591 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=591 AND
        migration_id='591_autodefense_publish_count' AND
        checksum_sha256='cf2fd4f3225cdfcef6759ba33e7162609fa0167055b9f0478e1ce58154f52ec8' AND
        down_checksum_sha256='9f8d1c72fa50fbd87c41ee6b66eaf9bd2c55f351606f97486a667c2d8651a256' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='node_presence' AND column_name='telemetry_error_code'
       ) THEN
        RAISE EXCEPTION 'migration 592 requires the exact verified 591 release head' USING ERRCODE='P5920';
    END IF;
END;
$migration_592_up$;

-- 592 (r136 fix-l4meter3, placeholder; renumber at the merge to the next
-- free number and re-pin the predecessor). The telemetry pipeline
-- degradation of the latest heartbeat (EdgeRuntimeStatus.telemetry = 8):
-- the error code (L4_USAGE_LEDGER_FULL, L4_USAGE_ATTRIBUTION_PENDING,
-- TELEMETRY_*, ...), when the Agent first and last saw it (Agent clock) and
-- in how many heartbeats. All NULL: the pipeline is healthy, disabled or the
-- Agent did not report it; the next healthy heartbeat clears them.
ALTER TABLE node_presence
    ADD COLUMN telemetry_error_code text
        CONSTRAINT node_presence_telemetry_error_code_592_check
        CHECK (telemetry_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    ADD COLUMN telemetry_first_seen_at timestamptz,
    ADD COLUMN telemetry_last_seen_at timestamptz,
    ADD COLUMN telemetry_count bigint
        CONSTRAINT node_presence_telemetry_count_592_check CHECK (telemetry_count >= 1),
    ADD CONSTRAINT node_presence_telemetry_592_shape_check CHECK (
        (telemetry_error_code IS NULL AND telemetry_first_seen_at IS NULL AND
            telemetry_last_seen_at IS NULL AND telemetry_count IS NULL) OR
        (telemetry_error_code IS NOT NULL AND telemetry_first_seen_at IS NOT NULL AND
            telemetry_last_seen_at IS NOT NULL AND telemetry_count IS NOT NULL AND
            telemetry_first_seen_at <= telemetry_last_seen_at)
    );
