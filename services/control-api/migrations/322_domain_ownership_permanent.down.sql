LOCK TABLE schema_migrations, domain_ownerships IN ACCESS EXCLUSIVE MODE;

DO $migration_322_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 322 OR
       (SELECT max(version) FROM schema_migrations) <> 322 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=322 AND
        migration_id='322_domain_ownership_permanent' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 322 down requires the exact verified migration head' USING ERRCODE='P3221';
    END IF;
END;
$migration_322_down$;

-- Restore the 303 recheck columns; every verified proof is due 30 days after
-- it was verified (or now, when that is already past).
ALTER TABLE domain_ownerships DROP CONSTRAINT domain_ownerships_verified_at_322;
ALTER TABLE domain_ownerships
    ADD COLUMN next_check_at timestamptz CHECK (next_check_at IS NULL OR isfinite(next_check_at)),
    ADD COLUMN consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures BETWEEN 0 AND 3);
UPDATE domain_ownerships SET next_check_at=GREATEST(verified_at + interval '30 days', clock_timestamp())
WHERE status='verified';
ALTER TABLE domain_ownerships ADD CONSTRAINT domain_ownerships_verified_recheck_303
    CHECK (status <> 'verified' OR (verified_at IS NOT NULL AND next_check_at IS NOT NULL));
CREATE INDEX domain_ownerships_due_299_idx ON domain_ownerships(next_check_at) WHERE status = 'verified';
