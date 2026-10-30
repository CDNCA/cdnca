LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_410_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 410 OR
       (SELECT max(version) FROM schema_migrations) <> 410 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=410 AND
        migration_id='410_autodefense_baseline_drift' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 410 down requires the exact verified migration head' USING ERRCODE='P4101';
    END IF;
    -- Drift receipts would violate the restored kind check; they are two day
    -- idempotency rows only (the report stream keeps one day).
END;
$migration_410_down$;

DELETE FROM autodefense_report_receipts WHERE kind='drift';
ALTER TABLE autodefense_report_receipts DROP CONSTRAINT autodefense_report_receipts_kind_check;
ALTER TABLE autodefense_report_receipts ADD CONSTRAINT autodefense_report_receipts_kind_check
    CHECK (kind IN ('minute', 'state', 'candidate', 'verdicts', 'adjust', 'node_event'));
DROP TABLE autodefense_baseline_drifts;
