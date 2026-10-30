LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_380_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 380 OR
       (SELECT max(version) FROM schema_migrations) <> 380 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=380 AND
        migration_id='380_identity_login_throttle' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 380 down requires the exact verified migration head' USING ERRCODE='P3801';
    END IF;
END;
$migration_380_down$;

-- Throttle counters and one-time CAPTCHA challenges are short-lived runtime
-- facts (one-hour window); dropping them only resets the counters.
DROP TABLE identity_login_captchas;
DROP TABLE identity_login_attempts;
