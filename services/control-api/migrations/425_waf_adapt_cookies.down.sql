LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_425_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 425 OR
       (SELECT max(version) FROM schema_migrations) <> 425 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=425 AND
        migration_id='425_waf_adapt_cookies' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 425 down requires the exact verified migration head' USING ERRCODE='P4251';
    END IF;
END;
$migration_425_down$;

-- Cookie 名集合由后续 waf_evidence 重新学习。
DROP TABLE waf_adapt_cookies;
ALTER TABLE waf_adapt_sites DROP COLUMN cookie_last_day, DROP COLUMN cookie_day_bits, DROP COLUMN cookie_samples;
