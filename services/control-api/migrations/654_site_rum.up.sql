LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

-- Guard: the verified 653 head (653_challenge_external_captcha), with its
-- checksums pinned.
DO $migration_654_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 653 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 653 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=653 AND
        migration_id='653_challenge_external_captcha' AND
        checksum_sha256='8611331fac13d1f555aae7f9e4661e33decac52c1efb9d178957b3598ae0ccb3' AND
        down_checksum_sha256='ce9aa36d05be3e251a51e86da48b22a2a29cfbd78981e6914e80adef592ce2f3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='rum_sample_percent'
       ) THEN
        RAISE EXCEPTION 'migration 654 requires the exact verified 653 release head' USING ERRCODE='P6540';
    END IF;
END;
$migration_654_up$;

-- 真实用户体验上报. NULL is off (the default); a
-- value is the sample rate in percent. The node injects the same-origin RUM
-- script into the site's HTML documents and folds the beacons into per
-- minute histograms. Any change of the column advances the scope's source
-- revision (335 compares whole rows). A NULL default adds the column without
-- rewriting the table.
ALTER TABLE sites
    ADD COLUMN rum_sample_percent smallint
        CONSTRAINT sites_rum_sample_percent_range CHECK (rum_sample_percent IS NULL OR rum_sample_percent BETWEEN 1 AND 100);
