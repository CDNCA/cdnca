LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

-- Guard: the verified 654 head (654_site_rum).
DO $migration_655_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 654 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 654 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=654 AND
        migration_id='654_site_rum' AND
        checksum_sha256='7adcc97f56ec61e02455fc2e38aed856f57734c275c8b7a92726f162657e8b92' AND
        down_checksum_sha256='bcf318b58826127312d95d8c56cb2245913495ef6454a7c96a755fa0471ce98b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='content_rewrite'
       ) THEN
        RAISE EXCEPTION 'migration 655 requires the exact verified 654 release head' USING ERRCODE='P6550';
    END IF;
END;
$migration_655_up$;

-- 内容改写. NULL is no rule (the default; a
-- site whose rules are all removed is written back to NULL); a value is the
-- whole settings object (max_bytes, rules) the control plane validated
-- (contentrewrite.Normalize). The node gets the enabled rules compiled into
-- the site object. Any change of the column advances the scope's source
-- revision (335 compares whole rows). A NULL default adds the column without
-- rewriting the table.
ALTER TABLE sites
    ADD COLUMN content_rewrite jsonb
        CONSTRAINT sites_content_rewrite_shape CHECK (content_rewrite IS NULL OR
            (jsonb_typeof(content_rewrite)='object' AND octet_length(content_rewrite::text) <= 262144));
