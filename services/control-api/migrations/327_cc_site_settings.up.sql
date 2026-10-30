LOCK TABLE schema_migrations, security_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_327_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 326 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 326 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=326 AND
        migration_id='326_site_force_https' AND
        checksum_sha256='426b36dbec1b76641382cf268a036796e028e579276d89778f4375ced79ba576' AND
        down_checksum_sha256='b5eb71acdff1b8e3f0bc9c88226a0220991bb968f17baa1a5821d792d75ef6ed' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='security_policies' AND column_name='cc_settings'
       ) THEN
        RAISE EXCEPTION 'migration 327 requires the exact verified 326 release head' USING ERRCODE='P3270';
    END IF;
END;
$migration_327_up$;

-- G1-e (NF30, FX08/FX17): a CC policy's site-level settings — ban / pass
-- durations and the auto switch (securitypolicy.CCSettings). NULL keeps
-- every rule's own values and no auto switch, i.e. what policies did before.
-- The policy version documents carry the same object.
ALTER TABLE security_policies
    ADD COLUMN cc_settings jsonb,
    ADD CONSTRAINT security_policies_cc_settings_327
        CHECK (cc_settings IS NULL OR kind = 'cc' AND jsonb_typeof(cc_settings) = 'object');
