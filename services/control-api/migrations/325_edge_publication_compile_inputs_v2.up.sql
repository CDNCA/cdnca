LOCK TABLE schema_migrations, edge_publication_compile_inputs IN ACCESS EXCLUSIVE MODE;

DO $migration_325_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 324 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 324 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=324 AND
        migration_id='324_system_republication_secondary_verification' AND
        checksum_sha256='eac4de7e8d9d3300b841caacef1293550623edd4ae3834f6376912f57112412a' AND
        down_checksum_sha256='82429290291a45689ebe035f9f3af3fb9f2dafc949b4a077e2c2587effbf143e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 325 requires the exact verified 324 release head' USING ERRCODE='P3250';
    END IF;
END;
$migration_325_up$;

-- r136 g11: site runtime v2 publications keep their compiled source too, as
-- non-secret facts plus references: the runtime document (certificates by
-- certificate_version_id only), HTTP policy / firewall action / capture
-- policy revisions by (policy, revision, digest), origin-route documents and
-- the L2 topology. No artifact plaintext, ciphertext or key material: a stop
-- overlay reloads the referenced revisions, re-validates every referenced
-- certificate version and encrypts per target node like any v2 publication.
ALTER TABLE edge_publication_compile_inputs
    ALTER COLUMN spec DROP NOT NULL,
    ADD COLUMN site_runtime_v2 jsonb CHECK (site_runtime_v2 IS NULL OR
        jsonb_typeof(site_runtime_v2) = 'object' AND octet_length(site_runtime_v2::text) <= 4194304),
    ADD CONSTRAINT edge_publication_compile_inputs_one_source_325
        CHECK ((spec IS NULL) <> (site_runtime_v2 IS NULL));
