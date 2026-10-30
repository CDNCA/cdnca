LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_326_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 325 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 325 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=325 AND
        migration_id='325_edge_publication_compile_inputs_v2' AND
        checksum_sha256='6e35017fb83ec6fdcd24838f845171589b6a621abe5084156391b776f5f0f52c' AND
        down_checksum_sha256='0753b89b55c8a32625d9ed994d92b889b67c39bdd05f40e24769289a29f698f2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='force_https'
       ) THEN
        RAISE EXCEPTION 'migration 326 requires the exact verified 325 release head' USING ERRCODE='P3260';
    END IF;
END;
$migration_326_up$;

-- FX07: a site may redirect plain HTTP to HTTPS (301). https_redirect_port is
-- one of the site's HTTPS ports; 0 means its lowest HTTPS port, so it follows
-- port edits. Forcing needs HTTPS. New sites inherit the system default
-- (网站默认 > HTTPS > 强制HTTPS); existing sites do not redirect.
ALTER TABLE sites
    ADD COLUMN force_https boolean NOT NULL DEFAULT false,
    ADD COLUMN https_redirect_port integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT sites_force_https_326 CHECK (
        (NOT force_https OR https_enabled AND cardinality(https_ports) > 0) AND
        (https_redirect_port = 0 OR https_redirect_port::text = ANY(https_ports))
    );
