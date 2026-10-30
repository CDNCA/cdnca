LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_318_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 317 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 317 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=317 AND
        migration_id='317_identity_secondary_verification_site_holds' AND
        checksum_sha256='64ca2e1ae3498152b5b0d9d28f494f031de87d2ecd8c8416e7163c3ddd510cac' AND
        down_checksum_sha256='926397567843234f34420ae3ba06c9d298044b59ff903d1cfca1adf64f9e1cbb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.edge_publication_compile_inputs') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 318 requires the exact verified 317 release head' USING ERRCODE='P3180';
    END IF;
END;
$migration_318_up$;

-- r136 g11: the compiled source of each site runtime v1 publication (the
-- edgeconfig.Spec without the system CRS rule text, and its required
-- capabilities). A system republication of a scope with unpublished tenant
-- edits starts from it and only takes out (or puts back) the sites a system
-- stop changed, so a stop reaches the nodes without carrying a draft. Its
-- content is already in the publication's signed plaintext bundle.
CREATE TABLE edge_publication_compile_inputs (
    config_version_id uuid PRIMARY KEY REFERENCES config_versions(id) ON DELETE RESTRICT,
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    -- overlay: built from an earlier publication's inputs, not the scope's rows.
    overlay boolean NOT NULL,
    spec jsonb NOT NULL CHECK (jsonb_typeof(spec) = 'object' AND octet_length(spec::text) <= 4194304),
    required_capabilities jsonb NOT NULL CHECK (jsonb_typeof(required_capabilities) = 'array'),
    created_at timestamptz NOT NULL,
    UNIQUE (configuration_scope_id, source_revision)
);

CREATE FUNCTION protect_edge_publication_compile_inputs_318()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'edge publication compile inputs are immutable' USING ERRCODE = 'P3181';
END;
$$;
CREATE TRIGGER edge_publication_compile_inputs_immutable_318
BEFORE UPDATE OR DELETE ON edge_publication_compile_inputs
FOR EACH ROW EXECUTE FUNCTION protect_edge_publication_compile_inputs_318();

REVOKE ALL ON edge_publication_compile_inputs FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_edge_publication_compile_inputs_318() FROM PUBLIC;
GRANT SELECT, INSERT ON edge_publication_compile_inputs TO cdnca_control_app, cdnca_control_runtime;
