LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_328_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 327 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 327 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=327 AND
        migration_id='327_cc_site_settings' AND
        checksum_sha256='ea7159112cd8cd207b0d57a86de28f82c65a4b25bf13a450a340951b690c4447' AND
        down_checksum_sha256='3aa5c37c1bd32cc711dc981f8c26cbc2f6183a50ec17a674fb385221075f6e16' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='l4_forwards' AND column_name='session_log_enabled'
       ) THEN
        RAISE EXCEPTION 'migration 328 requires the exact verified 327 release head' USING ERRCODE='P3280';
    END IF;
END;
$migration_328_up$;

-- Per-stream session log (v6.1.0 #6, docs/architecture/l4-v6-fields.md):
-- off by default; v2 streams only.
ALTER TABLE l4_forwards
    ADD COLUMN session_log_enabled boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT l4_forwards_session_log_328 CHECK (NOT session_log_enabled OR site_id IS NOT NULL);

-- Runtime intents of logging streams carry "session_log": true; others omit it.
CREATE FUNCTION validate_l4_runtime_spec_328(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF NOT validate_l4_runtime_spec_316(target_stream_id,target_scope_id,target_site_id,runtime_spec-'session_log') THEN
        RETURN false;
    END IF;
    IF NOT runtime_spec ? 'session_log' THEN RETURN true; END IF;
    RETURN target_site_id IS NOT NULL AND runtime_spec->'session_log' = 'true'::jsonb;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_316,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_328
    CHECK(validate_l4_runtime_spec_328(stream_id,scope_id,site_id,runtime_spec));

REVOKE ALL ON FUNCTION validate_l4_runtime_spec_328(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION validate_l4_runtime_spec_328(uuid,uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
