LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_316_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 315 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 315 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=315 AND
        migration_id='315_ip_intel_library' AND
        checksum_sha256='5632dfd2da07bdf177f02996c1b319075aa6c781c1a745b3bf4e2814b9b84755' AND
        down_checksum_sha256='b2e8ac45c3b828a7ba13f20b18340cfe59cc8b511da8beea43e4efa8357399c8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='l4_forwards' AND column_name='toa'
       ) THEN
        RAISE EXCEPTION 'migration 316 requires the exact verified 315 release head' USING ERRCODE='P3160';
    END IF;
END;
$migration_316_up$;

-- 回源携带客户端 IP via TOA (v6.1.0 #5, docs/architecture/l4-toa-poc.md):
-- a v2 TCP stream without PROXY protocol in either direction.
ALTER TABLE l4_forwards
    ADD COLUMN toa boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT l4_forwards_toa_316 CHECK (
        NOT toa OR (protocol = 'tcp' AND site_id IS NOT NULL AND
                    NOT proxy_protocol_inbound AND NOT proxy_protocol_v1)
    );

-- Runtime intents of TOA streams carry "toa": true (the last field); others
-- omit it. Every socket of such a stream is TCP and no PROXY header is used.
CREATE FUNCTION validate_l4_runtime_spec_316(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF NOT validate_l4_runtime_spec_300(target_stream_id,target_scope_id,target_site_id,runtime_spec-'toa') THEN
        RETURN false;
    END IF;
    IF NOT runtime_spec ? 'toa' THEN RETURN true; END IF;
    RETURN target_site_id IS NOT NULL AND runtime_spec->'toa' = 'true'::jsonb AND
        runtime_spec#>>'{listener,protocol}' = 'tcp' AND
        runtime_spec->'proxy_protocol_inbound' = 'false'::jsonb AND
        runtime_spec->'proxy_protocol_outbound' = 'false'::jsonb AND
        NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(COALESCE(runtime_spec->'additional_listeners','[]'::jsonb)) socket
            WHERE socket->>'protocol' IS DISTINCT FROM 'tcp'
        );
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_300,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_316
    CHECK(validate_l4_runtime_spec_316(stream_id,scope_id,site_id,runtime_spec));

REVOKE ALL ON FUNCTION validate_l4_runtime_spec_316(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION validate_l4_runtime_spec_316(uuid,uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
