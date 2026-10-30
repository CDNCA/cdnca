LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_341_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 340 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 340 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=340 AND
        migration_id='340_edge_signer_trust' AND
        checksum_sha256='2a5bbd98e64db2e52fa2e9f5683ecd8cbac139ef01e5cbaf3f41524667fea8f5' AND
        down_checksum_sha256='4cd5ebdedd4e5ed677b4b1916d179a244597d4ac47605414c82aa0f88a02927f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='l4_forwards' AND column_name='guard_rules'
       ) THEN
        RAISE EXCEPTION 'migration 341 requires the exact verified 340 release head' USING ERRCODE='P3410';
    END IF;
END;
$migration_341_up$;

-- L4 guard rules of a v2 stream (v6.1.0 #8, docs/architecture/l4-v6-fields.md):
-- NULL is none. The database checks the shape the publication relies on (a
-- 1..64 array of objects with a canonical UUID id, a known action and the
-- ban fields exactly when banning); edgeconfig.NormalizeL4GuardRules checks
-- the conditions themselves before anything is written.
CREATE FUNCTION valid_l4_guard_rules_341(rules jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE rule jsonb;
BEGIN
    IF jsonb_typeof(rules) IS DISTINCT FROM 'array' OR jsonb_array_length(rules) NOT BETWEEN 1 AND 64 OR
       (SELECT count(DISTINCT item->>'id') FROM jsonb_array_elements(rules) item) <> jsonb_array_length(rules) THEN
        RETURN false;
    END IF;
    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) IS DISTINCT FROM 'object' OR
           COALESCE(rule->>'id', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR
           COALESCE(rule->>'action', '') NOT IN ('drop', 'ban', 'allow') OR
           NOT (rule ?| ARRAY['first_packet', 'server_names', 'client_ip', 'geo']) OR
           EXISTS (SELECT 1 FROM jsonb_object_keys(rule) keys(key) WHERE key NOT IN
               ('id', 'action', 'first_packet', 'server_names', 'client_ip', 'geo', 'ban_seconds', 'threshold', 'window_seconds')) THEN
            RETURN false;
        END IF;
        IF rule->>'action' = 'ban' THEN
            IF COALESCE(rule->>'ban_seconds', '') !~ '^[1-9][0-9]{0,4}$' OR (rule->>'ban_seconds')::integer > 86400 OR
               COALESCE(rule->>'threshold', '') !~ '^[1-9][0-9]{0,4}$' OR (rule->>'threshold')::integer > 10000 OR
               ((rule->>'threshold')::integer = 1) = (rule ? 'window_seconds') OR
               (rule ? 'window_seconds' AND (COALESCE(rule->>'window_seconds', '') !~ '^[1-9][0-9]{0,3}$' OR
                   (rule->>'window_seconds')::integer > 3600)) THEN
                RETURN false;
            END IF;
        ELSIF rule ?| ARRAY['ban_seconds', 'threshold', 'window_seconds'] THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

ALTER TABLE l4_forwards
    ADD COLUMN guard_rules jsonb,
    ADD CONSTRAINT l4_forwards_guard_rules_341 CHECK (
        guard_rules IS NULL OR (site_id IS NOT NULL AND valid_l4_guard_rules_341(guard_rules))
    );

-- Runtime intents of guarded streams carry guard_rules; others omit it.
-- Stripped of it, the intent is a valid 340 intent.
CREATE FUNCTION validate_l4_runtime_spec_341(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF NOT validate_l4_runtime_spec_334(target_stream_id,target_scope_id,target_site_id,runtime_spec-'guard_rules') THEN
        RETURN false;
    END IF;
    IF NOT runtime_spec ? 'guard_rules' THEN RETURN true; END IF;
    RETURN target_site_id IS NOT NULL AND valid_l4_guard_rules_341(runtime_spec->'guard_rules');
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_334,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_341
    CHECK(validate_l4_runtime_spec_341(stream_id,scope_id,site_id,runtime_spec));

REVOKE ALL ON FUNCTION valid_l4_guard_rules_341(jsonb), validate_l4_runtime_spec_341(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION valid_l4_guard_rules_341(jsonb),
            validate_l4_runtime_spec_341(uuid,uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
