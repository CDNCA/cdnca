LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents IN ACCESS EXCLUSIVE MODE;

DO $migration_300_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 299 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 299 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=299 AND
        migration_id='299_package_traffic_enforcement' AND
        checksum_sha256='61b0f33fbdade032abffa52015271acb3b4fb117be787c889663ee27d75b9824' AND
        down_checksum_sha256='8b1fcea6bf466652afc1e876f80556aa30a61898dd1abcc34ee31a52c30be091' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='l4_forwards' AND column_name='max_new_connections_per_client_per_second'
       ) THEN
        RAISE EXCEPTION 'migration 300 requires the exact verified 299 release head' USING ERRCODE='P3000';
    END IF;
END;
$migration_300_up$;

-- Per-client new connection rate of a v2 stream (v6.1.0 #3,
-- docs/architecture/l4-v6-fields.md): 0 is unlimited; burst and ban only
-- apply to a rate. The bounds are edgeconfig.ValidL4NewConnRate's.
ALTER TABLE l4_forwards
    ADD COLUMN max_new_connections_per_client_per_second integer NOT NULL DEFAULT 0,
    ADD COLUMN new_connection_burst integer NOT NULL DEFAULT 0,
    ADD COLUMN new_connection_ban_seconds integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT l4_forwards_new_connection_rate_300 CHECK (
        max_new_connections_per_client_per_second BETWEEN 0 AND 100000 AND
        new_connection_burst BETWEEN 0 AND 100000 AND new_connection_ban_seconds BETWEEN 0 AND 86400 AND
        (max_new_connections_per_client_per_second > 0 OR (new_connection_burst = 0 AND new_connection_ban_seconds = 0)) AND
        (max_new_connections_per_client_per_second = 0 OR site_id IS NOT NULL)
    );

-- Runtime intents of limited streams carry new_conn_rate; others omit it.
CREATE FUNCTION validate_l4_runtime_spec_300(
    target_stream_id uuid, target_scope_id uuid, target_site_id uuid, runtime_spec jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE rate jsonb;
BEGIN
    IF NOT validate_l4_runtime_spec_293(target_stream_id,target_scope_id,target_site_id,runtime_spec-'new_conn_rate') THEN
        RETURN false;
    END IF;
    IF NOT runtime_spec ? 'new_conn_rate' THEN RETURN true; END IF;
    rate := runtime_spec->'new_conn_rate';
    IF target_site_id IS NULL OR jsonb_typeof(rate)<>'object' OR
       (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(rate) keys(key)) IS DISTINCT FROM
           ARRAY['ban_seconds','burst','rate_per_second']::text[] OR
       jsonb_typeof(rate->'rate_per_second')<>'number' OR jsonb_typeof(rate->'burst')<>'number' OR
       jsonb_typeof(rate->'ban_seconds')<>'number' OR
       (rate->>'rate_per_second') !~ '^[1-9][0-9]{0,5}$' OR (rate->>'burst') !~ '^(0|[1-9][0-9]{0,5})$' OR
       (rate->>'ban_seconds') !~ '^(0|[1-9][0-9]{0,4})$' THEN
        RETURN false;
    END IF;
    RETURN (rate->>'rate_per_second')::integer <= 100000 AND (rate->>'burst')::integer <= 100000 AND
        (rate->>'ban_seconds')::integer <= 86400;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_293,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_300
    CHECK(validate_l4_runtime_spec_300(stream_id,scope_id,site_id,runtime_spec));

REVOKE ALL ON FUNCTION validate_l4_runtime_spec_300(uuid,uuid,uuid,jsonb) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT EXECUTE ON FUNCTION validate_l4_runtime_spec_300(uuid,uuid,uuid,jsonb) TO cdnca_control_app;
    END IF;
END $$;
